//! `wsnet` - the wsnet node client and its management CLI (USAGE.md section 2).
//!
//! ```text
//! wsnet check   --config ~/.config/wsnet/client.toml
//! wsnet run     --config ~/.config/wsnet/client.toml
//! wsnet status
//! wsnet services list [--hub HUB] [--node NODE]
//! wsnet forward list
//! wsnet forward remove NAME
//! wsnet keygen --node NODE
//! ```
//!
//! `status`, `services`, and `forward` talk to the *running* daemon over the
//! per-user local control endpoint; they never open a network listener. The
//! endpoint is a named pipe on Windows and a `0600` Unix socket elsewhere, which
//! is what keeps the control surface off any public interface (USAGE.md section 2).

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use wsnet_config::ClientConfig;
use wsnet_control::{
    default_endpoint, ControlClient, ControlHandler, ControlServer, Counters, DaemonState,
    Endpoint, ErrorCode, ErrorResponse, ForwardInfo, ForwardListReport, ForwardState,
    HubSession as ControlHubSession, Request, Response, ServiceDescriptor, ServiceState,
    ServicesReport, SessionState as ControlSessionState, StatusReport,
};
use wsnet_node::{Node, NodeOptions};

#[derive(Debug, Parser)]
#[command(name = "wsnet", version, about = "wsnet node client and management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse and validate the configuration, then exit.
    Check {
        /// Path to `client.toml`.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Run the node, its SOCKS5 listener, and its local forwards.
    Run {
        /// Path to `client.toml`.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Override the local control endpoint.
        ///
        /// The default is per-user, so a second daemon for the same user needs
        /// its own name; this is what makes two identities on one host possible.
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Option<String>,
    },
    /// Ask the running node for its status.
    Status {
        /// Override the local control endpoint.
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Option<String>,
    },
    /// Ask the running node about services.
    Services {
        #[command(subcommand)]
        command: ServicesCommand,
    },
    /// Ask the running node about local forwards.
    Forward {
        #[command(subcommand)]
        command: ForwardCommand,
    },
    /// Generate a pre-shared key for one node.
    Keygen {
        /// Node the key is for, used only in the printed hint.
        #[arg(long, value_name = "NODE")]
        node: String,
    },
}

#[derive(Debug, Subcommand)]
enum ServicesCommand {
    /// List the services this node publishes.
    List {
        /// Override the local control endpoint.
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Option<String>,
        /// Restrict to one Hub.
        #[arg(long, value_name = "HUB")]
        hub: Option<String>,
        /// Restrict to one node.
        #[arg(long, value_name = "NODE")]
        node: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ForwardCommand {
    /// List active local forwards.
    List {
        /// Override the local control endpoint.
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Option<String>,
    },
    /// Remove a local forward.
    Remove {
        /// Name of the forward to remove.
        name: String,
        /// Override the local control endpoint.
        #[arg(long, value_name = "ENDPOINT")]
        endpoint: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().command {
        Command::Check { config } => check(&config),
        Command::Run { config, endpoint } => run(&config, endpoint.as_deref()).await,
        Command::Status { endpoint } => status(endpoint.as_deref()).await,
        Command::Services {
            command: ServicesCommand::List {
                endpoint,
                hub,
                node,
            },
        } => services(endpoint.as_deref(), hub, node).await,
        Command::Forward {
            command: ForwardCommand::List { endpoint },
        } => forward_list(endpoint.as_deref()).await,
        Command::Forward {
            command: ForwardCommand::Remove { name, endpoint },
        } => forward_remove(endpoint.as_deref(), &name).await,
        Command::Keygen { node } => keygen(&node),
    }
}

fn check(path: &Path) -> anyhow::Result<()> {
    let config =
        ClientConfig::load_from_path(path).with_context(|| format!("loading {}", path.display()))?;
    println!("configuration is valid");
    println!("  node id   : {}", config.client.node_id);
    println!("  socks     : {}", config.client.socks_listen);
    println!("  hubs      : {}", config.servers.len());
    println!("  services  : {}", config.services.len());
    println!("  forwards  : {}", config.forwards.len());
    Ok(())
}

async fn run(path: &Path, endpoint_override: Option<&str>) -> anyhow::Result<()> {
    let config =
        ClientConfig::load_from_path(path).with_context(|| format!("loading {}", path.display()))?;

    // The control handler needs the configured forward and service lists, so
    // keep a copy before the node takes ownership of the configuration.
    let forwards = config.forwards.clone();
    let services = config.services.clone();
    let node_id = config.client.node_id.clone();

    let options = NodeOptions::default();
    let node = Node::build(config, options).context("building the node")?;

    let endpoint = match endpoint_override {
        Some(value) => Endpoint::new(value)?,
        None => default_endpoint().context("resolving the control endpoint")?,
    };
    let server = ControlServer::bind(&endpoint)
        .await
        .with_context(|| format!("binding the control endpoint {}", endpoint.as_str()))?;

    node.start().await.context("starting the node")?;
    if let Some(addr) = node.socks_addr() {
        tracing::info!(%addr, "SOCKS5 listening");
    }
    for hub in node.hub_ids() {
        tracing::info!(hub = %hub, "hub session starting");
    }

    let handler = Handler {
        node: Arc::clone(&node),
        node_id,
        started: Instant::now(),
        forwards,
        services,
        requests: AtomicU64::new(0),
    };

    tracing::info!(endpoint = endpoint.as_str(), "control endpoint ready");
    tokio::select! {
        result = server.serve(handler) => result.context("the control server stopped")?,
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted; stopping"),
    }
    node.shutdown();
    Ok(())
}

fn keygen(node: &str) -> anyhow::Result<()> {
    let psk = wsnet_crypto::Psk::generate();
    let hex: String = psk
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("{hex}");
    eprintln!(
        "A fresh 32-byte key for `{node}`. Store it in a permission-controlled file and never in \
         the repository or a log; the Hub must be given the same key."
    );
    Ok(())
}

fn endpoint_from(override_value: Option<&str>) -> anyhow::Result<Endpoint> {
    match override_value {
        Some(value) => Endpoint::new(value).map_err(Into::into),
        None => default_endpoint().map_err(Into::into),
    }
}

async fn status(endpoint: Option<&str>) -> anyhow::Result<()> {
    let endpoint = endpoint_from(endpoint)?;
    let mut client = ControlClient::connect(&endpoint)
        .await
        .with_context(|| format!("no running node on {}", endpoint.as_str()))?;
    match client.request(Request::Status).await? {
        Response::Status(report) => {
            println!("daemon   : {:?}", report.daemon);
            println!("node     : {}", report.node_id);
            println!("uptime   : {}s", report.uptime_secs);
            println!("hubs     :");
            for hub in &report.hubs {
                println!("  {:<20} {:?}", hub.hub_id, hub.state);
            }
            println!("counters :");
            println!("  streams open      : {}", report.counters.streams_open);
            println!("  forwards active   : {}", report.counters.forwards_active);
            println!("  services published: {}", report.counters.services_published);
            Ok(())
        }
        Response::Error(error) => anyhow::bail!("{} ({:?})", error.message, error.code),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

async fn services(
    endpoint: Option<&str>,
    hub: Option<String>,
    node: Option<String>,
) -> anyhow::Result<()> {
    let endpoint = endpoint_from(endpoint)?;
    let mut client = ControlClient::connect(&endpoint)
        .await
        .with_context(|| format!("no running node on {}", endpoint.as_str()))?;
    match client
        .request(Request::ServicesList { hub, node })
        .await?
    {
        Response::Services(report) => {
            if report.services.is_empty() {
                println!("no services");
            }
            for service in &report.services {
                println!(
                    "{:<12} {:<16} {:<10} {:?} rev {} {:?}",
                    service.hub,
                    service.node,
                    service.name,
                    service.proto,
                    service.revision,
                    service.state
                );
            }
            Ok(())
        }
        Response::Error(error) => anyhow::bail!("{} ({:?})", error.message, error.code),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

async fn forward_list(endpoint: Option<&str>) -> anyhow::Result<()> {
    let endpoint = endpoint_from(endpoint)?;
    let mut client = ControlClient::connect(&endpoint)
        .await
        .with_context(|| format!("no running node on {}", endpoint.as_str()))?;
    match client.request(Request::ForwardList).await? {
        Response::ForwardList(report) => {
            if report.forwards.is_empty() {
                println!("no forwards");
            }
            for forward in &report.forwards {
                println!(
                    "{:<12} {:<24} {:?} -> {:?}",
                    forward.spec.name,
                    forward.resolved_listen.to_string(),
                    forward.state,
                    forward.spec.destination
                );
            }
            Ok(())
        }
        Response::Error(error) => anyhow::bail!("{} ({:?})", error.message, error.code),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

async fn forward_remove(endpoint: Option<&str>, name: &str) -> anyhow::Result<()> {
    let endpoint = endpoint_from(endpoint)?;
    let mut client = ControlClient::connect(&endpoint)
        .await
        .with_context(|| format!("no running node on {}", endpoint.as_str()))?;
    match client
        .request(Request::ForwardRemove {
            name: name.to_string(),
        })
        .await?
    {
        Response::ForwardRemoved { name } => {
            println!("removed {name}");
            Ok(())
        }
        Response::Error(error) => anyhow::bail!("{} ({:?})", error.message, error.code),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

/// Answers management requests from the live node.
///
/// Two answers are deliberately narrower than the wire format allows:
///
/// * `services list` reports the services *this* node publishes. The node crate's
///   `ServiceDirectory` supports membership queries (`contains`) but not
///   enumeration, so a remote directory listing cannot be produced faithfully and
///   is not faked.
/// * `forward add` is refused. The node binds the forwards from its configuration
///   at startup and exposes no runtime add, so accepting the request would report
///   success for a listener that was never created.
struct Handler {
    node: Arc<Node>,
    node_id: String,
    started: Instant,
    forwards: Vec<wsnet_config::ForwardConfig>,
    services: Vec<wsnet_config::ServiceConfig>,
    requests: AtomicU64,
}

impl Handler {
    fn status_report(&self) -> StatusReport {
        let hubs = self
            .node
            .hub_ids()
            .into_iter()
            .map(|hub_id| {
                let state = self
                    .node
                    .session(&hub_id)
                    .map(|session| map_session_state(session.state()))
                    .unwrap_or(ControlSessionState::Offline);
                ControlHubSession { hub_id, state }
            })
            .collect();

        let active = self
            .forwards
            .iter()
            .filter(|forward| self.node.forward_addr(&forward.name).is_some())
            .count() as u64;

        StatusReport {
            daemon: DaemonState::Running,
            node_id: self.node_id.clone(),
            uptime_secs: self.started.elapsed().as_secs(),
            hubs,
            counters: Counters {
                streams_open: 0,
                forwards_active: active,
                services_published: self.services.len() as u64,
                control_requests: self.requests.load(Ordering::Relaxed),
                ..Counters::default()
            },
        }
    }

    fn forward_infos(&self) -> Vec<ForwardInfo> {
        self.forwards
            .iter()
            .filter_map(|forward| {
                let resolved = self.node.forward_addr(&forward.name)?;
                let requested: SocketAddr = forward.listen.parse().ok()?;
                // Validation rejects a missing destination, so this is present
                // for any configuration that loaded successfully.
                let destination = forward.destination.clone()?;
                Some(ForwardInfo {
                    spec: wsnet_control::ForwardSpec {
                        name: forward.name.clone(),
                        listen: requested,
                        proto: forward.proto,
                        hub: forward.hub.clone(),
                        via: forward.via.clone(),
                        destination,
                    },
                    resolved_listen: resolved,
                    // The node tracks readiness internally; a bound listener with
                    // no reported failure is what the CLI can honestly show.
                    state: ForwardState::Bound,
                })
            })
            .collect()
    }

    /// The services this node publishes, as configured.
    ///
    /// The node crate's `ServiceDirectory` answers membership queries but cannot
    /// enumerate a remote directory, so a remote listing is not faked here. What
    /// this reports is exactly what the node registered in its `Hello`.
    fn services(&self) -> Vec<ServiceDescriptor> {
        let hub = self
            .node
            .hub_ids()
            .into_iter()
            .next()
            .unwrap_or_else(|| "local".to_string());
        self.services
            .iter()
            .map(|service| ServiceDescriptor {
                hub: hub.clone(),
                node: self.node_id.clone(),
                name: service.name.clone(),
                proto: service.proto,
                revision: 0,
                state: ServiceState::Ready,
            })
            .collect()
    }
}

impl ControlHandler for Handler {
    fn handle(
        &self,
        request: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + 'static>> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let response = match request {
            Request::Status => Response::Status(self.status_report()),
            Request::ServicesList { .. } => Response::Services(ServicesReport {
                services: self.services(),
            }),
            Request::ForwardList => Response::ForwardList(ForwardListReport {
                forwards: self.forward_infos(),
            }),
            Request::ForwardAdd { .. } => Response::Error(ErrorResponse::new(
                ErrorCode::Unavailable,
                "dynamic forwards are not supported by this build; add a [[forwards]] entry to \
                 the configuration and restart the node",
            )),
            Request::ForwardRemove { name } => {
                if self.forwards.iter().any(|forward| forward.name == name) {
                    Response::Error(ErrorResponse::new(
                        ErrorCode::Unavailable,
                        "configured forwards cannot be removed at runtime; edit the configuration \
                         and restart the node",
                    ))
                } else {
                    Response::Error(ErrorResponse::new(
                        ErrorCode::NotFound,
                        format!("no forward named `{name}`"),
                    ))
                }
            }
        };
        Box::pin(async move { response })
    }
}

/// Maps the session engine's lifecycle onto the management view.
fn map_session_state(state: wsnet_session::SessionState) -> ControlSessionState {
    match state {
        wsnet_session::SessionState::Offline => ControlSessionState::Offline,
        wsnet_session::SessionState::Authenticating => ControlSessionState::Authenticating,
        wsnet_session::SessionState::Binding => ControlSessionState::Binding,
        wsnet_session::SessionState::HelloPending => ControlSessionState::HelloPending,
        wsnet_session::SessionState::Ready => ControlSessionState::Ready,
        wsnet_session::SessionState::Degraded => ControlSessionState::Degraded,
        wsnet_session::SessionState::Closed => ControlSessionState::Closed,
    }
}
