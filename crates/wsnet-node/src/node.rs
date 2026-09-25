//! The node: configuration, hub registry, local entry points, and shutdown.
//!
//! DESIGN.md section 5.5 makes a node a client of *several* Hubs at once, so the
//! runtime keeps one [`HubSession`] per `[[servers]]` entry in failover order and
//! answers every flow request with a Hub chosen by [`crate::select`]. Two rules
//! from the same section are structural here:
//!
//! * failover recovers **new connections only**: an existing [`crate::SessionStream`]
//!   belongs to the session that created it and is never migrated, so a lost Hub
//!   fails those streams explicitly;
//! * an unconfirmed `Open` is never redone on another Hub, which is why
//!   [`NodeRuntime::open_flow`] selects a Hub once and lets the failure surface.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use wsnet_config::{ClientConfig, ConfigError, ForwardConfig};
use wsnet_crypto::Psk;
use wsnet_forward::{ForwardError, ForwardManager};
use wsnet_limits::{KEEPALIVE_INTERVAL_SECS, PSK_LEN};
use wsnet_operation::OperationError;
use wsnet_protocol::CanonError;
use wsnet_routing::{Destination, Proto};
use wsnet_session::{
    HandshakeError, MessageError, OpenStatus, ServiceRegistration, SessionError, SessionState,
    SUPPORTED_CAPABILITIES,
};
use wsnet_socks::{IpPrefix, Socks5Server, SocksConfig, SocksError, UserPass};

use crate::endpoint::{HubEndpoint, HubTransport, TransportFactory};
use crate::forward::{choice_of, spec_of, ForwardBridge};
use crate::http::HttpTransportFactory;
use crate::hub::HubSession;
use crate::select::{select_hub, Candidate, HubChoice};
use crate::socks::SocksBridge;
use crate::stream::SessionStream;
use crate::{lock, BoxFuture};

/// Everything that can stop the node from running.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// The configuration document is unusable.
    #[error("configuration: {0}")]
    Config(#[from] ConfigError),
    /// The `Auth`/`AuthOk` exchange failed.
    #[error("hub handshake: {0}")]
    Handshake(#[from] HandshakeError),
    /// A message carried unreadable metadata.
    #[error("message metadata: {0}")]
    Message(#[from] MessageError),
    /// Metadata was not canonical.
    #[error("canonical metadata: {0}")]
    Canonical(#[from] CanonError),
    /// The session engine refused an operation.
    #[error("session: {0}")]
    Session(#[from] SessionError),
    /// The operation table refused an operation.
    #[error("operation table: {0}")]
    Operation(#[from] OperationError),
    /// A socket operation failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The inbound SOCKS5 listener refused to start.
    #[error("socks5 listener: {0}")]
    Socks(#[from] SocksError),
    /// A Local Forward listener refused to start.
    #[error("local forward: {0}")]
    Forward(#[from] ForwardError),
    /// One Hub reported or suffered a transport-level failure.
    #[error("hub `{hub_id}`: {detail}")]
    Hub {
        /// Hub identity.
        hub_id: String,
        /// A local, log-safe explanation.
        detail: String,
    },
    /// A transport-level failure that is not attributable to one Hub.
    #[error("transport: {0}")]
    Transport(String),
    /// The transport bound no usable carrier.
    #[error("carrier: {0}")]
    Carrier(String),
    /// A Hub's pre-shared key could not be loaded.
    #[error("hub `{hub_id}` secret: {detail}")]
    Secret {
        /// Hub identity.
        hub_id: String,
        /// Why the secret could not be used.
        detail: String,
    },
    /// No `[[servers]]` entry names this Hub.
    #[error("hub `{hub_id}` is not configured")]
    UnknownHub {
        /// The requested Hub.
        hub_id: String,
    },
    /// No Hub can serve the flow right now (DESIGN.md section 5.5).
    #[error("no healthy hub is ready for this destination")]
    NoHub,
    /// The publisher or service is not online on any candidate Hub.
    #[error("the target is offline: {0}")]
    Offline(String),
    /// The ACL refused the flow.
    #[error("the target is denied: {0}")]
    Denied(String),
    /// Business traffic was attempted before `HelloOk` (DESIGN.md section 5.3).
    #[error("the hub session is not ready for business traffic")]
    NotReady,
    /// The session ended before the operation finished.
    #[error("the hub session is closed")]
    CarrierClosed,
    /// No `HelloOk` arrived inside the deadline.
    #[error("no HelloOk arrived inside the deadline")]
    HelloTimeout,
    /// No `OpenResult` arrived inside the deadline.
    #[error("no OpenResult arrived inside the deadline")]
    OpenTimeout,
    /// The Hub refused the `Open`.
    #[error("the open was refused ({})", .status.as_str())]
    OpenFailed {
        /// The Hub's verdict.
        status: OpenStatus,
        /// A local-only detail, never forwarded to an application.
        detail: String,
    },
    /// A retried `request_id` was answered from the operation cache.
    #[error("the open was answered from the operation cache: {detail}")]
    CachedFailure {
        /// The cached failure detail.
        detail: String,
    },
    /// The same `request_id` already opened a stream.
    #[error("request_id {request_id} already opened a stream and cannot be shared")]
    DuplicateOpen {
        /// The repeated operation id, in hex.
        request_id: String,
    },
    /// An `Open` with this id is still in flight.
    #[error("an Open with this request_id is still in flight")]
    OpenPending,
    /// A non-loopback SOCKS5 listener was configured without the protections
    /// DESIGN.md section 9.3 requires.
    #[error(
        "refusing the non-loopback socks5 listener {0}: section 9.3 requires credentials and a \
         source allowlist"
    )]
    UnsafeSocksListen(SocketAddr),
}

/// Opens remote flows for the local entry points.
///
/// The SOCKS5 and Local Forward layers only ever need this, which keeps every
/// local-entry test independent of the Hub-side plumbing.
pub trait FlowOpener: Send + Sync + 'static {
    /// Opens one remote flow, choosing a Hub per `choice` (DESIGN.md section 5.5).
    fn open_flow(
        &self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
        choice: HubChoice,
    ) -> BoxFuture<'static, Result<SessionStream, NodeError>>;
}

/// Where one Hub's pre-shared key comes from.
#[derive(Clone)]
enum SecretSource {
    /// Injected directly, which is what tests and secret managers use.
    Injected(Psk),
    /// Read from the configured `secret_file`.
    File(PathBuf),
}

/// One `[[servers]]` entry together with its credential source.
#[derive(Clone)]
struct HubPlan {
    endpoint: HubEndpoint,
    secret: SecretSource,
}

/// Construction options that a validated [`ClientConfig`] does not carry.
pub struct NodeOptions {
    /// RFC 1929 credentials for the inbound SOCKS5 listener.
    ///
    /// DESIGN.md section 9.3 makes these mandatory together with a source
    /// allowlist before a non-loopback listener may start. The configuration
    /// schema has no field for them, so they are supplied here.
    pub socks_userpass: Option<UserPass>,
    /// Per-Hub key material, keyed by `hub_id`, overriding `secret_file`.
    pub psk_overrides: HashMap<String, Psk>,
    /// How the node reaches each Hub. Defaults to the HTTP carrier set.
    pub transport: Arc<dyn TransportFactory>,
    /// How long to wait for the `HelloOk` business barrier.
    pub hello_timeout: Duration,
}

impl Default for NodeOptions {
    fn default() -> Self {
        NodeOptions {
            socks_userpass: None,
            psk_overrides: HashMap::new(),
            transport: Arc::new(HttpTransportFactory::default()),
            hello_timeout: Duration::from_secs(10),
        }
    }
}

impl NodeOptions {
    /// Replaces the transport factory.
    pub fn with_transport(mut self, transport: Arc<dyn TransportFactory>) -> Self {
        self.transport = transport;
        self
    }

    /// Sets the RFC 1929 credentials for the SOCKS5 listener.
    pub fn with_socks_credentials(mut self, userpass: UserPass) -> Self {
        self.socks_userpass = Some(userpass);
        self
    }

    /// Injects key material for one Hub.
    pub fn with_psk(mut self, hub_id: impl Into<String>, psk: Psk) -> Self {
        self.psk_overrides.insert(hub_id.into(), psk);
        self
    }

    /// Sets the `HelloOk` deadline.
    pub fn with_hello_timeout(mut self, timeout: Duration) -> Self {
        self.hello_timeout = timeout;
        self
    }
}

use crate::inbound::InboundPolicy;

/// The shared state behind a [`Node`].
pub struct NodeRuntime {
    node_id: String,
    services: Vec<ServiceRegistration>,
    /// What an inbound `Open` may reach beyond those services (section 9.3).
    inbound: InboundPolicy,
    capabilities: Vec<String>,
    plans: Vec<HubPlan>,
    transport: Arc<dyn TransportFactory>,
    hello_timeout: Duration,
    hubs: Mutex<BTreeMap<String, Arc<HubSession>>>,
    forwards: Mutex<Option<Arc<ForwardManager>>>,
    socks_addr: Mutex<Option<SocketAddr>>,
    shutdown: watch::Sender<bool>,
}

impl NodeRuntime {
    /// The node identity this client authenticates as.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Every configured Hub, in failover order.
    pub fn hub_ids(&self) -> Vec<String> {
        self.plans
            .iter()
            .map(|plan| plan.endpoint.hub_id.clone())
            .collect()
    }

    /// The live session for `hub_id`, if it is connected.
    pub fn hub(&self, hub_id: &str) -> Option<Arc<HubSession>> {
        lock(&self.hubs).get(hub_id).cloned()
    }

    /// The local SOCKS5 address actually bound, once the node started.
    pub fn socks_addr(&self) -> Option<SocketAddr> {
        *lock(&self.socks_addr)
    }

    /// The Local Forward manager, once the node started.
    pub fn forwards(&self) -> Option<Arc<ForwardManager>> {
        lock(&self.forwards).clone()
    }

    /// A receiver that resolves to `true` when the node is asked to stop.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    /// Asks every task to stop.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Authenticates to one Hub and waits for its `HelloOk` barrier.
    ///
    /// # Errors
    ///
    /// The handshake error of that Hub, including a bad `AuthOk` MAC, and
    /// [`NodeError::HelloTimeout`] when the barrier never lifts.
    pub async fn connect_hub(&self, hub_id: &str) -> Result<Arc<HubSession>, NodeError> {
        let plan = self
            .plans
            .iter()
            .find(|plan| plan.endpoint.hub_id == hub_id)
            .ok_or_else(|| NodeError::UnknownHub {
                hub_id: hub_id.to_string(),
            })?
            .clone();
        let psk = self.load_psk(&plan)?;
        let transport: Arc<dyn HubTransport> = self.transport.open(&plan.endpoint).await?;
        let session = HubSession::connect(
            plan.endpoint.clone(),
            self.node_id.clone(),
            psk,
            self.services.clone(),
            self.inbound.clone(),
            self.capabilities.clone(),
            transport,
        )
        .await?;
        session.wait_ready(self.hello_timeout).await?;
        lock(&self.hubs).insert(hub_id.to_string(), Arc::clone(&session));
        self.spawn_health_loop(hub_id.to_string(), Arc::clone(&session));
        Ok(session)
    }

    /// Reads or resolves one Hub's pre-shared key.
    fn load_psk(&self, plan: &HubPlan) -> Result<Psk, NodeError> {
        match &plan.secret {
            SecretSource::Injected(psk) => Ok(psk.clone()),
            SecretSource::File(path) => read_psk(path).map_err(|detail| NodeError::Secret {
                hub_id: plan.endpoint.hub_id.clone(),
                detail,
            }),
        }
    }

    /// Keeps one Hub's section 5.5 health verdict current.
    fn spawn_health_loop(&self, hub_id: String, session: Arc<HubSession>) {
        let mut shutdown = self.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(KEEPALIVE_INTERVAL_SECS)) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return;
                        }
                        continue;
                    }
                }
                if session.state() == SessionState::Closed {
                    return;
                }
                if let Err(error) = session.health_check().await {
                    debug!(hub = %hub_id, %error, "hub health check failed");
                }
            }
        });
    }

    /// The session a flow must use, applying section 5.5 selection.
    fn session_for(
        &self,
        destination: &Destination,
        choice: &HubChoice,
    ) -> Result<Arc<HubSession>, NodeError> {
        match choice {
            HubChoice::Hub(hub_id) => self.hub(hub_id).ok_or_else(|| NodeError::UnknownHub {
                hub_id: hub_id.clone(),
            }),
            HubChoice::Auto => {
                let candidates: Vec<Candidate> = self
                    .plans
                    .iter()
                    .map(|plan| {
                        let session = self.hub(&plan.endpoint.hub_id);
                        Candidate {
                            hub_id: plan.endpoint.hub_id.clone(),
                            ready: session.as_ref().is_some_and(|hub| hub.is_ready()),
                            healthy: session
                                .as_ref()
                                .is_some_and(|hub| hub.health().is_healthy()),
                            // A directory that is merely empty because no
                            // `PeerList` arrived yet must stay `None`, so that
                            // absence of evidence is not read as evidence of
                            // absence.
                            directory: session
                                .as_ref()
                                .map(|hub| hub.directory())
                                .filter(|directory| directory.is_known()),
                        }
                    })
                    .collect();
                let chosen = select_hub(&candidates, destination)
                    .ok_or_else(|| offline_error(destination))?;
                self.hub(&chosen.hub_id).ok_or(NodeError::NoHub)
            }
        }
    }

    /// The services a Hub has advertised to this node.
    pub fn directory(&self, hub_id: &str) -> Option<crate::ServiceDirectory> {
        self.hub(hub_id).map(|hub| hub.directory())
    }
}

impl FlowOpener for NodeRuntime {
    fn open_flow(
        &self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
        choice: HubChoice,
    ) -> BoxFuture<'static, Result<SessionStream, NodeError>> {
        let session = match self.session_for(&destination, &choice) {
            Ok(session) => session,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        // Section 5.5: the Hub is chosen once. A failure is reported, never
        // retried on another Hub, because the first attempt may have reached the
        // target.
        Box::pin(async move { session.open(destination, proto, via).await })
    }
}

/// The running client, built from a [`ClientConfig`].
pub struct Node {
    config: ClientConfig,
    runtime: Arc<NodeRuntime>,
    socks_listen: SocketAddr,
    socks_config: SocksConfig,
}

impl Node {
    /// Validates the configuration and prepares the node without any I/O.
    ///
    /// Construction is where DESIGN.md section 9.3 is enforced: a non-loopback
    /// `socks_listen` without credentials and a source allowlist is refused here,
    /// not at the first connection.
    ///
    /// # Errors
    ///
    /// [`NodeError::UnsafeSocksListen`] for the section 9.3 case and
    /// [`NodeError::Config`] for a document the schema rejects.
    pub fn build(config: ClientConfig, options: NodeOptions) -> Result<Arc<Self>, NodeError> {
        let socks_listen = parse_listen(&config.client.socks_listen)?;
        let socks_config = build_socks_config(&config, &options, socks_listen)?;

        // The document is validated only after the node's own listener check, so
        // the section 9.3 refusal is the one an operator sees first.
        config.validate()?;

        let mut servers: Vec<_> = config.servers.iter().collect();
        servers.sort_by_key(|entry| entry.priority);
        let plans = servers
            .into_iter()
            .map(|entry| HubPlan {
                endpoint: HubEndpoint {
                    hub_id: entry.hub_id.clone(),
                    url: entry.url.clone(),
                    key_id: entry.key_id.clone(),
                    priority: entry.priority,
                },
                secret: match options.psk_overrides.get(&entry.hub_id) {
                    Some(psk) => SecretSource::Injected(psk.clone()),
                    None => SecretSource::File(entry.secret_file.clone()),
                },
            })
            .collect();

        let services = config
            .services
            .iter()
            .map(|service| ServiceRegistration {
                name: service.name.clone(),
                proto: service.proto,
                target: service.target.clone(),
            })
            .collect();

        // The configuration layer already refuses an unusable CIDR, so a failure
        // here means the config was bypassed. Falling back to deny-all keeps that
        // fail-closed instead of panicking in a library.
        let mut inbound = InboundPolicy::deny_all();
        for cidr in &config.client.allow_node_address {
            match inbound.clone().allow_node_address(cidr) {
                Ok(policy) => inbound = policy,
                Err(detail) => {
                    tracing::warn!(%detail, "ignoring an unusable node-address allowlist entry");
                }
            }
        }

        let (shutdown, _receiver) = watch::channel(false);
        let runtime = Arc::new(NodeRuntime {
            node_id: config.client.node_id.clone(),
            services,
            inbound,
            capabilities: SUPPORTED_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect(),
            plans,
            transport: Arc::clone(&options.transport),
            hello_timeout: options.hello_timeout,
            hubs: Mutex::new(BTreeMap::new()),
            forwards: Mutex::new(None),
            socks_addr: Mutex::new(None),
            shutdown,
        });

        Ok(Arc::new(Node {
            config,
            runtime,
            socks_listen,
            socks_config,
        }))
    }

    /// The shared runtime, for callers that need a [`FlowOpener`].
    pub fn runtime(&self) -> &Arc<NodeRuntime> {
        &self.runtime
    }

    /// The configured Hub entries, in failover order.
    pub fn hub_ids(&self) -> Vec<String> {
        self.runtime.hub_ids()
    }

    /// Connects every configured Hub, then starts the local entry points.
    ///
    /// A Hub that cannot be reached is recorded and skipped, so a partial
    /// deployment still serves traffic; the call only fails when *no* Hub could
    /// be reached, and then with the first Hub's error.
    pub async fn start(self: &Arc<Self>) -> Result<(), NodeError> {
        let mut connected = 0usize;
        let mut first_error: Option<NodeError> = None;
        for hub_id in self.runtime.hub_ids() {
            match self.runtime.connect_hub(&hub_id).await {
                Ok(_) => {
                    connected += 1;
                    info!(hub = %hub_id, "hub session ready");
                }
                Err(error) => {
                    warn!(hub = %hub_id, %error, "hub session unavailable");
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if connected == 0 {
            return Err(first_error.unwrap_or(NodeError::NoHub));
        }
        self.start_socks().await?;
        self.start_forwards()?;
        Ok(())
    }

    /// Connects one Hub by id, without starting the local entry points.
    pub async fn connect_hub(&self, hub_id: &str) -> Result<Arc<HubSession>, NodeError> {
        self.runtime.connect_hub(hub_id).await
    }

    /// The live session for a Hub.
    pub fn session(&self, hub_id: &str) -> Option<Arc<HubSession>> {
        self.runtime.hub(hub_id)
    }

    /// The local SOCKS5 address actually bound.
    pub fn socks_addr(&self) -> Option<SocketAddr> {
        self.runtime.socks_addr()
    }

    /// The bound address of one Local Forward, including an OS-assigned port.
    pub fn forward_addr(&self, name: &str) -> Option<SocketAddr> {
        self.runtime
            .forwards()
            .and_then(|manager| manager.listen_addr(name))
    }

    /// Opens one flow with automatic Hub selection.
    pub async fn open_flow(
        &self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
    ) -> Result<SessionStream, NodeError> {
        self.runtime
            .open_flow(destination, proto, via, HubChoice::Auto)
            .await
    }

    /// Closes one Hub's session, deliberately taking it out of service.
    ///
    /// Existing streams on that Hub fail explicitly; nothing is migrated
    /// (DESIGN.md section 5.5).
    pub fn mark_hub_offline(&self, hub_id: &str) -> Result<(), NodeError> {
        let session = self
            .runtime
            .hub(hub_id)
            .ok_or_else(|| NodeError::UnknownHub {
                hub_id: hub_id.to_string(),
            })?;
        session.close("taken out of service locally");
        Ok(())
    }

    /// Binds and serves the inbound SOCKS5 listener.
    async fn start_socks(self: &Arc<Self>) -> Result<(), NodeError> {
        let listener = TcpListener::bind(self.socks_listen).await?;
        let opener: Arc<dyn FlowOpener> = self.runtime.clone();
        let server = Socks5Server::new(
            listener,
            SocksBridge::new(opener),
            self.socks_config.clone(),
        )?;
        let local = server.local_addr()?;
        *lock(&self.runtime.socks_addr) = Some(local);
        info!(listen = %local, "socks5 listener started");
        tokio::spawn(async move {
            if let Err(error) = server.run().await {
                warn!(%error, "socks5 listener stopped");
            }
        });
        Ok(())
    }

    /// Binds and serves every configured Local Forward listener.
    fn start_forwards(self: &Arc<Self>) -> Result<(), NodeError> {
        if self.config.forwards.is_empty() {
            return Ok(());
        }
        let opener: Arc<dyn FlowOpener> = self.runtime.clone();
        let mut bridge = ForwardBridge::new(opener);
        let mut specs = Vec::with_capacity(self.config.forwards.len());
        for forward in &self.config.forwards {
            let spec = spec_of(forward).ok_or_else(|| {
                NodeError::Config(ConfigError::MissingDestination {
                    field: format!("forwards.{}.destination", forward.name),
                })
            })?;
            bridge = bridge.with_hub(&spec.destination, choice_of(&forward.hub));
            specs.push(spec);
        }
        let mut manager = ForwardManager::new(Arc::new(bridge));
        for spec in specs {
            let handle = manager.add(spec)?;
            info!(forward = %handle.name(), listen = %handle.listen_addr(), "local forward bound");
        }
        let manager = Arc::new(manager);
        *lock(&self.runtime.forwards) = Some(Arc::clone(&manager));
        tokio::spawn(manager.run(self.runtime.subscribe()));
        Ok(())
    }

    /// Stops every background task this node started.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
        for hub_id in self.runtime.hub_ids() {
            if let Some(session) = self.runtime.hub(&hub_id) {
                session.close("node shutdown");
            }
        }
    }

    /// The `[[forwards]]` entries this node was built from.
    pub fn forward_configs(&self) -> &[ForwardConfig] {
        &self.config.forwards
    }
}

/// Builds the inbound SOCKS5 policy from the client configuration.
///
/// `loopback_only` is cleared deliberately: DESIGN.md section 9.3 permits a
/// non-loopback listener once credentials *and* a source allowlist are present,
/// and `SocksConfig` then enforces exactly that pair.
fn build_socks_config(
    config: &ClientConfig,
    options: &NodeOptions,
    listen: SocketAddr,
) -> Result<SocksConfig, NodeError> {
    let allowlist: Result<Vec<IpPrefix>, SocksError> = config
        .client
        .allow_from
        .iter()
        .map(|entry| IpPrefix::from_str(entry))
        .collect();
    let mut socks = SocksConfig::new();
    socks.loopback_only = false;
    socks.udp_enabled = false;
    socks.userpass = options.socks_userpass.clone();
    socks.source_allowlist = allowlist?;
    match socks.validate_for(listen) {
        Ok(()) => Ok(socks),
        Err(SocksError::NonLoopbackListen(address))
        | Err(SocksError::UnsafeListenAddress(address)) => {
            Err(NodeError::UnsafeSocksListen(address))
        }
        Err(other) => Err(NodeError::Socks(other)),
    }
}

/// Parses `host:port`, accepting the bracketed IPv6 form.
///
/// Only an IP literal is accepted, because the loopback decision of DESIGN.md
/// section 9.3 must be made without a resolver: a name could resolve to a
/// non-loopback address after the check.
fn parse_listen(text: &str) -> Result<SocketAddr, NodeError> {
    if let Ok(address) = text.parse::<SocketAddr>() {
        return Ok(address);
    }
    let (host, port) = text.rsplit_once(':').ok_or_else(|| {
        NodeError::Config(ConfigError::InvalidListen {
            field: "client.socks_listen".to_string(),
            value: text.to_string(),
        })
    })?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().map_err(|_| {
        NodeError::Config(ConfigError::InvalidListen {
            field: "client.socks_listen".to_string(),
            value: text.to_string(),
        })
    })?;
    let ip = host.parse::<std::net::IpAddr>().map_err(|_| {
        NodeError::Config(ConfigError::InvalidListen {
            field: "client.socks_listen".to_string(),
            value: text.to_string(),
        })
    })?;
    Ok(SocketAddr::new(ip, port))
}

/// Reads a pre-shared key from a file.
///
/// Two representations are accepted, because both are natural for an operator to
/// produce: 64 hex characters with optional surrounding whitespace, or exactly
/// 32 raw bytes. Anything else is refused rather than hashed into a key, so a
/// truncated secret cannot silently become a different one.
fn read_psk(path: &std::path::Path) -> Result<Psk, String> {
    let raw = std::fs::read(path).map_err(|error| error.to_string())?;
    let compact: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.len() == PSK_LEN * 2 && compact.iter().all(u8::is_ascii_hexdigit) {
        let decoded = hex::decode(&compact).map_err(|error| error.to_string())?;
        return Psk::try_from_slice(&decoded).map_err(|error| error.to_string());
    }
    if raw.len() == PSK_LEN {
        return Psk::try_from_slice(&raw).map_err(|error| error.to_string());
    }
    Err(format!(
        "expected {PSK_LEN} raw bytes or {} hex characters",
        PSK_LEN * 2
    ))
}

/// The section 5.5 error for a destination no Hub can serve.
fn offline_error(destination: &Destination) -> NodeError {
    match destination {
        Destination::Service { node, name, .. } => NodeError::Offline(format!(
            "no ready hub advertises service `{name}` of node `{node}`"
        )),
        Destination::NodeAddress { node, .. } => {
            NodeError::Offline(format!("node `{node}` is not reachable on any ready hub"))
        }
        Destination::Address { .. } => NodeError::NoHub,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hub::cached_outcome_error;
    use std::net::{IpAddr, Ipv4Addr};

    fn client_config(socks_listen: &str, allow_from: Vec<String>) -> ClientConfig {
        let mut config = ClientConfig::default();
        config.client.node_id = "client-a".to_string();
        config.client.socks_listen = socks_listen.to_string();
        config.client.allow_from = allow_from;
        config
    }

    /// Section 9.3: a non-loopback listener without credentials and an allowlist
    /// must be refused at construction.
    #[test]
    fn a_bare_non_loopback_socks_listener_is_refused() {
        let config = client_config("0.0.0.0:1080", Vec::new());
        let error = Node::build(config, NodeOptions::default()).err().unwrap();
        assert!(matches!(error, NodeError::UnsafeSocksListen(_)), "{error}");

        // Credentials alone are not enough.
        let config = client_config("0.0.0.0:1080", Vec::new());
        let options = NodeOptions::default()
            .with_socks_credentials(UserPass::new("alice", "s3cret").unwrap());
        let error = Node::build(config, options).err().unwrap();
        assert!(matches!(error, NodeError::UnsafeSocksListen(_)), "{error}");

        // An allowlist alone is not enough either.
        let config = client_config("0.0.0.0:1080", vec!["10.0.0.0/8".to_string()]);
        let error = Node::build(config, NodeOptions::default()).err().unwrap();
        assert!(matches!(error, NodeError::UnsafeSocksListen(_)), "{error}");
    }

    /// Both protections together are what section 9.3 asks for.
    #[test]
    fn a_protected_non_loopback_socks_listener_is_accepted() {
        let config = client_config("0.0.0.0:1080", vec!["10.0.0.0/8".to_string()]);
        let options = NodeOptions::default()
            .with_socks_credentials(UserPass::new("alice", "s3cret").unwrap());
        assert!(Node::build(config, options).is_ok());
    }

    /// A loopback listener needs neither, because the bind address is the
    /// allowlist.
    #[test]
    fn a_loopback_socks_listener_needs_nothing_extra() {
        let config = client_config("127.0.0.1:1080", Vec::new());
        assert!(Node::build(config, NodeOptions::default()).is_ok());
    }

    /// The section 9.3 check runs before schema validation, so that is the error
    /// an operator sees for this mistake.
    #[test]
    fn the_listener_check_precedes_document_validation() {
        let config = client_config("0.0.0.0:1080", Vec::new());
        let error = Node::build(config, NodeOptions::default()).err().unwrap();
        assert!(matches!(error, NodeError::UnsafeSocksListen(_)));
    }

    #[test]
    fn listen_addresses_are_parsed_without_a_resolver() {
        assert_eq!(
            parse_listen("127.0.0.1:1080").unwrap(),
            "127.0.0.1:1080".parse().unwrap()
        );
        assert_eq!(
            parse_listen("[::1]:1080").unwrap(),
            SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 1080)
        );
        assert!(parse_listen("localhost:1080").is_err());
        assert!(parse_listen("127.0.0.1").is_err());
        assert_eq!(
            parse_listen("0.0.0.0:0").unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );
    }

    /// Hub entries are tried in ascending priority (DESIGN.md section 8).
    #[test]
    fn hubs_are_ordered_by_priority() {
        let mut config = client_config("127.0.0.1:1080", Vec::new());
        config.servers = vec![
            wsnet_config::ServerEntry {
                hub_id: "hub-b".to_string(),
                url: "https://b.example.com".to_string(),
                key_id: "a-2".to_string(),
                secret_file: PathBuf::from("b.key"),
                priority: 2,
            },
            wsnet_config::ServerEntry {
                hub_id: "hub-a".to_string(),
                url: "https://a.example.com".to_string(),
                key_id: "a-1".to_string(),
                secret_file: PathBuf::from("a.key"),
                priority: 1,
            },
        ];
        let node = Node::build(config, NodeOptions::default()).unwrap();
        assert_eq!(node.hub_ids(), vec!["hub-a", "hub-b"]);
    }

    /// A `request_id` that was already settled is answered from the cache.
    #[test]
    fn cached_outcomes_never_dial_again() {
        use wsnet_operation::Outcome;
        let request_id = [0xab; 16];
        let duplicate = cached_outcome_error(request_id, Outcome::Complete(vec![1, 2, 3]));
        assert!(matches!(duplicate, NodeError::DuplicateOpen { .. }));
        assert!(duplicate.to_string().contains(&hex::encode(request_id)));

        let cached = cached_outcome_error(request_id, Outcome::Failed(b"refused".to_vec()));
        assert!(matches!(cached, NodeError::CachedFailure { .. }));
    }
}
