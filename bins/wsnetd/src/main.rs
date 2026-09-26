//! `wsnetd` - the wsnet Hub daemon (USAGE.md sections 2 and 3.1).
//!
//! The Hub is the loopback backend that nginx terminates TLS in front of, so it
//! refuses any non-loopback `listen` address and says so at startup rather than
//! binding an interface it should not own (DESIGN.md section 9.3).
//!
//! ```text
//! wsnetd check --config /etc/wsnet/server.toml
//! wsnetd serve --config /etc/wsnet/server.toml
//! ```

#![forbid(unsafe_code)]

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use wsnet_config::ServerConfig;
use wsnet_hub::{Hub, NodeSecrets};

#[derive(Debug, Parser)]
#[command(name = "wsnetd", version, about = "wsnet Hub daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse and validate the configuration, then exit without binding anything.
    Check {
        /// Path to `server.toml`.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Run the Hub until interrupted.
    Serve {
        /// Path to `server.toml`.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        // Colour only when a person is watching. A Hub is normally run under a
        // supervisor with its output in a file, and an escape sequence in the middle
        // of `carrier=...` turns a log line into something grep cannot find.
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    match Cli::parse().command {
        Command::Check { config } => check(&config),
        Command::Serve { config } => serve(&config).await,
    }
}

/// Validates the configuration and reports what would be served.
///
/// `check` deliberately binds nothing: an operator runs it before a restart, and
/// a successful check must not collide with the instance that is still running.
fn check(path: &Path) -> anyhow::Result<()> {
    let config = ServerConfig::load_from_path(path)
        .with_context(|| format!("loading {}", path.display()))?;
    // Resolving the secrets here means a missing or malformed key file is
    // reported by `check` rather than only at the first authentication.
    let secrets = NodeSecrets::from_server_config(&config).context("loading node secrets")?;

    // Building the Hub is the only way to know whether the ACL, the nonce store,
    // and the listen address are all acceptable, so `check` builds one too.
    let hub = Hub::new(config, secrets).context("the Hub would refuse to start")?;

    println!("configuration is valid");
    println!("  hub id        : {}", hub.hub_id());
    println!("  listen        : {}", hub.listen());
    println!("  nodes         : {}", hub.config().nodes.len());
    println!("  acl rules     : {}", hub.config().acl.len());
    println!("  profile paths : {}", hub.profiles().entries().len());
    Ok(())
}

/// Runs the Hub.
async fn serve(path: &Path) -> anyhow::Result<()> {
    let config = ServerConfig::load_from_path(path)
        .with_context(|| format!("loading {}", path.display()))?;
    let secrets = NodeSecrets::from_server_config(&config).context("loading node secrets")?;
    let hub = Arc::new(Hub::new(config, secrets).context("the Hub refused to start")?);

    let listen = hub.listen();
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;

    tracing::info!(
        hub = hub.hub_id(),
        %listen,
        "wsnet Hub listening; nginx is expected to terminate TLS in front of this address"
    );

    tokio::select! {
        result = Arc::clone(&hub).serve(listener) => {
            result.context("the Hub server stopped")?;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("interrupted; stopping");
        }
    }
    Ok(())
}
