//! The Hub's `PeerList` snapshot, end to end (DESIGN.md sections 4.1, 5.5, 8).
//!
//! Section 8 makes the Hub tell each node what that node may discover. Until this
//! test existed the *stub* Hub sent `PeerList` and the real Hub never did, so the
//! node's `ServiceDirectory` stayed unknown in every real deployment and
//! `wsnet services list` could only ever report the node's own publications.
//!
//! One real Hub and three real nodes run here:
//!
//! * `publisher` registers a service named `web`;
//! * `caller` has a `connect_service` rule for it;
//! * `stranger` has no rule at all.
//!
//! The assertions are that the caller's directory learns the service without any
//! restart, that the stranger's directory stays empty (section 9.3: the snapshot is
//! filtered by the caller's ACL, so an unlisted service is indistinguishable from
//! an absent one), and that the service disappears again when the publisher's
//! lease is released.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wsnet_config::{ClientConfig, ServerConfig};
use wsnet_hub::{Hub, NodeSecrets};
use wsnet_node::{Node, NodeOptions, ServiceDirectory};
use wsnet_routing::Proto;

const PSK: [u8; 32] = [0x5C; 32];

/// Installs a tracing subscriber once per test binary, so a hang speaks.
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
            )
            .with_test_writer()
            .try_init();
    });
}

fn psk_hex() -> String {
    PSK.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn scratch_dir(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("wsnet-peer-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// A path in the form TOML needs on Windows: a backslash in a basic string is an
/// escape sequence, not a separator.
fn toml_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "/")
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    listener.local_addr().expect("local addr").port()
}

/// An echo target, so the publisher's service names something real.
async fn spawn_echo_target() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo target");
    let addr = listener.local_addr().expect("target addr");
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            drop(socket);
        }
    });
    addr
}

async fn wait_until_ready(node: &Arc<Node>, hub_id: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        if node
            .session(hub_id)
            .is_some_and(|session| session.is_ready())
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the node never reached Ready on {hub_id}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Waits for a directory to satisfy `condition`, or fails with the last value.
async fn wait_for_directory(
    node: &Arc<Node>,
    hub_id: &str,
    what: &str,
    mut condition: impl FnMut(&ServiceDirectory) -> bool,
) -> ServiceDirectory {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(directory) = node.directory(hub_id) {
            if condition(&directory) {
                return directory;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the directory never became {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Builds one node from a TOML document and starts it.
async fn start_node(document: &str) -> Arc<Node> {
    let config = ClientConfig::from_toml(document).expect("the client configuration must parse");
    let node = Node::build(config, NodeOptions::default()).expect("the node must build");
    node.start().await.expect("the node must start");
    wait_until_ready(&node, "hub-a").await;
    node
}

#[tokio::test]
async fn the_hub_tells_a_permitted_caller_what_it_may_reach() {
    init_tracing();
    let scratch = scratch_dir("advertise");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);
    let target = spawn_echo_target().await;

    let hub_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hub");
    let hub_port = hub_listener.local_addr().expect("hub addr").port();

    let server_toml = format!(
        r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:{hub_port}"
relay_allow = []

[[nodes]]
id = "publisher"
key_id = "pub-1"
secret_file = "{key}"

[[nodes]]
id = "caller"
key_id = "call-1"
secret_file = "{key}"

[[nodes]]
id = "stranger"
key_id = "str-1"
secret_file = "{key}"

# Only `caller` may discover or reach the service. `stranger` has no rule, so the
# Hub must not even tell it that the service exists.
[[acl]]
caller = "caller"
action = "connect_service"
node = "publisher"
service = "web"
allow = true
"#
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("the server must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // --- publisher -----------------------------------------------------------
    let publisher_socks = free_port().await;
    let publisher = start_node(&format!(
        r#"
[client]
node_id = "publisher"
socks_listen = "127.0.0.1:{publisher_socks}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "pub-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"

[[services]]
name = "web"
proto = "tcp"
target = "{target}"
"#
    ))
    .await;

    // --- caller --------------------------------------------------------------
    let caller_socks = free_port().await;
    let caller = start_node(&format!(
        r#"
[client]
node_id = "caller"
socks_listen = "127.0.0.1:{caller_socks}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "call-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    ))
    .await;

    let directory = wait_for_directory(&caller, "hub-a", "aware of `web`", |directory| {
        directory.contains("publisher", "web")
    })
    .await;
    assert!(directory.is_known(), "a received snapshot is a known one");
    let advertised: Vec<_> = directory.advertisements().collect();
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].0, "publisher");
    assert_eq!(advertised[0].1, "web");
    assert_eq!(advertised[0].2.proto, Some(Proto::Tcp));
    assert_eq!(
        advertised[0].2.revision,
        Some(1),
        "the Hub must report the revision the lease actually holds"
    );
    let first_revision = directory.revision().expect("a versioned snapshot");

    // --- stranger ------------------------------------------------------------
    let stranger_socks = free_port().await;
    let stranger = start_node(&format!(
        r#"
[client]
node_id = "stranger"
socks_listen = "127.0.0.1:{stranger_socks}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "str-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    ))
    .await;

    let stranger_directory =
        wait_for_directory(&stranger, "hub-a", "known", |directory| directory.is_known()).await;
    assert!(
        stranger_directory.is_empty(),
        "section 9.3: a caller with no rule must not be told the service exists, got {:?}",
        stranger_directory.entries().collect::<Vec<_>>()
    );
    assert!(stranger_directory
        .advertisements()
        .next()
        .is_none());

    // --- withdrawal ----------------------------------------------------------
    // Releasing the lease is a directory change, so every remaining session gets a
    // newer snapshot rather than keeping a stale entry until it reconnects.
    publisher
        .mark_hub_offline("hub-a")
        .expect("the publisher must have a live session");

    let after = wait_for_directory(&caller, "hub-a", "aware that `web` is gone", |directory| {
        !directory.contains("publisher", "web")
    })
    .await;
    assert!(after.is_empty());
    assert!(
        after.revision().expect("a versioned snapshot") > first_revision,
        "a withdrawal must arrive as a newer revision, not as a rollback"
    );

    caller.shutdown();
    stranger.shutdown();
    publisher.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}
