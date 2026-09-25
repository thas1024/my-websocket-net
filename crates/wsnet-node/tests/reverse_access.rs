//! Reverse-access acceptance: a caller reaches a publisher's local service.
//!
//! This is the path USAGE.md section 5.1 documents, and the one DESIGN.md
//! section 7.6 makes the primary way to reach a named service:
//!
//! ```text
//!   application -> caller's forward listener -> caller node
//!               -> Hub -> publisher node -> publisher's local target
//! ```
//!
//! Nothing here is stubbed. One real Hub and two real nodes run in this process,
//! each with its own identity and its own secret; the caller reaches the service
//! through a `[[forwards]]` entry using a `ServiceTarget`, and the assertion is
//! that bytes written by an ordinary TCP client are echoed back by a listener the
//! *publisher* dialled. If the Hub's relay, the publisher's inbound-`Open`
//! handling, the ACL, or the local service resolution regresses, this fails.
//!
//! Note that the Hub never dials the target and the publisher never talks to the
//! caller directly: every byte crosses the Hub, which is what makes the two
//! halves of the feature separately meaningful.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use wsnet_config::{ClientConfig, ServerConfig};
use wsnet_hub::{Hub, NodeSecrets};
use wsnet_node::{Node, NodeOptions};

const PSK: [u8; 32] = [0x6B; 32];

/// Installs a tracing subscriber once per test binary.
///
/// Without this a hung acceptance test produces no output at all, which is the
/// difference between a five-minute diagnosis and an afternoon.
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

fn scratch_dir() -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("wsnet-reverse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// A path in the form TOML needs on Windows: a backslash in a basic string is an
/// escape sequence, not a separator.
fn toml_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "/")
}

async fn bound_loopback() -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback")
}

async fn free_port() -> u16 {
    let listener = bound_loopback().await;
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// An echo target: whatever it reads, it writes straight back.
async fn spawn_echo_target() -> std::net::SocketAddr {
    let listener = bound_loopback().await;
    let addr = listener.local_addr().expect("target addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                if let Ok(read) = socket.read(&mut buffer).await {
                    if read > 0 {
                        let _ = socket.write_all(&buffer[..read]).await;
                        let _ = socket.flush().await;
                    }
                }
                let _ = socket.shutdown().await;
            });
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

/// A caller reaches a publisher's published service through Local Forward.
#[tokio::test]
async fn a_caller_reaches_a_publishers_service_through_local_forward() {
    init_tracing();
    let scratch = scratch_dir();
    let key_path = scratch.join("publisher.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");

    // The publisher will serve this local target; it must exist before the
    // publisher's configuration can name it.
    let target = spawn_echo_target().await;

    // --- Hub -----------------------------------------------------------------
    let hub_listener = bound_loopback().await;
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

# The caller may reach the publisher's named service. No address rule is needed:
# the publisher dials its own target, and the Hub never dials on this path.
[[acl]]
caller = "caller"
action = "connect_service"
node = "publisher"
service = "web"
allow = true
"#,
        key = toml_path(&key_path)
    );

    let server_config =
        ServerConfig::from_toml(&server_toml).expect("the server configuration must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // --- publisher -----------------------------------------------------------
    let publisher_socks = free_port().await;
    let publisher_toml = format!(
        r#"
[client]
node_id = "publisher"
socks_listen = "127.0.0.1:{publisher_socks}"
udp_enabled = false

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "pub-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"

# The service the caller will reach. The target is local configuration; a caller
# can never override it.
[[services]]
name = "web"
proto = "tcp"
target = "{target}"
"#,
        key = toml_path(&key_path),
        target = target
    );

    let publisher_config =
        ClientConfig::from_toml(&publisher_toml).expect("the publisher configuration must parse");
    let publisher = Node::build(publisher_config, NodeOptions::default())
        .expect("the publisher node must build");
    publisher.start().await.expect("the publisher must start");
    wait_until_ready(&publisher, "hub-a").await;

    // --- caller --------------------------------------------------------------
    let caller_socks = free_port().await;
    let caller_toml = format!(
        r#"
[client]
node_id = "caller"
socks_listen = "127.0.0.1:{caller_socks}"
udp_enabled = false

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "call-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"

# USAGE.md section 5.1: the forward names a node and a service, never an address.
[[forwards]]
name = "to-web"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
via = []
destination = {{ type = "service", node = "publisher", name = "web" }}
"#,
        key = toml_path(&key_path)
    );

    let caller_config =
        ClientConfig::from_toml(&caller_toml).expect("the caller configuration must parse");
    let caller =
        Node::build(caller_config, NodeOptions::default()).expect("the caller node must build");
    caller.start().await.expect("the caller must start");
    wait_until_ready(&caller, "hub-a").await;

    // --- the actual assertion ------------------------------------------------
    let listen = caller
        .forward_addr("to-web")
        .expect("the caller's forward listener must be bound");

    let payload = b"reverse access";
    let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
        .await
        .expect("connecting to the forward timed out")
        .expect("the forward listener must accept");

    client.write_all(payload).await.expect("write payload");
    client.flush().await.expect("flush payload");

    let mut echoed = vec![0u8; payload.len()];
    timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
        .await
        .expect("the echo timed out: the reverse path did not carry bytes")
        .expect("the echo must arrive");
    assert_eq!(
        &echoed, payload,
        "bytes must survive caller -> Hub -> publisher -> local target and back"
    );

    caller.shutdown();
    publisher.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// A second connection over the same forward must also work, so a completed
/// stream did not consume the forward or the publisher's service.
#[tokio::test]
async fn the_forward_keeps_working_for_later_connections() {
    init_tracing();
    let scratch = scratch_dir();
    let key_path = scratch.join("publisher.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let target = spawn_echo_target().await;

    let hub_listener = bound_loopback().await;
    let hub_port = hub_listener.local_addr().expect("hub addr").port();

    let server_toml = format!(
        r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:{hub_port}"

[[nodes]]
id = "publisher"
key_id = "pub-1"
secret_file = "{key}"

[[nodes]]
id = "caller"
key_id = "call-1"
secret_file = "{key}"

[[acl]]
caller = "caller"
action = "connect_service"
node = "publisher"
service = "web"
allow = true
"#,
        key = toml_path(&key_path)
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("server config");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("secrets");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("hub"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    let publisher_socks = free_port().await;
    let publisher_toml = format!(
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
"#,
        key = toml_path(&key_path),
        target = target
    );
    let publisher = Node::build(
        ClientConfig::from_toml(&publisher_toml).expect("publisher config"),
        NodeOptions::default(),
    )
    .expect("publisher");
    publisher.start().await.expect("start publisher");
    wait_until_ready(&publisher, "hub-a").await;

    let caller_socks = free_port().await;
    let caller_toml = format!(
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

[[forwards]]
name = "to-web"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
destination = {{ type = "service", node = "publisher", name = "web" }}
"#,
        key = toml_path(&key_path)
    );
    let caller = Node::build(
        ClientConfig::from_toml(&caller_toml).expect("caller config"),
        NodeOptions::default(),
    )
    .expect("caller");
    caller.start().await.expect("start caller");
    wait_until_ready(&caller, "hub-a").await;

    let listen = caller.forward_addr("to-web").expect("forward listener");

    for round in 0..3u8 {
        let payload = [b'0' + round; 6];
        let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
            .await
            .expect("connect timed out")
            .expect("the forward must accept");
        client.write_all(&payload).await.expect("write");
        let mut echoed = vec![0u8; payload.len()];
        timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
            .await
            .expect("read timed out")
            .expect("read");
        assert_eq!(echoed, payload, "round {round} must echo correctly");
    }

    caller.shutdown();
    publisher.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// A raw node address works only when the publisher's own allowlist names it.
///
/// This is the wiring test for `client.allow_node_address`: the `resolve_inbound`
/// unit tests cover the predicate, and this covers the path from configuration,
/// through the node, into the inbound policy. DESIGN.md section 9.3 makes the
/// publisher's own check the second gate, so the Hub's ACL permitting the
/// address is not by itself enough.
#[tokio::test]
async fn a_publishers_allowlist_admits_an_explicit_node_address() {
    init_tracing();
    let scratch = scratch_dir();
    let key_path = scratch.join("publisher.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");

    let target = spawn_echo_target().await;
    let target_port = target.port();

    let hub_listener = bound_loopback().await;
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

# The Hub's gate: this caller may reach that address in the publisher's view.
[[acl]]
caller = "caller"
action = "connect_node_address"
node = "publisher"
host_cidr = "127.0.0.1/32"
ports = [{target_port}]
proto = "tcp"
allow = true
"#,
        key = toml_path(&key_path)
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("server config");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("secrets");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("hub"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // The publisher's own gate: without this list the address stays denied, and
    // this is the configuration field the test exists to exercise.
    let publisher_socks = free_port().await;
    let publisher_toml = format!(
        r#"
[client]
node_id = "publisher"
socks_listen = "127.0.0.1:{publisher_socks}"
allow_node_address = ["127.0.0.1/32"]

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "pub-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#,
        key = toml_path(&key_path)
    );
    let publisher = Node::build(
        ClientConfig::from_toml(&publisher_toml).expect("publisher config"),
        NodeOptions::default(),
    )
    .expect("publisher");
    publisher.start().await.expect("start publisher");
    wait_until_ready(&publisher, "hub-a").await;

    let caller_socks = free_port().await;
    let caller_toml = format!(
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

[[forwards]]
name = "to-addr"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
destination = {{ type = "node_address", node = "publisher", host = "127.0.0.1", port = {target_port} }}
"#,
        key = toml_path(&key_path)
    );
    let caller = Node::build(
        ClientConfig::from_toml(&caller_toml).expect("caller config"),
        NodeOptions::default(),
    )
    .expect("caller");
    caller.start().await.expect("start caller");
    wait_until_ready(&caller, "hub-a").await;

    let listen = caller
        .forward_addr("to-addr")
        .expect("the caller's forward listener must be bound");

    let payload = b"raw address";
    let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
        .await
        .expect("connect timed out")
        .expect("the forward must accept");
    client.write_all(payload).await.expect("write");
    let mut echoed = vec![0u8; payload.len()];
    timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
        .await
        .expect("the echo timed out: the allowlisted address was not reached")
        .expect("the echo must arrive");
    assert_eq!(&echoed, payload);

    caller.shutdown();
    publisher.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}
