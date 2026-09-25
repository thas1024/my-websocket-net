//! WebSocket-carrier acceptance: the node reaches a Hub over `GET /w` alone.
//!
//! DESIGN.md section 6.1 allows client-to-server data over a WebSocket *or* over
//! HTTPS `POST`, and section 6.2 allows server-to-client data over a WebSocket,
//! SSE, or a bounded `POST` response. The shipped node used only the `POST /m`
//! plus `GET /e` pair, which left a deployment that disables `POST /m` with no
//! carrier at all. This test pins the other choice end to end:
//!
//! ```text
//!   tcp client -> node's forward listener -> node
//!              -> Hub's GET /w (both directions) -> Hub exit -> echo target
//! ```
//!
//! Nothing here is stubbed and nothing is faked: one real Hub and one real node
//! run in this process, the node is built with the WebSocket factory, and the
//! assertion is that bytes written by an ordinary TCP client come back. If the
//! bootstrap exchange, the bound upgrade and its `BindProof`, the Binary record
//! framing, or the close propagation regress, this fails — and a regression in
//! "does the Hub accept a WebSocket at all" shows up as the session never
//! reaching Ready.
//!
//! The Hub is left with its default `[[acl]]` posture except for the one rule the
//! flow needs: a loopback destination is only reachable through an explicit
//! `connect_address` rule naming its `host_cidr`, which is why the test writes
//! that rule rather than relying on the address being local.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use wsnet_config::{ClientConfig, ServerConfig};
use wsnet_hub::{Hub, NodeSecrets};
use wsnet_node::{Node, NodeOptions, WsTransportFactory};

const PSK: [u8; 32] = [0x5A; 32];

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
    dir.push(format!("wsnet-ws-carrier-{}", std::process::id()));
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
            "the node never reached Ready on {hub_id} over the websocket carrier"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A forward carried entirely by `GET /w` echoes a client's bytes back.
#[tokio::test]
async fn a_forward_is_carried_over_the_websocket_carrier() {
    init_tracing();
    let scratch = scratch_dir();
    let key_path = scratch.join("node.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");

    let target = spawn_echo_target().await;
    let target_port = target.port();

    // --- Hub -----------------------------------------------------------------
    let hub_listener = bound_loopback().await;
    let hub_port = hub_listener.local_addr().expect("hub addr").port();

    let server_toml = format!(
        r#"
[server]
hub_id = "hub-ws"
listen = "127.0.0.1:{hub_port}"
relay_allow = []

[[nodes]]
id = "node-ws"
key_id = "ws-1"
secret_file = "{key}"

# A loopback destination is only reachable through an explicit address rule, so
# the flow this test asserts needs one; everything else stays default-deny.
[[acl]]
caller = "node-ws"
action = "connect_address"
host_cidr = "127.0.0.1/32"
allow = true
"#,
        key = toml_path(&key_path)
    );

    let server_config =
        ServerConfig::from_toml(&server_toml).expect("the server configuration must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // --- node ----------------------------------------------------------------
    let socks = free_port().await;
    let client_toml = format!(
        r#"
[client]
node_id = "node-ws"
socks_listen = "127.0.0.1:{socks}"
carrier = "ws"

[[servers]]
hub_id = "hub-ws"
url = "http://127.0.0.1:{hub_port}"
key_id = "ws-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"

# The destination is a raw address in the Hub's own view, which the Hub dials;
# the node never reaches the target itself on this path.
[[forwards]]
name = "to-echo"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
destination = {{ type = "address", host = "127.0.0.1", port = {target_port} }}
"#,
        key = toml_path(&key_path)
    );

    let client_config =
        ClientConfig::from_toml(&client_toml).expect("the client configuration must parse");
    // The carrier is forced to the WebSocket factory rather than trusted to the
    // document, so this test cannot pass by silently using `POST /m`.
    let options = NodeOptions::default().with_transport(Arc::new(WsTransportFactory::new()));
    let node = Node::build(client_config, options).expect("the node must build");
    node.start().await.expect("the node must start");

    // Reaching Ready means the Hub accepted the `Auth` bootstrap *and* the bound
    // upgrade, because the node sends `Hello` only after both.
    wait_until_ready(&node, "hub-ws").await;
    assert_eq!(
        hub.session_count(),
        1,
        "the Hub must hold exactly the session this node authenticated over GET /w"
    );

    // --- the actual assertion ------------------------------------------------
    let listen = node
        .forward_addr("to-echo")
        .expect("the forward listener must be bound");

    let payload = b"websocket carrier";
    let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
        .await
        .expect("connecting to the forward timed out")
        .expect("the forward listener must accept");

    client.write_all(payload).await.expect("write payload");
    client.flush().await.expect("flush payload");

    let mut echoed = vec![0u8; payload.len()];
    timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
        .await
        .expect("the echo timed out: the websocket carrier did not carry bytes")
        .expect("the echo must arrive");
    assert_eq!(
        &echoed, payload,
        "bytes must survive node -> GET /w -> Hub exit -> echo target and back"
    );

    // Section 5.5's periodic liveness check must be non-destructive on this
    // carrier: the Hub ends a session when a *bound* `GET /w` socket ends, so a
    // health check that opened and dropped a second upgrade would kill the very
    // session it was checking. Probing the carrier in place has to leave both the
    // session and the Hub's lease intact.
    let session = node.session("hub-ws").expect("the session must exist");
    timeout(Duration::from_secs(10), session.health_check())
        .await
        .expect("the health check must not hang")
        .expect("the health check must succeed on a live websocket carrier");
    assert!(
        session.is_ready(),
        "a health check must not end the session"
    );
    assert_eq!(
        hub.session_count(),
        1,
        "the Hub must still hold the session after a health check"
    );

    // A second connection proves the first flow did not consume the carrier, and
    // that the health check left it working.
    let second = b"again";
    let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
        .await
        .expect("second connect timed out")
        .expect("the forward must accept again");
    client.write_all(second).await.expect("write payload");
    let mut echoed = vec![0u8; second.len()];
    timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
        .await
        .expect("the second echo timed out")
        .expect("the second echo must arrive");
    assert_eq!(&echoed, second);

    node.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}
