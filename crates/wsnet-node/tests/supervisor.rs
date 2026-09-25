//! The Hub supervisor: reconnection after a dead Hub, and new-connection
//! failover (DESIGN.md section 5.5).
//!
//! Section 5.5 requires two things of a node with more than one Hub:
//!
//! > 多 Hub 注册与新连接故障转移；跨 Hub 只恢复新连接
//!
//! * a Hub that dies must be re-established rather than left closed, with a
//!   backoff instead of a busy retry;
//! * a *new* connection must move to another Hub while existing ones fail
//!   explicitly, because section 5.5 forbids migrating a live stream.
//!
//! Both are driven here against real Hubs. Nothing is stubbed, so a regression in
//! the supervisor, in the health accounting, or in selection fails these tests
//! rather than passing a unit test of a policy in isolation.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

use wsnet_config::{ClientConfig, ServerConfig};
use wsnet_hub::{Hub, NodeSecrets};
use wsnet_node::{Node, NodeError, NodeOptions};
use wsnet_routing::Destination;
use wsnet_session::OpenStatus;

const PSK: [u8; 32] = [0x71; 32];

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
    dir.push(format!("wsnet-supervisor-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

fn toml_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "/")
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    listener.local_addr().expect("local addr").port()
}

/// Waits until something is listening on `port`, so a test does not race the
/// Hub's own bind.
async fn wait_for_listener(port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "nothing ever listened on 127.0.0.1:{port}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Waits until nothing is listening on `port` any more, so "the Hub is dead" is
/// established by observation rather than by assumption.
async fn wait_for_listener_to_close(port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "something is still listening on 127.0.0.1:{port}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A Hub that owns the runtime its connections live on.
///
/// This matters: `axum::serve` lets hyper spawn one task per connection, so
/// aborting the task that called `serve` would leave every established socket
/// open and the node would never observe the Hub dying. Owning the runtime is
/// what makes "kill the Hub" mean the same thing it means in production — the
/// sockets close.
struct HubProcess {
    port: u16,
    server_toml: String,
    runtime: Option<Runtime>,
}

impl HubProcess {
    /// Starts a Hub on `port` from `server_toml`.
    fn start(port: u16, server_toml: String) -> Self {
        let mut process = HubProcess {
            port,
            server_toml,
            runtime: None,
        };
        process.spawn();
        process
    }

    /// Starts (or restarts) the Hub on its port.
    fn spawn(&mut self) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a hub runtime");
        let toml = self.server_toml.clone();
        let port = self.port;
        runtime.spawn(async move {
            let listener = TcpListener::bind(("127.0.0.1", port))
                .await
                .expect("the hub must bind its port");
            let config = ServerConfig::from_toml(&toml).expect("the hub configuration must parse");
            let secrets =
                NodeSecrets::from_server_config(&config).expect("the hub secrets must load");
            let hub = Arc::new(Hub::new(config, secrets).expect("the hub must start"));
            let _ = hub.serve(listener).await;
        });
        self.runtime = Some(runtime);
    }

    /// Kills the Hub and every connection it owns.
    ///
    /// `Runtime::shutdown_timeout` blocks the calling thread, which panics inside
    /// an async test, so the non-blocking form is used and the caller waits for the
    /// listener to actually stop accepting.
    fn kill(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl Drop for HubProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

async fn wait_until_ready(node: &Arc<Node>, hub_id: &str, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if node
            .session(hub_id)
            .is_some_and(|session| session.is_ready())
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the node never reached Ready on {hub_id} ({what})"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if condition() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// An echo target, so a successful flow is proven by bytes rather than by a
/// status.
async fn spawn_echo_target() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo target");
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

/// A Hub whose only job is to accept one node, with no ACL rules at all.
fn bare_hub_toml(hub_id: &str, port: u16, node_id: &str, key_id: &str, key: &str) -> String {
    format!(
        r#"
[server]
hub_id = "{hub_id}"
listen = "127.0.0.1:{port}"

[[nodes]]
id = "{node_id}"
key_id = "{key_id}"
secret_file = "{key}"
"#
    )
}

/// Section 5.5: a session that was closed deliberately is re-established.
///
/// This is the supervisor's core loop with the *short* path to a decision: the
/// session state is `Closed` immediately, so the supervisor needs only its next
/// keepalive tick. The Hub itself stays up, so the first backoff step is enough and
/// the test does not encode the retry schedule.
#[tokio::test]
async fn a_closed_hub_session_is_re_established_by_the_supervisor() {
    init_tracing();
    let scratch = scratch_dir("reopen");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);

    let port = free_port().await;
    let mut hub = HubProcess::start(port, bare_hub_toml("hub-a", port, "client-a", "a-1", &key));
    wait_for_listener(port).await;

    let socks = free_port().await;
    let client_toml = format!(
        r#"
[client]
node_id = "client-a"
socks_listen = "127.0.0.1:{socks}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{port}"
key_id = "a-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    );
    let config = ClientConfig::from_toml(&client_toml).expect("the client configuration must parse");
    let node = Node::build(config, NodeOptions::default()).expect("the node must build");
    node.start().await.expect("the node must start");
    wait_until_ready(&node, "hub-a", "before the session is closed").await;

    let first = node.session("hub-a").expect("a live session");

    // Section 5.5: taking a Hub out of service locally closes the session. The
    // supervisor is what must bring it back; without it the node would stay
    // offline forever.
    node.mark_hub_offline("hub-a")
        .expect("hub-a must have a live session");
    assert!(!first.is_ready(), "a closed session must not report Ready");

    wait_until(
        || {
            node.session("hub-a")
                .is_some_and(|session| session.is_ready() && !Arc::ptr_eq(&session, &first))
        },
        "the supervisor to re-establish the closed session",
        Duration::from_secs(60),
    )
    .await;

    let second = node.session("hub-a").expect("a live session");
    assert!(
        second.health().is_healthy(),
        "a freshly established session must not start out unhealthy"
    );

    node.shutdown();
    hub.kill();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// Section 5.5: a Hub that dies silently is reconnected, not left closed.
///
/// A Hub that is merely unreachable never announces anything, so the node's only
/// evidence is the authenticated health round trip. §5.5 requires three
/// consecutive failures before the Hub is failed over, and the check runs once per
/// keepalive interval, so this test deliberately takes about a minute: the wait is
/// the design's own failover budget, not test slack.
#[tokio::test]
async fn a_dead_hub_is_reconnected_by_the_supervisor() {
    init_tracing();
    let scratch = scratch_dir("reconnect");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);

    let port = free_port().await;
    let server_toml = bare_hub_toml("hub-a", port, "client-a", "a-1", &key);
    let mut hub = HubProcess::start(port, server_toml.clone());
    wait_for_listener(port).await;

    let socks = free_port().await;
    let client_toml = format!(
        r#"
[client]
node_id = "client-a"
socks_listen = "127.0.0.1:{socks}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{port}"
key_id = "a-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    );
    let config = ClientConfig::from_toml(&client_toml).expect("the client configuration must parse");
    let node = Node::build(config, NodeOptions::default()).expect("the node must build");
    node.start().await.expect("the node must start");
    wait_until_ready(&node, "hub-a", "before the Hub is killed").await;
    let first = node.session("hub-a").expect("a live session");

    // --- kill the Hub --------------------------------------------------------
    hub.kill();
    wait_for_listener_to_close(port).await;

    // The supervisor's health accounting must retire the Hub. Waiting for the
    // withdrawal itself would be a race against the reconnect, so the observable
    // that proves the decision is the health verdict.
    wait_until(
        || {
            node.session("hub-a")
                .is_none_or(|session| !session.health().is_healthy())
        },
        "three failed health checks to retire the dead Hub",
        Duration::from_secs(180),
    )
    .await;

    // --- bring it back -------------------------------------------------------
    hub.spawn();
    wait_for_listener(port).await;

    wait_until(
        || {
            node.session("hub-a").is_some_and(|session| {
                session.is_ready() && !Arc::ptr_eq(&session, &first) && session.health().is_healthy()
            })
        },
        "the supervisor to re-establish the dead Hub",
        Duration::from_secs(180),
    )
    .await;

    let session = node.session("hub-a").expect("a live session");
    assert!(
        session.is_ready() && session.health().is_healthy(),
        "the reconnected session must be Ready and healthy"
    );

    node.shutdown();
    hub.kill();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// Section 5.5: a *new* connection moves to the next Hub when the first is taken
/// out of service.
///
/// The two Hubs are configured so that only the *second* one can succeed, which is
/// what makes the test prove selection rather than mere success: while the first
/// Hub is live it is chosen (priority 1) and refuses the address, and after it is
/// taken out of service the very same flow succeeds through the second.
#[tokio::test]
async fn a_new_flow_fails_over_to_the_second_hub() {
    init_tracing();
    let scratch = scratch_dir("failover");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);
    let target = spawn_echo_target().await;

    // Hub A has no rules at all, so it refuses every address.
    let port_a = free_port().await;
    let mut hub_a = HubProcess::start(
        port_a,
        bare_hub_toml("hub-a", port_a, "caller", "a-1", &key),
    );
    wait_for_listener(port_a).await;

    // Hub B permits the loopback address. Section 9.3 requires a `host_cidr` rule
    // before a special address may be dialled, so this is the narrowest rule that
    // can work.
    let port_b = free_port().await;
    let server_b = format!(
        r#"
[server]
hub_id = "hub-b"
listen = "127.0.0.1:{port_b}"

[[nodes]]
id = "caller"
key_id = "b-1"
secret_file = "{key}"

[[acl]]
caller = "caller"
action = "connect_address"
host_cidr = "127.0.0.1/32"
allow = true
"#
    );
    let mut hub_b = HubProcess::start(port_b, server_b);
    wait_for_listener(port_b).await;

    let socks = free_port().await;
    let client_toml = format!(
        r#"
[client]
node_id = "caller"
socks_listen = "127.0.0.1:{socks}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{port_a}"
key_id = "a-1"
secret_file = "{key}"
priority = 1

[[servers]]
hub_id = "hub-b"
url = "http://127.0.0.1:{port_b}"
key_id = "b-1"
secret_file = "{key}"
priority = 2

[router]
final = "server"
"#
    );
    let config = ClientConfig::from_toml(&client_toml).expect("the client configuration must parse");
    let node = Node::build(config, NodeOptions::default()).expect("the node must build");
    node.start().await.expect("the node must start");
    wait_until_ready(&node, "hub-a", "priority 1").await;
    wait_until_ready(&node, "hub-b", "priority 2").await;

    let destination = Destination::address("127.0.0.1", target.port());

    // While both are live, priority 1 wins, and that Hub denies the address. A
    // refusal is the proof that selection really did pick `hub-a`.
    let refused = match node
        .open_flow(destination.clone(), wsnet_routing::Proto::Tcp, Vec::new())
        .await
    {
        Ok(_) => panic!("hub-a has no acl rule, so the flow must be refused"),
        Err(error) => error,
    };
    match refused {
        NodeError::OpenFailed { status, detail } => {
            assert_eq!(
                status,
                OpenStatus::Denied,
                "an ACL denial must be reported as a denial, not as a transport error ({detail})"
            );
        }
        other => panic!("expected an OpenFailed refusal from hub-a, got {other:?}"),
    }

    // Take the first Hub out of service locally. Section 5.5 recovers only *new*
    // connections, so this is exactly the operation that must move the next one.
    node.mark_hub_offline("hub-a")
        .expect("hub-a must have a live session");

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(20),
        node.open_flow(destination, wsnet_routing::Proto::Tcp, Vec::new()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => panic!("the flow was not carried by the second hub: {error}"),
        Err(_) => panic!("opening through hub-b timed out"),
    };

    let payload = b"failover";
    stream.write_all(payload).await.expect("write");
    stream.flush().await.expect("flush");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut echoed))
        .await
        .expect("the echo timed out: hub-b did not carry the flow")
        .expect("the echo must arrive");
    assert_eq!(&echoed, payload);

    node.shutdown();
    // The second Hub must stay up for the assertion above; it is only dropped
    // here.
    hub_b.kill();
    hub_a.kill();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}
