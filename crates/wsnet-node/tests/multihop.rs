//! Multi-hop chains, end to end (DESIGN.md sections 7.1 and 7.6).
//!
//! Section 7.1 fixes the shape of a chain:
//!
//! > `via=[]` 在 Hub 出口；`via=[A]` 在 A 出口；`via=[A,B]` 路径为 client→H→A→H→B→target。
//! > v1 是同 Hub 星型回转链，不是任意 mesh
//!
//! So `via=[A]` moves the *exit* to A: the Hub does not dial the target, A does,
//! in A's own view and under A's own policy. That is what this file proves against
//! a real Hub and two real nodes — the Hub's ACL authorises the chain edge, and A's
//! own `allow_node_address` allowlist is the second, independent gate that section
//! 9.3 requires ("出口节点独立校验本地策略").
//!
//! The Hub's own unit and integration tests cover chain *validation* (loops,
//! duplicates, the hop budget, and the two-gate rule); this covers the chain that
//! is actually carried.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use wsnet_config::{ClientConfig, ServerConfig};
use wsnet_hub::{Hub, NodeSecrets};
use wsnet_node::{Node, NodeOptions};

const PSK: [u8; 32] = [0x3D; 32];

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
    dir.push(format!("wsnet-multihop-{}-{name}", std::process::id()));
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

/// An echo target: whatever it reads, it writes straight back.
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

async fn start_node(document: &str) -> Arc<Node> {
    let config = ClientConfig::from_toml(document).expect("the client configuration must parse");
    let node = Node::build(config, NodeOptions::default()).expect("the node must build");
    node.start().await.expect("the node must start");
    wait_until_ready(&node, "hub-a").await;
    node
}

/// Sends `payload` through `listen` and requires exactly those bytes back.
async fn echo_through(listen: std::net::SocketAddr, payload: &[u8]) {
    let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
        .await
        .expect("connecting to the forward timed out")
        .expect("the forward listener must accept");
    client.write_all(payload).await.expect("write payload");
    client.flush().await.expect("flush payload");
    let mut echoed = vec![0u8; payload.len()];
    timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
        .await
        .expect("the echo timed out: the chain did not carry bytes")
        .expect("the echo must arrive");
    assert_eq!(&echoed, payload, "bytes must survive the chain and back");
}

/// `via = [hop]` with a plain address moves the dial to the hop.
///
/// The Hub is configured so it *cannot* dial the target itself in the chain's
/// sense: the only `connect_address` rule is written with `via` in mind and there is
/// no rule letting the Hub dial without a hop. A successful flow therefore proves
/// the exit really was the hop rather than the Hub quietly dialling directly.
///
/// The destination is a plain `AddressTarget` and the hop is named only in `via`,
/// which is the shape the design's own chain validator requires: `via` names the
/// *intermediate* nodes, so naming the exit there as well is rejected as
/// `DestinationInPath`.
#[tokio::test]
async fn a_single_hop_chain_moves_the_exit_to_the_hop() {
    init_tracing();
    let scratch = scratch_dir("single");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);
    let target = spawn_echo_target().await;
    let target_port = target.port();

    let hub_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hub");
    let hub_port = hub_listener.local_addr().expect("hub addr").port();

    let server_toml = format!(
        r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:{hub_port}"
# Section 9.3: relaying through `hop` is a capability switch, and the `relay` rule
# below is the per-edge permit. Both are required.
relay_allow = ["hop"]

[[nodes]]
id = "caller"
key_id = "call-1"
secret_file = "{key}"

[[nodes]]
id = "hop"
key_id = "hop-1"
secret_file = "{key}"

# The Hub authorises the chain edge...
[[acl]]
caller = "caller"
action = "relay"
node = "hop"
allow = true

# ...and the target. A loopback address needs a `host_cidr` rule in this Hub's
# egress policy, so this rule is both the target permit and the section 9.3
# allowlist entry.
[[acl]]
caller = "caller"
action = "connect_address"
host_cidr = "127.0.0.1/32"
ports = [{target_port}]
proto = "tcp"
allow = true
"#
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("the server must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // --- hop -----------------------------------------------------------------
    // Section 9.3: the exit node's own allowlist is the second gate.
    let hop_socks = free_port().await;
    let hop = start_node(&format!(
        r#"
[client]
node_id = "hop"
socks_listen = "127.0.0.1:{hop_socks}"
allow_node_address = ["127.0.0.1/32"]

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "hop-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
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

[[forwards]]
name = "through-hop"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
via = ["hop"]
destination = {{ type = "address", host = "127.0.0.1", port = {target_port} }}
"#
    ))
    .await;

    let listen = caller
        .forward_addr("through-hop")
        .expect("the caller's forward listener must be bound");
    echo_through(listen, b"single hop").await;

    caller.shutdown();
    hop.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// A chain whose exit node has not authorised the address stays refused.
///
/// This is the negative half of the same property: the Hub's permit is not enough,
/// because section 9.3 makes the exit node check its own policy again. Without this
/// test, the second gate could be deleted and the positive test above would still
/// pass.
#[tokio::test]
async fn a_chain_whose_exit_has_not_authorised_the_address_is_refused() {
    init_tracing();
    let scratch = scratch_dir("denied");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);
    let target = spawn_echo_target().await;
    let target_port = target.port();

    let hub_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hub");
    let hub_port = hub_listener.local_addr().expect("hub addr").port();

    let server_toml = format!(
        r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:{hub_port}"
relay_allow = ["hop"]

[[nodes]]
id = "caller"
key_id = "call-1"
secret_file = "{key}"

[[nodes]]
id = "hop"
key_id = "hop-1"
secret_file = "{key}"

[[acl]]
caller = "caller"
action = "relay"
node = "hop"
allow = true

[[acl]]
caller = "caller"
action = "connect_address"
host_cidr = "127.0.0.1/32"
ports = [{target_port}]
proto = "tcp"
allow = true
"#
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("the server must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // The hop has no `allow_node_address`, so it refuses the address even though
    // the Hub permitted it.
    let hop_socks = free_port().await;
    let hop = start_node(&format!(
        r#"
[client]
node_id = "hop"
socks_listen = "127.0.0.1:{hop_socks}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "hop-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    ))
    .await;

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

[[forwards]]
name = "through-hop"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
via = ["hop"]
destination = {{ type = "address", host = "127.0.0.1", port = {target_port} }}
"#
    ))
    .await;

    let listen = caller
        .forward_addr("through-hop")
        .expect("the caller's forward listener must be bound");

    // The local forward reports the refusal by closing the connection rather than
    // by dialling anything directly, so the client sees an immediate end of stream
    // and never a byte of the target's echo.
    let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
        .await
        .expect("connect timed out")
        .expect("the forward listener must accept");
    client.write_all(b"denied").await.expect("write");
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(20), client.read_to_end(&mut echoed))
        .await
        .expect("the refusal must close the connection instead of hanging")
        .expect("read");
    assert!(
        echoed.is_empty(),
        "a refused chain must not carry target bytes, got {echoed:?}"
    );

    caller.shutdown();
    hop.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// `via = [hop1, hop2]` is client→H→hop1→H→hop2→target, and each hop must consent.
///
/// This is the path section 7.1 calls a star-shaped return chain: `hop1` is not an
/// exit, so it hands the flow back to the Hub with `hop2` still to run. The Hub is
/// given no way to dial the target without going through both hops, and `hop1` is
/// the node whose local `relay_forward` switch is exercised.
#[tokio::test]
async fn a_two_hop_chain_returns_through_the_hub_at_each_hop() {
    init_tracing();
    let scratch = scratch_dir("two");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);
    let target = spawn_echo_target().await;
    let target_port = target.port();

    let hub_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hub");
    let hub_port = hub_listener.local_addr().expect("hub addr").port();

    let server_toml = format!(
        r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:{hub_port}"
relay_allow = ["hop1", "hop2"]

[[nodes]]
id = "caller"
key_id = "call-1"
secret_file = "{key}"

[[nodes]]
id = "hop1"
key_id = "h1-1"
secret_file = "{key}"

[[nodes]]
id = "hop2"
key_id = "h2-1"
secret_file = "{key}"

# Every relay edge needs its own permit (section 7.6), including the one from the
# first hop to the second.
[[acl]]
caller = "caller"
action = "relay"
node = "hop1"
allow = true

[[acl]]
caller = "caller"
action = "relay"
node = "hop2"
allow = true

[[acl]]
caller = "hop1"
action = "relay"
node = "hop2"
allow = true

# The target is the second hop's exit, so `hop1` needs no address rule at all.
[[acl]]
caller = "caller"
action = "connect_address"
host_cidr = "127.0.0.1/32"
ports = [{target_port}]
proto = "tcp"
allow = true

# Section 7.6: "多跳还需每条 relay edge 的独立 permit". The flow `hop1` hands back
# to the Hub is a *new* `Open` whose caller is `hop1`, so it needs a permit of its
# own — the caller's own rule grants nothing to an intermediate node, which is what
# keeps a hop from inheriting authority it was never given.
[[acl]]
caller = "hop1"
action = "connect_address"
host_cidr = "127.0.0.1/32"
ports = [{target_port}]
proto = "tcp"
allow = true
"#
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("the server must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // hop1 consents to carrying another caller's chain; hop2 is the exit.
    let hop1_socks = free_port().await;
    let hop1 = start_node(&format!(
        r#"
[client]
node_id = "hop1"
socks_listen = "127.0.0.1:{hop1_socks}"
relay_forward = true

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "h1-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    ))
    .await;

    let hop2_socks = free_port().await;
    let hop2 = start_node(&format!(
        r#"
[client]
node_id = "hop2"
socks_listen = "127.0.0.1:{hop2_socks}"
allow_node_address = ["127.0.0.1/32"]

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "h2-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    ))
    .await;

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

[[forwards]]
name = "through-two"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
via = ["hop1", "hop2"]
destination = {{ type = "address", host = "127.0.0.1", port = {target_port} }}
"#
    ))
    .await;

    let listen = caller
        .forward_addr("through-two")
        .expect("the caller's forward listener must be bound");
    echo_through(listen, b"two hops").await;

    caller.shutdown();
    hop1.shutdown();
    hop2.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// A hop that has not consented refuses to carry the chain.
///
/// The Hub permits the whole chain, so the only thing that can stop this flow is
/// `hop1`'s own `relay_forward` switch being off. That is the local-consent half of
/// section 9.3 for an intermediate node, and it is what stops a Hub from conscripting
/// a node as a hop.
#[tokio::test]
async fn a_hop_that_has_not_consented_refuses_to_carry_the_chain() {
    init_tracing();
    let scratch = scratch_dir("nohop");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);
    let target = spawn_echo_target().await;
    let target_port = target.port();

    let hub_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hub");
    let hub_port = hub_listener.local_addr().expect("hub addr").port();

    let server_toml = format!(
        r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:{hub_port}"
relay_allow = ["hop1", "hop2"]

[[nodes]]
id = "caller"
key_id = "call-1"
secret_file = "{key}"

[[nodes]]
id = "hop1"
key_id = "h1-1"
secret_file = "{key}"

[[nodes]]
id = "hop2"
key_id = "h2-1"
secret_file = "{key}"

[[acl]]
caller = "caller"
action = "relay"
node = "hop1"
allow = true

[[acl]]
caller = "caller"
action = "relay"
node = "hop2"
allow = true

[[acl]]
caller = "hop1"
action = "relay"
node = "hop2"
allow = true

[[acl]]
caller = "caller"
action = "connect_address"
host_cidr = "127.0.0.1/32"
ports = [{target_port}]
proto = "tcp"
allow = true
"#
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("the server must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // hop1 has no `relay_forward`, so it must refuse to continue the chain.
    let hop1_socks = free_port().await;
    let hop1 = start_node(&format!(
        r#"
[client]
node_id = "hop1"
socks_listen = "127.0.0.1:{hop1_socks}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "h1-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    ))
    .await;

    let hop2_socks = free_port().await;
    let hop2 = start_node(&format!(
        r#"
[client]
node_id = "hop2"
socks_listen = "127.0.0.1:{hop2_socks}"
allow_node_address = ["127.0.0.1/32"]

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "h2-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    ))
    .await;

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

[[forwards]]
name = "through-two"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
via = ["hop1", "hop2"]
destination = {{ type = "address", host = "127.0.0.1", port = {target_port} }}
"#
    ))
    .await;

    let listen = caller
        .forward_addr("through-two")
        .expect("the caller's forward listener must be bound");

    let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
        .await
        .expect("connect timed out")
        .expect("the forward listener must accept");
    client.write_all(b"no consent").await.expect("write");
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(20), client.read_to_end(&mut echoed))
        .await
        .expect("the refusal must close the connection instead of hanging")
        .expect("read");
    assert!(
        echoed.is_empty(),
        "an unconsenting hop must not carry bytes, got {echoed:?}"
    );

    caller.shutdown();
    hop1.shutdown();
    hop2.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}
