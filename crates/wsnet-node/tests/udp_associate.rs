//! SOCKS5 UDP ASSOCIATE, end to end (DESIGN.md section 7.4).
//!
//! The whole path, with nothing stubbed:
//!
//! ```text
//!   udp client -> node's SOCKS5 association socket -> node
//!              -> tunnel route (Proto::Udp stream) -> Hub UDP egress -> echo target
//! ```
//!
//! Section 7.4 splits this across three things that are each tested separately
//! elsewhere — the SOCKS5 association server, the node's datagram plumbing, and the
//! Hub's UDP egress — so what this file adds is that they agree: a real client
//! datagram reaches a real UDP socket through the tunnel, and its answer comes back
//! rewritten with the address it actually came from.
//!
//! The second test covers the switch rather than the path: with `udp_enabled` off,
//! the node must answer the RFC's "command not supported" instead of advertising an
//! association socket it will not serve.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use wsnet_config::{ClientConfig, ServerConfig};
use wsnet_hub::{Hub, NodeSecrets};
use wsnet_node::{Node, NodeOptions};
use wsnet_socks::{encode_target, encode_udp_datagram, Command, ReplyCode, SocksTarget, UdpHeader};

const PSK: [u8; 32] = [0x9E; 32];
const WAIT: Duration = Duration::from_secs(20);

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
    dir.push(format!("wsnet-udp-{}-{name}", std::process::id()));
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

/// A UDP echo target: whatever it receives, it sends back.
async fn spawn_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the echo target");
    let addr = socket.local_addr().expect("echo address");
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            if socket.send_to(&buffer[..len], from).await.is_err() {
                break;
            }
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

/// A Hub that permits a UDP route to loopback.
async fn start_hub(name: &str, key: &str) -> u16 {
    let hub_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hub");
    let hub_port = hub_listener.local_addr().expect("hub addr").port();
    let server_toml = format!(
        r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:{hub_port}"

[[nodes]]
id = "client-a"
key_id = "a-1"
secret_file = "{key}"

# Section 9.3: a loopback destination needs an explicit address rule in the Hub's
# egress policy, and the rule is the same one TCP uses.
[[acl]]
caller = "client-a"
action = "connect_address"
host_cidr = "127.0.0.1/32"
allow = true
"#
    );
    let _ = name;
    let server_config = ServerConfig::from_toml(&server_toml).expect("the server must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    tokio::spawn(Arc::clone(&hub).serve(hub_listener));
    hub_port
}

/// A node TOML document, with datagram inbound switched on or off.
fn client_toml(hub_port: u16, socks: u16, key: &str, udp_enabled: bool) -> String {
    format!(
        r#"
[client]
node_id = "client-a"
socks_listen = "127.0.0.1:{socks}"
udp_enabled = {udp_enabled}

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "a-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#
    )
}

/// Builds and starts a node against the Hub, and returns it with its SOCKS address.
async fn start_node(hub_port: u16, key: &str, udp_enabled: bool) -> (Arc<Node>, SocketAddr) {
    let socks = free_port().await;
    let config = ClientConfig::from_toml(&client_toml(hub_port, socks, key, udp_enabled))
        .expect("the client configuration must parse");
    let node = Node::build(config, NodeOptions::default()).expect("the node must build");
    node.start().await.expect("the node must start");
    wait_until_ready(&node, "hub-a").await;
    let addr = node.socks_addr().expect("the node must have bound SOCKS5");
    (node, addr)
}

/// Runs the RFC 1928 UDP ASSOCIATE handshake and returns the controlling TCP
/// connection plus the relay address the node advertised.
async fn udp_associate(addr: SocketAddr) -> Result<(TcpStream, SocketAddr), ReplyCode> {
    let mut stream = timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .expect("method reply");
    assert_eq!(method, [0x05, 0x00], "the node must accept no-auth");

    // Section 7.4 binds the association to this control connection; the requested
    // target is a placeholder the RFC requires but the association ignores.
    let mut request = vec![0x05, Command::UdpAssociate.as_u8(), 0x00];
    encode_target(
        &SocksTarget::Ip("127.0.0.1".parse().expect("loopback")),
        &mut request,
    )
    .expect("encode target");
    request.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&request).await.expect("request");

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.expect("reply head");
    assert_eq!(head[0], 0x05);
    assert_eq!(head[2], 0x00);
    let code = ReplyCode::from_u8(head[1]).expect("an assigned reply code");
    let mut body = [0u8; 6];
    stream.read_exact(&mut body).await.expect("reply body");
    assert_eq!(head[3], 0x01, "the node advertises an IPv4 relay address");
    let bind = SocketAddr::new(
        IpAddr::from([body[0], body[1], body[2], body[3]]),
        u16::from_be_bytes([body[4], body[5]]),
    );
    if code == ReplyCode::Succeeded {
        Ok((stream, bind))
    } else {
        Err(code)
    }
}

/// One client datagram, header included.
fn datagram(target: &SocksTarget, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_udp_datagram(target, port, payload, &mut out).expect("encode datagram");
    out
}

/// A client datagram reaches a real UDP socket through the tunnel and back.
#[tokio::test]
async fn a_client_datagram_reaches_a_udp_target_through_the_tunnel() {
    init_tracing();
    let scratch = scratch_dir("relay");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);
    let echo = spawn_udp_echo().await;

    let hub_port = start_hub("relay", &key).await;
    let (node, socks) = start_node(hub_port, &key, true).await;

    let (_control, bind) = udp_associate(socks)
        .await
        .expect("datagram inbound is enabled, so the association must succeed");
    assert_ne!(bind.port(), 0, "the advertised port must be the real one");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let target = SocksTarget::Ip("127.0.0.1".parse().expect("loopback"));
    timeout(
        WAIT,
        client.send_to(&datagram(&target, echo.port(), b"through the tunnel"), bind),
    )
    .await
    .expect("send timed out")
    .expect("send");

    let mut buffer = vec![0u8; 2048];
    let (len, from) = timeout(WAIT, client.recv_from(&mut buffer))
        .await
        .expect("the relayed answer never arrived")
        .expect("recv");
    assert_eq!(from, bind, "the answer must come from the relay socket");
    let (header, offset) = UdpHeader::parse(&buffer[..len]).expect("a valid reply header");
    assert_eq!(header.frag, 0);
    assert_eq!(
        header.port,
        echo.port(),
        "the header must name the address the answer came from"
    );
    assert_eq!(header.target, target);
    assert_eq!(&buffer[offset..len], b"through the tunnel");

    // A second datagram on the same route must work, so the first reply did not
    // consume the mapping.
    timeout(
        WAIT,
        client.send_to(&datagram(&target, echo.port(), b"again"), bind),
    )
    .await
    .expect("send timed out")
    .expect("send");
    let (len, _) = timeout(WAIT, client.recv_from(&mut buffer))
        .await
        .expect("the second answer never arrived")
        .expect("recv");
    let (_, offset) = UdpHeader::parse(&buffer[..len]).expect("a valid reply header");
    assert_eq!(&buffer[offset..len], b"again");

    node.shutdown();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// With datagram inbound off, the node must refuse by name, not fake a socket.
#[tokio::test]
async fn udp_associate_is_refused_when_datagram_inbound_is_disabled() {
    init_tracing();
    let scratch = scratch_dir("disabled");
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");
    let key = toml_path(&key_path);

    let hub_port = start_hub("disabled", &key).await;
    let (node, socks) = start_node(hub_port, &key, false).await;

    let code = udp_associate(socks)
        .await
        .expect_err("datagram inbound is off, so the association must be refused");
    assert_eq!(
        code,
        ReplyCode::CommandNotSupported,
        "section 7.4 keeps the refusal an RFC reply code, not a reason"
    );

    node.shutdown();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}
