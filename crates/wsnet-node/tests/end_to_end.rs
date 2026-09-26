//! End-to-end acceptance: a real Hub, a real node, and a real SOCKS5 client.
//!
//! Everything here is the production path rather than a stub: the Hub serves
//! `POST /m` and `GET /e` over a real loopback listener, the node authenticates
//! with `Auth`/`AuthOk`, presents a `BindProof` on every bound request, reaches
//! `Ready`, and exposes a real SOCKS5 listener. The assertion that matters is the
//! last one: bytes written by a SOCKS5 client are echoed back by a target socket
//! that the *Hub* dialled.
//!
//! If any seam in that chain regresses — the bootstrap framing, the binding MAC,
//! the `HelloOk` barrier, the egress guard, or the credit accounting — this test
//! fails rather than the unit tests staying green.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use wsnet_config::{ClientConfig, ServerConfig};
use wsnet_hub::{Hub, NodeSecrets};
use wsnet_node::{Node, NodeOptions};

/// The shared secret both sides load from the same file.
const PSK: [u8; 32] = [0x5A; 32];

fn psk_hex() -> String {
    PSK.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A per-test scratch directory for the key file both sides read.
///
/// The test name is part of the path on purpose: the tests in one binary run in
/// parallel threads of the same process, so a directory keyed only by the process id
/// is shared, and one test's cleanup deletes the file another test is about to read
/// (`BadSecret`). Isolation here is the difference between a real failure and a
/// scheduling accident.
fn scratch_dir(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("wsnet-acceptance-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// A path in the form TOML needs on Windows.
///
/// A backslash inside a TOML basic string is an escape sequence, so a raw
/// `C:\...` path is a parse error rather than a path.
fn toml_path(path: &std::path::Path) -> String {
    path.display().to_string().replace('\\', "/")
}

/// Binds a listener and returns it with its port, so nothing can take the port in
/// between choosing it and using it.
async fn bound_loopback() -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback")
}

/// Reserves a port for a component that insists on a literal address.
async fn free_port() -> u16 {
    let listener = bound_loopback().await;
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// A SOCKS5 `CONNECT` that returns the established stream.
///
/// Only the no-authentication method and `ATYP=DOMAIN` are used, which is the
/// path a typical application takes.
async fn socks_connect(
    proxy: std::net::SocketAddr,
    host: &str,
    port: u16,
) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;

    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    assert_eq!(method, [5, 0], "the proxy must accept no-auth");

    let mut request = vec![5u8, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    // Consume the bound address; its width depends on the address type.
    let skip = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => 0,
    };
    let mut rest = vec![0u8; skip + 2];
    stream.read_exact(&mut rest).await?;

    if reply[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("the proxy refused the CONNECT with code {:#04x}", reply[1]),
        ));
    }
    Ok(stream)
}

/// Waits until the node reports a usable session, or fails the test.
async fn wait_until_ready(node: &Arc<Node>, hub_id: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
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

/// The whole chain: SOCKS5 client to node to Hub to target and back.
#[tokio::test]
async fn a_socks5_request_traverses_the_node_and_the_hub_to_a_target() {
    let scratch = scratch_dir("traverse");
    let key_path = scratch.join("client-a.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");

    // --- Hub -----------------------------------------------------------------
    // Binding the listener first removes the window in which another process
    // could take the port the configuration names.
    let hub_listener = bound_loopback().await;
    let hub_port = hub_listener.local_addr().expect("hub addr").port();

    let server_toml = format!(
        r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:{hub_port}"
relay_allow = []

[[nodes]]
id = "client-a"
key_id = "a-1"
secret_file = "{key}"

[[acl]]
caller = "client-a"
action = "connect_address"
allow = true

# Section 9.3 makes a special-purpose address (loopback included) dialable only
# through a rule that names a CIDR, so an ordinary "any address" rule cannot
# exempt a local target by accident. The echo target is on loopback.
[[acl]]
caller = "client-a"
action = "connect_address"
host_cidr = "127.0.0.1/32"
allow = true

[[acl]]
caller = "client-a"
action = "connect_service"
node = "client-a"
service = "web"
allow = true
"#,
        key = toml_path(&key_path)
    );

    let server_config =
        ServerConfig::from_toml(&server_toml).expect("the server configuration must parse");
    let secrets =
        NodeSecrets::from_server_config(&server_config).expect("the node secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    // --- node ----------------------------------------------------------------
    let socks_port = free_port().await;
    let client_toml = format!(
        r#"
[client]
node_id = "client-a"
socks_listen = "127.0.0.1:{socks_port}"
udp_enabled = false

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "a-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"

[[services]]
name = "web"
proto = "tcp"
target = "127.0.0.1:8080"
"#,
        key = toml_path(&key_path)
    );

    let client_config =
        ClientConfig::from_toml(&client_toml).expect("the client configuration must parse");
    let node = Node::build(client_config, NodeOptions::default()).expect("the node must build");
    node.start().await.expect("the node must start");
    wait_until_ready(&node, "hub-a").await;

    // --- target and the actual assertion -------------------------------------
    let target = spawn_echo_target().await;
    let proxy = node.socks_addr().expect("the SOCKS5 listener must be bound");

    let payload = b"hello wsnet";
    let mut client = timeout(
        Duration::from_secs(15),
        socks_connect(proxy, &target.ip().to_string(), target.port()),
    )
    .await
    .expect("the SOCKS5 connect timed out")
    .expect("the SOCKS5 connect must succeed once the Hub has egress");

    client.write_all(payload).await.expect("write payload");
    client.flush().await.expect("flush payload");

    let mut echoed = vec![0u8; payload.len()];
    timeout(Duration::from_secs(15), client.read_exact(&mut echoed))
        .await
        .expect("the echo timed out")
        .expect("the echo must arrive");
    assert_eq!(
        &echoed, payload,
        "bytes must survive SOCKS5 -> node -> Hub -> target and back"
    );

    node.shutdown();
    hub_task.abort();

    // Best-effort cleanup; the key is a throwaway for this run.
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// A second connection on the same session must work, so a stream that finished
/// did not take the session with it.
#[tokio::test]
async fn a_second_request_reuses_the_same_session() {
    let scratch = scratch_dir("reuse");
    let key_path = scratch.join("client-a.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");

    let hub_listener = bound_loopback().await;
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

[[acl]]
caller = "client-a"
action = "connect_address"
allow = true

[[acl]]
caller = "client-a"
action = "connect_address"
host_cidr = "127.0.0.1/32"
allow = true
"#,
        key = toml_path(&key_path)
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("server config");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("secrets");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("hub"));
    let hub_task = tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    let socks_port = free_port().await;
    let client_toml = format!(
        r#"
[client]
node_id = "client-a"
socks_listen = "127.0.0.1:{socks_port}"

[[servers]]
hub_id = "hub-a"
url = "http://127.0.0.1:{hub_port}"
key_id = "a-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"
"#,
        key = toml_path(&key_path)
    );
    let client_config = ClientConfig::from_toml(&client_toml).expect("client config");
    let node = Node::build(client_config, NodeOptions::default()).expect("node");
    node.start().await.expect("start");
    wait_until_ready(&node, "hub-a").await;

    let target = spawn_echo_target().await;
    let proxy = node.socks_addr().expect("socks listener");

    for round in 0..3u8 {
        let payload = [b'a' + round; 8];
        let mut client = timeout(
            Duration::from_secs(15),
            socks_connect(proxy, &target.ip().to_string(), target.port()),
        )
        .await
        .expect("connect timed out")
        .expect("connect must succeed");

        client.write_all(&payload).await.expect("write");
        let mut echoed = vec![0u8; payload.len()];
        timeout(Duration::from_secs(15), client.read_exact(&mut echoed))
            .await
            .expect("read timed out")
            .expect("read");
        assert_eq!(echoed, payload, "round {round} must echo correctly");
    }

    node.shutdown();
    hub_task.abort();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}
