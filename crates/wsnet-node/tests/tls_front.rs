//! Outer TLS: the node reaches a Hub through a TLS-terminating front end.
//!
//! DESIGN.md section 11 puts the outer TLS in front of the deployment — nginx or an
//! equivalent — and requires the node's carriers to keep working through it, with
//! certificate verification and forward secrecy intact. nginx is not available in
//! this environment, so the front end is terminated here by the same library the
//! node uses, and the *deployment shape* is what is exercised:
//!
//! ```text
//!   node --https--> TLS front end --plain http--> Hub (loopback)
//! ```
//!
//! Two properties are asserted, and the second is the one that keeps the first
//! honest:
//!
//! * with the front end's CA added as a root, the whole carrier set works through
//!   TLS and bytes survive the round trip;
//! * with the default trust store, the very same node **cannot** connect, so
//!   verification is genuinely running rather than silently bypassed for a private
//!   CA.
//!
//! The front end is a byte-level TCP proxy on purpose: it must not understand
//! HTTP, or it would be testing a second implementation of the protocol rather than
//! the deployment the design calls for.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::TlsAcceptor;

use wsnet_config::{ClientConfig, ServerConfig};
use wsnet_hub::{Hub, NodeSecrets};
use wsnet_node::{HttpTransportFactory, Node, NodeOptions};

const PSK: [u8; 32] = [0xC1; 32];

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
    dir.push(format!("wsnet-tls-{}-{name}", std::process::id()));
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

/// An echo target, so a successful flow is proven by bytes.
async fn spawn_echo_target() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// The certificate and key a TLS front end serves, plus the PEM an operator would
/// install as a root.
struct FrontCertificate {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    pem: String,
}

/// Generates a self-signed certificate for `localhost`.
///
/// `localhost` and not an IP literal: the node verifies the hostname against the
/// URL it was configured with, and a SAN of `127.0.0.1` would let a test pass while
/// the name check was broken.
fn self_signed_for_localhost() -> FrontCertificate {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("a self-signed certificate");
    FrontCertificate {
        chain: vec![CertificateDer::from(certified.cert.der().to_vec())],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.key_pair.serialize_der(),
        )),
        pem: certified.cert.pem(),
    }
}

/// Starts a TLS-terminating byte proxy in front of `upstream`, and returns its port.
///
/// A hop-by-hop copy is deliberate: the front end must be transparent to whatever
/// the Hub speaks, so anything that works through it works through nginx.
async fn spawn_tls_front(certificate: FrontCertificate, upstream: u16) -> u16 {
    let config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate.chain, certificate.key)
        .expect("a TLS server configuration");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the front end");
    let port = listener.local_addr().expect("front end addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let Ok(mut back) = TcpStream::connect(("127.0.0.1", upstream)).await else {
                    return;
                };
                let _ = copy_bidirectional(&mut tls, &mut back).await;
            });
        }
    });
    port
}

async fn wait_until_ready(node: &Arc<Node>, hub_id: &str, what: &str) {
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
            "the node never reached Ready on {hub_id} ({what})"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The Hub, its TLS front end, and the key file the node reads.
async fn setup(name: &str) -> (std::sync::Arc<Hub>, u16, u16, PathBuf, PathBuf, FrontCertificate) {
    let scratch = scratch_dir(name);
    let key_path = scratch.join("shared.key");
    std::fs::write(&key_path, psk_hex()).expect("write the shared key");

    let hub_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hub");
    let hub_port = hub_listener.local_addr().expect("hub addr").port();
    let target = spawn_echo_target().await;

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
host_cidr = "127.0.0.1/32"
allow = true
"#,
        key = toml_path(&key_path)
    );
    let server_config = ServerConfig::from_toml(&server_toml).expect("the server must parse");
    let secrets = NodeSecrets::from_server_config(&server_config).expect("the secrets must load");
    let hub = Arc::new(Hub::new(server_config, secrets).expect("the Hub must start"));
    tokio::spawn(Arc::clone(&hub).serve(hub_listener));

    let certificate = self_signed_for_localhost();
    let front_port = spawn_tls_front(
        FrontCertificate {
            chain: certificate.chain.clone(),
            key: certificate.key.clone_key(),
            pem: certificate.pem.clone(),
        },
        hub_port,
    )
    .await;

    (hub, front_port, target.port(), key_path, scratch, certificate)
}

/// A node TOML document that reaches the front end over HTTPS.
fn client_toml(front_port: u16, socks: u16, target_port: u16, key: &str) -> String {
    format!(
        r#"
[client]
node_id = "client-a"
socks_listen = "127.0.0.1:{socks}"

[[servers]]
hub_id = "hub-a"
# The URL names the certificate's own identity, so the hostname check runs.
url = "https://localhost:{front_port}"
key_id = "a-1"
secret_file = "{key}"
priority = 1

[router]
final = "server"

[[forwards]]
name = "to-echo"
listen = "127.0.0.1:0"
proto = "tcp"
hub = "auto"
destination = {{ type = "address", host = "127.0.0.1", port = {target_port} }}
"#
    )
}

/// The whole carrier set works through a TLS front end when its CA is trusted.
#[tokio::test]
async fn the_carriers_work_through_a_tls_front_end() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    init_tracing();
    let (_hub, front_port, target_port, key_path, scratch, certificate) = setup("trusted").await;
    let key = toml_path(&key_path);
    let socks = free_port().await;

    let config = ClientConfig::from_toml(&client_toml(front_port, socks, target_port, &key))
        .expect("the client configuration must parse");
    let factory = HttpTransportFactory::new()
        .with_root_certificate(certificate.pem.as_bytes())
        .expect("the front end's certificate must be usable as a root");
    let node = Node::build(config, NodeOptions::default().with_transport(Arc::new(factory)))
        .expect("the node must build");
    node.start().await.expect("the node must start through TLS");
    wait_until_ready(&node, "hub-a", "over https").await;

    let listen = node
        .forward_addr("to-echo")
        .expect("the forward listener must be bound");
    let payload = b"through tls";
    let mut client = timeout(Duration::from_secs(20), TcpStream::connect(listen))
        .await
        .expect("connect timed out")
        .expect("the forward must accept");
    client.write_all(payload).await.expect("write");
    let mut echoed = vec![0u8; payload.len()];
    timeout(Duration::from_secs(20), client.read_exact(&mut echoed))
        .await
        .expect("the echo timed out: TLS did not carry the flow")
        .expect("the echo must arrive");
    assert_eq!(&echoed, payload);

    node.shutdown();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}

/// Without the front end's CA, the very same deployment must fail.
///
/// This is what makes the test above meaningful: if anything in the node disabled
/// verification — or accepted any certificate — this case would connect too. It is
/// also the negative half of section 11's "外层 TLS 保留证书验证".
#[tokio::test]
async fn an_untrusted_tls_front_end_is_refused() {
    init_tracing();
    let (_hub, front_port, target_port, key_path, scratch, _certificate) = setup("untrusted").await;
    let key = toml_path(&key_path);
    let socks = free_port().await;

    let config = ClientConfig::from_toml(&client_toml(front_port, socks, target_port, &key))
        .expect("the client configuration must parse");
    // The default trust store, which cannot contain a freshly generated root.
    let node = Node::build(config, NodeOptions::default()).expect("the node must build");
    let started = timeout(Duration::from_secs(30), node.start()).await;
    let refusal = match started {
        Ok(Ok(())) => panic!("the node trusted an unknown certificate authority"),
        Ok(Err(error)) => error,
        Err(_) => panic!("the node hung instead of refusing an untrusted front end"),
    };
    let detail = refusal.to_string();
    assert!(
        !detail.is_empty(),
        "a refusal must name something locally diagnosable"
    );
    assert!(
        node.session("hub-a").is_none(),
        "a refused handshake must not leave a session behind"
    );

    node.shutdown();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_dir(&scratch);
}
