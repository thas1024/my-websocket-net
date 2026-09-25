//! End-to-end tests for the node against an in-process stub Hub.
//!
//! Every test builds a real node and a real hub-side `SessionHandle` and moves
//! production records and envelopes between them over a loopback TCP listener, so
//! what is exercised is the wire protocol, not a mock of it.

mod support;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{free_port, wait_for, within, StubConfig, StubHub, StubNetwork};

use wsnet_config::{ClientConfig, ForwardConfig, ServerEntry, ServiceConfig};
use wsnet_crypto::Psk;
use wsnet_node::{HubSession, Node, NodeError, NodeOptions};
use wsnet_routing::{Destination, Proto};
use wsnet_session::{HandshakeError, SessionState, SUPPORTED_CAPABILITIES};

/// The pre-shared key every test uses.
const PSK: [u8; 32] = [0x42; 32];

fn psk() -> Psk {
    Psk::from_bytes(PSK)
}

/// A validated client document pointing at one or more stub Hubs.
fn client_config(servers: &[(&str, &str)], socks_listen: &str) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.client.node_id = "client-a".to_string();
    config.client.socks_listen = socks_listen.to_string();
    config.servers = servers
        .iter()
        .enumerate()
        .map(|(index, (hub_id, url))| ServerEntry {
            hub_id: (*hub_id).to_string(),
            url: (*url).to_string(),
            key_id: format!("key-{}", index + 1),
            // The key is injected through `NodeOptions`, so the path is never read.
            secret_file: PathBuf::from("unused.key"),
            priority: index as u32 + 1,
        })
        .collect();
    config
}

/// Node options that reach the stub network with an injected key.
fn options(network: Arc<StubNetwork>, hello_timeout: Duration) -> NodeOptions {
    let mut options = NodeOptions::default()
        .with_transport(network)
        .with_hello_timeout(hello_timeout);
    for hub_id in ["hub-a", "hub-b"] {
        options = options.with_psk(hub_id, psk());
    }
    options
}

fn single_hub_options(hub: &StubHub) -> NodeOptions {
    options(
        Arc::new(StubNetwork::new(&[("hub-a", hub)])),
        Duration::from_secs(5),
    )
}

/// The SOCKS5 listener address for a test: never port 0, because the schema
/// requires a port the node will actually be reached on.
fn socks_listen() -> String {
    format!("127.0.0.1:{}", free_port())
}

/// Section 5.1 to 5.3: an authenticated, registered session, and the same key set
/// on both ends.
#[tokio::test]
async fn the_node_registers_with_a_stub_hub_using_the_same_keys() {
    let hub = within(StubHub::start(StubConfig::default())).await;
    let mut config = client_config(&[("hub-a", &hub.url())], &socks_listen());
    config.services = vec![ServiceConfig {
        name: "web".to_string(),
        proto: Proto::Tcp,
        target: "127.0.0.1:8080".to_string(),
    }];
    let node = Node::build(config, single_hub_options(&hub)).unwrap();
    within(node.start()).await.unwrap();

    let session = node.session("hub-a").expect("a live session");
    assert_eq!(session.state(), SessionState::Ready);

    // The stub only records a `Hello` it could open and decode with the keys it
    // derived from the same transcript, so this is the key-agreement assertion.
    wait_for(|| !hub.observed.hellos.lock().unwrap().is_empty()).await;
    let hello = hub.observed.hellos.lock().unwrap()[0].clone();
    assert_eq!(hello.services.len(), 1);
    assert_eq!(hello.services[0].name, "web");
    assert_eq!(hello.services[0].target, "127.0.0.1:8080");
    assert_eq!(hub.observed.auth_ok_sent.load(Ordering::SeqCst), 1);
    node.shutdown();
}

/// Section 6.7: an `AuthOk` whose MAC does not verify must not create a session.
#[tokio::test]
async fn a_bad_authok_mac_is_refused() {
    let hub = within(StubHub::start(StubConfig::bad_authok())).await;
    let config = client_config(&[("hub-a", &hub.url())], &socks_listen());
    let node = Node::build(config, single_hub_options(&hub)).unwrap();
    let error = within(node.start()).await.err().unwrap();
    assert!(
        matches!(error, NodeError::Handshake(HandshakeError::BadMac)),
        "unexpected error: {error}"
    );
    assert!(node.session("hub-a").is_none());
}

/// Section 5.3: `HelloOk` is the business barrier, so an `Open` before it is
/// refused and the Hub never sees it.
#[tokio::test]
async fn hello_ok_gates_ready_and_refuses_an_early_open() {
    let silent = within(StubHub::start(StubConfig::silent_after_auth())).await;
    let transport = within(silent.transport()).await;
    let session = within(HubSession::connect(
        silent.endpoint("hub-a"),
        "client-a".to_string(),
        psk(),
        Vec::new(),
        wsnet_node::InboundPolicy::deny_all(),
        capabilities(),
        transport,
    ))
    .await
    .unwrap();

    assert_eq!(session.state(), SessionState::HelloPending);
    assert!(!session.is_ready());

    let error = within(session.open(
        Destination::address("example.com", 80),
        Proto::Tcp,
        Vec::new(),
    ))
    .await
    .err()
    .unwrap();
    assert!(matches!(error, NodeError::NotReady), "unexpected: {error}");
    assert!(
        silent.observed.opens.lock().unwrap().is_empty(),
        "an Open before HelloOk reached the Hub"
    );

    let pending = within(session.wait_ready(Duration::from_millis(300))).await;
    assert!(matches!(pending, Err(NodeError::HelloTimeout)));

    // The same exchange against a Hub that answers lifts the barrier.
    let live = within(StubHub::start(StubConfig::default())).await;
    let transport = within(live.transport()).await;
    let session = within(HubSession::connect(
        live.endpoint("hub-a"),
        "client-a".to_string(),
        psk(),
        Vec::new(),
        wsnet_node::InboundPolicy::deny_all(),
        capabilities(),
        transport,
    ))
    .await
    .unwrap();
    assert_eq!(session.state(), SessionState::HelloPending);
    within(session.wait_ready(Duration::from_secs(5)))
        .await
        .unwrap();
    assert!(session.is_ready());
}

/// Sections 7.1 and 9.3: a SOCKS5 CONNECT reaches the Hub with the domain still
/// unresolved, and bytes flow both ways.
#[tokio::test]
async fn a_socks_connect_passes_the_domain_through_and_relays_bytes() {
    let hub = within(StubHub::start(StubConfig::default())).await;
    let config = client_config(&[("hub-a", &hub.url())], &socks_listen());
    let node = Node::build(config, single_hub_options(&hub)).unwrap();
    within(node.start()).await.unwrap();

    let mut client = within(TcpStream::connect(node.socks_addr().unwrap()))
        .await
        .unwrap();

    // Method negotiation: no credentials are configured, so no-auth is chosen.
    within(client.write_all(&[0x05, 0x01, 0x00])).await.unwrap();
    let mut method = [0u8; 2];
    within(client.read_exact(&mut method)).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    // CONNECT example.com:80 as ATYP=DOMAIN.
    let mut request = vec![0x05, 0x01, 0x00, 0x03, 11];
    request.extend_from_slice(b"example.com");
    request.extend_from_slice(&80u16.to_be_bytes());
    within(client.write_all(&request)).await.unwrap();

    let mut head = [0u8; 4];
    within(client.read_exact(&mut head)).await.unwrap();
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "the connect was refused");
    // Skip BND.ADDR and BND.PORT.
    let bound = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        other => panic!("unexpected ATYP {other}"),
    };
    let mut tail = vec![0u8; bound];
    within(client.read_exact(&mut tail)).await.unwrap();

    within(client.write_all(b"ping")).await.unwrap();
    let mut echo = [0u8; 4];
    within(client.read_exact(&mut echo)).await.unwrap();
    assert_eq!(&echo, b"ping", "bytes did not flow back from the Hub");

    let destinations = hub.observed.destinations();
    assert_eq!(destinations.len(), 1);
    assert_eq!(
        destinations[0],
        Destination::address("example.com", 80),
        "the node resolved the domain locally"
    );
    node.shutdown();
}

/// Section 5.2: a retried `Open` with the same `request_id` is answered from the
/// operation table and never dialled twice.
#[tokio::test]
async fn a_retried_open_is_answered_from_the_cache() {
    let hub = within(StubHub::start(StubConfig::default())).await;
    let config = client_config(&[("hub-a", &hub.url())], &socks_listen());
    let node = Node::build(config, single_hub_options(&hub)).unwrap();
    within(node.start()).await.unwrap();

    let session = node.session("hub-a").expect("a live session");
    let destination = Destination::service("client-a", "web");
    let request_id = [7u8; 16];

    let first = within(session.open_with_request_id(
        destination.clone(),
        Proto::Tcp,
        Vec::new(),
        request_id,
    ))
    .await
    .unwrap();
    assert_eq!(
        first.stream_id() % 2,
        1,
        "the node side uses odd stream ids"
    );

    let retry =
        within(session.open_with_request_id(destination, Proto::Tcp, Vec::new(), request_id))
            .await
            .err()
            .unwrap();
    assert!(
        matches!(retry, NodeError::DuplicateOpen { .. }),
        "unexpected: {retry}"
    );
    assert_eq!(
        hub.observed.opens.lock().unwrap().len(),
        1,
        "the retry dialled the target a second time"
    );
    drop(first);
    node.shutdown();
}

/// Sections 7.6 and 5.5: a Local Forward reaches its service target, and once the
/// Hub fails new connections fail explicitly instead of falling back.
#[tokio::test]
async fn a_local_forward_reaches_its_service_and_fails_closed() {
    let hub = within(StubHub::start(StubConfig::default())).await;
    let mut config = client_config(&[("hub-a", &hub.url())], &socks_listen());
    config.forwards = vec![ForwardConfig {
        name: "a-web".to_string(),
        listen: format!("127.0.0.1:{}", free_port()),
        proto: Proto::Tcp,
        hub: "auto".to_string(),
        via: Vec::new(),
        allow_from: Vec::new(),
        destination: Some(Destination::service("client-a", "web")),
    }];
    let node = Node::build(config, single_hub_options(&hub)).unwrap();
    within(node.start()).await.unwrap();

    let listen = node.forward_addr("a-web").expect("a bound forward");
    let mut client = within(TcpStream::connect(listen)).await.unwrap();
    within(client.write_all(b"hello")).await.unwrap();
    let mut echo = [0u8; 5];
    within(client.read_exact(&mut echo)).await.unwrap();
    assert_eq!(&echo, b"hello");

    // The Hub goes away: existing sockets are not migrated, and new ones must
    // fail rather than being served directly (DESIGN.md section 5.5).
    node.mark_hub_offline("hub-a").unwrap();
    wait_for(|| {
        node.session("hub-a")
            .map(|session| session.state() == SessionState::Closed)
            .unwrap_or(false)
    })
    .await;

    let mut second = within(TcpStream::connect(listen)).await.unwrap();
    let mut byte = [0u8; 1];
    let read = within(second.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "the forward kept a dead connection open: {read:?}"
    );
    assert_eq!(
        hub.observed.opens.lock().unwrap().len(),
        1,
        "a second open was dialled after the Hub failed"
    );
}

/// Section 5.5: `hub = "auto"` skips a Hub whose publisher is not ready.
#[tokio::test]
async fn auto_selection_skips_a_hub_without_the_publisher() {
    // hub-a has the higher priority but advertises no services; hub-b advertises
    // the service the flow needs.
    let hub_a = within(StubHub::start(StubConfig {
        hub_id: "hub-a".to_string(),
        ..StubConfig::advertising(&[])
    }))
    .await;
    let hub_b = within(StubHub::start(StubConfig {
        hub_id: "hub-b".to_string(),
        ..StubConfig::advertising(&[("client-a", "web")])
    }))
    .await;
    let config = client_config(
        &[("hub-a", &hub_a.url()), ("hub-b", &hub_b.url())],
        &socks_listen(),
    );
    let network = Arc::new(StubNetwork::new(&[("hub-a", &hub_a), ("hub-b", &hub_b)]));
    let node = Node::build(config, options(network, Duration::from_secs(5))).unwrap();
    within(node.start()).await.unwrap();

    // Both directories must be known before selection can skip one.
    wait_for(|| {
        node.runtime()
            .directory("hub-a")
            .map(|directory| directory.is_known())
            .unwrap_or(false)
    })
    .await;
    wait_for(|| {
        node.runtime()
            .directory("hub-b")
            .map(|directory| directory.contains("client-a", "web"))
            .unwrap_or(false)
    })
    .await;

    let stream = within(node.open_flow(
        Destination::service("client-a", "web"),
        Proto::Tcp,
        Vec::new(),
    ))
    .await
    .unwrap();
    assert_eq!(stream.stream_id() % 2, 1);

    assert_eq!(hub_b.observed.opens.lock().unwrap().len(), 1);
    assert_eq!(
        hub_a.observed.opens.lock().unwrap().len(),
        0,
        "auto selection used a Hub that does not advertise the service"
    );
    node.shutdown();
}

/// Section 9.3: a non-loopback SOCKS5 listener without credentials and a source
/// allowlist is refused at construction.
#[tokio::test]
async fn a_non_loopback_listener_without_credentials_is_refused() {
    let config = client_config(&[], "0.0.0.0:1080");
    let error = Node::build(config, NodeOptions::default()).err().unwrap();
    assert!(
        matches!(error, NodeError::UnsafeSocksListen(_)),
        "unexpected: {error}"
    );
}

/// The capability list a node offers, as `Hello` and `Auth` carry it.
fn capabilities() -> Vec<String> {
    SUPPORTED_CAPABILITIES
        .iter()
        .map(|capability| (*capability).to_string())
        .collect()
}
