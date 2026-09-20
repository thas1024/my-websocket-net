//! Socket-level tests: a real listener on `127.0.0.1:0`, driven by real clients.
//!
//! Every await is wrapped in a timeout so a bug shows up as a failing assertion
//! instead of a hung suite.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;
use wsnet_socks::{
    encode_target, encode_udp_datagram, BoxDuplex, BoxFuture, Command, Counter, ReplyCode,
    Socks5Server, SocksConfig, SocksError, SocksHandler, SocksRequest, SocksTarget, StatsHandle,
    UdpControl, UdpReply, UserPass,
};

/// Upper bound for any single step, so a bug cannot hang the suite.
const WAIT: Duration = Duration::from_secs(5);

/// A behaviour script for one UDP association.
type UdpScript =
    Arc<dyn Fn(UdpControl) -> BoxFuture<'static, Result<(), SocksError>> + Send + Sync>;

/// A handler that records CONNECTs, returns a scripted stream, and runs a
/// scripted UDP association.
struct TestHandler {
    connects: mpsc::UnboundedSender<SocksRequest>,
    connect_reply: Mutex<Option<Result<BoxDuplex, SocksError>>>,
    udp: Mutex<Option<UdpScript>>,
}

impl SocksHandler for TestHandler {
    fn connect(&self, request: SocksRequest) -> BoxFuture<'static, Result<BoxDuplex, SocksError>> {
        let _ = self.connects.send(request);
        let scripted = self
            .connect_reply
            .lock()
            .expect("handler mutex")
            .take()
            .unwrap_or_else(|| Err(SocksError::Handler("no scripted CONNECT reply".to_string())));
        Box::pin(async move { scripted })
    }

    fn udp_associate(&self, control: UdpControl) -> BoxFuture<'static, Result<(), SocksError>> {
        let script = self.udp.lock().expect("handler mutex").take();
        match script {
            Some(script) => script(control),
            None => Box::pin(async { Ok(()) }),
        }
    }
}

fn new_handler() -> (Arc<TestHandler>, mpsc::UnboundedReceiver<SocksRequest>) {
    let (connects, requests) = mpsc::unbounded_channel();
    (
        Arc::new(TestHandler {
            connects,
            connect_reply: Mutex::new(None),
            udp: Mutex::new(None),
        }),
        requests,
    )
}

impl TestHandler {
    fn script_connect(&self, result: Result<BoxDuplex, SocksError>) {
        *self.connect_reply.lock().expect("handler mutex") = Some(result);
    }

    fn script_udp(&self, script: UdpScript) {
        *self.udp.lock().expect("handler mutex") = Some(script);
    }
}

/// Starts a server on an ephemeral loopback port.
async fn start(
    handler: Arc<TestHandler>,
    config: SocksConfig,
) -> (
    SocketAddr,
    StatsHandle,
    tokio::task::JoinHandle<Result<(), SocksError>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback listener");
    start_on(listener, handler, config).await
}

/// Starts a server on an already-bound listener.
async fn start_on(
    listener: TcpListener,
    handler: Arc<TestHandler>,
    config: SocksConfig,
) -> (
    SocketAddr,
    StatsHandle,
    tokio::task::JoinHandle<Result<(), SocksError>>,
) {
    let addr = listener.local_addr().expect("listener address");
    let server = Socks5Server::new(listener, handler, config).expect("server construction");
    let stats = server.stats_handle();
    let task = tokio::spawn(async move { server.run().await });
    (addr, stats, task)
}

/// Connects and sends a greeting, returning the chosen method byte.
async fn greet(addr: SocketAddr, methods: &[u8]) -> (TcpStream, u8) {
    let mut stream = timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect did not time out")
        .expect("connect");
    let mut greeting = vec![0x05u8, methods.len() as u8];
    greeting.extend_from_slice(methods);
    timeout(WAIT, stream.write_all(&greeting))
        .await
        .expect("greeting write did not time out")
        .expect("greeting write");
    let mut reply = [0u8; 2];
    timeout(WAIT, stream.read_exact(&mut reply))
        .await
        .expect("method reply did not time out")
        .expect("method reply");
    assert_eq!(reply[0], 0x05, "the server must answer with version 5");
    (stream, reply[1])
}

/// Connects through the no-auth path.
async fn handshake(addr: SocketAddr) -> TcpStream {
    let (stream, method) = greet(addr, &[0x00]).await;
    assert_eq!(method, 0x00, "no-auth should have been selected");
    stream
}

/// Sends one request.
async fn send_request(stream: &mut TcpStream, command: Command, target: &SocksTarget, port: u16) {
    let mut out = vec![0x05, command.as_u8(), 0x00];
    encode_target(target, &mut out).expect("encode target");
    out.extend_from_slice(&port.to_be_bytes());
    timeout(WAIT, stream.write_all(&out))
        .await
        .expect("request write did not time out")
        .expect("request write");
}

/// Sends a raw request, for the wire cases a well-formed encoder cannot produce.
async fn send_raw_request(stream: &mut TcpStream, bytes: &[u8]) {
    timeout(WAIT, stream.write_all(bytes))
        .await
        .expect("request write did not time out")
        .expect("request write");
}

/// Reads a reply header and its bound address.
async fn read_reply(stream: &mut TcpStream) -> (ReplyCode, SocketAddr) {
    let mut head = [0u8; 4];
    timeout(WAIT, stream.read_exact(&mut head))
        .await
        .expect("reply did not time out")
        .expect("reply header");
    assert_eq!(head[0], 0x05, "reply version");
    assert_eq!(head[2], 0x00, "reply RSV");
    let code = ReplyCode::from_u8(head[1]).expect("assigned reply code");
    let bind = match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            timeout(WAIT, stream.read_exact(&mut rest))
                .await
                .expect("reply body did not time out")
                .expect("reply body");
            SocketAddr::new(
                IpAddr::from([rest[0], rest[1], rest[2], rest[3]]),
                u16::from_be_bytes([rest[4], rest[5]]),
            )
        }
        0x04 => {
            let mut rest = [0u8; 18];
            timeout(WAIT, stream.read_exact(&mut rest))
                .await
                .expect("reply body did not time out")
                .expect("reply body");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            SocketAddr::new(
                IpAddr::from(octets),
                u16::from_be_bytes([rest[16], rest[17]]),
            )
        }
        atyp => panic!("unexpected reply address type {atyp}"),
    };
    (code, bind)
}

/// Asserts that the server neither replied nor kept the connection open.
async fn expect_closed(stream: &mut TcpStream) {
    let mut buf = [0u8; 1];
    match timeout(WAIT, stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("expected the server to close the connection"),
        Err(_) => panic!("the server neither replied nor closed the connection"),
    }
}

async fn next_request(requests: &mut mpsc::UnboundedReceiver<SocksRequest>) -> SocksRequest {
    timeout(WAIT, requests.recv())
        .await
        .expect("the handler never saw the request")
        .expect("handler channel alive")
}

/// Starts a UDP echo server and returns its address.
async fn spawn_udp_echo() -> SocketAddr {
    spawn_udp_echo_on("127.0.0.1:0").await
}

/// Starts a UDP echo server on an address of a chosen family.
async fn spawn_udp_echo_on(bind: &str) -> SocketAddr {
    let socket = UdpSocket::bind(bind).await.expect("echo bind");
    let addr = socket.local_addr().expect("echo address");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            if socket.send_to(&buf[..len], from).await.is_err() {
                break;
            }
        }
    });
    addr
}

/// Builds a client-side SOCKS5 UDP datagram.
fn udp_datagram(target: &SocksTarget, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_udp_datagram(target, port, payload, &mut out).expect("encode datagram");
    out
}

/// Runs a UDP association handshake and returns the controlling connection plus
/// the advertised relay address.
async fn udp_associate(addr: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut stream = handshake(addr).await;
    let target = SocksTarget::Ip("127.0.0.1".parse().expect("loopback"));
    send_request(&mut stream, Command::UdpAssociate, &target, 5300).await;
    let (code, bind) = read_reply(&mut stream).await;
    assert_eq!(code, ReplyCode::Succeeded);
    (stream, bind)
}

#[tokio::test]
async fn no_auth_is_accepted_and_connect_reaches_the_handler() {
    let (handler, mut requests) = new_handler();
    let (upstream, mut peer) = tokio::io::duplex(4096);
    handler.script_connect(Ok(Box::new(upstream)));
    let (addr, stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    let mut stream = handshake(addr).await;
    let target = SocksTarget::Domain("example.com".to_string());
    send_request(&mut stream, Command::Connect, &target, 443).await;

    let request = next_request(&mut requests).await;
    assert_eq!(request.target, target);
    assert_eq!(request.port, 443);

    let (code, bind) = read_reply(&mut stream).await;
    assert_eq!(code, ReplyCode::Succeeded);
    assert_eq!(bind.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(stats.get(Counter::MethodNoAuthAccepted), 1);
    assert_eq!(stats.get(Counter::ConnectSucceeded), 1);

    // The relay copies in both directions.
    timeout(WAIT, stream.write_all(b"ping"))
        .await
        .expect("write did not time out")
        .expect("write");
    let mut buf = [0u8; 4];
    timeout(WAIT, peer.read_exact(&mut buf))
        .await
        .expect("read did not time out")
        .expect("read");
    assert_eq!(&buf, b"ping");

    timeout(WAIT, peer.write_all(b"pong"))
        .await
        .expect("write did not time out")
        .expect("write");
    timeout(WAIT, stream.read_exact(&mut buf))
        .await
        .expect("read did not time out")
        .expect("read");
    assert_eq!(&buf, b"pong");
}

#[tokio::test]
async fn every_address_type_reaches_the_handler_unchanged() {
    let (handler, mut requests) = new_handler();
    let (addr, _stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    let cases = [
        (SocksTarget::Domain("example.com".to_string()), 443u16),
        (SocksTarget::Ip("192.0.2.5".parse().unwrap()), 80),
        (SocksTarget::Ip("2001:db8::7".parse().unwrap()), 853),
    ];

    for (target, port) in &cases {
        let mut stream = handshake(addr).await;
        send_request(&mut stream, Command::Connect, target, *port).await;
        let request = next_request(&mut requests).await;
        assert_eq!(request.target, *target);
        assert_eq!(request.port, *port);
        // The handler has no scripted stream, so the client gets a failure
        // reply; that also proves a handler error is answered, not hung.
        let (code, _) = read_reply(&mut stream).await;
        assert_eq!(code, ReplyCode::GeneralFailure);
    }
}

#[tokio::test]
async fn credentials_refuse_no_auth_and_check_rfc1929() {
    let (handler, _requests) = new_handler();
    let config = SocksConfig::new().with_credentials(UserPass::new("alice", "s3cret").unwrap());
    let (addr, stats, _task) = start(Arc::clone(&handler), config).await;

    // No-auth must never be accepted while credentials are configured.
    let (mut refused, method) = greet(addr, &[0x00]).await;
    assert_eq!(method, 0xFF);
    expect_closed(&mut refused).await;
    assert_eq!(stats.get(Counter::MethodRejected), 1);
    assert_eq!(stats.get(Counter::MethodNoAuthAccepted), 0);

    // Correct credentials pass.
    let (mut ok, method) = greet(addr, &[0x02]).await;
    assert_eq!(method, 0x02);
    timeout(
        WAIT,
        ok.write_all(&[
            0x01, 0x05, b'a', b'l', b'i', b'c', b'e', 0x06, b's', b'3', b'c', b'r', b'e', b't',
        ]),
    )
    .await
    .expect("write did not time out")
    .expect("write");
    let mut status = [0u8; 2];
    timeout(WAIT, ok.read_exact(&mut status))
        .await
        .expect("read did not time out")
        .expect("read");
    assert_eq!(status, [0x01, 0x00]);
    assert_eq!(stats.get(Counter::MethodUserPassAccepted), 1);

    // Wrong credentials are refused with the RFC 1929 failure status.
    let (mut bad, method) = greet(addr, &[0x02]).await;
    assert_eq!(method, 0x02);
    timeout(
        WAIT,
        bad.write_all(&[
            0x01, 0x05, b'a', b'l', b'i', b'c', b'e', 0x05, b'w', b'r', b'o', b'n', b'g',
        ]),
    )
    .await
    .expect("write did not time out")
    .expect("write");
    let mut status = [0u8; 2];
    timeout(WAIT, bad.read_exact(&mut status))
        .await
        .expect("read did not time out")
        .expect("read");
    assert_eq!(status, [0x01, 0x01]);
    assert_eq!(stats.get(Counter::AuthFailed), 1);
    expect_closed(&mut bad).await;
}

#[tokio::test]
async fn unsupported_atyp_command_and_port_get_rfc_replies() {
    let (handler, _requests) = new_handler();
    let (addr, stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    // ATYP = 2 does not exist.
    let mut stream = handshake(addr).await;
    send_raw_request(&mut stream, &[0x05, 0x01, 0x00, 0x02, 1, 2, 3, 4, 0, 80]).await;
    assert_eq!(
        read_reply(&mut stream).await.0,
        ReplyCode::AddressTypeNotSupported
    );

    // BIND is a real command this server does not implement.
    let mut stream = handshake(addr).await;
    send_raw_request(&mut stream, &[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80]).await;
    assert_eq!(
        read_reply(&mut stream).await.0,
        ReplyCode::CommandNotSupported
    );

    // An unassigned command byte is the same reply.
    let mut stream = handshake(addr).await;
    send_raw_request(&mut stream, &[0x05, 0x09, 0x00, 0x01, 127, 0, 0, 1, 0, 80]).await;
    assert_eq!(
        read_reply(&mut stream).await.0,
        ReplyCode::CommandNotSupported
    );

    // A zero destination port is refused as a general failure.
    let mut stream = handshake(addr).await;
    send_raw_request(&mut stream, &[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).await;
    assert_eq!(read_reply(&mut stream).await.0, ReplyCode::GeneralFailure);

    assert_eq!(stats.get(Counter::UnsupportedAtyp), 1);
    assert_eq!(stats.get(Counter::UnsupportedCommand), 2);
    assert_eq!(stats.get(Counter::PortZeroRejected), 1);
}

#[tokio::test]
async fn a_handler_error_becomes_a_failure_reply() {
    let (handler, _requests) = new_handler();
    handler.script_connect(Err(SocksError::ConnectRefused));
    let (addr, stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    let mut stream = handshake(addr).await;
    let target = SocksTarget::Ip("192.0.2.9".parse().unwrap());
    send_request(&mut stream, Command::Connect, &target, 80).await;
    assert_eq!(
        read_reply(&mut stream).await.0,
        ReplyCode::ConnectionRefused
    );
    assert_eq!(stats.get(Counter::ConnectFailed), 1);

    // A non-specific handler failure is a general SOCKS failure.
    let (second_handler, _second_requests) = new_handler();
    second_handler.script_connect(Err(SocksError::Handler("boom".to_string())));
    let (addr, stats, _task) = start(Arc::clone(&second_handler), SocksConfig::new()).await;
    let mut stream = handshake(addr).await;
    send_request(&mut stream, Command::Connect, &target, 80).await;
    assert_eq!(read_reply(&mut stream).await.0, ReplyCode::GeneralFailure);
    assert_eq!(stats.get(Counter::ConnectFailed), 1);
}

#[tokio::test]
async fn a_non_loopback_listener_requires_the_section_9_3_protections() {
    let (handler, _requests) = new_handler();
    let listen = TcpListener::bind("0.0.0.0:0").await.expect("bind wildcard");

    // Loopback only is the default, so a wildcard listener is refused outright.
    assert!(Socks5Server::new(
        TcpListener::bind("0.0.0.0:0")
            .await
            .expect("bind wildcard again"),
        Arc::clone(&handler),
        SocksConfig::new(),
    )
    .is_err());

    // Opening the flag without credentials and an allowlist is still refused.
    let mut open = SocksConfig::new();
    open.loopback_only = false;
    assert!(Socks5Server::new(listen, Arc::clone(&handler), open).is_err());

    // With both, the non-loopback listener is accepted.
    let mut configured = SocksConfig::new();
    configured.loopback_only = false;
    configured.userpass = Some(UserPass::new("alice", "s3cret").unwrap());
    configured.source_allowlist = vec!["10.0.0.0/8".parse().unwrap()];
    let listener = TcpListener::bind("0.0.0.0:0").await.expect("bind wildcard");
    assert!(Socks5Server::new(listener, Arc::clone(&handler), configured).is_ok());

    // A loopback listener stays allowed with the default configuration.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    assert!(Socks5Server::new(listener, handler, SocksConfig::new()).is_ok());
}

#[tokio::test]
async fn the_source_allowlist_is_enforced() {
    let (handler, _requests) = new_handler();
    let mut config = SocksConfig::new();
    config.source_allowlist = vec!["10.0.0.0/8".parse().unwrap()];
    let (addr, stats, _task) = start(Arc::clone(&handler), config).await;

    let mut stream = timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect did not time out")
        .expect("connect");
    expect_closed(&mut stream).await;
    assert_eq!(stats.get(Counter::SourceDenied), 1);
}

#[tokio::test]
async fn concurrent_unauthenticated_connections_are_bounded_per_source() {
    let (handler, _requests) = new_handler();
    let mut config = SocksConfig::new();
    config.max_unauth_connections_per_ip = 2;
    config.handshake_timeout = Duration::from_secs(30);
    let (addr, stats, _task) = start(Arc::clone(&handler), config).await;

    let first = timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect did not time out")
        .expect("connect");
    let second = timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect did not time out")
        .expect("connect");

    // Both slots must be held before the third connection is attempted,
    // otherwise the accept order decides which connection wins the race.
    for _ in 0..200 {
        if stats.get(Counter::ConnectionsAccepted) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(stats.get(Counter::ConnectionsAccepted) >= 2);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut third = timeout(WAIT, TcpStream::connect(addr))
        .await
        .expect("connect did not time out")
        .expect("connect");
    expect_closed(&mut third).await;
    assert_eq!(stats.get(Counter::ConnectionLimitDropped), 1);

    drop(first);
    drop(second);
}

#[tokio::test]
async fn udp_datagrams_are_relayed_and_replies_are_rewritten() {
    let (handler, _requests) = new_handler();
    let echo = spawn_udp_echo().await;
    let seen = Arc::new(AtomicUsize::new(0));
    handler.script_udp(echo_script(Arc::clone(&seen)));
    let (addr, stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    let (_control, bind) = udp_associate(addr).await;
    assert_eq!(bind.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_ne!(
        bind.port(),
        0,
        "the advertised port must be the real bound port"
    );

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let target = SocksTarget::Ip("127.0.0.1".parse().unwrap());
    let request = udp_datagram(&target, echo.port(), b"hello");
    timeout(WAIT, client.send_to(&request, bind))
        .await
        .expect("send did not time out")
        .expect("send");

    let mut buf = vec![0u8; 2048];
    let (len, from) = timeout(WAIT, client.recv_from(&mut buf))
        .await
        .expect("the relayed reply did not arrive")
        .expect("recv");
    assert_eq!(from, bind, "the reply must come from the relay socket");
    let (header, offset) = wsnet_socks::UdpHeader::parse(&buf[..len]).expect("valid reply header");
    assert_eq!(header.frag, 0);
    assert_eq!(header.port, echo.port());
    assert_eq!(header.target, target);
    assert_eq!(&buf[offset..len], b"hello");

    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert_eq!(stats.get(Counter::UdpRelayed), 1);
    assert_eq!(stats.get(Counter::UdpRepliesSent), 1);
    assert_eq!(stats.get(Counter::UdpAssociateStarted), 1);
}

#[tokio::test]
async fn udp_fragments_and_foreign_sources_are_dropped() {
    let (handler, _requests) = new_handler();
    let echo = spawn_udp_echo().await;
    let seen = Arc::new(AtomicUsize::new(0));
    handler.script_udp(echo_script(Arc::clone(&seen)));
    let (addr, stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    let (_control, bind) = udp_associate(addr).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let target = SocksTarget::Ip("127.0.0.1".parse().unwrap());
    let mut buf = vec![0u8; 2048];

    // FRAG != 0 is dropped and counted, never reassembled (section 7.4).
    let mut fragmented = udp_datagram(&target, echo.port(), b"fragment");
    fragmented[2] = 1;
    client.send_to(&fragmented, bind).await.expect("send");

    // A datagram from an address that is neither the TCP peer nor allowlisted is
    // dropped. Some platforms cannot bind a second loopback address, in which
    // case the rule stays covered by the association unit tests.
    let stranger_bound = UdpSocket::bind("127.0.0.2:0").await;
    let foreign_sent = match &stranger_bound {
        Ok(stranger) => stranger
            .send_to(&udp_datagram(&target, echo.port(), b"foreign"), bind)
            .await
            .is_ok(),
        Err(_) => false,
    };

    // A well-formed datagram proves ordering: receiving its reply means every
    // earlier datagram has already been classified.
    client
        .send_to(&udp_datagram(&target, echo.port(), b"ok"), bind)
        .await
        .expect("send");
    let (len, _from) = timeout(WAIT, client.recv_from(&mut buf))
        .await
        .expect("the valid datagram must still be relayed")
        .expect("recv");
    assert!(len > 0);

    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "only one datagram may reach the handler"
    );
    assert_eq!(stats.get(Counter::UdpFragDropped), 1);
    assert_eq!(
        stats.get(Counter::UdpSourceMismatchDropped),
        u64::from(foreign_sent),
        "a foreign source must be dropped when the platform can produce one"
    );
}

#[tokio::test]
async fn udp_source_port_drift_is_refused() {
    let (handler, _requests) = new_handler();
    let echo = spawn_udp_echo().await;
    let seen = Arc::new(AtomicUsize::new(0));
    handler.script_udp(echo_script(Arc::clone(&seen)));
    let (addr, stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    let (_control, bind) = udp_associate(addr).await;
    let target = SocksTarget::Ip("127.0.0.1".parse().unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let mut buf = vec![0u8; 2048];

    // The first datagram locks the endpoint.
    client
        .send_to(&udp_datagram(&target, echo.port(), b"first"), bind)
        .await
        .expect("send");
    let (len, _from) = timeout(WAIT, client.recv_from(&mut buf))
        .await
        .expect("the first datagram must be relayed")
        .expect("recv");
    assert!(len > 0);

    // A second socket, same address but a different port, must not be followed.
    let drifted = UdpSocket::bind("127.0.0.1:0").await.expect("drifted bind");
    drifted
        .send_to(&udp_datagram(&target, echo.port(), b"drift"), bind)
        .await
        .expect("send");

    client
        .send_to(&udp_datagram(&target, echo.port(), b"second"), bind)
        .await
        .expect("send");
    let (_len, _from) = timeout(WAIT, client.recv_from(&mut buf))
        .await
        .expect("the locked endpoint must keep working")
        .expect("recv");

    assert_eq!(seen.load(Ordering::SeqCst), 2);
    assert_eq!(stats.get(Counter::UdpSourceDriftDropped), 1);
}

#[tokio::test]
async fn udp_unmapped_and_unexpected_replies_are_dropped() {
    let (handler, _requests) = new_handler();
    let echo = spawn_udp_echo().await;
    let target = SocksTarget::Ip("127.0.0.1".parse().unwrap());
    let echo_port = echo.port();

    // For the first datagram the script answers three times: an unmapped
    // target, a hijacked source for the mapped target, and the real answer.
    handler.script_udp(Arc::new(move |mut control: UdpControl| {
        Box::pin(async move {
            while let Some(datagram) = control.recv().await {
                let unmapped = UdpReply::new(
                    SocksTarget::Ip("192.0.2.1".parse().expect("ip")),
                    9,
                    "192.0.2.1:9".parse().expect("addr"),
                    b"unmapped".to_vec(),
                );
                let hijacked = UdpReply::new(
                    datagram.target.clone(),
                    datagram.port,
                    "127.0.0.9:1".parse().expect("addr"),
                    b"hijacked".to_vec(),
                );
                let real = UdpReply::new(
                    datagram.target.clone(),
                    datagram.port,
                    format!("127.0.0.1:{echo_port}").parse().expect("addr"),
                    datagram.payload.clone(),
                );
                for reply in [unmapped, hijacked, real] {
                    if control.send_reply(reply).await.is_err() {
                        return Ok(());
                    }
                }
            }
            Ok(())
        })
    }));
    let (addr, stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    let (_control, bind) = udp_associate(addr).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    client
        .send_to(&udp_datagram(&target, echo_port, b"answer"), bind)
        .await
        .expect("send");
    let mut buf = vec![0u8; 2048];
    let (len, _from) = timeout(WAIT, client.recv_from(&mut buf))
        .await
        .expect("the mapped reply must arrive")
        .expect("recv");
    let (header, offset) = wsnet_socks::UdpHeader::parse(&buf[..len]).expect("valid header");
    assert_eq!(header.target, target);
    assert_eq!(header.port, echo_port);
    assert_eq!(&buf[offset..len], b"answer");

    // Nothing else may be delivered: the other two replies must have been
    // dropped rather than rewritten for this client.
    let mut extra = vec![0u8; 2048];
    let unexpected = timeout(Duration::from_millis(300), client.recv_from(&mut extra)).await;
    assert!(
        unexpected.is_err(),
        "an unmapped or hijacked reply was delivered"
    );
    assert_eq!(stats.get(Counter::UdpUnmappedReplyDropped), 1);
    assert_eq!(stats.get(Counter::UdpUnexpectedSourceDropped), 1);
    assert_eq!(stats.get(Counter::UdpRepliesSent), 1);
}

#[tokio::test]
async fn udp_queued_datagrams_expire_on_the_monotonic_ttl() {
    let (handler, _requests) = new_handler();
    let echo = spawn_udp_echo().await;
    let (expired_tx, mut expired_rx) = mpsc::unbounded_channel::<bool>();
    handler.script_udp(Arc::new(move |mut control: UdpControl| {
        let signal = expired_tx.clone();
        Box::pin(async move {
            // Waiting past the queue TTL must leave the datagram expired, so it
            // is dropped and counted instead of being relayed late.
            tokio::time::sleep(Duration::from_millis(300)).await;
            let received = control.try_recv();
            let _ = signal.send(received.is_none());
            Ok(())
        })
    }));
    let mut config = SocksConfig::new();
    config.udp_queue_ttl = Duration::from_millis(100);
    let (addr, stats, _task) = start(Arc::clone(&handler), config).await;

    let (_control, bind) = udp_associate(addr).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let target = SocksTarget::Ip("127.0.0.1".parse().unwrap());
    client
        .send_to(&udp_datagram(&target, echo.port(), b"late"), bind)
        .await
        .expect("send");

    let none_received = timeout(WAIT, expired_rx.recv())
        .await
        .expect("the handler never observed the expiry")
        .expect("handler signal");
    assert!(
        none_received,
        "an expired datagram was handed to the handler"
    );
    // The datagram was handed over for relaying, then expired before a handler
    // could take it live, so it was dropped and counted rather than relayed.
    assert_eq!(stats.get(Counter::UdpRelayed), 1);
    assert_eq!(stats.get(Counter::UdpTtlExpiredDropped), 1);
    assert_eq!(stats.get(Counter::UdpRepliesSent), 0);
}

#[tokio::test]
async fn closing_the_control_connection_tears_the_association_down() {
    let (handler, _requests) = new_handler();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<()>();
    handler.script_udp(Arc::new(move |mut control: UdpControl| {
        let signal = ended_tx.clone();
        Box::pin(async move {
            control.closed().await;
            let _ = signal.send(());
            Ok(())
        })
    }));
    let (addr, stats, _task) = start(Arc::clone(&handler), SocksConfig::new()).await;

    let (control, bind) = udp_associate(addr).await;
    assert!(!bind.ip().is_unspecified());

    // Dropping the controlling TCP connection must end the association.
    drop(control);
    timeout(WAIT, ended_rx.recv())
        .await
        .expect("the handler was not told the association ended")
        .expect("handler signal");

    // The relay socket is gone, so nothing answers on the advertised address.
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let target = SocksTarget::Ip("127.0.0.1".parse().unwrap());
    let _ = client
        .send_to(&udp_datagram(&target, 53, b"after"), bind)
        .await;
    let mut buf = vec![0u8; 64];
    match timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await {
        // Either the datagram is swallowed, or the closed port answers with an
        // ICMP error that surfaces as a socket error; both mean no relay.
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("the torn-down association still relayed a datagram"),
    }
    assert_eq!(stats.get(Counter::UdpAssociationEnded), 1);
}

#[tokio::test]
async fn an_idle_association_is_torn_down() {
    let (handler, _requests) = new_handler();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<()>();
    handler.script_udp(Arc::new(move |mut control: UdpControl| {
        let signal = ended_tx.clone();
        Box::pin(async move {
            control.closed().await;
            let _ = signal.send(());
            Ok(())
        })
    }));
    let mut config = SocksConfig::new();
    config.udp_idle_timeout = Duration::from_millis(200);
    let (addr, stats, _task) = start(Arc::clone(&handler), config).await;

    let (control, _bind) = udp_associate(addr).await;
    timeout(WAIT, ended_rx.recv())
        .await
        .expect("the idle association was never torn down")
        .expect("handler signal");
    assert_eq!(stats.get(Counter::UdpAssociationEnded), 1);
    drop(control);
}

#[tokio::test]
async fn udp_associate_is_refused_when_disabled() {
    let (handler, _requests) = new_handler();
    let mut config = SocksConfig::new();
    config.udp_enabled = false;
    let (addr, stats, _task) = start(Arc::clone(&handler), config).await;

    let mut stream = handshake(addr).await;
    let target = SocksTarget::Ip("127.0.0.1".parse().unwrap());
    send_request(&mut stream, Command::UdpAssociate, &target, 5300).await;
    assert_eq!(
        read_reply(&mut stream).await.0,
        ReplyCode::CommandNotSupported
    );
    assert_eq!(stats.get(Counter::UnsupportedCommand), 1);
    assert_eq!(stats.get(Counter::UdpAssociateStarted), 0);
}

/// A handler script that echoes every relayed datagram through a real UDP
/// socket, so the test exercises the whole relay path.
fn echo_script(seen: Arc<AtomicUsize>) -> UdpScript {
    echo_script_on(seen, "127.0.0.1:0")
}

/// The same echo script, with a chosen address family for the relay socket.
fn echo_script_on(seen: Arc<AtomicUsize>, bind: &'static str) -> UdpScript {
    Arc::new(move |mut control: UdpControl| {
        let seen = Arc::clone(&seen);
        Box::pin(async move {
            let socket = UdpSocket::bind(bind).await?;
            let mut buffer = vec![0u8; 65_535];
            while let Some(datagram) = control.recv().await {
                seen.fetch_add(1, Ordering::SeqCst);
                let SocksTarget::Ip(ip) = &datagram.target else {
                    return Err(SocksError::Handler("tests only use IP targets".to_string()));
                };
                let destination = SocketAddr::new(*ip, datagram.port);
                socket.send_to(&datagram.payload, destination).await?;
                let (len, source) = socket.recv_from(&mut buffer).await?;
                let reply = UdpReply::new(
                    datagram.target.clone(),
                    datagram.port,
                    source,
                    buffer[..len].to_vec(),
                );
                if control.send_reply(reply).await.is_err() {
                    break;
                }
            }
            Ok(())
        })
    })
}

#[tokio::test]
async fn a_udp_association_matches_the_ipv6_family() {
    let (handler, _requests) = new_handler();
    let Ok(listener) = TcpListener::bind("[::1]:0").await else {
        // IPv6 may be unavailable on the host; the family rule is also covered
        // by the configuration unit tests.
        return;
    };
    let echo = spawn_udp_echo_on("[::1]:0").await;
    let seen = Arc::new(AtomicUsize::new(0));
    handler.script_udp(echo_script_on(Arc::clone(&seen), "[::1]:0"));
    let (addr, stats, _task) = start_on(listener, Arc::clone(&handler), SocksConfig::new()).await;

    let mut stream = handshake(addr).await;
    let target = SocksTarget::Ip("::1".parse().unwrap());
    send_request(&mut stream, Command::UdpAssociate, &target, 5300).await;
    let (code, bind) = read_reply(&mut stream).await;
    assert_eq!(code, ReplyCode::Succeeded);
    assert!(
        bind.is_ipv6(),
        "the advertised association address must match the control connection family"
    );

    let client = UdpSocket::bind("[::1]:0").await.expect("client bind");
    client
        .send_to(&udp_datagram(&target, echo.port(), b"v6"), bind)
        .await
        .expect("send");
    let mut buf = vec![0u8; 2048];
    let (len, from) = timeout(WAIT, client.recv_from(&mut buf))
        .await
        .expect("the relayed IPv6 reply did not arrive")
        .expect("recv");
    assert_eq!(from, bind);
    let (header, offset) = wsnet_socks::UdpHeader::parse(&buf[..len]).expect("valid header");
    assert_eq!(header.target, target);
    assert_eq!(header.port, echo.port());
    assert_eq!(&buf[offset..len], b"v6");
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert_eq!(stats.get(Counter::UdpRepliesSent), 1);
}
