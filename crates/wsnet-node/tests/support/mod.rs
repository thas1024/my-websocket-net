//! A stub Hub that speaks the real wsnet protocol over a loopback TCP listener.
//!
//! The stub exists so the node can be tested end to end in one process without a
//! live Hub deployment. It is deliberately built from the same crates the real
//! Hub would use  `verify_auth`, `authok_mac`, `session_keys`, and a real
//! `SessionHandle` on `Side::Hub`  so a test that passes proves agreement on the
//! wire format, not agreement with a mock.
//!
//! Framing on the loopback link is `length:u32be | body`, where the body is the
//! canonical metadata of `Auth`/`AuthOk` during the bootstrap and a sealed
//! envelope afterwards. That framing is a property of this test transport only;
//! the records inside it are the production ones.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use wsnet_crypto::Psk;
use wsnet_limits::MAX_CARRIER_RECORD;
use wsnet_node::{
    BoundSession, BoxFuture, CarrierIo, CarrierKind, HubEndpoint, HubTransport, NodeError,
    TransportFactory,
};
use wsnet_protocol::Canonical;
use wsnet_session::{
    auth_mac, authok_mac, fresh_epoch, fresh_nonce, fresh_session_id, session_keys, verify_auth,
    AuthOkFields, HelloFields, HelloOkFields, OpenFields, OpenResultFields, OpenStatus, Session,
    SessionConfig, SessionEvent, Side,
};
use wsnet_protocol::{MessageKind, Record};

/// Everything about the stub Hub's behaviour that a test may want to vary.
#[derive(Clone)]
pub struct StubConfig {
    /// Hub identity the stub authenticates as.
    pub hub_id: String,
    /// Node identity the stub expects.
    pub node_id: String,
    /// Pre-shared key the stub verifies against.
    pub psk: Psk,
    /// Whether the stub answers `Hello` with `HelloOk`.
    pub hello_ok: bool,
    /// Whether the `AuthOk` MAC is computed correctly.
    pub authok_ok: bool,
    /// Whether the stub sends a `PeerList` at all.
    pub peer_list: bool,
    /// The `(node, service)` pairs the stub advertises in its `PeerList`.
    pub services: Vec<(String, String)>,
    /// Whether the stub echoes every `Data` record back.
    pub echo: bool,
}

impl Default for StubConfig {
    fn default() -> Self {
        StubConfig {
            hub_id: "hub-a".to_string(),
            node_id: "client-a".to_string(),
            psk: Psk::from_bytes([0x42; 32]),
            hello_ok: true,
            authok_ok: true,
            peer_list: false,
            services: Vec::new(),
            echo: true,
        }
    }
}

impl StubConfig {
    /// A stub that advertises exactly the named services.
    pub fn advertising(services: &[(&str, &str)]) -> Self {
        StubConfig {
            peer_list: true,
            services: services
                .iter()
                .map(|(node, name)| ((*node).to_string(), (*name).to_string()))
                .collect(),
            ..StubConfig::default()
        }
    }

    /// A stub that withholds `HelloOk`, so the business barrier never lifts.
    pub fn silent_after_auth() -> Self {
        StubConfig {
            hello_ok: false,
            ..StubConfig::default()
        }
    }

    /// A stub that answers with a valid but wrongly signed `AuthOk`.
    pub fn bad_authok() -> Self {
        StubConfig {
            authok_ok: false,
            ..StubConfig::default()
        }
    }
}

/// What the stub Hub observed, for assertions.
#[derive(Default)]
pub struct Observed {
    /// Every `Open` the stub authenticated, in arrival order.
    pub opens: Mutex<Vec<OpenFields>>,
    /// Every `Hello` the stub authenticated.
    pub hellos: Mutex<Vec<HelloFields>>,
    /// How many `AuthOk` bootstraps were answered.
    pub auth_ok_sent: AtomicUsize,
    /// How many `Fin` records arrived.
    pub fins: AtomicUsize,
}

impl Observed {
    /// The destinations the stub was asked to open.
    pub fn destinations(&self) -> Vec<wsnet_routing::Destination> {
        self.opens
            .lock()
            .unwrap()
            .iter()
            .map(|fields| fields.destination.clone())
            .collect()
    }
}

/// A running stub Hub.
pub struct StubHub {
    /// The loopback address the stub listens on.
    pub addr: SocketAddr,
    /// What the stub saw.
    pub observed: Arc<Observed>,
}

impl StubHub {
    /// Binds a stub Hub and starts accepting connections.
    pub async fn start(config: StubConfig) -> StubHub {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub hub");
        let addr = listener.local_addr().expect("stub hub address");
        let observed = Arc::new(Observed::default());
        let observed_for_task = Arc::clone(&observed);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let config = config.clone();
                let observed = Arc::clone(&observed_for_task);
                tokio::spawn(async move {
                    // One connection is one carrier; a failure ends that carrier
                    // only, exactly as a real Hub would treat it.
                    let _ = serve_connection(stream, config, observed).await;
                });
            }
        });
        StubHub { addr, observed }
    }

    /// A transport for this stub, built the way the node builds it.
    pub async fn transport(&self) -> Arc<dyn HubTransport> {
        let transport: Arc<dyn HubTransport> = Arc::new(StubCarrier {
            connection: Arc::new(StubConnection {
                addr: self.addr,
                stream: Mutex::new(None),
            }),
        });
        transport
    }

    /// The `[[servers]]` entry that would reach this stub.
    pub fn endpoint(&self, hub_id: &str) -> HubEndpoint {
        HubEndpoint {
            hub_id: hub_id.to_string(),
            url: self.url(),
            key_id: "key-1".to_string(),
            priority: 1,
        }
    }

    /// The `[[servers]]` URL for this stub.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// A transport factory that routes each Hub id to its own stub.
pub struct StubNetwork {
    routes: std::collections::HashMap<String, SocketAddr>,
}

impl StubNetwork {
    /// Routes `(hub_id, stub)` pairs.
    pub fn new(routes: &[(&str, &StubHub)]) -> Self {
        StubNetwork {
            routes: routes
                .iter()
                .map(|(hub_id, hub)| ((*hub_id).to_string(), hub.addr))
                .collect(),
        }
    }
}

impl TransportFactory for StubNetwork {
    fn open(
        &self,
        endpoint: &HubEndpoint,
    ) -> BoxFuture<'static, Result<Arc<dyn HubTransport>, NodeError>> {
        let hub_id = endpoint.hub_id.clone();
        let addr = self.routes.get(&endpoint.hub_id).copied();
        Box::pin(async move {
            let addr = addr.ok_or(NodeError::UnknownHub { hub_id })?;
            let transport: Arc<dyn HubTransport> = Arc::new(StubCarrier {
                connection: Arc::new(StubConnection {
                    addr,
                    stream: Mutex::new(None),
                }),
            });
            Ok(transport)
        })
    }
}

async fn serve_connection(
    stream: TcpStream,
    config: StubConfig,
    observed: Arc<Observed>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();

    // --- bootstrap ---------------------------------------------------------
    let auth_bytes = read_frame(&mut reader).await?;
    // The node sends the bootstrap as an `Auth` record, which is the same shape
    // the real Hub decodes. The stub mirrors that exactly so the two framings
    // cannot drift apart unnoticed.
    let auth_record =
        Record::decode(&auth_bytes).map_err(|error| invalid(error.to_string()))?;
    if auth_record.kind != MessageKind::Auth {
        return Err(invalid(format!(
            "stub hub expected Auth, got {}",
            auth_record.kind
        )));
    }
    let auth = verify_auth(&config.psk, &auth_record.metadata)
        .map_err(|error| invalid(format!("stub hub refused Auth: {error}")))?;
    // The Hub is configured per node identity, so an unexpected one is refused
    // before any session key is derived.
    if auth.node_id != config.node_id {
        return Err(invalid(format!(
            "stub hub expected node `{}`, got `{}`",
            config.node_id, auth.node_id
        )));
    }
    if auth.hub_id != config.hub_id {
        return Err(invalid(format!(
            "stub hub `{}` was addressed as `{}`",
            config.hub_id, auth.hub_id
        )));
    }
    let auth_mac = auth_mac(&config.psk, &auth);
    let authok = AuthOkFields {
        session_id: fresh_session_id(),
        session_epoch: fresh_epoch(),
        attempt_id: auth.attempt_id,
        server_nonce: fresh_nonce(),
        expires_at: auth.ts + 600,
        capabilities: auth.capabilities.clone(),
    };
    let mut ok_mac = authok_mac(&config.psk, &auth_mac, &authok);
    if !config.authok_ok {
        ok_mac[0] ^= 0xff;
    }
    let authok_record = Record::new(MessageKind::AuthOk, authok.to_canonical(&ok_mac))
        .encode()
        .map_err(|error| invalid(error.to_string()))?;
    write_frame(&mut writer, &authok_record).await?;
    observed.auth_ok_sent.fetch_add(1, Ordering::SeqCst);

    let keys = session_keys(&config.psk, &auth, &authok);
    // The Hub id is bound into the envelope's associated data, so the stub must
    // answer as the identity the node addressed it by.
    let session = Session::new(
        SessionConfig::new(
            auth.hub_id.clone(),
            auth.node_id.clone(),
            authok.session_id,
            authok.session_epoch,
            Side::Hub,
        ),
        keys,
    );
    let handle = session.handle.clone();
    let mut events = session.events;
    let mut outbound = session.outbound;

    // --- carriers ----------------------------------------------------------
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Some(body) = out_rx.recv().await {
            if write_frame(&mut writer, &body).await.is_err() {
                return;
            }
        }
    });

    let feed_handle = handle.clone();
    tokio::spawn(async move {
        loop {
            match read_frame(&mut reader).await {
                Ok(body) => {
                    if !feed_handle.feed_lossy(&body) {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    let pump = out_tx.clone();
    tokio::spawn(async move {
        while let Some(envelope) = outbound.recv().await {
            if pump.send(envelope).is_err() {
                return;
            }
        }
    });

    // --- hub-side business logic -------------------------------------------
    let echo_handle = handle.clone();
    while let Some(event) = events.recv().await {
        match event {
            SessionEvent::Hello(fields) => {
                observed.hellos.lock().unwrap().push(fields);
                if !config.hello_ok {
                    continue;
                }
                let _ = handle.send_hello_ok(&HelloOkFields {
                    request_id: [0u8; 16],
                    capabilities: vec!["flow.credit".to_string()],
                });
                if config.peer_list {
                    let _ = handle.send_peer_list(peer_list(&config.services));
                }
            }
            SessionEvent::Open(fields) => {
                observed.opens.lock().unwrap().push(fields.clone());
                let _ = handle.send_open_result(&OpenResultFields {
                    request_id: fields.request_id,
                    stream_id: fields.stream_id,
                    status: OpenStatus::Ok,
                    detail: "stub hub accepted the open".to_string(),
                });
            }
            SessionEvent::Data {
                stream_id, payload, ..
            } => {
                if config.echo {
                    let _ = echo_handle.send_data(stream_id, &payload);
                }
            }
            SessionEvent::Fin(fields) => {
                observed.fins.fetch_add(1, Ordering::SeqCst);
                if config.echo {
                    let _ = echo_handle.send_fin(fields.stream_id);
                }
            }
            SessionEvent::Ping => {
                let _ = handle.send_pong();
            }
            SessionEvent::Bye(_) => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

/// The `PeerList` metadata shape this node reads (DESIGN.md section 4.1).
fn peer_list(services: &[(String, String)]) -> Canonical {
    Canonical::object([
        (
            "services",
            Canonical::Array(
                services
                    .iter()
                    .map(|(node, name)| {
                        Canonical::object([
                            ("name", Canonical::str(name.clone())),
                            ("node", Canonical::str(node.clone())),
                            ("proto", Canonical::str("tcp")),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("version", Canonical::int(1)),
    ])
}

/// The connection an authenticated stub carrier keeps until `bind` takes it.
struct StubConnection {
    addr: SocketAddr,
    stream: Mutex<Option<TcpStream>>,
}

/// The stub carrier: one TCP connection, length-prefixed frames both ways.
struct StubCarrier {
    connection: Arc<StubConnection>,
}

impl HubTransport for StubCarrier {
    fn authenticate(&self, auth: Vec<u8>) -> BoxFuture<'static, Result<Vec<u8>, NodeError>> {
        // The connection is moved into the shared slot so that `bind`, which
        // gets only `&self`, can take it over.
        let connection = Arc::clone(&self.connection);
        Box::pin(async move {
            let mut stream = TcpStream::connect(connection.addr)
                .await
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            write_frame(&mut stream, &auth)
                .await
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            let body = read_frame(&mut stream)
                .await
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            *connection.stream.lock().unwrap() = Some(stream);
            Ok(body)
        })
    }

    fn bind(
        &self,
        _session: BoundSession,
    ) -> BoxFuture<'static, Result<Vec<CarrierIo>, NodeError>> {
        let connection = Arc::clone(&self.connection);
        Box::pin(async move {
            let stream = connection.stream.lock().unwrap().take().ok_or_else(|| {
                NodeError::Carrier("the stub transport was not authenticated".into())
            })?;
            let (mut reader, mut writer) = stream.into_split();
            let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
            let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();

            tokio::spawn(async move {
                while let Some(body) = outbound_rx.recv().await {
                    if write_frame(&mut writer, &body).await.is_err() {
                        return;
                    }
                }
            });
            tokio::spawn(async move {
                loop {
                    match read_frame(&mut reader).await {
                        Ok(body) => {
                            if inbound_tx.send(body).is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });

            Ok(vec![CarrierIo::new(
                CarrierKind::Post,
                inbound_rx,
                outbound_tx,
            )])
        })
    }

    fn health(&self, _session: BoundSession) -> BoxFuture<'static, Result<(), NodeError>> {
        // The stub's liveness is the connection itself, so a health round trip
        // succeeds until the connection is gone; the node's thresholds are
        // covered by the `HealthTracker` unit tests.
        Box::pin(async move { Ok(()) })
    }
}

/// Writes one length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    body: &[u8],
) -> std::io::Result<()> {
    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

/// Reads one length-prefixed frame, bounded by the carrier record limit.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut prefix = [0u8; 4];
    reader.read_exact(&mut prefix).await?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_CARRIER_RECORD {
        return Err(invalid(format!("frame of {len} bytes exceeds the bound")));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

fn invalid(reason: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, reason.into())
}

/// Runs a future under a hard deadline, so a broken path fails instead of hanging.
pub async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(Duration::from_secs(10), future).await {
        Ok(value) => value,
        Err(_) => panic!("the test exceeded its 10 s budget"),
    }
}

/// Polls `condition` until it holds, or fails the test.
pub async fn wait_for(mut condition: impl FnMut() -> bool) {
    for _ in 0..400 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the condition never became true");
}

/// A loopback port nothing is listening on any more.
pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    listener.local_addr().expect("probe address").port()
}
