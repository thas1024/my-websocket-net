//! The WebSocket carrier set of DESIGN.md section 6.1: one socket, both ways.
//!
//! Section 6.1 allows client-to-server data over a WebSocket or over HTTPS
//! `POST`, and section 6.2 allows server-to-client data over a WebSocket, SSE, or
//! a bounded `POST` response. The Hub serves the WebSocket form at `GET /w`, so a
//! deployment that switches `POST /m` off still has a carrier pair that satisfies
//! section 5.3's "at least one combination that can send and receive" — and it
//! satisfies it with a *single* carrier, because a WebSocket is uplink- and
//! downlink-capable at once.
//!
//! Two upgrade forms exist on the Hub side and both are used here:
//!
//! * the bootstrap form, which presents no `BindProof` because no session exists
//!   yet, and exchanges one hex-encoded `Auth` for one hex-encoded `AuthOk` in
//!   Text frames inside `WS_AUTH_DEADLINE_SECS`;
//! * the bound form, which presents the section 4.4 `BindProof` for `GET /w` and
//!   then carries exactly one sealed envelope per Binary frame.
//!
//! A Text frame after a bound upgrade is a protocol violation, and so is a Binary
//! frame that the shared `wsnet-transport` codec refuses; both end the carrier
//! rather than being skipped, because section 4.3 makes the Binary record the
//! only thing a WebSocket carrier may move.
//!
//! The bootstrap socket is deliberately *retained* rather than dropped once
//! `AuthOk` arrives. The Hub's `GET /w` handler continues the same socket into
//! the bound loop, so that socket owns the session's lifetime: closing it would
//! tear down the lease before `bind` could present a proof for it. It is held for
//! as long as this transport lives, which is exactly as long as its session.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use reqwest::header::{HeaderMap, HeaderValue};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tracing::debug;

use wsnet_config::ClientCarrier;
use wsnet_limits::{BIND_PROOF_TTL_SECS, HANDSHAKE_TIMEOUT_MS, WS_AUTH_DEADLINE_SECS};
use wsnet_session::{binding_mac, body_hash, BindProof, BindTarget, BIND_PROOF_HEADER};

use crate::carrier::{CarrierIo, CarrierKind};
use crate::endpoint::{BoundSession, HubEndpoint, HubTransport, TransportFactory};
use crate::http::HttpTransportFactory;
use crate::node::NodeError;
use crate::{lock, BoxFuture};

/// One upgraded WebSocket, however it was negotiated.
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Where a bound carrier accepts a liveness probe.
type ProbeSender = mpsc::UnboundedSender<Probe>;

/// Selects the carrier family a configuration asked for.
///
/// DESIGN.md section 6.1 makes the choice a deployment decision rather than a
/// capability the node may guess, so the mapping is total and explicit: `Auto`
/// and `Post` keep the shipped `POST /m` plus `GET /e` pair, and only an explicit
/// `Ws` moves the node onto `GET /w`. That is what keeps an existing deployment's
/// behaviour unchanged across an upgrade.
pub fn factory_for(carrier: ClientCarrier) -> Arc<dyn TransportFactory> {
    match carrier {
        ClientCarrier::Auto | ClientCarrier::Post => Arc::new(HttpTransportFactory::default()),
        ClientCarrier::Ws => Arc::new(WsTransportFactory::new()),
    }
}

/// Builds the WebSocket carrier for every Hub.
pub struct WsTransportFactory {
    request_timeout: Duration,
}

impl Default for WsTransportFactory {
    fn default() -> Self {
        WsTransportFactory {
            request_timeout: Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
        }
    }
}

impl WsTransportFactory {
    /// Builds a factory with the design's handshake deadline for every upgrade.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the deadline applied to each upgrade and liveness round trip.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

impl TransportFactory for WsTransportFactory {
    fn open(
        &self,
        endpoint: &HubEndpoint,
    ) -> BoxFuture<'static, Result<Arc<dyn HubTransport>, NodeError>> {
        let transport = WsTransport {
            base: endpoint.url.trim_end_matches('/').to_string(),
            request_timeout: self.request_timeout,
            bootstrap: Arc::new(Mutex::new(None)),
            probe: Arc::new(Mutex::new(None)),
        };
        Box::pin(async move { Ok(Arc::new(transport) as Arc<dyn HubTransport>) })
    }
}

/// One Hub's WebSocket carriers.
///
/// The value is created by [`WsTransportFactory::open`] and belongs to exactly one
/// Hub session, which is why it may own the socket the bootstrap was negotiated
/// on: the Hub ties that socket's lifetime to the session it created.
pub struct WsTransport {
    base: String,
    request_timeout: Duration,
    /// The socket the section 4.4 bootstrap was answered on.
    ///
    /// The Hub keeps using it as the session's carrier after authentication, so it
    /// has to stay open for the whole session rather than only for `authenticate`.
    bootstrap: Arc<Mutex<Option<Socket>>>,
    /// Set once [`HubTransport::bind`] has a live socket, so `health` can probe
    /// the carrier the session actually uses instead of opening a second one.
    probe: Arc<Mutex<Option<ProbeSender>>>,
}

impl WsTransport {
    /// The `GET /w` endpoint, derived by upgrading the configured base URL's
    /// scheme rather than by rewriting it, so a deployment's `http(s)` spelling
    /// survives.
    fn carrier_url(&self) -> String {
        let base = match self.base.split_once("://") {
            Some(("http", rest)) => format!("ws://{rest}"),
            Some(("https", rest)) => format!("wss://{rest}"),
            // The schema refuses a base that is not absolute `http(s)`, so this is
            // reached only by a caller that bypassed validation; letting the
            // upgrade fail is better than inventing a scheme.
            _ => self.base.clone(),
        };
        format!("{base}/w")
    }

    /// A bootstrap upgrade request, which carries no proof because section 4.4
    /// reserves an unauthenticated `GET /w` for exactly this exchange.
    fn bootstrap_request(&self) -> Result<Request, NodeError> {
        let url = self.carrier_url();
        url.as_str()
            .into_client_request()
            .map_err(|error| NodeError::Transport(error.to_string()))
    }

    /// A bound upgrade request, carrying the section 4.4 proof for `GET /w`.
    fn bound_request(&self, session: &BoundSession) -> Result<Request, NodeError> {
        let url = self.carrier_url();
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|error| NodeError::Transport(error.to_string()))?;
        request
            .headers_mut()
            .extend(Self::bind_headers(session, "GET", "/w", &[]));
        Ok(request)
    }

    /// Builds the `BindProof` header for one request.
    ///
    /// Section 4.4 makes the proof cover the method, the canonical path, the
    /// session identity, the channel, the *body hash*, and an expiry, and makes
    /// the nonce single-use. A proof is therefore built once per request rather
    /// than once per session, which is why this cannot be a cached header map:
    /// a proof for an empty-body `GET /w` must not be replayable onto a `POST /m`
    /// carrying a batch.
    fn bind_headers(session: &BoundSession, method: &str, path: &str, body: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let now = unix_seconds();
        let proof = BindProof {
            session_id: session.session_id,
            channel_id: fresh_channel_id(),
            bind_nonce: fresh_bind_nonce(),
            // Section 4.4 caps the lifetime at 30 seconds and at the session
            // expiry; the session TTL is far longer, so the cap is what binds.
            expires_at: now + BIND_PROOF_TTL_SECS as i64,
            mac: [0u8; 32],
        };
        let target = BindTarget {
            method,
            path,
            hub_id: &session.hub_id,
            session_id: session.session_id,
            session_epoch: session.session_epoch,
            channel_id: proof.channel_id,
            bind_nonce: proof.bind_nonce,
            body_hash: body_hash(body),
            expires_at: proof.expires_at,
        };
        let mac = binding_mac(&session.bind_key, &target);
        let proof = BindProof { mac, ..proof };
        if let Ok(value) = HeaderValue::from_str(&proof.encode()) {
            headers.insert(BIND_PROOF_HEADER, value);
        }
        headers
    }

    /// Upgrades one request into a WebSocket inside the handshake deadline.
    ///
    /// A refusal arrives as an HTTP response rather than as an upgrade, so the
    /// library's error is split out only to say which side refused; the caller
    /// treats both as a failed carrier.
    async fn connect(request: Request, timeout: Duration) -> Result<Socket, NodeError> {
        match tokio::time::timeout(timeout, connect_async(request)).await {
            Ok(Ok((socket, _response))) => Ok(socket),
            Ok(Err(error)) => Err(NodeError::Transport(format!(
                "the hub did not complete the websocket upgrade: {error}"
            ))),
            Err(_) => Err(NodeError::Transport(
                "the websocket upgrade did not complete inside the handshake deadline".to_string(),
            )),
        }
    }
}

impl HubTransport for WsTransport {
    fn authenticate(&self, auth: Vec<u8>) -> BoxFuture<'static, Result<Vec<u8>, NodeError>> {
        let request = self.bootstrap_request();
        let timeout = self.request_timeout;
        let bootstrap = Arc::clone(&self.bootstrap);
        Box::pin(async move {
            let request = request?;
            let mut socket = WsTransport::connect(request, timeout).await?;
            // Section 4.4 transports the unsealed `Auth` as hex inside a Text
            // frame, because a Text frame has to stay valid UTF-8 while the record
            // is arbitrary bytes. The record itself stays unsealed: no session key
            // exists yet, which is what makes this the bootstrap.
            socket
                .send(Message::Text(hex::encode(&auth)))
                .await
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            // The Hub gives the peer `WS_AUTH_DEADLINE_SECS` to produce the `Auth`
            // and answers inside that window; waiting exactly that long means the
            // node neither abandons a session the Hub is about to accept nor hangs
            // past the Hub's own refusal.
            let deadline = Duration::from_secs(WS_AUTH_DEADLINE_SECS);
            let frame = tokio::time::timeout(deadline, socket.next())
                .await
                .map_err(|_| {
                    NodeError::Transport(
                        "the hub did not answer the Auth bootstrap inside its own deadline"
                            .to_string(),
                    )
                })?;
            let text = match frame {
                Some(Ok(Message::Text(text))) => text,
                Some(Ok(_)) => {
                    return Err(NodeError::Transport(
                        "the hub answered the Auth bootstrap with something other than text"
                            .to_string(),
                    ))
                }
                Some(Err(error)) => return Err(NodeError::Transport(error.to_string())),
                None => {
                    return Err(NodeError::Transport(
                        "the hub closed the socket instead of answering the Auth bootstrap"
                            .to_string(),
                    ))
                }
            };
            let bytes = hex::decode(text.trim())
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            // The Hub's `GET /w` handler carries this same socket on into the bound
            // loop, so the socket *is* the session's lifetime. Handing it to the
            // transport is what keeps the session alive until `bind` presents its
            // proof, and what lets the session end the moment the carrier does.
            *lock(&bootstrap) = Some(socket);
            Ok(bytes)
        })
    }

    fn bind(&self, session: BoundSession) -> BoxFuture<'static, Result<Vec<CarrierIo>, NodeError>> {
        let request = self.bound_request(&session);
        let timeout = self.request_timeout;
        let probe_slot = Arc::clone(&self.probe);
        Box::pin(async move {
            let socket = WsTransport::connect(request?, timeout).await?;
            let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
            let (probe_tx, probe_rx) = mpsc::unbounded_channel();
            *lock(&probe_slot) = Some(probe_tx);
            // One socket carries both directions, so there is exactly one carrier
            // here rather than the HTTP pair; section 5.3 is satisfied by the
            // carrier's kind, not by its count.
            tokio::spawn(pump_socket(socket, inbound_tx, outbound_rx, probe_rx));
            Ok(vec![CarrierIo::new(
                CarrierKind::Ws,
                inbound_rx,
                outbound_tx,
            )])
        })
    }

    fn health(&self, session: BoundSession) -> BoxFuture<'static, Result<(), NodeError>> {
        let live = lock(&self.probe).as_ref().cloned();
        let request = self.bound_request(&session);
        let timeout = self.request_timeout;
        Box::pin(async move {
            // Section 5.5 wants an *authenticated* exchange, and a fresh bound
            // upgrade is exactly that: the Hub verifies a `BindProof` covering this
            // session, so a success proves the Hub still holds the session and that
            // the binding key still works. It is non-destructive because only the
            // socket that authenticated the session owns it
            // (crates/wsnet-hub/src/server.rs), so the probe can come and go.
            let probe_error = match request {
                Ok(request) => match upgrade_probe(request, timeout).await {
                    Ok(()) => return Ok(()),
                    Err(error) => Some(error),
                },
                Err(error) => Some(error),
            };

            // The probe can fail for a reason that has nothing to do with this
            // session — a Hub that is briefly out of descriptors refuses the new
            // socket while serving the existing one perfectly well. Failing the
            // session over that would drop a working carrier, so the live carrier
            // gets the last word: a control-frame round trip on the socket the data
            // actually uses. It is the weaker question, which is why it is only
            // asked after the authenticated one has already failed.
            if let Some(probe) = live {
                let payload = fresh_channel_id().to_vec();
                let (reply_tx, reply_rx) = oneshot::channel();
                if probe
                    .send(Probe {
                        payload,
                        reply: reply_tx,
                    })
                    .is_ok()
                {
                    match tokio::time::timeout(timeout, reply_rx).await {
                        Ok(Ok(result)) => return result,
                        Ok(Err(_)) => {
                            return Err(NodeError::Transport(
                                "the bound websocket ended during the health check".to_string(),
                            ))
                        }
                        Err(_) => {
                            return Err(NodeError::Transport(
                                "the hub did not answer a ping on the bound websocket".to_string(),
                            ))
                        }
                    }
                }
            }
            Err(probe_error.unwrap_or_else(|| {
                NodeError::Transport("the websocket health check could not run".to_string())
            }))
        })
    }
}

/// Forwards both directions of one bound socket and ends the carrier when it does.
///
/// The two channels are the carrier's ends: dropping them is how the session
/// driver observes the carrier closing, so every exit from this task — a closed
/// socket, a refused record, a protocol violation — must leave both dropped.
fn pump_socket(
    socket: Socket,
    inbound: mpsc::UnboundedSender<Vec<u8>>,
    mut outbound: mpsc::UnboundedReceiver<Vec<u8>>,
    mut probes: mpsc::UnboundedReceiver<Probe>,
) -> impl std::future::Future<Output = ()> {
    let (mut sink, mut stream): (SplitSink<Socket, Message>, SplitStream<Socket>) = socket.split();
    async move {
        let mut pending: VecDeque<Probe> = VecDeque::new();
        let mut probes_open = true;
        loop {
            tokio::select! {
                outgoing = outbound.recv() => {
                    let Some(envelope) = outgoing else { break };
                    // The shared codec decides what a legal envelope is, so the
                    // size bound of section 4.3 is enforced on the way out too.
                    let payload = match wsnet_transport::ws::encode(&envelope) {
                        Ok(payload) => payload,
                        Err(error) => {
                            debug!(%error, "the websocket carrier refused an oversized envelope");
                            continue;
                        }
                    };
                    if sink.send(Message::Binary(payload)).await.is_err() {
                        break;
                    }
                }
                probe = probes.recv(), if probes_open => {
                    let Some(probe) = probe else {
                        probes_open = false;
                        continue;
                    };
                    // A Ping is a control frame, never a record, so a liveness
                    // check can never be mistaken for an envelope.
                    if sink.send(Message::Ping(probe.payload.clone())).await.is_err() {
                        let _ = probe.reply.send(Err(NodeError::Transport(
                            "the bound websocket ended".to_string(),
                        )));
                        break;
                    }
                    pending.push_back(probe);
                }
                incoming = stream.next() => match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        match wsnet_transport::ws::decode_ref(&bytes) {
                            Ok(envelope) => {
                                if inbound.send(envelope.to_vec()).is_err() {
                                    break;
                                }
                            }
                            // Section 4.3 lets a peer frame nothing but one sealed
                            // envelope per Binary message, so a record the codec
                            // refuses is a protocol violation rather than a
                            // message to skip.
                            Err(error) => {
                                debug!(%error, "the hub sent a websocket record the codec refuses");
                                break;
                            }
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if sink.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(payload))) => {
                        if let Some(index) = pending.iter().position(|probe| probe.payload == payload) {
                            if let Some(probe) = pending.remove(index) {
                                let _ = probe.reply.send(Ok(()));
                            }
                        }
                    }
                    // Text is legal only in the bootstrap exchange, so after an
                    // upgrade it is the violation the Hub itself would close on.
                    Some(Ok(Message::Text(_))) => {
                        debug!("the hub sent a text frame after the upgrade");
                        break;
                    }
                    // The library's raw-frame variant is never handed to a caller;
                    // ignoring it keeps the record channel Binary-only.
                    Some(Ok(Message::Frame(_))) => continue,
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                },
            }
        }
        // A probe that never got its answer must learn the carrier is gone rather
        // than wait for a reply the socket can no longer deliver.
        for probe in pending {
            let _ = probe.reply.send(Err(NodeError::Transport(
                "the bound websocket ended".to_string(),
            )));
        }
    }
}

/// Opens a bound upgrade, requires the Hub to answer, and then lets it go.
///
/// This proves only that the Hub accepted a section 4.4 proof for this session and
/// kept the socket open long enough to answer a control frame; it says nothing
/// about whether business data can flow. It is also destructive — the Hub ends the
/// session when a bound socket ends — which is why the carrier itself is probed
/// whenever one is bound.
async fn upgrade_probe(request: Request, timeout: Duration) -> Result<(), NodeError> {
    let mut socket = WsTransport::connect(request, timeout).await?;
    let payload = fresh_channel_id().to_vec();
    socket
        .send(Message::Ping(payload.clone()))
        .await
        .map_err(|error| NodeError::Transport(error.to_string()))?;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(NodeError::Transport(
                "the hub did not answer a ping on the bound websocket".to_string(),
            ));
        }
        let incoming = tokio::time::timeout(remaining, socket.next()).await;
        match incoming {
            Ok(Some(Ok(Message::Pong(reply)))) if reply == payload => return Ok(()),
            Ok(Some(Ok(Message::Ping(reply)))) => {
                if socket.send(Message::Pong(reply)).await.is_err() {
                    return Err(NodeError::Transport(
                        "the hub closed the bound websocket health probe".to_string(),
                    ));
                }
            }
            Ok(Some(Ok(Message::Pong(_)))) | Ok(Some(Ok(Message::Binary(_)))) => continue,
            Ok(Some(Ok(Message::Frame(_)))) => continue,
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {
                return Err(NodeError::Transport(
                    "the hub closed the bound websocket health probe".to_string(),
                ))
            }
            Ok(Some(Ok(Message::Text(_)))) => {
                return Err(NodeError::Transport(
                    "the hub sent a text frame after the upgrade".to_string(),
                ))
            }
            Ok(Some(Err(error))) => return Err(NodeError::Transport(error.to_string())),
            Err(_) => {
                return Err(NodeError::Transport(
                    "the hub did not answer a ping on the bound websocket".to_string(),
                ))
            }
        }
    }
}

/// One in-flight liveness probe and where its answer belongs.
struct Probe {
    /// Payload that identifies this probe's Pong, since a Pong carries it back.
    payload: Vec<u8>,
    /// Completed when the matching Pong arrives, or with an error if it cannot.
    reply: oneshot::Sender<Result<(), NodeError>>,
}

/// A fresh 16-byte carrier channel id.
fn fresh_channel_id() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes
}

/// A fresh 16-byte single-use binding nonce.
fn fresh_bind_nonce() -> [u8; 16] {
    fresh_channel_id()
}

/// UTC Unix seconds, matching the Hub's window arithmetic.
fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsnet_session::verify_binding_mac;

    fn session() -> BoundSession {
        BoundSession {
            hub_id: "hub-a".to_string(),
            node_id: "node-a".to_string(),
            session_id: [1u8; 16],
            session_epoch: [2u8; 16],
            bind_key: [3u8; 32],
        }
    }

    fn transport() -> WsTransport {
        WsTransport {
            base: "http://hub.example:8443".to_string(),
            request_timeout: Duration::from_secs(1),
            bootstrap: Arc::new(Mutex::new(None)),
            probe: Arc::new(Mutex::new(None)),
        }
    }

    /// Section 4.4: the configured base is upgraded in scheme, not rewritten.
    #[test]
    fn the_carrier_url_keeps_the_configured_scheme_and_gains_the_path() {
        assert_eq!(transport().carrier_url(), "ws://hub.example:8443/w");

        let secure = WsTransport {
            base: "https://hub.example".to_string(),
            ..transport()
        };
        assert_eq!(secure.carrier_url(), "wss://hub.example/w");
    }

    /// Section 4.4: a bound upgrade must present a proof over `GET /w` with an
    /// empty body, so a proof made for `POST /m` can never be replayed onto it.
    #[test]
    fn the_bound_upgrade_proof_covers_get_slash_w_and_an_empty_body() {
        let session = session();
        let headers = WsTransport::bind_headers(&session, "GET", "/w", &[]);
        let value = headers
            .get(BIND_PROOF_HEADER)
            .expect("the proof header must be present")
            .to_str()
            .expect("a header value is ASCII");
        let proof = BindProof::parse(value).expect("the header must be a v1 proof");
        assert_eq!(proof.session_id, session.session_id);

        let target = BindTarget {
            method: "GET",
            path: "/w",
            hub_id: &session.hub_id,
            session_id: proof.session_id,
            session_epoch: session.session_epoch,
            channel_id: proof.channel_id,
            bind_nonce: proof.bind_nonce,
            body_hash: body_hash(b""),
            expires_at: proof.expires_at,
        };
        assert!(verify_binding_mac(&session.bind_key, &target, &proof.mac));
        // The same proof on the uplink path must not verify.
        let other = BindTarget { path: "/m", ..target };
        assert!(!verify_binding_mac(&session.bind_key, &other, &proof.mac));
    }

    /// The nonce is single-use, so two requests must never share one.
    #[test]
    fn every_bound_request_gets_its_own_nonce_and_channel() {
        let session = session();
        let first = WsTransport::bind_headers(&session, "GET", "/w", &[]);
        let second = WsTransport::bind_headers(&session, "GET", "/w", &[]);
        let read = |headers: &HeaderMap| {
            BindProof::parse(
                headers
                    .get(BIND_PROOF_HEADER)
                    .expect("proof")
                    .to_str()
                    .expect("ascii"),
            )
            .expect("v1 proof")
        };
        let first = read(&first);
        let second = read(&second);
        assert_ne!(first.bind_nonce, second.bind_nonce);
        assert_ne!(first.channel_id, second.channel_id);
    }

    /// Every configured carrier must produce a usable factory without connecting.
    #[tokio::test]
    async fn every_carrier_choice_opens_a_transport() {
        let endpoint = HubEndpoint {
            hub_id: "hub-a".to_string(),
            url: "http://127.0.0.1:8443".to_string(),
            key_id: "node-a-1".to_string(),
            priority: 1,
        };
        for carrier in [ClientCarrier::Auto, ClientCarrier::Post, ClientCarrier::Ws] {
            assert!(
                factory_for(carrier).open(&endpoint).await.is_ok(),
                "{carrier:?} must open a transport"
            );
        }
    }
}
