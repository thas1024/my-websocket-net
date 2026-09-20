//! Carrier endpoints (DESIGN.md sections 4.3, 4.4, 9.1, 11).
//!
//! Section 11 fixes the paths nginx forwards: `POST /m`, `GET /e`, `GET /w`, and
//! one exact location per configured profile. Everything else belongs to the site,
//! including a real 404 (section 6.5).
//!
//! The stage rule of section 9.1 is enforced structurally here rather than by
//! discipline:
//!
//! * before an upgrade or before SSE headers, a failure is
//!   [`Hub::http_failure_response`], the deployment's ordinary failure page;
//! * after a WebSocket upgrade, a failure is a valid Close whose code comes from
//!   `Site::failure(FailureStage::WsPreAuth)`, and no HTTP bytes are ever written
//!   again;
//! * after SSE headers, the stream only ever emits bounded SSE events.
//!
//! Two carrier details are worth calling out because the design does not fix them:
//!
//! * The WebSocket bootstrap phase carries the `Auth` record as a **hex Text**
//!   frame. Section 4.4 says the unauthenticated peer sends "一次 Auth Text" and
//!   that the carrier switches to Binary only after success, but a record's
//!   framing is binary, so the Text payload needs an encoding; lowercase hex keeps
//!   the frame valid UTF-8 without adding a dependency to the wire contract.
//! * `GET /e` and `GET /w` are bound to a session with the same `BindProof` as
//!   `POST /m`, with an empty body hash, as section 4.4 requires ("空 body hash").

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, Method, Response as HttpResponse, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::Receiver;
use wsnet_limits::{
    KEEPALIVE_INTERVAL_SECS, MAX_HTTP_BODY, MAX_POST_BATCH_BYTES, MAX_POST_BATCH_RECORDS,
    WS_AUTH_DEADLINE_SECS,
};
use wsnet_protocol::Record;
use wsnet_site::Response as SiteResponse;
use wsnet_transport::{ws as ws_carrier, Carrier};

use crate::bind::{body_hash, BIND_PROOF_HEADER};
use crate::guard::UnauthenticatedConnection;
use crate::hub::{handshake_budget, Hub};
use crate::session::SharedSession;

/// Builds the endpoint router (section 11).
pub(crate) fn router(hub: &Arc<Hub>) -> Router {
    let mut router: Router<Arc<Hub>> = Router::new()
        .route("/m", post(post_carrier))
        .route("/e", get(sse_carrier))
        .route("/w", get(websocket_carrier));
    for (path, _) in hub.profiles().entries() {
        router = router.route(path, post(post_carrier));
    }
    router.fallback(site_fallback).with_state(Arc::clone(hub))
}

// ---------------------------------------------------------------------------
// POST carriers
// ---------------------------------------------------------------------------

/// `POST /m` and every configured profile path.
///
/// One handler serves all of them, because section 6.4's profile paths differ from
/// `/m` only in their encoding: the authentication rules, the binding rules, and
/// the stage behaviour must not be able to drift apart per path.
async fn post_carrier(
    State(hub): State<Arc<Hub>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();
    let carrier = hub.carrier_for_path(&path);

    // Bound the request body before decoding anything (sections 4.1 and 9.2), and
    // bound how long an unauthenticated peer may take to deliver it.
    let body = match tokio::time::timeout(
        handshake_budget(),
        axum::body::to_bytes(request.into_body(), MAX_HTTP_BODY),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return http_failure(&hub, "POST"),
    };

    hub.reap_expired_sessions();

    match headers
        .get(BIND_PROOF_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        Some(proof) => {
            let entry = match hub.verify_binding("POST", &path, proof, body_hash(&body)) {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::debug!(reason = %error.reason(), "refusing a bound carrier request");
                    return http_failure(&hub, "POST");
                }
            };
            let envelopes = match carrier.decode(&body) {
                Ok(envelopes) => envelopes,
                Err(error) => {
                    tracing::debug!(%error, "refusing a malformed carrier batch");
                    return http_failure(&hub, "POST");
                }
            };
            // Subscribe before feeding, so a reply produced by this batch is still
            // in the fan-out when the response is assembled.
            let mut downlink = entry.downlink.subscribe();
            hub.feed_records(&entry, &envelopes);
            carrier_response(carrier, drain_downlink(&mut downlink))
        }
        None => {
            // Section 9.2's per-source budget covers unauthenticated connections.
            let _guard = match hub.begin_unauthenticated(peer.ip()) {
                Ok(guard) => guard,
                Err(_) => return http_failure(&hub, "POST"),
            };
            // Section 4.4: the unauthenticated mode accepts exactly one `Auth`.
            let envelopes = match carrier.decode(&body) {
                Ok(envelopes) if envelopes.len() == 1 => envelopes,
                _ => return http_failure(&hub, "POST"),
            };
            let record = match Record::decode(&envelopes[0]) {
                Ok(record) => record,
                Err(_) => return http_failure(&hub, "POST"),
            };
            match hub.authenticate(&record, peer.ip()) {
                Ok(success) => match success.authok.encode() {
                    Ok(encoded) => carrier_response(carrier, vec![encoded]),
                    Err(_) => http_failure(&hub, "POST"),
                },
                Err(error) => {
                    // The variant is logged locally and never leaves the process:
                    // section 9.1 requires one appearance for all of them.
                    tracing::debug!(reason = %error.detail(), "refusing an authentication bootstrap");
                    http_failure(&hub, "POST")
                }
            }
        }
    }
}

/// Collects at most one carrier batch of queued downlink records.
fn drain_downlink(downlink: &mut Receiver<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut total = 0usize;
    while let Ok(envelope) = downlink.try_recv() {
        if out.len() >= MAX_POST_BATCH_RECORDS || total + envelope.len() + 4 > MAX_POST_BATCH_BYTES
        {
            // Section 4.3 bounds a batch by count *and* bytes; the rest stays
            // queued for the next request rather than being sent in an oversized
            // batch. Delivery is not confirmation anyway (section 7.3).
            break;
        }
        total += envelope.len() + 4;
        out.push(envelope);
    }
    out
}

fn carrier_response(carrier: Carrier, envelopes: Vec<Vec<u8>>) -> Response {
    match carrier.encode(&envelopes) {
        Ok(bytes) => build(StatusCode::OK, content_type(carrier), "no-store", bytes),
        Err(error) => {
            tracing::warn!(%error, "cannot encode a carrier response");
            plain(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

const fn content_type(carrier: Carrier) -> &'static str {
    match carrier {
        Carrier::Post => "application/octet-stream",
        Carrier::JsonProfile => "application/json",
        Carrier::HtmlProfile => "text/html; charset=utf-8",
        Carrier::CssProfile => "text/css; charset=utf-8",
        Carrier::JsProfile => "application/javascript",
        // The downlink carries no SSE or WebSocket body from this handler.
        Carrier::Sse | Carrier::Ws => "application/octet-stream",
    }
}

// ---------------------------------------------------------------------------
// SSE downlink
// ---------------------------------------------------------------------------

/// `GET /e`: the SSE downlink (sections 4.3, 4.4, 6.2).
///
/// The response head is returned immediately and the body is a stream, so nginx'
/// `proxy_buffering off` has something to flush: the first item is an SSE comment
/// that also proves to a client that the subscription is live.
async fn sse_carrier(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    let Some(proof) = headers
        .get(BIND_PROOF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return http_failure(&hub, "GET");
    };
    // A subscription has no body, so the proof's body hash is the hash of nothing.
    let entry = match hub.verify_binding("GET", "/e", proof, body_hash(b"")) {
        Ok(entry) => entry,
        Err(error) => {
            tracing::debug!(reason = %error.reason(), "refusing an SSE subscription");
            return http_failure(&hub, "GET");
        }
    };
    let generation = entry.claim_sse_owner();
    match HttpResponse::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/event-stream")
        .header(CACHE_CONTROL, "no-store")
        // A reverse proxy must not buffer an events stream (section 11).
        .header("x-accel-buffering", "no")
        .body(sse_body(entry, generation))
    {
        Ok(response) => response,
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// The SSE body: bounded events from the session's downlink fan-out.
fn sse_body(entry: SharedSession, generation: u64) -> Body {
    let downlink = entry.downlink.subscribe();
    let state = (entry, downlink, generation, false);
    Body::from_stream(futures_util::stream::unfold(
        state,
        |(entry, mut downlink, generation, started)| async move {
            if !started {
                return Some((
                    Ok::<Bytes, Infallible>(Bytes::from_static(b": connected\n\n")),
                    (entry, downlink, generation, true),
                ));
            }
            loop {
                // Section 4.4: a subscription that has been replaced stops, and
                // the replacement is already the owner.
                if !entry.owns_sse(generation) || entry.is_closed() {
                    return None;
                }
                tokio::select! {
                    message = downlink.recv() => match message {
                        Ok(envelope) => match wsnet_transport::sse::encode(&[envelope]) {
                            Ok(bytes) => {
                                return Some((
                                    Ok(Bytes::from(bytes)),
                                    (entry, downlink, generation, true),
                                ))
                            }
                            Err(error) => {
                                tracing::debug!(%error, "dropping an unencodable SSE event");
                                continue;
                            }
                        },
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => return None,
                    },
                    () = tokio::time::sleep(Duration::from_secs(KEEPALIVE_INTERVAL_SECS)) => {
                        return Some((
                            Ok(Bytes::from_static(b": keep-alive\n\n")),
                            (entry, downlink, generation, true),
                        ))
                    }
                }
            }
        },
    ))
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/// `GET /w`: a WebSocket upgrade (section 4.4).
///
/// A bound upgrade, one that carries a valid `BindProof`, switches straight to
/// Binary records. An unbound upgrade is the bootstrap form: the peer has five
/// seconds to send one `Auth` as a Text frame, and only then does the carrier
/// accept records at all.
async fn websocket_carrier(
    State(hub): State<Arc<Hub>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let bound = match headers
        .get(BIND_PROOF_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        Some(proof) => match hub.verify_binding("GET", "/w", proof, body_hash(b"")) {
            Ok(entry) => Some(entry),
            Err(error) => {
                tracing::debug!(reason = %error.reason(), "refusing a websocket upgrade");
                return http_failure(&hub, "GET");
            }
        },
        None => None,
    };

    let guard = if bound.is_some() {
        None
    } else {
        match hub.begin_unauthenticated(peer.ip()) {
            Ok(guard) => Some(guard),
            Err(_) => return http_failure(&hub, "GET"),
        }
    };

    upgrade.on_upgrade(move |socket| run_socket(hub, socket, bound, peer, guard))
}

async fn run_socket(
    hub: Arc<Hub>,
    socket: WebSocket,
    bound: Option<SharedSession>,
    peer: SocketAddr,
    guard: Option<UnauthenticatedConnection>,
) {
    // The two halves are split so that receiving and sending can be selected on
    // together: a single `WebSocket` cannot be borrowed mutably twice.
    let (mut sender, mut receiver) = socket.split();

    let entry = match bound {
        Some(entry) => entry,
        None => match bootstrap_auth(&hub, &mut sender, &mut receiver, peer).await {
            Some(entry) => {
                // The connection is no longer unauthenticated, so it stops
                // consuming section 9.2's unauthenticated budget.
                drop(guard);
                entry
            }
            None => {
                close_with_site(&hub, &mut sender).await;
                return;
            }
        },
    };

    let mut downlink = entry.downlink.subscribe();
    loop {
        tokio::select! {
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Binary(bytes))) => {
                    hub.feed_records(&entry, &[bytes]);
                }
                Some(Ok(Message::Ping(payload))) => {
                    if sender.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Text(_))) => {
                    // Section 4.4: Binary is the only record carrier after the
                    // bootstrap, so a Text record is a protocol violation.
                    close_with_site(&hub, &mut sender).await;
                    break;
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
            },
            message = downlink.recv() => match message {
                Ok(envelope) => {
                    if ws_carrier::decode_ref(&envelope).is_ok()
                        && sender.send(Message::Binary(envelope)).await.is_err()
                    {
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            },
        }
    }

    // Section 5.3: the local side reclaims its resources, and section 5.5's
    // session/epoch guard makes sure a late teardown cannot delete a newer lease.
    hub.close_session(&entry.session_id, &entry.epoch, "websocket closed");
}

/// The pre-authentication phase: one `Auth` Text frame inside the deadline.
async fn bootstrap_auth(
    hub: &Arc<Hub>,
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    receiver: &mut futures_util::stream::SplitStream<WebSocket>,
    peer: SocketAddr,
) -> Option<SharedSession> {
    let deadline = Duration::from_secs(WS_AUTH_DEADLINE_SECS);
    let first = match tokio::time::timeout(deadline, receiver.next()).await {
        Ok(Some(Ok(message))) => message,
        _ => return None,
    };
    let Message::Text(text) = first else {
        return None;
    };
    let bytes = hex::decode(text.trim()).ok()?;
    let record = Record::decode(&bytes).ok()?;
    let success = hub.authenticate(&record, peer.ip()).ok()?;
    let encoded = success.authok.encode().ok()?;
    sender
        .send(Message::Text(hex::encode(encoded)))
        .await
        .ok()?;
    Some(success.entry)
}

/// Closes a WebSocket with the code the site's failure appearance specifies.
async fn close_with_site(
    hub: &Hub,
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) {
    let code = hub.ws_failure_close_code();
    let frame = CloseFrame {
        code,
        reason: "".into(),
    };
    let _ = sender.send(Message::Close(Some(frame))).await;
}

// ---------------------------------------------------------------------------
// Site
// ---------------------------------------------------------------------------

/// Serves everything the carriers do not own, including a real 404 (section 6.5).
async fn site_fallback(State(hub): State<Arc<Hub>>, method: Method, uri: Uri) -> Response {
    match hub.site().route(uri.path()) {
        Some(response) => site_response(&response, method.as_str()),
        // A reserved path with no handler must still not be answered by the site,
        // so the deployment's failure appearance is used rather than a page.
        None => site_response(&hub.http_failure_response(), method.as_str()),
    }
}

fn http_failure(hub: &Hub, method: &str) -> Response {
    site_response(&hub.http_failure_response(), method)
}

fn site_response(response: &SiteResponse, method: &str) -> Response {
    build(
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::NOT_FOUND),
        response.content_type,
        response.cache_control,
        response.body_for_method(method).to_vec(),
    )
}

fn build(status: StatusCode, content_type: &str, cache_control: &str, body: Vec<u8>) -> Response {
    match HttpResponse::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .header(CACHE_CONTROL, cache_control)
        .body(Body::from(body))
    {
        Ok(response) => response,
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn plain(status: StatusCode) -> Response {
    HttpResponse::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
