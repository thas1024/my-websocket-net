//! The shipped carrier set: `POST /m` for uplink, `GET /e` SSE for downlink.
//!
//! DESIGN.md section 6.1 allows client-to-server data over WebSocket or HTTPS
//! POST and forbids SSE; section 6.2 allows server-to-client data over
//! WebSocket, SSE, or a bounded POST response. This transport implements the
//! POST-uplink plus SSE-downlink pair, which section 5.3 accepts as the required
//! "至少一个可双向收发的组合", and additionally carries downlink envelopes that
//! arrive in the POST responses themselves so a Hub may answer without an SSE
//! subscription.
//!
//! Both directions reuse the carrier encodings of `wsnet-transport`, so the node
//! cannot invent a framing the rest of the workspace does not share.
//!
//! The WebSocket carrier of section 6.1 is *not* implemented here: the node has
//! no WebSocket uplink, so a deployment that disables `POST /m` cannot use this
//! transport. That limitation is deliberate and is reported rather than papered
//! over by silently downgrading to a direct connection.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::Client;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use wsnet_limits::{HANDSHAKE_TIMEOUT_MS, MAX_POST_BATCH_BYTES, MAX_POST_BATCH_RECORDS};
use wsnet_transport::{post, SseDecoder};

use crate::carrier::{CarrierIo, CarrierKind};
use crate::endpoint::{BoundSession, HubEndpoint, HubTransport, TransportFactory};
use crate::node::NodeError;
use crate::BoxFuture;

/// The header a Hub uses to attribute a request to an authenticated session.
///
/// DESIGN.md section 4.4 keeps session material in headers or bodies and never in
/// a URL, so that a front-end log cannot capture it together with the path.
const SESSION_HEADER: &str = "x-wsnet-session";

/// Builds the HTTP carrier set for every Hub.
pub struct HttpTransportFactory {
    client: Client,
    request_timeout: Duration,
}

impl Default for HttpTransportFactory {
    fn default() -> Self {
        HttpTransportFactory {
            client: Client::new(),
            request_timeout: Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
        }
    }
}

impl HttpTransportFactory {
    /// Builds a factory with the design's handshake deadline for every request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the deadline applied to each individual HTTP request.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}

impl TransportFactory for HttpTransportFactory {
    fn open(
        &self,
        endpoint: &HubEndpoint,
    ) -> BoxFuture<'static, Result<Arc<dyn HubTransport>, NodeError>> {
        let transport = HttpTransport {
            client: self.client.clone(),
            base: endpoint.url.trim_end_matches('/').to_string(),
            request_timeout: self.request_timeout,
        };
        Box::pin(async move { Ok(Arc::new(transport) as Arc<dyn HubTransport>) })
    }
}

/// One Hub's HTTP carriers.
///
/// The value is created by [`HttpTransportFactory::open`] and holds the client
/// and base URL of exactly one Hub session.
pub struct HttpTransport {
    client: Client,
    base: String,
    request_timeout: Duration,
}

impl HttpTransport {
    /// The `POST /m` endpoint, which DESIGN.md section 4.4 reserves for the
    /// bootstrap before authentication and for protected bodies afterwards.
    fn message_url(&self) -> String {
        format!("{}/m", self.base)
    }

    /// The `GET /e` endpoint, the SSE downlink of section 6.2.
    fn events_url(&self) -> String {
        format!("{}/e", self.base)
    }

    fn session_headers(session: &BoundSession) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(&hex::encode(session.session_id)) {
            headers.insert(SESSION_HEADER, value);
        }
        headers
    }
}

impl HubTransport for HttpTransport {
    fn authenticate(&self, auth: Vec<u8>) -> BoxFuture<'static, Result<Vec<u8>, NodeError>> {
        let client = self.client.clone();
        let url = self.message_url();
        let timeout = self.request_timeout;
        Box::pin(async move {
            // Section 4.3 fixes the POST body as a carrier batch, so the `Auth`
            // record is length-prefixed rather than sent bare, and the reply is
            // read back through the same framing. The record itself stays
            // unsealed: section 4.4 reserves unauthenticated `/m` for the
            // bootstrap, where no session key exists yet.
            let body = wsnet_transport::post::encode(std::slice::from_ref(&auth))
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            let response = client
                .post(url)
                .header(CONTENT_TYPE, "application/octet-stream")
                .timeout(timeout)
                .body(body)
                .send()
                .await
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            let status = response.status();
            if !status.is_success() {
                return Err(NodeError::Transport(format!(
                    "the hub answered the Auth bootstrap with {status}"
                )));
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            let mut envelopes = wsnet_transport::post::decode(&bytes)
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            if envelopes.len() != 1 {
                return Err(NodeError::Transport(format!(
                    "the Auth bootstrap reply carried {} records, expected 1",
                    envelopes.len()
                )));
            }
            Ok(envelopes.remove(0))
        })
    }

    fn bind(&self, session: BoundSession) -> BoxFuture<'static, Result<Vec<CarrierIo>, NodeError>> {
        let client = self.client.clone();
        let message_url = self.message_url();
        let events_url = self.events_url();
        let timeout = self.request_timeout;
        let headers = Self::session_headers(&session);
        Box::pin(async move {
            let (uplink_tx, uplink_rx) = mpsc::unbounded_channel();
            // The POST responses and the SSE subscription are reported as
            // separate carriers, so the session only ends once *both* have
            // ended, exactly as a broken carrier should be observed.
            let (post_tx, post_rx) = mpsc::unbounded_channel();
            let (sse_tx, sse_rx) = mpsc::unbounded_channel();

            spawn_post_carrier(
                client.clone(),
                message_url,
                timeout,
                headers.clone(),
                uplink_rx,
                post_tx,
            );
            spawn_sse_carrier(client, events_url, headers, sse_tx);

            Ok(vec![
                CarrierIo::new(CarrierKind::Post, post_rx, uplink_tx),
                // The SSE half gets an outbound channel nobody drains; the
                // session driver drops it, which is what keeps section 6.1's
                // downlink-only rule true by construction.
                CarrierIo::new(CarrierKind::Sse, sse_rx, mpsc::unbounded_channel().0),
            ])
        })
    }

    fn health(&self, session: BoundSession) -> BoxFuture<'static, Result<(), NodeError>> {
        let client = self.client.clone();
        let url = self.message_url();
        let timeout = self.request_timeout;
        let headers = Self::session_headers(&session);
        Box::pin(async move {
            // Section 5.5 forbids treating a static page as proof of a working
            // proxy, so the check is an authenticated POST into the session
            // queue: only a Hub with a live session answers it successfully.
            let response = client
                .post(url)
                .headers(headers)
                .timeout(timeout)
                .body(Vec::new())
                .send()
                .await
                .map_err(|error| NodeError::Transport(error.to_string()))?;
            if response.status().is_success() {
                Ok(())
            } else {
                Err(NodeError::Transport(format!(
                    "the hub answered the health check with {}",
                    response.status()
                )))
            }
        })
    }
}

/// Batches uplink envelopes into `POST /m`, and feeds the response bodies back.
fn spawn_post_carrier(
    client: Client,
    url: String,
    timeout: Duration,
    headers: HeaderMap,
    mut uplink: mpsc::UnboundedReceiver<Vec<u8>>,
    inbound: mpsc::UnboundedSender<Vec<u8>>,
) {
    tokio::spawn(async move {
        while let Some(first) = uplink.recv().await {
            let mut batch = vec![first];
            let mut bytes: usize = batch[0].len();
            // Section 4.3 bounds a POST batch by records *and* bytes; both caps
            // are applied here so a burst cannot build an illegal body.
            while batch.len() < MAX_POST_BATCH_RECORDS && bytes < MAX_POST_BATCH_BYTES {
                match uplink.try_recv() {
                    Ok(envelope) => {
                        bytes += envelope.len();
                        batch.push(envelope);
                    }
                    Err(_) => break,
                }
            }
            let body = match post::encode(&batch) {
                Ok(body) => body,
                Err(error) => {
                    warn!(%error, "post carrier refused a batch");
                    continue;
                }
            };
            let response = client
                .post(&url)
                .headers(headers.clone())
                .timeout(timeout)
                .body(body)
                .send()
                .await;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    debug!(%error, "post carrier request failed");
                    continue;
                }
            };
            if !response.status().is_success() {
                debug!(status = %response.status(), "post carrier was refused");
                continue;
            }
            let Ok(body) = response.bytes().await else {
                continue;
            };
            if body.is_empty() {
                continue;
            }
            match post::decode(&body) {
                Ok(envelopes) => {
                    for envelope in envelopes {
                        if inbound.send(envelope).is_err() {
                            return;
                        }
                    }
                }
                Err(error) => debug!(%error, "post carrier response was not a batch"),
            }
        }
    });
}

/// Streams `GET /e` and feeds every decoded event into the session.
///
/// The request carries no overall deadline: an SSE subscription is a long-lived
/// response by definition, so bounding it with a per-request timeout would end
/// the downlink on a timer. Liveness is instead the section 5.5 health round trip
/// on the POST path.
fn spawn_sse_carrier(
    client: Client,
    url: String,
    headers: HeaderMap,
    inbound: mpsc::UnboundedSender<Vec<u8>>,
) {
    tokio::spawn(async move {
        let request = client
            .get(&url)
            .headers(headers)
            .header(ACCEPT, "text/event-stream")
            .send()
            .await;
        let response = match request {
            Ok(response) => response,
            Err(error) => {
                debug!(%error, "sse carrier could not subscribe");
                return;
            }
        };
        if !response.status().is_success() {
            debug!(status = %response.status(), "sse carrier was refused");
            return;
        }
        let mut decoder = SseDecoder::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else {
                debug!("sse carrier ended with a transport error");
                return;
            };
            match decoder.feed(&chunk) {
                Ok(envelopes) => {
                    for envelope in envelopes {
                        if inbound.send(envelope).is_err() {
                            return;
                        }
                    }
                }
                Err(error) => {
                    debug!(%error, "sse carrier refused an event");
                    return;
                }
            }
        }
        debug!("sse carrier ended");
    });
}
