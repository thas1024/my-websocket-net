//! Bridging a caller's stream to the publishing node (DESIGN.md sections 7.1,
//! 7.5, 7.6, 8).
//!
//! [`crate::Hub::authorize_open`] resolves a service or a node-viewed address to
//! an [`crate::ExitPlan::ServiceExit`] or [`crate::ExitPlan::NodeExit`]; this
//! module turns one such plan into the two legs of one stream: the caller's leg
//! on the caller's session, and a Hub-initiated even stream on the *publishing
//! node's* session. The publisher terminates the leg, which is why nothing here
//! dials a socket: the destination handed to the publisher is the caller's own,
//! unchanged, so the publisher re-resolves it against its own service table and
//! its own local policy (section 7.6).
//!
//! Three rules shape the task:
//!
//! * **One task per bridge.** Section 7.5 forbids one stream blocking the whole
//!   session's reader, so both legs are pumped from a task of their own while the
//!   sessions keep arbitrating other streams.
//! * **Credit is per leg, and it is what bounds the buffer.** Section 7.5 grants
//!   credit only for bytes the application consumed, and a leg is consumed only
//!   once the other leg accepted the bytes, so the bytes held here can never
//!   exceed the window the two peers granted: a slow side backpressures the fast
//!   one, and nothing is buffered without bound.
//! * **A half-close is half.** Section 7.2 makes a `Fin` close one direction, so a
//!   `Fin` is forwarded and the other direction keeps carrying bytes; only a
//!   `Reset`, or a leg that ends without one, tears both legs down.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use wsnet_routing::{Destination, Proto};
use wsnet_session::{
    OpenFields, OpenResultFields, OpenStatus, ResetReason, SessionError, SessionEvent,
    SessionHandle,
};
use wsnet_stream::StreamError;

use crate::hub::Hub;
use crate::session::SharedSession;

/// How long the publishing node may take to accept a bridged `Open`.
///
/// Section 7.1 bounds one leg of a stream at ten seconds, and the same budget
/// covers the publisher's answer: a node that never reports either half of the
/// stream must not hold the caller's stream open forever.
const RELAY_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Detail used when the publishing node has no live session here.
const DETAIL_PUBLISHER_OFFLINE: &str = "the publishing node has no live session on this hub";

/// Detail used when the publishing node refused the stream.
///
/// The status is relayed verbatim, but section 4.1 makes `detail` a local
/// diagnosis, so the publisher's own text is not copied into the caller's answer.
const DETAIL_PUBLISHER_REFUSED: &str = "the publishing node did not open the stream";

/// Detail used when the publisher's session ended before it answered.
const DETAIL_PUBLISHER_GONE: &str = "the publishing node's session ended before it answered";

/// Detail used when the publisher reset the stream before it was ready.
const DETAIL_PUBLISHER_RESET: &str = "the publishing node reset the stream before it was ready";

/// Detail used when the publisher sent data before the stream was ready.
const DETAIL_PUBLISHER_EARLY_DATA: &str =
    "the publishing node sent data before the stream was ready";

/// Detail used when the publisher closed the stream before it was ready.
const DETAIL_PUBLISHER_EARLY_FIN: &str =
    "the publishing node closed the stream before it was ready";

/// Detail used when the publisher never answered the `Open`.
const DETAIL_PUBLISHER_TIMEOUT: &str = "the publishing node did not answer the open in time";

/// Detail used when the publishing session cannot accept another stream.
const DETAIL_PUBLISHER_UNAVAILABLE: &str = "the publishing node cannot accept another stream";

/// Detail used when the publisher's stream id is already owned by a task.
const DETAIL_STREAM_TAKEN: &str = "the stream id is already in use";

/// Detail used when the bridge needs an async runtime that is not there.
const DETAIL_NO_RUNTIME: &str = "bridging to a publishing node needs an async runtime";

/// Detail used for a relay plan whose hop list turned out to be empty.
const DETAIL_RELAY_EMPTY_CHAIN: &str = "the relay chain has no hops";

/// Detail reported with a successful bridged `OpenResult`.
const DETAIL_BRIDGED: &str = "bridged to the publishing node";

/// Why one leg of a bridge could not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayFailure {
    /// The status the caller is told.
    status: OpenStatus,
    /// A local-only explanation; never the publisher's own detail text.
    detail: &'static str,
}

impl RelayFailure {
    const fn new(status: OpenStatus, detail: &'static str) -> Self {
        RelayFailure { status, detail }
    }
}

/// A fresh operation id for the Hub-initiated `Open`.
///
/// Section 4.2 keeps `request_id` an opaque per-operation label, so the id on the
/// publisher's leg must not be one the caller already used: the publisher's
/// idempotency table is keyed by it.
fn fresh_request_id() -> [u8; 16] {
    let nonce = wsnet_session::fresh_nonce();
    let mut request_id = [0u8; 16];
    request_id.copy_from_slice(&nonce[..16]);
    request_id
}

/// Spawns the task that bridges one authorised `Open` to the publishing node.
///
/// The publisher is found through the registry lease and the session table, never
/// by dialling anything directly: section 7.6 makes the publishing node the final
/// leg, so a Hub that cannot find that node's live session answers `Offline`
/// rather than substituting a target of its own.
pub(crate) fn spawn_relay(hub: &Hub, entry: &SharedSession, fields: &OpenFields, node_id: &str) {
    spawn_relay_with_via(hub, entry, fields, node_id, Vec::new());
}

/// Spawns the task that bridges one authorised `Open` to the first hop of a chain.
///
/// Section 7.1 fixes the shape of a multi-hop path:
///
/// > `via=[A,B]` 路径为 client→H→A→H→B→target。v1 是同 Hub 星型回转链，不是任意
/// > mesh
///
/// so a hop is not an exit: it is asked to hand the flow *back* to the Hub with the
/// rest of the chain still to run. The leg opened here therefore carries the
/// remaining chain in its own `via`, which is what a hop needs in order to forward
/// rather than dial. Because the chain strictly shrinks at every hop, a loop is
/// impossible by construction rather than by a hop counter, and `authorize_open`
/// has already rejected a chain that repeats a node.
pub(crate) fn spawn_relay_chain(
    hub: &Hub,
    entry: &SharedSession,
    fields: &OpenFields,
    hops: &[String],
) {
    let Some((first, rest)) = hops.split_first() else {
        // `authorize_open` returns `Relay` only for a non-empty chain, so this is
        // unreachable; answering rather than panicking keeps a Hub that got here
        // through some future change diagnosable instead of aborting the process.
        tracing::warn!(
            session = %hex::encode(entry.session_id),
            "a relay plan with no hops cannot be bridged"
        );
        hub.refuse_open(
            entry,
            fields,
            OpenStatus::Refused,
            DETAIL_RELAY_EMPTY_CHAIN,
        );
        return;
    };
    spawn_relay_with_via(hub, entry, fields, first, rest.to_vec());
}

/// Bridges one `Open` to `node_id`, telling that node which chain is left to run.
fn spawn_relay_with_via(
    hub: &Hub,
    entry: &SharedSession,
    fields: &OpenFields,
    node_id: &str,
    via: Vec<String>,
) {
    let Some(publisher) = hub.session_for_node(node_id) else {
        hub.refuse_open(entry, fields, OpenStatus::Offline, DETAIL_PUBLISHER_OFFLINE);
        return;
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        // Answering rather than panicking keeps a Hub driven from a synchronous
        // caller diagnosable instead of aborting the process.
        hub.refuse_open(entry, fields, OpenStatus::Unreachable, DETAIL_NO_RUNTIME);
        return;
    };

    // Section 4.2 never reuses a stream id, so a live id stays with the task that
    // already owns it instead of being bridged a second time.
    let (sink, events) = mpsc::unbounded_channel();
    if !entry.claim_stream(fields.stream_id, sink) {
        tracing::debug!(
            session = %hex::encode(entry.session_id),
            stream_id = fields.stream_id,
            "refusing a second bridge for a live stream"
        );
        return;
    }

    let bridge = Bridge {
        caller_node: entry.node_id.clone(),
        caller: Arc::clone(entry),
        caller_handle: entry.handle.clone(),
        caller_stream: fields.stream_id,
        caller_request: fields.request_id,
        publisher,
        destination: fields.destination.clone(),
        via,
        proto: fields.proto,
    };
    tracing::debug!(
        caller = %bridge.caller_node,
        session = %hex::encode(entry.session_id),
        stream_id = fields.stream_id,
        publisher_node = %node_id,
        hops_left = bridge.via.len(),
        "bridging a stream to the publishing node"
    );
    runtime.spawn(async move { bridge.run(events).await });
}

/// One bridged stream: everything its task needs after authorisation.
struct Bridge {
    /// Who opened the stream, for logging.
    caller_node: String,
    /// The caller's session, for routing and for publishing records.
    caller: SharedSession,
    /// The caller's engine, for `OpenResult`, `Data`, `Fin`, and `Reset`.
    caller_handle: SessionHandle,
    /// The caller's stream id, which the caller allocated.
    caller_stream: u64,
    /// The caller's operation id, echoed in the answer.
    caller_request: [u8; 16],
    /// The publishing node's session.
    publisher: SharedSession,
    /// The destination exactly as the caller wrote it, pinned revision included.
    destination: Destination,
    /// The chain this leg still has to run, as written into the leg's own `Open`.
    ///
    /// Empty for a plan that reaches the publishing node or the raw-address exit;
    /// non-empty when the leg goes to an intermediate hop, which is what tells that
    /// hop to hand the flow back to the Hub instead of dialling it (section 7.1).
    via: Vec<String>,
    /// Protocol the `Open` named.
    proto: Proto,
}

impl Bridge {
    /// Opens on the publisher, answers the caller, pumps, and then leaves nothing
    /// registered on either side (section 7.1).
    async fn run(self, mut caller_events: mpsc::UnboundedReceiver<SessionEvent>) {
        let (publisher_stream, mut publisher_events) = match self.open_on_publisher() {
            Ok(opened) => opened,
            Err(failure) => {
                self.refuse_caller(failure);
                self.release_caller();
                return;
            }
        };

        // Section 7.1 reports success only once both receive halves are installed,
        // which the publisher signals with `OpenResult{Ok}` and then `Ready`.
        let handshake = tokio::time::timeout(
            RELAY_OPEN_TIMEOUT,
            self.await_open(publisher_stream, &mut publisher_events),
        )
        .await;
        let failure = match handshake {
            Ok(Ok(())) => None,
            Ok(Err(failure)) => Some(failure),
            Err(_) => Some(RelayFailure::new(
                OpenStatus::Timeout,
                DETAIL_PUBLISHER_TIMEOUT,
            )),
        };
        if let Some(failure) = failure {
            // The caller's `Open` is answered exactly once: this return is the
            // only answer on this path.
            self.refuse_caller(failure);
            self.release_caller();
            self.release_publisher(publisher_stream);
            return;
        }

        if !self.answer_caller() {
            // The caller's session is gone, so the publisher leg has no peer.
            self.release_publisher(publisher_stream);
            self.release_caller();
            return;
        }
        self.bridge(publisher_stream, &mut caller_events, &mut publisher_events)
            .await;
    }

    /// Opens the bridged stream on the publishing node's session.
    ///
    /// The caller's destination is passed through *unchanged*, pinned revision
    /// included: section 7.6 makes the publisher re-resolve it against its own
    /// service table and its own local policy, so a Hub that rewrote the target
    /// here would be deciding something it cannot see.
    fn open_on_publisher(
        &self,
    ) -> Result<(u64, mpsc::UnboundedReceiver<SessionEvent>), RelayFailure> {
        let (stream_id, _) = self
            .publisher
            .handle
            .open(
                self.destination.clone(),
                self.via.clone(),
                self.proto,
                fresh_request_id(),
            )
            .map_err(|error| {
                tracing::debug!(
                    session = %hex::encode(self.publisher.session_id),
                    %error,
                    "cannot open a stream on the publishing node"
                );
                RelayFailure::new(OpenStatus::Refused, DETAIL_PUBLISHER_UNAVAILABLE)
            })?;

        // Section 7.5: the publisher's events belong to this task, so the sink is
        // installed before anything can be routed to it.
        let (sink, events) = mpsc::unbounded_channel();
        if !self.publisher.claim_stream(stream_id, sink) {
            tracing::debug!(
                session = %hex::encode(self.publisher.session_id),
                stream_id,
                "the publishing node's stream id is already live"
            );
            let _ = self
                .publisher
                .handle
                .send_reset(stream_id, ResetReason::Canceled);
            self.publisher.flush_outbound();
            return Err(RelayFailure::new(OpenStatus::Refused, DETAIL_STREAM_TAKEN));
        }
        // The `Open` was produced outside the publisher's own carrier loop, so
        // the session has to be flushed for the record to leave the engine.
        self.publisher.flush_outbound();
        Ok((stream_id, events))
    }

    /// Waits for the publisher's `OpenResult` and, when it is `Ok`, its `Ready`.
    ///
    /// Every other outcome is a refusal that names itself locally, so the caller
    /// is never told the stream exists when it does not. Returns `Ok` only once
    /// both halves were reported.
    async fn await_open(
        &self,
        publisher_stream: u64,
        events: &mut mpsc::UnboundedReceiver<SessionEvent>,
    ) -> Result<(), RelayFailure> {
        let mut opened = false;
        loop {
            let Some(event) = events.recv().await else {
                return Err(RelayFailure::new(
                    OpenStatus::Unreachable,
                    DETAIL_PUBLISHER_GONE,
                ));
            };
            match event {
                SessionEvent::OpenResult(fields) => {
                    if fields.status != OpenStatus::Ok {
                        return Err(RelayFailure::new(fields.status, DETAIL_PUBLISHER_REFUSED));
                    }
                    opened = true;
                }
                // A `Ready` before the `OpenResult` is not evidence of anything;
                // the order section 7.1 fixes is `OpenResult` then `Ready`.
                SessionEvent::Ready(_) if opened => return Ok(()),
                SessionEvent::Ready(_) => {}
                SessionEvent::Reset(_) => {
                    return Err(RelayFailure::new(
                        OpenStatus::Unreachable,
                        DETAIL_PUBLISHER_RESET,
                    ))
                }
                SessionEvent::Fin(_) => {
                    return Err(RelayFailure::new(
                        OpenStatus::Unreachable,
                        DETAIL_PUBLISHER_EARLY_FIN,
                    ))
                }
                SessionEvent::Data { .. } => {
                    return Err(RelayFailure::new(
                        OpenStatus::Unreachable,
                        DETAIL_PUBLISHER_EARLY_DATA,
                    ))
                }
                other => tracing::trace!(
                    stream_id = publisher_stream,
                    event = ?other,
                    "ignoring a publisher event before the stream was ready"
                ),
            }
        }
    }

    /// Carries both legs until one of them ends.
    ///
    /// The loop is single-threaded and owns no socket, so there is no shared
    /// buffer to guard: the two legs are two receive queues, and what one leg
    /// produced is handed to the other before anything else is read.
    async fn bridge(
        &self,
        publisher_stream: u64,
        caller_events: &mut mpsc::UnboundedReceiver<SessionEvent>,
        publisher_events: &mut mpsc::UnboundedReceiver<SessionEvent>,
    ) {
        // Bytes accepted from one leg that the other leg's credit has not taken
        // yet. Section 7.5 bounds this: a leg is consumed only once the other leg
        // accepted the bytes, so a peer cannot get more than its granted window
        // ahead of what the bridge forwarded.
        let mut to_publisher: Vec<u8> = Vec::new();
        let mut to_caller: Vec<u8> = Vec::new();
        // A `Fin` is remembered per direction, because a half-close closes one
        // half and the other keeps carrying bytes (section 7.2).
        let mut caller_fin = false;
        let mut publisher_fin = false;
        let mut caller_fin_sent = false;
        let mut publisher_fin_sent = false;
        // A leg that is already closed must not be reset a second time: section
        // 7.1 makes a reset terminal, and two ends answering a reset with another
        // reset would ping-pong.
        let mut caller_done = false;
        let mut publisher_done = false;
        // Why the halves that are still open are being torn down.
        let mut reason = ResetReason::Canceled;

        loop {
            // Hand over what arrived, then grant the source the credit it earned:
            // section 7.5 makes credit follow consumption, never arrival.
            let before = to_publisher.len();
            if !self.push(
                &self.publisher,
                &self.publisher.handle,
                publisher_stream,
                &mut to_publisher,
            ) {
                reason = ResetReason::Unreachable;
                break;
            }
            let sent_to_publisher = before - to_publisher.len();
            if sent_to_publisher > 0
                && self
                    .caller_handle
                    .consume(self.caller_stream, sent_to_publisher as u64)
                    .is_err()
            {
                reason = ResetReason::Unreachable;
                break;
            }

            let before = to_caller.len();
            if !self.push(
                &self.caller,
                &self.caller_handle,
                self.caller_stream,
                &mut to_caller,
            ) {
                reason = ResetReason::Unreachable;
                break;
            }
            let sent_to_caller = before - to_caller.len();
            if sent_to_caller > 0
                && self
                    .publisher
                    .handle
                    .consume(publisher_stream, sent_to_caller as u64)
                    .is_err()
            {
                reason = ResetReason::Unreachable;
                break;
            }

            // Section 7.2: the half-close goes out only once every byte below it
            // was forwarded, so a `Fin` can never overtake its own payload.
            if caller_fin && !publisher_fin_sent && to_publisher.is_empty() {
                if self.publisher.handle.send_fin(publisher_stream).is_err() {
                    reason = ResetReason::Unreachable;
                    break;
                }
                publisher_fin_sent = true;
            }
            if publisher_fin && !caller_fin_sent && to_caller.is_empty() {
                if self.caller_handle.send_fin(self.caller_stream).is_err() {
                    reason = ResetReason::Unreachable;
                    break;
                }
                caller_fin_sent = true;
            }

            // Flush unconditionally. `push` drains what it can, so gating this on
            // a pending buffer would skip exactly the iteration that produced new
            // records: they would then sit in the engine until unrelated traffic
            // happened to flush them, which makes latency depend on the peer
            // sending something.
            self.caller.flush_outbound();
            self.publisher.flush_outbound();

            if caller_fin_sent && publisher_fin_sent {
                // Both directions closed with a `Fin`: nothing is left to tell.
                caller_done = true;
                publisher_done = true;
                break;
            }

            tokio::select! {
                event = caller_events.recv() => {
                    let Some(event) = event else {
                        // The caller's session or stream registry is gone, so its
                        // leg has no one left to answer.
                        caller_done = true;
                        break;
                    };
                    match event {
                        SessionEvent::Data { payload, .. } => {
                            if caller_fin {
                                // Section 7.2: bytes after a `Fin` cannot be
                                // forwarded without truncating or reordering.
                                reason = ResetReason::ProtocolError;
                                break;
                            }
                            to_publisher.extend_from_slice(&payload);
                        }
                        SessionEvent::Fin(_) => caller_fin = true,
                        SessionEvent::Reset(fields) => {
                            tracing::debug!(
                                caller = %self.caller_node,
                                stream_id = self.caller_stream,
                                reason = ?fields.reason,
                                "the caller reset a bridged stream"
                            );
                            // Section 7.1: a reset is terminal for the whole
                            // stream, so the publisher is told and neither leg is
                            // reset a second time.
                            let _ = self
                                .publisher
                                .handle
                                .send_reset(publisher_stream, fields.reason);
                            caller_done = true;
                            publisher_done = true;
                            break;
                        }
                        // A `Progress` matters only through the raised limit the
                        // engine already recorded; the next `push` picks it up.
                        SessionEvent::Progress(_) => {}
                        other => tracing::trace!(
                            stream_id = self.caller_stream,
                            event = ?other,
                            "ignoring a caller event on a bridged stream"
                        ),
                    }
                }
                event = publisher_events.recv() => {
                    let Some(event) = event else {
                        publisher_done = true;
                        break;
                    };
                    match event {
                        SessionEvent::Data { payload, .. } => {
                            if publisher_fin {
                                reason = ResetReason::ProtocolError;
                                break;
                            }
                            to_caller.extend_from_slice(&payload);
                        }
                        SessionEvent::Fin(_) => publisher_fin = true,
                        SessionEvent::Reset(fields) => {
                            tracing::debug!(
                                caller = %self.caller_node,
                                stream_id = publisher_stream,
                                reason = ?fields.reason,
                                "the publishing node reset a bridged stream"
                            );
                            let _ = self
                                .caller_handle
                                .send_reset(self.caller_stream, fields.reason);
                            caller_done = true;
                            publisher_done = true;
                            break;
                        }
                        SessionEvent::Progress(_) => {}
                        // A second `OpenResult` or `Ready` after the handshake is
                        // the publisher repeating itself; the stream is already
                        // installed, so it changes nothing.
                        other => tracing::trace!(
                            stream_id = publisher_stream,
                            event = ?other,
                            "ignoring a publisher event on a bridged stream"
                        ),
                    }
                }
            }
        }

        // Tear down whichever half is still open and release both local mappings:
        // section 7.1 keeps the sessions and every other stream usable.
        if !publisher_done {
            let _ = self.publisher.handle.send_reset(publisher_stream, reason);
        }
        if !caller_done {
            let _ = self.caller_handle.send_reset(self.caller_stream, reason);
        }
        self.caller.unregister_stream(self.caller_stream);
        self.caller_handle.close_stream(self.caller_stream);
        self.publisher.unregister_stream(publisher_stream);
        self.publisher.handle.close_stream(publisher_stream);
        self.caller.flush_outbound();
        self.publisher.flush_outbound();
    }

    /// Hands buffered bytes to one leg, honouring the credit that leg granted.
    ///
    /// Section 7.5 makes over-credit data a protocol error, so nothing is sent
    /// past the leg's `limit_offset`: the part that fits goes out and the rest
    /// waits for a `Progress` that raises the limit. No byte is dropped, and none
    /// is sent twice. Returns whether the leg can still carry the stream.
    fn push(
        &self,
        session: &SharedSession,
        handle: &SessionHandle,
        stream_id: u64,
        pending: &mut Vec<u8>,
    ) -> bool {
        while !pending.is_empty() {
            match handle.send_data(stream_id, pending) {
                Ok(_) => pending.clear(),
                Err(SessionError::Stream(StreamError::CreditExceeded { .. })) => {
                    let Some((offset, limit, _)) = handle.offsets(stream_id) else {
                        return false;
                    };
                    let room = limit.saturating_sub(offset) as usize;
                    if room == 0 {
                        // Wait for `Progress`; the other direction keeps moving.
                        return true;
                    }
                    let take = room.min(pending.len());
                    if handle.send_data(stream_id, &pending[..take]).is_err() {
                        return false;
                    }
                    pending.drain(..take);
                }
                Err(error) => {
                    tracing::debug!(
                        session = %hex::encode(session.session_id),
                        stream_id,
                        %error,
                        "a bridged leg cannot carry stream data"
                    );
                    return false;
                }
            }
        }
        true
    }

    /// Answers the caller with a specific status, once, and releases its stream.
    ///
    /// A non-`Ok` status makes the engine drop the stream state, so a refused
    /// `Open` leaves nothing registered for a later event to find. A stream the
    /// engine no longer has is not answered at all: section 8 makes a second
    /// `Open` for a live id its own refusal, and that refusal already answered
    /// the caller's leg.
    fn refuse_caller(&self, failure: RelayFailure) {
        if self.caller_handle.offsets(self.caller_stream).is_none() {
            tracing::debug!(
                session = %hex::encode(self.caller.session_id),
                stream_id = self.caller_stream,
                "the caller's stream is already released; not answering again"
            );
            return;
        }
        let result = OpenResultFields {
            request_id: self.caller_request,
            stream_id: self.caller_stream,
            status: failure.status,
            detail: failure.detail.to_string(),
        };
        if let Err(error) = self.caller_handle.send_open_result(&result) {
            tracing::debug!(
                session = %hex::encode(self.caller.session_id),
                stream_id = self.caller_stream,
                %error,
                "cannot answer a refused Open"
            );
        }
        self.caller.flush_outbound();
    }

    /// Installs the caller's stream and answers `OpenResult{Ok}` plus `Ready`.
    ///
    /// Section 7.1 requires the success to be reported only once both receive
    /// halves are installed, which `send_open_result` does by sending `Ready`
    /// itself. Returns whether the answer went out; a stream the engine already
    /// released (a duplicate `Open` was refused, or the caller reset it) is not
    /// answered a second time.
    fn answer_caller(&self) -> bool {
        if self.caller_handle.offsets(self.caller_stream).is_none() {
            tracing::debug!(
                session = %hex::encode(self.caller.session_id),
                stream_id = self.caller_stream,
                "the caller's stream is already released; not answering"
            );
            return false;
        }
        let result = OpenResultFields {
            request_id: self.caller_request,
            stream_id: self.caller_stream,
            status: OpenStatus::Ok,
            detail: DETAIL_BRIDGED.to_string(),
        };
        match self.caller_handle.send_open_result(&result) {
            Ok(()) => {
                self.caller.flush_outbound();
                true
            }
            Err(error) => {
                tracing::debug!(
                    session = %hex::encode(self.caller.session_id),
                    stream_id = self.caller_stream,
                    %error,
                    "cannot answer Open"
                );
                self.caller.flush_outbound();
                false
            }
        }
    }

    /// Forgets the caller's local stream mapping.
    fn release_caller(&self) {
        self.caller.unregister_stream(self.caller_stream);
        self.caller_handle.close_stream(self.caller_stream);
        self.caller.flush_outbound();
    }

    /// Releases the publisher's leg, telling the publisher first when its stream
    /// is still installed locally.
    ///
    /// A refused `OpenResult` already removed the stream on both ends, and
    /// section 7.1 makes a reset terminal, so a leg whose engine no longer has the
    /// stream is not reset a second time.
    fn release_publisher(&self, stream_id: u64) {
        if self.publisher.handle.offsets(stream_id).is_some() {
            let _ = self
                .publisher
                .handle
                .send_reset(stream_id, ResetReason::Canceled);
        }
        self.publisher.unregister_stream(stream_id);
        self.publisher.handle.close_stream(stream_id);
        self.publisher.flush_outbound();
    }
}

#[cfg(test)]
mod tests {
    use wsnet_protocol::MessageKind;
    use wsnet_routing::{AclAction, AclRule};
    use wsnet_session::{ReadyFields, ServiceRegistration};

    use super::*;
    use crate::dataplane::tests::{connect_node, hub_for_nodes, soon, within, NodeLink};

    const CALLER: &str = "client-a";
    const CALLER_KEY: &str = "a-1";
    const PUBLISHER: &str = "pub-a";
    const PUBLISHER_KEY: &str = "p-1";
    const SERVICE: &str = "web";
    const TARGET: &str = "127.0.0.1:8080";

    /// A rule that authorises one caller to reach one published service.
    fn service_rule(service: &str) -> AclRule {
        AclRule {
            caller: CALLER.to_string(),
            action: AclAction::ConnectService,
            allow: true,
            node: Some(PUBLISHER.to_string()),
            service: Some(service.to_string()),
            host_cidr: None,
            ports: None,
            proto: None,
        }
    }

    /// A rule that authorises one caller to reach an address in a node's view.
    fn node_address_rule() -> AclRule {
        AclRule {
            caller: CALLER.to_string(),
            action: AclAction::ConnectNodeAddress,
            allow: true,
            node: Some(PUBLISHER.to_string()),
            service: None,
            host_cidr: None,
            ports: None,
            proto: None,
        }
    }

    /// The services the publisher registers for these tests.
    fn web_service() -> Vec<ServiceRegistration> {
        vec![ServiceRegistration {
            name: SERVICE.to_string(),
            proto: Proto::Tcp,
            target: TARGET.to_string(),
        }]
    }

    /// A caller and a publisher, both authenticated, registered, and on one Hub.
    async fn linked(acl: Vec<AclRule>, services: Vec<ServiceRegistration>) -> (NodeLink, NodeLink) {
        let hub = hub_for_nodes(acl, &[(CALLER, CALLER_KEY), (PUBLISHER, PUBLISHER_KEY)]);
        let caller = connect_node(&hub, CALLER, CALLER_KEY, 0x11).await;
        caller.hello(Vec::new(), 0x31).await;
        let publisher = connect_node(&hub, PUBLISHER, PUBLISHER_KEY, 0x12).await;
        publisher.hello(services, 0x32).await;
        (caller, publisher)
    }

    /// A bridge that is already carrying: the publisher accepted the caller's
    /// `Open`, and the caller's leg was answered.
    async fn bridged() -> (NodeLink, NodeLink, u64, u64) {
        let (mut caller, mut publisher) = linked(vec![service_rule(SERVICE)], web_service()).await;
        let caller_stream = open(&caller, Destination::service(PUBLISHER, SERVICE));
        let open_fields = next_open(&mut publisher).await;
        let publisher_stream = open_fields.stream_id;
        publisher
            .node
            .send_open_result(&OpenResultFields {
                request_id: open_fields.request_id,
                stream_id: publisher_stream,
                status: OpenStatus::Ok,
                detail: "publisher-local".to_string(),
            })
            .expect("the publisher must answer");
        let result = open_result(&mut caller, caller_stream).await;
        assert_eq!(result.status, OpenStatus::Ok, "{}", result.detail);
        (caller, publisher, caller_stream, publisher_stream)
    }

    /// Opens one destination on a node's session and returns the stream id.
    fn open(link: &NodeLink, destination: Destination) -> u64 {
        let (stream_id, _) = link
            .node
            .open(destination, Vec::new(), Proto::Tcp, [0x77; 16])
            .expect("the Open must queue");
        stream_id
    }

    /// The next event this node's engine produced, with a deadline.
    async fn next_event(link: &mut NodeLink) -> SessionEvent {
        soon("a node event", link.events.recv())
            .await
            .expect("the session must stay open")
    }

    /// The next `Open` this node's engine saw.
    async fn next_open(link: &mut NodeLink) -> OpenFields {
        loop {
            if let SessionEvent::Open(fields) = next_event(link).await {
                return fields;
            }
        }
    }

    /// The first `OpenResult` this node sees for `stream_id`.
    async fn open_result(link: &mut NodeLink, stream_id: u64) -> OpenResultFields {
        loop {
            if let SessionEvent::OpenResult(fields) = next_event(link).await {
                if fields.stream_id == stream_id {
                    return fields;
                }
            }
        }
    }

    /// The first `Reset` this node sees for `stream_id`.
    async fn next_reset(link: &mut NodeLink, stream_id: u64) -> wsnet_session::ResetFields {
        loop {
            if let SessionEvent::Reset(fields) = next_event(link).await {
                if fields.stream_id == stream_id {
                    return fields;
                }
            }
        }
    }

    /// Every `Data` byte for `stream_id` until its `Fin`, plus the offset.
    ///
    /// A `Reset` ends the wait with no offset, so a broken stream is visible
    /// instead of hanging.
    async fn read_until_fin(link: &mut NodeLink, stream_id: u64) -> (Vec<u8>, Option<u64>) {
        let mut bytes = Vec::new();
        loop {
            match next_event(link).await {
                SessionEvent::Data {
                    stream_id: id,
                    payload,
                    ..
                } if id == stream_id => bytes.extend_from_slice(&payload),
                SessionEvent::Fin(fields) if fields.stream_id == stream_id => {
                    return (bytes, Some(fields.final_offset))
                }
                SessionEvent::Reset(fields) if fields.stream_id == stream_id => {
                    return (bytes, None)
                }
                _ => {}
            }
        }
    }

    /// Reads exactly `wanted` bytes of `stream_id`, skipping other events.
    async fn read_bytes(link: &mut NodeLink, stream_id: u64, wanted: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        while bytes.len() < wanted {
            if let SessionEvent::Data {
                stream_id: id,
                payload,
                ..
            } = next_event(link).await
            {
                if id == stream_id {
                    bytes.extend_from_slice(&payload);
                }
            }
        }
        bytes
    }

    /// Waits until a condition holds, so no test depends on a fixed sleep.
    async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
        soon(what, async move {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
    }

    /// Asserts that no `Open` reaches this leg inside a short window.
    async fn assert_no_open(link: &mut NodeLink) {
        let idle = tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                if let SessionEvent::Open(fields) = next_event(link).await {
                    panic!("an unexpected Open was sent: stream {}", fields.stream_id);
                }
            }
        })
        .await;
        assert!(
            idle.is_err(),
            "the hub sent an Open that no check authorised"
        );
    }

    /// Asserts that no `OpenResult` for `stream_id` reaches this leg inside a
    /// short window, so a premature answer is caught rather than waited for.
    async fn assert_no_answer(link: &mut NodeLink, stream_id: u64) {
        let idle = tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                if let SessionEvent::OpenResult(fields) = next_event(link).await {
                    if fields.stream_id == stream_id {
                        panic!("the caller was answered too early: {fields:?}");
                    }
                }
            }
        })
        .await;
        assert!(idle.is_err(), "the caller was answered too early");
    }

    /// A caller `Open` for a published service reaches the publisher with the
    /// same destination, and only `OpenResult{Ok}` plus `Ready` releases success
    /// (sections 7.1, 7.6).
    #[tokio::test]
    async fn a_service_open_reaches_the_publisher_and_success_needs_both_halves() {
        within(async {
            let (mut caller, mut publisher) =
                linked(vec![service_rule(SERVICE)], web_service()).await;
            // A pinned revision travels with the destination: the publisher is
            // what re-resolves it (section 7.6).
            let destination = Destination::Service {
                node: PUBLISHER.to_string(),
                name: SERVICE.to_string(),
                revision: Some(1),
            };
            let caller_stream = open(&caller, destination.clone());

            let open_fields = next_open(&mut publisher).await;
            assert_eq!(
                open_fields.destination, destination,
                "the caller's destination must reach the publisher unchanged"
            );
            assert_eq!(open_fields.proto, Proto::Tcp);
            assert!(open_fields.via.is_empty());
            let publisher_stream = open_fields.stream_id;
            assert_eq!(
                publisher_stream % 2,
                0,
                "a Hub-initiated stream uses the even id space"
            );

            // `OpenResult{Ok}` alone is not success (section 7.1).
            publisher
                .node
                .send_control(
                    MessageKind::OpenResult,
                    OpenResultFields {
                        request_id: open_fields.request_id,
                        stream_id: publisher_stream,
                        status: OpenStatus::Ok,
                        detail: "publisher-local".to_string(),
                    }
                    .to_canonical(),
                )
                .expect("the OpenResult must queue");
            assert_no_answer(&mut caller, caller_stream).await;

            publisher
                .node
                .send_control(
                    MessageKind::Ready,
                    ReadyFields {
                        stream_id: publisher_stream,
                    }
                    .to_canonical(),
                )
                .expect("the Ready must queue");

            let result = open_result(&mut caller, caller_stream).await;
            assert_eq!(result.status, OpenStatus::Ok);
            assert_eq!(result.request_id, [0x77; 16]);
            assert_eq!(result.detail, DETAIL_BRIDGED);
            assert_eq!(caller.entry.handle.stream_count(), 1);
            assert_eq!(publisher.entry.handle.stream_count(), 1);
            assert_eq!(caller.entry.live_streams(), 1);
            assert_eq!(publisher.entry.live_streams(), 1);
        })
        .await;
    }

    /// A node-viewed address is bridged the same way, with the same destination
    /// (section 7.6).
    #[tokio::test]
    async fn a_node_address_open_reaches_the_named_node() {
        within(async {
            let (mut caller, mut publisher) = linked(vec![node_address_rule()], Vec::new()).await;
            let destination = Destination::node_address(PUBLISHER, "127.0.0.1", 8080);
            let caller_stream = open(&caller, destination.clone());

            let open_fields = next_open(&mut publisher).await;
            assert_eq!(open_fields.destination, destination);
            let publisher_stream = open_fields.stream_id;
            publisher
                .node
                .send_open_result(&OpenResultFields {
                    request_id: open_fields.request_id,
                    stream_id: publisher_stream,
                    status: OpenStatus::Ok,
                    detail: "publisher-local".to_string(),
                })
                .expect("the publisher must answer");

            assert_eq!(
                open_result(&mut caller, caller_stream).await.status,
                OpenStatus::Ok
            );
        })
        .await;
    }

    /// Bytes travel caller to publisher and publisher to caller byte for byte
    /// (sections 7.1, 7.5).
    #[tokio::test]
    async fn bytes_travel_both_ways_byte_for_byte() {
        within(async {
            let (mut caller, mut publisher, caller_stream, publisher_stream) = bridged().await;

            let uplink: Vec<u8> = (0..4096u32).map(|index| (index % 251) as u8).collect();
            assert_eq!(
                caller
                    .node
                    .send_data(caller_stream, &uplink)
                    .expect("the caller's bytes must fit the credit"),
                uplink.len()
            );
            let seen = read_bytes(&mut publisher, publisher_stream, uplink.len()).await;
            assert_eq!(seen, uplink);

            let downlink: Vec<u8> = (0..4096u32).map(|index| (index % 197) as u8).collect();
            assert_eq!(
                publisher
                    .node
                    .send_data(publisher_stream, &downlink)
                    .expect("the publisher's bytes must fit the credit"),
                downlink.len()
            );
            let seen = read_bytes(&mut caller, caller_stream, downlink.len()).await;
            assert_eq!(seen, downlink);
        })
        .await;
    }

    /// A refused or offline publisher is relayed as that status, with a local
    /// detail, and the Hub never sends a second `Open` (sections 4.1, 7.1).
    #[tokio::test]
    async fn a_publisher_refusal_is_relayed_and_never_retried() {
        within(async {
            let (mut caller, mut publisher) =
                linked(vec![service_rule(SERVICE)], web_service()).await;

            for (status, seed) in [
                (OpenStatus::Refused, [0xA1u8; 16]),
                (OpenStatus::Offline, [0xA2u8; 16]),
            ] {
                let (caller_stream, _) = caller
                    .node
                    .open(
                        Destination::service(PUBLISHER, SERVICE),
                        Vec::new(),
                        Proto::Tcp,
                        seed,
                    )
                    .expect("the Open must queue");
                let open_fields = next_open(&mut publisher).await;
                publisher
                    .node
                    .send_open_result(&OpenResultFields {
                        request_id: open_fields.request_id,
                        stream_id: open_fields.stream_id,
                        status,
                        detail: "publisher-local".to_string(),
                    })
                    .expect("the publisher must answer");

                let result = open_result(&mut caller, caller_stream).await;
                assert_eq!(result.status, status);
                assert_eq!(
                    result.detail, DETAIL_PUBLISHER_REFUSED,
                    "the detail must stay local to this hub"
                );
                eventually("the caller's leg to be released", || {
                    caller.entry.live_streams() == 0
                })
                .await;
                eventually("the publisher's leg to be released", || {
                    publisher.entry.live_streams() == 0
                })
                .await;
            }

            assert_no_open(&mut publisher).await;
        })
        .await;
    }

    /// An unregistered publisher is `Offline`, and no session is invented for it
    /// (sections 7.6, 8).
    #[tokio::test]
    async fn an_unregistered_publisher_is_offline() {
        within(async {
            // The rule authorises the service, but no node publishes it.
            let hub = hub_for_nodes(vec![service_rule(SERVICE)], &[(CALLER, CALLER_KEY)]);
            let mut caller = connect_node(&hub, CALLER, CALLER_KEY, 0x11).await;
            caller.hello(Vec::new(), 0x31).await;
            assert!(
                hub.session_for_node(PUBLISHER).is_none(),
                "no publisher session may be invented"
            );

            let caller_stream = open(&caller, Destination::service(PUBLISHER, SERVICE));
            let result = open_result(&mut caller, caller_stream).await;
            assert_eq!(result.status, OpenStatus::Offline);
            // Nothing was dialled: no bridge ever claimed the caller's stream.
            assert_eq!(caller.entry.live_streams(), 0);
            assert_eq!(caller.entry.handle.stream_count(), 0);
        })
        .await;
    }

    /// A missing `connect_service` rule is `Denied` before the publisher is ever
    /// asked (section 9.3).
    #[tokio::test]
    async fn a_missing_service_rule_is_denied_and_reaches_no_publisher() {
        within(async {
            // The publisher is live and publishing, but no rule names the service.
            let (mut caller, mut publisher) = linked(Vec::new(), web_service()).await;
            let caller_stream = open(&caller, Destination::service(PUBLISHER, SERVICE));

            let result = open_result(&mut caller, caller_stream).await;
            assert_eq!(result.status, OpenStatus::Denied);
            assert_eq!(caller.entry.live_streams(), 0);
            assert_no_open(&mut publisher).await;
        })
        .await;
    }

    /// A `Fin` from the publisher half-closes one direction only (section 7.2).
    #[tokio::test]
    async fn a_fin_from_the_publisher_half_closes_one_direction() {
        within(async {
            let (mut caller, mut publisher, caller_stream, publisher_stream) = bridged().await;

            let downlink = b"the publisher's output".to_vec();
            assert_eq!(
                publisher
                    .node
                    .send_data(publisher_stream, &downlink)
                    .expect("the publisher writes"),
                downlink.len()
            );
            assert_eq!(
                publisher
                    .node
                    .send_fin(publisher_stream)
                    .expect("the publisher half-closes"),
                downlink.len() as u64
            );

            let (bytes, fin) = read_until_fin(&mut caller, caller_stream).await;
            assert_eq!(bytes, downlink);
            assert_eq!(fin, Some(downlink.len() as u64));

            // The caller's direction is still open: a half-close is half.
            let uplink = b"still sending".to_vec();
            assert_eq!(
                caller
                    .node
                    .send_data(caller_stream, &uplink)
                    .expect("the caller still has credit"),
                uplink.len()
            );
            assert_eq!(
                read_bytes(&mut publisher, publisher_stream, uplink.len()).await,
                uplink
            );
            assert_eq!(caller.entry.live_streams(), 1);
            assert_eq!(publisher.entry.live_streams(), 1);
        })
        .await;
    }

    /// A `Reset` from the caller tears both legs down and frees both stream ids
    /// (sections 7.1, 8).
    #[tokio::test]
    async fn a_reset_from_the_caller_frees_both_legs() {
        within(async {
            let (caller, mut publisher, caller_stream, publisher_stream) = bridged().await;

            caller
                .node
                .send_reset(caller_stream, ResetReason::Canceled)
                .expect("the reset must queue");
            assert_eq!(
                next_reset(&mut publisher, publisher_stream).await.reason,
                ResetReason::Canceled
            );

            eventually("the caller's leg to be released", || {
                caller.entry.live_streams() == 0
            })
            .await;
            eventually("the publisher's leg to be released", || {
                publisher.entry.live_streams() == 0
            })
            .await;
            assert_eq!(caller.entry.handle.stream_count(), 0);
            assert_eq!(publisher.entry.handle.stream_count(), 0);
        })
        .await;
    }

    /// A `Reset` from the publisher tears both legs down and frees both stream
    /// ids (sections 7.1, 8).
    #[tokio::test]
    async fn a_reset_from_the_publisher_frees_both_legs() {
        within(async {
            let (mut caller, publisher, caller_stream, publisher_stream) = bridged().await;

            publisher
                .node
                .send_reset(publisher_stream, ResetReason::Canceled)
                .expect("the reset must queue");
            assert_eq!(
                next_reset(&mut caller, caller_stream).await.reason,
                ResetReason::Canceled
            );

            eventually("the publisher's leg to be released", || {
                publisher.entry.live_streams() == 0
            })
            .await;
            eventually("the caller's leg to be released", || {
                caller.entry.live_streams() == 0
            })
            .await;
            assert_eq!(caller.entry.handle.stream_count(), 0);
            assert_eq!(publisher.entry.handle.stream_count(), 0);
        })
        .await;
    }

    /// Two bridges share the two sessions, and resetting one leaves the other
    /// carrying bytes (sections 7.1, 7.5).
    #[tokio::test]
    async fn a_reset_leaves_a_second_bridge_usable() {
        within(async {
            let (mut caller, mut publisher) =
                linked(vec![service_rule(SERVICE)], web_service()).await;

            let mut caller_streams = Vec::new();
            let mut publisher_streams = Vec::new();
            for seed in [[0xB1u8; 16], [0xB2u8; 16]] {
                let (caller_stream, _) = caller
                    .node
                    .open(
                        Destination::service(PUBLISHER, SERVICE),
                        Vec::new(),
                        Proto::Tcp,
                        seed,
                    )
                    .expect("the Open must queue");
                let open_fields = next_open(&mut publisher).await;
                let publisher_stream = open_fields.stream_id;
                publisher
                    .node
                    .send_open_result(&OpenResultFields {
                        request_id: open_fields.request_id,
                        stream_id: publisher_stream,
                        status: OpenStatus::Ok,
                        detail: "publisher-local".to_string(),
                    })
                    .expect("the publisher must answer");
                assert_eq!(
                    open_result(&mut caller, caller_stream).await.status,
                    OpenStatus::Ok
                );
                caller_streams.push(caller_stream);
                publisher_streams.push(publisher_stream);
            }
            let (first_caller, second_caller) = (caller_streams[0], caller_streams[1]);
            let (first_publisher, second_publisher) = (publisher_streams[0], publisher_streams[1]);
            assert_eq!(caller.entry.live_streams(), 2);
            assert_eq!(publisher.entry.live_streams(), 2);

            // Resetting the first bridge must not touch the second.
            caller
                .node
                .send_reset(first_caller, ResetReason::Canceled)
                .expect("the reset must queue");
            assert_eq!(
                next_reset(&mut publisher, first_publisher).await.stream_id,
                first_publisher
            );
            eventually("the reset bridge to be released", || {
                caller.entry.live_streams() == 1 && publisher.entry.live_streams() == 1
            })
            .await;

            let uplink = b"the surviving bridge".to_vec();
            assert_eq!(
                caller
                    .node
                    .send_data(second_caller, &uplink)
                    .expect("the second stream still has credit"),
                uplink.len()
            );
            assert_eq!(
                read_bytes(&mut publisher, second_publisher, uplink.len()).await,
                uplink
            );
            let downlink = b"still bridged".to_vec();
            assert_eq!(
                publisher
                    .node
                    .send_data(second_publisher, &downlink)
                    .expect("the second stream still has credit"),
                downlink.len()
            );
            assert_eq!(
                read_bytes(&mut caller, second_caller, downlink.len()).await,
                downlink
            );
        })
        .await;
    }
}
