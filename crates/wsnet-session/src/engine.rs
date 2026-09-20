//! The session engine: sealing, replay, and stream multiplexing (DESIGN.md sections 4-7).
//!
//! The engine is deliberately transport-free. It consumes *sealed envelopes* on
//! the way in and produces them on the way out, through two channels:
//!
//! ```text
//!   carrier task --- envelope ---> SessionHandle::feed
//!   SessionHandle --- envelope ---> outbound channel ---> carrier task
//! ```
//!
//! Everything true of a session regardless of carrier lives here: one
//! `packet_no` allocator per direction (section 4.2), the replay window, stream
//! ids allocated by parity (section 4.2), per-stream credit and bounded reorder
//! (sections 7.3 and 7.5), and the lifecycle states of section 5.3.
//!
//! Section 4.2's warning that transport replay is not business idempotency is
//! respected structurally: this engine drops a duplicated *envelope* and does
//! nothing else. Deciding whether a repeated `request_id` may run again is
//! `wsnet-operation`'s job, so `Open` is surfaced as an event for the caller to
//! arbitrate rather than resolved here.
//!
//! The engine never holds the pre-shared key. It is constructed from an already
//! derived [`SessionKeys`], so the PSK's lifetime is confined to the handshake
//! and cannot leak into the data path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use wsnet_auth_store::{ReplayError, ReplayWindow};
use wsnet_crypto::{
    open, seal, Direction, EnvelopeContext, EnvelopeError, PacketNoAllocator, PacketNoError,
    SessionKeys,
};
use wsnet_limits::{
    FLOW_WINDOW_BYTES, MAX_STREAMS_PER_SESSION, MAX_TCP_PAYLOAD, STREAM_INITIAL_CREDIT,
};
use wsnet_protocol::{Canonical, MessageKind, Record, RecordError};
use wsnet_routing::{Destination, Proto};
use wsnet_stream::{CreditAccount, ReorderBuffer, StreamError};

use crate::message::{
    ByeFields, CancelCandidateFields, DataFields, FinFields, HelloFields, HelloOkFields,
    MessageError, OpenFields, OpenResultFields, OpenStatus, ProgressFields, ReadyFields,
    ResetFields, ResetReason, ResumeFields,
};

/// Which end of the protocol this engine is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The node side; uses odd stream ids.
    Node,
    /// The Hub side; uses even stream ids.
    Hub,
}

impl Side {
    /// The direction this side sends in.
    pub const fn send_direction(self) -> Direction {
        match self {
            Side::Node => Direction::ClientToServer,
            Side::Hub => Direction::ServerToClient,
        }
    }

    /// The direction this side receives from.
    pub const fn recv_direction(self) -> Direction {
        self.send_direction().peer()
    }

    /// The first stream id this side may allocate.
    ///
    /// Section 4.2 reserves 0 and splits the space by parity: "客户端发起用奇数、
    /// Hub 发起用偶数，0 保留".
    pub const fn first_stream_id(self) -> u64 {
        match self {
            Side::Node => 1,
            Side::Hub => 2,
        }
    }
}

/// Everything the engine needs to know about a session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Hub this session belongs to.
    pub hub_id: String,
    /// Session id; a routing label, never a bearer credential.
    pub session_id: [u8; 16],
    /// Key epoch.
    pub session_epoch: [u8; 16],
    /// Which end this engine is.
    pub side: Side,
    /// Node identity, for logging.
    pub node_id: String,
    /// Per-stream flow-control window.
    pub flow_window: u64,
    /// Concurrent stream cap.
    pub max_streams: usize,
}

impl SessionConfig {
    /// Builds a configuration with the design's default budgets.
    pub fn new(
        hub_id: impl Into<String>,
        node_id: impl Into<String>,
        session_id: [u8; 16],
        session_epoch: [u8; 16],
        side: Side,
    ) -> Self {
        SessionConfig {
            hub_id: hub_id.into(),
            node_id: node_id.into(),
            session_id,
            session_epoch,
            side,
            flow_window: FLOW_WINDOW_BYTES,
            max_streams: MAX_STREAMS_PER_SESSION,
        }
    }
}

/// Session lifecycle (DESIGN.md section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// No session yet.
    Offline,
    /// Authentication in flight.
    Authenticating,
    /// Authenticated, binding carriers.
    Binding,
    /// Bound, waiting for `HelloOk`; business `Open` is refused before it.
    HelloPending,
    /// Fully usable.
    Ready,
    /// A carrier broke but the session may still recover.
    Degraded,
    /// Terminal.
    Closed,
}

/// Errors from the session engine.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The envelope failed to open.
    #[error("envelope: {0}")]
    Envelope(#[from] EnvelopeError),
    /// The envelope was a replay or unjudgeable.
    #[error("replay: {0}")]
    Replay(#[from] ReplayError),
    /// The record framing was invalid.
    #[error("record: {0}")]
    Record(#[from] RecordError),
    /// The metadata was invalid.
    #[error("message: {0}")]
    Message(#[from] MessageError),
    /// The stream state machine refused the operation.
    #[error("stream: {0}")]
    Stream(#[from] StreamError),
    /// The `packet_no` space is exhausted; the session must be rebuilt.
    #[error("packet_no: {0}")]
    PacketNo(#[from] PacketNoError),
    /// The peer referenced a stream this side does not have.
    #[error("unknown stream {0}")]
    UnknownStream(u64),
    /// The stream cap is reached.
    #[error("session already has {0} streams")]
    TooManyStreams(usize),
    /// No further stream ids can be allocated without wrapping.
    #[error("stream id space exhausted")]
    StreamIdsExhausted,
    /// The carrier channel is gone; the session is over.
    #[error("session transport is closed")]
    Closed,
    /// Business traffic was attempted before `HelloOk`.
    #[error("session is not ready for business traffic")]
    NotReady,
}

/// Something the caller must react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    /// The peer wants a stream opened.
    Open(OpenFields),
    /// The peer answered an `Open`.
    OpenResult(OpenResultFields),
    /// The peer queried a cached result.
    QueryResult(OpenResultFields),
    /// The peer registered.
    Hello(HelloFields),
    /// Registration was acknowledged; the business barrier is lifted.
    HelloOk(HelloOkFields),
    /// A stream's receive halves are installed.
    Ready(ReadyFields),
    /// Ordered business bytes.
    Data {
        /// Stream the bytes belong to.
        stream_id: u64,
        /// Absolute offset of the first byte.
        offset: u64,
        /// The bytes.
        payload: Vec<u8>,
    },
    /// One UDP datagram, with its metadata still in canonical form.
    ///
    /// The association state machine lives above the engine, so the engine
    /// carries the metadata through rather than re-decoding it into a shape only
    /// the UDP layer understands.
    Datagram {
        /// Canonical `Datagram` metadata.
        metadata: Canonical,
        /// The datagram payload.
        payload: Vec<u8>,
    },
    /// A half-close.
    Fin(FinFields),
    /// A termination.
    Reset(ResetFields),
    /// Credit and acknowledgement progress.
    Progress(ProgressFields),
    /// An in-session recovery request.
    Resume(ResumeFields),
    /// A candidate was cancelled.
    CancelCandidate(CancelCandidateFields),
    /// Keepalive.
    Ping,
    /// Keepalive response.
    Pong,
    /// Session close requested by the peer.
    Bye(ByeFields),
    /// Registration snapshot.
    PeerList(Canonical),
    /// A replayed envelope was dropped. Never a business error (section 4.2).
    Dropped {
        /// The `packet_no` that was dropped.
        packet_no: u64,
    },
    /// The session state changed.
    StateChanged(SessionState),
}

/// A session: the handle plus the channels a carrier task drives.
pub struct Session {
    /// Call this to send and to feed inbound envelopes.
    pub handle: SessionHandle,
    /// Events for the caller to arbitrate.
    pub events: mpsc::UnboundedReceiver<SessionEvent>,
    /// Sealed envelopes to hand to a carrier.
    pub outbound: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// A cloneable handle to one session.
#[derive(Clone)]
pub struct SessionHandle {
    inner: Arc<Inner>,
}

struct Inner {
    config: SessionConfig,
    ctx: EnvelopeContext,
    keys: SessionKeys,
    send_allocator: PacketNoAllocator,
    recv_window: Mutex<ReplayWindow>,
    outbound: mpsc::UnboundedSender<Vec<u8>>,
    events: mpsc::UnboundedSender<SessionEvent>,
    state: Mutex<SessionState>,
    streams: Mutex<HashMap<u64, StreamEntry>>,
    next_stream_id: AtomicU64,
}

struct StreamEntry {
    recv: ReorderBuffer,
    credit: CreditAccount,
    send_offset: u64,
    send_limit: u64,
    fin_sent: bool,
    fin_received: Option<u64>,
}

impl StreamEntry {
    fn new(window: u64) -> Self {
        let initial = STREAM_INITIAL_CREDIT.min(window);
        StreamEntry {
            recv: ReorderBuffer::new(0),
            credit: CreditAccount::new(initial, window),
            send_offset: 0,
            send_limit: initial,
            fin_sent: false,
            fin_received: None,
        }
    }
}

impl Session {
    /// Creates a session and its two channels.
    ///
    /// This is an associated function on [`Session`] rather than on
    /// [`SessionHandle`] because it returns the whole session: a handle alone
    /// would leave the caller holding nothing to read events or envelopes from.
    pub fn new(config: SessionConfig, keys: SessionKeys) -> Session {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let ctx = EnvelopeContext::new(
            config.hub_id.clone(),
            config.session_id,
            config.session_epoch,
        );
        let inner = Inner {
            next_stream_id: AtomicU64::new(config.side.first_stream_id()),
            config,
            ctx,
            keys,
            send_allocator: PacketNoAllocator::new(),
            recv_window: Mutex::new(ReplayWindow::new()),
            outbound: outbound_tx,
            events: events_tx,
            state: Mutex::new(SessionState::Offline),
            streams: Mutex::new(HashMap::new()),
        };
        Session {
            handle: SessionHandle {
                inner: Arc::new(inner),
            },
            events: events_rx,
            outbound: outbound_rx,
        }
    }
}

impl SessionHandle {
    /// The session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.inner.config
    }

    /// The current lifecycle state.
    pub fn state(&self) -> SessionState {
        *self.inner.state.lock().expect("state mutex")
    }

    /// Moves the session to a new lifecycle state.
    pub fn set_state(&self, state: SessionState) {
        let mut guard = self.inner.state.lock().expect("state mutex");
        if *guard != state {
            *guard = state;
            let _ = self.inner.events.send(SessionEvent::StateChanged(state));
        }
    }

    /// Number of live streams.
    pub fn stream_count(&self) -> usize {
        self.inner.streams.lock().expect("streams mutex").len()
    }

    /// Whether the session may carry business traffic.
    pub fn is_ready(&self) -> bool {
        matches!(self.state(), SessionState::Ready)
    }

    /// The next outbound `packet_no`, for tests and diagnostics.
    pub fn next_packet_no(&self) -> Option<u64> {
        self.inner.send_allocator.next_unused()
    }

    fn send_key(&self) -> &[u8; 32] {
        self.inner
            .keys
            .message_key(self.inner.config.side.send_direction())
    }

    fn recv_key(&self) -> &[u8; 32] {
        self.inner
            .keys
            .message_key(self.inner.config.side.recv_direction())
    }

    /// Opens an inbound envelope, checks replay, and dispatches it.
    ///
    /// AEAD verification happens *before* the replay window is consulted, as
    /// section 4.2 requires ("先验 AEAD，再原子检查/登记"): an attacker must not
    /// be able to burn counter space with a forged record.
    pub fn feed(&self, envelope: &[u8]) -> Result<(), SessionError> {
        let opened = open(
            self.recv_key(),
            &self.inner.ctx,
            self.inner.config.side.recv_direction(),
            envelope,
        )?;
        self.inner
            .recv_window
            .lock()
            .expect("replay mutex")
            .check_and_record(opened.packet_no)?;
        let record = Record::decode(&opened.plaintext)?;
        self.dispatch(record)
    }

    /// Feeds an envelope, treating a transport replay as a drop.
    ///
    /// A duplicated envelope is normal on a lossy carrier, so a carrier task
    /// wants to ignore it and keep the session alive. Returns whether the
    /// envelope was authentic: `false` means it was forged or malformed, which
    /// the caller should count rather than ignore.
    pub fn feed_lossy(&self, envelope: &[u8]) -> bool {
        match self.feed(envelope) {
            Ok(()) => true,
            Err(SessionError::Replay(ReplayError::Duplicate(packet_no))) => {
                let _ = self.inner.events.send(SessionEvent::Dropped { packet_no });
                true
            }
            Err(_) => false,
        }
    }

    /// Seals and queues one message.
    pub fn send(
        &self,
        kind: MessageKind,
        metadata: Canonical,
        payload: Vec<u8>,
    ) -> Result<(), SessionError> {
        let record = if payload.is_empty() && !kind.carries_payload() {
            Record::new(kind, metadata)
        } else {
            Record::with_payload(kind, metadata, payload)
        };
        let plaintext = record.encode()?;
        let packet_no = self.inner.send_allocator.allocate()?;
        let envelope = seal(
            self.send_key(),
            &self.inner.ctx,
            self.inner.config.side.send_direction(),
            packet_no,
            &plaintext,
        )?;
        self.inner
            .outbound
            .send(envelope)
            .map_err(|_| SessionError::Closed)
    }

    /// Sends a metadata-only message.
    pub fn send_control(&self, kind: MessageKind, metadata: Canonical) -> Result<(), SessionError> {
        self.send(kind, metadata, Vec::new())
    }

    /// Sends `Hello`.
    pub fn send_hello(&self, hello: &HelloFields) -> Result<(), SessionError> {
        self.send_control(MessageKind::Hello, hello.to_canonical())
    }

    /// Sends `HelloOk` and lifts the business barrier.
    pub fn send_hello_ok(&self, hello_ok: &HelloOkFields) -> Result<(), SessionError> {
        self.send_control(MessageKind::HelloOk, hello_ok.to_canonical())?;
        self.set_state(SessionState::Ready);
        Ok(())
    }

    /// Allocates a stream id and sends `Open`.
    ///
    /// Returns the stream id and the `request_id`, so the caller can drive the
    /// idempotency table with the same identifier it put on the wire.
    pub fn open(
        &self,
        destination: Destination,
        via: Vec<String>,
        proto: Proto,
        request_id: [u8; 16],
    ) -> Result<(u64, [u8; 16]), SessionError> {
        let stream_id = self.allocate_stream_id()?;
        {
            let mut streams = self.inner.streams.lock().expect("streams mutex");
            if streams.len() >= self.inner.config.max_streams {
                return Err(SessionError::TooManyStreams(streams.len()));
            }
            streams.insert(stream_id, StreamEntry::new(self.inner.config.flow_window));
        }
        let fields = OpenFields {
            request_id,
            stream_id,
            proto,
            destination,
            via,
        };
        self.send_control(MessageKind::Open, fields.to_canonical())?;
        Ok((stream_id, request_id))
    }

    /// Sends `OpenResult`, and `Ready` when the open succeeded.
    ///
    /// Section 7.1 requires the success to be reported only after both receive
    /// halves are installed, so `Ready` is sent as part of the same operation
    /// rather than left to the caller to remember.
    pub fn send_open_result(&self, fields: &OpenResultFields) -> Result<(), SessionError> {
        self.send_control(MessageKind::OpenResult, fields.to_canonical())?;
        if fields.status == OpenStatus::Ok {
            self.send_ready(fields.stream_id)?;
        } else {
            self.close_stream(fields.stream_id);
        }
        Ok(())
    }

    /// Sends `Ready`.
    pub fn send_ready(&self, stream_id: u64) -> Result<(), SessionError> {
        self.send_control(
            MessageKind::Ready,
            ReadyFields { stream_id }.to_canonical(),
        )
    }

    /// Sends `Data`, splitting to the per-record payload limit.
    ///
    /// Every chunk respects the peer's granted `limit_offset`; exceeding it is a
    /// protocol error rather than something to truncate (section 7.5).
    pub fn send_data(&self, stream_id: u64, payload: &[u8]) -> Result<usize, SessionError> {
        if payload.is_empty() {
            return Ok(0);
        }
        // Check the whole payload against the granted credit before sending any
        // of it. Section 7.5 makes over-credit data a protocol error, and a
        // half-delivered block would be worse than a clean refusal: the caller
        // would have to reason about how much of its buffer actually went out.
        let (mut offset, limit) = {
            let streams = self.inner.streams.lock().expect("streams mutex");
            let entry = streams
                .get(&stream_id)
                .ok_or(SessionError::UnknownStream(stream_id))?;
            (entry.send_offset, entry.send_limit)
        };
        let end = offset
            .checked_add(payload.len() as u64)
            .ok_or(StreamError::OffsetOverflow)?;
        if end > limit {
            return Err(SessionError::Stream(StreamError::CreditExceeded {
                sent_to: end,
                limit,
            }));
        }

        let mut sent = 0usize;
        while sent < payload.len() {
            let chunk_len = (payload.len() - sent).min(MAX_TCP_PAYLOAD);
            let fields = DataFields { stream_id, offset };
            self.send(
                MessageKind::Data,
                fields.to_canonical(),
                payload[sent..sent + chunk_len].to_vec(),
            )?;
            offset += chunk_len as u64;
            {
                let mut streams = self.inner.streams.lock().expect("streams mutex");
                if let Some(entry) = streams.get_mut(&stream_id) {
                    entry.send_offset = offset;
                }
            }
            sent += chunk_len;
        }
        Ok(sent)
    }

    /// Sends `Fin` carrying the final offset.
    pub fn send_fin(&self, stream_id: u64) -> Result<u64, SessionError> {
        let final_offset = {
            let mut streams = self.inner.streams.lock().expect("streams mutex");
            let entry = streams
                .get_mut(&stream_id)
                .ok_or(SessionError::UnknownStream(stream_id))?;
            if entry.fin_sent {
                return Ok(entry.send_offset);
            }
            entry.fin_sent = true;
            entry.send_offset
        };
        self.send_control(
            MessageKind::Fin,
            FinFields {
                stream_id,
                final_offset,
            }
            .to_canonical(),
        )?;
        Ok(final_offset)
    }

    /// Sends `Reset` and forgets the stream.
    pub fn send_reset(&self, stream_id: u64, reason: ResetReason) -> Result<(), SessionError> {
        self.send_control(
            MessageKind::Reset,
            ResetFields { stream_id, reason }.to_canonical(),
        )?;
        self.close_stream(stream_id);
        Ok(())
    }

    /// Sends `Resume` for in-session recovery.
    pub fn send_resume(&self, stream_id: u64, received_offset: u64) -> Result<(), SessionError> {
        self.send_control(
            MessageKind::Resume,
            ResumeFields {
                stream_id,
                received_offset,
            }
            .to_canonical(),
        )
    }

    /// Sends `CancelCandidate`.
    pub fn send_cancel_candidate(&self, attempt_id: [u8; 16]) -> Result<(), SessionError> {
        self.send_control(
            MessageKind::CancelCandidate,
            CancelCandidateFields { attempt_id }.to_canonical(),
        )
    }

    /// Sends `Ping`.
    pub fn send_ping(&self) -> Result<(), SessionError> {
        self.send_control(MessageKind::Ping, crate::message::empty_metadata())
    }

    /// Sends `Pong`.
    pub fn send_pong(&self) -> Result<(), SessionError> {
        self.send_control(MessageKind::Pong, crate::message::empty_metadata())
    }

    /// Sends `Bye` and closes the session.
    pub fn send_bye(&self, reason: &str) -> Result<(), SessionError> {
        self.send_control(
            MessageKind::Bye,
            ByeFields {
                reason: reason.to_string(),
            }
            .to_canonical(),
        )?;
        self.set_state(SessionState::Closed);
        Ok(())
    }

    /// Sends `PeerList`.
    pub fn send_peer_list(&self, peer_list: Canonical) -> Result<(), SessionError> {
        self.send_control(MessageKind::PeerList, peer_list)
    }

    /// Sends one `Datagram` record.
    pub fn send_datagram(
        &self,
        metadata: Canonical,
        payload: Vec<u8>,
    ) -> Result<(), SessionError> {
        self.send(MessageKind::Datagram, metadata, payload)
    }

    /// Records that the application consumed bytes, emitting `Progress` when the
    /// peer earned new credit.
    ///
    /// Section 7.5 is explicit that credit is replenished from what the
    /// application *consumed*, never from what merely arrived.
    pub fn consume(
        &self,
        stream_id: u64,
        bytes: u64,
    ) -> Result<Option<ProgressFields>, SessionError> {
        let fields = {
            let mut streams = self.inner.streams.lock().expect("streams mutex");
            let entry = streams
                .get_mut(&stream_id)
                .ok_or(SessionError::UnknownStream(stream_id))?;
            let grant = entry.credit.consume(bytes)?;
            if grant == 0 {
                return Ok(None);
            }
            ProgressFields {
                stream_id,
                received_offset: entry.credit.received(),
                consumed_offset: entry.credit.consumed(),
                limit_offset: entry.credit.limit(),
            }
        };
        self.send_control(MessageKind::Progress, fields.to_canonical())?;
        Ok(Some(fields))
    }

    /// Sends the current cumulative `Progress` regardless of new credit, for the
    /// periodic refresh section 7.5 asks for.
    pub fn send_progress_now(&self, stream_id: u64) -> Result<ProgressFields, SessionError> {
        let fields = self.progress_fields(stream_id)?;
        self.send_control(MessageKind::Progress, fields.to_canonical())?;
        Ok(fields)
    }

    /// The current progress counters for a stream.
    pub fn progress_fields(&self, stream_id: u64) -> Result<ProgressFields, SessionError> {
        let streams = self.inner.streams.lock().expect("streams mutex");
        let entry = streams
            .get(&stream_id)
            .ok_or(SessionError::UnknownStream(stream_id))?;
        Ok(ProgressFields {
            stream_id,
            received_offset: entry.credit.received(),
            consumed_offset: entry.credit.consumed(),
            limit_offset: entry.credit.limit(),
        })
    }

    /// The send-side offsets for a stream: `(send_offset, send_limit, received)`.
    pub fn offsets(&self, stream_id: u64) -> Option<(u64, u64, u64)> {
        let streams = self.inner.streams.lock().expect("streams mutex");
        streams
            .get(&stream_id)
            .map(|entry| (entry.send_offset, entry.send_limit, entry.credit.received()))
    }

    /// Forgets a stream's state.
    pub fn close_stream(&self, stream_id: u64) {
        self.inner
            .streams
            .lock()
            .expect("streams mutex")
            .remove(&stream_id);
    }

    fn allocate_stream_id(&self) -> Result<u64, SessionError> {
        let id = self.inner.next_stream_id.fetch_add(2, Ordering::AcqRel);
        // `fetch_add` wraps, so refuse once the next id would overflow instead of
        // silently reusing an id (section 4.2 forbids stream id reuse).
        if id.checked_add(2).is_none() {
            return Err(SessionError::StreamIdsExhausted);
        }
        Ok(id)
    }

    fn dispatch(&self, record: Record) -> Result<(), SessionError> {
        use MessageKind::*;
        match record.kind {
            Ping => {
                let _ = self.inner.events.send(SessionEvent::Ping);
            }
            Pong => {
                let _ = self.inner.events.send(SessionEvent::Pong);
            }
            Hello => {
                let fields = HelloFields::from_canonical(&record.metadata)?;
                let _ = self.inner.events.send(SessionEvent::Hello(fields));
            }
            HelloOk => {
                let fields = HelloOkFields::from_canonical(&record.metadata)?;
                self.set_state(SessionState::Ready);
                let _ = self.inner.events.send(SessionEvent::HelloOk(fields));
            }
            Open => {
                let fields = OpenFields::from_canonical(&record.metadata)?;
                if self.state() != SessionState::Ready {
                    // Section 5.3: HelloOk is the business barrier, so an early
                    // Open is reset rather than half-installed.
                    self.send_reset(fields.stream_id, ResetReason::ProtocolError)
                        .ok();
                    return Err(SessionError::NotReady);
                }
                {
                    let mut streams = self.inner.streams.lock().expect("streams mutex");
                    streams
                        .entry(fields.stream_id)
                        .or_insert_with(|| StreamEntry::new(self.inner.config.flow_window));
                }
                let _ = self.inner.events.send(SessionEvent::Open(fields));
            }
            OpenResult => {
                let fields = OpenResultFields::from_canonical(&record.metadata)?;
                if fields.status != OpenStatus::Ok {
                    self.close_stream(fields.stream_id);
                }
                let _ = self.inner.events.send(SessionEvent::OpenResult(fields));
            }
            QueryResult => {
                let fields = OpenResultFields::from_canonical(&record.metadata)?;
                let _ = self.inner.events.send(SessionEvent::QueryResult(fields));
            }
            Ready => {
                let fields = ReadyFields::from_canonical(&record.metadata)?;
                let _ = self.inner.events.send(SessionEvent::Ready(fields));
            }
            Data => {
                let fields = DataFields::from_canonical(&record.metadata)?;
                self.deliver_data(fields, record.payload)?;
            }
            Datagram => {
                let _ = self.inner.events.send(SessionEvent::Datagram {
                    metadata: record.metadata.clone(),
                    payload: record.payload,
                });
            }
            Fin => {
                let fields = FinFields::from_canonical(&record.metadata)?;
                {
                    let mut streams = self.inner.streams.lock().expect("streams mutex");
                    if let Some(entry) = streams.get_mut(&fields.stream_id) {
                        entry.fin_received = Some(fields.final_offset);
                    }
                }
                let _ = self.inner.events.send(SessionEvent::Fin(fields));
            }
            Reset => {
                let fields = ResetFields::from_canonical(&record.metadata)?;
                self.close_stream(fields.stream_id);
                let _ = self.inner.events.send(SessionEvent::Reset(fields));
            }
            Progress => {
                let fields = ProgressFields::from_canonical(&record.metadata)?;
                {
                    let mut streams = self.inner.streams.lock().expect("streams mutex");
                    if let Some(entry) = streams.get_mut(&fields.stream_id) {
                        // Section 7.5: the granted limit never goes backwards,
                        // so a duplicated or late Progress cannot shrink it.
                        entry.send_limit = entry.send_limit.max(fields.limit_offset);
                    }
                }
                let _ = self.inner.events.send(SessionEvent::Progress(fields));
            }
            Resume => {
                let fields = ResumeFields::from_canonical(&record.metadata)?;
                let _ = self.inner.events.send(SessionEvent::Resume(fields));
            }
            CancelCandidate => {
                let fields = CancelCandidateFields::from_canonical(&record.metadata)?;
                let _ = self.inner.events.send(SessionEvent::CancelCandidate(fields));
            }
            Bye => {
                let fields = ByeFields::from_canonical(&record.metadata)?;
                self.set_state(SessionState::Closed);
                let _ = self.inner.events.send(SessionEvent::Bye(fields));
            }
            PeerList => {
                let _ = self
                    .inner
                    .events
                    .send(SessionEvent::PeerList(record.metadata.clone()));
            }
            Auth | AuthOk => {
                // The bootstrap runs before a session engine exists, so seeing
                // one here means the peer is confused about which session it is
                // on. Section 5.3 makes that terminal rather than ignorable.
                self.set_state(SessionState::Closed);
                let _ = self.inner.events.send(SessionEvent::Bye(ByeFields {
                    reason: "unexpected bootstrap message".into(),
                }));
            }
        }
        Ok(())
    }

    fn deliver_data(&self, fields: DataFields, payload: Vec<u8>) -> Result<(), SessionError> {
        let delivered = {
            let mut streams = self.inner.streams.lock().expect("streams mutex");
            let entry = streams
                .get_mut(&fields.stream_id)
                .ok_or(SessionError::UnknownStream(fields.stream_id))?;
            let delivered = entry.recv.insert_offsets(fields.offset, &payload)?;
            for (offset, bytes) in &delivered {
                entry.credit.record_received(*offset, bytes.len())?;
            }
            delivered
        };
        for (offset, bytes) in delivered {
            let _ = self.inner.events.send(SessionEvent::Data {
                stream_id: fields.stream_id,
                offset,
                payload: bytes,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsnet_crypto::Psk;
    use wsnet_protocol::PROTOCOL_VERSION;

    fn psk() -> Psk {
        Psk::from_bytes([0x21; 32])
    }

    const AUTH_BYTES: &[u8] = br#"{"attempt_id":"00000000000000000000000000000000","capabilities":["flow.credit"],"hub_id":"hub-a","key_id":"k1","node_id":"client-a","nonce":"0000000000000000000000000000000000000000000000000000000000000000","ts":"1700000000","version":1}"#;
    const AUTHOK_BYTES: &[u8] = br#"{"attempt_id":"00000000000000000000000000000000","capabilities":["flow.credit"],"expires_at":"1700000600","server_nonce":"0000000000000000000000000000000000000000000000000000000000000000","session_epoch":"01010101010101010101010101010101","session_id":"02020202020202020202020202020202"}"#;

    /// Derives a fresh key set; the engine takes ownership, so each end derives
    /// its own copy from the same transcript.
    fn keys() -> SessionKeys {
        SessionKeys::derive(&psk(), AUTH_BYTES, AUTHOK_BYTES)
    }

    fn node_config() -> SessionConfig {
        SessionConfig::new("hub-a", "client-a", [2u8; 16], [1u8; 16], Side::Node)
    }

    fn hub_config() -> SessionConfig {
        SessionConfig::new("hub-a", "client-a", [2u8; 16], [1u8; 16], Side::Hub)
    }

    /// Builds a connected node/Hub pair plus the task moving envelopes between
    /// them. The sessions themselves move into the task so their channels stay
    /// open.
    fn pair() -> (SessionHandle, SessionHandle, tokio::task::JoinHandle<()>) {
        let node = Session::new(node_config(), keys());
        let hub = Session::new(hub_config(), keys());
        let node_handle = node.handle.clone();
        let hub_handle = hub.handle.clone();
        let node_for_task = node_handle.clone();
        let hub_for_task = hub_handle.clone();

        let pump = tokio::spawn(async move {
            let mut node = node;
            let mut hub = hub;
            loop {
                tokio::select! {
                    Some(envelope) = node.outbound.recv() => {
                        let _ = hub_for_task.feed_lossy(&envelope);
                    }
                    Some(envelope) = hub.outbound.recv() => {
                        let _ = node_for_task.feed_lossy(&envelope);
                    }
                    else => break,
                }
            }
        });
        (node_handle, hub_handle, pump)
    }

    /// Waits until `condition` holds, so the tests do not depend on a fixed
    /// sleep being long enough.
    async fn wait_for(mut condition: impl FnMut() -> bool) {
        for _ in 0..200 {
            if condition() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("condition never became true");
    }

    #[tokio::test]
    async fn opening_a_stream_installs_state_on_both_ends() {
        let (node, hub, pump) = pair();
        node.set_state(SessionState::Ready);
        hub.set_state(SessionState::Ready);

        let (stream_id, request_id) = node
            .open(
                Destination::service("client-a", "web"),
                vec![],
                Proto::Tcp,
                [1u8; 16],
            )
            .unwrap();
        assert_eq!(stream_id, 1, "the node side must use odd stream ids");
        assert_eq!(request_id, [1u8; 16]);

        wait_for(|| hub.stream_count() == 1).await;
        assert_eq!(node.stream_count(), 1);
        pump.abort();
    }

    #[tokio::test]
    async fn data_arrives_in_order_with_the_right_offsets() {
        let (node, hub, pump) = pair();
        node.set_state(SessionState::Ready);
        hub.set_state(SessionState::Ready);
        let (stream_id, _) = node
            .open(Destination::address("example.com", 443), vec![], Proto::Tcp, [2u8; 16])
            .unwrap();
        wait_for(|| hub.stream_count() == 1).await;

        assert_eq!(node.send_data(stream_id, b"hello wsnet").unwrap(), 11);
        assert_eq!(node.offsets(stream_id).unwrap().0, 11);

        // The Hub side must observe the bytes at their absolute offsets.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(hub.offsets(stream_id).unwrap().2, 11);
        pump.abort();
    }

    /// Section 4.2: the two directions use different keys, so a record cannot be
    /// reflected back at its sender.
    #[test]
    fn a_record_cannot_be_reflected() {
        let mut session = Session::new(node_config(), keys());
        session.handle.set_state(SessionState::Ready);
        session.handle.send_ping().unwrap();
        let envelope = session.outbound.try_recv().unwrap();
        assert!(
            session.handle.feed(&envelope).is_err(),
            "reflecting a record back must not verify"
        );
        assert!(!session.handle.feed_lossy(&envelope));
    }

    /// Section 4.2: an identical envelope delivered twice is dropped.
    #[test]
    fn a_replayed_envelope_is_refused() {
        // Built by hand rather than through `pair`, because the point is to
        // deliver the *same* envelope twice.
        let mut node_session = Session::new(node_config(), keys());
        let hub_session = Session::new(hub_config(), keys());
        let node = node_session.handle.clone();
        let hub = hub_session.handle;

        node.set_state(SessionState::Ready);
        node.send_ping().unwrap();
        let envelope = node_session.outbound.try_recv().unwrap();

        assert!(hub.feed_lossy(&envelope), "the first delivery must verify");
        assert!(
            matches!(
                hub.feed(&envelope),
                Err(SessionError::Replay(ReplayError::Duplicate(_)))
            ),
            "the same envelope must not be accepted twice"
        );
    }

    /// Section 5.3: an `Open` before `HelloOk` is refused.
    #[tokio::test]
    async fn open_before_hello_ok_is_refused() {
        let (node, hub, pump) = pair();
        hub.set_state(SessionState::HelloPending);
        node.set_state(SessionState::Ready);
        node.open(
            Destination::address("example.com", 443),
            vec![],
            Proto::Tcp,
            [4u8; 16],
        )
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // The Hub must not have installed a stream for it.
        assert_eq!(hub.stream_count(), 0);
        pump.abort();
    }

    /// Section 7.5: sending past the granted credit is refused, and the refusal
    /// must not advance the offset.
    #[tokio::test]
    async fn sending_past_the_credit_limit_is_refused() {
        let (node, _hub, pump) = pair();
        node.set_state(SessionState::Ready);
        let (stream_id, _) = node
            .open(Destination::address("example.com", 443), vec![], Proto::Tcp, [5u8; 16])
            .unwrap();
        let (_, limit, _) = node.offsets(stream_id).unwrap();
        let too_much = vec![0u8; (limit + 1) as usize];
        assert!(matches!(
            node.send_data(stream_id, &too_much),
            Err(SessionError::Stream(StreamError::CreditExceeded { .. }))
        ));
        assert_eq!(node.offsets(stream_id).unwrap().0, 0);
        pump.abort();
    }

    #[tokio::test]
    async fn a_full_window_is_accepted_and_then_closed() {
        let (node, _hub, pump) = pair();
        node.set_state(SessionState::Ready);
        let (stream_id, _) = node
            .open(Destination::address("example.com", 443), vec![], Proto::Tcp, [6u8; 16])
            .unwrap();
        let (_, limit, _) = node.offsets(stream_id).unwrap();
        let payload = vec![0xABu8; limit as usize];
        assert_eq!(node.send_data(stream_id, &payload).unwrap() as u64, limit);
        assert_eq!(node.offsets(stream_id).unwrap().0, limit);
        assert!(node.send_data(stream_id, b"x").is_err());
        pump.abort();
    }

    /// Section 7.5: consuming bytes is what earns the peer new credit.
    #[tokio::test]
    async fn consumption_grants_new_credit() {
        let (node, hub, pump) = pair();
        node.set_state(SessionState::Ready);
        hub.set_state(SessionState::Ready);
        let (stream_id, _) = node
            .open(Destination::address("example.com", 443), vec![], Proto::Tcp, [7u8; 16])
            .unwrap();
        wait_for(|| hub.stream_count() == 1).await;

        node.send_data(stream_id, b"0123456789").unwrap();
        wait_for(|| hub.offsets(stream_id).map(|o| o.2) == Some(10)).await;

        // Nothing consumed yet: no new credit may be granted.
        assert!(hub.consume(stream_id, 0).unwrap().is_none());
        // Consuming grants exactly what was consumed.
        let progress = hub.consume(stream_id, 10).unwrap().unwrap();
        assert_eq!(progress.consumed_offset, 10);
        assert_eq!(progress.limit_offset, STREAM_INITIAL_CREDIT + 10);

        // The node must see the raised limit.
        wait_for(|| node.offsets(stream_id).map(|o| o.1) == Some(STREAM_INITIAL_CREDIT + 10)).await;
        pump.abort();
    }

    /// Section 4.2: ids are split by parity and never reused.
    #[tokio::test]
    async fn stream_ids_follow_parity() {
        assert_eq!(Side::Node.first_stream_id(), 1);
        assert_eq!(Side::Hub.first_stream_id(), 2);
        assert_eq!(Side::Node.first_stream_id() % 2, 1);
        assert_eq!(Side::Hub.first_stream_id() % 2, 0);

        let (node, hub, pump) = pair();
        let (first, _) = node
            .open(Destination::address("a", 1), vec![], Proto::Tcp, [1u8; 16])
            .unwrap();
        let (second, _) = node
            .open(Destination::address("a", 1), vec![], Proto::Tcp, [2u8; 16])
            .unwrap();
        assert_eq!((first, second), (1, 3));
        let (hub_first, _) = hub
            .open(Destination::address("a", 1), vec![], Proto::Tcp, [3u8; 16])
            .unwrap();
        assert_eq!(hub_first, 2);
        pump.abort();
    }

    /// Section 4.2: `packet_no` starts at 0 and increments once per record.
    #[test]
    fn packet_numbers_start_at_zero_and_increment() {
        let mut session = Session::new(node_config(), keys());
        assert_eq!(session.handle.next_packet_no(), Some(0));
        session.handle.send_ping().unwrap();
        assert_eq!(session.handle.next_packet_no(), Some(1));
        session.handle.send_pong().unwrap();
        assert_eq!(session.handle.next_packet_no(), Some(2));
        let _ = session.outbound.try_recv();
    }

    /// The session cap is enforced rather than growing without bound.
    #[test]
    fn the_stream_cap_is_enforced() {
        let config = SessionConfig {
            max_streams: 2,
            ..node_config()
        };
        let session = Session::new(config, keys());
        let node = session.handle;
        node.set_state(SessionState::Ready);
        assert!(node
            .open(Destination::address("a", 1), vec![], Proto::Tcp, [1u8; 16])
            .is_ok());
        assert!(node
            .open(Destination::address("a", 1), vec![], Proto::Tcp, [2u8; 16])
            .is_ok());
        assert!(matches!(
            node.open(Destination::address("a", 1), vec![], Proto::Tcp, [3u8; 16]),
            Err(SessionError::TooManyStreams(2))
        ));
    }

    #[test]
    fn hello_ok_lifts_the_business_barrier() {
        let session = Session::new(node_config(), keys());
        let node = session.handle;
        assert!(!node.is_ready());
        node.send_hello_ok(&HelloOkFields {
            request_id: [1u8; 16],
            capabilities: vec!["flow.credit".into()],
        })
        .unwrap();
        assert!(node.is_ready());
    }

    #[tokio::test]
    async fn fin_reports_the_final_offset() {
        let (node, _hub, pump) = pair();
        node.set_state(SessionState::Ready);
        let (stream_id, _) = node
            .open(Destination::address("a", 1), vec![], Proto::Tcp, [1u8; 16])
            .unwrap();
        node.send_data(stream_id, b"12345").unwrap();
        assert_eq!(node.send_fin(stream_id).unwrap(), 5);
        // Fin is idempotent and keeps reporting the same offset.
        assert_eq!(node.send_fin(stream_id).unwrap(), 5);
        pump.abort();
    }

    #[test]
    fn the_protocol_version_is_the_shared_constant() {
        assert_eq!(PROTOCOL_VERSION, wsnet_limits::PROTOCOL_VERSION);
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
