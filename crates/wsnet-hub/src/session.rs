//! One Hub-side session: the engine plus the downlink fan-out (DESIGN.md sections 4.4, 6.3).
//!
//! A carrier never owns session state. `POST /m`, `GET /e`, and `GET /w` all feed
//! *sealed envelopes* into the same [`SessionHandle`] and read replies from the
//! same downlink channel, which is what lets section 6.3's rule that a stream id
//! survives a carrier switch hold: the engine's `packet_no` counters, replay
//! window, and stream table are per session, not per connection.
//!
//! Everything the engine produces is pushed to a [`tokio::sync::broadcast`]
//! channel instead of a single queue. The reason is section 4.4 and section 6.2
//! together: several carriers may be active at once (a POST response, an SSE
//! subscription, a WebSocket), and any of them may carry the next downlink record.
//! A fan-out channel gives each carrier its own cursor, so a record delivered on
//! one carrier is not *lost* for the others; delivery is not confirmation anyway
//! (section 7.3), and the receiver's replay window (section 4.2) drops duplicates.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, mpsc};
use wsnet_crypto::SessionKeys;
use wsnet_session::{SessionEvent, SessionHandle, SessionState};

/// Capacity of one session's downlink fan-out.
///
/// Section 4.2's scheduler bound is 4_096 in-flight sealed records; a carrier that
/// falls further behind than this is dropped from the fan-out (see `Lagged`), and
/// section 7.3's recovery is what is supposed to notice, not a shared queue that
/// silently grows.
pub(crate) const DOWNLINK_CAPACITY: usize = 256;

/// A Hub-side session.
pub(crate) struct SessionEntry {
    /// Routing label, never a bearer credential.
    pub(crate) session_id: [u8; 16],
    /// Key epoch the session authenticated with.
    pub(crate) epoch: [u8; 16],
    /// Node that owns the session.
    pub(crate) node_id: String,
    /// Key generation the node presented.
    pub(crate) key_id: String,
    /// Absolute session expiry, UTC Unix seconds.
    pub(crate) expires_at: i64,
    /// The three derived keys; shared so carriers can verify binding proofs.
    pub(crate) keys: Arc<SessionKeys>,
    /// The engine.
    pub(crate) handle: SessionHandle,
    /// Downlink fan-out for every bound carrier.
    pub(crate) downlink: broadcast::Sender<Vec<u8>>,
    /// Set once the session has been torn down.
    pub(crate) closed: AtomicBool,
    pump: Mutex<Pump>,
}

struct Pump {
    events: mpsc::UnboundedReceiver<SessionEvent>,
    outbound: mpsc::UnboundedReceiver<Vec<u8>>,
    /// One event sink per live stream task, keyed by stream id.
    ///
    /// Section 7.1 gives every leg of a stream its own local mapping, so the
    /// engine's events have to reach the task that owns the target socket rather
    /// than the session's business logic. Section 8 is why this table exists at
    /// all: an unknown stream is refused, so the table is also the authority on
    /// which stream ids are live.
    streams: HashMap<u64, mpsc::UnboundedSender<SessionEvent>>,
    /// Generation counter for SSE ownership.
    next_sse_generation: u64,
    /// The generation that currently owns the single SSE subscription (4.4).
    sse_owner: Option<u64>,
}

impl SessionEntry {
    /// Wraps the parts of a freshly authenticated session.
    pub(crate) fn new(
        session_id: [u8; 16],
        epoch: [u8; 16],
        node_id: String,
        key_id: String,
        expires_at: i64,
        keys: Arc<SessionKeys>,
        session: wsnet_session::Session,
    ) -> Self {
        let (downlink, _) = broadcast::channel(DOWNLINK_CAPACITY);
        SessionEntry {
            session_id,
            epoch,
            node_id,
            key_id,
            expires_at,
            keys,
            handle: session.handle,
            downlink,
            closed: AtomicBool::new(false),
            pump: Mutex::new(Pump {
                events: session.events,
                outbound: session.outbound,
                streams: HashMap::new(),
                next_sse_generation: 0,
                sse_owner: None,
            }),
        }
    }

    /// Whether the session has been torn down.
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Takes ownership of the single SSE subscription (section 4.4).
    ///
    /// Section 4.4 requires that replacing a subscription switches the owner
    /// atomically before the old subscription is closed, so a stale stream cannot
    /// clear the new owner. Handing out a fresh generation and storing
    /// it atomically is exactly that: the previous stream notices that its own
    /// generation is no longer current and ends, while the new one is already the
    /// owner.
    pub(crate) fn claim_sse_owner(&self) -> u64 {
        let mut pump = self.pump.lock().expect("pump mutex");
        pump.next_sse_generation = pump.next_sse_generation.wrapping_add(1);
        let generation = pump.next_sse_generation;
        pump.sse_owner = Some(generation);
        generation
    }

    /// Whether `generation` still owns the SSE subscription.
    pub(crate) fn owns_sse(&self, generation: u64) -> bool {
        let pump = self.pump.lock().expect("pump mutex");
        pump.sse_owner == Some(generation)
    }

    /// Claims one stream id for a stream task, and reports whether it was free.
    ///
    /// Section 4.2 forbids reusing a stream id, so a second task for the same id
    /// would be a second dial for one stream; the caller must refuse instead.
    pub(crate) fn claim_stream(&self, stream_id: u64, sink: mpsc::UnboundedSender<SessionEvent>) -> bool {
        let mut pump = self.pump.lock().expect("pump mutex");
        if pump.streams.contains_key(&stream_id) {
            return false;
        }
        pump.streams.insert(stream_id, sink);
        true
    }

    /// Forgets a stream task's sink once the stream is over.
    pub(crate) fn unregister_stream(&self, stream_id: u64) {
        self.pump
            .lock()
            .expect("pump mutex")
            .streams
            .remove(&stream_id);
    }

    /// Hands one engine event to the stream task that owns it.
    ///
    /// `false` means no task owns this stream, which section 8 makes an explicit
    /// refusal rather than something to create on demand.
    pub(crate) fn route_stream_event(&self, stream_id: u64, event: SessionEvent) -> bool {
        let pump = self.pump.lock().expect("pump mutex");
        match pump.streams.get(&stream_id) {
            Some(sink) => sink.send(event).is_ok(),
            None => false,
        }
    }

    /// Drops every stream task's sink, which ends the task and frees its socket.
    ///
    /// Section 5.3 makes an unreachable peer's resources the local side's
    /// problem, so tearing a session down must not leave an egress socket
    /// behind; a task whose sink is gone sees the channel close and returns.
    pub(crate) fn close_streams(&self) {
        self.pump.lock().expect("pump mutex").streams.clear();
    }

    /// Number of live stream tasks, for diagnostics and tests.
    pub(crate) fn live_streams(&self) -> usize {
        self.pump.lock().expect("pump mutex").streams.len()
    }
}

/// What one pump round did, so the caller can pump until quiescent.
pub(crate) struct PumpRound {
    /// Events handed to the caller this round.
    pub(crate) events: Vec<SessionEvent>,
}

impl SessionEntry {
    /// Moves everything the engine has produced so far to the downlink fan-out and
    /// returns the events that need arbitrating.
    pub(crate) fn drain(&self) -> PumpRound {
        let mut pump = self.pump.lock().expect("pump mutex");
        Self::flush_locked(&self.downlink, &mut pump);
        let mut events = Vec::new();
        while let Ok(event) = pump.events.try_recv() {
            events.push(event);
        }
        PumpRound { events }
    }

    /// Moves queued envelopes to the downlink fan-out without touching events.
    ///
    /// A stream task produces work outside the session's carrier loop, so it has
    /// to be able to publish its own records; section 6.2's fan-out is what makes
    /// that safe, because every carrier keeps its own cursor.
    pub(crate) fn flush_outbound(&self) {
        let mut pump = self.pump.lock().expect("pump mutex");
        Self::flush_locked(&self.downlink, &mut pump);
    }

    fn flush_locked(downlink: &broadcast::Sender<Vec<u8>>, pump: &mut Pump) {
        while let Ok(envelope) = pump.outbound.try_recv() {
            // A send error only means no carrier is subscribed just now.
            let _ = downlink.send(envelope);
        }
    }

    /// Whether the engine still needs arbitrating after a drain.
    pub(crate) fn needs_pump(&self) -> bool {
        let pump = self.pump.lock().expect("pump mutex");
        !pump.events.is_empty() || !pump.outbound.is_empty()
    }
}

impl core::fmt::Debug for SessionEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionEntry")
            .field("session_id", &hex::encode(self.session_id))
            .field("node_id", &self.node_id)
            .field("key_id", &self.key_id)
            .field("state", &self.handle.state())
            .field("streams", &self.handle.stream_count())
            .field("closed", &self.is_closed())
            .finish()
    }
}

/// Convenience for the lifecycle state, used in diagnostics.
pub(crate) fn state_name(state: SessionState) -> &'static str {
    match state {
        SessionState::Offline => "offline",
        SessionState::Authenticating => "authenticating",
        SessionState::Binding => "binding",
        SessionState::HelloPending => "hello-pending",
        SessionState::Ready => "ready",
        SessionState::Degraded => "degraded",
        SessionState::Closed => "closed",
    }
}

/// A shared, cloneable handle to a session.
pub(crate) type SharedSession = Arc<SessionEntry>;

/// The session table.
#[derive(Debug, Default)]
pub(crate) struct Sessions {
    entries: Mutex<std::collections::HashMap<[u8; 16], SharedSession>>,
}

impl Sessions {
    /// An empty table.
    pub(crate) fn new() -> Self {
        Sessions::default()
    }

    /// Inserts a session, replacing any earlier entry with the same id.
    pub(crate) fn insert(&self, entry: SharedSession) {
        self.entries
            .lock()
            .expect("session mutex")
            .insert(entry.session_id, entry);
    }

    /// Looks a session up by its routing label.
    pub(crate) fn get(&self, session_id: &[u8; 16]) -> Option<SharedSession> {
        self.entries
            .lock()
            .expect("session mutex")
            .get(session_id)
            .cloned()
    }

    /// Removes a session, but only when the epoch still matches.
    ///
    /// The epoch guard is section 5.5's rule applied to the session table: a late
    /// teardown from an old session must not remove the session that replaced it.
    pub(crate) fn remove_if_epoch(&self, session_id: &[u8; 16], epoch: &[u8; 16]) -> bool {
        let mut entries = self.entries.lock().expect("session mutex");
        match entries.get(session_id) {
            Some(entry) if entry.epoch == *epoch => {
                entries.remove(session_id);
                true
            }
            _ => false,
        }
    }

    /// Number of live sessions.
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().expect("session mutex").len()
    }

    /// Sessions whose absolute expiry has passed.
    pub(crate) fn expired(&self, now_wall_secs: i64) -> Vec<SharedSession> {
        self.entries
            .lock()
            .expect("session mutex")
            .values()
            .filter(|entry| entry.expires_at < now_wall_secs)
            .cloned()
            .collect()
    }
}
