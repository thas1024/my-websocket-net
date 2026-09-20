//! UDP Local Forward: the listener side and its association bookkeeping.
//!
//! USAGE.md section 9 fixes what is different from SOCKS5 UDP ASSOCIATE: a Local
//! Forward targets one fixed remote service, while an ASSOCIATE datagram carries
//! its own target. What is the same is DESIGN.md section 7.4's source validation,
//! TTL, bounded queue, datagram identity, and per-association isolation, so this
//! module reuses the same budgets from `wsnet-limits` rather than inventing new
//! ones.
//!
//! The bookkeeping (one bounded association per local source tuple) is separated
//! from the transport: [`UdpAssociationTable`] is a plain, deterministic
//! structure whose clock is injected, and [`UdpForwardOpener`] is the seam that
//! turns one source tuple into a remote session.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Notify};
use tracing::{debug, warn};

use wsnet_limits::{
    MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION, MAX_QUEUED_DATAGRAM_BYTES, MAX_UDP_ASSOCIATIONS,
    OPERATION_OPEN_TIMEOUT_SECS, UDP_ASSOCIATION_IDLE_SECS, UDP_MAX_PAYLOAD_DEFAULT,
    UDP_QUEUE_TTL_DEFAULT_MS,
};
use wsnet_routing::Destination;

use crate::{lock, BoxFuture, ForwardError};

/// How often the receive loop sweeps expired datagrams and idle associations.
///
/// The shortest configurable queue TTL is 100 ms (UDP_QUEUE_TTL_MIN_MS in
/// `wsnet-limits`), so a 50 ms sweep bounds how long an expired datagram can
/// still occupy its association's memory.
const SWEEP_INTERVAL_MS: u64 = 50;

/// The bounds applied to one UDP Local Forward listener (DESIGN.md section 7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpLimits {
    /// Maximum concurrently tracked source tuples.
    pub max_associations: usize,
    /// Maximum queued datagrams per association.
    pub max_queued_datagrams: usize,
    /// Maximum queued bytes per association.
    pub max_queued_bytes: usize,
    /// How long a queued datagram stays valid before it is dropped.
    pub queue_ttl: Duration,
    /// How long an association may stay idle before it is reclaimed.
    pub association_idle: Duration,
}

impl Default for UdpLimits {
    fn default() -> Self {
        UdpLimits {
            max_associations: MAX_UDP_ASSOCIATIONS,
            max_queued_datagrams: MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION,
            max_queued_bytes: MAX_QUEUED_DATAGRAM_BYTES,
            queue_ttl: Duration::from_millis(UDP_QUEUE_TTL_DEFAULT_MS),
            association_idle: Duration::from_secs(UDP_ASSOCIATION_IDLE_SECS),
        }
    }
}

/// What the table did with one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDisposition {
    /// The datagram is queued for its association.
    Queued,
    /// The association limit is reached and no idle association could be
    /// reclaimed, so the datagram was dropped and counted.
    AssociationLimit,
    /// The association's bounded queue is full, so the datagram was dropped and
    /// counted. Queued datagrams keep their order; the arriving one is dropped.
    QueueFull,
    /// The payload is over the accepted UDP payload bound, so it was dropped.
    PayloadTooLarge,
}

/// The result of one sweep.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UdpSweep {
    /// Queued datagrams dropped because their queue TTL had passed.
    pub expired: u64,
    /// Associations reclaimed because they were idle past the idle limit.
    pub reclaimed: Vec<SocketAddr>,
}

/// A read-only snapshot of one association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpAssociationStats {
    /// Datagrams currently queued.
    pub queued: usize,
    /// Bytes currently queued.
    pub queued_bytes: usize,
    /// Datagrams dropped for this association so far.
    pub dropped: u64,
    /// Datagrams dropped for this association after their TTL had passed.
    pub expired: u64,
    /// Time since the last datagram from this source tuple.
    pub idle: Duration,
}

/// One datagram and the monotonic time it was queued.
#[derive(Debug, Clone)]
struct QueuedDatagram {
    payload: Vec<u8>,
    queued_at: Instant,
}

/// The bounded state of one source tuple.
#[derive(Debug)]
struct Association {
    last_seen: Instant,
    queue: VecDeque<QueuedDatagram>,
    queued_bytes: usize,
    dropped: u64,
    expired: u64,
}

impl Association {
    fn new(now: Instant) -> Self {
        Association {
            last_seen: now,
            queue: VecDeque::new(),
            queued_bytes: 0,
            dropped: 0,
            expired: 0,
        }
    }
}

/// One bounded association per local source tuple (USAGE.md section 9).
///
/// Every method takes the current monotonic time from the caller, which keeps TTL
/// and idle behaviour deterministic in tests without sleeping and matches
/// DESIGN.md section 7.4's rule that TTL accounting uses a monotonic clock rather
/// than the wall clock.
#[derive(Debug)]
pub struct UdpAssociationTable {
    limits: UdpLimits,
    associations: HashMap<SocketAddr, Association>,
    dropped_over_limit: u64,
}

impl UdpAssociationTable {
    /// Creates an empty table with the given bounds.
    pub fn new(limits: UdpLimits) -> Self {
        UdpAssociationTable {
            limits,
            associations: HashMap::new(),
            dropped_over_limit: 0,
        }
    }

    /// The configured bounds.
    pub fn limits(&self) -> UdpLimits {
        self.limits
    }

    /// How many source tuples are tracked.
    pub fn len(&self) -> usize {
        self.associations.len()
    }

    /// Whether no source tuple is tracked.
    pub fn is_empty(&self) -> bool {
        self.associations.is_empty()
    }

    /// How many datagrams were dropped because the association limit was reached.
    pub fn dropped_over_limit(&self) -> u64 {
        self.dropped_over_limit
    }

    /// The tracked source tuples, in unspecified order.
    pub fn sources(&self) -> Vec<SocketAddr> {
        self.associations.keys().copied().collect()
    }

    /// Whether `source` currently has an association.
    pub fn contains(&self, source: SocketAddr) -> bool {
        self.associations.contains_key(&source)
    }

    /// Queues one datagram for `source`, creating its association if needed.
    pub fn enqueue(&mut self, source: SocketAddr, payload: Vec<u8>, now: Instant) -> UdpDisposition {
        if payload.len() > UDP_MAX_PAYLOAD_DEFAULT {
            return UdpDisposition::PayloadTooLarge;
        }
        if !self.associations.contains_key(&source)
            && self.associations.len() >= self.limits.max_associations
        {
            // Capacity pressure reclaims idle associations first, mirroring the
            // rule that full tables must not evict still-valid state.
            self.reclaim_idle(now);
            if self.associations.len() >= self.limits.max_associations {
                self.dropped_over_limit += 1;
                return UdpDisposition::AssociationLimit;
            }
        }

        let limits = self.limits;
        let association = self
            .associations
            .entry(source)
            .or_insert_with(|| Association::new(now));
        association.last_seen = now;
        if association.queue.len() >= limits.max_queued_datagrams
            || association.queued_bytes + payload.len() > limits.max_queued_bytes
        {
            association.dropped += 1;
            return UdpDisposition::QueueFull;
        }
        association.queued_bytes += payload.len();
        association.queue.push_back(QueuedDatagram {
            payload,
            queued_at: now,
        });
        UdpDisposition::Queued
    }

    /// Pops the oldest still-valid datagram for `source`.
    ///
    /// Expired datagrams are dropped and counted on the way, so a stalled
    /// association can never deliver a datagram past its TTL and a full queue can
    /// always make progress.
    pub fn pop_ready(&mut self, source: SocketAddr, now: Instant) -> Option<Vec<u8>> {
        let limits = self.limits;
        let association = self.associations.get_mut(&source)?;
        association.last_seen = now;
        while let Some(front) = association.queue.front() {
            let expired = now.duration_since(front.queued_at) > limits.queue_ttl;
            let front = association.queue.pop_front().expect("front is present");
            association.queued_bytes = association.queued_bytes.saturating_sub(front.payload.len());
            if expired {
                association.expired += 1;
                continue;
            }
            return Some(front.payload);
        }
        None
    }

    /// Drops expired datagrams everywhere and reclaims associations that have been
    /// idle past the idle limit (DESIGN.md section 7.4).
    pub fn sweep(&mut self, now: Instant) -> UdpSweep {
        let limits = self.limits;
        let mut expired = 0;
        for association in self.associations.values_mut() {
            let before = association.queue.len();
            association.queue.retain(|datagram| {
                now.duration_since(datagram.queued_at) <= limits.queue_ttl
            });
            let dropped = before - association.queue.len();
            if dropped > 0 {
                association.expired += dropped as u64;
                let retained: usize = association.queue.iter().map(|d| d.payload.len()).sum();
                association.queued_bytes = retained;
                expired += dropped as u64;
            }
        }
        let reclaimed = self.reclaim_idle(now);
        UdpSweep { expired, reclaimed }
    }

    /// Removes and returns the source tuples that have been idle too long.
    fn reclaim_idle(&mut self, now: Instant) -> Vec<SocketAddr> {
        let idle_limit = self.limits.association_idle;
        let stale: Vec<SocketAddr> = self
            .associations
            .iter()
            .filter(|(_, association)| now.duration_since(association.last_seen) > idle_limit)
            .map(|(source, _)| *source)
            .collect();
        for source in &stale {
            self.associations.remove(source);
        }
        stale
    }

    /// Forgets one association, as an association task does when its session ends.
    pub fn forget(&mut self, source: SocketAddr) {
        self.associations.remove(&source);
    }

    /// A snapshot of one association, or `None` when the tuple is not tracked.
    pub fn stats(&self, source: SocketAddr, now: Instant) -> Option<UdpAssociationStats> {
        self.associations.get(&source).map(|association| {
            UdpAssociationStats {
                queued: association.queue.len(),
                queued_bytes: association.queued_bytes,
                dropped: association.dropped,
                expired: association.expired,
                idle: now.duration_since(association.last_seen),
            }
        })
    }
}

/// The remote half of one UDP association.
///
/// The two halves are deliberately directional: a Local Forward has one fixed
/// target per association, so the opener never has to carry a per-datagram
/// destination the way SOCKS5 UDP ASSOCIATE does (USAGE.md section 9).
pub struct UdpSession {
    /// Datagrams the listener wants sent to the fixed remote target.
    pub to_remote: mpsc::Sender<Vec<u8>>,
    /// Datagrams the fixed remote target sent back.
    pub from_remote: mpsc::Receiver<Vec<u8>>,
}

impl std::fmt::Debug for UdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSession").finish_non_exhaustive()
    }
}

/// Opens the remote half of a UDP association.
///
/// This is separate from [`crate::ForwardOpener`] because a datagram flow has no
/// byte stream: what the listener needs back is a datagram channel pair, not a
/// duplex byte stream.
pub trait UdpForwardOpener: Send + Sync + 'static {
    /// Opens one remote association for the local `source` tuple.
    ///
    /// `source` travels with the request so the remote side can apply the same
    /// per-source isolation and cleanup rules as the local listener
    /// (DESIGN.md section 7.4).
    fn open_udp(
        &self,
        destination: Destination,
        via: Vec<String>,
        source: SocketAddr,
    ) -> BoxFuture<'static, Result<UdpSession, ForwardError>>;
}

/// One UDP Local Forward listener: a bound socket plus its associations.
///
/// The socket is kept in its standard-library form until [`UdpForwardListener::run`]
/// so that a forward can be added, and rejected, outside a Tokio runtime.
pub struct UdpForwardListener {
    socket: Mutex<Option<std::net::UdpSocket>>,
    addr: SocketAddr,
    opener: Arc<dyn UdpForwardOpener>,
    destination: Destination,
    via: Vec<String>,
    limits: UdpLimits,
    table: Mutex<UdpAssociationTable>,
    /// One wake handle per live tuple.
    ///
    /// A `Notify` per association is what makes a queued datagram impossible to
    /// lose: the receive loop stores a permit instead of racing a shared signal.
    wakes: Mutex<HashMap<SocketAddr, Arc<Notify>>>,
    accepting: watch::Sender<bool>,
}

impl UdpForwardListener {
    /// Takes ownership of a bound, non-blocking UDP socket.
    pub fn new(
        socket: std::net::UdpSocket,
        opener: Arc<dyn UdpForwardOpener>,
        destination: Destination,
        via: Vec<String>,
        limits: UdpLimits,
    ) -> io::Result<Self> {
        let addr = socket.local_addr()?;
        socket.set_nonblocking(true)?;
        let (accepting, _) = watch::channel(true);
        Ok(UdpForwardListener {
            socket: Mutex::new(Some(socket)),
            addr,
            opener,
            destination,
            via,
            limits,
            table: Mutex::new(UdpAssociationTable::new(limits)),
            wakes: Mutex::new(HashMap::new()),
            accepting,
        })
    }

    /// The address the listener holds, including an OS-assigned port.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The configured association bounds.
    pub fn limits(&self) -> UdpLimits {
        self.limits
    }

    /// How many source tuples currently have an association.
    pub fn associations(&self) -> usize {
        lock(&self.table).len()
    }

    /// Stops or resumes accepting datagrams.
    ///
    /// The manager calls this when a forward becomes `OFFLINE`, `DENIED`, or
    /// `ERROR`, so a fast-failed forward drops datagrams instead of forwarding
    /// them through a path the node knows is not usable (USAGE.md section 7).
    pub fn set_accepting(&self, accepting: bool) {
        self.accepting.send_replace(accepting);
    }

    /// Whether datagrams are currently accepted.
    pub fn is_accepting(&self) -> bool {
        *self.accepting.borrow()
    }

    /// Receives datagrams until `shutdown` is true.
    pub async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let std_socket = lock(&self.socket).take();
        let Some(std_socket) = std_socket else {
            debug!("udp listener already started");
            return;
        };
        let socket = match UdpSocket::from_std(std_socket) {
            Ok(socket) => Arc::new(socket),
            Err(error) => {
                warn!(%error, "udp listener could not be registered");
                return;
            }
        };
        let mut accepting = self.accepting.subscribe();
        let mut buffer = vec![0_u8; UDP_MAX_PAYLOAD_DEFAULT];
        let mut sweep = tokio::time::interval(Duration::from_millis(SWEEP_INTERVAL_MS));

        loop {
            if *shutdown.borrow_and_update() {
                break;
            }
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                received = socket.recv_from(&mut buffer) => match received {
                    Ok((len, source)) => {
                        if !*accepting.borrow_and_update() {
                            continue;
                        }
                        self.ingest(Arc::clone(&socket), source, buffer[..len].to_vec(), &shutdown);
                    }
                    Err(error) => {
                        debug!(%error, "udp receive failed");
                    }
                },
                _ = sweep.tick() => self.reclaim(),
            }
        }
        debug!(addr = %self.addr, "udp listener stopped");
    }

    /// Queues one datagram and makes sure its association has a task.
    fn ingest(
        self: &Arc<Self>,
        socket: Arc<UdpSocket>,
        source: SocketAddr,
        payload: Vec<u8>,
        shutdown: &watch::Receiver<bool>,
    ) {
        let existing = lock(&self.wakes).get(&source).cloned();
        if let Some(wake) = existing {
            lock(&self.table).enqueue(source, payload, Instant::now());
            wake.notify_one();
            return;
        }

        let disposition = lock(&self.table).enqueue(source, payload, Instant::now());
        if disposition != UdpDisposition::Queued {
            debug!(peer = %source, ?disposition, "udp datagram dropped");
            return;
        }
        let wake = Arc::new(Notify::new());
        lock(&self.wakes).insert(source, Arc::clone(&wake));
        let listener = Arc::clone(self);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            run_association(listener, socket, wake, source, shutdown).await;
        });
    }

    /// Sweeps the table and wakes any association task whose tuple was reclaimed.
    fn reclaim(&self) {
        let swept = lock(&self.table).sweep(Instant::now());
        if swept.expired > 0 {
            debug!(expired = swept.expired, "udp datagrams expired in the queue");
        }
        for source in swept.reclaimed {
            let wake = lock(&self.wakes).remove(&source);
            if let Some(wake) = wake {
                wake.notify_one();
            }
        }
    }

    /// Whether `wake` is still the handle for `source`.
    ///
    /// This is how an association task notices that its tuple was reclaimed and a
    /// newer association may own it: it must not touch the newer one's queue.
    fn owns(&self, source: SocketAddr, wake: &Arc<Notify>) -> bool {
        lock(&self.wakes)
            .get(&source)
            .is_some_and(|current| Arc::ptr_eq(current, wake))
    }

    /// Releases one association's bookkeeping when its task ends.
    fn finish(&self, source: SocketAddr, wake: &Arc<Notify>) {
        let removed = {
            let mut wakes = lock(&self.wakes);
            if wakes.get(&source).is_some_and(|current| Arc::ptr_eq(current, wake)) {
                wakes.remove(&source);
                true
            } else {
                false
            }
        };
        if removed {
            lock(&self.table).forget(source);
        }
    }
}

impl std::fmt::Debug for UdpForwardListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpForwardListener")
            .field("addr", &self.addr)
            .field("destination", &self.destination)
            .field("associations", &self.associations())
            .finish_non_exhaustive()
    }
}

/// Opens one association, then pumps datagrams in both directions.
///
/// The task is the only writer to its [`UdpSession`], and it owns the drain of its
/// own queue, which is what keeps one slow association from stalling the others.
async fn run_association(
    listener: Arc<UdpForwardListener>,
    socket: Arc<UdpSocket>,
    wake: Arc<Notify>,
    source: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) {
    let attempt = listener.opener.open_udp(
        listener.destination.clone(),
        listener.via.clone(),
        source,
    );
    let opened = tokio::time::timeout(Duration::from_secs(OPERATION_OPEN_TIMEOUT_SECS), attempt).await;
    let mut session = match opened {
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            warn!(peer = %source, %error, "udp association open failed");
            listener.finish(source, &wake);
            return;
        }
        Err(_elapsed) => {
            warn!(peer = %source, "udp association open timed out");
            listener.finish(source, &wake);
            return;
        }
    };

    loop {
        if !listener.owns(source, &wake) || *shutdown.borrow_and_update() {
            break;
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            received = session.from_remote.recv() => match received {
                Some(datagram) => {
                    if let Err(error) = socket.send_to(&datagram, source).await {
                        debug!(peer = %source, %error, "udp response could not be delivered");
                        break;
                    }
                }
                None => break,
            },
            () = wake.notified() => {}
        }

        loop {
            let next = lock(&listener.table).pop_ready(source, Instant::now());
            let Some(payload) = next else { break };
            if session.to_remote.send(payload).await.is_err() {
                listener.finish(source, &wake);
                return;
            }
        }
    }
    listener.finish(source, &wake);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_associations: usize, queued: usize, bytes: usize) -> UdpLimits {
        UdpLimits {
            max_associations,
            max_queued_datagrams: queued,
            max_queued_bytes: bytes,
            queue_ttl: Duration::from_millis(100),
            association_idle: Duration::from_secs(60),
        }
    }

    fn source(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// USAGE.md section 9: each local source tuple is a separate association, so
    /// one tuple can never observe another's queued datagrams.
    #[test]
    fn associations_are_isolated_by_source_tuple() {
        let mut table = UdpAssociationTable::new(limits(4, 4, 4096));
        let now = Instant::now();
        assert_eq!(
            table.enqueue(source(1), b"one".to_vec(), now),
            UdpDisposition::Queued
        );
        assert_eq!(
            table.enqueue(source(2), b"two".to_vec(), now),
            UdpDisposition::Queued
        );

        assert_eq!(table.pop_ready(source(1), now), Some(b"one".to_vec()));
        assert_eq!(table.pop_ready(source(1), now), None);
        assert_eq!(table.pop_ready(source(2), now), Some(b"two".to_vec()));
        assert_eq!(table.len(), 2);
    }

    /// DESIGN.md section 7.4: the queued-datagram count is bounded, and drops are
    /// counted rather than silently discarded.
    #[test]
    fn queue_count_limit_drops_and_counts() {
        let mut table = UdpAssociationTable::new(limits(4, 3, 4096));
        let now = Instant::now();
        for i in 0..6_u8 {
            table.enqueue(source(7), vec![i], now);
        }
        let stats = table.stats(source(7), now).expect("association exists");
        assert_eq!(stats.queued, 3);
        assert_eq!(stats.dropped, 3);
        // The datagrams that were queued first are the ones that survive.
        assert_eq!(table.pop_ready(source(7), now), Some(vec![0]));
        assert_eq!(table.pop_ready(source(7), now), Some(vec![1]));
        assert_eq!(table.pop_ready(source(7), now), Some(vec![2]));
    }

    /// DESIGN.md section 7.4: the queued-byte cap binds independently of the count.
    #[test]
    fn queue_byte_limit_drops_and_counts() {
        // A 100-byte budget with 40-byte datagrams holds exactly two, even
        // though the *count* limit is 64. That is the point of having both caps.
        let mut table = UdpAssociationTable::new(limits(4, 64, 100));
        let now = Instant::now();
        for _ in 0..2 {
            assert_eq!(
                table.enqueue(source(8), vec![0_u8; 40], now),
                UdpDisposition::Queued
            );
        }
        for _ in 0..3 {
            assert_eq!(
                table.enqueue(source(8), vec![0_u8; 40], now),
                UdpDisposition::QueueFull
            );
        }
        let stats = table.stats(source(8), now).expect("association exists");
        assert_eq!(stats.queued, 2);
        assert_eq!(stats.queued_bytes, 80);
        assert_eq!(stats.dropped, 3);
    }

    /// DESIGN.md section 7.4: queued datagrams have a TTL and are dropped once it
    /// passes, counted as expired instead of being delivered late.
    #[test]
    fn queued_datagrams_expire_after_the_ttl() {
        let mut table = UdpAssociationTable::new(limits(4, 4, 4096));
        let now = Instant::now();
        table.enqueue(source(9), b"late".to_vec(), now);

        let after = now + Duration::from_millis(150);
        assert_eq!(table.pop_ready(source(9), after), None);
        let stats = table.stats(source(9), after).expect("association exists");
        assert_eq!(stats.queued, 0);
        assert_eq!(stats.queued_bytes, 0);
        assert_eq!(stats.expired, 1);

        // A datagram still inside its TTL is delivered.
        table.enqueue(source(9), b"fresh".to_vec(), after);
        assert_eq!(
            table.pop_ready(source(9), after + Duration::from_millis(50)),
            Some(b"fresh".to_vec())
        );
    }

    /// USAGE.md section 9 and DESIGN.md section 7.4: the association count is
    /// bounded, and capacity pressure reclaims idle tuples before dropping a live
    /// one.
    #[test]
    fn association_limit_is_enforced_and_idle_tuples_are_reclaimed() {
        let mut table = UdpAssociationTable::new(limits(2, 4, 4096));
        let now = Instant::now();
        assert_eq!(
            table.enqueue(source(1), b"a".to_vec(), now),
            UdpDisposition::Queued
        );
        assert_eq!(
            table.enqueue(source(2), b"b".to_vec(), now),
            UdpDisposition::Queued
        );
        assert_eq!(
            table.enqueue(source(3), b"c".to_vec(), now),
            UdpDisposition::AssociationLimit
        );
        assert_eq!(table.len(), 2);
        assert_eq!(table.dropped_over_limit(), 1);

        // Past the idle limit the two old tuples are reclaimed, so a new tuple is
        // admitted without evicting anything still valid.
        let later = now + Duration::from_secs(61);
        assert_eq!(
            table.enqueue(source(3), b"c".to_vec(), later),
            UdpDisposition::Queued
        );
        assert_eq!(table.sources(), vec![source(3)]);
    }

    /// DESIGN.md section 7.4: an over-large payload is dropped, never split into a
    /// pseudo stream.
    #[test]
    fn oversized_datagrams_are_dropped() {
        let mut table = UdpAssociationTable::new(UdpLimits::default());
        let now = Instant::now();
        let big = vec![0_u8; UDP_MAX_PAYLOAD_DEFAULT + 1];
        assert_eq!(
            table.enqueue(source(4), big, now),
            UdpDisposition::PayloadTooLarge
        );
        assert!(table.is_empty());
    }

    /// A sweep reports both expiries and reclaimed idle tuples.
    #[test]
    fn sweep_reports_expiry_and_reclamation() {
        let mut table = UdpAssociationTable::new(limits(4, 4, 4096));
        let now = Instant::now();
        table.enqueue(source(1), b"x".to_vec(), now);
        table.enqueue(source(2), b"y".to_vec(), now);

        let mid = now + Duration::from_millis(150);
        let swept = table.sweep(mid);
        assert_eq!(swept.expired, 2);
        assert!(swept.reclaimed.is_empty());
        assert_eq!(table.len(), 2);

        let later = mid + Duration::from_secs(61);
        let swept = table.sweep(later);
        assert_eq!(swept.expired, 0);
        assert_eq!(swept.reclaimed.len(), 2);
        assert!(table.is_empty());
    }

    /// `forget` is the association task's cleanup and must not disturb others.
    #[test]
    fn forgetting_one_tuple_leaves_the_others() {
        let mut table = UdpAssociationTable::new(limits(4, 4, 4096));
        let now = Instant::now();
        table.enqueue(source(1), b"a".to_vec(), now);
        table.enqueue(source(2), b"b".to_vec(), now);
        table.forget(source(1));
        assert!(!table.contains(source(1)));
        assert!(table.contains(source(2)));
        assert_eq!(table.pop_ready(source(2), now), Some(b"b".to_vec()));
    }

}
