//! UDP ASSOCIATE (section 7.4).
//!
//! The split of responsibility is deliberate. This module owns the SOCKS5 UDP
//! wire semantics that the design pins down (header parsing, source locking, the
//! bounded per-target map and send queue, TTL accounting, header rewriting), and
//! the handler owns the tunnel: it receives already-validated
//! [`UdpDatagram`]s and answers with [`UdpReply`]s. Nothing here resolves a name
//! or dials a target, so the exit node stays the only place with that authority
//! (section 7.1).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep_until, timeout, Instant as TokioInstant};
use tracing::{debug, warn};
use wsnet_limits::{
    MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION, MAX_QUEUED_DATAGRAM_BYTES,
    MAX_UDP_TARGETS_PER_ASSOCIATION,
};

use crate::config::{wildcard_for, IpPrefix, SocksConfig};
use crate::error::SocksError;
use crate::stats::{Counter, Counters, SocksStats};
use crate::wire::{encode_udp_reply, Reply, ReplyCode, SocksTarget, UdpHeader, UDP_HEADER_MAX};
use crate::SocksHandler;

/// How long a handler's `udp_associate` future is given to observe that the
/// association ended before the server drops it.
///
/// This is a join grace, not a protocol budget: every protocol bound below comes
/// from `wsnet-limits`, and this only prevents a handler that ignores closure
/// from pinning the connection task forever after the mapping is already gone.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

/// One client datagram that passed source, header, and payload validation.
#[derive(Debug, Clone)]
pub struct UdpDatagram {
    /// The association this datagram belongs to.
    pub association_id: u64,
    /// Monotonic per-association identifier, used for duplicate suppression and
    /// tracing within one session epoch (section 7.4).
    pub datagram_id: u64,
    /// The destination the client asked for. A domain is resolved by the exit.
    pub target: SocksTarget,
    /// The destination port.
    pub port: u16,
    /// The datagram payload, header stripped.
    pub payload: Vec<u8>,
    /// Monotonic time the datagram was accepted.
    pub received_at: Instant,
    /// Monotonic instant after which this datagram is stale.
    pub deadline: Instant,
}

impl UdpDatagram {
    /// Remaining queue TTL, computed from the monotonic clock so it never
    /// depends on host wall-clock agreement between hops (section 7.4).
    pub fn remaining_ttl(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }

    /// Whether this datagram is past its queue TTL.
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }
}

/// A handler's answer for one mapped target, to be rewritten and sent to the
/// SOCKS5 client.
#[derive(Debug, Clone)]
pub struct UdpReply {
    /// The mapped target this answer belongs to. A reply for an unmapped target
    /// is dropped rather than delivered (section 7.4).
    pub target: SocksTarget,
    /// The target port this answer belongs to.
    pub port: u16,
    /// The address the answer actually came from; it becomes the rewritten
    /// header's source.
    pub source: SocketAddr,
    /// The answer payload.
    pub payload: Vec<u8>,
}

impl UdpReply {
    /// Builds a reply.
    pub fn new(target: SocksTarget, port: u16, source: SocketAddr, payload: Vec<u8>) -> Self {
        Self {
            target,
            port,
            source,
            payload,
        }
    }
}

/// The handler's handle on one UDP association.
///
/// The controlling TCP connection is the association's lifetime (section 7.4):
/// when it ends, [`UdpControl::closed`] resolves, the datagram channel closes,
/// and the local UDP socket is already gone, so a reply can no longer be
/// delivered to anyone.
pub struct UdpControl {
    association_id: u64,
    peer: SocketAddr,
    client_addr: SocketAddr,
    datagrams: mpsc::Receiver<UdpDatagram>,
    replies: mpsc::Sender<UdpReply>,
    closed: watch::Receiver<bool>,
    counters: Arc<Counters>,
}

impl UdpControl {
    /// The association identifier, stable for the life of the mapping.
    pub fn association_id(&self) -> u64 {
        self.association_id
    }

    /// The controlling TCP connection's peer, which is the only source the
    /// association accepts without an allowlist entry (section 7.4).
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The address advertised to the client as `BND.ADDR`/`BND.PORT`: the real
    /// bound UDP socket address, or the configured override with the real port.
    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// The live statistics of the server this association belongs to.
    pub fn stats(&self) -> SocksStats {
        self.counters.snapshot()
    }

    /// Records one event in the shared statistics, for drops the handler itself
    /// decides on.
    pub fn count(&self, counter: Counter) {
        self.counters.inc(counter);
    }

    /// Waits for the next live client datagram.
    ///
    /// Returns `None` once the association has ended. Datagrams that expired in
    /// the queue are dropped and counted instead of being handed over.
    pub async fn recv(&mut self) -> Option<UdpDatagram> {
        loop {
            let datagram = self.datagrams.recv().await?;
            if datagram.is_expired(Instant::now()) {
                self.counters.inc(Counter::UdpTtlExpiredDropped);
                continue;
            }
            return Some(datagram);
        }
    }

    /// Receives without waiting, with the same expiry accounting as `recv`.
    pub fn try_recv(&mut self) -> Option<UdpDatagram> {
        loop {
            let datagram = self.datagrams.try_recv().ok()?;
            if datagram.is_expired(Instant::now()) {
                self.counters.inc(Counter::UdpTtlExpiredDropped);
                continue;
            }
            return Some(datagram);
        }
    }

    /// Hands a reply to the association without waiting.
    ///
    /// Returns the reply back when the rewrite queue is full or the association
    /// has ended, so a caller can count the drop instead of blocking.
    pub fn try_reply(&self, reply: UdpReply) -> Result<(), UdpReply> {
        self.replies.try_send(reply).map_err(|error| match error {
            mpsc::error::TrySendError::Full(reply) | mpsc::error::TrySendError::Closed(reply) => {
                reply
            }
        })
    }

    /// Hands a reply to the association, waiting for queue capacity.
    pub async fn send_reply(&self, reply: UdpReply) -> Result<(), SocksError> {
        self.replies
            .send(reply)
            .await
            .map_err(|_| SocksError::AssociationClosed)
    }

    /// Resolves when the controlling TCP connection ends or the association
    /// times out.
    pub async fn closed(&mut self) {
        // `wait_for` also returns when the sender is gone, which is the same
        // outcome for a handler: the association is over.
        let _ = self.closed.wait_for(|closed| *closed).await;
    }

    /// Whether the association has already ended.
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
}

/// Everything one UDP association needs from its server.
pub(crate) struct UdpAssociation<H> {
    pub(crate) handler: Arc<H>,
    pub(crate) config: Arc<SocksConfig>,
    pub(crate) counters: Arc<Counters>,
    pub(crate) association_id: u64,
    pub(crate) peer: SocketAddr,
    pub(crate) local: SocketAddr,
}

/// Binds the association's UDP socket and runs it until the controlling TCP
/// connection ends.
///
/// The success reply is only written after the socket exists, because
/// `BND.ADDR`/`BND.PORT` must be an address the client can actually reach
/// (section 7.4).
pub(crate) async fn run<H: SocksHandler>(association: UdpAssociation<H>, stream: TcpStream) {
    let mut stream = stream;
    let counters = Arc::clone(&association.counters);
    let config = Arc::clone(&association.config);
    let peer = association.peer;

    let socket = match bind_udp(&config, association.local).await {
        Ok(socket) => socket,
        Err(error) => {
            warn!(peer = %peer, %error, "socks5: cannot bind a UDP association socket");
            let _ = Reply::failure(ReplyCode::GeneralFailure)
                .write(&mut stream)
                .await;
            return;
        }
    };
    let bound = match advertised_address(&config, &socket, association.local) {
        Ok(bound) => bound,
        Err(error) => {
            warn!(peer = %peer, %error, "socks5: cannot read the UDP association address");
            let _ = Reply::failure(ReplyCode::GeneralFailure)
                .write(&mut stream)
                .await;
            return;
        }
    };
    if Reply::new(ReplyCode::Succeeded, bound)
        .write(&mut stream)
        .await
        .is_err()
    {
        return;
    }
    counters.inc(Counter::UdpAssociateStarted);
    debug!(peer = %peer, association = association.association_id, %bound, "socks5: UDP association established");

    let (datagram_tx, datagram_rx) =
        mpsc::channel::<UdpDatagram>(MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION);
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION);
    let (closed_tx, closed_rx) = watch::channel(false);
    let control = UdpControl {
        association_id: association.association_id,
        peer,
        client_addr: bound,
        datagrams: datagram_rx,
        replies: reply_tx,
        closed: closed_rx,
        counters: Arc::clone(&counters),
    };

    let handler_future = association.handler.udp_associate(control);
    tokio::pin!(handler_future);
    let mut handler_finished = false;

    // The block scopes the socket so that tearing the association down is the
    // first thing that happens after the loop, before the handler is joined.
    {
        let mut core = Association::new(
            &config,
            Arc::clone(&counters),
            association.association_id,
            peer.ip(),
        );
        let mut read_buffer = vec![0u8; config.max_udp_payload + UDP_HEADER_MAX + 1];
        let mut scratch = [0u8; 1];
        let mut wire = Vec::with_capacity(config.max_udp_payload + UDP_HEADER_MAX);
        let mut stream = stream;

        loop {
            let now = Instant::now();
            while let Some(datagram) = core.pop_ready(now) {
                match datagram_tx.try_send(datagram) {
                    Ok(()) => counters.inc(Counter::UdpRelayed),
                    Err(mpsc::error::TrySendError::Full(datagram)) => {
                        core.enqueue(datagram);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        handler_finished = true;
                        break;
                    }
                }
            }
            if handler_finished || core.is_idle(now) {
                break;
            }
            let deadline = TokioInstant::from_std(core.next_deadline());

            tokio::select! {
                // The handler's tunnel work progresses here; when it finishes,
                // the association is over even if the client is still connected.
                finished = &mut handler_future => {
                    handler_finished = true;
                    if let Err(error) = finished {
                        debug!(%error, "socks5: the UDP association handler failed");
                    }
                    break;
                }
                // The control connection carries no further protocol data; it is
                // read only to notice that the client went away.
                read = stream.read(&mut scratch) => match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                },
                reply = reply_rx.recv() => match reply {
                    Some(reply) => {
                        let now = Instant::now();
                        if let Some(client) = core.on_reply(&reply, now) {
                            if reply.payload.len() > config.max_udp_payload {
                                counters.inc(Counter::UdpOversizedDropped);
                            } else {
                                wire.clear();
                                if encode_udp_reply(reply.source, &reply.payload, &mut wire).is_ok() {
                                    match socket.send_to(&wire, client).await {
                                        Ok(_) => counters.inc(Counter::UdpRepliesSent),
                                        Err(error) => {
                                            counters.inc(Counter::UdpSendFailed);
                                            debug!(%error, "socks5: cannot send a relayed UDP reply");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        handler_finished = true;
                        break;
                    }
                },
                received = socket.recv_from(&mut read_buffer) => match received {
                    Ok((len, source)) => {
                        let now = Instant::now();
                        let truncated = len == read_buffer.len();
                        if let Some(datagram) =
                            core.accept_datagram(source, &read_buffer[..len], truncated, now)
                        {
                            match datagram_tx.try_send(datagram) {
                                Ok(()) => counters.inc(Counter::UdpRelayed),
                                Err(mpsc::error::TrySendError::Full(datagram)) => core.enqueue(datagram),
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    handler_finished = true;
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        debug!(%error, "socks5: UDP association socket failed");
                        break;
                    }
                },
                _ = sleep_until(deadline) => {}
            }
        }
    }

    let _ = closed_tx.send(true);
    if !handler_finished {
        let _ = timeout(SHUTDOWN_GRACE, handler_future).await;
    }
    counters.inc(Counter::UdpAssociationEnded);
    debug!(peer = %peer, association = association.association_id, "socks5: UDP association ended");
}

/// Binds the association's UDP socket.
///
/// The default is the address the client already reached us on, so the returned
/// `BND.ADDR` is reachable without the client having to guess what a wildcard
/// bind means (section 7.4).
async fn bind_udp(config: &SocksConfig, local: SocketAddr) -> std::io::Result<UdpSocket> {
    if let Some(advertise) = config.udp_advertise {
        if let Ok(socket) = UdpSocket::bind(advertise).await {
            return Ok(socket);
        }
        // A NAT-translated port cannot be bound locally, but its address is
        // still what the client must send to.
        return UdpSocket::bind(SocketAddr::new(advertise.ip(), 0)).await;
    }
    match UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await {
        Ok(socket) => Ok(socket),
        // A scoped or ephemeral interface address can refuse an exact bind; the
        // wildcard keeps the association usable and the advertised address then
        // comes from the address the client reached us on.
        Err(_) => UdpSocket::bind(SocketAddr::new(wildcard_for(local), 0)).await,
    }
}

/// The address reported to the client: always the real bound port, with the
/// configured address substituted when one is set.
fn advertised_address(
    config: &SocksConfig,
    socket: &UdpSocket,
    local: SocketAddr,
) -> std::io::Result<SocketAddr> {
    let bound = socket.local_addr()?;
    match (config.udp_advertise, bound.ip().is_unspecified()) {
        (Some(advertise), _) => Ok(SocketAddr::new(advertise.ip(), bound.port())),
        (None, true) => Ok(SocketAddr::new(local.ip(), bound.port())),
        (None, false) => Ok(bound),
    }
}

/// A mapped target and what is known about it.
#[derive(Debug)]
struct TargetState {
    /// Address this target is pinned to. An IP target is pinned at registration
    /// so a hijacked or mistaken reply for another address never reaches a
    /// client (section 7.4); a domain is pinned by its first answer, because
    /// only the exit knows what it resolved to.
    pinned_source: Option<IpAddr>,
    /// Monotonic time of the last datagram or reply for this target, used to
    /// reclaim the mapping when it goes idle.
    last_seen: Instant,
}

/// Per-association state, with time injected so every bound is unit-testable
/// without sleeping.
struct Association {
    peer_ip: IpAddr,
    allowlist: Vec<IpPrefix>,
    client: Option<SocketAddr>,
    targets: HashMap<(SocksTarget, u16), TargetState>,
    queue: VecDeque<UdpDatagram>,
    queued_bytes: usize,
    next_datagram_id: u64,
    association_id: u64,
    counters: Arc<Counters>,
    max_payload: usize,
    queue_ttl: Duration,
    idle: Duration,
    last_activity: Instant,
}

impl Association {
    fn new(
        config: &SocksConfig,
        counters: Arc<Counters>,
        association_id: u64,
        peer_ip: IpAddr,
    ) -> Self {
        Self {
            peer_ip,
            allowlist: config.source_allowlist.clone(),
            client: None,
            targets: HashMap::new(),
            queue: VecDeque::new(),
            queued_bytes: 0,
            next_datagram_id: 0,
            association_id,
            counters,
            max_payload: config.max_udp_payload,
            queue_ttl: config.udp_queue_ttl,
            idle: config.udp_idle_timeout,
            last_activity: Instant::now(),
        }
    }

    /// Whether a datagram source may talk to this association (section 7.4).
    fn source_allowed(&self, ip: IpAddr) -> bool {
        ip == self.peer_ip || self.allowlist.iter().any(|entry| entry.contains(ip))
    }

    /// Reclaims target mappings that have been idle (section 7.4).
    fn reap_targets(&mut self, now: Instant) {
        let idle = self.idle;
        self.targets
            .retain(|_, state| now.saturating_duration_since(state.last_seen) < idle);
    }

    /// Validates one received datagram and registers its target.
    ///
    /// Every rejection is counted, because section 7.4 requires each drop reason
    /// to be visible; the returned `None` means "drop".
    fn accept_datagram(
        &mut self,
        source: SocketAddr,
        datagram: &[u8],
        truncated: bool,
        now: Instant,
    ) -> Option<UdpDatagram> {
        self.reap_targets(now);
        if !self.source_allowed(source.ip()) {
            self.counters.inc(Counter::UdpSourceMismatchDropped);
            return None;
        }
        match self.client {
            None => self.client = Some(source),
            Some(locked) if locked != source => {
                // A relay that follows a moving source becomes an open UDP
                // relay, so the endpoint is locked by the first datagram.
                self.counters.inc(Counter::UdpSourceDriftDropped);
                return None;
            }
            Some(_) => {}
        }
        if truncated {
            self.counters.inc(Counter::UdpOversizedDropped);
            return None;
        }
        if datagram.len() < 4 {
            self.counters.inc(Counter::UdpMalformedDropped);
            return None;
        }
        if datagram[0] != 0x00 || datagram[1] != 0x00 {
            self.counters.inc(Counter::UdpMalformedDropped);
            return None;
        }
        if datagram[2] != 0x00 {
            // Version 1 does not reassemble SOCKS5 UDP fragments (section 7.4).
            self.counters.inc(Counter::UdpFragDropped);
            return None;
        }
        let (header, offset) = match UdpHeader::parse(datagram) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.counters.inc(Counter::UdpMalformedDropped);
                return None;
            }
        };
        let payload = &datagram[offset..];
        if payload.len() > self.max_payload {
            self.counters.inc(Counter::UdpOversizedDropped);
            return None;
        }
        let key = (header.target.clone(), header.port);
        match self.targets.get_mut(&key) {
            Some(state) => state.last_seen = now,
            None => {
                if self.targets.len() >= MAX_UDP_TARGETS_PER_ASSOCIATION {
                    self.counters.inc(Counter::UdpTargetLimitDropped);
                    return None;
                }
                let pinned_source = match &header.target {
                    SocksTarget::Ip(ip) => Some(*ip),
                    SocksTarget::Domain(_) => None,
                };
                self.targets.insert(
                    key,
                    TargetState {
                        pinned_source,
                        last_seen: now,
                    },
                );
            }
        }
        self.last_activity = now;
        self.next_datagram_id += 1;
        Some(UdpDatagram {
            association_id: self.association_id,
            datagram_id: self.next_datagram_id,
            target: header.target,
            port: header.port,
            payload: payload.to_vec(),
            received_at: now,
            deadline: now + self.queue_ttl,
        })
    }

    /// Queues a datagram that could not be handed over immediately.
    ///
    /// The queue is bounded in both count and bytes (section 7.4), so the oldest
    /// entry is dropped, and counted, rather than letting either bound slip.
    fn enqueue(&mut self, datagram: UdpDatagram) {
        if datagram.payload.len() > MAX_QUEUED_DATAGRAM_BYTES {
            self.counters.inc(Counter::UdpQueueOverflowDropped);
            return;
        }
        while self.queue.len() >= MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION
            || self.queued_bytes + datagram.payload.len() > MAX_QUEUED_DATAGRAM_BYTES
        {
            let Some(dropped) = self.queue.pop_front() else {
                break;
            };
            self.queued_bytes -= dropped.payload.len();
            self.counters.inc(Counter::UdpQueueOverflowDropped);
        }
        self.queued_bytes += datagram.payload.len();
        self.queue.push_back(datagram);
    }

    /// Pops the next queue entry, dropping and counting anything past its TTL.
    fn pop_ready(&mut self, now: Instant) -> Option<UdpDatagram> {
        loop {
            let front = self.queue.front()?;
            if !front.is_expired(now) {
                break;
            }
            let expired = self.queue.pop_front()?;
            self.queued_bytes -= expired.payload.len();
            self.counters.inc(Counter::UdpTtlExpiredDropped);
        }
        let datagram = self.queue.pop_front()?;
        self.queued_bytes -= datagram.payload.len();
        Some(datagram)
    }

    /// Validates a handler reply, returning the client endpoint to send it to.
    fn on_reply(&mut self, reply: &UdpReply, now: Instant) -> Option<SocketAddr> {
        let client = match self.client {
            Some(client) => client,
            None => {
                self.counters.inc(Counter::UdpUnmappedReplyDropped);
                return None;
            }
        };
        let key = (reply.target.clone(), reply.port);
        let state = match self.targets.get_mut(&key) {
            Some(state) => state,
            None => {
                // A reply for an unmapped target must never be delivered, or one
                // client's answer could be injected into another flow.
                self.counters.inc(Counter::UdpUnmappedReplyDropped);
                return None;
            }
        };
        let source_ip = reply.source.ip();
        match state.pinned_source {
            Some(pinned) if pinned != source_ip => {
                self.counters.inc(Counter::UdpUnexpectedSourceDropped);
                return None;
            }
            Some(_) => {}
            None => state.pinned_source = Some(source_ip),
        }
        state.last_seen = now;
        self.last_activity = now;
        Some(client)
    }

    /// Whether the association has been idle for its whole idle budget.
    fn is_idle(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= self.idle
    }

    /// The next instant the loop must wake for: the oldest queue TTL or the idle
    /// deadline, whichever comes first.
    fn next_deadline(&self) -> Instant {
        let idle_deadline = self.last_activity + self.idle;
        match self.queue.front() {
            Some(front) if front.deadline < idle_deadline => front.deadline,
            _ => idle_deadline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UserPass;
    use crate::wire::encode_udp_datagram;

    fn base_config() -> SocksConfig {
        SocksConfig::new()
    }

    fn association(config: &SocksConfig) -> Association {
        Association::new(
            config,
            Arc::new(Counters::new()),
            1,
            "127.0.0.1".parse().unwrap(),
        )
    }

    fn stats(core: &Association) -> SocksStats {
        core.counters.snapshot()
    }

    fn datagram(port: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_udp_datagram(
            &SocksTarget::Ip("198.51.100.9".parse().unwrap()),
            port,
            payload,
            &mut out,
        )
        .expect("encode");
        out
    }

    fn client() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    #[test]
    fn only_the_tcp_peer_or_an_allowlisted_address_may_send() {
        let config = base_config();
        let mut core = association(&config);
        let now = Instant::now();
        let stranger: SocketAddr = "127.0.0.2:40000".parse().unwrap();
        assert!(core
            .accept_datagram(stranger, &datagram(53, b"q"), false, now)
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpSourceMismatchDropped), 1);
        // The rejected datagram must not have locked the endpoint either.
        assert!(core.client.is_none());

        // An allowlisted address may open the association, and then owns the
        // endpoint lock like any other source.
        let mut config = base_config();
        config.source_allowlist = vec!["127.0.0.0/8".parse().unwrap()];
        let mut core = association(&config);
        assert!(core
            .accept_datagram(stranger, &datagram(53, b"q"), false, now)
            .is_some());
        assert_eq!(core.client, Some(stranger));
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(core
            .accept_datagram(peer, &datagram(53, b"q"), false, now)
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpSourceDriftDropped), 1);
    }

    #[test]
    fn the_source_endpoint_is_locked_by_the_first_datagram() {
        let config = base_config();
        let mut core = association(&config);
        let now = Instant::now();
        assert!(core
            .accept_datagram(client(), &datagram(53, b"q"), false, now)
            .is_some());
        let moved: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        assert!(core
            .accept_datagram(moved, &datagram(53, b"q"), false, now)
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpSourceDriftDropped), 1);
    }

    #[test]
    fn fragments_are_dropped_and_counted() {
        let config = base_config();
        let mut core = association(&config);
        let now = Instant::now();
        let mut fragmented = datagram(53, b"q");
        fragmented[2] = 1;
        assert!(core
            .accept_datagram(client(), &fragmented, false, now)
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpFragDropped), 1);
        assert_eq!(stats(&core).get(Counter::UdpMalformedDropped), 0);
    }

    #[test]
    fn malformed_oversized_and_truncated_datagrams_are_dropped() {
        let mut config = base_config();
        config.max_udp_payload = 8;
        let mut core = association(&config);
        let now = Instant::now();

        assert!(core.accept_datagram(client(), &[], false, now).is_none());
        assert!(core
            .accept_datagram(client(), &[0x00, 0x01, 0x00, 0x01], false, now)
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpMalformedDropped), 2);

        assert!(core
            .accept_datagram(client(), &datagram(53, b"123456789"), false, now)
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpOversizedDropped), 1);

        // A datagram that filled the read buffer was truncated by the kernel.
        assert!(core
            .accept_datagram(client(), &datagram(53, b"12345678"), true, now)
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpOversizedDropped), 2);

        assert!(core
            .accept_datagram(client(), &datagram(53, b"12345678"), false, now)
            .is_some());
    }

    #[test]
    fn the_target_map_is_bounded_and_reclaimed() {
        let mut config = base_config();
        config.udp_idle_timeout = Duration::from_secs(60);
        let mut core = association(&config);
        let start = Instant::now();
        for port in 1..=MAX_UDP_TARGETS_PER_ASSOCIATION as u16 {
            assert!(core
                .accept_datagram(client(), &datagram(port, b"q"), false, start)
                .is_some());
        }
        assert_eq!(core.targets.len(), MAX_UDP_TARGETS_PER_ASSOCIATION);
        assert!(core
            .accept_datagram(client(), &datagram(9_999, b"q"), false, start)
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpTargetLimitDropped), 1);

        // After the idle budget the mappings are gone, so a new target fits.
        let later = start + Duration::from_secs(61);
        assert!(core
            .accept_datagram(client(), &datagram(9_999, b"q"), false, later)
            .is_some());
        assert_eq!(core.targets.len(), 1);
    }

    #[test]
    fn the_send_queue_is_bounded_by_count_and_bytes() {
        let mut config = base_config();
        config.max_udp_payload = 4096;
        let mut core = association(&config);
        let now = Instant::now();
        for _ in 0..MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION {
            let queued = core
                .accept_datagram(client(), &datagram(53, b"q"), false, now)
                .expect("accepted");
            core.enqueue(queued);
        }
        assert_eq!(core.queue.len(), MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION);
        let queued = core
            .accept_datagram(client(), &datagram(53, b"q"), false, now)
            .expect("accepted");
        core.enqueue(queued);
        assert_eq!(core.queue.len(), MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION);
        assert_eq!(stats(&core).get(Counter::UdpQueueOverflowDropped), 1);
    }

    #[test]
    fn queued_datagrams_expire_on_the_monotonic_ttl() {
        let mut config = base_config();
        config.udp_queue_ttl = Duration::from_millis(1_000);
        let mut core = association(&config);
        let start = Instant::now();
        let queued = core
            .accept_datagram(client(), &datagram(53, b"q"), false, start)
            .expect("accepted");
        core.enqueue(queued);
        assert_eq!(core.queue.len(), 1);

        // Still inside the TTL the datagram is handed over.
        assert!(core.pop_ready(start + Duration::from_millis(999)).is_some());
        assert_eq!(stats(&core).get(Counter::UdpTtlExpiredDropped), 0);

        let queued = core
            .accept_datagram(client(), &datagram(53, b"q"), false, start)
            .expect("accepted");
        core.enqueue(queued);
        assert!(core
            .pop_ready(start + Duration::from_millis(1_001))
            .is_none());
        assert_eq!(stats(&core).get(Counter::UdpTtlExpiredDropped), 1);
        assert_eq!(core.queued_bytes, 0);
    }

    #[test]
    fn replies_must_match_a_mapped_target_and_its_source() {
        let config = base_config();
        let mut core = association(&config);
        let now = Instant::now();
        let request = core
            .accept_datagram(client(), &datagram(53, b"q"), false, now)
            .expect("accepted");
        assert!(core
            .on_reply(&reply_for(&request, "198.51.100.9:53"), now)
            .is_some());

        // An unmapped target is refused outright.
        let unmapped = UdpReply::new(
            SocksTarget::Ip("198.51.100.9".parse().unwrap()),
            9999,
            "198.51.100.9:9999".parse().unwrap(),
            b"x".to_vec(),
        );
        assert!(core.on_reply(&unmapped, now).is_none());
        assert_eq!(stats(&core).get(Counter::UdpUnmappedReplyDropped), 1);

        // An IP target may only answer from the address the client asked for.
        let hijacked = reply_for(&request, "198.51.100.10:53");
        assert!(core.on_reply(&hijacked, now).is_none());
        assert_eq!(stats(&core).get(Counter::UdpUnexpectedSourceDropped), 1);
    }

    #[test]
    fn a_domain_target_pins_its_first_answer() {
        let config = base_config();
        let mut core = association(&config);
        let now = Instant::now();
        let mut bytes = Vec::new();
        encode_udp_datagram(
            &SocksTarget::Domain("example.com".into()),
            53,
            b"q",
            &mut bytes,
        )
        .expect("encode");
        let request = core
            .accept_datagram(client(), &bytes, false, now)
            .expect("accepted");

        let first = reply_for(&request, "203.0.113.5:53");
        assert!(core.on_reply(&first, now).is_some());
        let second = reply_for(&request, "203.0.113.6:53");
        assert!(core.on_reply(&second, now).is_none());
        assert_eq!(stats(&core).get(Counter::UdpUnexpectedSourceDropped), 1);
    }

    #[test]
    fn a_reply_without_any_client_endpoint_is_dropped() {
        let config = base_config();
        let mut core = association(&config);
        let reply = UdpReply::new(
            SocksTarget::Ip("198.51.100.9".parse().unwrap()),
            53,
            "198.51.100.9:53".parse().unwrap(),
            b"x".to_vec(),
        );
        assert!(core.on_reply(&reply, Instant::now()).is_none());
        assert_eq!(stats(&core).get(Counter::UdpUnmappedReplyDropped), 1);
    }

    #[test]
    fn the_idle_deadline_is_the_earliest_of_ttl_and_idle() {
        let mut config = base_config();
        config.udp_queue_ttl = Duration::from_millis(500);
        config.udp_idle_timeout = Duration::from_secs(2);
        let mut core = association(&config);
        let start = Instant::now();
        core.last_activity = start;
        assert_eq!(core.next_deadline(), start + Duration::from_secs(2));

        let queued = core
            .accept_datagram(client(), &datagram(53, b"q"), false, start)
            .expect("accepted");
        core.enqueue(queued);
        assert_eq!(core.next_deadline(), start + Duration::from_millis(500));
        assert!(!core.is_idle(start + Duration::from_millis(1_999)));
        assert!(core.is_idle(start + Duration::from_secs(2)));
    }

    #[test]
    fn userpass_configuration_does_not_change_udp_source_rules() {
        // The allowlist and the peer rule are the only UDP source authorities;
        // credentials govern the TCP handshake that creates the association.
        let mut config = base_config();
        config.userpass = Some(UserPass::new("alice", "s3cret").unwrap());
        let mut core = association(&config);
        let now = Instant::now();
        assert!(core
            .accept_datagram(
                "127.0.0.1:40000".parse().unwrap(),
                &datagram(53, b"q"),
                false,
                now
            )
            .is_some());
        assert!(core
            .accept_datagram(
                "127.0.0.2:40000".parse().unwrap(),
                &datagram(53, b"q"),
                false,
                now
            )
            .is_none());
    }

    fn reply_for(request: &UdpDatagram, source: &str) -> UdpReply {
        UdpReply::new(
            request.target.clone(),
            request.port,
            source.parse().unwrap(),
            b"answer".to_vec(),
        )
    }
}
