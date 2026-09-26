//! The Hub-exit data plane (DESIGN.md sections 7.1, 7.2, 7.5, 8, 9.3).
//!
//! [`crate::Hub::authorize_open`] decides *whether* an `Open` may proceed and
//! ends at an [`crate::ExitPlan`]; this module turns one such plan
//! (`ExitPlan::HubExit`) into a socket and then into bytes, and nothing else. The
//! split is deliberate: the decision stays synchronous, complete, and testable,
//! while the part that can block on a network lives in a task of its own.
//!
//! Three rules shape the task:
//!
//! * **One task per stream.** Section 7.5 forbids one stream blocking the whole
//!   session's reader, so the session's own event loop keeps arbitrating
//!   `Hello`, `Open`, and other streams while this task waits on a socket.
//! * **The address is checked, not the name.** Section 9.3 requires resolving
//!   once, checking every candidate, and connecting to an address that already
//!   passed, which is what [`HubExit::dial`] does.
//! * **Credit follows consumption, and a half-close follows the bytes.** Section
//!   7.5 grants credit only for bytes written to the target, and section 7.2
//!   shuts the write half down only once every byte below `final_offset` reached
//!   it, so a `Fin` that overtakes its data cannot truncate the stream.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use wsnet_limits::{MAX_TCP_PAYLOAD, MAX_UDP_PAYLOAD, UDP_QUEUE_TTL_DEFAULT_MS};
use wsnet_routing::{AclAction, AclQuery, Proto};
use wsnet_session::{
    DatagramFields, OpenFields, OpenResultFields, OpenStatus, ResetReason, SessionError,
    SessionEvent, SessionHandle,
};
use wsnet_stream::StreamError;

use crate::egress::EgressPolicy;
use crate::hub::Hub;
use crate::session::SharedSession;

/// How long one Hub-exit dial may take before it is reported unreachable.
///
/// Section 7.1 bounds a failed leg at ten seconds, and the same budget covers
/// resolution: a name server that never answers must not hold a stream open
/// forever.
const EGRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How many bytes one read from the target may produce.
///
/// Section 4.1's record limit is the same size, so one read is at most one
/// `Data` record and a slow peer cannot make this task buffer more than one
/// record's worth of un-delivered bytes.
const READ_CHUNK: usize = MAX_TCP_PAYLOAD;

/// Detail used when a stream cannot be dialled because there is no runtime.
const DETAIL_NO_RUNTIME: &str = "hub exit needs an async runtime to dial";

/// Detail reported with a successful `OpenResult`.
///
/// Section 4.1 keeps `detail` for local diagnosis only; on success there is
/// nothing to diagnose, but an empty field is indistinguishable from a producer
/// that never filled it in, so a short note is more useful.
const DETAIL_CONNECTED: &str = "hub exit connected";

/// Detail reported with a successful `OpenResult` for a UDP route (section 7.4).
const DETAIL_UDP_ROUTE_READY: &str = "hub udp route ready";

/// Why a Hub exit could not produce a socket.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DialFailure {
    /// The status the caller is told.
    status: OpenStatus,
    /// A local-only explanation.
    detail: String,
}

impl DialFailure {
    fn new(status: OpenStatus, detail: impl Into<String>) -> Self {
        DialFailure {
            status,
            detail: detail.into(),
        }
    }
}

/// Spawns the task that dials one `ExitPlan::HubExit` destination.
///
/// The stream is registered *before* the task starts, so an event can never
/// arrive for a stream whose socket is not yet being pumped. A stream id that is
/// already live is never dialled twice (section 4.2 forbids reusing an id, and
/// section 8 refuses an unknown stream rather than creating one).
pub(crate) fn spawn_hub_exit(
    hub: &Hub,
    entry: &SharedSession,
    fields: &OpenFields,
    host: String,
    port: u16,
) {
    // Section 7.4 gives UDP its own carrier shape: one route is one connected
    // socket, and its traffic travels in `Datagram` records rather than in the
    // ordered byte stream. Dispatching here keeps the decision in one place — the
    // `Open` is already authorised by the time either task runs.
    if fields.proto == Proto::Udp {
        spawn_udp_exit(hub, entry, fields, host, port);
        return;
    }

    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        // Answering rather than panicking keeps a Hub that is driven from a
        // synchronous caller diagnosable instead of aborting the process.
        hub.refuse_open(entry, fields, OpenStatus::Unreachable, DETAIL_NO_RUNTIME);
        return;
    };

    let (sink, events) = mpsc::unbounded_channel();
    if !entry.claim_stream(fields.stream_id, sink) {
        tracing::debug!(
            session = %hex::encode(entry.session_id),
            stream_id = fields.stream_id,
            "refusing a second dial for a live stream"
        );
        return;
    }

    let exit = HubExit {
        session: Arc::clone(entry),
        handle: entry.handle.clone(),
        policy: hub.egress_policy().clone(),
        caller: entry.node_id.clone(),
        proto: fields.proto,
        request_id: fields.request_id,
        stream_id: fields.stream_id,
        host,
        port,
    };
    tracing::debug!(
        session = %hex::encode(entry.session_id),
        stream_id = fields.stream_id,
        streams = entry.live_streams(),
        "hub exit stream dialling"
    );
    runtime.spawn(async move { exit.run(events).await });
}

/// One Hub-exit stream: everything its task needs after authorisation.
struct HubExit {
    /// The session the stream belongs to, for routing and for publishing records.
    session: SharedSession,
    /// The engine handle, for `Data`, `Fin`, `Progress`, and `Reset`.
    handle: SessionHandle,
    /// Section 9.3's egress policy, derived from the deployment's ACL.
    policy: EgressPolicy,
    /// Who opened the stream; the ACL is per caller.
    caller: String,
    /// Protocol the `Open` named.
    proto: Proto,
    /// Operation id, echoed in the answer.
    request_id: [u8; 16],
    /// Stream being served.
    stream_id: u64,
    /// Host exactly as the caller wrote it.
    host: String,
    /// Destination port.
    port: u16,
}

impl HubExit {
    /// The ACL question for one concrete candidate address.
    fn query(&self, ip: IpAddr) -> AclQuery<'_> {
        AclQuery {
            caller: &self.caller,
            action: AclAction::ConnectAddress,
            node: None,
            service: None,
            ip: Some(ip),
            port: Some(self.port),
            proto: self.proto,
        }
    }

    /// Dials, answers, pumps, and then leaves nothing registered.
    async fn run(self, mut events: mpsc::UnboundedReceiver<SessionEvent>) {
        match self.dial().await {
            Err(failure) => self.refuse(failure),
            Ok(mut socket) => {
                if self.answer_ok() {
                    self.session.flush_outbound();
                    self.pump(&mut socket, &mut events).await;
                }
            }
        }
        // Section 7.1: a stream that is over releases its local mapping, while
        // the session and every other stream stay usable.
        self.session.unregister_stream(self.stream_id);
        self.handle.close_stream(self.stream_id);
        self.session.flush_outbound();
    }

    /// Resolves the name once, checks every candidate, and connects to a checked one.
    ///
    /// Section 9.3 is explicit about the order: the address that is connected to
    /// must be the address that was checked, so the candidate list is resolved
    /// once and reused rather than re-resolved at connect time (which a DNS
    /// rebind would otherwise win).
    async fn dial(&self) -> Result<TcpStream, DialFailure> {
        let resolved = tokio::time::timeout(
            EGRESS_CONNECT_TIMEOUT,
            lookup_host((self.host.as_str(), self.port)),
        )
        .await;
        let candidates: Vec<SocketAddr> = match resolved {
            Ok(Ok(candidates)) => candidates.collect(),
            Ok(Err(error)) => {
                return Err(DialFailure::new(
                    OpenStatus::Unreachable,
                    format!("cannot resolve the destination: {error}"),
                ))
            }
            Err(_) => {
                return Err(DialFailure::new(
                    OpenStatus::Unreachable,
                    "resolving the destination timed out",
                ))
            }
        };
        if candidates.is_empty() {
            return Err(DialFailure::new(
                OpenStatus::Unreachable,
                "the destination resolved to no address",
            ));
        }

        let mut last: Option<DialFailure> = None;
        for candidate in candidates {
            if let Err(refusal) = self
                .policy
                .check(&self.query(candidate.ip()), candidate.ip())
            {
                tracing::debug!(
                    session = %hex::encode(self.session.session_id),
                    stream_id = self.stream_id,
                    class = ?crate::egress::classify(candidate.ip()),
                    "egress guard refused a candidate address"
                );
                last = Some(DialFailure::new(OpenStatus::Denied, refusal.detail()));
                continue;
            }
            match tokio::time::timeout(EGRESS_CONNECT_TIMEOUT, TcpStream::connect(candidate)).await
            {
                Ok(Ok(stream)) => {
                    // Interactive streams of section 7.1 should not wait for a
                    // delayed acknowledgement to coalesce small records.
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Ok(Err(error)) => {
                    // The detail is a protocol field and a log line, so it must
                    // not be the OS message: that text is localized, varies
                    // between builds, and would leak host wording. Map the kind
                    // to a stable name instead.
                    let (status, detail) = match error.kind() {
                        std::io::ErrorKind::ConnectionRefused => (
                            OpenStatus::Refused,
                            "the target refused the connection".to_string(),
                        ),
                        std::io::ErrorKind::TimedOut => (
                            OpenStatus::Unreachable,
                            "connecting to the destination timed out".to_string(),
                        ),
                        other => (
                            OpenStatus::Unreachable,
                            format!("connect failed: {other:?}"),
                        ),
                    };
                    last = Some(DialFailure::new(status, detail));
                }
                Err(_) => {
                    last = Some(DialFailure::new(
                        OpenStatus::Unreachable,
                        "connecting to the destination timed out",
                    ));
                }
            }
        }
        Err(last.unwrap_or_else(|| {
            DialFailure::new(OpenStatus::Unreachable, "the destination is unreachable")
        }))
    }

    /// Reports a failure to the peer; the engine drops the stream state.
    fn refuse(&self, failure: DialFailure) {
        let result = OpenResultFields {
            request_id: self.request_id,
            stream_id: self.stream_id,
            status: failure.status,
            detail: failure.detail,
        };
        if let Err(error) = self.handle.send_open_result(&result) {
            tracing::debug!(
                session = %hex::encode(self.session.session_id),
                stream_id = self.stream_id,
                %error,
                "cannot answer a refused Open"
            );
        }
        self.session.flush_outbound();
    }

    /// Installs the stream and answers `OpenResult{Ok}` plus `Ready`.
    ///
    /// Section 7.1 requires the success to be reported only once both receive
    /// halves are installed, which `send_open_result` does by sending `Ready`
    /// itself. Returns whether the answer went out; a closed session has nothing
    /// left to pump.
    fn answer_ok(&self) -> bool {
        let result = OpenResultFields {
            request_id: self.request_id,
            stream_id: self.stream_id,
            status: OpenStatus::Ok,
            detail: DETAIL_CONNECTED.to_string(),
        };
        match self.handle.send_open_result(&result) {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(
                    session = %hex::encode(self.session.session_id),
                    stream_id = self.stream_id,
                    %error,
                    "cannot answer Open"
                );
                false
            }
        }
    }

    /// Carries bytes in both directions until the stream is finished.
    ///
    /// The loop is deliberately single-threaded: one task owns the socket, so
    /// there is no shared buffer to guard, and the session's own event loop is
    /// never involved (section 7.5).
    async fn pump(
        &self,
        socket: &mut TcpStream,
        events: &mut mpsc::UnboundedReceiver<SessionEvent>,
    ) {
        let mut buffer = vec![0u8; READ_CHUNK];
        // Bytes read from the target that the peer's credit has not yet accepted.
        let mut pending: Vec<u8> = Vec::new();
        let mut target_eof = false;
        let mut fin_sent = false;
        // The peer's `Fin`, remembered until every byte below it is written.
        let mut final_offset: Option<u64> = None;
        // Bytes that reached the target socket, which is what section 7.2's
        // `final_offset` is measured against.
        let mut written = 0u64;
        let mut write_shutdown = false;

        loop {
            if !self.deliver(&mut pending) {
                self.reset_stream(ResetReason::Unreachable);
                return;
            }
            // Flush unconditionally. `deliver` drains `pending` when it succeeds,
            // so gating this on `pending` still holding bytes skipped precisely
            // the case that had just produced new downlink records: the data then
            // sat in the engine until unrelated traffic happened to flush it,
            // which made downlink latency depend on the peer sending something.
            self.session.flush_outbound();

            // Section 7.2: the target's end of stream is a half-close.
            if target_eof && pending.is_empty() && !fin_sent {
                if self.handle.send_fin(self.stream_id).is_err() {
                    return;
                }
                fin_sent = true;
                self.session.flush_outbound();
            }

            // Section 7.2: shut the write half down only after everything below
            // the peer's `final_offset` reached the socket.
            if let Some(offset) = final_offset {
                if !write_shutdown && written >= offset {
                    let _ = socket.shutdown().await;
                    write_shutdown = true;
                }
            }
            if fin_sent && write_shutdown {
                return;
            }

            tokio::select! {
                // Backpressure is a paused read, never a dropped byte (section 7.5).
                read = socket.read(&mut buffer), if !target_eof && pending.is_empty() => {
                    match read {
                        Ok(0) => target_eof = true,
                        Ok(n) => pending.extend_from_slice(&buffer[..n]),
                        Err(error) => {
                            tracing::debug!(
                                session = %hex::encode(self.session.session_id),
                                stream_id = self.stream_id,
                                %error,
                                "the target socket failed"
                            );
                            self.reset_stream(ResetReason::Unreachable);
                            return;
                        }
                    }
                }
                event = events.recv() => {
                    // A closed channel means the session or the stream registry
                    // is gone; there is nothing left to answer.
                    let Some(event) = event else { return };
                    match event {
                        SessionEvent::Data { payload, .. } => {
                            if socket.write_all(&payload).await.is_err() {
                                self.reset_stream(ResetReason::Unreachable);
                                return;
                            }
                            written += payload.len() as u64;
                            // Section 7.5: credit is granted for what reached the
                            // next hop, never for what merely arrived here.
                            if self
                                .handle
                                .consume(self.stream_id, payload.len() as u64)
                                .is_err()
                            {
                                self.reset_stream(ResetReason::ProtocolError);
                                return;
                            }
                            self.session.flush_outbound();
                        }
                        SessionEvent::Fin(fields) => final_offset = Some(fields.final_offset),
                        SessionEvent::Reset(_) => return,
                        // A `Progress` only matters through the raised limit that
                        // the engine already recorded; the next delivery attempt
                        // picks it up.
                        SessionEvent::Progress(_) => {}
                        SessionEvent::Ready(_) => {}
                        other => tracing::trace!(
                            session = %hex::encode(self.session.session_id),
                            stream_id = self.stream_id,
                            event = ?other,
                            "ignoring a session event on a stream task"
                        ),
                    }
                }
            }
        }
    }

    /// Hands buffered target bytes to the peer, honouring the granted credit.
    ///
    /// Section 7.5 makes over-credit data a protocol error, so nothing is ever
    /// sent past the peer's `limit_offset`. When the whole buffer does not fit,
    /// the part that does is sent and the rest waits for a `Progress` event that
    /// raises the limit; no byte is dropped, and none is sent twice. Returns
    /// whether the stream can continue.
    fn deliver(&self, pending: &mut Vec<u8>) -> bool {
        while !pending.is_empty() {
            match self.handle.send_data(self.stream_id, pending) {
                Ok(_) => pending.clear(),
                Err(SessionError::Stream(StreamError::CreditExceeded { .. })) => {
                    let Some((offset, limit, _)) = self.handle.offsets(self.stream_id) else {
                        return false;
                    };
                    let room = limit.saturating_sub(offset) as usize;
                    if room == 0 {
                        // Wait for `Progress`; the task is still free to keep
                        // writing the other direction.
                        return true;
                    }
                    let take = room.min(pending.len());
                    if self
                        .handle
                        .send_data(self.stream_id, &pending[..take])
                        .is_err()
                    {
                        return false;
                    }
                    pending.drain(..take);
                }
                Err(error) => {
                    tracing::debug!(
                        session = %hex::encode(self.session.session_id),
                        stream_id = self.stream_id,
                        %error,
                        "the peer cannot receive target data"
                    );
                    return false;
                }
            }
        }
        true
    }

    /// Tells the peer the stream failed and releases the local mapping.
    fn reset_stream(&self, reason: ResetReason) {
        let _ = self.handle.send_reset(self.stream_id, reason);
        self.session.flush_outbound();
    }
}

/// Spawns the task that serves one authorised UDP route (section 7.4).
///
/// A route is one connected socket towards one target, which is what makes the
/// per-association, per-target mapping of section 7.4 a mapping from a route to a
/// socket: a response can only arrive from the target this route was opened for, so
/// an unrelated peer cannot inject one.
pub(crate) fn spawn_udp_exit(
    hub: &Hub,
    entry: &SharedSession,
    fields: &OpenFields,
    host: String,
    port: u16,
) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        hub.refuse_open(entry, fields, OpenStatus::Unreachable, DETAIL_NO_RUNTIME);
        return;
    };

    let (sink, events) = mpsc::unbounded_channel();
    if !entry.claim_stream(fields.stream_id, sink) {
        tracing::debug!(
            session = %hex::encode(entry.session_id),
            stream_id = fields.stream_id,
            "refusing a second route for a live stream"
        );
        return;
    }

    let exit = UdpExit {
        session: Arc::clone(entry),
        handle: entry.handle.clone(),
        policy: hub.egress_policy().clone(),
        caller: entry.node_id.clone(),
        request_id: fields.request_id,
        stream_id: fields.stream_id,
        host,
        port,
    };
    tracing::debug!(
        session = %hex::encode(entry.session_id),
        stream_id = fields.stream_id,
        "hub udp route dialling"
    );
    runtime.spawn(async move { exit.run(events).await });
}

/// One Hub-exit UDP route.
struct UdpExit {
    /// The session the route belongs to, for routing and publishing records.
    session: SharedSession,
    /// The engine handle, for `Datagram`, `OpenResult`, and `Reset`.
    handle: SessionHandle,
    /// Section 9.3's egress policy, derived from the deployment's ACL.
    policy: EgressPolicy,
    /// Who opened the route; the ACL is per caller.
    caller: String,
    /// Operation id, echoed in the answer.
    request_id: [u8; 16],
    /// Route being served.
    stream_id: u64,
    /// Host exactly as the caller wrote it.
    host: String,
    /// Destination port.
    port: u16,
}

impl UdpExit {
    /// The ACL question for one concrete candidate address.
    fn query(&self, ip: IpAddr) -> AclQuery<'_> {
        AclQuery {
            caller: &self.caller,
            action: AclAction::ConnectAddress,
            node: None,
            service: None,
            ip: Some(ip),
            port: Some(self.port),
            proto: Proto::Udp,
        }
    }

    /// Resolves, answers, pumps, and then leaves nothing registered.
    async fn run(self, mut events: mpsc::UnboundedReceiver<SessionEvent>) {
        match self.dial().await {
            Err(failure) => self.refuse(failure),
            Ok(socket) => {
                if self.answer_ok() {
                    self.session.flush_outbound();
                    self.pump(socket, &mut events).await;
                }
            }
        }
        self.session.unregister_stream(self.stream_id);
        self.handle.close_stream(self.stream_id);
        self.session.flush_outbound();
    }

    /// Resolves the name, checks every candidate, and connects to a checked one.
    ///
    /// The order is section 9.3's: the address that is connected to is the address
    /// that was checked, resolved once rather than re-resolved at connect time.
    ///
    /// Unlike TCP there is no handshake to fail, so `connect` on a UDP socket only
    /// fixes the peer. An unreachable target therefore does not surface here; its
    /// datagrams are simply lost, which is what section 7.4 means when it says UDP
    /// carries no delivery promise.
    async fn dial(&self) -> Result<UdpSocket, DialFailure> {
        let resolved = tokio::time::timeout(
            EGRESS_CONNECT_TIMEOUT,
            lookup_host((self.host.as_str(), self.port)),
        )
        .await;
        let candidates: Vec<SocketAddr> = match resolved {
            Ok(Ok(candidates)) => candidates.collect(),
            Ok(Err(error)) => {
                return Err(DialFailure::new(
                    OpenStatus::Unreachable,
                    format!("cannot resolve the destination: {error}"),
                ))
            }
            Err(_) => {
                return Err(DialFailure::new(
                    OpenStatus::Unreachable,
                    "resolving the destination timed out",
                ))
            }
        };

        let mut last: Option<DialFailure> = None;
        for candidate in candidates {
            if let Err(refusal) = self
                .policy
                .check(&self.query(candidate.ip()), candidate.ip())
            {
                tracing::debug!(
                    session = %hex::encode(self.session.session_id),
                    stream_id = self.stream_id,
                    "egress guard refused a udp candidate address"
                );
                last = Some(DialFailure::new(OpenStatus::Denied, refusal.detail()));
                continue;
            }
            // The local address is chosen by the OS: a UDP route has no listening
            // socket, and binding one explicitly would only invite a port
            // collision.
            let bind: SocketAddr = if candidate.is_ipv4() {
                "0.0.0.0:0".parse().expect("a valid wildcard address")
            } else {
                "[::]:0".parse().expect("a valid wildcard address")
            };
            match UdpSocket::bind(bind).await {
                Ok(socket) => match socket.connect(candidate).await {
                    Ok(()) => return Ok(socket),
                    Err(error) => {
                        last = Some(DialFailure::new(
                            OpenStatus::Unreachable,
                            format!("cannot connect the udp socket: {error:?}"),
                        ));
                    }
                },
                Err(error) => {
                    last = Some(DialFailure::new(
                        OpenStatus::Unreachable,
                        format!("cannot bind a udp socket: {error:?}"),
                    ));
                }
            }
        }
        Err(last.unwrap_or_else(|| {
            DialFailure::new(OpenStatus::Unreachable, "the destination is unreachable")
        }))
    }

    /// Reports a failure to the peer; the engine drops the route's state.
    fn refuse(&self, failure: DialFailure) {
        let result = OpenResultFields {
            request_id: self.request_id,
            stream_id: self.stream_id,
            status: failure.status,
            detail: failure.detail,
        };
        if let Err(error) = self.handle.send_open_result(&result) {
            tracing::debug!(
                session = %hex::encode(self.session.session_id),
                stream_id = self.stream_id,
                %error,
                "cannot answer a refused Open"
            );
        }
        self.session.flush_outbound();
    }

    /// Installs the route and answers `OpenResult{Ok}` plus `Ready`.
    fn answer_ok(&self) -> bool {
        let result = OpenResultFields {
            request_id: self.request_id,
            stream_id: self.stream_id,
            status: OpenStatus::Ok,
            detail: DETAIL_UDP_ROUTE_READY.to_string(),
        };
        match self.handle.send_open_result(&result) {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(
                    session = %hex::encode(self.session.session_id),
                    stream_id = self.stream_id,
                    %error,
                    "cannot answer Open"
                );
                false
            }
        }
    }

    /// Moves datagrams in both directions until the route ends.
    ///
    /// One association owns a route, which is what lets the reply carry the
    /// association id the caller needs without the Hub having to trust a number it
    /// was handed: the first datagram fixes it, and a later one claiming a different
    /// association is dropped rather than re-homed.
    async fn pump(&self, socket: UdpSocket, events: &mut mpsc::UnboundedReceiver<SessionEvent>) {
        let mut buffer = vec![0u8; MAX_UDP_PAYLOAD];
        let mut association: Option<u64> = None;
        let mut next_id: u64 = 0;

        loop {
            tokio::select! {
                received = socket.recv_from(&mut buffer) => {
                    let Ok((len, source)) = received else {
                        // A connected UDP socket reports an ICMP error from the peer
                        // here. The route stays open: a later datagram may still
                        // reach the target, and closing would turn one lost packet
                        // into a lost route.
                        tracing::trace!(
                            stream_id = self.stream_id,
                            "a udp route saw an error from its target"
                        );
                        continue;
                    };
                    let Some(association_id) = association else {
                        continue;
                    };
                    // Section 4.1 forbids wrapping a datagram id, so a route that
                    // exhausts the space ends instead of reusing an id.
                    let Some(datagram_id) = next_id.checked_add(1) else {
                        tracing::debug!(
                            stream_id = self.stream_id,
                            "a udp route exhausted its datagram ids"
                        );
                        return;
                    };
                    next_id = datagram_id;

                    // Section 7.4: the response travels back with the address it
                    // actually came from, so the local side can rebuild the SOCKS5
                    // header rather than claiming the original destination answered.
                    let fields = DatagramFields {
                        stream_id: self.stream_id,
                        association_id,
                        datagram_id,
                        host: source.ip().to_string(),
                        port: source.port(),
                        remaining_ttl_ms: UDP_QUEUE_TTL_DEFAULT_MS,
                    };
                    if let Err(error) = self
                        .handle
                        .send_datagram(fields.to_canonical(), buffer[..len].to_vec())
                    {
                        tracing::debug!(
                            stream_id = self.stream_id,
                            %error,
                            "cannot send a datagram response"
                        );
                        return;
                    }
                    self.session.flush_outbound();
                }
                event = events.recv() => match event {
                    Some(SessionEvent::Datagram { metadata, payload }) => {
                        let Ok(fields) = DatagramFields::from_canonical(&metadata) else {
                            tracing::debug!(
                                stream_id = self.stream_id,
                                "dropping a datagram whose metadata does not parse"
                            );
                            continue;
                        };
                        if fields.stream_id != self.stream_id {
                            continue;
                        }
                        match association {
                            None => association = Some(fields.association_id),
                            Some(known) if known != fields.association_id => {
                                tracing::debug!(
                                    stream_id = self.stream_id,
                                    "dropping a datagram for another association"
                                );
                                continue;
                            }
                            Some(_) => {}
                        }
                        // Section 7.4: a datagram whose queue budget is spent is
                        // dropped rather than sent late, and never requeued.
                        if fields.remaining_ttl_ms == 0 {
                            tracing::debug!(
                                stream_id = self.stream_id,
                                "dropping an expired datagram"
                            );
                            continue;
                        }
                        if let Err(error) = socket.send(&payload).await {
                            tracing::debug!(
                                stream_id = self.stream_id,
                                %error,
                                "a udp route could not reach its target"
                            );
                        }
                    }
                    // A half-close is not meaningful for datagrams, so either
                    // terminal event ends the route.
                    Some(SessionEvent::Fin(fields)) if fields.stream_id == self.stream_id => return,
                    Some(SessionEvent::Reset(fields)) if fields.stream_id == self.stream_id => {
                        return
                    }
                    Some(_) => {}
                    None => return,
                },
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {    use std::future::Future;
    use std::net::IpAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    use wsnet_config::{ServerConfig, ServerSection};
    use wsnet_crypto::Psk;
    use wsnet_protocol::{MessageKind, Record};
    use wsnet_routing::{AclRule, Destination};
    use wsnet_session::{
        auth_mac, session_keys, AuthFields, AuthOkFields, FinFields, HelloFields, OpenStatus,
        ServiceRegistration, Session, SessionConfig, SessionEvent, SessionHandle, SessionState,
        Side,
    };

    use super::*;
    use crate::hub::NodeSecrets;

    /// Installs a tracing subscriber once per test binary.
    ///
    /// A test binary has no subscriber by default, so every `tracing::debug!` in
    /// the data plane is silently discarded — which makes a hanging test
    /// undiagnosable. `RUST_LOG=wsnet_hub=debug` now actually produces output.
    fn init_tracing() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
                )
                .with_test_writer()
                .try_init();
        });
    }

    const HUB_ID: &str = "hub-a";
    const NODE_ID: &str = "client-a";
    const KEY_ID: &str = "a-1";
    /// The peer's first grant: `STREAM_INITIAL_CREDIT` from the engine config.
    const INITIAL_CREDIT: u64 = 256 * 1024;

    fn psk() -> Psk {
        Psk::from_bytes([0x42; 32])
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Runs one test body under a hard deadline, so a bug cannot hang the suite.
    pub(crate) async fn within<F: Future>(future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(30), future)
            .await
            .expect("the test did not finish inside its deadline")
    }

    /// One bounded wait, so no test blocks on a condition that never comes.
    ///
    /// Visible to the crate's other test modules (the relay bridge reuses this
    /// harness), which is why it is not private to this module.
    pub(crate) async fn soon<F: Future>(what: &str, future: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
    }

    /// A Hub and a node-side session wired to each other in-process.
    ///
    /// The carriers of section 4.3 are not needed to test the data plane: the
    /// Hub's own `SessionHandle` is driven directly, which is less code and moves
    /// exactly the same sealed records.
    struct Paired {
        hub: Arc<Hub>,
        entry: SharedSession,
        node: SessionHandle,
        events: mpsc::UnboundedReceiver<SessionEvent>,
        pump: JoinHandle<()>,
    }

    impl Drop for Paired {
        fn drop(&mut self) {
            self.pump.abort();
        }
    }

    /// Matches the ACL rule helper the rest of the crate's tests use.
    fn rule(action: AclAction, host_cidr: Option<&str>) -> AclRule {
        AclRule {
            caller: NODE_ID.to_string(),
            action,
            allow: true,
            node: None,
            service: None,
            host_cidr: host_cidr.map(Into::into),
            ports: None,
            proto: None,
        }
    }

    /// A rule that names the loopback range, which is section 9.3's explicit
    /// allowlist entry for the local targets these tests dial.
    fn loopback_rule() -> AclRule {
        rule(AclAction::ConnectAddress, Some("127.0.0.1/32"))
    }

    /// A Hub that accepts one credential per `(node_id, key_id)` pair.
    ///
    /// The relay bridge needs more than one node on the same Hub, so the
    /// credential set is a parameter rather than `pair`'s single node.
    pub(crate) fn hub_for_nodes(acl: Vec<AclRule>, nodes: &[(&str, &str)]) -> Arc<Hub> {
        init_tracing();
        let mut secrets = NodeSecrets::new();
        for (node_id, key_id) in nodes {
            secrets.insert(*node_id, *key_id, psk());
        }
        let config = ServerConfig {
            server: ServerSection {
                hub_id: HUB_ID.to_string(),
                listen: "127.0.0.1:8443".to_string(),
                ..ServerSection::default()
            },
            nodes: Vec::new(),
            acl,
        };
        Arc::new(Hub::new(config, secrets).expect("a hub"))
    }

    /// One node's side of a Hub session, wired to the Hub in-process.
    pub(crate) struct NodeLink {
        /// The Hub's session entry for this node.
        pub(crate) entry: SharedSession,
        /// The node-side engine handle.
        pub(crate) node: SessionHandle,
        /// The node's own events, for the test to arbitrate.
        pub(crate) events: mpsc::UnboundedReceiver<SessionEvent>,
        /// The task moving sealed envelopes both ways; it ends with the runtime.
        pub(crate) pump: JoinHandle<()>,
    }

    impl NodeLink {
        /// Sends `Hello` and waits for the session to become ready (section 5.3).
        ///
        /// `services` is what the Hub's registry then publishes for this node, and
        /// `seed` keeps each node's Hello request id distinct.
        pub(crate) async fn hello(&self, services: Vec<ServiceRegistration>, seed: u8) {
            self.node
                .send_control(
                    MessageKind::Hello,
                    HelloFields {
                        request_id: [seed; 16],
                        services,
                        capabilities: vec!["flow.credit".to_string()],
                    }
                    .to_canonical(),
                )
                .expect("the Hello must queue");
            let ready = self.node.clone();
            soon("the session to become ready", async move {
                while ready.state() != SessionState::Ready {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
        }
    }

    /// Authenticates one node and moves sealed envelopes between the two engines.
    ///
    /// The carriers of section 4.3 are not needed to test the data plane: the
    /// Hub's own `SessionHandle` is driven directly, which is less code and moves
    /// exactly the same sealed records. `seed` keeps each node's `Auth` distinct,
    /// which section 5.1's replay window is per credential about.
    pub(crate) async fn connect_node(
        hub: &Arc<Hub>,
        node_id: &str,
        key_id: &str,
        seed: u8,
    ) -> NodeLink {
        let fields = AuthFields {
            version: 1,
            hub_id: HUB_ID.to_string(),
            key_id: key_id.to_string(),
            node_id: node_id.to_string(),
            attempt_id: [seed; 16],
            ts: now_secs(),
            nonce: [seed; 32],
            capabilities: vec!["flow.credit".to_string()],
        };
        let mac = auth_mac(&psk(), &fields);
        let auth = Record::new(MessageKind::Auth, fields.to_canonical(&mac));
        let success = hub
            .authenticate(&auth, IpAddr::from([127, 0, 0, 1]))
            .expect("the credentials must authenticate");
        let (authok, _) =
            AuthOkFields::from_canonical(&success.authok.metadata).expect("AuthOk metadata");
        let keys = session_keys(&psk(), &fields, &authok);
        let node = Session::new(
            SessionConfig::new(
                HUB_ID,
                node_id,
                authok.session_id,
                authok.session_epoch,
                Side::Node,
            ),
            keys,
        );
        let entry = success.entry;
        let node_handle = node.handle.clone();
        let mut downlink = entry.downlink.subscribe();
        let (event_tx, events) = mpsc::unbounded_channel();
        let mut outbound = node.outbound;
        let mut node_events = node.events;
        let feeding_hub = Arc::clone(hub);
        let feeding_entry = Arc::clone(&entry);
        let feeding_handle = node_handle.clone();

        // One task moves sealed records both ways and forwards the node's events
        // to the test, which is exactly what a carrier pair would do.
        let pump = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(envelope) = outbound.recv() => {
                        feeding_hub.feed_records(&feeding_entry, &[envelope]);
                    }
                    Ok(envelope) = downlink.recv() => {
                        let accepted = feeding_handle.feed_lossy(&envelope);
                        tracing::debug!(
                            accepted,
                            len = envelope.len(),
                            "harness pump: hub -> node"
                        );
                    }
                    Some(event) = node_events.recv() => {
                        tracing::debug!(?event, "harness pump: node event");
                        if event_tx.send(event).is_err() {
                            break;
                        }
                    }
                    else => break,
                }
            }
        });

        NodeLink {
            entry,
            node: node_handle,
            events,
            pump,
        }
    }

    async fn pair(acl: Vec<AclRule>) -> Paired {
        let hub = hub_for_nodes(acl, &[(NODE_ID, KEY_ID)]);
        let link = connect_node(&hub, NODE_ID, KEY_ID, 0x11).await;
        // `Hello`/`HelloOk` is section 5.3's business barrier.
        link.hello(Vec::new(), 0x31).await;

        Paired {
            hub,
            entry: link.entry,
            node: link.node,
            events: link.events,
            pump: link.pump,
        }
    }

    impl Paired {
        /// Opens one address on this session and returns its stream id.
        fn open(&self, host: &str, port: u16, request_id: [u8; 16]) -> u64 {
            let (stream_id, _) = self
                .node
                .open(
                    Destination::address(host, port),
                    Vec::new(),
                    Proto::Tcp,
                    request_id,
                )
                .expect("the Open must queue");
            stream_id
        }

        /// The next event, with a deadline.
        async fn next(&mut self) -> SessionEvent {
            soon("a session event", self.events.recv())
                .await
                .expect("the session must stay open")
        }

        /// The first `OpenResult` for `stream_id`.
        async fn open_result(&mut self, stream_id: u64) -> OpenResultFields {
            loop {
                if let SessionEvent::OpenResult(fields) = self.next().await {
                    if fields.stream_id == stream_id {
                        return fields;
                    }
                }
            }
        }

        /// Every `Data` byte for `stream_id` until its `Fin`, plus the offset.
        async fn read_until_fin(&mut self, stream_id: u64) -> (Vec<u8>, Option<u64>) {
            let mut bytes = Vec::new();
            loop {
                match self.next().await {
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
    }

    /// A loopback listener that accepts once and returns both halves.
    /// A loopback UDP echo target: whatever it receives, it sends back.
    ///
    /// The socket moves into the task that serves it, which is also what keeps it
    /// alive: the caller only needs the port it bound.
    async fn bind_udp_echo() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback udp socket");
        let port = socket.local_addr().expect("a bound address").port();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_UDP_PAYLOAD];
            loop {
                let Ok((len, from)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let _ = socket.send_to(&buffer[..len], from).await;
            }
        });
        port
    }

    impl Paired {
        /// Opens one UDP route on this session and returns its stream id.
        fn open_udp(&self, host: &str, port: u16, request_id: [u8; 16]) -> u64 {
            let (stream_id, _) = self
                .node
                .open(
                    Destination::address(host, port),
                    Vec::new(),
                    Proto::Udp,
                    request_id,
                )
                .expect("the Open must queue");
            stream_id
        }

        /// The next datagram for `stream_id`, ignoring everything else.
        async fn read_datagram(&mut self, stream_id: u64) -> (DatagramFields, Vec<u8>) {
            loop {
                if let SessionEvent::Datagram { metadata, payload } = self.next().await {
                    let fields = DatagramFields::from_canonical(&metadata)
                        .expect("the hub must send readable metadata");
                    if fields.stream_id == stream_id {
                        return (fields, payload);
                    }
                }
            }
        }

        /// Sends one datagram and returns the payload it used.
        fn send_datagram(&self, fields: DatagramFields, payload: &[u8]) {
            self.node
                .send_datagram(fields.to_canonical(), payload.to_vec())
                .expect("the datagram must queue");
        }
    }

    fn datagram_fields(
        stream_id: u64,
        association_id: u64,
        datagram_id: u64,
        port: u16,
        remaining_ttl_ms: u64,
    ) -> DatagramFields {
        DatagramFields {
            stream_id,
            association_id,
            datagram_id,
            host: "127.0.0.1".to_string(),
            port,
            remaining_ttl_ms,
        }
    }

    /// An authorised UDP route carries datagrams both ways over a real socket
    /// (section 7.4), and the response names the address it actually came from.
    #[tokio::test]
    async fn an_authorised_udp_route_carries_datagrams_both_ways() {
        within(async {
            let port = bind_udp_echo().await;
            let mut pair = pair(vec![loopback_rule()]).await;

            let stream_id = pair.open_udp("127.0.0.1", port, [0x51; 16]);
            let result = pair.open_result(stream_id).await;
            assert_eq!(result.status, OpenStatus::Ok, "{}", result.detail);
            assert_eq!(result.detail, DETAIL_UDP_ROUTE_READY);

            pair.send_datagram(datagram_fields(stream_id, 9, 1, port, 1_000), b"ping");
            let (fields, payload) = pair.read_datagram(stream_id).await;
            assert_eq!(payload, b"ping");
            assert_eq!(fields.association_id, 9, "the association must survive");
            assert_eq!(fields.stream_id, stream_id);
            // Section 7.4: the response carries the address it really came from.
            assert_eq!(fields.host, "127.0.0.1");
            assert_eq!(fields.port, port);
            assert_eq!(
                fields.remaining_ttl_ms, UDP_QUEUE_TTL_DEFAULT_MS,
                "the response starts its own queue budget"
            );

            // A second datagram on the same route still works, so the first did not
            // consume the socket.
            pair.send_datagram(datagram_fields(stream_id, 9, 2, port, 1_000), b"pong");
            let (_, payload) = pair.read_datagram(stream_id).await;
            assert_eq!(payload, b"pong");

            pair.entry.handle.close_stream(stream_id);
        })
        .await;
    }

    /// A route belongs to one association, and a spent queue budget is not spent
    /// twice: both are dropped rather than forwarded.
    #[tokio::test]
    async fn a_udp_route_drops_another_association_and_an_expired_datagram() {
        within(async {
            let port = bind_udp_echo().await;
            let mut pair = pair(vec![loopback_rule()]).await;
            let stream_id = pair.open_udp("127.0.0.1", port, [0x52; 16]);
            assert_eq!(pair.open_result(stream_id).await.status, OpenStatus::Ok);

            // The first datagram fixes the association...
            pair.send_datagram(datagram_fields(stream_id, 9, 1, port, 1_000), b"first");
            assert_eq!(pair.read_datagram(stream_id).await.1, b"first");

            // ...so a later one claiming a different association must be dropped,
            // followed by a legal datagram whose echo is therefore the next event.
            pair.send_datagram(datagram_fields(stream_id, 10, 2, port, 1_000), b"intruder");
            pair.send_datagram(datagram_fields(stream_id, 9, 3, port, 1_000), b"legal");
            assert_eq!(pair.read_datagram(stream_id).await.1, b"legal");

            // Section 7.4: a datagram whose queue budget is already spent is
            // dropped rather than delivered late.
            pair.send_datagram(datagram_fields(stream_id, 9, 4, port, 0), b"expired");
            pair.send_datagram(datagram_fields(stream_id, 9, 5, port, 1_000), b"fresh");
            assert_eq!(pair.read_datagram(stream_id).await.1, b"fresh");
        })
        .await;
    }

    /// Section 9.3: the egress guard applies to a UDP route exactly as it does to a
    /// TCP one, so a route to a special address without an explicit rule is refused.
    #[tokio::test]
    async fn a_udp_route_to_loopback_needs_the_explicit_egress_rule() {
        within(async {
            let port = bind_udp_echo().await;
            let mut pair = pair(Vec::new()).await;
            let stream_id = pair.open_udp("127.0.0.1", port, [0x53; 16]);
            let result = pair.open_result(stream_id).await;
            assert_eq!(
                result.status,
                OpenStatus::Denied,
                "a loopback udp route must need an explicit rule: {}",
                result.detail
            );
            assert_eq!(
                pair.entry.handle.stream_count(),
                0,
                "a refused route must register nothing"
            );
        })
        .await;
    }

    async fn bind_listener() -> (TcpListener, u16) {        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let port = listener.local_addr().expect("a bound address").port();
        (listener, port)
    }

    async fn accept(listener: &TcpListener) -> TcpStream {
        soon("the hub to dial the target", listener.accept())
            .await
            .expect("the listener must accept")
            .0
    }

    impl Paired {
        /// Waits until the engine has carried `bytes` to the peer.
        async fn wait_for_offset(&self, stream_id: u64, bytes: u64) {
            let handle = self.node.clone();
            soon("the peer to advance its offset", async move {
                loop {
                    if handle
                        .offsets(stream_id)
                        .map(|(_, _, received)| received >= bytes)
                        .unwrap_or(false)
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
        }
    }

    /// An authorised address `Open` reaches a real listener and both directions
    /// carry bytes (sections 7.1, 7.5).
    #[tokio::test]
    async fn an_authorised_open_carries_bytes_both_ways_over_a_real_socket() {
        within(async {
            let (listener, port) = bind_listener().await;
            let mut pair = pair(vec![loopback_rule()]).await;
            // The session is a real one: `Hello` registered the node's lease.
            assert!(pair.hub.is_node_registered(NODE_ID));
            assert_eq!(pair.hub.session_count(), 1);

            let stream_id = pair.open("127.0.0.1", port, [0x41; 16]);
            let mut target = accept(&listener).await;

            let result = pair.open_result(stream_id).await;
            assert_eq!(result.status, OpenStatus::Ok, "{}", result.detail);
            assert_eq!(result.detail, DETAIL_CONNECTED);
            assert_eq!(pair.entry.handle.stream_count(), 1);
            assert_eq!(pair.entry.live_streams(), 1);

            // Target -> peer.
            target
                .write_all(b"hello from the target")
                .await
                .expect("the target must be able to write");
            // Section 7.2 sends `Fin` on EOF, so the test has to actually close
            // the target's write half; without this the Hub can never observe an
            // end of stream and the wait below is for something that cannot
            // happen.
            let _ = target.shutdown().await;
            let (bytes, fin) = pair.read_until_fin(stream_id).await;
            assert_eq!(bytes, b"hello from the target");
            // The target half-closed, so the peer sees the same stream end.
            assert_eq!(fin, Some(bytes.len() as u64));

            // Peer -> target: the reply reaches the socket byte for byte.
            let reply = b"the peer's reply";
            assert_eq!(
                pair.node
                    .send_data(stream_id, reply)
                    .expect("the reply must fit the credit"),
                reply.len()
            );
            let mut echoed = vec![0u8; reply.len()];
            soon(
                "the target to read the reply",
                target.read_exact(&mut echoed),
            )
            .await
            .expect("the target must read the reply");
            assert_eq!(echoed, reply);
            assert_eq!(pair.entry.handle.stream_count(), 1);
        })
        .await;
    }

    /// A `Fin` that overtakes its data must not truncate the stream, and a
    /// normal `Fin` closes the write half only after the payload (section 7.2).
    #[tokio::test]
    async fn a_fin_that_arrives_before_its_data_does_not_truncate() {
        within(async {
            let (listener, port) = bind_listener().await;
            let mut pair = pair(vec![loopback_rule()]).await;

            let stream_id = pair.open("127.0.0.1", port, [0x42; 16]);
            let mut target = accept(&listener).await;
            assert_eq!(pair.open_result(stream_id).await.status, OpenStatus::Ok);

            let payload = b"the whole payload, in two pieces";
            // Section 7.2: the `Fin` carries the end offset and may cross a
            // carrier ahead of the bytes, so it is sent first, by hand.
            pair.node
                .send_control(
                    MessageKind::Fin,
                    FinFields {
                        stream_id,
                        final_offset: payload.len() as u64,
                    }
                    .to_canonical(),
                )
                .expect("the Fin must queue");

            let (first, second) = payload.split_at(11);
            assert_eq!(
                pair.node
                    .send_data(stream_id, first)
                    .expect("the first half"),
                first.len()
            );
            soon(
                "the first half to reach the target",
                target.read_exact(&mut vec![0u8; first.len()]),
            )
            .await
            .expect("the target must read the first half");
            let mut seen = first.to_vec();
            // The write half must still be open: a shutdown here would truncate.
            let mut extra = [0u8; 1];
            let early =
                tokio::time::timeout(Duration::from_millis(200), target.read(&mut extra)).await;
            assert!(
                early.is_err(),
                "the target saw the write half close before the payload arrived: {early:?}"
            );

            assert_eq!(
                pair.node
                    .send_data(stream_id, second)
                    .expect("the second half"),
                second.len()
            );
            soon(
                "the second half to reach the target",
                target.read_exact(&mut vec![0u8; second.len()]),
            )
            .await
            .expect("the target must read the second half");
            seen.extend_from_slice(second);

            // Every byte below `final_offset` was written, so now the write half
            // closes and the target sees it.
            let mut tail = Vec::new();
            soon("the write half to close", target.read_to_end(&mut tail))
                .await
                .expect("the target must see the half-close");
            assert!(tail.is_empty(), "nothing beyond the payload may arrive");
            assert_eq!(seen, payload);
        })
        .await;
    }

    /// The peer's credit is absolute: the Hub waits for `Progress` instead of
    /// dropping or duplicating bytes (section 7.5).
    #[tokio::test]
    async fn credit_is_waited_for_rather_than_dropped_or_duplicated() {
        within(async {
            let (listener, port) = bind_listener().await;
            let mut pair = pair(vec![loopback_rule()]).await;
            let stream_id = pair.open("127.0.0.1", port, [0x43; 16]);
            let mut target = accept(&listener).await;
            assert_eq!(pair.open_result(stream_id).await.status, OpenStatus::Ok);

            // One byte past the initial grant, so the Hub must block at the limit.
            let total = INITIAL_CREDIT as usize + 44 * 1024;
            let payload: Vec<u8> = (0..total).map(|index| (index % 251) as u8).collect();
            let writing = payload.clone();
            let writer = tokio::spawn(async move {
                target.write_all(&writing).await.expect("the target writes");
                target.shutdown().await.expect("the target half-closes");
                target
            });

            // The peer consumes nothing until it holds the whole first window,
            // which is what makes the Hub stop exactly at its limit.
            let mut received = Vec::new();
            let mut consumed = false;
            let mut fin = None;
            while fin.is_none() {
                match pair.next().await {
                    SessionEvent::Data {
                        stream_id: id,
                        payload,
                        ..
                    } if id == stream_id => {
                        received.extend_from_slice(&payload);
                        if !consumed && received.len() as u64 >= INITIAL_CREDIT {
                            // The Hub cannot have sent more than the grant.
                            let (sent, limit, _) = pair
                                .entry
                                .handle
                                .offsets(stream_id)
                                .expect("the hub engine knows the stream");
                            assert_eq!(limit, INITIAL_CREDIT, "the peer granted no more");
                            assert_eq!(
                                sent, INITIAL_CREDIT,
                                "the hub must stop exactly at the granted limit"
                            );
                            consumed = true;
                            pair.node
                                .consume(stream_id, received.len() as u64)
                                .expect("consume must raise the limit");
                        }
                    }
                    SessionEvent::Fin(fields) if fields.stream_id == stream_id => {
                        fin = Some(fields.final_offset);
                    }
                    SessionEvent::Reset(fields) if fields.stream_id == stream_id => {
                        panic!("the stream was reset: {:?}", fields.reason);
                    }
                    _ => {}
                }
            }
            assert!(consumed, "the peer must have driven the credit forward");
            assert_eq!(
                fin,
                Some(total as u64),
                "the Fin must close the whole stream"
            );
            assert_eq!(received.len(), total, "no byte may be dropped");
            assert_eq!(received, payload, "no byte may be duplicated or reordered");
            let _target = soon("the writer to finish", writer)
                .await
                .expect("the writer");
            pair.wait_for_offset(stream_id, total as u64).await;
        })
        .await;
    }

    /// Section 9.3: loopback egress is refused unless a rule names the range.
    #[tokio::test]
    async fn loopback_is_refused_by_default_and_allowed_by_an_explicit_rule() {
        within(async {
            // A rule that authorises the access but names no range is not an
            // allowlist entry, so the guard still refuses the loopback target.
            let (listener, port) = bind_listener().await;
            let mut denied = pair(vec![rule(AclAction::ConnectAddress, None)]).await;
            let stream_id = denied.open("127.0.0.1", port, [0x44; 16]);
            let result = denied.open_result(stream_id).await;
            assert_eq!(result.status, OpenStatus::Denied);
            assert!(result.detail.contains("loopback"), "{}", result.detail);
            assert_eq!(denied.entry.handle.stream_count(), 0);
            assert_eq!(denied.entry.live_streams(), 0);
            // Nothing was dialled: the listener has no connection to hand out.
            let idle = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            assert!(
                idle.is_err(),
                "the guard must not dial the target: {idle:?}"
            );

            // Naming the range is the explicit allowlist entry of section 9.3.
            let (allowed_listener, allowed_port) = bind_listener().await;
            let mut allowed = pair(vec![loopback_rule()]).await;
            let stream_id = allowed.open("127.0.0.1", allowed_port, [0x45; 16]);
            let mut target = accept(&allowed_listener).await;
            assert_eq!(allowed.open_result(stream_id).await.status, OpenStatus::Ok);
            target
                .write_all(b"local service")
                .await
                .expect("the target writes");
            // `Fin` follows EOF (section 7.2), so the target's write half must be
            // closed before an end of stream can be observed.
            let _ = target.shutdown().await;
            let (bytes, _) = allowed.read_until_fin(stream_id).await;
            assert_eq!(bytes, b"local service");
        })
        .await;
    }

    /// A refused connection and a guard refusal both leave the session clean
    /// (sections 7.1, 9.3).
    #[tokio::test]
    async fn a_refused_connection_maps_to_refused_and_registers_no_stream() {
        within(async {
            let (listener, port) = bind_listener().await;
            // Take the port back, so the dial is refused by the kernel.
            drop(listener);

            let mut pair = pair(vec![loopback_rule()]).await;
            let stream_id = pair.open("127.0.0.1", port, [0x46; 16]);
            let result = pair.open_result(stream_id).await;
            assert_eq!(result.status, OpenStatus::Refused, "{}", result.detail);
            assert!(
                result.detail.contains("refused"),
                "the detail must name the cause: {}",
                result.detail
            );
            assert_eq!(pair.entry.handle.stream_count(), 0);
            assert_eq!(pair.entry.live_streams(), 0);

            // The same session is still usable for another stream.
            let (listener, port) = bind_listener().await;
            let stream_id = pair.open("127.0.0.1", port, [0x47; 16]);
            let mut target = accept(&listener).await;
            assert_eq!(pair.open_result(stream_id).await.status, OpenStatus::Ok);
            target
                .write_all(b"still alive")
                .await
                .expect("the target writes");
            // Same reason as above: `Fin` needs a real end of stream.
            let _ = target.shutdown().await;
            let (bytes, _) = pair.read_until_fin(stream_id).await;
            assert_eq!(bytes, b"still alive");
        })
        .await;
    }

    /// Two streams share one session, and resetting one leaves the other alone
    /// (sections 7.5, 8).
    #[tokio::test]
    async fn two_streams_run_concurrently_and_a_reset_leaves_the_other_usable() {
        within(async {
            let (first_listener, first_port) = bind_listener().await;
            let (second_listener, second_port) = bind_listener().await;
            let mut pair = pair(vec![loopback_rule()]).await;

            let first = pair.open("127.0.0.1", first_port, [0x48; 16]);
            let second = pair.open("127.0.0.1", second_port, [0x49; 16]);
            assert_ne!(first, second);
            let mut first_target = accept(&first_listener).await;
            let mut second_target = accept(&second_listener).await;
            assert_eq!(pair.open_result(first).await.status, OpenStatus::Ok);
            assert_eq!(pair.open_result(second).await.status, OpenStatus::Ok);
            assert_eq!(pair.entry.live_streams(), 2);

            // Both directions move on both streams.
            first_target
                .write_all(b"first")
                .await
                .expect("the first target writes");
            second_target
                .write_all(b"second")
                .await
                .expect("the second target writes");
            let mut seen_first = Vec::new();
            let mut seen_second = Vec::new();
            while seen_first.len() < 5 || seen_second.len() < 6 {
                if let SessionEvent::Data {
                    stream_id, payload, ..
                } = pair.next().await
                {
                    if stream_id == first {
                        seen_first.extend_from_slice(&payload);
                    } else if stream_id == second {
                        seen_second.extend_from_slice(&payload);
                    }
                }
            }
            assert_eq!(seen_first, b"first");
            assert_eq!(seen_second, b"second");

            // Resetting one stream tears its socket down and leaves the other.
            pair.node
                .send_reset(first, ResetReason::Canceled)
                .expect("the reset must queue");
            let closed = soon(
                "the first target to see the close",
                first_target.read(&mut [0u8; 8]),
            )
            .await
            .expect("the read must not fail");
            assert_eq!(closed, 0, "the reset stream's socket must be closed");

            assert_eq!(
                pair.node
                    .send_data(second, b"unaffected")
                    .expect("the second stream still has credit"),
                b"unaffected".len()
            );
            let mut echoed = vec![0u8; b"unaffected".len()];
            soon(
                "the second target to read the reply",
                second_target.read_exact(&mut echoed),
            )
            .await
            .expect("the second stream must still carry bytes");
            assert_eq!(echoed, b"unaffected");
        })
        .await;
    }

    /// Section 8: an event for a stream nobody owns is reset, never dialled.
    #[tokio::test]
    async fn an_unknown_stream_id_is_reset_and_never_dialled() {
        within(async {
            let (listener, port) = bind_listener().await;
            let mut pair = pair(vec![loopback_rule()]).await;
            // A stream the Hub never opened, with a well-formed `Fin` at offset 0.
            let unknown = 9_999;
            pair.node
                .send_control(
                    MessageKind::Fin,
                    FinFields {
                        stream_id: unknown,
                        final_offset: 0,
                    }
                    .to_canonical(),
                )
                .expect("the Fin must queue");

            let reset = soon("a reset for the unknown stream", async {
                loop {
                    if let SessionEvent::Reset(fields) = pair.next().await {
                        if fields.stream_id == unknown {
                            return fields;
                        }
                    }
                }
            })
            .await;
            assert_eq!(reset.reason, ResetReason::ProtocolError);
            assert_eq!(pair.entry.handle.stream_count(), 0);
            assert_eq!(pair.entry.live_streams(), 0);
            // No dial: the listener is still waiting for its first connection.
            let idle = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            assert!(idle.is_err(), "an unknown stream must not dial: {idle:?}");

            // An unknown stream's `Data` is refused by the engine before it can
            // reach the Hub at all, and is not an unauthenticated record either.
            pair.node
                .send_data(unknown + 2, b"for a stream nobody opened")
                .expect_err("the engine must refuse an unknown stream");
            let _ = port;
        })
        .await;
    }
}
