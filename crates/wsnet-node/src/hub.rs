//! One hub session: authentication, carriers, and the `Open` path.
//!
//! This module is where DESIGN.md sections 5.1 to 5.3 and 5.5 become code:
//!
//! * the `Auth`/`AuthOk` exchange of section 5.1 runs over the transport's
//!   bootstrap, and the `AuthOk` MAC is verified against the *offered* candidate
//!   before any key exists, so a response for a losing candidate is refused
//!   (section 6.7);
//! * the session keys are derived from both canonical halves (section 4.2), so
//!   the node and the Hub agree without either sending a key;
//! * `Hello` publishes the locally configured `[[services]]` and `HelloOk` is the
//!   business barrier (section 5.3) —an `Open` before it is refused rather than
//!   half-installed;
//! * a business `Open` is arbitrated by [`OperationTable`] on the caller side
//!   (section 5.2), so a retried `request_id` is answered from the cache instead
//!   of dialling a second target.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, info, warn};

use wsnet_crypto::Psk;
use wsnet_limits::{HANDSHAKE_TIMEOUT_MS, OPERATION_OPEN_TIMEOUT_SECS};
use wsnet_operation::{Admit, OperationConfig, OperationHash, OperationTable, Outcome};
use wsnet_protocol::{Canonical, PROTOCOL_VERSION};
use wsnet_routing::{Destination, Proto};
use wsnet_session::{
    auth_mac, fresh_attempt_id, fresh_nonce, fresh_session_id, session_keys, verify_authok,
    AuthFields, HelloFields, OpenFields, OpenResultFields, OpenStatus, ResetReason,
    ServiceRegistration, Session, SessionConfig, SessionEvent, SessionHandle, SessionState, Side,
};
use wsnet_protocol::{MessageKind, Record};

use crate::carrier::CarrierIo;
use crate::endpoint::{BoundSession, HubEndpoint, HubTransport};
use crate::health::HealthTracker;
use crate::inbound::{self, InboundPolicy};
use crate::node::NodeError;
use crate::select::ServiceDirectory;
use crate::stream::{SessionStream, StreamMsg};
use crate::{lock, now_ms, unix_seconds};

/// How long one bounded health round trip may take (DESIGN.md section 5.5).
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Everything the hub session asks its driver to do.
enum Command {
    /// Establish one stream.
    Open {
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
        request_id: [u8; 16],
        reply: oneshot::Sender<Result<SessionStream, NodeError>>,
    },
    /// Stop the driver and release every carrier.
    Close,
}

/// One stream the driver is tracking.
struct StreamSlot {
    tx: mpsc::UnboundedSender<StreamMsg>,
    stream: Option<SessionStream>,
    reply: Option<oneshot::Sender<Result<SessionStream, NodeError>>>,
    request_id: [u8; 16],
}

/// One live client session with a Hub.
pub struct HubSession {
    endpoint: HubEndpoint,
    handle: SessionHandle,
    commands: mpsc::UnboundedSender<Command>,
    directory: Arc<Mutex<ServiceDirectory>>,
    operations: Arc<Mutex<OperationTable>>,
    health: Arc<Mutex<HealthTracker>>,
    gone: Arc<Notify>,
    closed: Arc<AtomicBool>,
    transport: Arc<dyn HubTransport>,
    bound: BoundSession,
}

impl HubSession {
    /// Authenticates to `endpoint`, binds its carriers, and sends `Hello`.
    ///
    /// Returns while the session is still in `HelloPending`: DESIGN.md section
    /// 5.3 makes `HelloOk` the business barrier, and a caller that wants the
    /// barrier to have lifted calls [`HubSession::wait_ready`]. Splitting the two
    /// is what lets an `Open` before `HelloOk` be tested for the refusal it must
    /// produce rather than merely for a timeout.
    ///
    /// # Errors
    ///
    /// A malformed `AuthOk`, a MAC that does not verify, or a transport failure
    /// aborts the session before any carrier is bound.
    pub async fn connect(
        endpoint: HubEndpoint,
        node_id: String,
        psk: Psk,
        services: Vec<ServiceRegistration>,
        inbound_policy: InboundPolicy,
        capabilities: Vec<String>,
        transport: Arc<dyn HubTransport>,
    ) -> Result<Arc<Self>, NodeError> {
        let auth = AuthFields {
            version: PROTOCOL_VERSION,
            hub_id: endpoint.hub_id.clone(),
            key_id: endpoint.key_id.clone(),
            node_id: node_id.clone(),
            attempt_id: fresh_attempt_id(),
            ts: unix_seconds(),
            nonce: fresh_nonce(),
            capabilities: capabilities.clone(),
        };
        let offered_mac = auth_mac(&psk, &auth);
        // Sections 4.3 and 4.4: the bootstrap is an `Auth` *record*, carried in
        // the same framing as every other message. Sending bare metadata here
        // would be rejected as a malformed batch, because the Hub decodes the
        // body with the ordinary record path before it looks at the kind.
        let request = Record::new(MessageKind::Auth, auth.to_canonical(&offered_mac))
            .encode()
            .map_err(|error| NodeError::Hub {
                hub_id: endpoint.hub_id.clone(),
                detail: format!("cannot encode the Auth record: {error}"),
            })?;

        let response = tokio::time::timeout(
            Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
            transport.authenticate(request),
        )
        .await
        .map_err(|_| NodeError::Hub {
            hub_id: endpoint.hub_id.clone(),
            detail: "the Auth bootstrap timed out".to_string(),
        })??;

        // The reply is an `AuthOk` record in the same framing.
        let reply = Record::decode(&response).map_err(|error| NodeError::Hub {
            hub_id: endpoint.hub_id.clone(),
            detail: format!("the Auth bootstrap reply is not a record: {error}"),
        })?;
        if reply.kind != MessageKind::AuthOk {
            return Err(NodeError::Hub {
                hub_id: endpoint.hub_id.clone(),
                detail: format!("expected AuthOk, got {}", reply.kind),
            });
        }
        // Section 6.7: a response for a losing candidate must not become the
        // owner of this session.
        let authok = verify_authok(&psk, &auth.attempt_id, &offered_mac, &reply.metadata)?;
        let keys = session_keys(&psk, &auth, &authok);
        let bound = BoundSession {
            hub_id: endpoint.hub_id.clone(),
            node_id: node_id.clone(),
            session_id: authok.session_id,
            session_epoch: authok.session_epoch,
            bind_key: *keys.bind_key(),
        };
        let config = SessionConfig::new(
            endpoint.hub_id.clone(),
            node_id,
            authok.session_id,
            authok.session_epoch,
            Side::Node,
        );
        let session = Session::new(config, keys);
        let handle = session.handle.clone();
        // Section 5.3 orders the lifecycle `Authenticating -> Binding ->
        // HelloPending`, and the driver only starts once the barrier state is
        // set, so a Hub that answers instantly cannot be observed as ready before
        // `Hello` was ever sent.
        handle.set_state(SessionState::Binding);

        let carriers = tokio::time::timeout(
            Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
            transport.bind(bound.clone()),
        )
        .await
        .map_err(|_| NodeError::Hub {
            hub_id: endpoint.hub_id.clone(),
            detail: "binding the carriers timed out".to_string(),
        })??;
        if carriers.is_empty() {
            return Err(NodeError::Carrier(
                "the transport bound no carrier; section 5.3 requires at least one".to_string(),
            ));
        }
        handle.set_state(SessionState::HelloPending);

        let directory = Arc::new(Mutex::new(ServiceDirectory::unknown()));
        let operations = Arc::new(Mutex::new(OperationTable::new(OperationConfig::default())));
        let health = Arc::new(Mutex::new(HealthTracker::new()));
        let gone = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));
        let (commands, command_rx) = mpsc::unbounded_channel();

        let (inbound, uplink) = Driver::merge_carriers(carriers);
        let driver = Driver {
            handle: handle.clone(),
            events: session.events,
            outbound: session.outbound,
            inbound,
            commands: command_rx,
            uplink,
            streams: HashMap::new(),
            services: services.clone(),
            policy: inbound_policy,
            directory: Arc::clone(&directory),
            operations: Arc::clone(&operations),
            gone: Arc::clone(&gone),
            closed: Arc::clone(&closed),
        };
        tokio::spawn(driver.run());

        handle.send_hello(&HelloFields {
            request_id: fresh_session_id(),
            services,
            capabilities,
        })?;

        info!(hub = %endpoint.hub_id, "wsnet hub session authenticated");
        Ok(Arc::new(HubSession {
            endpoint,
            handle,
            commands,
            directory,
            operations,
            health,
            gone,
            closed,
            transport,
            bound,
        }))
    }

    /// The Hub this session belongs to.
    pub fn hub_id(&self) -> &str {
        &self.endpoint.hub_id
    }

    /// The current session lifecycle state (DESIGN.md section 5.3).
    pub fn state(&self) -> SessionState {
        self.handle.state()
    }

    /// Whether the session may carry business traffic.
    pub fn is_ready(&self) -> bool {
        self.handle.is_ready()
    }

    /// Waits for the `HelloOk` barrier, or gives up.
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::HelloTimeout`] when the barrier never lifts and
    /// [`NodeError::CarrierClosed`] when the session ended first, so a caller can
    /// tell "slow Hub" from "dead Hub".
    pub async fn wait_ready(&self, limit: Duration) -> Result<(), NodeError> {
        let deadline = Instant::now() + limit;
        loop {
            if self.handle.is_ready() {
                return Ok(());
            }
            if self.closed.load(Ordering::SeqCst) {
                return Err(NodeError::CarrierClosed);
            }
            if Instant::now() >= deadline {
                return Err(NodeError::HelloTimeout);
            }
            // The driver wakes every waiter when it ends; the short timeout is
            // only there so a session that dies without notifying still fails.
            let _ = tokio::time::timeout(Duration::from_millis(20), self.gone.notified()).await;
        }
    }

    /// The services the Hub last advertised to this node.
    pub fn directory(&self) -> ServiceDirectory {
        lock(&self.directory).clone()
    }

    /// The current section 5.5 health verdict for this Hub.
    pub fn health(&self) -> HealthTracker {
        lock(&self.health).clone()
    }

    /// Records one health outcome, as the node's health loop does.
    pub fn record_health(&self, healthy: bool) {
        let mut tracker = lock(&self.health);
        match healthy {
            true => tracker.record_success(Instant::now()),
            false => tracker.record_failure(Instant::now()),
        }
    }

    /// Runs one bounded liveness round trip and records its outcome.
    pub async fn health_check(&self) -> Result<(), NodeError> {
        let outcome =
            tokio::time::timeout(HEALTH_TIMEOUT, self.transport.health(self.bound.clone()))
                .await
                .map_err(|_| NodeError::Hub {
                    hub_id: self.endpoint.hub_id.clone(),
                    detail: "the health check timed out".to_string(),
                })
                .and_then(|result| result);
        self.record_health(outcome.is_ok());
        outcome
    }

    /// Closes the session locally (DESIGN.md section 5.5).
    ///
    /// Existing streams fail explicitly; they are never migrated to another Hub.
    pub fn close(&self, reason: &str) {
        let _ = self.commands.send(Command::Close);
        self.handle.set_state(SessionState::Closed);
        debug!(hub = %self.endpoint.hub_id, reason, "hub session closed locally");
    }

    /// Opens one stream with a fresh `request_id`.
    pub async fn open(
        &self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
    ) -> Result<SessionStream, NodeError> {
        self.open_with_request_id(destination, proto, via, fresh_session_id())
            .await
    }

    /// Opens one stream under a caller-chosen `request_id` (DESIGN.md section 5.2).
    ///
    /// The same `request_id` presented twice is answered from the operation table
    /// the second time and never dials the target again.
    ///
    /// # Errors
    ///
    /// [`NodeError::NotReady`] before `HelloOk`, [`NodeError::OpenTimeout`] when
    /// no result arrives in the `Open` deadline, and [`NodeError::DuplicateOpen`]
    /// when the same `request_id` already opened a stream.
    pub async fn open_with_request_id(
        &self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
        request_id: [u8; 16],
    ) -> Result<SessionStream, NodeError> {
        // Section 5.3: `HelloOk` is the business barrier, so a stream is refused
        // here rather than sent and reset by the peer.
        if !self.handle.is_ready() {
            return Err(NodeError::NotReady);
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(NodeError::CarrierClosed);
        }
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Open {
                destination,
                proto,
                via,
                request_id,
                reply,
            })
            .map_err(|_| NodeError::CarrierClosed)?;
        match tokio::time::timeout(Duration::from_secs(OPERATION_OPEN_TIMEOUT_SECS), answer).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(NodeError::CarrierClosed),
            Err(_) => Err(NodeError::OpenTimeout),
        }
    }

    /// Pulls the current run of pending operations forward, retiring expired ids.
    ///
    /// Section 5.2 requires a window, so the node ticks the table periodically
    /// rather than letting records accumulate without bound.
    pub fn tick_operations(&self) {
        let _ = lock(&self.operations).tick(now_ms());
    }
}

/// The per-session event loop: carriers in, carriers out, streams dispatched.
struct Driver {
    handle: SessionHandle,
    events: mpsc::UnboundedReceiver<SessionEvent>,
    outbound: mpsc::UnboundedReceiver<Vec<u8>>,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    commands: mpsc::UnboundedReceiver<Command>,
    uplink: Option<mpsc::UnboundedSender<Vec<u8>>>,
    streams: HashMap<u64, StreamSlot>,
    /// Services this node publishes, as registered in its `Hello`.
    ///
    /// The same list is what an inbound `ServiceTarget` resolves against, so what
    /// a caller can reach and what this node will dial cannot drift apart.
    services: Vec<ServiceRegistration>,
    /// What an inbound `Open` may reach beyond those services.
    policy: InboundPolicy,
    directory: Arc<Mutex<ServiceDirectory>>,
    operations: Arc<Mutex<OperationTable>>,
    gone: Arc<Notify>,
    closed: Arc<AtomicBool>,
}

/// What woke the driver loop.
enum Wake {
    Command(Option<Command>),
    Inbound(Option<Vec<u8>>),
    Outbound(Option<Vec<u8>>),
    Event(Option<SessionEvent>),
}

impl Driver {
    /// Fans every carrier's inbound channel into one queue and picks the uplink.
    ///
    /// One merged queue is what lets the driver use a single `select`, and it is
    /// also what makes "all carriers are gone" a single, observable `None`. The
    /// uplink is the first carrier that is allowed to carry client-to-server
    /// data; every other outbound half is dropped here, so a downlink-only
    /// carrier can never be drained into an uplink request (section 6.1).
    fn merge_carriers(
        carriers: Vec<CarrierIo>,
    ) -> (
        mpsc::UnboundedReceiver<Vec<u8>>,
        Option<mpsc::UnboundedSender<Vec<u8>>>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut uplink = None;
        for io in carriers {
            let CarrierIo {
                kind,
                mut inbound,
                outbound,
            } = io;
            let forward = tx.clone();
            tokio::spawn(async move {
                while let Some(envelope) = inbound.recv().await {
                    if forward.send(envelope).is_err() {
                        break;
                    }
                }
            });
            debug!(carrier = kind.name(), "carrier bound");
            if kind.is_uplink_capable() && uplink.is_none() {
                uplink = Some(outbound);
            }
        }
        drop(tx);
        (rx, uplink)
    }

    async fn run(mut self) {
        loop {
            let wake = tokio::select! {
                command = self.commands.recv() => Wake::Command(command),
                envelope = self.inbound.recv() => Wake::Inbound(envelope),
                envelope = self.outbound.recv() => Wake::Outbound(envelope),
                event = self.events.recv() => Wake::Event(event),
            };
            match wake {
                Wake::Command(None) => break,
                Wake::Command(Some(Command::Close)) => {
                    // Section 5.5: a deliberate local close is *announced*. If the
                    // loop merely stopped, the Hub would keep this node's lease and
                    // its service registrations until the session's TTL expired, so
                    // a service this node took out of service would still be
                    // advertised by the directory and still be selected by other
                    // nodes' `Open`s — which would then never be answered.
                    if let Err(error) = self.handle.send_bye("closed locally") {
                        debug!(
                            hub = %self.handle.config().hub_id,
                            %error,
                            "cannot announce the close to the hub"
                        );
                    }
                    self.flush_uplink();
                    break;
                }
                Wake::Command(Some(Command::Open {
                    destination,
                    proto,
                    via,
                    request_id,
                    reply,
                })) => self.begin_open(destination, proto, via, request_id, reply),
                Wake::Inbound(None) => {
                    debug!(hub = %self.handle.config().hub_id, "every carrier ended");
                    break;
                }
                Wake::Inbound(Some(envelope)) => {
                    if !self.handle.feed_lossy(&envelope) {
                        // A forged or malformed envelope is counted, not ignored:
                        // the session stays up, because a lossy carrier is
                        // allowed to deliver a duplicate but never a forgery.
                        warn!(hub = %self.handle.config().hub_id, "discarded an envelope that did not authenticate");
                    }
                }
                Wake::Outbound(None) => break,
                Wake::Outbound(Some(envelope)) => self.send_uplink(envelope),
                Wake::Event(None) => break,
                Wake::Event(Some(event)) => self.on_event(event),
            }
        }
        self.handle.set_state(SessionState::Closed);
        self.closed.store(true, Ordering::SeqCst);
        self.gone.notify_waiters();
    }

    /// Moves everything the engine has queued to the uplink carrier.
    ///
    /// The driver stops draining `outbound` as soon as it breaks, so the terminal
    /// `Bye` has to be pushed out explicitly; otherwise it dies in the channel and
    /// the Hub never learns the session ended.
    fn flush_uplink(&mut self) {
        while let Ok(envelope) = self.outbound.try_recv() {
            self.send_uplink(envelope);
        }
    }

    /// Hands one sealed envelope to the uplink carrier.
    fn send_uplink(&self, envelope: Vec<u8>) {
        match &self.uplink {
            Some(uplink) => {
                if uplink.send(envelope).is_err() {
                    debug!(hub = %self.handle.config().hub_id, "the uplink carrier is gone");
                }
            }
            // Section 6.1 forbids sending uplink data over SSE, and there is no
            // other carrier, so the envelope is dropped rather than misrouted.
            None => debug!(
                hub = %self.handle.config().hub_id,
                "no uplink-capable carrier; dropping an outbound envelope"
            ),
        }
    }

    /// Arbitrates one `Open` against the operation table, then dials (section 5.2).
    fn begin_open(
        &mut self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
        request_id: [u8; 16],
        reply: oneshot::Sender<Result<SessionStream, NodeError>>,
    ) {
        // Advance the idempotency window before admitting new work, so settled
        // records are retired instead of accumulating (DESIGN.md section 5.2).
        let _ = lock(&self.operations).tick(now_ms());
        let hash = OperationHash::of(&operation_bytes(&destination, proto, &via));
        let admitted = lock(&self.operations).begin(request_id, hash, now_ms());
        match admitted {
            Ok(Admit::Execute) => {}
            Ok(Admit::AlreadyPending) => {
                let _ = reply.send(Err(NodeError::OpenPending));
                return;
            }
            Ok(Admit::Cached(outcome)) => {
                let _ = reply.send(Err(cached_outcome_error(request_id, outcome)));
                return;
            }
            Err(error) => {
                let _ = reply.send(Err(NodeError::Operation(error)));
                return;
            }
        }

        match self.handle.open(destination, via, proto, request_id) {
            Ok((stream_id, _)) => {
                let (tx, rx) = mpsc::unbounded_channel();
                let stream = SessionStream::new(self.handle.clone(), stream_id, rx);
                self.streams.insert(
                    stream_id,
                    StreamSlot {
                        tx,
                        stream: Some(stream),
                        reply: Some(reply),
                        request_id,
                    },
                );
            }
            Err(error) => {
                self.settle(request_id, Outcome::Failed(error.to_string().into_bytes()));
                let _ = reply.send(Err(NodeError::Session(error)));
            }
        }
    }

    /// Settles one operation-table record.
    fn settle(&self, request_id: [u8; 16], outcome: Outcome) {
        let _ = lock(&self.operations).settle(request_id, outcome, now_ms());
    }

    /// Handles an inbound `Open` relayed by the Hub (DESIGN.md sections 7.1, 7.6).
    ///
    /// The stream is registered before the task starts, so a `Data` record can
    /// never arrive for a stream whose socket is not yet being pumped. Two outcomes
    /// are possible: this node is the exit and dials, or it is a hop of a chain and
    /// has to open the next leg on this same session.
    fn on_inbound_open(&mut self, fields: OpenFields) {
        if self.streams.contains_key(&fields.stream_id) {
            // Section 4.2 forbids reusing a stream id, so a second `Open` for a
            // live stream is a protocol error rather than a second dial.
            let _ = self
                .handle
                .send_reset(fields.stream_id, ResetReason::ProtocolError);
            return;
        }

        let node_id = self.handle.config().node_id.clone();
        let plan = match inbound::plan_inbound(&node_id, &self.services, &self.policy, &fields) {
            Ok(plan) => plan,
            Err(refusal) => {
                debug!(
                    stream = fields.stream_id,
                    status = ?refusal.status,
                    reason = %refusal.detail,
                    "refusing an inbound open"
                );
                let result = OpenResultFields {
                    request_id: fields.request_id,
                    stream_id: fields.stream_id,
                    status: refusal.status,
                    detail: refusal.detail,
                };
                let _ = self.handle.send_open_result(&result);
                return;
            }
        };

        let (tx, rx) = mpsc::unbounded_channel();
        self.streams.insert(
            fields.stream_id,
            StreamSlot {
                tx,
                stream: None,
                reply: None,
                request_id: fields.request_id,
            },
        );

        match plan {
            inbound::InboundPlan::Dial(target) => {
                let handle = self.handle.clone();
                tokio::spawn(inbound::serve_inbound(
                    handle,
                    fields.request_id,
                    fields.stream_id,
                    target,
                    rx,
                ));
            }
            inbound::InboundPlan::Forward => {
                self.relay_chain_leg(fields, rx);
            }
        }
    }

    /// Opens the next leg of a chain on this session and bridges the two halves.
    ///
    /// Section 7.1 keeps a chain on one Hub, so the next leg is opened on *this*
    /// session rather than through Hub selection: choosing a Hub here could move
    /// the chain somewhere the caller's ACL never permitted. The leg carries the
    /// destination and the hops still to run, so the Hub authorises the next edge
    /// exactly as it authorised this one.
    fn relay_chain_leg(&mut self, fields: OpenFields, inbound_rx: mpsc::UnboundedReceiver<StreamMsg>) {
        let leg = inbound::ChainLeg {
            destination: fields.destination.clone(),
            via: fields.via.clone(),
            proto: fields.proto,
        };
        let request_id = fields.request_id;
        let stream_id = fields.stream_id;

        // The next leg goes through the ordinary `Open` path, so it gets the same
        // operation-table idempotency and open deadline as any other flow.
        let (reply, answer) = oneshot::channel();
        let next_request = fresh_session_id();
        self.begin_open(
            leg.destination.clone(),
            leg.proto,
            leg.via.clone(),
            next_request,
            reply,
        );

        let handle = self.handle.clone();
        let inbound = SessionStream::new(handle.clone(), stream_id, inbound_rx);
        tokio::spawn(async move {
            match answer.await {
                Ok(Ok(next)) => {
                    inbound::relay_leg(handle, request_id, stream_id, inbound, next).await;
                }
                Ok(Err(error)) => {
                    // The next leg could not be opened, so the caller's `Open` is
                    // answered with that failure instead of a stream that does not
                    // exist. Section 9.1 keeps the reason local; the status is what
                    // the caller needs.
                    debug!(%stream_id, %error, "the next chain leg could not be opened");
                    let result = OpenResultFields {
                        request_id,
                        stream_id,
                        status: match error {
                            NodeError::OpenFailed { status, .. } => status,
                            _ => OpenStatus::Unreachable,
                        },
                        detail: "the next hop of the chain refused the stream".to_string(),
                    };
                    let _ = handle.send_open_result(&result);
                }
                Err(_) => {
                    debug!(%stream_id, "the driver ended before the next leg was opened");
                }
            }
        });
    }

    fn on_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::Open(fields) => self.on_inbound_open(fields),
            SessionEvent::OpenResult(fields) => self.on_open_result(fields),
            SessionEvent::Ready(fields) => {
                debug!(stream = fields.stream_id, "stream is ready");
            }
            SessionEvent::Data {
                stream_id, payload, ..
            } => self.deliver(stream_id, StreamMsg::Data(payload)),
            SessionEvent::Fin(fields) => {
                self.deliver(fields.stream_id, StreamMsg::Fin(fields.final_offset));
            }
            SessionEvent::Reset(fields) => {
                self.deliver(fields.stream_id, StreamMsg::Reset(fields.reason));
            }
            SessionEvent::Progress(fields) => {
                self.deliver(fields.stream_id, StreamMsg::Credit);
            }
            SessionEvent::Datagram { metadata, payload } => {
                // Section 4.1 puts the route in the datagram's own metadata, so a
                // record with an unreadable one belongs to no route and is dropped
                // rather than guessed at (section 7.4 drops an unmapped datagram).
                match wsnet_session::DatagramFields::from_canonical(&metadata) {
                    Ok(fields) => {
                        self.deliver(fields.stream_id, StreamMsg::Datagram(Box::new(fields), payload));
                    }
                    Err(error) => {
                        debug!(%error, "dropping a datagram with unreadable metadata");
                    }
                }
            }
            SessionEvent::PeerList(value) => {
                let mut directory = lock(&self.directory);
                // Section 8: a snapshot that is not newer is dropped, so a
                // retransmitted old one cannot resurrect a withdrawn service.
                if !directory.apply_peer_list(&value) {
                    debug!(
                        hub = %self.handle.config().hub_id,
                        "ignored a peer list that is not newer than the applied one"
                    );
                    return;
                }
                debug!(
                    hub = %self.handle.config().hub_id,
                    services = directory.len(),
                    "hub peer list received"
                );
            }
            SessionEvent::Ping => {
                let _ = self.handle.send_pong();
            }
            SessionEvent::Bye(fields) => {
                debug!(hub = %self.handle.config().hub_id, reason = %fields.reason, "hub closed the session");
            }
            SessionEvent::Hello(fields) => {
                debug!(
                    services = fields.services.len(),
                    "unexpected Hello on a client session"
                );
            }
            SessionEvent::Dropped { packet_no } => {
                debug!(packet_no, "dropped a replayed envelope");
            }
            SessionEvent::StateChanged(state) => {
                debug!(hub = %self.handle.config().hub_id, ?state, "session state changed");
            }
            _ => {}
        }
    }

    /// Forwards one stream message, forgetting a stream whose owner is gone.
    fn deliver(&mut self, stream_id: u64, message: StreamMsg) {
        let Some(slot) = self.streams.get(&stream_id) else {
            return;
        };
        if slot.tx.send(message).is_err() {
            self.streams.remove(&stream_id);
        }
    }

    /// Releases an `Open` once its result arrives (DESIGN.md section 7.1).
    fn on_open_result(&mut self, fields: wsnet_session::OpenResultFields) {
        let Some(mut slot) = self.streams.remove(&fields.stream_id) else {
            return;
        };
        if fields.status == OpenStatus::Ok {
            self.settle(slot.request_id, Outcome::Complete(Vec::new()));
            if let Some(reply) = slot.reply.take() {
                let answer = match slot.stream.take() {
                    Some(stream) => Ok(stream),
                    None => Err(NodeError::CarrierClosed),
                };
                let _ = reply.send(answer);
            }
            self.streams.insert(fields.stream_id, slot);
            return;
        }

        self.settle(
            slot.request_id,
            Outcome::Failed(fields.detail.clone().into_bytes()),
        );
        self.handle.close_stream(fields.stream_id);
        if let Some(reply) = slot.reply.take() {
            let _ = reply.send(Err(NodeError::OpenFailed {
                status: fields.status,
                detail: fields.detail,
            }));
        }
        // Dropping the slot closes the stream channel, so a reader parked on the
        // stream sees the end rather than waiting for a stream that never opened.
    }
}

/// The bytes hashed into the operation identity (DESIGN.md section 5.2).
fn operation_bytes(destination: &Destination, proto: Proto, via: &[String]) -> Vec<u8> {
    Canonical::object([
        ("destination", destination.to_canonical()),
        ("proto", Canonical::str(proto.as_str())),
        (
            "via",
            Canonical::Array(
                via.iter()
                    .map(|hop| Canonical::str(hop.clone()))
                    .collect::<Vec<_>>(),
            ),
        ),
    ])
    .to_bytes()
}

/// Turns a cached operation outcome into the refusal a retry must observe.
pub(crate) fn cached_outcome_error(request_id: [u8; 16], outcome: Outcome) -> NodeError {
    match outcome {
        // A stream cannot be shared with a retry, so a successful cached open is
        // reported as a duplicate rather than silently dialling again.
        Outcome::Complete(_) => NodeError::DuplicateOpen {
            request_id: hex::encode(request_id),
        },
        Outcome::Failed(bytes) => NodeError::CachedFailure {
            detail: String::from_utf8_lossy(&bytes).into_owned(),
        },
    }
}
