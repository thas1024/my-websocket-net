#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Local Forward listeners: binding, lifecycle, and the TCP accept path.
//!
//! Local Forward is the design's formal entry point for identity-shaped reverse
//! access (DESIGN.md section 7.6): a local TCP or UDP listener whose remote target
//! is fixed by configuration, so an application never has to express "node X's
//! service Y" through SOCKS5, which cannot carry it (USAGE.md section 4).
//!
//! The rules this crate implements, and where each one comes from:
//!
//! * one TCP accept creates exactly one independent remote `Open`, and no byte
//!   reaches the local socket before that `Open` succeeded (USAGE.md section 7
//!   steps 1-4). A generic TCP forward never fabricates an HTTP response.
//! * the listener lifecycle of USAGE.md section 7 is observable and separate
//!   from the remote state; `OFFLINE` and `DENIED` fast-fail new connections and
//!   never fall back to a direct connection.
//! * `listen = "127.0.0.1:0"` reports the OS-assigned port and a duplicate name
//!   or duplicate resolved listen address is rejected atomically (USAGE.md
//!   section 12, DESIGN.md T21).
//! * a non-loopback listener without an explicit `allow_from` CIDR list is
//!   refused at startup rather than bound (DESIGN.md section 7.6, USAGE.md
//!   section 12).
//! * the UDP listener keeps one bounded association per local source tuple
//!   (USAGE.md section 9); see [`udp`].

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ipnet::IpNet;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use wsnet_limits::OPERATION_OPEN_TIMEOUT_SECS;
use wsnet_routing::{is_slug, validate_chain, Destination, DestinationError, Proto, RouteError};

pub mod udp;

pub use udp::{
    UdpAssociationStats, UdpAssociationTable, UdpDisposition, UdpForwardListener, UdpForwardOpener,
    UdpLimits, UdpSession, UdpSweep,
};

/// How many local connection outcomes one forward keeps for diagnostics.
///
/// DESIGN.md section 7.6 keeps a listener usable after a remote failure and
/// USAGE.md section 7 step 4 requires the reason to be available locally, so a
/// bounded history is kept instead of an unbounded log that a failing remote
/// could grow without limit.
const EVENT_HISTORY: usize = 64;

/// The chain validator needs the calling node id to detect a self-loop, and this
/// crate is never told the local node id.
///
/// Passing the empty string is safe: an empty hop id is not a slug, so
/// `validate_chain` already rejects it, which means no hop can be mistaken for
/// the caller. Every other rule of USAGE.md section 5.3 (hop count, duplicate
/// hops, slug shape, publisher named as a hop) still applies.
const LOCAL_CALLER: &str = "";

/// Anything that can carry a forwarded byte stream.
///
/// This is the seam the `Open` implementation plugs into: the transport chooses
/// how a stream is carried, and the listener only needs a duplex object.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A boxed [`Duplex`], handed back by a successful [`ForwardOpener::open`].
pub type BoxDuplex = Box<dyn Duplex>;

/// A boxed future, so a [`ForwardOpener`] can stay object safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How the listener actually reaches its destination.
///
/// The listener owns no routing policy: it hands the strict `Open` destination
/// (DESIGN.md section 7.6) plus the intermediate `via` hops to the opener, which
/// is where Hub selection, ACL evaluation, and the real `OpenResult`/`Ready`
/// exchange happen.
pub trait ForwardOpener: Send + Sync + 'static {
    /// Opens one remote flow for `destination`.
    ///
    /// The returned stream must not be considered usable until this future
    /// resolves successfully, which is what USAGE.md section 7 step 2-3 means by
    /// "warten auf OpenResult und Ready, dann weiterleiten".
    fn open(
        &self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
    ) -> BoxFuture<'static, Result<BoxDuplex, ForwardError>>;
}

/// Errors from Local Forward validation, binding, and connection setup.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    /// A forward with this name already exists; the map is unchanged.
    #[error("a forward named `{name}` already exists")]
    DuplicateName {
        /// The rejected name.
        name: String,
    },
    /// The listen address is already held by another forward.
    #[error("listen address {listen} is already used by forward `{name}`")]
    DuplicateListen {
        /// The resolved address that collided.
        listen: SocketAddr,
        /// The forward that already holds it.
        name: String,
    },
    /// The forward name is not usable as a stable local label.
    #[error("`{name}` is not a normalised ASCII slug")]
    InvalidName {
        /// The rejected name.
        name: String,
    },
    /// The `listen` value could not be turned into a local address.
    #[error("`{listen}` is not a usable listen address: {reason}")]
    InvalidListen {
        /// The rejected text.
        listen: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A `allow_from` entry is not a CIDR.
    #[error("`{value}` is not a valid CIDR")]
    InvalidAllowFrom {
        /// The rejected text.
        value: String,
    },
    /// A non-loopback listener was configured without an explicit allowlist.
    #[error("listen address {listen} is not loopback, so an explicit allow_from CIDR list is required")]
    AllowListRequired {
        /// The address that was refused before binding.
        listen: SocketAddr,
    },
    /// The `hub` field is neither `auto` nor a hub id.
    #[error("hub `{hub}` is neither `auto` nor a hub id")]
    InvalidHub {
        /// The rejected text.
        hub: String,
    },
    /// No forward with this name is known.
    #[error("no forward named `{name}`")]
    UnknownForward {
        /// The requested name.
        name: String,
    },
    /// The destination is not a valid `Open` target.
    #[error("destination is not valid: {source}")]
    InvalidDestination {
        /// The routing crate's verdict.
        #[from]
        source: DestinationError,
    },
    /// The `via` chain is not valid.
    #[error("via chain is not valid: {source}")]
    InvalidChain {
        /// The routing crate's verdict.
        #[from]
        source: RouteError,
    },
    /// Binding the local socket failed.
    #[error("binding `{listen}` failed: {source}")]
    Bind {
        /// The requested listen text.
        listen: String,
        /// The OS error.
        source: io::Error,
    },
    /// The opener could not complete the remote `Open`.
    ///
    /// USAGE.md section 7 step 4: the local connection is closed and the reason
    /// is reported locally; nothing is invented for the application.
    #[error("remote open failed: {reason}")]
    RemoteOpen {
        /// A local-only, log-safe explanation.
        reason: String,
    },
    /// The publisher or service is not online.
    #[error("forward target is offline: {reason}")]
    Offline {
        /// A local-only, log-safe explanation.
        reason: String,
    },
    /// The ACL refused the flow.
    #[error("forward target is denied: {reason}")]
    Denied {
        /// A local-only, log-safe explanation.
        reason: String,
    },
    /// A UDP forward was added but no [`UdpForwardOpener`] is configured.
    #[error("UDP local forward requires a UdpForwardOpener, and none is configured")]
    UdpOpenerMissing,
    /// UDP association bookkeeping refused the datagram.
    #[error("UDP association refused the datagram: {reason}")]
    UdpAssociation {
        /// A local-only, log-safe explanation.
        reason: String,
    },
}

impl ForwardError {
    /// The lifecycle verdict this error carries, when it is a stable verdict.
    ///
    /// Only `OFFLINE` and `DENIED` are verdicts about the forward itself
    /// (USAGE.md section 7 table). Everything else is a transient failure that
    /// must not move the observable state, because the design keeps the listener
    /// `BOUND` while the remote side is being repaired.
    pub fn lifecycle_state(&self) -> Option<ForwardState> {
        match self {
            ForwardError::Offline { .. } => Some(ForwardState::Offline),
            ForwardError::Denied { .. } => Some(ForwardState::Denied),
            _ => None,
        }
    }
}

/// The lifecycle of one forward (USAGE.md section 7 table).
///
/// The local listener state is deliberately separate from the remote state: a
/// bound socket proves nothing about the far side, and DESIGN.md section 7.6
/// keeps the listener `BOUND` after a remote failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardState {
    /// The local socket is bound; the remote path is not known to work yet.
    Bound,
    /// The selected Hub sees the publisher/service and the ACL allows the flow.
    Ready,
    /// The Hub or a carrier is unhealthy while a same-Hub recovery window is open.
    Degraded,
    /// The publisher or service is not online; new connections fast-fail.
    Offline,
    /// The ACL refused the flow; a denied forward never falls back to direct.
    Denied,
    /// A local bind or configuration error.
    Error,
}

impl ForwardState {
    /// The spelling used by the CLI state table (USAGE.md section 7).
    pub const fn as_str(self) -> &'static str {
        match self {
            ForwardState::Bound => "BOUND",
            ForwardState::Ready => "READY",
            ForwardState::Degraded => "DEGRADED",
            ForwardState::Offline => "OFFLINE",
            ForwardState::Denied => "DENIED",
            ForwardState::Error => "ERROR",
        }
    }

    /// Whether a new connection may reach the opener in this state.
    ///
    /// USAGE.md section 7 makes `OFFLINE` fast-fail new connections and DESIGN.md
    /// section 10 forbids turning a missing target or a missing ACL into a direct
    /// connection, and `DENIED` is exactly that case. `ERROR` is a local failure,
    /// so forwarding through it would be a report of success the node cannot back.
    pub const fn allows_open(self) -> bool {
        matches!(
            self,
            ForwardState::Bound | ForwardState::Ready | ForwardState::Degraded
        )
    }
}

impl fmt::Display for ForwardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One Local Forward as configured or added through the local control API.
///
/// The field set mirrors the `[[forwards]]` example of USAGE.md section 5.1 so a
/// static config and a dynamic `forward add` produce the same internal target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSpec {
    /// Stable local label; also the key for add, remove, state, and list.
    pub name: String,
    /// Listener address in `host:port` form; port 0 asks the OS to choose one.
    pub listen: String,
    /// Stream or datagram protocol of the forwarded flow.
    pub proto: Proto,
    /// `"auto"` or a hub id (DESIGN.md section 8 hub selection).
    ///
    /// The manager validates and exposes this field but does not act on it: the
    /// required [`ForwardOpener::open`] signature carries no hub, so hub choice
    /// belongs to the opener that owns the sessions.
    pub hub: String,
    /// Intermediate nodes only; for a named service the publisher is the final
    /// leg and must not be repeated here (USAGE.md section 5.3).
    pub via: Vec<String>,
    /// The strict `Open` destination (DESIGN.md section 7.6).
    pub destination: Destination,
    /// Source CIDRs allowed to use the listener.
    ///
    /// Required and enforced when `listen` is not loopback (DESIGN.md section
    /// 7.6, USAGE.md section 12). When it is empty on a loopback listener the
    /// bind address itself is the allowlist.
    pub allow_from: Vec<String>,
}

impl ForwardSpec {
    /// Builds a spec with the defaults of USAGE.md section 5.1: `hub = "auto"`,
    /// no intermediate hops, and no explicit source allowlist.
    pub fn new(
        name: impl Into<String>,
        listen: impl Into<String>,
        proto: Proto,
        destination: Destination,
    ) -> Self {
        ForwardSpec {
            name: name.into(),
            listen: listen.into(),
            proto,
            hub: "auto".to_string(),
            via: Vec::new(),
            destination,
            allow_from: Vec::new(),
        }
    }

    /// Sets the Hub choice, `"auto"` or a hub id.
    pub fn with_hub(mut self, hub: impl Into<String>) -> Self {
        self.hub = hub.into();
        self
    }

    /// Sets the intermediate hops.
    pub fn with_via(mut self, via: Vec<String>) -> Self {
        self.via = via;
        self
    }

    /// Sets the source CIDR allowlist.
    pub fn with_allow_from(mut self, allow_from: Vec<String>) -> Self {
        self.allow_from = allow_from;
        self
    }
}

/// The outcome of one local connection attempt, kept for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardEvent {
    /// The local peer the event is about.
    pub peer: SocketAddr,
    /// What the manager did with the connection.
    pub outcome: ForwardOutcome,
}

/// What happened to one local connection (USAGE.md section 7 steps 1-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardOutcome {
    /// The remote `Open` succeeded and the two sockets were joined.
    Opened,
    /// The peer was outside `allow_from`, so the opener was never called.
    PeerRefused,
    /// The forward was offline, denied, or in error, so the connection fast-failed.
    FastFailed(ForwardState),
    /// The opener failed and the local connection was closed.
    OpenFailed(String),
    /// The joined connection ended; the payload is the copy error, if any.
    Closed(Option<String>),
}

/// A handle to one live forward.
///
/// The handle stays valid after the forward is removed, which is what lets the
/// caller watch the connections that were already established (USAGE.md section
/// 7 step 5: removal never resurrects or kills old sockets).
#[derive(Clone)]
pub struct ForwardHandle {
    entry: Arc<ForwardEntry>,
}

impl ForwardHandle {
    /// The configured name.
    pub fn name(&self) -> &str {
        &self.entry.spec.name
    }

    /// The actual bound address, including an OS-assigned port.
    pub fn listen_addr(&self) -> SocketAddr {
        self.entry.listen_addr
    }

    /// The current lifecycle state.
    pub fn state(&self) -> ForwardState {
        self.entry.state()
    }

    /// Overrides the lifecycle state, as the session or registry layer does when
    /// a lease, a service revision, or an ACL verdict changes (USAGE.md section
    /// 7, DESIGN.md section 5).
    pub fn set_state(&self, state: ForwardState) {
        self.entry.set_state(state);
    }

    /// The full specification this forward was added with.
    pub fn spec(&self) -> &ForwardSpec {
        &self.entry.spec
    }

    /// The fixed remote target.
    pub fn destination(&self) -> &Destination {
        &self.entry.spec.destination
    }

    /// How many remote `Open` attempts this listener started.
    pub fn open_attempts(&self) -> u64 {
        self.entry.open_attempts.load(Ordering::Relaxed)
    }

    /// The bounded local history of connection outcomes, oldest first.
    pub fn events(&self) -> Vec<ForwardEvent> {
        self.entry.events()
    }

    /// The most recent remote failure reason, if any.
    pub fn last_failure(&self) -> Option<String> {
        self.entry.last_failure()
    }
}

impl fmt::Debug for ForwardHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardHandle")
            .field("name", &self.entry.spec.name)
            .field("listen", &self.entry.listen_addr)
            .field("state", &self.entry.state())
            .field("destination", &self.entry.spec.destination)
            .finish()
    }
}

/// Binds and drives a set of Local Forward listeners.
///
/// `add` binds immediately, so a configuration error such as a duplicate listen
/// address or a non-loopback listener without an allowlist is reported before
/// anything is forwarded (USAGE.md section 12).
pub struct ForwardManager {
    opener: Arc<dyn ForwardOpener>,
    udp_opener: Option<Arc<dyn UdpForwardOpener>>,
    forwards: Mutex<BTreeMap<String, Arc<ForwardEntry>>>,
}

impl ForwardManager {
    /// Creates a manager that reaches remote targets through `opener`.
    pub fn new(opener: Arc<dyn ForwardOpener>) -> Self {
        ForwardManager {
            opener,
            udp_opener: None,
            forwards: Mutex::new(BTreeMap::new()),
        }
    }

    /// Configures the opener used by `Proto::Udp` forwards.
    ///
    /// A UDP forward without one is rejected by [`ForwardManager::add`] instead of
    /// silently dropping datagrams.
    pub fn with_udp_opener(mut self, opener: Arc<dyn UdpForwardOpener>) -> Self {
        self.udp_opener = Some(opener);
        self
    }

    /// Sets the opener used by `Proto::Udp` forwards.
    pub fn set_udp_opener(&mut self, opener: Arc<dyn UdpForwardOpener>) {
        self.udp_opener = Some(opener);
    }

    /// Validates `spec`, binds its listener, and registers it.
    ///
    /// A duplicate `name` or a duplicate resolved `listen` address is rejected
    /// before the socket is bound, so a rejected call leaves the manager exactly
    /// as it was (USAGE.md section 12, DESIGN.md T21).
    pub fn add(&mut self, spec: ForwardSpec) -> Result<ForwardHandle, ForwardError> {
        validate_spec(&spec)?;
        let desired = parse_listen(&spec.listen)?;
        if !desired.ip().is_loopback() && spec.allow_from.is_empty() {
            return Err(ForwardError::AllowListRequired { listen: desired });
        }
        let allow = parse_allow_from(&spec.allow_from)?;
        if spec.proto == Proto::Udp && self.udp_opener.is_none() {
            return Err(ForwardError::UdpOpenerMissing);
        }

        let mut forwards = lock(&self.forwards);
        if forwards.contains_key(&spec.name) {
            return Err(ForwardError::DuplicateName { name: spec.name });
        }
        if desired.port() != 0 {
            if let Some(holder) = forwards.values().find(|entry| entry.listen_addr == desired) {
                return Err(ForwardError::DuplicateListen {
                    listen: desired,
                    name: holder.spec.name.clone(),
                });
            }
        }

        let bound = bind_listener(spec.proto, desired)?;
        let listen_addr = local_addr(&bound).map_err(|source| ForwardError::Bind {
            listen: spec.listen.clone(),
            source,
        })?;
        // A port-0 bind can only collide with an address that was already known,
        // so this second check covers the address the OS actually handed out.
        if let Some(holder) = forwards
            .values()
            .find(|entry| entry.listen_addr == listen_addr)
        {
            return Err(ForwardError::DuplicateListen {
                listen: listen_addr,
                name: holder.spec.name.clone(),
            });
        }

        let entry = match bound {
            BoundListener::Tcp(listener) => Arc::new(ForwardEntry::tcp(spec, listen_addr, listener, allow)),
            BoundListener::Udp(socket) => {
                let udp_opener = self
                    .udp_opener
                    .clone()
                    .ok_or(ForwardError::UdpOpenerMissing)?;
                let listener = udp::UdpForwardListener::new(
                    socket,
                    udp_opener,
                    spec.destination.clone(),
                    spec.via.clone(),
                    UdpLimits::default(),
                )
                .map_err(|source| ForwardError::Bind {
                    listen: listen_addr.to_string(),
                    source,
                })?;
                Arc::new(ForwardEntry::udp(spec, listen_addr, Arc::new(listener), allow))
            }
        };
        let handle = ForwardHandle {
            entry: Arc::clone(&entry),
        };
        info!(
            forward = %entry.spec.name,
            listen = %listen_addr,
            proto = entry.spec.proto.as_str(),
            "local forward bound"
        );
        forwards.insert(entry.spec.name.clone(), entry);
        Ok(handle)
    }

    /// The actual bound address of `name`, including an OS-assigned port.
    pub fn listen_addr(&self, name: &str) -> Option<SocketAddr> {
        lock(&self.forwards).get(name).map(|entry| entry.listen_addr)
    }

    /// The current lifecycle state of `name`.
    pub fn state(&self, name: &str) -> Option<ForwardState> {
        lock(&self.forwards).get(name).map(|entry| entry.state())
    }

    /// Overrides the lifecycle state of `name`.
    pub fn set_state(&self, name: &str, state: ForwardState) -> Result<(), ForwardError> {
        let entry = lock(&self.forwards)
            .get(name)
            .cloned()
            .ok_or_else(|| ForwardError::UnknownForward {
                name: name.to_string(),
            })?;
        entry.set_state(state);
        Ok(())
    }

    /// A handle to `name`, for watching the connections it already accepted.
    pub fn handle(&self, name: &str) -> Option<ForwardHandle> {
        lock(&self.forwards)
            .get(name)
            .map(|entry| ForwardHandle {
                entry: Arc::clone(entry),
            })
    }

    /// Every registered forward as `(name, listen address, state, destination)`,
    /// ordered by name.
    pub fn list(&self) -> Vec<(String, SocketAddr, ForwardState, Destination)> {
        lock(&self.forwards)
            .values()
            .map(|entry| {
                (
                    entry.spec.name.clone(),
                    entry.listen_addr,
                    entry.state(),
                    entry.spec.destination.clone(),
                )
            })
            .collect()
    }

    /// Unregisters `name` and returns the state it had.
    ///
    /// The listener stops accepting new connections; connections that are already
    /// established keep their sockets and are not resurrected or killed (USAGE.md
    /// section 7 step 5).
    pub fn remove(&self, name: &str) -> Result<ForwardState, ForwardError> {
        let entry = lock(&self.forwards)
            .remove(name)
            .ok_or_else(|| ForwardError::UnknownForward {
                name: name.to_string(),
            })?;
        let state = entry.state();
        entry.mark_removed();
        info!(forward = %name, "local forward removed");
        Ok(state)
    }

    /// Accepts connections on every registered listener until `shutdown` is true.
    ///
    /// Established connections are not torn down: each owns its sockets and ends
    /// when either side closes, which is the same rule that keeps removal from
    /// disturbing live flows (USAGE.md section 7 step 5).
    pub async fn run(self: Arc<Self>, shutdown: watch::Receiver<bool>) {
        let entries: Vec<Arc<ForwardEntry>> = lock(&self.forwards).values().cloned().collect();
        let mut tasks = JoinSet::new();
        for entry in entries {
            let opener = Arc::clone(&self.opener);
            let udp_opener = self.udp_opener.clone();
            let shutdown = shutdown.clone();
            tasks.spawn(async move {
                match entry.spec.proto {
                    Proto::Tcp => accept_loop(entry, opener, shutdown).await,
                    Proto::Udp => {
                        if udp_opener.is_some() {
                            // The listener already owns its opener, so it is not
                            // threaded through here a second time.
                            run_udp_listener(entry, shutdown).await;
                        } else {
                            // `add` rejects this combination, so reaching it means
                            // the opener was removed after the fact.
                            warn!(forward = %entry.spec.name, "UDP forward has no opener");
                        }
                    }
                }
            });
        }

        let mut shutdown = shutdown;
        loop {
            if *shutdown.borrow_and_update() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        debug!("local forward manager shutting down");
        while tasks.join_next().await.is_some() {}
    }
}

/// One registered forward: its spec, its bound listener, and its local history.
struct ForwardEntry {
    spec: ForwardSpec,
    listen_addr: SocketAddr,
    bound: Bound,
    allow: Vec<IpNet>,
    state: Mutex<ForwardState>,
    events: Mutex<VecDeque<ForwardEvent>>,
    removed: AtomicBool,
    /// Wakes the accept loop when the forward is removed, so `remove` does not
    /// have to wait for the next connection to stop the listener.
    gone: Notify,
    open_attempts: AtomicU64,
}

/// The bound half of a forward, which `run` takes ownership of.
enum Bound {
    Tcp(Mutex<Option<StdTcpListener>>),
    Udp(Arc<UdpForwardListener>),
}

impl ForwardEntry {
    fn tcp(spec: ForwardSpec, listen_addr: SocketAddr, listener: StdTcpListener, allow: Vec<IpNet>) -> Self {
        ForwardEntry {
            spec,
            listen_addr,
            bound: Bound::Tcp(Mutex::new(Some(listener))),
            allow,
            state: Mutex::new(ForwardState::Bound),
            events: Mutex::new(VecDeque::new()),
            removed: AtomicBool::new(false),
            gone: Notify::new(),
            open_attempts: AtomicU64::new(0),
        }
    }

    fn udp(
        spec: ForwardSpec,
        listen_addr: SocketAddr,
        listener: Arc<UdpForwardListener>,
        allow: Vec<IpNet>,
    ) -> Self {
        ForwardEntry {
            spec,
            listen_addr,
            bound: Bound::Udp(listener),
            allow,
            state: Mutex::new(ForwardState::Bound),
            events: Mutex::new(VecDeque::new()),
            removed: AtomicBool::new(false),
            gone: Notify::new(),
            open_attempts: AtomicU64::new(0),
        }
    }

    fn state(&self) -> ForwardState {
        *lock(&self.state)
    }

    fn set_state(&self, state: ForwardState) {
        *lock(&self.state) = state;
        if let Bound::Udp(listener) = &self.bound {
            // The UDP path reads datagrams only while a new association may be
            // opened, so a fast-failed forward must not keep forwarding them.
            listener.set_accepting(state.allows_open());
        }
    }

    fn is_removed(&self) -> bool {
        self.removed.load(Ordering::Relaxed)
    }

    fn mark_removed(&self) {
        self.removed.store(true, Ordering::Relaxed);
        self.gone.notify_waiters();
    }

    fn record(&self, peer: SocketAddr, outcome: ForwardOutcome) {
        let mut events = lock(&self.events);
        if events.len() == EVENT_HISTORY {
            events.pop_front();
        }
        events.push_back(ForwardEvent { peer, outcome });
    }

    fn events(&self) -> Vec<ForwardEvent> {
        lock(&self.events).iter().cloned().collect()
    }

    fn last_failure(&self) -> Option<String> {
        lock(&self.events).iter().rev().find_map(|event| {
            if let ForwardOutcome::OpenFailed(reason) = &event.outcome {
                Some(reason.clone())
            } else {
                None
            }
        })
    }

    /// Whether `peer` may use this listener (DESIGN.md section 7.6, section 9.3).
    ///
    /// An empty allowlist is only reachable for a loopback listener, where the
    /// bind address is already the allowlist. A configured allowlist is always
    /// enforced, loopback included, so tightening a listener is possible.
    fn peer_allowed(&self, peer: IpAddr) -> bool {
        if self.allow.is_empty() {
            return self.listen_addr.ip().is_loopback();
        }
        self.allow.iter().any(|net| net.contains(&peer))
    }
}

impl fmt::Debug for ForwardEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForwardEntry")
            .field("name", &self.spec.name)
            .field("listen", &self.listen_addr)
            .finish_non_exhaustive()
    }
}

/// Accepts local TCP connections until the forward is removed or the node stops.
async fn accept_loop(
    entry: Arc<ForwardEntry>,
    opener: Arc<dyn ForwardOpener>,
    mut shutdown: watch::Receiver<bool>,
) {
    let std_listener = match &entry.bound {
        Bound::Tcp(listener) => lock(listener).take(),
        Bound::Udp(_) => None,
    };
    let Some(std_listener) = std_listener else {
        // A second `run` on the same manager finds the listeners already taken.
        debug!(forward = %entry.spec.name, "listener already started");
        return;
    };
    let listener = match TcpListener::from_std(std_listener) {
        Ok(listener) => listener,
        Err(error) => {
            entry.set_state(ForwardState::Error);
            warn!(forward = %entry.spec.name, %error, "listener could not be registered");
            return;
        }
    };

    loop {
        if entry.is_removed() || *shutdown.borrow_and_update() {
            break;
        }
        tokio::select! {
            biased;
            () = entry.gone.notified() => break,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    if entry.is_removed() || *shutdown.borrow() {
                        drop(stream);
                        break;
                    }
                    let entry = Arc::clone(&entry);
                    let opener = Arc::clone(&opener);
                    tokio::spawn(async move {
                        serve_tcp(entry, opener, stream, peer).await;
                    });
                }
                Err(error) => {
                    // A failed accept is transient (per-connection resource
                    // exhaustion, for example); DESIGN.md section 7.6 keeps the
                    // listener bound, so back off briefly instead of dying.
                    warn!(forward = %entry.spec.name, %error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            },
        }
    }
    debug!(forward = %entry.spec.name, "listener stopped accepting");
}

/// Drives one UDP forward listener (USAGE.md section 9).
async fn run_udp_listener(entry: Arc<ForwardEntry>, shutdown: watch::Receiver<bool>) {
    let listener = match &entry.bound {
        Bound::Udp(listener) => Arc::clone(listener),
        Bound::Tcp(_) => return,
    };
    if entry.is_removed() {
        return;
    }
    tokio::select! {
        () = listener.run(shutdown) => {}
        () = entry.gone.notified() => {
            // Dropping the run future stops the receive loop, so the removed
            // forward takes no new source tuple. Associations already opened keep
            // their sockets, matching removal for TCP.
            debug!(forward = %entry.spec.name, "udp listener removed");
        }
    }
}

/// Serves one accepted TCP connection (USAGE.md section 7 steps 1-4).
async fn serve_tcp(
    entry: Arc<ForwardEntry>,
    opener: Arc<dyn ForwardOpener>,
    mut local: TcpStream,
    peer: SocketAddr,
) {
    if !entry.peer_allowed(peer.ip()) {
        entry.record(peer, ForwardOutcome::PeerRefused);
        info!(forward = %entry.spec.name, %peer, "local peer is not in allow_from");
        let _ = local.shutdown().await;
        return;
    }

    let state = entry.state();
    if !state.allows_open() {
        entry.record(peer, ForwardOutcome::FastFailed(state));
        info!(forward = %entry.spec.name, %peer, %state, "fast-failing a new connection");
        let _ = local.shutdown().await;
        return;
    }

    // USAGE.md section 7 step 1: the local socket is not read until the remote
    // `Open` is confirmed, so nothing is pipelined to a target that may not exist.
    entry.open_attempts.fetch_add(1, Ordering::Relaxed);
    let attempt = opener.open(
        entry.spec.destination.clone(),
        entry.spec.proto,
        entry.spec.via.clone(),
    );
    let opened = tokio::time::timeout(Duration::from_secs(OPERATION_OPEN_TIMEOUT_SECS), attempt).await;
    let mut remote = match opened {
        Ok(Ok(remote)) => remote,
        Ok(Err(error)) => {
            fail_open(&entry, &mut local, peer, error).await;
            return;
        }
        Err(_elapsed) => {
            let reason = format!("no OpenResult within {OPERATION_OPEN_TIMEOUT_SECS} s");
            fail_open(&entry, &mut local, peer, ForwardError::RemoteOpen { reason }).await;
            return;
        }
    };

    // A successful `Open` is evidence that the publisher/service exists and the
    // ACL allows it, which is what READY means in the USAGE.md section 7 table.
    // A transient failure deliberately leaves the state alone.
    if matches!(entry.state(), ForwardState::Bound | ForwardState::Degraded) {
        entry.set_state(ForwardState::Ready);
    }
    entry.record(peer, ForwardOutcome::Opened);
    let name = entry.spec.name.clone();
    match tokio::io::copy_bidirectional(&mut local, &mut remote).await {
        Ok(_) => entry.record(peer, ForwardOutcome::Closed(None)),
        Err(error) => {
            debug!(forward = %name, %peer, %error, "forwarded connection ended with an error");
            entry.record(peer, ForwardOutcome::Closed(Some(error.to_string())));
        }
    }
}

/// Closes a local connection whose remote `Open` failed, keeping the reason local.
async fn fail_open(
    entry: &ForwardEntry,
    local: &mut TcpStream,
    peer: SocketAddr,
    error: ForwardError,
) {
    // A stable verdict moves the observable state so later connections fast-fail;
    // a transient failure must not, or one unlucky connection would take the
    // whole forward down (USAGE.md section 7 step 5).
    if let Some(state) = error.lifecycle_state() {
        entry.set_state(state);
    }
    entry.record(peer, ForwardOutcome::OpenFailed(error.to_string()));
    warn!(forward = %entry.spec.name, %peer, %error, "remote open failed, closing the local connection");
    let _ = local.shutdown().await;
}

/// Validates the parts of a spec that do not depend on the bound socket.
fn validate_spec(spec: &ForwardSpec) -> Result<(), ForwardError> {
    if !is_slug(&spec.name) {
        return Err(ForwardError::InvalidName {
            name: spec.name.clone(),
        });
    }
    if spec.hub != "auto" && !is_slug(&spec.hub) {
        return Err(ForwardError::InvalidHub {
            hub: spec.hub.clone(),
        });
    }
    spec.destination.validate()?;
    validate_chain(LOCAL_CALLER, &spec.via, &spec.destination)?;
    Ok(())
}

/// Parses a listener address.
///
/// Only an IP literal is accepted, because the loopback decision of DESIGN.md
/// section 7.6 must be made without a resolver: a name could resolve to a
/// non-loopback address after the allowlist check, which is exactly the
/// DNS-rebinding shape section 9.3 forbids.
fn parse_listen(text: &str) -> Result<SocketAddr, ForwardError> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let invalid = |reason: &str| ForwardError::InvalidListen {
        listen: text.to_string(),
        reason: reason.to_string(),
    };
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| invalid("expected `address:port`"))?;
    let port: u16 = port.parse().map_err(|_| invalid("port must be 0-65535"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ip = if host.is_empty() {
        // The documented `:0` shorthand means "unspecified address, OS-chosen
        // port"; it is not loopback, so the allowlist rule below still applies.
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        host.parse::<IpAddr>()
            .map_err(|_| invalid("host must be an IP literal"))?
    };
    Ok(SocketAddr::new(ip, port))
}

/// Parses the source allowlist.
fn parse_allow_from(values: &[String]) -> Result<Vec<IpNet>, ForwardError> {
    let mut nets = Vec::with_capacity(values.len());
    for value in values {
        let net = value
            .parse::<IpNet>()
            .map_err(|_| ForwardError::InvalidAllowFrom {
                value: value.clone(),
            })?;
        nets.push(net);
    }
    Ok(nets)
}

/// The bound listener of one forward, before `run` takes it over.
enum BoundListener {
    Tcp(StdTcpListener),
    Udp(std::net::UdpSocket),
}

/// Binds the local socket. Non-blocking, because `run` hands it to Tokio.
fn bind_listener(proto: Proto, addr: SocketAddr) -> Result<BoundListener, ForwardError> {
    let bind_error = |source: io::Error| ForwardError::Bind {
        listen: addr.to_string(),
        source,
    };
    match proto {
        Proto::Tcp => {
            let listener = StdTcpListener::bind(addr).map_err(bind_error)?;
            listener.set_nonblocking(true).map_err(bind_error)?;
            Ok(BoundListener::Tcp(listener))
        }
        Proto::Udp => {
            let socket = std::net::UdpSocket::bind(addr).map_err(bind_error)?;
            socket.set_nonblocking(true).map_err(bind_error)?;
            Ok(BoundListener::Udp(socket))
        }
    }
}

/// The address a bound listener actually holds, including an OS-assigned port.
fn local_addr(bound: &BoundListener) -> io::Result<SocketAddr> {
    match bound {
        BoundListener::Tcp(listener) => listener.local_addr(),
        BoundListener::Udp(socket) => socket.local_addr(),
    }
}

/// Locks a manager mutex, recovering the value if an unrelated task panicked.
///
/// A panic inside one connection task must not turn every later control-plane
/// call into a panic: the guarded values are simple bookkeeping, and the worst
/// case is one stale event record.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}
