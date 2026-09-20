//! Hub state and decisions (DESIGN.md sections 5, 7.1, 8, 9.3).
//!
//! This module owns everything that is true regardless of which carrier a record
//! arrived on:
//!
//! * **Credentials.** A node's PSK is looked up by the `(hub_id, key_id, node_id)`
//!   triple the `Auth` names, so a key id that belongs to another node, or a key
//!   id that belongs to another Hub, simply does not resolve.
//! * **Replay.** Section 5.1's atomic nonce registration happens *after* the MAC
//!   verifies and before any session exists.
//! * **Leases.** The [`Registry`] is the single authority on who is present and
//!   what they publish; every mutation carries the `(session_id, epoch)` that is
//!   allowed to perform it, so a late teardown cannot delete a newer lease.
//! * **Authorisation.** [`Hub::authorize_open`] is the only place that decides
//!   whether an `Open` may proceed, and it is default-deny.
//!
//! # Why the egress plan is separate from the dial
//!
//! `authorize_open` stops at an [`ExitPlan`]: the exact leg an `Open` resolved to.
//! Turning a plan into sockets is the Hub's data plane, which this build does not
//! implement. Keeping the two apart means the *decision* is complete and testable
//! (including section 7.6's service resolution and section 7.1's chain checks),
//! and the unimplemented part is reported as a refusal that names itself instead
//! of being hidden behind a silent success.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use tokio::net::TcpListener;
use wsnet_auth_store::{AuthStoreError, NonceKey, NonceStore, NonceStoreConfig, Now};
use wsnet_config::{ServerConfig, ServerSection};
use wsnet_crypto::Psk;
use wsnet_limits::BIND_PROOF_TTL_SECS;
use wsnet_protocol::{MessageKind, Record};
use wsnet_registry::Registry;
use wsnet_routing::{validate_chain, AclQuery, AclTable, Destination, RelayAllow, RouteError};
use wsnet_session::{
    authok_mac, fresh_epoch, fresh_nonce, fresh_session_id, negotiate_capabilities, session_keys,
    verify_auth, AuthFields, AuthOkFields, HelloFields, HelloOkFields, OpenFields,
    OpenResultFields, OpenStatus, Session, SessionConfig, SessionState, Side,
};
use wsnet_site::{FailureStage, Response as SiteResponse, Site, StageResponse};
use wsnet_transport::Carrier;

use crate::bind::{verify_binding_mac, BindProof, BindProofError, BindProofRegistry, BindTarget};
use crate::error::HubStartError;
use crate::guard::{DosGuards, GuardError, UnauthenticatedConnection};
use crate::server;
use crate::session::{state_name, SessionEntry, Sessions, SharedSession};

/// Default absolute session lifetime, in seconds.
///
/// Section 5.1 bounds the *clock skew* window but leaves the session lifetime to
/// the deployment; a Hub that never expires a session would keep leases alive
/// after the last carrier went away, so a bounded default is the safe choice.
pub const DEFAULT_SESSION_TTL_SECS: i64 = 900;

/// Paths the carrier endpoints own; the site must never serve them (section 6.5).
pub const CARRIER_PATHS: [&str; 3] = ["/m", "/e", "/w"];

/// How many times one carrier may drain the engine before it stops looking for
/// follow-on replies.
///
/// A pump round can produce another reply (a `Ping` produces a `Pong`), so the
/// loop must run until quiescent; the bound stops a pathological peer from
/// monopolising the carrier.
const MAX_PUMP_ROUNDS: usize = 8;

/// Detail strings carried by an `OpenResult`.
///
/// Section 4.1 puts a locally diagnosable detail in `OpenResult`, and section 9.1
/// keeps that detail out of any unauthenticated appearance: these strings are only
/// ever sent inside a protected record.
const DETAIL_INVALID_DESTINATION: &str = "destination is not a valid target";
const DETAIL_CHAIN_LOOP: &str = "via chain loops back to the caller";
const DETAIL_CHAIN_DUPLICATE: &str = "via chain repeats a node";
const DETAIL_CHAIN_TOO_LONG: &str = "via chain exceeds the hop budget";
const DETAIL_CHAIN_INVALID: &str = "via chain is not a chain of node slugs";
const DETAIL_CHAIN_PUBLISHER: &str = "via chain names the destination node";
const DETAIL_ACL_DENIED: &str = "no acl rule permits this access";
const DETAIL_RELAY_NOT_ALLOWED: &str = "relay_allow does not permit a hop in this chain";
const DETAIL_RELAY_ACL_DENIED: &str = "no acl rule permits relaying through this hop";
const DETAIL_SERVICE_OFFLINE: &str = "the publishing node has no live lease on this hub";
const DETAIL_SERVICE_PROTO: &str = "the published service protocol differs from the open";
const DETAIL_SERVICE_STALE: &str = "the pinned service revision is stale";
const DETAIL_RELAY_UNIMPLEMENTED: &str = "multi-hop relay is not implemented in this build";
const DETAIL_EXIT_UNIMPLEMENTED: &str = "hub exit dialling is not implemented in this build";
const DETAIL_SERVICE_UNIMPLEMENTED: &str =
    "forwarding to the publishing node is not implemented in this build";
const DETAIL_NODE_EXIT_UNIMPLEMENTED: &str =
    "dialling from the named node is not implemented in this build";

/// The exit leg an `Open` resolved to.
///
/// This is the output of authorisation, not of dialling: everything here has
/// already passed the ACL, the chain checks, and (for a service) the registry
/// lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitPlan {
    /// The Hub itself would dial this address.
    HubExit {
        /// Host as written by the caller.
        host: String,
        /// Destination port.
        port: u16,
    },
    /// The current publisher of a named service is the final leg.
    ServiceExit {
        /// Publishing node.
        node_id: String,
        /// Service name.
        service_name: String,
        /// Target the publisher configured.
        target: String,
        /// Revision the plan was resolved against.
        revision: u64,
    },
    /// A named node's view of an address is the final leg.
    NodeExit {
        /// Node whose view is meant.
        node_id: String,
        /// Host as seen from that node.
        host: String,
        /// Destination port.
        port: u16,
    },
    /// Relay through these intermediate nodes, in order.
    Relay {
        /// Intermediate hops, never the destination's own node (section 7.6).
        hops: Vec<String>,
    },
}

/// A refused `Open`, in the shape an `OpenResult` needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenRefusal {
    /// Status to report.
    pub status: OpenStatus,
    /// Locally diagnosable detail.
    pub detail: &'static str,
}

impl OpenRefusal {
    const fn denied(detail: &'static str) -> Self {
        OpenRefusal {
            status: OpenStatus::Denied,
            detail,
        }
    }

    const fn refused(detail: &'static str) -> Self {
        OpenRefusal {
            status: OpenStatus::Refused,
            detail,
        }
    }

    const fn offline(detail: &'static str) -> Self {
        OpenRefusal {
            status: OpenStatus::Offline,
            detail,
        }
    }
}

/// Why an authentication attempt did not produce a session.
///
/// Deliberately private and never rendered to a peer: section 9.1 requires every
/// one of these to look identical from outside, so the only place a variant is
/// observed is a local log.
#[derive(Debug)]
pub(crate) enum AuthFailure {
    /// The record was not a well-formed `Auth`.
    Malformed,
    /// The named node, key id, or Hub is unknown.
    UnknownNode,
    /// The MAC did not verify.
    BadMac,
    /// The `Auth` (or its timestamp) was replay or outside the acceptance window.
    Nonce(AuthStoreError),
    /// A required capability is not supported.
    UnsupportedCapability,
    /// The source exceeded the authentication rate.
    RateLimited,
}

impl AuthFailure {
    /// A log-safe explanation.
    ///
    /// This never contains key material or message contents, and it is never sent
    /// to the peer: section 9.1 keeps the distinction between these causes local.
    pub(crate) fn detail(&self) -> String {
        match self {
            AuthFailure::Malformed => "malformed Auth record".to_string(),
            AuthFailure::UnknownNode => "unknown hub, key id, or node".to_string(),
            AuthFailure::BadMac => "Auth mac did not verify".to_string(),
            AuthFailure::Nonce(error) => format!("nonce refused: {error}"),
            AuthFailure::UnsupportedCapability => "unsupported required capability".to_string(),
            AuthFailure::RateLimited => "authentication rate budget exhausted".to_string(),
        }
    }
}

/// A successful authentication.
pub(crate) struct AuthSuccess {
    /// The freshly created session.
    pub(crate) entry: SharedSession,
    /// The `AuthOk` record to return on the same carrier.
    pub(crate) authok: Record,
}

/// The carrier paths this deployment configures (section 6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePaths {
    /// HTML template profile.
    pub page: String,
    /// JavaScript template profile.
    pub script: String,
    /// CSS template profile.
    pub style: String,
    /// JSON API profile.
    pub json: String,
}

impl Default for ProfilePaths {
    fn default() -> Self {
        ProfilePaths {
            page: "/transport/page".to_string(),
            script: "/transport/script".to_string(),
            style: "/transport/style".to_string(),
            json: "/transport/api".to_string(),
        }
    }
}

impl ProfilePaths {
    /// Every configured path paired with its carrier.
    pub fn entries(&self) -> [(&str, Carrier); 4] {
        [
            (self.page.as_str(), Carrier::HtmlProfile),
            (self.script.as_str(), Carrier::JsProfile),
            (self.style.as_str(), Carrier::CssProfile),
            (self.json.as_str(), Carrier::JsonProfile),
        ]
    }

    /// The carrier one path is served with, if this deployment configures it.
    pub fn carrier_for(&self, path: &str) -> Option<Carrier> {
        self.entries()
            .into_iter()
            .find(|(candidate, _)| *candidate == path)
            .map(|(_, carrier)| carrier)
    }
}

/// The node credentials a Hub accepts.
///
/// Keyed by `(key_id, node_id)`; the Hub id is checked separately, so a key id
/// that belongs to another Hub in a multi-Hub deployment does not authenticate
/// here (section 5.5).
#[derive(Default)]
pub struct NodeSecrets {
    entries: BTreeMap<(String, String), Psk>,
}

impl NodeSecrets {
    /// An empty credential set, which accepts nobody.
    pub fn new() -> Self {
        NodeSecrets::default()
    }

    /// Adds one node's pre-shared key, returning the set for chaining.
    pub fn with(mut self, node_id: impl Into<String>, key_id: impl Into<String>, psk: Psk) -> Self {
        self.insert(node_id, key_id, psk);
        self
    }

    /// Adds one node's pre-shared key.
    pub fn insert(&mut self, node_id: impl Into<String>, key_id: impl Into<String>, psk: Psk) {
        self.entries.insert((key_id.into(), node_id.into()), psk);
    }

    /// Number of configured credentials.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no credential is configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The key for one `(key_id, node_id)` pair.
    pub fn get(&self, key_id: &str, node_id: &str) -> Option<&Psk> {
        self.entries.get(&(key_id.to_string(), node_id.to_string()))
    }

    /// Loads every `[[nodes]]` credential file (section 10).
    ///
    /// A credential file holds either 32 raw bytes or 64 lowercase hex
    /// characters; anything else is refused rather than truncated into a key.
    pub fn from_server_config(config: &ServerConfig) -> Result<Self, HubStartError> {
        let mut secrets = NodeSecrets::new();
        for node in &config.nodes {
            let path = node.secret_file.display().to_string();
            let bytes =
                std::fs::read(&node.secret_file).map_err(|error| HubStartError::SecretFile {
                    path: path.clone(),
                    message: error.to_string(),
                })?;
            let psk = parse_secret(&bytes).ok_or(HubStartError::BadSecret { path })?;
            secrets.insert(node.id.clone(), node.key_id.clone(), psk);
        }
        Ok(secrets)
    }
}

impl core::fmt::Debug for NodeSecrets {
    /// Lists identities only; key material is never printed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let identities: Vec<String> = self
            .entries
            .keys()
            .map(|(key_id, node_id)| format!("{node_id}/{key_id}"))
            .collect();
        f.debug_struct("NodeSecrets")
            .field("identities", &identities)
            .field("keys", &"<redacted>")
            .finish()
    }
}

fn parse_secret(bytes: &[u8]) -> Option<Psk> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let trimmed = text.trim();
        if trimmed.len() == 64 {
            if let Ok(raw) = hex::decode(trimmed) {
                return Psk::try_from_slice(&raw).ok();
            }
        }
    }
    Psk::try_from_slice(bytes).ok()
}

/// A monotonic-plus-wall clock, in the shape [`Now`] expects.
#[derive(Debug)]
pub(crate) struct Clock {
    origin: Instant,
}

impl Clock {
    pub(crate) fn new() -> Self {
        Clock {
            origin: Instant::now(),
        }
    }

    pub(crate) fn now(&self) -> Now {
        let wall_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let monotonic_ms = self.origin.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        Now::new(wall_secs, monotonic_ms)
    }
}

/// The Hub: one process, one `hub_id`, one loopback listener.
pub struct Hub {
    config: ServerConfig,
    hub_id: String,
    listen: SocketAddr,
    secrets: NodeSecrets,
    site: Site,
    profiles: ProfilePaths,
    acl: AclTable,
    relay: RelayAllow,
    nonces: Mutex<NonceStore>,
    binds: Mutex<BindProofRegistry>,
    registry: Mutex<Registry>,
    sessions: Sessions,
    guards: Arc<DosGuards>,
    clock: Clock,
    session_ttl_secs: i64,
}

impl core::fmt::Debug for Hub {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hub")
            .field("hub_id", &self.hub_id)
            .field("listen", &self.listen)
            .field("nodes", &self.secrets.len())
            .field("acl_rules", &self.acl.len())
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl Hub {
    /// Builds a Hub from configuration and credentials (section 10).
    ///
    /// The loopback check runs *before* the configuration's own validation so that
    /// an operator who tries to expose the backend directly gets that specific
    /// diagnosis rather than a downstream complaint about allowlists.
    pub fn new(config: ServerConfig, secrets: NodeSecrets) -> Result<Self, HubStartError> {
        Hub::with_profiles(config, secrets, ProfilePaths::default())
    }

    /// Builds a Hub with an explicit set of profile paths (section 6.4).
    pub fn with_profiles(
        config: ServerConfig,
        secrets: NodeSecrets,
        profiles: ProfilePaths,
    ) -> Result<Self, HubStartError> {
        let listen = parse_listen(&config.server.listen)?;
        config.validate().map_err(HubStartError::Config)?;

        let mut site = Site::builtin();
        for path in CARRIER_PATHS {
            site.reserve_path(path);
        }
        for (path, _) in profiles.entries() {
            site.reserve_path(path);
        }

        let acl = config.acl_table()?;
        let relay = config.relay_allow();
        let nonce_config = NonceStoreConfig {
            window_secs: config.server.auth_window_secs,
            per_node_max: config.server.auth_nonce_max_per_node,
            ..NonceStoreConfig::default()
        };

        Ok(Hub {
            hub_id: config.server.hub_id.clone(),
            listen,
            secrets,
            site,
            profiles,
            acl,
            relay,
            nonces: Mutex::new(NonceStore::new(nonce_config)?),
            binds: Mutex::new(BindProofRegistry::new()),
            registry: Mutex::new(Registry::new(config.server.hub_id.clone())),
            sessions: Sessions::new(),
            guards: Arc::new(DosGuards::new()),
            clock: Clock::new(),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            config,
        })
    }

    /// The Hub identity this process authenticates as.
    pub fn hub_id(&self) -> &str {
        &self.hub_id
    }

    /// The configuration this Hub was built from.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// The `[server]` section.
    pub fn server_section(&self) -> &ServerSection {
        &self.config.server
    }

    /// The configured listen address, always loopback.
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// The deployment's public site and failure appearance (section 6.5).
    pub fn site(&self) -> &Site {
        &self.site
    }

    /// The configured profile paths (section 6.4).
    pub fn profiles(&self) -> &ProfilePaths {
        &self.profiles
    }

    /// The carrier one path is served with.
    pub(crate) fn carrier_for_path(&self, path: &str) -> Carrier {
        if path == "/m" {
            return Carrier::Post;
        }
        self.profiles.carrier_for(path).unwrap_or(Carrier::Post)
    }

    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Node ids with a live lease, sorted.
    pub fn is_node_registered(&self, node_id: &str) -> bool {
        self.registry
            .lock()
            .expect("registry mutex")
            .is_registered(node_id)
    }

    /// Number of nodes with a live lease.
    pub fn registered_node_count(&self) -> usize {
        self.registry.lock().expect("registry mutex").node_count()
    }

    /// Service names one node currently publishes, sorted.
    pub fn registered_services(&self, node_id: &str) -> Vec<String> {
        self.registry
            .lock()
            .expect("registry mutex")
            .node(node_id)
            .map(|lease| lease.services.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The stage-appropriate failure response for a request that was never
    /// upgraded and never started SSE (section 9.1).
    pub fn http_failure_response(&self) -> SiteResponse {
        match self.site.failure(FailureStage::HttpPreAuth) {
            StageResponse::Http(response) => response,
            // `Site::failure` only returns the other stages for the other stages.
            _ => SiteResponse::no_store(404, "text/html; charset=utf-8", Vec::new()),
        }
    }

    /// The WebSocket close code a pre-authentication failure must use (section
    /// 9.1: after an upgrade only frames or a Close are legal).
    pub(crate) fn ws_failure_close_code(&self) -> u16 {
        match self.site.failure(FailureStage::WsPreAuth) {
            StageResponse::WsClose(code) => code,
            _ => 1000,
        }
    }

    /// Charges one unauthenticated connection to `ip` (section 9.2).
    pub(crate) fn begin_unauthenticated(
        &self,
        ip: IpAddr,
    ) -> Result<UnauthenticatedConnection, GuardError> {
        self.guards.begin_unauthenticated(ip)
    }

    /// The router serving every endpoint (section 11).
    pub fn router(self: &Arc<Self>) -> Router {
        server::router(self)
    }

    /// Serves the router until the process ends.
    ///
    /// Connection information is required for section 9.2's per-source budgets, so
    /// the service is built with connect info rather than a bare make-service.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        let router = self.router();
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }

    /// Drops sessions whose absolute expiry has passed.
    ///
    /// Section 5.3 makes an unreachable peer's resources the local side's problem,
    /// so expiry is enforced here rather than waiting for a carrier to notice.
    pub fn reap_expired_sessions(&self) -> usize {
        let now = self.clock.now();
        let expired = self.sessions.expired(now.wall_secs);
        let count = expired.len();
        for entry in expired {
            tracing::debug!(session = %hex::encode(entry.session_id), "session expired");
            self.close_session(&entry.session_id, &entry.epoch, "expired");
        }
        count
    }

    /// Tears a session down, but only for the epoch that still owns it.
    ///
    /// The registry's own `(session_id, epoch)` guard (section 5.5) does the
    /// interesting part: a late teardown from a superseded session is a no-op, so a
    /// fresh lease that replaced it survives.
    pub(crate) fn close_session(&self, session_id: &[u8; 16], epoch: &[u8; 16], reason: &str) {
        let Some(entry) = self.sessions.get(session_id) else {
            return;
        };
        if entry.epoch != *epoch {
            // A newer epoch already owns this id; nothing to tear down.
            return;
        }
        if !self.sessions.remove_if_epoch(session_id, epoch) {
            return;
        }
        entry.closed.store(true, Ordering::SeqCst);
        entry.handle.set_state(SessionState::Closed);
        let node_id = entry.node_id.clone();
        match self
            .registry
            .lock()
            .expect("registry mutex")
            .unregister(&node_id, session_id, epoch)
        {
            Ok(true) => tracing::debug!(%node_id, reason, "node lease released"),
            Ok(false) => tracing::debug!(
                %node_id,
                "a newer lease owns this node; leaving it registered"
            ),
            Err(_) => {}
        }
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /// Verifies an `Auth` and creates the session it names (sections 4.4, 5.1).
    ///
    /// The order is the one section 5.1 fixes: bound the input, check the fields,
    /// verify the MAC, and only then atomically register the nonce and create a
    /// usable session. Every failure is returned as an [`AuthFailure`] and becomes
    /// the same site failure appearance at the carrier.
    pub(crate) fn authenticate(
        &self,
        record: &Record,
        peer: IpAddr,
    ) -> Result<AuthSuccess, AuthFailure> {
        if record.kind != MessageKind::Auth || !record.payload.is_empty() {
            return Err(AuthFailure::Malformed);
        }
        let (fields, _presented) =
            AuthFields::from_canonical(&record.metadata).map_err(|_| AuthFailure::Malformed)?;

        let now = self.clock.now();
        self.guards
            .spend_auth_token(peer, now.monotonic_ms)
            .map_err(|_| AuthFailure::RateLimited)?;

        // Section 5.5: a Hub id is a separate trust domain, so an `Auth` that
        // names another Hub never resolves here even when the PSK matches.
        if fields.hub_id != self.hub_id {
            return Err(AuthFailure::UnknownNode);
        }
        let psk = self
            .secrets
            .get(&fields.key_id, &fields.node_id)
            .ok_or(AuthFailure::UnknownNode)?;

        // Section 5.1: the MAC is checked in constant time before the nonce is
        // spent, so forged records cannot burn replay-window entries.
        verify_auth(psk, &record.metadata).map_err(|_| AuthFailure::BadMac)?;
        let capabilities = negotiate_capabilities(&fields.capabilities)
            .map_err(|_| AuthFailure::UnsupportedCapability)?;
        let auth_mac = wsnet_session::auth_mac(psk, &fields);

        {
            let nonce = NonceKey::new(
                self.hub_id.clone(),
                fields.key_id.clone(),
                fields.node_id.clone(),
                fields.nonce,
            );
            self.nonces
                .lock()
                .expect("nonce mutex")
                .register(nonce, fields.ts, now)
                .map_err(AuthFailure::Nonce)?;
        }

        let session_id = fresh_session_id();
        let session_epoch = fresh_epoch();
        let authok = AuthOkFields {
            session_id,
            session_epoch,
            attempt_id: fields.attempt_id,
            server_nonce: fresh_nonce(),
            expires_at: now.wall_secs + self.session_ttl_secs,
            capabilities,
        };
        let mac = authok_mac(psk, &auth_mac, &authok);
        let authok_record = Record::new(MessageKind::AuthOk, authok.to_canonical(&mac));

        let keys = Arc::new(session_keys(psk, &fields, &authok));
        let config = SessionConfig::new(
            self.hub_id.clone(),
            fields.node_id.clone(),
            session_id,
            session_epoch,
            Side::Hub,
        );
        let session = Session::new(config, session_keys(psk, &fields, &authok));
        session.handle.set_state(SessionState::Binding);
        let entry = Arc::new(SessionEntry::new(
            session_id,
            session_epoch,
            fields.node_id.clone(),
            fields.key_id.clone(),
            authok.expires_at,
            keys,
            session,
        ));
        self.sessions.insert(Arc::clone(&entry));
        tracing::debug!(
            node = %fields.node_id,
            session = %hex::encode(session_id),
            "session authenticated"
        );

        Ok(AuthSuccess {
            entry,
            authok: authok_record,
        })
    }

    // -----------------------------------------------------------------------
    // Binding
    // -----------------------------------------------------------------------

    /// Verifies a `BindProof` header against the request it arrived on
    /// (section 4.4).
    ///
    /// The proof is refused unless every one of these holds: the session exists,
    /// the proof's expiry is in the future and inside both its own 30-second
    /// budget and the session's expiry, the MAC covers this method, path, body,
    /// and session epoch, and the `bind_nonce` has never been used before.
    pub(crate) fn verify_binding(
        &self,
        method: &str,
        path: &str,
        header: &str,
        body: [u8; 32],
    ) -> Result<SharedSession, BindFailure> {
        let proof = BindProof::parse(header).map_err(BindFailure::Malformed)?;
        let entry = self
            .sessions
            .get(&proof.session_id)
            .ok_or(BindFailure::UnknownSession)?;
        if entry.is_closed() {
            return Err(BindFailure::UnknownSession);
        }

        let now = self.clock.now();
        if proof.expires_at < now.wall_secs {
            return Err(BindFailure::Expired);
        }
        if proof.expires_at > entry.expires_at {
            // Section 4.4: a proof must not outlive the session it binds.
            return Err(BindFailure::Expired);
        }
        if proof.expires_at - now.wall_secs > BIND_PROOF_TTL_SECS as i64 {
            return Err(BindFailure::Expired);
        }

        let target = BindTarget {
            method,
            path,
            hub_id: &self.hub_id,
            session_id: entry.session_id,
            session_epoch: entry.epoch,
            channel_id: proof.channel_id,
            bind_nonce: proof.bind_nonce,
            body_hash: body,
            expires_at: proof.expires_at,
        };
        if !verify_binding_mac(entry.keys.bind_key(), &target, &proof.mac) {
            return Err(BindFailure::BadMac);
        }
        if !self
            .binds
            .lock()
            .expect("bind mutex")
            .claim(proof.bind_nonce, proof.expires_at, now)
        {
            return Err(BindFailure::Replayed);
        }
        Ok(entry)
    }

    // -----------------------------------------------------------------------
    // Leases and events
    // -----------------------------------------------------------------------

    /// Feeds sealed envelopes into a session and arbitrates whatever they produce.
    pub(crate) fn feed_records(&self, entry: &SharedSession, envelopes: &[Vec<u8>]) {
        for envelope in envelopes {
            if !entry.handle.feed_lossy(envelope) {
                // Section 9.1: a forged or malformed record is counted and
                // dropped; it never reaches business state.
                tracing::debug!(session = %hex::encode(entry.session_id), "dropping an unauthenticated envelope");
            }
        }
        self.pump_session(entry);
    }

    /// Moves engine output to the downlink fan-out and handles the events a Hub
    /// must respond to.
    pub(crate) fn pump_session(&self, entry: &SharedSession) {
        for _ in 0..MAX_PUMP_ROUNDS {
            let round = entry.drain();
            if round.events.is_empty() && !entry.needs_pump() {
                return;
            }
            for event in round.events {
                self.on_session_event(entry, event);
            }
            if !entry.needs_pump() {
                return;
            }
        }
        tracing::debug!(
            session = %hex::encode(entry.session_id),
            "pump round limit reached"
        );
    }

    fn on_session_event(&self, entry: &SharedSession, event: wsnet_session::SessionEvent) {
        use wsnet_session::SessionEvent as Event;
        match event {
            Event::Hello(fields) => self.on_hello(entry, fields),
            Event::Open(fields) => self.on_open(entry, fields),
            Event::Ping => {
                if entry.handle.send_pong().is_err() {
                    tracing::debug!(session = %hex::encode(entry.session_id), "cannot answer Ping");
                }
            }
            Event::Bye(fields) => {
                tracing::debug!(session = %hex::encode(entry.session_id), reason = %fields.reason, "peer said Bye");
                self.close_session(&entry.session_id, &entry.epoch, "bye");
            }
            Event::Data { stream_id, .. } => {
                // The egress data plane is not implemented, so a stream that
                // somehow produced data is reset rather than silently dropped:
                // section 7.2 requires an explicit failure over a stall.
                let _ = entry
                    .handle
                    .send_reset(stream_id, wsnet_session::ResetReason::Unreachable);
            }
            Event::Datagram { .. } => {
                // Section 7.4: a datagram with no association is dropped and
                // counted; it never dials anything on its own.
                tracing::debug!(
                    session = %hex::encode(entry.session_id),
                    "dropping a datagram for an unimplemented association"
                );
            }
            Event::StateChanged(state) => {
                tracing::trace!(
                    session = %hex::encode(entry.session_id),
                    state = state_name(state),
                    "session state changed"
                );
            }
            Event::QueryResult(_) => {
                tracing::debug!(session = %hex::encode(entry.session_id), "QueryResult is not implemented");
            }
            Event::Dropped { packet_no } => {
                tracing::trace!(packet_no, "dropped a replayed envelope");
            }
            other => {
                tracing::trace!(
                    session = %hex::encode(entry.session_id),
                    event = ?other,
                    "unhandled session event"
                );
            }
        }
    }

    /// Section 5.3: `Hello` registers the node, and only `HelloOk` lifts the
    /// business barrier.
    fn on_hello(&self, entry: &SharedSession, fields: HelloFields) {
        let accepted = match negotiate_capabilities(&fields.capabilities) {
            Ok(capabilities) => capabilities,
            Err(error) => {
                // Section 4.1: an unknown required capability is refused, never
                // silently downgraded.
                tracing::warn!(node = %entry.node_id, %error, "refusing Hello");
                let _ = entry.handle.send_bye("unsupported capability");
                self.close_session(&entry.session_id, &entry.epoch, "capability refused");
                return;
            }
        };

        {
            let mut registry = self.registry.lock().expect("registry mutex");
            if registry.register_ready(&entry.node_id, entry.session_id, entry.epoch) {
                tracing::debug!(node = %entry.node_id, "a newer session replaced an earlier lease");
            }
            for service in &fields.services {
                match registry.publish(
                    &entry.node_id,
                    &entry.session_id,
                    &entry.epoch,
                    &service.name,
                    service.proto,
                    &service.target,
                ) {
                    Ok(revision) => tracing::debug!(
                        node = %entry.node_id,
                        service = %service.name,
                        revision,
                        "service published"
                    ),
                    // A malformed service entry is refused on its own; it must not
                    // take the rest of the registration down with it.
                    Err(error) => tracing::warn!(
                        node = %entry.node_id,
                        service = %service.name,
                        %error,
                        "refusing service registration"
                    ),
                }
            }
        }

        entry.handle.set_state(SessionState::HelloPending);
        let hello_ok = HelloOkFields {
            request_id: fields.request_id,
            capabilities: accepted,
        };
        if let Err(error) = entry.handle.send_hello_ok(&hello_ok) {
            tracing::warn!(node = %entry.node_id, %error, "cannot answer Hello");
            self.close_session(&entry.session_id, &entry.epoch, "hello failed");
        }
    }

    /// Turns an `Open` into an `OpenResult`, authorising before anything else.
    fn on_open(&self, entry: &SharedSession, fields: OpenFields) {
        let (status, detail) = match self.authorize_open(&entry.node_id, &fields) {
            Ok(plan) => {
                let detail = match &plan {
                    ExitPlan::Relay { .. } => DETAIL_RELAY_UNIMPLEMENTED,
                    ExitPlan::ServiceExit { .. } => DETAIL_SERVICE_UNIMPLEMENTED,
                    ExitPlan::NodeExit { .. } => DETAIL_NODE_EXIT_UNIMPLEMENTED,
                    ExitPlan::HubExit { .. } => DETAIL_EXIT_UNIMPLEMENTED,
                };
                (OpenStatus::Refused, detail)
            }
            Err(refusal) => (refusal.status, refusal.detail),
        };
        let result = OpenResultFields {
            request_id: fields.request_id,
            stream_id: fields.stream_id,
            status,
            detail: detail.to_string(),
        };
        if let Err(error) = entry.handle.send_open_result(&result) {
            tracing::debug!(node = %entry.node_id, %error, "cannot answer Open");
        }
    }

    /// Decides whether an `Open` may proceed, and to which exit leg (sections 7.1,
    /// 7.6, 9.3).
    ///
    /// The order matters and is the design's:
    ///
    /// 1. the destination union must be valid;
    /// 2. the `via` chain must be a chain (section 7.1's loops, duplicates, hop
    ///    budget, and publisher checks);
    /// 3. the ACL must permit this caller, action, and target, with
    ///    `NodeAddressTarget` requiring its own `connect_node_address` rule, so a
    ///    service rule can never grant raw address access (section 7.6);
    /// 4. a named service must resolve to a live lease with a matching protocol
    ///    and revision;
    /// 5. every relay hop must be both enabled by `relay_allow` and permitted by
    ///    its own `relay` rule (section 9.3 makes `relay_allow` a capability
    ///    switch, not a full authorisation).
    ///
    /// A refusal is never a fallback: no path re-derives the destination or
    /// quietly dials directly when a check fails.
    pub fn authorize_open(
        &self,
        caller: &str,
        fields: &OpenFields,
    ) -> Result<ExitPlan, OpenRefusal> {
        if fields.destination.validate().is_err() {
            return Err(OpenRefusal::denied(DETAIL_INVALID_DESTINATION));
        }
        if let Err(error) = validate_chain(caller, &fields.via, &fields.destination) {
            return Err(OpenRefusal::denied(match error {
                RouteError::TooManyHops { .. } => DETAIL_CHAIN_TOO_LONG,
                RouteError::DuplicateHop(_) => DETAIL_CHAIN_DUPLICATE,
                RouteError::SelfLoop(_) => DETAIL_CHAIN_LOOP,
                RouteError::DestinationInPath(_) => DETAIL_CHAIN_PUBLISHER,
                RouteError::NotASlug(_) | RouteError::InvalidPattern(_) => DETAIL_CHAIN_INVALID,
            }));
        }

        let (action, node, service, ip, port) = match &fields.destination {
            Destination::Address { host, port } => (
                wsnet_routing::AclAction::ConnectAddress,
                None,
                None,
                host.parse::<IpAddr>().ok(),
                Some(*port),
            ),
            Destination::Service { node, name, .. } => (
                wsnet_routing::AclAction::ConnectService,
                Some(node.as_str()),
                Some(name.as_str()),
                None,
                None,
            ),
            Destination::NodeAddress { node, host, port } => (
                wsnet_routing::AclAction::ConnectNodeAddress,
                Some(node.as_str()),
                None,
                host.parse::<IpAddr>().ok(),
                Some(*port),
            ),
        };
        let query = AclQuery {
            caller,
            action,
            node,
            service,
            ip,
            port,
            proto: fields.proto,
        };
        if !self.acl.check(&query).is_allowed() {
            return Err(OpenRefusal::denied(DETAIL_ACL_DENIED));
        }

        if !fields.via.is_empty() {
            for hop in &fields.via {
                if !self.relay.is_allowed(hop) {
                    return Err(OpenRefusal::denied(DETAIL_RELAY_NOT_ALLOWED));
                }
                let relay_query = AclQuery {
                    caller,
                    action: wsnet_routing::AclAction::Relay,
                    node: Some(hop.as_str()),
                    service: None,
                    ip: None,
                    port: None,
                    proto: fields.proto,
                };
                if !self.acl.check(&relay_query).is_allowed() {
                    return Err(OpenRefusal::denied(DETAIL_RELAY_ACL_DENIED));
                }
            }
            return Ok(ExitPlan::Relay {
                hops: fields.via.clone(),
            });
        }

        match &fields.destination {
            Destination::Service {
                node,
                name,
                revision,
            } => {
                let registry = self.registry.lock().expect("registry mutex");
                let lease = registry
                    .lookup(node, name)
                    .ok_or_else(|| OpenRefusal::offline(DETAIL_SERVICE_OFFLINE))?;
                if lease.proto != fields.proto {
                    return Err(OpenRefusal::refused(DETAIL_SERVICE_PROTO));
                }
                if let Some(pinned) = revision {
                    if *pinned != lease.revision {
                        return Err(OpenRefusal::refused(DETAIL_SERVICE_STALE));
                    }
                }
                Ok(ExitPlan::ServiceExit {
                    node_id: lease.node_id.clone(),
                    service_name: lease.service_name.clone(),
                    target: lease.target.clone(),
                    revision: lease.revision,
                })
            }
            Destination::NodeAddress { node, host, port } => {
                // Section 7.6: a raw address is reached *in that node's view*, so
                // the node must have a live lease even though its own ACL rules
                // were already checked above.
                if self
                    .registry
                    .lock()
                    .expect("registry mutex")
                    .node(node)
                    .is_none()
                {
                    return Err(OpenRefusal::offline(DETAIL_SERVICE_OFFLINE));
                }
                Ok(ExitPlan::NodeExit {
                    node_id: node.clone(),
                    host: host.clone(),
                    port: *port,
                })
            }
            Destination::Address { host, port } => Ok(ExitPlan::HubExit {
                host: host.clone(),
                port: *port,
            }),
        }
    }
}

/// Why a `BindProof` was refused.
#[derive(Debug)]
pub(crate) enum BindFailure {
    /// The header could not be parsed.
    Malformed(BindProofError),
    /// No such session, or it is already torn down.
    UnknownSession,
    /// The proof is outside its validity window.
    Expired,
    /// The MAC did not verify, which includes a proof used on another path.
    BadMac,
    /// The `bind_nonce` was already spent.
    Replayed,
}

impl BindFailure {
    /// A log-safe explanation; never sent to a peer (section 9.1).
    pub(crate) fn reason(&self) -> String {
        match self {
            BindFailure::Malformed(error) => format!("malformed bind proof: {error}"),
            BindFailure::UnknownSession => "unknown session".to_string(),
            BindFailure::Expired => "expired bind proof".to_string(),
            BindFailure::BadMac => "bind mac mismatch".to_string(),
            BindFailure::Replayed => "replayed bind nonce".to_string(),
        }
    }
}

impl From<BindProofError> for BindFailure {
    fn from(error: BindProofError) -> Self {
        BindFailure::Malformed(error)
    }
}

/// Parses and validates the configured listen address (section 9.3).
///
/// Only loopback is accepted. `localhost` is resolved to `127.0.0.1` so a
/// developer document does not need to be rewritten, but any other host name is
/// refused rather than looked up: resolving a name here would make the security
/// property depend on DNS.
fn parse_listen(value: &str) -> Result<SocketAddr, HubStartError> {
    let (host, port_text) = if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| HubStartError::InvalidListen(value.to_string()))?;
        (
            host,
            tail.strip_prefix(':')
                .ok_or_else(|| HubStartError::InvalidListen(value.to_string()))?,
        )
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| HubStartError::InvalidListen(value.to_string()))?;
        if host.contains(':') {
            // An unbracketed IPv6 literal is ambiguous with the port separator.
            return Err(HubStartError::InvalidListen(value.to_string()));
        }
        (host, port)
    };
    let port = port_text
        .parse::<u16>()
        .map_err(|_| HubStartError::InvalidListen(value.to_string()))?;
    let ip: IpAddr = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host.parse()
            .map_err(|_| HubStartError::InvalidListen(value.to_string()))?
    };
    if !ip.is_loopback() {
        return Err(HubStartError::NonLoopbackListen(value.to_string()));
    }
    Ok(SocketAddr::new(ip, port))
}

/// A duration helper for the carriers' bounded waits.
pub(crate) fn handshake_budget() -> Duration {
    Duration::from_millis(wsnet_limits::HANDSHAKE_TIMEOUT_MS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsnet_limits::{MAX_CHAIN_HOPS, PSK_LEN};
    use wsnet_routing::{AclAction, AclRule, Proto as RouteProto};

    const SID: [u8; 16] = [0x51; 16];
    const EPOCH: [u8; 16] = [0x6E; 16];

    fn psk() -> Psk {
        Psk::from_bytes([0x42; PSK_LEN])
    }

    fn config() -> ServerConfig {
        ServerConfig {
            server: ServerSection {
                hub_id: "hub-a".into(),
                listen: "127.0.0.1:8443".into(),
                ..ServerSection::default()
            },
            ..ServerConfig::default()
        }
    }

    fn rule(caller: &str, action: AclAction, node: Option<&str>, service: Option<&str>) -> AclRule {
        AclRule {
            caller: caller.into(),
            action,
            allow: true,
            node: node.map(Into::into),
            service: service.map(Into::into),
            host_cidr: None,
            ports: None,
            proto: None,
        }
    }

    fn hub_with(rules: Vec<AclRule>, relay: Vec<&str>) -> Hub {
        let mut config = config();
        config.acl = rules;
        config.server.relay_allow = relay.into_iter().map(|s| s.to_string()).collect();
        Hub::new(config, NodeSecrets::new().with("client-a", "a-1", psk())).unwrap()
    }

    fn open(destination: Destination, via: Vec<&str>) -> OpenFields {
        OpenFields {
            request_id: [1u8; 16],
            stream_id: 1,
            proto: RouteProto::Tcp,
            destination,
            via: via.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn a_non_loopback_listener_is_refused_at_construction() {
        for listen in ["0.0.0.0:8443", "192.168.1.10:8443", "[::]:8443"] {
            let mut config = config();
            config.server.listen = listen.to_string();
            let error = Hub::new(config, NodeSecrets::new()).unwrap_err();
            assert!(
                matches!(error, HubStartError::NonLoopbackListen(_)),
                "{listen} produced {error:?}"
            );
        }
        // ...even when an allowlist would otherwise satisfy the configuration.
        let mut config = config();
        config.server.listen = "0.0.0.0:8443".into();
        config.server.allow_from = vec!["10.0.0.0/8".into()];
        assert!(matches!(
            Hub::new(config, NodeSecrets::new()).unwrap_err(),
            HubStartError::NonLoopbackListen(_)
        ));
    }

    #[test]
    fn loopback_forms_are_accepted() {
        for listen in ["127.0.0.1:8443", "localhost:8443", "[::1]:8443"] {
            let mut config = config();
            config.server.listen = listen.to_string();
            assert!(Hub::new(config, NodeSecrets::new()).is_ok(), "{listen}");
        }
        let mut config = config();
        config.server.listen = "example.com:8443".into();
        assert!(matches!(
            Hub::new(config, NodeSecrets::new()).unwrap_err(),
            HubStartError::InvalidListen(_)
        ));
    }

    #[test]
    fn an_empty_acl_denies_every_kind_of_open() {
        let hub = hub_with(vec![], vec![]);
        for destination in [
            Destination::address("example.com", 443),
            Destination::service("client-b", "web"),
            Destination::node_address("client-b", "10.0.0.1", 22),
        ] {
            let refusal = hub.authorize_open("client-a", &open(destination, vec![]));
            assert_eq!(refusal.unwrap_err().status, OpenStatus::Denied);
        }
    }

    #[test]
    fn a_permitted_address_resolves_to_a_hub_exit() {
        let hub = hub_with(
            vec![rule("client-a", AclAction::ConnectAddress, None, None)],
            vec![],
        );
        let plan = hub
            .authorize_open(
                "client-a",
                &open(Destination::address("example.com", 443), vec![]),
            )
            .unwrap();
        assert_eq!(
            plan,
            ExitPlan::HubExit {
                host: "example.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn a_service_rule_does_not_grant_raw_node_addresses() {
        let hub = hub_with(
            vec![rule(
                "client-a",
                AclAction::ConnectService,
                Some("client-b"),
                Some("web"),
            )],
            vec![],
        );
        let refusal = hub
            .authorize_open(
                "client-a",
                &open(
                    Destination::node_address("client-b", "127.0.0.1", 22),
                    vec![],
                ),
            )
            .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);
        assert_eq!(refusal.detail, DETAIL_ACL_DENIED);

        // With its own rule the same target resolves.
        let hub = hub_with(
            vec![rule(
                "client-a",
                AclAction::ConnectNodeAddress,
                Some("client-b"),
                None,
            )],
            vec![],
        );
        // A raw address is reached in the named node's view, so it must have a
        // live lease (section 7.6).
        assert_eq!(
            hub.authorize_open(
                "client-a",
                &open(
                    Destination::node_address("client-b", "127.0.0.1", 22),
                    vec![]
                )
            )
            .unwrap_err()
            .status,
            OpenStatus::Offline
        );
        {
            let mut registry = hub.registry.lock().unwrap();
            registry.register_ready("client-b", SID, EPOCH);
        }
        assert_eq!(
            hub.authorize_open(
                "client-a",
                &open(
                    Destination::node_address("client-b", "127.0.0.1", 22),
                    vec![]
                )
            )
            .unwrap(),
            ExitPlan::NodeExit {
                node_id: "client-b".into(),
                host: "127.0.0.1".into(),
                port: 22
            }
        );
    }

    #[test]
    fn an_unpublished_service_is_offline_and_a_stale_revision_is_refused() {
        let hub = hub_with(
            vec![rule(
                "client-a",
                AclAction::ConnectService,
                Some("client-b"),
                Some("web"),
            )],
            vec![],
        );
        let refusal = hub
            .authorize_open(
                "client-a",
                &open(Destination::service("client-b", "web"), vec![]),
            )
            .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Offline);

        // Publish it, and the same request resolves to the publisher's target.
        {
            let mut registry = hub.registry.lock().unwrap();
            registry.register_ready("client-b", SID, EPOCH);
            registry
                .publish(
                    "client-b",
                    &SID,
                    &EPOCH,
                    "web",
                    RouteProto::Tcp,
                    "127.0.0.1:8080",
                )
                .unwrap();
        }
        assert_eq!(
            hub.authorize_open(
                "client-a",
                &open(Destination::service("client-b", "web"), vec![])
            )
            .unwrap(),
            ExitPlan::ServiceExit {
                node_id: "client-b".into(),
                service_name: "web".into(),
                target: "127.0.0.1:8080".into(),
                revision: 1
            }
        );

        // A pinned revision that no longer matches is refused rather than
        // re-resolved onto whatever is published now (section 7.6).
        let mut pinned = open(Destination::service("client-b", "web"), vec![]);
        pinned.destination = Destination::Service {
            node: "client-b".into(),
            name: "web".into(),
            revision: Some(9),
        };
        assert_eq!(
            hub.authorize_open("client-a", &pinned).unwrap_err().status,
            OpenStatus::Refused
        );
    }

    #[test]
    fn bad_via_chains_are_refused_before_any_acl_question() {
        let hub = hub_with(vec![], vec!["client-b"]);
        let too_long: Vec<&str> = vec!["h1", "h2", "h3", "h4", "h5"];
        assert_eq!(too_long.len(), MAX_CHAIN_HOPS + 1);

        for (via, expected) in [
            (vec!["client-a"], DETAIL_CHAIN_LOOP),
            (vec!["client-b", "client-b"], DETAIL_CHAIN_DUPLICATE),
            (too_long, DETAIL_CHAIN_TOO_LONG),
            (vec!["not a slug"], DETAIL_CHAIN_INVALID),
        ] {
            let refusal = hub
                .authorize_open(
                    "client-a",
                    &open(Destination::address("example.com", 443), via),
                )
                .unwrap_err();
            assert_eq!(refusal.status, OpenStatus::Denied);
            assert_eq!(refusal.detail, expected);
        }
    }

    #[test]
    fn a_valid_chain_still_needs_relay_permission() {
        // `relay_allow` names the hop, but no `[[acl]]` relay rule exists.
        let hub = hub_with(
            vec![rule("client-a", AclAction::ConnectAddress, None, None)],
            vec!["client-b"],
        );
        let refusal = hub
            .authorize_open(
                "client-a",
                &open(Destination::address("example.com", 443), vec!["client-b"]),
            )
            .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);
        assert_eq!(refusal.detail, DETAIL_RELAY_ACL_DENIED);

        // Without `relay_allow` the same chain is refused earlier.
        let hub = hub_with(
            vec![
                rule("client-a", AclAction::ConnectAddress, None, None),
                rule("client-a", AclAction::Relay, Some("client-b"), None),
            ],
            vec![],
        );
        assert_eq!(
            hub.authorize_open(
                "client-a",
                &open(Destination::address("example.com", 443), vec!["client-b"])
            )
            .unwrap_err()
            .detail,
            DETAIL_RELAY_NOT_ALLOWED
        );

        // With both gates open the chain resolves to a relay plan.
        let hub = hub_with(
            vec![
                rule("client-a", AclAction::ConnectAddress, None, None),
                rule("client-a", AclAction::Relay, Some("client-b"), None),
            ],
            vec!["client-b"],
        );
        assert_eq!(
            hub.authorize_open(
                "client-a",
                &open(Destination::address("example.com", 443), vec!["client-b"])
            )
            .unwrap(),
            ExitPlan::Relay {
                hops: vec!["client-b".into()]
            }
        );
    }

    #[test]
    fn a_service_chain_must_not_name_the_publisher() {
        let hub = hub_with(
            vec![rule(
                "client-a",
                AclAction::ConnectService,
                Some("client-b"),
                Some("web"),
            )],
            vec![],
        );
        let refusal = hub
            .authorize_open(
                "client-a",
                &open(Destination::service("client-b", "web"), vec!["client-b"]),
            )
            .unwrap_err();
        assert_eq!(refusal.detail, DETAIL_CHAIN_PUBLISHER);
    }

    #[test]
    fn an_invalid_destination_is_refused() {
        let hub = hub_with(
            vec![rule("client-a", AclAction::ConnectAddress, None, None)],
            vec![],
        );
        let mut fields = open(Destination::address("example.com", 443), vec![]);
        fields.destination = Destination::address("example.com", 0);
        assert_eq!(
            hub.authorize_open("client-a", &fields).unwrap_err().detail,
            DETAIL_INVALID_DESTINATION
        );
    }

    #[test]
    fn node_secrets_refuse_a_key_that_belongs_to_another_node_or_hub() {
        let secrets = NodeSecrets::new().with("client-a", "a-1", psk());
        assert!(secrets.get("a-1", "client-a").is_some());
        assert!(secrets.get("a-1", "client-b").is_none());
        assert!(secrets.get("a-2", "client-a").is_none());
        assert_eq!(secrets.len(), 1);
        assert!(!secrets.is_empty());
    }

    #[test]
    fn a_hub_without_credentials_starts_but_registers_nobody() {
        // A Hub with no credentials accepts nobody, but it must still start: the
        // refusal belongs to the authentication path, not to construction.
        let hub = Hub::new(config(), NodeSecrets::new()).unwrap();
        assert!(!hub.is_node_registered("client-a"));
        assert_eq!(hub.registered_node_count(), 0);
        assert_eq!(hub.session_count(), 0);
    }
}
