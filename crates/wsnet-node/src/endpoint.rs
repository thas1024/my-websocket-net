//! The seam between the node and one Hub's plumbing.
//!
//! DESIGN.md section 5.3 requires at least one carrier pair that can send and
//! receive (`WS`, or `POST` uplink plus an `SSE`/`POST` response downlink), and
//! section 4.4 fixes where the bootstrap lives: `/m` accepts only the `Auth`
//! bootstrap before authentication. Both facts are expressed here as three
//! transport operations, so the session logic in [`crate::hub`] never mentions
//! HTTP, WebSocket, or any other framing.

use std::sync::Arc;

use crate::{BoxFuture, NodeError};

/// One configured `[[servers]]` entry, as a transport needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubEndpoint {
    /// Hub identity, matched against the Hub's own `hub_id`.
    pub hub_id: String,
    /// Absolute `http`/`https` base URL of the Hub.
    pub url: String,
    /// Key identifier presented during authentication.
    pub key_id: String,
    /// Failover order; lower is tried first (DESIGN.md section 8).
    pub priority: u32,
}

/// What a transport needs to address an already authenticated session.
///
/// The session id is a routing label, never a bearer credential (DESIGN.md
/// section 4.4), which is why it is safe to hand to a transport purely so that
/// requests land in the right per-session queue.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundSession {
    /// Hub the session belongs to.
    pub hub_id: String,
    /// Node identity that authenticated.
    pub node_id: String,
    /// Assigned session id.
    pub session_id: [u8; 16],
    /// Session key epoch.
    pub session_epoch: [u8; 16],
    /// The binding key `K_bind` from section 4.2.
    ///
    /// Section 4.4 requires every authenticated carrier request to present a
    /// `BindProof` MACed with this key, and the transport is where that proof is
    /// built, so the key has to reach it. It never leaves this process, and the
    /// manual `Debug` below keeps it out of logs.
    pub bind_key: [u8; 32],
}

impl core::fmt::Debug for BoundSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoundSession")
            .field("hub_id", &self.hub_id)
            .field("node_id", &self.node_id)
            .field("session_id", &hex::encode(self.session_id))
            .field("session_epoch", &hex::encode(self.session_epoch))
            .field("bind_key", &"<redacted>")
            .finish()
    }
}

/// One Hub's carrier plumbing.
///
/// Every method is bounded by the caller: the node applies the handshake and
/// open deadlines from `wsnet-limits` rather than trusting a transport to give
/// up on its own.
pub trait HubTransport: Send + Sync + 'static {
    /// Sends the `Auth` bootstrap and returns the `AuthOk` bootstrap body.
    ///
    /// The bytes are the canonical metadata of `Auth` and `AuthOk`; the node —
    /// not the transport — computes and verifies the MACs, so a transport can
    /// never be the place a PSK leaks into.
    fn authenticate(&self, auth: Vec<u8>) -> BoxFuture<'static, Result<Vec<u8>, NodeError>>;

    /// Binds the carriers of an authenticated session.
    ///
    /// At least one returned carrier must be able to carry uplink data and at
    /// least one must be able to carry downlink data, which is the section 5.3
    /// requirement that a session has "至少一个可双向收发的组合".
    fn bind(
        &self,
        session: BoundSession,
    ) -> BoxFuture<'static, Result<Vec<crate::CarrierIo>, NodeError>>;

    /// Runs one bounded liveness round trip on an authenticated session.
    ///
    /// DESIGN.md section 5.5 requires a health check that proves the *proxy*
    /// works ("不把静态网页 HTTP 200 当代理可用"), so this must be an
    /// authenticated exchange and not a plain page fetch.
    fn health(&self, session: BoundSession) -> BoxFuture<'static, Result<(), NodeError>>;
}

/// Builds the [`HubTransport`] that reaches one Hub.
pub trait TransportFactory: Send + Sync + 'static {
    /// Opens the transport for `endpoint`.
    ///
    /// A transport instance belongs to exactly one Hub session, so it may keep
    /// the connection it authenticated with.
    fn open(
        &self,
        endpoint: &HubEndpoint,
    ) -> BoxFuture<'static, Result<Arc<dyn HubTransport>, NodeError>>;
}
