#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! The wsnet Hub server (DESIGN.md sections 4.3, 4.4, 5, 7.1, 8, 9, 11).
//!
//! The Hub is the HTTP(S) face of a wsnet deployment. nginx terminates TLS and
//! forwards a small, fixed set of paths to this backend, which must therefore
//! listen on loopback only (section 9.3). Everything the backend serves is one of:
//!
//! | path | carrier | who may use it |
//! | --- | --- | --- |
//! | `POST /m` | POST batch (section 4.3) | one `Auth` before authentication, then `BindProof`-bound records |
//! | `GET /e` | SSE downlink (section 4.3) | an authenticated session with a `BindProof` |
//! | `GET /w` | WebSocket (section 4.4) | a Text `Auth` bootstrap, or a `BindProof`-bound session |
//! | configured profile paths | JSON/HTML/CSS/JS profiles (section 6.4) | the same rules as `POST /m` |
//! | anything else | the deployment site ([`wsnet_site`]) | unauthenticated, public content only |
//!
//! Three properties of this crate are worth stating explicitly, because they are
//! the reason the module split looks the way it does:
//!
//! * **Every failure looks the same.** Authentication, replay, unknown-node, and
//!   binding failures all resolve to [`wsnet_site::Site::failure`] for the current
//!   protocol stage. Section 9.1's table is enforced by the type: the failure API
//!   takes a [`wsnet_site::FailureStage`] and nothing else, so a call site cannot
//!   leak *which* check refused the request.
//! * **Carriers own no session state.** A session is a [`wsnet_session`] engine
//!   plus one downlink broadcast channel ([`session`]); every carrier feeds sealed
//!   envelopes into the same engine and reads replies from the same channel, so
//!   switching carriers never changes the session (section 6.3).
//! * **Nothing is dialled that was not authorised.** [`Hub::authorize_open`] is
//!   the single place that turns an `Open` into a decision, and it is default-deny
//!   in the sense of section 9.3: an empty `[[acl]]` permits nothing.
//!
//! # What this build deliberately does not implement
//!
//! The Hub-side *egress data plane* is not implemented. An `Open` that passes
//! every authorisation check is answered with a clear `OpenResult` refusal rather
//! than silently succeeding, and multi-hop `via` chains are validated and then
//! refused with a distinct detail. See [`Hub::authorize_open`].

pub mod bind;
mod error;
mod guard;
mod hub;
mod server;
mod session;

pub use bind::{
    binding_mac, body_hash, BindProof, BindProofError, BindProofRegistry, BindTarget,
    BIND_PROOF_HEADER,
};
pub use error::HubStartError;
pub use hub::{ExitPlan, Hub, NodeSecrets, OpenRefusal, ProfilePaths, DEFAULT_SESSION_TTL_SECS};
