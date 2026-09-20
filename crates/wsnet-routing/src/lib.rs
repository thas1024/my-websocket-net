//! wsnet routing, destinations, and authorisation.
//!
//! Three concerns that the design keeps explicitly separate:
//!
//! * [`dest`] — the strict `Open` destination union (§7.6).
//! * [`router`] — ordered match rules that pick a *route*, including chain
//!   validation (§7.1).
//! * [`acl`] — default-deny authorisation (§9.3).
//!
//! §10 states the relationship plainly: "路由选中了节点，不代表访问一定被允许".
//! Nothing in this crate turns a route into a permission; both gates are checked
//! independently by the Hub and again by the exit node.

#![forbid(unsafe_code)]

pub mod acl;
pub mod dest;
pub mod router;

pub use acl::{AclAction, AclDecision, AclError, AclQuery, AclRule, AclTable, RelayAllow};
pub use dest::{
    is_slug, Destination, DestinationError, DestinationKind, Proto, MAX_SLUG_LEN,
};
pub use router::{validate_chain, FinalRoute, RouteDecision, RouteError, RouteRule, Router, RouterTable};
