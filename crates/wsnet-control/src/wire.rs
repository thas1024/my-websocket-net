//! The management conversation: what the CLI asks and what the daemon answers.
//!
//! The variants cover exactly the commands USAGE.md section 2 lists for a running
//! node, and nothing else. A management protocol that can express more than the
//! documented CLI surface is a second, undocumented management API, which
//! USAGE.md section 1 rules out.
//!
//! Payloads reuse the data plane's own selector types
//! ([`wsnet_routing::Destination`], [`wsnet_routing::Proto`]) instead of a
//! control-only copy, because USAGE.md section 12 requires the CLI and the static
//! configuration to produce the same `Open` target selector.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use wsnet_routing::{Destination, Proto};

/// State of the daemon process, as reported by [`Request::Status`].
///
/// USAGE.md section 2 exposes `wsnet status` for a running node; these are the
/// process-level answers that command can give. Session-level detail is carried
/// per Hub by [`HubSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonState {
    /// Starting up: listeners may be bound, but no Hub session is usable yet.
    Starting,
    /// Serving traffic.
    Running,
    /// Shutting down: new work is refused while existing sessions drain.
    Stopping,
}

/// State of one Hub session.
///
/// The states are the lifecycle DESIGN.md section 5.3 defines
/// (`Offline -> Authenticating -> Binding -> HelloPending -> Ready -> Degraded ->
/// Ready/Closed`). A node may hold a session to several Hubs at once
/// (DESIGN.md section 5.5), so status reports one of these per Hub rather than a
/// single node-wide session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// No carrier is up for this Hub.
    Offline,
    /// Authenticating on at least one carrier candidate.
    Authenticating,
    /// Credentials accepted; carriers still being bound.
    Binding,
    /// Bound, waiting for the business barrier (`HelloOk`).
    HelloPending,
    /// Usable for new work.
    Ready,
    /// A carrier failed inside the same-Hub grace window; recovery is possible.
    Degraded,
    /// Session ended; outstanding work failed rather than being migrated.
    Closed,
}

/// One Hub's session state inside a [`StatusReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubSession {
    /// Stable Hub identifier from the node's configuration (DESIGN.md section 5.5).
    pub hub_id: String,
    /// Current lifecycle state of the session to that Hub.
    pub state: SessionState,
}

/// Traffic and object counters shown by `wsnet status`.
///
/// DESIGN.md section 7.5 accounts for bytes as they are consumed rather than as
/// they arrive, so `bytes_sent` and `bytes_received` are the daemon's own
/// accounting, not a socket-level guess.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    /// Bytes handed to Hub carriers since start.
    pub bytes_sent: u64,
    /// Bytes taken from Hub carriers since start.
    pub bytes_received: u64,
    /// Streams currently open across all sessions.
    pub streams_open: u64,
    /// Local forwards currently bound, in any lifecycle state.
    pub forwards_active: u64,
    /// Services this node currently publishes.
    pub services_published: u64,
    /// Management requests answered since start, including refused ones.
    pub control_requests: u64,
}

/// The reply to [`Request::Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    /// Process-level state.
    pub daemon: DaemonState,
    /// This node's identity, as known to the Hubs.
    pub node_id: String,
    /// Seconds since the daemon started.
    pub uptime_secs: u64,
    /// Per-Hub session states.
    pub hubs: Vec<HubSession>,
    /// Traffic and object counters.
    pub counters: Counters,
}

/// Visibility state of one published service.
///
/// This is the state field USAGE.md section 6 requires in a service-directory
/// entry. It mirrors the publishing node's session state (DESIGN.md section 5.3)
/// for the Hub the entry was learned from, and never widens what the caller is
/// allowed to discover (DESIGN.md section 9.3, default deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// Published by a Ready node on this Hub.
    Ready,
    /// Publisher or carrier degraded, but the lease still exists.
    Degraded,
    /// Publisher not currently registered on this Hub.
    Offline,
}

/// One entry of the service directory.
///
/// The field set is the one USAGE.md section 6 promises: hub id, node id, service
/// name, protocol, revision, and state. Listing is already filtered by the
/// caller's discoverability, so an unlisted service is indistinguishable from an
/// absent one rather than reported as denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDescriptor {
    /// Hub the entry was learned from.
    pub hub: String,
    /// Node that publishes the service.
    pub node: String,
    /// Service name (a normalised ASCII slug, DESIGN.md section 7.6).
    pub name: String,
    /// Protocol the service is published over.
    pub proto: Proto,
    /// Service revision; a newer registration of the same name changes it.
    pub revision: u64,
    /// Current visibility state.
    pub state: ServiceState,
}

/// The reply to [`Request::ServicesList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServicesReport {
    /// Visible services, after the hub and node filters were applied.
    pub services: Vec<ServiceDescriptor>,
}

/// Lifecycle state of a local forward.
///
/// USAGE.md section 7 separates the local listener from remote readiness, and
/// these six states are that table: `Bound` means only that the local socket
/// exists. Reporting them separately is what lets `wsnet forward list` explain a
/// listener that is up while the far end is offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardState {
    /// The local TCP/UDP socket is bound; this says nothing about the far end.
    Bound,
    /// Publisher Ready, service present, ACL allows.
    Ready,
    /// Hub or carrier trouble, possibly recoverable inside the grace window.
    Degraded,
    /// Publisher or service offline; new connections fail fast.
    Offline,
    /// Refused by ACL; never silently replaced by a direct connection.
    Denied,
    /// Local bind or configuration error.
    Error,
}

/// A request to bind one local forward, as described by USAGE.md section 5.
///
/// `listen` is a [`SocketAddr`] rather than a host-and-port string on purpose:
/// USAGE.md section 5.1 restricts local forwards to loopback unless a source
/// allowlist is configured, and an IP literal is what makes that restriction
/// checkable. A name such as `localhost` could pass a text check and still
/// resolve to a public interface.
///
/// Unknown fields are refused. Every other request shape fails loudly on a
/// missing field, but a forward spec is the place where an ignored extra field
/// would quietly change what the user asked for (a mistyped `via` list becoming a
/// direct forward, for instance).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardSpec {
    /// User-chosen name, unique among active forwards.
    pub name: String,
    /// Requested local address. Port 0 asks the OS for one (USAGE.md section 5.1).
    pub listen: SocketAddr,
    /// Local transport protocol.
    pub proto: Proto,
    /// Hub id, or the literal `"auto"` for automatic Hub selection.
    pub hub: String,
    /// Intermediate relay nodes only; the destination node is the final leg
    /// (USAGE.md section 5.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via: Vec<String>,
    /// Strict target union (DESIGN.md section 7.6).
    pub destination: Destination,
}

/// One active forward, as listed by `wsnet forward list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardInfo {
    /// What the client asked for.
    pub spec: ForwardSpec,
    /// The address the listener actually bound, which differs from
    /// [`ForwardSpec::listen`] whenever the port was left to the OS. USAGE.md
    /// section 5.1 requires the CLI to print this real address.
    pub resolved_listen: SocketAddr,
    /// Current lifecycle state.
    pub state: ForwardState,
}

/// The reply to [`Request::ForwardList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardListReport {
    /// Active forwards, in the daemon's own order.
    pub forwards: Vec<ForwardInfo>,
}

/// One management command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// `wsnet status` (USAGE.md section 2).
    Status,
    /// `wsnet services list [--hub HUB] [--node NODE]` (USAGE.md section 2).
    ServicesList {
        /// Restrict to one Hub when set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hub: Option<String>,
        /// Restrict to services published by one node when set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node: Option<String>,
    },
    /// `wsnet forward list` (USAGE.md section 2).
    ForwardList,
    /// `wsnet forward add` (USAGE.md section 5). In-memory only, so it disappears
    /// with the process.
    ForwardAdd {
        /// The forward to add.
        spec: ForwardSpec,
    },
    /// `wsnet forward remove NAME` (USAGE.md section 2).
    ForwardRemove {
        /// Name of the active forward to drop.
        name: String,
    },
}

/// Why a request was refused.
///
/// USAGE.md section 7 requires a reason to be available locally when a forward
/// cannot be used, and DESIGN.md section 9.3 keeps refusals explicit rather than
/// silently substituting another route, so a refusal is a first-class response
/// rather than a transport error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The request itself was unusable (bad slug, non-loopback listen, and so on).
    BadRequest,
    /// The named forward or service does not exist.
    NotFound,
    /// The name or listen address is already taken.
    Conflict,
    /// ACL or policy refused; no automatic bypass follows.
    Denied,
    /// The daemon cannot serve this right now (no ready Hub, for instance).
    Unavailable,
    /// An unexpected internal failure.
    Internal,
}

/// A refusal, carrying the reason the CLI prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Machine-readable class of the refusal.
    pub code: ErrorCode,
    /// Human-readable reason.
    pub message: String,
}

impl ErrorResponse {
    /// Builds a refusal.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ErrorResponse {
            code,
            message: message.into(),
        }
    }
}

/// One management answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    /// Answer to [`Request::Status`].
    Status(StatusReport),
    /// Answer to [`Request::ServicesList`].
    Services(ServicesReport),
    /// Answer to [`Request::ForwardList`].
    ForwardList(ForwardListReport),
    /// Answer to [`Request::ForwardAdd`], carrying the address that was really
    /// bound.
    ForwardAdded {
        /// Name of the forward that was added.
        name: String,
        /// Real listen address.
        listen: SocketAddr,
    },
    /// Answer to [`Request::ForwardRemove`].
    ForwardRemoved {
        /// Name of the forward that was removed.
        name: String,
    },
    /// Any refusal.
    Error(ErrorResponse),
}

impl Response {
    /// Builds a refusal, the only sanctioned way for a handler to say no.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Response::Error(ErrorResponse::new(code, message))
    }

    /// Whether this answer is a refusal.
    pub const fn is_error(&self) -> bool {
        matches!(self, Response::Error(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every request variant must survive a JSON round trip. The framing tests
    /// cover the same variants with the length prefix; this one keeps a failure
    /// attributable to the payload type rather than to the codec.
    #[test]
    fn every_request_variant_round_trips_through_json() {
        for request in [
            Request::Status,
            Request::ServicesList {
                hub: None,
                node: None,
            },
            Request::ServicesList {
                hub: Some("hub-a".into()),
                node: Some("client-a".into()),
            },
            Request::ForwardList,
            Request::ForwardAdd {
                spec: ForwardSpec {
                    name: "a-web".into(),
                    listen: "127.0.0.1:0".parse().unwrap(),
                    proto: Proto::Tcp,
                    hub: "auto".into(),
                    via: vec!["client-b".into()],
                    destination: Destination::service("client-a", "web"),
                },
            },
            Request::ForwardRemove {
                name: "a-web".into(),
            },
        ] {
            let text = serde_json::to_string(&request).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&text).unwrap(), request);
        }
    }

    /// The optional filters must be absent from the JSON when unset, so a plain
    /// `wsnet services list` and one with filters stay distinguishable on the
    /// wire.
    #[test]
    fn unset_services_filters_are_not_serialised() {
        let text = serde_json::to_string(&Request::ServicesList {
            hub: None,
            node: None,
        })
        .unwrap();
        assert_eq!(text, r#"{"request":"services_list"}"#);
    }

    /// A misspelled field in a forward spec must be refused, not ignored.
    #[test]
    fn unknown_forward_spec_fields_are_refused() {
        let text = r#"{
            "name": "a-web",
            "listen": "127.0.0.1:0",
            "proto": "tcp",
            "hub": "auto",
            "viia": ["client-b"],
            "destination": {"type": "service", "node": "client-a", "name": "web"}
        }"#;
        assert!(serde_json::from_str::<ForwardSpec>(text).is_err());
    }

    #[test]
    fn error_responses_report_themselves() {
        assert!(Response::error(ErrorCode::NotFound, "no such forward").is_error());
        assert!(!Response::ForwardRemoved { name: "a".into() }.is_error());
    }
}
