//! Inbound streams: this node acting as the *publisher* (DESIGN.md section 7.6).
//!
//! Section 7.6 splits reverse access in two: "Hub 解析当前 lease，最终节点按自身
//! 服务表再次解析，不接受调用方覆盖本机地址". The Hub routes by node and service
//! name; this module is the second resolution, and it is the only place that
//! decides which local address a caller can reach.
//!
//! Two properties are deliberately structural rather than conventional:
//!
//! * **The caller can never choose a local address.** A `ServiceTarget` resolves
//!   against this node's own `[[services]]` table, so the host and port come from
//!   local configuration even though the request carried a destination.
//! * **Raw node addresses are default deny** (section 9.3: "出口节点独立校验本地
//!   策略，注册服务不得绕过规则"). A `NodeAddressTarget` needs an explicit entry
//!   in [`InboundPolicy`], and publishing a service never implies access to any
//!   other address on this host.

use std::net::IpAddr;

use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use wsnet_session::{
    OpenFields, OpenResultFields, OpenStatus, ResetReason, ServiceRegistration, SessionHandle,
};

use crate::stream::{SessionStream, StreamMsg};

/// How much a single read from the local target may carry.
const READ_CHUNK: usize = 16 * 1024;

/// A local address this node is willing to dial for an inbound stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// Host exactly as this node's configuration wrote it.
    pub host: String,
    /// Port from this node's configuration.
    pub port: u16,
}

/// Why an inbound `Open` was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRefusal {
    /// Status reported to the Hub and, through it, to the caller.
    pub status: OpenStatus,
    /// A local-only explanation; it never reaches an application.
    pub detail: String,
}

impl InboundRefusal {
    fn new(status: OpenStatus, detail: impl Into<String>) -> Self {
        InboundRefusal {
            status,
            detail: detail.into(),
        }
    }
}

/// What this node allows an inbound `Open` to reach.
///
/// Default deny throughout: a `ServiceTarget` is resolvable only against the
/// published service table, and a `NodeAddressTarget` only against an explicit
/// allowlist. An empty policy therefore permits nothing but published services.
#[derive(Debug, Clone, Default)]
pub struct InboundPolicy {
    allow_node_address: Vec<IpNet>,
    /// Whether this node will act as an intermediate hop of another caller's
    /// chain (DESIGN.md section 7.1).
    ///
    /// Default deny, and deliberately separate from the Hub's own `relay` ACL:
    /// carrying someone else's traffic makes this node a hop for destinations it
    /// never published, so section 9.3's "出口节点独立校验本地策略" applies to the
    /// node's own consent as well as to the Hub's per-edge permit. A node with
    /// `relay_forward` off refuses every chain leg it did not publish itself.
    relay_forward: bool,
}

impl InboundPolicy {
    /// A policy that permits published services only.
    pub fn deny_all() -> Self {
        InboundPolicy::default()
    }

    /// Permits a raw node address inside `cidr`, which must parse.
    pub fn allow_node_address(mut self, cidr: &str) -> Result<Self, String> {
        let net: IpNet = cidr
            .parse()
            .map_err(|_| format!("`{cidr}` is not a valid CIDR"))?;
        self.allow_node_address.push(net);
        Ok(self)
    }

    /// Records whether this node consents to being an intermediate hop.
    pub fn with_relay_forward(mut self, allowed: bool) -> Self {
        self.relay_forward = allowed;
        self
    }

    /// Whether this node will continue another caller's chain (section 7.1).
    pub fn relays_forward(&self) -> bool {
        self.relay_forward
    }

    /// Whether this node may dial `host` for a `NodeAddressTarget`.
    ///
    /// A hostname is not an address, so it cannot be checked against a CIDR and
    /// is refused: accepting it would let a name resolve anywhere after the
    /// policy had already said yes.
    fn permits_node_address(&self, host: &str) -> bool {
        match host.parse::<IpAddr>() {
            Ok(ip) => self
                .allow_node_address
                .iter()
                .any(|net| net.contains(&ip)),
            Err(_) => false,
        }
    }
}

/// What this node should do with an inbound `Open`.
///
/// Section 7.1's chain is a star-shaped return path: `via=[A,B]` means
/// client→H→A→H→B→target, so a node that was handed a leg with hops left is not an
/// exit at all — it must hand the flow *back* to the Hub. That is a different
/// action from dialling, which is why the decision is a type rather than a flag on
/// [`ResolvedTarget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundPlan {
    /// Dial a local target: this node is the chain's exit.
    Dial(ResolvedTarget),
    /// Continue the chain through the Hub, because this node is a hop.
    Forward,
}

/// Decides between exiting and continuing a chain (DESIGN.md sections 7.1, 7.6).
///
/// The rule is a single question: does this leg name *this* node as the end? A leg
/// whose `via` is non-empty has hops left by construction, and a leg whose
/// destination names another node is a service or address that belongs to that
/// node — in both cases this node is a hop, never the exit. Everything else is the
/// existing reverse-access resolution in [`resolve_inbound`], which is where the
/// caller-invisible local policy lives.
pub fn plan_inbound(
    node_id: &str,
    services: &[ServiceRegistration],
    policy: &InboundPolicy,
    fields: &OpenFields,
) -> Result<InboundPlan, InboundRefusal> {
    let continue_chain = |what: &str| {
        if policy.relays_forward() {
            Ok(InboundPlan::Forward)
        } else {
            Err(InboundRefusal::new(
                OpenStatus::Denied,
                format!("{what}, and this node does not relay for other callers"),
            ))
        }
    };

    // Section 7.1: a hop is told the rest of the chain in the leg's own `via`.
    if !fields.via.is_empty() {
        return continue_chain("the open still has hops to run");
    }

    match &fields.destination {
        // The Hub sends a leg to the node it names as the exit, so any other name
        // is someone else's destination and this node is only a hop.
        wsnet_routing::Destination::Service { node, .. }
        | wsnet_routing::Destination::NodeAddress { node, .. }
            if node != node_id =>
        {
            continue_chain("the destination belongs to another node")
        }
        // A plain address with no hops left is a `via=[A]` chain: the Hub itself
        // dials plain addresses, so it only sends one here to make this node the
        // exit. The exit's own allowlist is the second gate section 9.3 requires,
        // and it is the *same* gate a `NodeAddressTarget` naming this node passes,
        // so being a chain's exit grants nothing a published forward could not
        // already ask for.
        wsnet_routing::Destination::Address { host, port } => {
            if *port == 0 || !policy.permits_node_address(host) {
                return Err(InboundRefusal::new(
                    OpenStatus::Denied,
                    format!("`{host}:{port}` is not in this node's allowlist"),
                ));
            }
            Ok(InboundPlan::Dial(ResolvedTarget {
                host: host.clone(),
                port: *port,
            }))
        }
        _ => resolve_inbound(node_id, services, policy, fields).map(InboundPlan::Dial),
    }
}

/// Resolves an inbound `Open` against this node's own configuration.
///
/// `services` is the same list this node registered in its `Hello`, so what a
/// caller can reach through the Hub and what this node will dial cannot drift
/// apart.
pub fn resolve_inbound(
    node_id: &str,
    services: &[ServiceRegistration],
    policy: &InboundPolicy,
    fields: &OpenFields,
) -> Result<ResolvedTarget, InboundRefusal> {
    match &fields.destination {
        wsnet_routing::Destination::Service {
            node,
            name,
            revision,
        } => {
            // A caller must not be able to make this node serve another node's
            // name, and must not reach a service this node never published.
            if node != node_id {
                return Err(InboundRefusal::new(
                    OpenStatus::Denied,
                    format!("service `{name}` is not published by this node"),
                ));
            }
            let service = services
                .iter()
                .find(|service| &service.name == name)
                .ok_or_else(|| {
                    InboundRefusal::new(
                        OpenStatus::Offline,
                        format!("no service named `{name}` is published here"),
                    )
                })?;
            if let Some(pinned) = revision {
                // A pinned revision this node cannot honour must fail rather
                // than silently resolving to whatever is configured now.
                if *pinned != 1 {
                    return Err(InboundRefusal::new(
                        OpenStatus::Offline,
                        format!("service `{name}` has no revision {pinned}"),
                    ));
                }
            }
            parse_target(&service.target).ok_or_else(|| {
                InboundRefusal::new(
                    OpenStatus::Unreachable,
                    format!("service `{name}` has an unusable local target"),
                )
            })
        }
        wsnet_routing::Destination::NodeAddress { node, host, port } => {
            if node != node_id {
                return Err(InboundRefusal::new(
                    OpenStatus::Denied,
                    "the address belongs to a different node",
                ));
            }
            if *port == 0 {
                return Err(InboundRefusal::new(
                    OpenStatus::Denied,
                    "port 0 is not a dialable address",
                ));
            }
            if !policy.permits_node_address(host) {
                return Err(InboundRefusal::new(
                    OpenStatus::Denied,
                    format!("`{host}:{port}` is not in this node's allowlist"),
                ));
            }
            Ok(ResolvedTarget {
                host: host.clone(),
                port: *port,
            })
        }
        wsnet_routing::Destination::Address { .. } => Err(InboundRefusal::new(
            OpenStatus::Denied,
            "an address target is not a reverse-access destination",
        )),
    }
}

/// Splits a configured `host:port`, accepting a bracketed IPv6 literal.
fn parse_target(target: &str) -> Option<ResolvedTarget> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host.to_string(), rest.strip_prefix(':')?)
    } else {
        let (host, port) = target.rsplit_once(':')?;
        (host.to_string(), port)
    };
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(ResolvedTarget { host, port })
}

/// Dials one inbound target, answers the Hub, and carries bytes both ways.
///
/// Everything after the `Open` is owned by this task, so one slow target cannot
/// stall the session driver or another stream (section 7.5).
///
/// Crate-internal because it is driven by the session driver and speaks
/// [`StreamMsg`], which is not part of the crate's public surface.
pub(crate) async fn serve_inbound(
    handle: SessionHandle,
    request_id: [u8; 16],
    stream_id: u64,
    target: ResolvedTarget,
    mut events: mpsc::UnboundedReceiver<StreamMsg>,
) {
    // The dial happens before the answer, because section 7.1 only allows a
    // success to be reported once the target really exists.
    let mut socket = match TcpStream::connect((target.host.as_str(), target.port)).await {
        Ok(socket) => socket,
        Err(error) => {
            // The OS message is localized and unstable, so only the kind is
            // reported; the full error stays in the local log.
            debug!(%error, %stream_id, "inbound dial failed");
            let status = match error.kind() {
                std::io::ErrorKind::ConnectionRefused => OpenStatus::Refused,
                _ => OpenStatus::Unreachable,
            };
            let result = OpenResultFields {
                request_id,
                stream_id,
                status,
                detail: "the published target is not reachable".to_string(),
            };
            let _ = handle.send_open_result(&result);
            return;
        }
    };

    let result = OpenResultFields {
        request_id,
        stream_id,
        status: OpenStatus::Ok,
        detail: "the published target accepted".to_string(),
    };
    // `send_open_result` sends `Ready` itself on success, which is what section
    // 7.1 requires before either side may forward target-originated bytes.
    if handle.send_open_result(&result).is_err() {
        return;
    }
    debug!(%stream_id, host = %target.host, port = target.port, "inbound stream established");

    let mut buffer = vec![0u8; READ_CHUNK];
    // Bytes read from the target that the peer's credit has not accepted yet.
    let mut pending: Vec<u8> = Vec::new();
    let mut target_eof = false;
    let mut fin_sent = false;
    // The peer's `Fin`, remembered until every byte below it reached the socket.
    let mut final_offset: Option<u64> = None;
    let mut written = 0u64;
    let mut write_shutdown = false;

    loop {
        // Move whatever the peer's credit allows. A short send is normal: the
        // rest stays here and is retried when `Progress` raises the limit.
        while !pending.is_empty() {
            match handle.send_data(stream_id, &pending) {
                Ok(0) => break,
                Ok(sent) => {
                    pending.drain(..sent);
                }
                Err(_) => break,
            }
        }

        if target_eof && pending.is_empty() && !fin_sent {
            if handle.send_fin(stream_id).is_err() {
                return;
            }
            fin_sent = true;
        }

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
                        debug!(%error, %stream_id, "the published target failed");
                        let _ = handle.send_reset(stream_id, ResetReason::Unreachable);
                        return;
                    }
                }
            }
            message = events.recv() => {
                match message {
                    Some(StreamMsg::Data(payload)) => {
                        if socket.write_all(&payload).await.is_err() {
                            let _ = handle.send_reset(stream_id, ResetReason::Unreachable);
                            return;
                        }
                        written += payload.len() as u64;
                        // Section 7.5: credit follows consumption, so it is
                        // granted only after the bytes reached the target.
                        let _ = handle.consume(stream_id, payload.len() as u64);
                    }
                    Some(StreamMsg::Fin(offset)) => final_offset = Some(offset),
                    Some(StreamMsg::Reset(_)) => {
                        let _ = socket.shutdown().await;
                        return;
                    }
                    // A raised limit is picked up by the next delivery attempt.
                    Some(StreamMsg::Credit) => trace!(%stream_id, "credit raised"),
                    None => return,
                }
            }
        }
    }
}

/// The next leg a hop has to open (DESIGN.md section 7.1).
///
/// Kept as a value so the *decision* ([`plan_inbound`]) stays independent of the
/// plumbing that carries it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainLeg {
    /// Destination exactly as the Hub wrote it; a hop never rewrites it.
    pub destination: wsnet_routing::Destination,
    /// Hops still to run, in order, which is what the next leg's `Open` carries.
    pub via: Vec<String>,
    /// Protocol the leg carries.
    pub proto: wsnet_routing::Proto,
}

/// Relays one chain leg in both directions (DESIGN.md sections 7.1, 7.2, 7.5).
///
/// A hop is a bridge, not a dialler: the next leg was already opened on the *same*
/// session (section 7.1 makes a chain same-Hub by construction), and this task only
/// moves bytes between the two halves. Both halves are [`SessionStream`]s, so
/// credit, backpressure, and half-close are the code the local entry points already
/// use instead of a second implementation that could silently disagree with it.
///
/// The answer to the leg's `Open` is produced here rather than before the bridge
/// exists, because section 7.1 only permits a success once the far end can carry
/// data: the next leg is `Ready` by the time this runs, which is what makes the
/// caller's success mean the whole chain is up.
pub(crate) async fn relay_leg(
    handle: SessionHandle,
    request_id: [u8; 16],
    stream_id: u64,
    mut inbound: SessionStream,
    mut next: SessionStream,
) {
    let result = OpenResultFields {
        request_id,
        stream_id,
        status: OpenStatus::Ok,
        detail: "the chain leg is ready".to_string(),
    };
    // `send_open_result` sends `Ready` itself on success.
    if handle.send_open_result(&result).is_err() {
        return;
    }
    debug!(%stream_id, "relaying a chain leg");

    // `copy_bidirectional` propagates end-of-stream as a half-close on the other
    // side, which is section 7.2's rule; a reset on either half surfaces as an
    // error here, and the leg is then reset rather than left half-open.
    if let Err(error) = tokio::io::copy_bidirectional(&mut inbound, &mut next).await {
        debug!(%error, %stream_id, "the chain leg ended with an error");
        let _ = handle.send_reset(stream_id, ResetReason::Unreachable);
    } else {
        trace!(%stream_id, "the chain leg ended cleanly");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsnet_routing::{Destination, Proto};
    fn registration(name: &str, target: &str) -> ServiceRegistration {
        ServiceRegistration {
            name: name.to_string(),
            proto: Proto::Tcp,
            target: target.to_string(),
        }
    }

    fn open(destination: Destination) -> OpenFields {
        OpenFields {
            request_id: [1u8; 16],
            stream_id: 1,
            proto: Proto::Tcp,
            destination,
            via: Vec::new(),
        }
    }

    #[test]
    fn a_published_service_resolves_to_its_local_target() {
        let services = vec![registration("web", "127.0.0.1:8080")];
        let resolved = resolve_inbound(
            "publisher",
            &services,
            &InboundPolicy::deny_all(),
            &open(Destination::service("publisher", "web")),
        )
        .expect("the published service must resolve");
        assert_eq!(resolved.host, "127.0.0.1");
        assert_eq!(resolved.port, 8080);
    }

    /// The caller cannot choose the address: it comes from local configuration.
    #[test]
    fn the_local_target_wins_over_anything_the_caller_sent() {
        let services = vec![registration("web", "127.0.0.1:8080")];
        // The request names only a node and a service; there is no field in
        // which a caller could supply a host or port, which is the point.
        let resolved = resolve_inbound(
            "publisher",
            &services,
            &InboundPolicy::deny_all(),
            &open(Destination::service("publisher", "web")),
        )
        .unwrap();
        assert_eq!(resolved.port, 8080);
    }

    #[test]
    fn an_unknown_service_is_offline() {
        let refusal = resolve_inbound(
            "publisher",
            &[registration("web", "127.0.0.1:8080")],
            &InboundPolicy::deny_all(),
            &open(Destination::service("publisher", "db")),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Offline);
    }

    /// A caller must not be able to make this node serve someone else's name.
    #[test]
    fn a_service_naming_another_node_is_denied() {
        let refusal = resolve_inbound(
            "publisher",
            &[registration("web", "127.0.0.1:8080")],
            &InboundPolicy::deny_all(),
            &open(Destination::service("someone-else", "web")),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);
    }

    #[test]
    fn a_pinned_revision_that_does_not_match_is_refused() {
        let destination = match Destination::service("publisher", "web") {
            Destination::Service { node, name, .. } => Destination::Service {
                node,
                name,
                revision: Some(9),
            },
            other => other,
        };
        let refusal = resolve_inbound(
            "publisher",
            &[registration("web", "127.0.0.1:8080")],
            &InboundPolicy::deny_all(),
            &open(destination),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Offline);
    }

    #[test]
    fn a_service_with_an_unusable_target_is_refused() {
        let refusal = resolve_inbound(
            "publisher",
            &[registration("web", "not-a-target")],
            &InboundPolicy::deny_all(),
            &open(Destination::service("publisher", "web")),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Unreachable);
    }

    /// Section 9.3: a raw node address is default deny, and publishing a service
    /// grants nothing laterally.
    #[test]
    fn node_address_is_denied_by_default_and_allowed_only_explicitly() {
        let destination = Destination::node_address("publisher", "127.0.0.1", 22);

        let refusal = resolve_inbound(
            "publisher",
            &[registration("web", "127.0.0.1:8080")],
            &InboundPolicy::deny_all(),
            &open(destination.clone()),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);

        let policy = InboundPolicy::deny_all()
            .allow_node_address("127.0.0.1/32")
            .expect("a valid CIDR");
        let resolved = resolve_inbound(
            "publisher",
            &[registration("web", "127.0.0.1:8080")],
            &policy,
            &open(destination),
        )
        .expect("an explicit allowlist entry must permit it");
        assert_eq!(resolved.port, 22);
    }

    /// A hostname cannot be checked against a CIDR, so it must not bypass the
    /// allowlist by resolving later.
    #[test]
    fn a_hostname_cannot_satisfy_the_node_address_allowlist() {
        let policy = InboundPolicy::deny_all()
            .allow_node_address("127.0.0.1/32")
            .unwrap();
        let refusal = resolve_inbound(
            "publisher",
            &[],
            &policy,
            &open(Destination::node_address("publisher", "localhost", 22)),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);
    }

    #[test]
    fn an_address_target_is_not_a_reverse_access_destination() {
        let refusal = resolve_inbound(
            "publisher",
            &[],
            &InboundPolicy::deny_all(),
            &open(Destination::address("example.com", 443)),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);
    }

    #[test]
    fn an_invalid_allowlist_entry_is_rejected() {
        assert!(InboundPolicy::deny_all().allow_node_address("not-a-cidr").is_err());
    }

    #[test]
    fn target_parsing_handles_ipv6_and_rejects_junk() {
        assert_eq!(
            parse_target("127.0.0.1:8080"),
            Some(ResolvedTarget {
                host: "127.0.0.1".into(),
                port: 8080
            })
        );
        assert_eq!(
            parse_target("[::1]:80"),
            Some(ResolvedTarget {
                host: "::1".into(),
                port: 80
            })
        );
        assert_eq!(parse_target("no-port"), None);
        assert_eq!(parse_target(":80"), None);
        assert_eq!(parse_target("host:0"), None);
    }

    // ------------------------------------------------------------- section 7.1

    fn open_with_via(destination: Destination, via: &[&str]) -> OpenFields {
        OpenFields {
            via: via.iter().map(|hop| (*hop).to_string()).collect(),
            ..open(destination)
        }
    }

    fn relaying() -> InboundPolicy {
        InboundPolicy::deny_all().with_relay_forward(true)
    }

    /// A leg that still names hops belongs to an intermediate node, whatever the
    /// destination says.
    #[test]
    fn a_leg_with_hops_left_is_forwarded_not_dialled() {
        let plan = plan_inbound(
            "hop1",
            &[],
            &relaying(),
            &open_with_via(Destination::address("127.0.0.1", 80), &["hop2"]),
        )
        .expect("a consented hop must continue the chain");
        assert_eq!(plan, InboundPlan::Forward);

        // Without consent the same leg is refused, which is the local half of the
        // section 9.3 gate for an intermediate node.
        let refusal = plan_inbound(
            "hop1",
            &[],
            &InboundPolicy::deny_all(),
            &open_with_via(Destination::address("127.0.0.1", 80), &["hop2"]),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);
        assert!(refusal.detail.contains("does not relay"), "{}", refusal.detail);
    }

    /// A destination naming another node is someone else's exit, so this node is a
    /// hop. A destination naming *this* node is not, and must still resolve
    /// locally.
    #[test]
    fn a_destination_naming_another_node_is_forwarded() {
        let plan = plan_inbound(
            "hop1",
            &[],
            &relaying(),
            &open(Destination::service("publisher", "web")),
        )
        .expect("a consented hop must continue the chain");
        assert_eq!(plan, InboundPlan::Forward);

        let refusal = plan_inbound(
            "hop1",
            &[],
            &InboundPolicy::deny_all(),
            &open(Destination::service("publisher", "web")),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);

        // Naming this node is the ordinary reverse-access case and never forwards,
        // even with relaying enabled: a node must not bounce its own traffic.
        let services = vec![registration("web", "127.0.0.1:8080")];
        let plan = plan_inbound(
            "publisher",
            &services,
            &relaying(),
            &open(Destination::service("publisher", "web")),
        )
        .expect("a published service must resolve locally");
        assert_eq!(
            plan,
            InboundPlan::Dial(ResolvedTarget {
                host: "127.0.0.1".into(),
                port: 8080
            })
        );
    }

    /// `via=[A]` sends A a plain address, and A's own allowlist is the gate.
    #[test]
    fn a_plain_address_exit_needs_this_nodes_allowlist() {
        let destination = Destination::address("127.0.0.1", 9000);

        let refusal = plan_inbound(
            "hop",
            &[],
            &InboundPolicy::deny_all(),
            &open(destination.clone()),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);

        let policy = InboundPolicy::deny_all()
            .allow_node_address("127.0.0.1/32")
            .unwrap();
        let plan = plan_inbound("hop", &[], &policy, &open(destination))
            .expect("an allowlisted address must be dialled");
        assert_eq!(
            plan,
            InboundPlan::Dial(ResolvedTarget {
                host: "127.0.0.1".into(),
                port: 9000
            })
        );

        // Port 0 is not a dialable address even inside the allowlist.
        let refusal = plan_inbound(
            "hop",
            &[],
            &policy,
            &open(Destination::address("127.0.0.1", 0)),
        )
        .unwrap_err();
        assert_eq!(refusal.status, OpenStatus::Denied);
    }
}
