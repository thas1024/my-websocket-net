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

use crate::stream::StreamMsg;

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
}
