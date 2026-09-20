//! Hub selection for `hub = "auto"` (DESIGN.md sections 5.5 and 7.6).
//!
//! > `hub="auto"` 仅选择调用方与发布方均 Ready、服务 lease 存在且 ACL 有效的健康 Hub；
//! > 跨 Hub 只恢复新连接。
//!
//! Selection is a pure function over a snapshot of each Hub's readiness, health,
//! and service directory, so the policy is testable without any I/O and the node
//! only has to gather the snapshot.

use std::collections::BTreeSet;

use wsnet_protocol::Canonical;
use wsnet_routing::Destination;

/// Which Hub a flow must use.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HubChoice {
    /// Pick any Hub that satisfies section 5.5.
    #[default]
    Auto,
    /// Pin to a named Hub from `[[servers]]`.
    Hub(String),
}

/// What one Hub session knows about the services published on it.
///
/// The node learns this from the Hub's `PeerList` (DESIGN.md section 4.1), which
/// section 9.3 restricts to what the caller may discover. An empty *known*
/// directory is a positive statement — "this Hub advertises no service to you" —
/// and is therefore different from a directory that was never received.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceDirectory {
    known: bool,
    services: BTreeSet<(String, String)>,
}

impl ServiceDirectory {
    /// A directory that has not been populated by a `PeerList` yet.
    pub fn unknown() -> Self {
        Self::default()
    }

    /// A directory that has been populated, possibly with no entries.
    pub fn known_empty() -> Self {
        ServiceDirectory {
            known: true,
            services: BTreeSet::new(),
        }
    }

    /// Reads a `PeerList` snapshot.
    ///
    /// The shape this node expects is `{"services":[{"node":..,"name":..},..]}`.
    /// Malformed entries are ignored rather than failing the whole snapshot: a
    /// directory is a routing hint, and a Hub that sends a partly unreadable one
    /// must not make the node unusable. A syntactically valid `PeerList` still
    /// marks the directory *known*.
    pub fn from_peer_list(value: &Canonical) -> Self {
        let mut directory = ServiceDirectory {
            known: true,
            services: BTreeSet::new(),
        };
        if let Ok(entries) = value.get_array("services") {
            for entry in entries {
                let (Ok(node), Ok(name)) = (entry.get_str("node"), entry.get_str("name")) else {
                    continue;
                };
                directory
                    .services
                    .insert((node.to_string(), name.to_string()));
            }
        }
        directory
    }

    /// Whether a `PeerList` has been received for this Hub.
    pub fn is_known(&self) -> bool {
        self.known
    }

    /// Number of advertised services.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether no service is advertised.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Whether `node` publishes `name` on this Hub.
    pub fn contains(&self, node: &str, name: &str) -> bool {
        self.services
            .contains(&(node.to_string(), name.to_string()))
    }
}

/// One Hub's selection-relevant state, gathered by the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Hub identity.
    pub hub_id: String,
    /// Whether the local session reached `Ready` (section 5.3).
    pub ready: bool,
    /// Whether the section 5.5 health check currently passes.
    pub healthy: bool,
    /// The service directory, or `None` when no `PeerList` was ever received.
    pub directory: Option<ServiceDirectory>,
}

/// Picks the Hub for `destination` from `candidates`, which are in failover order.
///
/// Section 5.5 requires both the caller and, for a named service, the publisher
/// to be `Ready` on the chosen Hub. Evidence about the publisher is therefore
/// preferred over ignorance: a Hub whose directory lists the service wins over a
/// Hub that has said nothing, and a Hub whose directory is known to lack the
/// service is skipped entirely.
pub fn select_hub<'a>(
    candidates: &'a [Candidate],
    destination: &Destination,
) -> Option<&'a Candidate> {
    let viable = |candidate: &&Candidate| candidate.ready && candidate.healthy;
    match destination {
        Destination::Service { node, name, .. } => {
            if let Some(found) = candidates.iter().find(|candidate| {
                candidate.ready
                    && candidate.healthy
                    && candidate
                        .directory
                        .as_ref()
                        .is_some_and(|directory| directory.contains(node, name))
            }) {
                return Some(found);
            }
            // No Hub has advertised the service, so an uninformed Hub is the
            // only remaining option; the Hub itself still has to authorise the
            // flow, so this is not a permission.
            candidates.iter().find(|candidate| {
                candidate.ready && candidate.healthy && candidate.directory.is_none()
            })
        }
        _ => candidates.iter().find(viable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        hub_id: &str,
        ready: bool,
        healthy: bool,
        directory: Option<ServiceDirectory>,
    ) -> Candidate {
        Candidate {
            hub_id: hub_id.to_string(),
            ready,
            healthy,
            directory,
        }
    }

    fn with_service(node: &str, name: &str) -> ServiceDirectory {
        ServiceDirectory {
            known: true,
            services: BTreeSet::from([(node.to_string(), name.to_string())]),
        }
    }

    fn peer_list(entries: &[(&str, &str)]) -> Canonical {
        Canonical::object([
            (
                "services",
                Canonical::Array(
                    entries
                        .iter()
                        .map(|(node, name)| {
                            Canonical::object([
                                ("name", Canonical::str(*name)),
                                ("node", Canonical::str(*node)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("version", Canonical::int(1)),
        ])
    }

    /// Section 5.5: a publisher that is not ready on a Hub removes that Hub.
    #[test]
    fn a_publisher_missing_from_a_directory_is_skipped() {
        let candidates = vec![
            candidate("hub-a", true, true, Some(ServiceDirectory::known_empty())),
            candidate("hub-b", true, true, Some(with_service("client-a", "web"))),
        ];
        let chosen = select_hub(&candidates, &Destination::service("client-a", "web")).unwrap();
        assert_eq!(chosen.hub_id, "hub-b");
    }

    /// A directory that has never been received is not evidence of absence, so
    /// the Hub stays a candidate.
    #[test]
    fn an_unknown_directory_does_not_remove_a_hub() {
        let candidates = vec![candidate("hub-a", true, true, None)];
        let chosen = select_hub(&candidates, &Destination::service("client-a", "web")).unwrap();
        assert_eq!(chosen.hub_id, "hub-a");
    }

    /// Evidence beats ignorance: a later Hub that advertises the service is
    /// preferred to an earlier Hub that has said nothing.
    #[test]
    fn advertised_services_win_over_an_uninformed_hub() {
        let candidates = vec![
            candidate("hub-a", true, true, None),
            candidate("hub-b", true, true, Some(with_service("client-a", "web"))),
        ];
        let chosen = select_hub(&candidates, &Destination::service("client-a", "web")).unwrap();
        assert_eq!(chosen.hub_id, "hub-b");
    }

    /// Section 5.5: no Hub satisfies the condition, so the flow must fail rather
    /// than silently falling back to a direct connection.
    #[test]
    fn no_candidate_yields_no_hub() {
        let candidates = vec![
            candidate("hub-a", false, true, None),
            candidate("hub-b", true, false, None),
            candidate("hub-c", true, true, Some(ServiceDirectory::known_empty())),
        ];
        assert!(select_hub(&candidates, &Destination::service("client-a", "web")).is_none());
    }

    /// An address destination only needs a ready, healthy Hub.
    #[test]
    fn an_address_uses_the_first_healthy_ready_hub() {
        let candidates = vec![
            candidate("hub-a", false, true, None),
            candidate("hub-b", true, false, None),
            candidate("hub-c", true, true, None),
        ];
        let chosen = select_hub(&candidates, &Destination::address("example.com", 443)).unwrap();
        assert_eq!(chosen.hub_id, "hub-c");
    }

    #[test]
    fn peer_lists_populate_the_directory() {
        let directory = ServiceDirectory::from_peer_list(&peer_list(&[("client-a", "web")]));
        assert!(directory.is_known());
        assert_eq!(directory.len(), 1);
        assert!(directory.contains("client-a", "web"));
        assert!(!directory.contains("client-a", "db"));

        let empty = ServiceDirectory::from_peer_list(&peer_list(&[]));
        assert!(empty.is_known());
        assert!(empty.is_empty());

        // A malformed entry is skipped, but the snapshot still counts as known.
        let malformed = ServiceDirectory::from_peer_list(&Canonical::object([(
            "services",
            Canonical::Array(vec![Canonical::int(7)]),
        )]));
        assert!(malformed.is_known());
        assert!(malformed.is_empty());
    }
}
