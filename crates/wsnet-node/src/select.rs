//! Hub selection for `hub = "auto"` (DESIGN.md sections 5.5 and 7.6).
//!
//! > `hub="auto"` 仅选择调用方与发布方均 Ready、服务 lease 存在且 ACL 有效的健康 Hub；
//! > 跨 Hub 只恢复新连接。
//!
//! Selection is a pure function over a snapshot of each Hub's readiness, health,
//! and service directory, so the policy is testable without any I/O and the node
//! only has to gather the snapshot.

use std::collections::BTreeMap;

use wsnet_protocol::Canonical;
use wsnet_routing::{Destination, Proto};

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
    services: BTreeMap<(String, String), Advertisement>,
    /// Revision of the snapshot currently applied.
    ///
    /// Section 4.1 makes `PeerList` a *versioned* snapshot and section 8 says a
    /// receiver ignores a revision older than one it has already applied, so the
    /// applied revision is kept here rather than being left to the caller: a
    /// retransmitted old snapshot must not silently resurrect a withdrawn service.
    revision: Option<u64>,
}

/// What a `PeerList` entry said about a service beyond its identity.
///
/// Both fields are optional because the snapshot is a routing hint: a Hub that
/// omits them still advertises the service, and dropping the entry would turn a
/// usable hint into a false negative.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Advertisement {
    /// Protocol the publisher registered.
    pub proto: Option<Proto>,
    /// Per-service revision at the time of the snapshot.
    pub revision: Option<u64>,
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
            services: BTreeMap::new(),
            revision: None,
        }
    }

    /// Reads a `PeerList` snapshot.
    ///
    /// The shape this node expects is
    /// `{"hub":..,"services":[{"node":..,"name":..},..],"version":..}`.
    /// Malformed entries are ignored rather than failing the whole snapshot: a
    /// directory is a routing hint, and a Hub that sends a partly unreadable one
    /// must not make the node unusable. A syntactically valid `PeerList` still
    /// marks the directory *known*.
    pub fn from_peer_list(value: &Canonical) -> Self {
        let mut directory = ServiceDirectory {
            known: true,
            services: BTreeMap::new(),
            revision: value.get_u64("version").ok(),
        };
        if let Ok(entries) = value.get_array("services") {
            for entry in entries {
                let (Ok(node), Ok(name)) = (entry.get_str("node"), entry.get_str("name")) else {
                    continue;
                };
                let proto = entry
                    .get_str("proto")
                    .ok()
                    .and_then(|text| match text {
                        "tcp" => Some(Proto::Tcp),
                        "udp" => Some(Proto::Udp),
                        _ => None,
                    });
                let revision = entry.get_u64("revision").ok();
                directory.services.insert(
                    (node.to_string(), name.to_string()),
                    Advertisement { proto, revision },
                );
            }
        }
        directory
    }

    /// Applies a `PeerList` snapshot, ignoring one that is not newer.
    ///
    /// Returns whether the snapshot was applied. A snapshot whose revision is not
    /// greater than the applied one is dropped, which is what section 8's
    /// "ignores a revision older than one it has already applied" requires; an
    /// unversioned snapshot is treated as older for the same reason, because
    /// accepting it could undo a newer one.
    pub fn apply_peer_list(&mut self, value: &Canonical) -> bool {
        let incoming = Self::from_peer_list(value);
        if let (Some(applied), Some(incoming_revision)) = (self.revision, incoming.revision) {
            if incoming_revision <= applied {
                return false;
            }
        } else if self.known && incoming.revision.is_none() {
            return false;
        }
        *self = incoming;
        true
    }

    /// Whether a `PeerList` has been received for this Hub.
    pub fn is_known(&self) -> bool {
        self.known
    }

    /// The revision of the applied snapshot, when it carried one.
    pub fn revision(&self) -> Option<u64> {
        self.revision
    }

    /// Number of advertised services.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether no service is advertised.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Every advertised `(node, service)` pair, in the directory's own order.
    ///
    /// This is what makes `wsnet services list` able to report what the Hub
    /// advertises instead of only what this node publishes itself. It is
    /// deliberately not a `&ServiceDirectory`-wide dump: the set is already
    /// filtered by the Hub's ACL for this caller.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.services
            .keys()
            .map(|(node, name)| (node.as_str(), name.as_str()))
    }

    /// Every advertisement, including the protocol and revision the Hub reported.
    pub fn advertisements(&self) -> impl Iterator<Item = (&str, &str, Advertisement)> {
        self.services
            .iter()
            .map(|((node, name), entry)| (node.as_str(), name.as_str(), *entry))
    }

    /// Whether `node` publishes `name` on this Hub.
    pub fn contains(&self, node: &str, name: &str) -> bool {
        self.services
            .contains_key(&(node.to_string(), name.to_string()))
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
            services: BTreeMap::from([(
                (node.to_string(), name.to_string()),
                Advertisement::default(),
            )]),
            revision: None,
        }
    }

    fn peer_list(entries: &[(&str, &str)]) -> Canonical {
        peer_list_versioned(entries, 1)
    }

    fn peer_list_versioned(entries: &[(&str, &str)], version: u64) -> Canonical {
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
            // Section 4.1: an unsigned revision travels as a decimal string.
            ("version", Canonical::u64_decimal(version)),
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

    /// `services list` needs the whole advertised set, not just membership.
    #[test]
    fn entries_enumerate_every_advertised_service() {
        let directory =
            ServiceDirectory::from_peer_list(&peer_list(&[("client-b", "web"), ("client-a", "db")]));
        let listed: Vec<(&str, &str)> = directory.entries().collect();
        assert_eq!(listed, vec![("client-a", "db"), ("client-b", "web")]);
        assert_eq!(directory.revision(), Some(1));
        assert!(ServiceDirectory::unknown().entries().next().is_none());
    }

    /// A richer snapshot keeps the protocol and revision it carried, and a
    /// minimal one still advertises the service.
    #[test]
    fn advertisements_carry_the_reported_protocol() {
        let rich = Canonical::object([
            (
                "services",
                Canonical::Array(vec![Canonical::object([
                    ("name", Canonical::str("dns")),
                    ("node", Canonical::str("client-a")),
                    ("proto", Canonical::str("udp")),
                    ("revision", Canonical::u64_decimal(9)),
                ])]),
            ),
            ("version", Canonical::u64_decimal(2)),
        ]);
        let directory = ServiceDirectory::from_peer_list(&rich);
        let entries: Vec<_> = directory.advertisements().collect();
        assert_eq!(
            entries,
            vec![(
                "client-a",
                "dns",
                Advertisement {
                    proto: Some(Proto::Udp),
                    revision: Some(9)
                }
            )]
        );
        assert!(directory.contains("client-a", "dns"));

        let minimal = ServiceDirectory::from_peer_list(&peer_list(&[("client-a", "web")]));
        let entry = minimal.advertisements().next().unwrap().2;
        assert_eq!(entry, Advertisement::default());
    }

    /// Section 8: a receiver ignores a revision it has already passed.
    #[test]
    fn an_older_peer_list_is_ignored() {
        let mut directory = ServiceDirectory::unknown();
        assert!(directory.apply_peer_list(&peer_list_versioned(&[("client-a", "web")], 4)));
        assert_eq!(directory.revision(), Some(4));

        // The same revision is not newer, so a withdrawal cannot be undone by a
        // retransmission of the snapshot that predates it.
        assert!(!directory.apply_peer_list(&peer_list_versioned(&[("client-a", "web")], 4)));
        assert!(!directory.apply_peer_list(&peer_list_versioned(&[("client-a", "db")], 3)));
        assert!(directory.contains("client-a", "web"));

        // A newer revision replaces the whole snapshot, including a removal.
        assert!(directory.apply_peer_list(&peer_list_versioned(&[("client-a", "db")], 5)));
        assert_eq!(directory.revision(), Some(5));
        assert!(!directory.contains("client-a", "web"));
        assert!(directory.contains("client-a", "db"));

        // An unversioned snapshot is treated as older than a versioned one.
        let unversioned = Canonical::object([(
            "services",
            Canonical::Array(vec![Canonical::object([
                ("name", Canonical::str("web")),
                ("node", Canonical::str("client-a")),
            ])]),
        )]);
        assert!(!directory.apply_peer_list(&unversioned));
        assert!(directory.contains("client-a", "db"));
    }
}
