//! Hub node leases and the service directory (DESIGN.md §5.5, §7.6, §8).
//!
//! The registry is the Hub's authority on *who is here* and *what they publish*.
//! Three design rules shape every method:
//!
//! * **Leases are bound to a session and epoch.** §7.6/USAGE: a service lease is
//!   tied to the publishing node's Hub session, so a reconnect must re-`Hello`
//!   rather than inherit anything.
//! * **A stale callback must never delete a newer lease.** §5.5: "同一节点同一
//!   Hub 默认一个活跃 epoch，新 Ready 注册原子取代旧注册；旧回调不得删除新
//!   lease". Every mutation therefore carries the `(session_id, epoch)` that is
//!   allowed to perform it, and a mismatch is a no-op.
//! * **Discovery is not authorisation.** §7.6: the directory "只展示当前调用方有
//!   权发现的服务", so listing filters through the same [`AclTable`] the data
//!   path uses.
//!
//! A service keeps its `revision` while its target is unchanged and gets a new
//! one when the target changes, which is what lets a caller detect that an `Open`
//! pinned to an old revision is stale (USAGE §7).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use wsnet_routing::{dest::is_slug, AclAction, AclQuery, AclTable, Proto};

/// A node's presence on this Hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLease {
    /// Session that owns this lease.
    pub session_id: [u8; 16],
    /// Key epoch the session authenticated with.
    pub epoch: [u8; 16],
    /// Services published by this node, by service name.
    pub services: BTreeMap<String, ServiceLease>,
}

/// A published service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLease {
    /// Hub that holds this lease.
    pub hub_id: String,
    /// Publishing node.
    pub node_id: String,
    /// Service name.
    pub service_name: String,
    /// Protocol.
    pub proto: Proto,
    /// Monotonic revision of this service's target.
    pub revision: u64,
    /// The target as configured by the publisher, `host:port`.
    pub target: String,
    /// Session that published it.
    pub session_id: [u8; 16],
    /// Epoch that published it.
    pub epoch: [u8; 16],
}

/// A service as the directory reports it (§7.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDescriptor {
    /// Hub id.
    pub hub_id: String,
    /// Publishing node.
    pub node_id: String,
    /// Service name.
    pub service_name: String,
    /// Protocol.
    pub proto: Proto,
    /// Current revision.
    pub revision: u64,
}

/// One node's entry in a [`PeerList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerNode {
    /// Node id.
    pub node_id: String,
    /// Services of this node visible to the caller.
    pub services: Vec<ServiceDescriptor>,
}

/// A versioned snapshot of what one caller may see (§4.1, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerList {
    /// Hub that produced this snapshot.
    pub hub_id: String,
    /// Monotonic revision; a receiver ignores a revision older than one it has
    /// already applied.
    pub revision: u64,
    /// Visible nodes.
    pub nodes: Vec<PeerNode>,
}

/// Errors from registry operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    /// The node has no live lease on this Hub.
    #[error("node `{0}` is not registered on this Hub")]
    NodeNotRegistered(String),
    /// The operation came from a superseded session or epoch.
    #[error("operation belongs to a superseded session or epoch")]
    StaleSession,
    /// A target string was not `host:port`.
    #[error("`{0}` is not a valid host:port target")]
    BadTarget(String),
    /// A service name was not a valid slug.
    #[error("`{0}` is not a normalised ASCII slug")]
    BadServiceName(String),
}

/// The Hub's registration and service directory.
#[derive(Debug)]
pub struct Registry {
    hub_id: String,
    nodes: BTreeMap<String, NodeLease>,
    revision: u64,
}

impl Registry {
    /// Creates an empty registry for one Hub id.
    pub fn new(hub_id: impl Into<String>) -> Self {
        Registry {
            hub_id: hub_id.into(),
            nodes: BTreeMap::new(),
            revision: 0,
        }
    }

    /// The Hub id.
    pub fn hub_id(&self) -> &str {
        &self.hub_id
    }

    /// The current snapshot revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Number of registered nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The lease for one node, if live.
    pub fn node(&self, node_id: &str) -> Option<&NodeLease> {
        self.nodes.get(node_id)
    }

    /// Whether a node is registered.
    pub fn is_registered(&self, node_id: &str) -> bool {
        self.nodes.contains_key(node_id)
    }

    fn bump(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }

    /// Whether `(session_id, epoch)` is the live lease for `node_id`.
    fn owns(&self, node_id: &str, session_id: &[u8; 16], epoch: &[u8; 16]) -> bool {
        self.nodes
            .get(node_id)
            .is_some_and(|lease| lease.session_id == *session_id && lease.epoch == *epoch)
    }

    /// Registers a node as ready, atomically replacing any earlier lease.
    ///
    /// Returns `true` when an earlier lease (a different session or epoch) was
    /// replaced, which the caller can log as a reconnect rather than a duplicate.
    pub fn register_ready(
        &mut self,
        node_id: &str,
        session_id: [u8; 16],
        epoch: [u8; 16],
    ) -> bool {
        let replaced = self
            .nodes
            .get(node_id)
            .is_some_and(|lease| lease.session_id != session_id || lease.epoch != epoch);
        self.nodes.insert(
            node_id.to_string(),
            NodeLease {
                session_id,
                epoch,
                services: BTreeMap::new(),
            },
        );
        self.bump();
        replaced
    }

    /// Removes a node's lease, but only if the caller still owns it.
    ///
    /// This is the guard §5.5 requires: a late callback from a superseded
    /// session must not delete the lease that replaced it. Returns `Ok(false)`
    /// when the lease belongs to someone else.
    pub fn unregister(
        &mut self,
        node_id: &str,
        session_id: &[u8; 16],
        epoch: &[u8; 16],
    ) -> Result<bool, RegistryError> {
        if !self.nodes.contains_key(node_id) {
            return Err(RegistryError::NodeNotRegistered(node_id.to_string()));
        }
        if !self.owns(node_id, session_id, epoch) {
            return Ok(false);
        }
        self.nodes.remove(node_id);
        self.bump();
        Ok(true)
    }

    /// Publishes or updates a service, returning its (possibly new) revision.
    ///
    /// Re-publishing the same target keeps the revision, so an `Open` pinned to
    /// it stays valid; changing the target bumps it, so a pinned `Open` can be
    /// detected as stale.
    pub fn publish(
        &mut self,
        node_id: &str,
        session_id: &[u8; 16],
        epoch: &[u8; 16],
        service_name: &str,
        proto: Proto,
        target: &str,
    ) -> Result<u64, RegistryError> {
        if !self.owns(node_id, session_id, epoch) {
            return Err(RegistryError::StaleSession);
        }
        if !is_slug(service_name) {
            return Err(RegistryError::BadServiceName(service_name.to_string()));
        }
        parse_target(target).ok_or_else(|| RegistryError::BadTarget(target.to_string()))?;

        let lease = self
            .nodes
            .get_mut(node_id)
            .expect("ownership was checked above");
        let revision = match lease.services.get(service_name) {
            Some(existing) if existing.target == target && existing.proto == proto => {
                existing.revision
            }
            Some(existing) => existing.revision.saturating_add(1),
            None => 1,
        };
        lease.services.insert(
            service_name.to_string(),
            ServiceLease {
                hub_id: self.hub_id.clone(),
                node_id: node_id.to_string(),
                service_name: service_name.to_string(),
                proto,
                revision,
                target: target.to_string(),
                session_id: *session_id,
                epoch: *epoch,
            },
        );
        self.bump();
        Ok(revision)
    }

    /// Withdraws one service, but only for the owning session.
    pub fn withdraw(
        &mut self,
        node_id: &str,
        session_id: &[u8; 16],
        epoch: &[u8; 16],
        service_name: &str,
    ) -> Result<bool, RegistryError> {
        if !self.owns(node_id, session_id, epoch) {
            return Ok(false);
        }
        let removed = self
            .nodes
            .get_mut(node_id)
            .is_some_and(|lease| lease.services.remove(service_name).is_some());
        if removed {
            self.bump();
        }
        Ok(removed)
    }

    /// Looks up one service lease without any ACL filtering.
    ///
    /// Callers must authorise first; this is the data-path resolver used by the
    /// Hub *after* it has checked `connect_service` for the calling node.
    pub fn lookup(&self, node_id: &str, service_name: &str) -> Option<&ServiceLease> {
        self.nodes
            .get(node_id)
            .and_then(|lease| lease.services.get(service_name))
    }

    /// Whether `caller` may discover `lease`.
    fn discoverable(&self, caller: &str, acl: &AclTable, lease: &ServiceLease) -> bool {
        acl.check(&AclQuery {
            caller,
            action: AclAction::ConnectService,
            node: Some(&lease.node_id),
            service: Some(&lease.service_name),
            ip: None,
            port: None,
            proto: lease.proto,
        })
        .is_allowed()
    }

    /// The services one caller may discover (§7.6).
    pub fn list_visible(&self, caller: &str, acl: &AclTable) -> Vec<ServiceDescriptor> {
        let mut out = Vec::new();
        for lease in self.nodes.values() {
            for service in lease.services.values() {
                if self.discoverable(caller, acl, service) {
                    out.push(descriptor(service));
                }
            }
        }
        out.sort_by(|a, b| (&a.node_id, &a.service_name).cmp(&(&b.node_id, &b.service_name)));
        out
    }

    /// Builds a versioned [`PeerList`] scoped to one caller (§8).
    pub fn peer_list(&self, caller: &str, acl: &AclTable) -> PeerList {
        let mut nodes = Vec::new();
        for (node_id, lease) in &self.nodes {
            let services: Vec<ServiceDescriptor> = lease
                .services
                .values()
                .filter(|service| self.discoverable(caller, acl, service))
                .map(descriptor)
                .collect();
            nodes.push(PeerNode {
                node_id: node_id.clone(),
                services,
            });
        }
        PeerList {
            hub_id: self.hub_id.clone(),
            revision: self.revision,
            nodes,
        }
    }
}

fn descriptor(lease: &ServiceLease) -> ServiceDescriptor {
    ServiceDescriptor {
        hub_id: lease.hub_id.clone(),
        node_id: lease.node_id.clone(),
        service_name: lease.service_name.clone(),
        proto: lease.proto,
        revision: lease.revision,
    }
}

/// Splits a `host:port` target, rejecting anything malformed.
///
/// IPv6 literals must be bracketed (`[::1]:80`) so that the split is unambiguous.
pub fn parse_target(target: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        (host.to_string(), port)
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
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wsnet_routing::AclRule;

    const S1: [u8; 16] = [1u8; 16];
    const S2: [u8; 16] = [2u8; 16];
    const E1: [u8; 16] = [0xE1; 16];
    const E2: [u8; 16] = [0xE2; 16];

    fn allow_service(caller: &str, node: &str, service: &str) -> AclRule {
        AclRule {
            caller: caller.into(),
            action: AclAction::ConnectService,
            allow: true,
            node: Some(node.into()),
            service: Some(service.into()),
            host_cidr: None,
            ports: None,
            proto: None,
        }
    }

    fn registry_with_web() -> Registry {
        let mut registry = Registry::new("hub-a");
        registry.register_ready("client-a", S1, E1);
        registry
            .publish("client-a", &S1, &E1, "web", Proto::Tcp, "127.0.0.1:8080")
            .unwrap();
        registry
    }

    #[test]
    fn register_and_publish() {
        let registry = registry_with_web();
        assert!(registry.is_registered("client-a"));
        let lease = registry.lookup("client-a", "web").unwrap();
        assert_eq!(lease.revision, 1);
        assert_eq!(lease.target, "127.0.0.1:8080");
        assert_eq!(lease.proto, Proto::Tcp);
        assert_eq!(lease.hub_id, "hub-a");
    }

    /// USAGE §7: the same name re-published to the same target keeps its
    /// revision, so a pinned `Open` stays valid.
    #[test]
    fn republication_to_the_same_target_keeps_the_revision() {
        let mut registry = registry_with_web();
        let revision = registry
            .publish("client-a", &S1, &E1, "web", Proto::Tcp, "127.0.0.1:8080")
            .unwrap();
        assert_eq!(revision, 1);
    }

    /// USAGE §7: a changed target gets a new revision, which is how a caller can
    /// tell a pinned `Open` is stale.
    #[test]
    fn republication_to_a_new_target_bumps_the_revision() {
        let mut registry = registry_with_web();
        let revision = registry
            .publish("client-a", &S1, &E1, "web", Proto::Tcp, "127.0.0.1:9090")
            .unwrap();
        assert_eq!(revision, 2);
        assert_eq!(
            registry.lookup("client-a", "web").unwrap().target,
            "127.0.0.1:9090"
        );
    }

    /// T14/T22: a late callback from a superseded session must not delete the
    /// lease that replaced it.
    #[test]
    fn a_stale_session_cannot_unregister_a_newer_lease() {
        let mut registry = registry_with_web();
        // A reconnect replaces the lease.
        assert!(registry.register_ready("client-a", S2, E2));
        assert_eq!(registry.node("client-a").unwrap().session_id, S2);

        // The old session's teardown arrives late.
        assert!(!registry.unregister("client-a", &S1, &E1).unwrap());
        assert!(
            registry.is_registered("client-a"),
            "the stale callback removed the new lease"
        );
        assert_eq!(registry.node("client-a").unwrap().session_id, S2);

        // The owning session can still remove it.
        assert!(registry.unregister("client-a", &S2, &E2).unwrap());
        assert!(!registry.is_registered("client-a"));
    }

    /// A new epoch on the same session id is also a replacement.
    #[test]
    fn a_new_epoch_replaces_the_lease() {
        let mut registry = registry_with_web();
        assert!(registry.register_ready("client-a", S1, E2));
        assert_eq!(registry.node("client-a").unwrap().epoch, E2);
        // And the previous epoch can no longer publish.
        assert_eq!(
            registry
                .publish("client-a", &S1, &E1, "db", Proto::Tcp, "127.0.0.1:1")
                .unwrap_err(),
            RegistryError::StaleSession
        );
    }

    /// Re-registering with the *same* session and epoch is not a replacement.
    #[test]
    fn re_registering_the_same_session_is_not_a_replacement() {
        let mut registry = registry_with_web();
        assert!(!registry.register_ready("client-a", S1, E1));
    }

    /// §5.3: reconnecting re-`Hello`s and does not inherit old services.
    #[test]
    fn re_registration_drops_services() {
        let mut registry = registry_with_web();
        registry.register_ready("client-a", S2, E2);
        assert!(registry.lookup("client-a", "web").is_none());
    }

    #[test]
    fn a_stale_session_cannot_publish_or_withdraw() {
        let mut registry = registry_with_web();
        registry.register_ready("client-a", S2, E2);
        assert_eq!(
            registry
                .publish("client-a", &S1, &E1, "db", Proto::Tcp, "127.0.0.1:1")
                .unwrap_err(),
            RegistryError::StaleSession
        );
        assert!(!registry.withdraw("client-a", &S1, &E1, "web").unwrap());
    }

    #[test]
    fn publishing_requires_a_live_lease() {
        let mut registry = Registry::new("hub-a");
        assert_eq!(
            registry
                .publish("ghost", &S1, &E1, "web", Proto::Tcp, "127.0.0.1:1")
                .unwrap_err(),
            RegistryError::StaleSession
        );
    }

    #[test]
    fn bad_service_names_and_targets_are_rejected() {
        let mut registry = registry_with_web();
        assert_eq!(
            registry
                .publish("client-a", &S1, &E1, "bad name", Proto::Tcp, "127.0.0.1:1")
                .unwrap_err(),
            RegistryError::BadServiceName("bad name".into())
        );
        assert_eq!(
            registry
                .publish("client-a", &S1, &E1, "db", Proto::Tcp, "no-port")
                .unwrap_err(),
            RegistryError::BadTarget("no-port".into())
        );
        assert_eq!(
            registry
                .publish("client-a", &S1, &E1, "db", Proto::Tcp, "127.0.0.1:0")
                .unwrap_err(),
            RegistryError::BadTarget("127.0.0.1:0".into())
        );
    }

    /// T22: the directory only lists what the caller may discover.
    #[test]
    fn listing_is_filtered_by_acl() {
        let mut registry = registry_with_web();
        registry
            .publish("client-a", &S1, &E1, "admin", Proto::Tcp, "127.0.0.1:9000")
            .unwrap();

        let acl = AclTable::new(vec![allow_service("client-b", "client-a", "web")]).unwrap();
        let visible = registry.list_visible("client-b", &acl);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].service_name, "web");

        // A caller with no rules sees nothing.
        assert!(registry.list_visible("client-c", &acl).is_empty());
    }

    /// T22: a service must not leak into the peer list of an unauthorised caller.
    #[test]
    fn peer_list_is_scoped_to_the_caller() {
        let registry = registry_with_web();
        let acl = AclTable::new(vec![allow_service("client-b", "client-a", "web")]).unwrap();

        let list = registry.peer_list("client-b", &acl);
        assert_eq!(list.hub_id, "hub-a");
        assert_eq!(list.nodes.len(), 1);
        assert_eq!(list.nodes[0].node_id, "client-a");
        assert_eq!(list.nodes[0].services.len(), 1);

        let empty = registry.peer_list("client-c", &acl);
        assert_eq!(empty.nodes.len(), 1);
        assert!(empty.nodes[0].services.is_empty());
    }

    /// T14: the revision is monotonic, so a late old snapshot can be ignored.
    #[test]
    fn revisions_are_monotonic() {
        let mut registry = Registry::new("hub-a");
        let start = registry.revision();
        registry.register_ready("client-a", S1, E1);
        let after_register = registry.revision();
        assert!(after_register > start);

        registry
            .publish("client-a", &S1, &E1, "web", Proto::Tcp, "127.0.0.1:1")
            .unwrap();
        let after_publish = registry.revision();
        assert!(after_publish > after_register);

        registry.unregister("client-a", &S1, &E1).unwrap();
        assert!(registry.revision() > after_publish);
    }

    #[test]
    fn withdraw_removes_only_the_named_service() {
        let mut registry = registry_with_web();
        registry
            .publish("client-a", &S1, &E1, "db", Proto::Tcp, "127.0.0.1:5432")
            .unwrap();
        assert!(registry.withdraw("client-a", &S1, &E1, "web").unwrap());
        assert!(registry.lookup("client-a", "web").is_none());
        assert!(registry.lookup("client-a", "db").is_some());
        // Withdrawing an unknown name is a no-op, not an error.
        assert!(!registry.withdraw("client-a", &S1, &E1, "web").unwrap());
    }

    #[test]
    fn unregistering_an_unknown_node_is_an_error() {
        let mut registry = Registry::new("hub-a");
        assert_eq!(
            registry.unregister("ghost", &S1, &E1).unwrap_err(),
            RegistryError::NodeNotRegistered("ghost".into())
        );
    }

    #[test]
    fn target_parsing_handles_ipv6_and_rejects_junk() {
        assert_eq!(
            parse_target("127.0.0.1:8080"),
            Some(("127.0.0.1".into(), 8080))
        );
        assert_eq!(parse_target("[::1]:80"), Some(("::1".into(), 80)));
        assert_eq!(
            parse_target("example.com:443"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(parse_target("no-port"), None);
        assert_eq!(parse_target(":80"), None);
        assert_eq!(parse_target("host:0"), None);
        assert_eq!(parse_target("host:99999"), None);
        assert_eq!(parse_target("[::1]"), None);
    }

    #[test]
    fn peer_list_serializes_with_the_documented_fields() {
        let registry = registry_with_web();
        let acl = AclTable::new(vec![allow_service("client-b", "client-a", "web")]).unwrap();
        let list = registry.peer_list("client-b", &acl);
        let json = serde_json::to_string(&list).unwrap();
        for field in [
            "hub_id",
            "revision",
            "nodes",
            "node_id",
            "services",
            "service_name",
            "proto",
        ] {
            assert!(json.contains(field), "missing {field} in {json}");
        }
    }
}
