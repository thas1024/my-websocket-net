//! Default-deny ACL (DESIGN.md §9.3).
//!
//! > `relay_allow=[]` 为默认；这是 Hub 中转能力开关而不是完整授权。Hub 还需明确
//! > `(caller,via hop,exit,target/service,proto,port/CIDR)` permit 规则，无匹配即拒绝。
//!
//! Two independent gates, because the design insists they are not the same thing:
//!
//! * [`RelayAllow`] decides whether a node may relay for others *at all*.
//! * [`AclTable`] decides whether one specific access is permitted.
//!
//! A rule that selects a route never grants permission, and permission never
//! implies a route: §10 says "路由选中了节点，不代表访问一定被允许".

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::dest::Proto;

/// What a rule authorises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    /// Caller may open a named service published by another node.
    ConnectService,
    /// Caller may reach a raw address in another node's view. Denied by default
    /// and requires its own rule (§7.6).
    ConnectNodeAddress,
    /// Caller may open a plain address through the Hub or an exit node.
    ConnectAddress,
    /// Caller may act as an intermediate relay hop.
    Relay,
}

/// Errors while compiling an ACL.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AclError {
    /// `host_cidr` was not a valid CIDR.
    #[error("`{0}` is not a valid CIDR")]
    InvalidCidr(String),
    /// A rule named neither a node nor a service where one is required.
    #[error("acl rule for action {0:?} is not specific enough")]
    TooBroad(AclAction),
}

/// One ACL rule, as written in configuration (§11 of USAGE.md).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    /// Node identity the rule applies to.
    pub caller: String,
    /// What is being authorised.
    pub action: AclAction,
    /// Whether a match allows or denies.
    #[serde(default = "default_true")]
    pub allow: bool,
    /// Target node, when the action names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Target service, when the action names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Permitted destination CIDR, for address actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_cidr: Option<String>,
    /// Permitted destination ports, for address actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<u16>>,
    /// Protocol the rule applies to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<Proto>,
}

fn default_true() -> bool {
    true
}

/// The facts one access decision is made from.
#[derive(Debug, Clone)]
pub struct AclQuery<'a> {
    /// The calling node.
    pub caller: &'a str,
    /// What the caller is trying to do.
    pub action: AclAction,
    /// Target node, when the action names one.
    pub node: Option<&'a str>,
    /// Target service, when the action names one.
    pub service: Option<&'a str>,
    /// Destination IP, once resolved. §9.3 checks "每个实际候选 IP".
    pub ip: Option<IpAddr>,
    /// Destination port.
    pub port: Option<u16>,
    /// Protocol.
    pub proto: Proto,
}

/// The outcome of an ACL check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    /// An explicit allow rule matched.
    Allowed,
    /// No allow rule matched, or an explicit deny matched first.
    Denied,
}

impl AclDecision {
    /// Whether access was granted.
    pub const fn is_allowed(self) -> bool {
        matches!(self, AclDecision::Allowed)
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rule: AclRule,
    net: Option<IpNet>,
}

/// A compiled, first-match-wins, default-deny ACL table.
#[derive(Debug, Clone, Default)]
pub struct AclTable {
    rules: Vec<CompiledRule>,
}

impl AclTable {
    /// Compiles rules, validating every CIDR up front.
    pub fn new(rules: Vec<AclRule>) -> Result<Self, AclError> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let net = match &rule.host_cidr {
                Some(text) => Some(
                    text.parse::<IpNet>()
                        .map_err(|_| AclError::InvalidCidr(text.clone()))?,
                ),
                None => None,
            };
            compiled.push(CompiledRule { rule, net });
        }
        Ok(AclTable { rules: compiled })
    }

    /// An empty table, which denies everything.
    pub fn deny_all() -> Self {
        AclTable::default()
    }

    /// Number of compiled rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the table has no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluates one access.
    ///
    /// The first rule whose every stated constraint matches decides; if no rule
    /// matches, access is denied. That ordering is what lets a deployment place
    /// a narrow deny ahead of a broad allow.
    pub fn check(&self, query: &AclQuery<'_>) -> AclDecision {
        for compiled in &self.rules {
            if Self::matches(compiled, query) {
                return if compiled.rule.allow {
                    AclDecision::Allowed
                } else {
                    AclDecision::Denied
                };
            }
        }
        AclDecision::Denied
    }

    fn matches(compiled: &CompiledRule, query: &AclQuery<'_>) -> bool {
        let rule = &compiled.rule;
        if rule.caller != query.caller || rule.action != query.action {
            return false;
        }
        if let Some(node) = &rule.node {
            if query.node != Some(node.as_str()) {
                return false;
            }
        }
        if let Some(service) = &rule.service {
            if query.service != Some(service.as_str()) {
                return false;
            }
        }
        if let Some(ports) = &rule.ports {
            match query.port {
                Some(port) if ports.contains(&port) => {}
                _ => return false,
            }
        }
        if let Some(proto) = rule.proto {
            if proto != query.proto {
                return false;
            }
        }
        if let Some(net) = compiled.net {
            match query.ip {
                Some(ip) if net.contains(&ip) => {}
                _ => return false,
            }
        }
        true
    }
}

/// The Hub's relaying capability switch (§9.3).
///
/// "`relay_allow=[]` 为默认" — an empty list means no node may relay, and this is
/// deliberately a separate gate from the target ACL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayAllow {
    allowed: Vec<String>,
}

impl RelayAllow {
    /// Builds the switch from configuration.
    pub fn new(allowed: Vec<String>) -> Self {
        RelayAllow { allowed }
    }

    /// Whether `node` may act as an intermediate hop.
    pub fn is_allowed(&self, node: &str) -> bool {
        self.allowed.iter().any(|candidate| candidate == node)
    }

    /// Whether relaying is enabled at all.
    pub fn is_enabled(&self) -> bool {
        !self.allowed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        caller: &str,
        action: AclAction,
        allow: bool,
        node: Option<&str>,
        service: Option<&str>,
    ) -> AclRule {
        AclRule {
            caller: caller.into(),
            action,
            allow,
            node: node.map(Into::into),
            service: service.map(Into::into),
            host_cidr: None,
            ports: None,
            proto: None,
        }
    }

    fn query<'a>(caller: &'a str, action: AclAction) -> AclQuery<'a> {
        AclQuery {
            caller,
            action,
            node: None,
            service: None,
            ip: None,
            port: None,
            proto: Proto::Tcp,
        }
    }

    /// §9.3: no matching rule means denial.
    #[test]
    fn an_empty_table_denies_everything() {
        let table = AclTable::deny_all();
        assert_eq!(
            table.check(&query("client-b", AclAction::ConnectAddress)),
            AclDecision::Denied
        );
    }

    #[test]
    fn an_explicit_allow_grants_access() {
        let table = AclTable::new(vec![rule(
            "client-b",
            AclAction::ConnectService,
            true,
            Some("client-a"),
            Some("web"),
        )])
        .unwrap();

        let mut q = query("client-b", AclAction::ConnectService);
        q.node = Some("client-a");
        q.service = Some("web");
        assert!(table.check(&q).is_allowed());

        // A different service on the same node is not covered.
        q.service = Some("db");
        assert!(!table.check(&q).is_allowed());
        // Nor is a different caller.
        q.service = Some("web");
        q.caller = "client-c";
        assert!(!table.check(&q).is_allowed());
    }

    /// T23: raw node addresses stay denied until a dedicated rule allows them,
    /// and publishing another service grants nothing laterally.
    #[test]
    fn node_address_access_needs_its_own_rule() {
        let table = AclTable::new(vec![rule(
            "client-b",
            AclAction::ConnectService,
            true,
            Some("client-a"),
            Some("web"),
        )])
        .unwrap();

        let mut q = query("client-b", AclAction::ConnectNodeAddress);
        q.node = Some("client-a");
        q.ip = Some("127.0.0.1".parse().unwrap());
        q.port = Some(22);
        assert!(
            !table.check(&q).is_allowed(),
            "publishing a service must not imply raw address access"
        );
    }

    #[test]
    fn cidr_and_port_constraints_are_enforced() {
        let table = AclTable::new(vec![AclRule {
            caller: "client-b".into(),
            action: AclAction::ConnectNodeAddress,
            allow: true,
            node: Some("client-a".into()),
            service: None,
            host_cidr: Some("127.0.0.1/32".into()),
            ports: Some(vec![22]),
            proto: Some(Proto::Tcp),
        }])
        .unwrap();

        let mut q = query("client-b", AclAction::ConnectNodeAddress);
        q.node = Some("client-a");
        q.ip = Some("127.0.0.1".parse().unwrap());
        q.port = Some(22);
        assert!(table.check(&q).is_allowed());

        // Wrong port.
        q.port = Some(23);
        assert!(!table.check(&q).is_allowed());

        // Address outside the CIDR.
        q.port = Some(22);
        q.ip = Some("127.0.0.2".parse().unwrap());
        assert!(!table.check(&q).is_allowed());

        // Unresolved address cannot satisfy a CIDR rule.
        q.ip = None;
        assert!(!table.check(&q).is_allowed());

        // Wrong protocol.
        q.ip = Some("127.0.0.1".parse().unwrap());
        q.proto = Proto::Udp;
        assert!(!table.check(&q).is_allowed());
    }

    /// A narrow deny placed before a broad allow must win.
    #[test]
    fn first_match_wins_so_a_deny_can_precede_an_allow() {
        let table = AclTable::new(vec![
            rule(
                "client-b",
                AclAction::ConnectService,
                false,
                Some("client-a"),
                Some("admin"),
            ),
            rule("client-b", AclAction::ConnectService, true, None, None),
        ])
        .unwrap();

        let mut q = query("client-b", AclAction::ConnectService);
        q.node = Some("client-a");
        q.service = Some("admin");
        assert!(!table.check(&q).is_allowed());

        q.service = Some("web");
        assert!(table.check(&q).is_allowed());
    }

    #[test]
    fn actions_are_distinguished() {
        let table = AclTable::new(vec![rule(
            "client-b",
            AclAction::ConnectAddress,
            true,
            None,
            None,
        )])
        .unwrap();
        assert!(table
            .check(&query("client-b", AclAction::ConnectAddress))
            .is_allowed());
        assert!(!table
            .check(&query("client-b", AclAction::ConnectService))
            .is_allowed());
    }

    #[test]
    fn invalid_cidr_is_rejected_at_compile_time() {
        let bad = AclRule {
            caller: "c".into(),
            action: AclAction::ConnectAddress,
            allow: true,
            node: None,
            service: None,
            host_cidr: Some("not-a-cidr".into()),
            ports: None,
            proto: None,
        };
        assert_eq!(
            AclTable::new(vec![bad]).unwrap_err(),
            AclError::InvalidCidr("not-a-cidr".into())
        );
    }

    /// §9.3: `relay_allow=[]` is the default and disables relaying.
    #[test]
    fn relay_allow_defaults_to_closed() {
        let relay = RelayAllow::default();
        assert!(!relay.is_enabled());
        assert!(!relay.is_allowed("client-a"));

        let relay = RelayAllow::new(vec!["client-a".into()]);
        assert!(relay.is_enabled());
        assert!(relay.is_allowed("client-a"));
        assert!(!relay.is_allowed("client-b"));
    }

    #[test]
    fn rules_parse_from_toml_shape_of_the_design() {
        #[derive(Deserialize)]
        struct Wrapper {
            acl: Vec<AclRule>,
        }
        let parsed: Wrapper = toml::from_str(
            r#"
[[acl]]
caller = "client-b"
action = "connect_service"
node = "client-a"
service = "web"
proto = "tcp"
allow = true

[[acl]]
caller = "client-b"
action = "connect_node_address"
node = "client-a"
host_cidr = "127.0.0.1/32"
ports = [22]
proto = "tcp"
allow = true
"#,
        )
        .unwrap();

        assert_eq!(parsed.acl.len(), 2);
        assert_eq!(parsed.acl[0].action, AclAction::ConnectService);
        assert!(parsed.acl[0].allow);
        let table = AclTable::new(parsed.acl).unwrap();
        assert_eq!(table.len(), 2);
    }
}
