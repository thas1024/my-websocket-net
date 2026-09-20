//! Route selection and chain validation (DESIGN.md §7.1, §7.6, §10).
//!
//! §7.1 fixes the rule shape: "规则按顺序首匹配，未匹配用 final". Routing and
//! authorisation are deliberately separate steps — §10 warns that "路由选中了
//! 节点，不代表访问一定被允许" — so a [`RouteDecision`] is an intent, never a
//! permission.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use wsnet_limits::MAX_CHAIN_HOPS;

use crate::dest::{is_slug, Destination};

/// Where a flow exits when no rule redirects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FinalRoute {
    /// Dial directly, without the proxy.
    Direct,
    /// Exit at the Hub.
    Server,
}

/// One ordered routing rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRule {
    /// Match patterns; any one matching selects this rule.
    #[serde(rename = "match")]
    pub matchers: Vec<String>,
    /// Intermediate nodes for the selected route.
    #[serde(default)]
    pub via: Vec<String>,
}

/// The router configuration section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Router {
    /// Fallback when no rule matches.
    #[serde(rename = "final")]
    pub final_route: FinalRoute,
    /// Ordered rules.
    #[serde(default, rename = "rules")]
    pub rules: Vec<RouteRule>,
}

impl Default for Router {
    fn default() -> Self {
        Router {
            final_route: FinalRoute::Server,
            rules: Vec::new(),
        }
    }
}

/// Errors from routing and chain validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteError {
    /// A match pattern could not be parsed.
    #[error("`{0}` is not a valid match pattern")]
    InvalidPattern(String),
    /// The chain is longer than the design permits.
    #[error("chain has {actual} hops, limit is {limit}")]
    TooManyHops {
        /// Hop count.
        actual: usize,
        /// The limit.
        limit: usize,
    },
    /// The same node appears twice in one chain.
    #[error("node `{0}` appears more than once in the chain")]
    DuplicateHop(String),
    /// The chain loops back to the calling node.
    #[error("chain loops back to the calling node `{0}`")]
    SelfLoop(String),
    /// The chain names the service publisher, which §7.6 makes the final leg.
    #[error("chain must not contain the destination node `{0}`")]
    DestinationInPath(String),
    /// A hop id was not a normalised slug.
    #[error("`{0}` is not a normalised ASCII slug")]
    NotASlug(String),
}

/// A parsed match pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    Any,
    Domain(String),
    DomainSuffix(String),
    Cidr(IpNet),
    Service { node: String, name: String },
    Node(String),
}

impl Pattern {
    fn parse(text: &str) -> Result<Pattern, RouteError> {
        let invalid = || RouteError::InvalidPattern(text.to_string());
        if text == "*" {
            return Ok(Pattern::Any);
        }
        let (prefix, value) = text.split_once(':').ok_or_else(invalid)?;
        match prefix {
            "domain" => {
                if let Some(suffix) = value.strip_prefix("*.") {
                    if suffix.is_empty() {
                        return Err(invalid());
                    }
                    Ok(Pattern::DomainSuffix(suffix.to_ascii_lowercase()))
                } else if value.is_empty() {
                    Err(invalid())
                } else {
                    Ok(Pattern::Domain(value.to_ascii_lowercase()))
                }
            }
            "cidr" => value.parse::<IpNet>().map(Pattern::Cidr).map_err(|_| invalid()),
            "node" => {
                if is_slug(value) {
                    Ok(Pattern::Node(value.to_string()))
                } else {
                    Err(invalid())
                }
            }
            "service" => {
                let (node, name) = value.split_once('/').ok_or_else(invalid)?;
                if !is_slug(node) || (name != "*" && !is_slug(name)) {
                    return Err(invalid());
                }
                Ok(Pattern::Service {
                    node: node.to_string(),
                    name: name.to_string(),
                })
            }
            _ => Err(invalid()),
        }
    }

    fn matches(&self, destination: &Destination) -> bool {
        match (self, destination) {
            (Pattern::Any, _) => true,
            (Pattern::Domain(expected), _) => destination
                .host_port()
                .is_some_and(|(host, _)| host.eq_ignore_ascii_case(expected)),
            (Pattern::DomainSuffix(suffix), _) => {
                destination.host_port().is_some_and(|(host, _)| {
                    let host = host.to_ascii_lowercase();
                    // The suffix must sit on a label boundary, so
                    // `notexample.com` cannot match `*.example.com`.
                    host == *suffix || host.ends_with(&format!(".{suffix}"))
                })
            }
            (Pattern::Cidr(net), _) => destination
                .host_port()
                .and_then(|(host, _)| host.parse::<IpAddr>().ok())
                .is_some_and(|ip| net.contains(&ip)),
            (
                Pattern::Service {
                    node: want_node,
                    name: want_name,
                },
                Destination::Service { node, name, .. },
            ) => node == want_node && (want_name == "*" || name == want_name),
            (Pattern::Node(want), _) => destination.named_node() == Some(want.as_str()),
            _ => false,
        }
    }
}

/// The chosen route for one destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    /// Intermediate nodes, in order. Empty means "exit at the current end".
    pub via: Vec<String>,
    /// Where the flow exits if the chain is empty.
    pub exit: FinalRoute,
}

/// A compiled router.
#[derive(Debug, Clone)]
pub struct RouterTable {
    final_route: FinalRoute,
    rules: Vec<(Vec<Pattern>, RouteRule)>,
}

impl RouterTable {
    /// Compiles the router, rejecting bad patterns up front.
    pub fn new(router: &Router) -> Result<Self, RouteError> {
        let mut rules = Vec::with_capacity(router.rules.len());
        for rule in &router.rules {
            let mut patterns = Vec::with_capacity(rule.matchers.len());
            for matcher in &rule.matchers {
                patterns.push(Pattern::parse(matcher)?);
            }
            rules.push((patterns, rule.clone()));
        }
        Ok(RouterTable {
            final_route: router.final_route,
            rules,
        })
    }

    /// The fallback route.
    pub fn final_route(&self) -> FinalRoute {
        self.final_route
    }

    /// Picks a route for `destination`, first match wins.
    pub fn decide(&self, destination: &Destination) -> RouteDecision {
        for (patterns, rule) in &self.rules {
            if patterns.iter().any(|pattern| pattern.matches(destination)) {
                return RouteDecision {
                    via: rule.via.clone(),
                    exit: self.final_route,
                };
            }
        }
        RouteDecision {
            via: Vec::new(),
            exit: self.final_route,
        }
    }
}

/// Validates a chain before it is used (§7.1).
///
/// §7.1 lists exactly these rejections: "Hub 检查全部 hop 身份、重复节点、自环、
/// 最大 4 跳、每边 ACL". Note the last clause of §7.6: for a named service the
/// `via` list holds *intermediate* nodes only, because the publisher is the final
/// leg — so naming the publisher in `via` is a rejected misconfiguration rather
/// than a harmless redundancy.
pub fn validate_chain(
    caller: &str,
    via: &[String],
    destination: &Destination,
) -> Result<(), RouteError> {
    if via.len() > MAX_CHAIN_HOPS {
        return Err(RouteError::TooManyHops {
            actual: via.len(),
            limit: MAX_CHAIN_HOPS,
        });
    }
    for hop in via {
        if !is_slug(hop) {
            return Err(RouteError::NotASlug(hop.clone()));
        }
        if hop == caller {
            return Err(RouteError::SelfLoop(hop.clone()));
        }
    }
    // Duplicate detection across the whole chain, including the caller.
    let mut seen: Vec<&str> = vec![caller];
    for hop in via {
        if seen.contains(&hop.as_str()) {
            return Err(RouteError::DuplicateHop(hop.clone()));
        }
        seen.push(hop);
    }
    if let Some(publisher) = destination.named_node() {
        if via.iter().any(|hop| hop == publisher) {
            return Err(RouteError::DestinationInPath(publisher.to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router_with(rules: Vec<RouteRule>) -> RouterTable {
        RouterTable::new(&Router {
            final_route: FinalRoute::Server,
            rules,
        })
        .unwrap()
    }

    fn rule(matchers: &[&str], via: &[&str]) -> RouteRule {
        RouteRule {
            matchers: matchers.iter().map(|s| s.to_string()).collect(),
            via: via.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn unmatched_destinations_use_final() {
        let table = router_with(vec![]);
        let decision = table.decide(&Destination::address("example.com", 443));
        assert!(decision.via.is_empty());
        assert_eq!(decision.exit, FinalRoute::Server);
    }

    #[test]
    fn first_matching_rule_wins() {
        let table = router_with(vec![
            rule(&["domain:*.internal.example"], &["client-b", "client-c"]),
            rule(&["domain:*.internal.example"], &["client-z"]),
        ]);
        let decision = table.decide(&Destination::address("db.internal.example", 5432));
        assert_eq!(decision.via, vec!["client-b", "client-c"]);
    }

    #[test]
    fn domain_and_suffix_patterns() {
        let table = router_with(vec![rule(&["domain:exact.example"], &["hop"])]);
        assert!(!table
            .decide(&Destination::address("exact.example", 80))
            .via
            .is_empty());
        assert!(table
            .decide(&Destination::address("sub.exact.example", 80))
            .via
            .is_empty());
        // Case-insensitive.
        assert!(!table
            .decide(&Destination::address("EXACT.EXAMPLE", 80))
            .via
            .is_empty());

        let table = router_with(vec![rule(&["domain:*.example.com"], &["hop"])]);
        // The bare suffix matches too, which is the useful reading of `*.x`.
        assert!(!table
            .decide(&Destination::address("example.com", 80))
            .via
            .is_empty());
        assert!(!table
            .decide(&Destination::address("a.b.example.com", 80))
            .via
            .is_empty());
        // A lookalike domain must not match.
        assert!(table
            .decide(&Destination::address("notexample.com", 80))
            .via
            .is_empty());
        assert!(table
            .decide(&Destination::address("example.com.evil.net", 80))
            .via
            .is_empty());
    }

    #[test]
    fn cidr_patterns_match_only_literal_ips() {
        let table = router_with(vec![rule(&["cidr:10.0.0.0/8"], &["internal"])]);
        assert!(!table
            .decide(&Destination::address("10.1.2.3", 80))
            .via
            .is_empty());
        assert!(table
            .decide(&Destination::address("11.1.2.3", 80))
            .via
            .is_empty());
        // A hostname is not an IP, so a CIDR rule cannot match it before DNS.
        assert!(table
            .decide(&Destination::address("db.internal.example", 80))
            .via
            .is_empty());
    }

    #[test]
    fn service_and_node_patterns() {
        let table = router_with(vec![rule(&["service:client-a/web"], &["relay"])]);
        assert!(!table
            .decide(&Destination::service("client-a", "web"))
            .via
            .is_empty());
        assert!(table
            .decide(&Destination::service("client-a", "db"))
            .via
            .is_empty());
        assert!(table
            .decide(&Destination::service("client-b", "web"))
            .via
            .is_empty());

        let table = router_with(vec![rule(&["service:client-a/*"], &["relay"])]);
        assert!(!table
            .decide(&Destination::service("client-a", "anything"))
            .via
            .is_empty());

        let table = router_with(vec![rule(&["node:client-a"], &["relay"])]);
        assert!(!table
            .decide(&Destination::node_address("client-a", "10.0.0.1", 22))
            .via
            .is_empty());
        assert!(table
            .decide(&Destination::address("10.0.0.1", 22))
            .via
            .is_empty());
    }

    #[test]
    fn any_pattern_matches_everything() {
        let table = router_with(vec![rule(&["*"], &["catch-all"])]);
        assert_eq!(
            table.decide(&Destination::service("a", "b")).via,
            vec!["catch-all"]
        );
        assert_eq!(
            table.decide(&Destination::address("h", 1)).via,
            vec!["catch-all"]
        );
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        for bad in [
            "domain:",
            "domain:*.",
            "cidr:not-a-net",
            "node:not a slug",
            "service:no-slash",
            "service:/web",
            "unknown:value",
            "nocolon",
        ] {
            let result = RouterTable::new(&Router {
                final_route: FinalRoute::Server,
                rules: vec![rule(&[bad], &[])],
            });
            assert!(result.is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn final_route_can_be_direct() {
        let table = RouterTable::new(&Router {
            final_route: FinalRoute::Direct,
            rules: vec![],
        })
        .unwrap();
        assert_eq!(
            table.decide(&Destination::address("h", 1)).exit,
            FinalRoute::Direct
        );
    }

    // ---------------------------------------------------------------- chains

    #[test]
    fn a_valid_chain_passes() {
        assert!(validate_chain(
            "caller",
            &["client-b".into(), "client-c".into()],
            &Destination::address("example.com", 443)
        )
        .is_ok());
    }

    /// T13: loops, duplicates, and over-long chains are rejected.
    #[test]
    fn invalid_chains_are_rejected() {
        assert_eq!(
            validate_chain("caller", &["caller".into()], &Destination::address("h", 1))
                .unwrap_err(),
            RouteError::SelfLoop("caller".into())
        );
        assert_eq!(
            validate_chain(
                "caller",
                &["a".into(), "a".into()],
                &Destination::address("h", 1)
            )
            .unwrap_err(),
            RouteError::DuplicateHop("a".into())
        );
        assert_eq!(
            validate_chain(
                "caller",
                &["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
                &Destination::address("h", 1)
            )
            .unwrap_err(),
            RouteError::TooManyHops {
                actual: 5,
                limit: MAX_CHAIN_HOPS
            }
        );
        assert_eq!(
            validate_chain("caller", &["bad hop".into()], &Destination::address("h", 1))
                .unwrap_err(),
            RouteError::NotASlug("bad hop".into())
        );
    }

    #[test]
    fn exactly_the_hop_limit_is_allowed() {
        let via: Vec<String> = (0..MAX_CHAIN_HOPS)
            .map(|i| format!("hop{i}"))
            .collect();
        assert!(validate_chain("caller", &via, &Destination::address("h", 1)).is_ok());
    }

    /// T13: for a named service the publisher is the final leg, so naming it as
    /// an intermediate hop is rejected.
    #[test]
    fn the_service_publisher_must_not_appear_as_a_hop() {
        assert_eq!(
            validate_chain(
                "caller",
                &["client-b".into(), "client-a".into()],
                &Destination::service("client-a", "web")
            )
            .unwrap_err(),
            RouteError::DestinationInPath("client-a".into())
        );
        // For a plain address there is no publisher, so the same id is fine.
        assert!(validate_chain(
            "caller",
            &["client-a".into()],
            &Destination::address("h", 1)
        )
        .is_ok());
    }

    #[test]
    fn router_parses_the_design_config_shape() {
        let parsed: Router = toml::from_str(
            r#"
final = "server"

[[rules]]
match = ["domain:*.internal.example"]
via = ["client-b", "client-c"]
"#,
        )
        .unwrap();
        assert_eq!(parsed.final_route, FinalRoute::Server);
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].via, vec!["client-b", "client-c"]);
        assert!(RouterTable::new(&parsed).is_ok());
    }
}
