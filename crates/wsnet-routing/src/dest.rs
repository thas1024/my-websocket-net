//! Protocol selector and the `Open` destination union (DESIGN.md §7.6).
//!
//! §7.6 requires the destination to be a *strict* union — "恰好出现一种" — so a
//! request that tries to carry both a service name and a raw address is
//! unrepresentable here rather than rejected later by a validation pass.

use serde::{Deserialize, Serialize};
use wsnet_protocol::Canonical;

/// Transport protocol of a stream or datagram flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// Stream protocol.
    Tcp,
    /// Datagram protocol.
    Udp,
}

impl Proto {
    /// The wire spelling used in metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Maximum length of a node id or service name slug.
pub const MAX_SLUG_LEN: usize = 64;

/// Whether `value` is a normalised ASCII slug.
///
/// §7.6 restricts the optional SOCKS namespace to "规范化 ASCII slug" and
/// forbids encoding a path, port, or arbitrary address into the name, so the
/// character set is intentionally narrow and the first character must be
/// alphanumeric. That last rule is what rejects `.` and `..`, which would
/// otherwise look like slugs while reading as path components.
pub fn is_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SLUG_LEN {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Errors from destination construction and validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DestinationError {
    /// A node id or service name was not a valid slug.
    #[error("`{0}` is not a normalised ASCII slug")]
    NotASlug(String),
    /// A port was zero, which is never a valid remote target.
    #[error("port 0 is not a valid target port")]
    ZeroPort,
    /// A host was empty.
    #[error("target host must not be empty")]
    EmptyHost,
}

/// The `Open` target, a strict union (§7.6).
///
/// `deny_unknown_fields` is what makes the union *strict* on the wire: without
/// it, a request carrying `type = "service"` plus a stray `host`/`port` would
/// deserialize successfully and silently drop the extra fields, which is exactly
/// the "指定 target 和 service 同时存在" case §7.1 says to reject.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Destination {
    /// A plain address: ordinary SOCKS or a Hub/node exit target.
    Address {
        /// Hostname or IP literal.
        host: String,
        /// Destination port.
        port: u16,
    },
    /// A named service published by a node; the recommended reverse-access form.
    Service {
        /// Publishing node.
        node: String,
        /// Published service name.
        name: String,
        /// Optional pinned service revision.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revision: Option<u64>,
    },
    /// An address as seen from a specific node. Denied by default.
    NodeAddress {
        /// Node whose view of the address is meant.
        node: String,
        /// Host as resolved by that node.
        host: String,
        /// Destination port.
        port: u16,
    },
}

impl Destination {
    /// Builds an [`Destination::Address`].
    pub fn address(host: impl Into<String>, port: u16) -> Self {
        Destination::Address {
            host: host.into(),
            port,
        }
    }

    /// Builds a [`Destination::Service`].
    pub fn service(node: impl Into<String>, name: impl Into<String>) -> Self {
        Destination::Service {
            node: node.into(),
            name: name.into(),
            revision: None,
        }
    }

    /// Builds a [`Destination::NodeAddress`].
    pub fn node_address(node: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Destination::NodeAddress {
            node: node.into(),
            host: host.into(),
            port,
        }
    }

    /// The destination kind, for diagnostics and ACL dispatch.
    pub const fn kind(&self) -> DestinationKind {
        match self {
            Destination::Address { .. } => DestinationKind::Address,
            Destination::Service { .. } => DestinationKind::Service,
            Destination::NodeAddress { .. } => DestinationKind::NodeAddress,
        }
    }

    /// The node this destination names, if any.
    ///
    /// For a [`Destination::Service`] this is the *publisher*, which §7.6 makes
    /// the final leg rather than an intermediate hop.
    pub fn named_node(&self) -> Option<&str> {
        match self {
            Destination::Address { .. } => None,
            Destination::Service { node, .. } | Destination::NodeAddress { node, .. } => Some(node),
        }
    }

    /// The host and port this destination ultimately dials, when it has one.
    pub fn host_port(&self) -> Option<(&str, u16)> {
        match self {
            Destination::Address { host, port } | Destination::NodeAddress { host, port, .. } => {
                Some((host, *port))
            }
            Destination::Service { .. } => None,
        }
    }

    /// Validates slugs and ports.
    pub fn validate(&self) -> Result<(), DestinationError> {
        match self {
            Destination::Address { host, port } => {
                if host.is_empty() {
                    return Err(DestinationError::EmptyHost);
                }
                if *port == 0 {
                    return Err(DestinationError::ZeroPort);
                }
                Ok(())
            }
            Destination::Service { node, name, .. } => {
                if !is_slug(node) {
                    return Err(DestinationError::NotASlug(node.clone()));
                }
                if !is_slug(name) {
                    return Err(DestinationError::NotASlug(name.clone()));
                }
                Ok(())
            }
            Destination::NodeAddress { node, host, port } => {
                if !is_slug(node) {
                    return Err(DestinationError::NotASlug(node.clone()));
                }
                if host.is_empty() {
                    return Err(DestinationError::EmptyHost);
                }
                if *port == 0 {
                    return Err(DestinationError::ZeroPort);
                }
                Ok(())
            }
        }
    }

    /// The destination as a canonical value, for embedding in message metadata.
    pub fn to_canonical(&self) -> Canonical {
        match self {
            Destination::Address { host, port } => Canonical::object([
                ("host", Canonical::str(host.clone())),
                ("port", Canonical::int(*port as i64)),
                ("type", Canonical::str("address")),
            ]),
            Destination::Service {
                node,
                name,
                revision,
            } => {
                let mut entries = vec![
                    ("name".to_string(), Canonical::str(name.clone())),
                    ("node".to_string(), Canonical::str(node.clone())),
                    ("type".to_string(), Canonical::str("service")),
                ];
                if let Some(revision) = revision {
                    entries.push(("revision".to_string(), Canonical::u64_decimal(*revision)));
                }
                Canonical::object(entries)
            }
            Destination::NodeAddress { node, host, port } => Canonical::object([
                ("host", Canonical::str(host.clone())),
                ("node", Canonical::str(node.clone())),
                ("port", Canonical::int(*port as i64)),
                ("type", Canonical::str("node_address")),
            ]),
        }
    }

    /// Reads a destination back out of canonical metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Destination, DestinationError> {
        let kind = value.get_str("type").map_err(|_| DestinationError::EmptyHost)?;
        let destination = match kind {
            "address" => Destination::Address {
                host: value
                    .get_str("host")
                    .map_err(|_| DestinationError::EmptyHost)?
                    .to_string(),
                port: u16::try_from(value.get_i64("port").unwrap_or(0)).unwrap_or(0),
            },
            "service" => Destination::Service {
                node: value
                    .get_str("node")
                    .map_err(|_| DestinationError::NotASlug(String::new()))?
                    .to_string(),
                name: value
                    .get_str("name")
                    .map_err(|_| DestinationError::NotASlug(String::new()))?
                    .to_string(),
                revision: value.get_u64("revision").ok(),
            },
            "node_address" => Destination::NodeAddress {
                node: value
                    .get_str("node")
                    .map_err(|_| DestinationError::NotASlug(String::new()))?
                    .to_string(),
                host: value
                    .get_str("host")
                    .map_err(|_| DestinationError::EmptyHost)?
                    .to_string(),
                port: u16::try_from(value.get_i64("port").unwrap_or(0)).unwrap_or(0),
            },
            _ => return Err(DestinationError::EmptyHost),
        };
        destination.validate()?;
        Ok(destination)
    }

    /// Canonical bytes, used as the `operation_hash` input (§5.2).
    ///
    /// The encoding is the workspace's sorted-key canonical JSON, so two nodes
    /// that build the same destination agree on the hash byte for byte.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_canonical().to_bytes()
    }
}

/// The kind of a [`Destination`], without its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestinationKind {
    /// Plain address.
    Address,
    /// Published named service.
    Service,
    /// Node-relative address.
    NodeAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_restricted() {
        for good in ["client-a", "web", "a.b_c", "A1"] {
            assert!(is_slug(good), "{good} should be a slug");
        }
        for bad in ["", "a b", "a/b", "a:b", "a?b", "..", "a\u{00e9}"] {
            assert!(!is_slug(bad), "{bad} should not be a slug");
        }
        assert!(!is_slug(&"a".repeat(MAX_SLUG_LEN + 1)));
    }

    #[test]
    fn service_destination_rejects_bad_slugs() {
        assert_eq!(
            Destination::service("client/a", "web").validate().unwrap_err(),
            DestinationError::NotASlug("client/a".into())
        );
        assert_eq!(
            Destination::service("client-a", "a b").validate().unwrap_err(),
            DestinationError::NotASlug("a b".into())
        );
        assert!(Destination::service("client-a", "web").validate().is_ok());
    }

    #[test]
    fn address_destination_rejects_zero_port_and_empty_host() {
        assert_eq!(
            Destination::address("example.com", 0).validate().unwrap_err(),
            DestinationError::ZeroPort
        );
        assert_eq!(
            Destination::address("", 443).validate().unwrap_err(),
            DestinationError::EmptyHost
        );
    }

    /// §7.6: the union is strict, so a value cannot be two kinds at once.
    #[test]
    fn the_union_is_strict_on_the_wire() {
        let service: Destination = toml::from_str(r#"type = "service"
node = "client-a"
name = "web""#)
        .unwrap();
        assert_eq!(service, Destination::service("client-a", "web"));

        // A service carrying a `host` field is not a valid service destination.
        let mixed = r#"type = "service"
node = "client-a"
name = "web"
host = "127.0.0.1""#;
        assert!(toml::from_str::<Destination>(mixed).is_err());

        // And a target naming both a service and a raw address cannot be
        // expressed by picking a type and stuffing both fields in.
        let address: Destination = toml::from_str(r#"type = "address"
host = "example.com"
port = 443"#)
        .unwrap();
        assert_eq!(address, Destination::address("example.com", 443));
    }

    #[test]
    fn node_address_round_trips() {
        let value = Destination::node_address("client-a", "127.0.0.1", 22);
        let text = toml::to_string(&value).unwrap();
        assert_eq!(toml::from_str::<Destination>(&text).unwrap(), value);
    }

    #[test]
    fn named_node_and_host_port_helpers() {
        assert_eq!(Destination::address("h", 1).named_node(), None);
        assert_eq!(
            Destination::service("client-a", "web").named_node(),
            Some("client-a")
        );
        assert_eq!(
            Destination::node_address("client-a", "10.0.0.1", 22).named_node(),
            Some("client-a")
        );
        assert_eq!(
            Destination::address("example.com", 443).host_port(),
            Some(("example.com", 443))
        );
        assert_eq!(Destination::service("a", "web").host_port(), None);
    }

    /// The canonical encoding must be stable and differ between kinds.
    #[test]
    fn canonical_bytes_are_sorted_and_distinct() {
        let service = Destination::service("client-a", "web");
        assert_eq!(
            String::from_utf8(service.canonical_bytes()).unwrap(),
            r#"{"name":"web","node":"client-a","type":"service"}"#
        );
        assert_ne!(
            service.canonical_bytes(),
            Destination::node_address("client-a", "127.0.0.1", 22).canonical_bytes()
        );
        assert_ne!(
            Destination::address("a", 1).canonical_bytes(),
            Destination::address("a", 2).canonical_bytes()
        );
    }

    /// A pinned revision must change the operation hash (§7.6 rejects stale
    /// revisions, which only works if the revision is part of the identity).
    #[test]
    fn revision_changes_the_canonical_encoding() {
        let mut pinned = Destination::service("client-a", "web");
        let unpinned = pinned.clone();
        pinned = match pinned {
            Destination::Service {
                node,
                name,
                revision: _,
            } => Destination::Service {
                node,
                name,
                revision: Some(7),
            },
            other => other,
        };
        assert_ne!(pinned.canonical_bytes(), unpinned.canonical_bytes());
        assert_eq!(
            String::from_utf8(pinned.canonical_bytes()).unwrap(),
            r#"{"name":"web","node":"client-a","revision":"7","type":"service"}"#
        );
    }

    #[test]
    fn kind_matches_the_variant() {
        assert_eq!(Destination::address("h", 1).kind(), DestinationKind::Address);
        assert_eq!(
            Destination::service("a", "b").kind(),
            DestinationKind::Service
        );
        assert_eq!(
            Destination::node_address("a", "h", 1).kind(),
            DestinationKind::NodeAddress
        );
    }
}
