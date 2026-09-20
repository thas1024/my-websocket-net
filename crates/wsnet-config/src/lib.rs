#![forbid(unsafe_code)]
//! `wsnet` TOML configuration schema and load-time validation.
//!
//! DESIGN.md section 10 defines two configuration documents:
//!
//! * [`ServerConfig`] for `server.toml`, the Hub side.
//! * [`ClientConfig`] for `client.toml`, the node side.
//!
//! Both reuse the routing crate's types rather than mirroring them: [`AclRule`]
//! for `[[acl]]`, [`Router`] for `[router]`, and [`Destination`] for a forward's
//! target, so a document cannot describe a shape the rest of the workspace is
//! unable to enforce.
//!
//! Parsing is tolerant and validation is strict. Every field has a serde
//! default, so a bare document parses; [`ServerConfig::validate`] and
//! [`ClientConfig::validate`] then refuse a document that would be unsafe to
//! serve. The cross-cutting rules implemented here are the ones the design wants
//! answered *before* a process starts:
//!
//! * the accepted clock skew window stays inside the budget DESIGN.md section 5.1
//!   fixes;
//! * names are normalised ASCII slugs (DESIGN.md section 7.6);
//! * hop chains, destinations, ACLs, and router patterns are compiled once at
//!   load instead of failing per connection;
//! * a non-loopback listener without a source allowlist is rejected, which is the
//!   acceptance item in USAGE.md section 12;
//! * credentials are only ever named by path — an inline `secret` key is an
//!   unknown field and therefore a parse error, never a silently ignored one.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use wsnet_limits::{
    AUTH_NONCE_PER_NODE_MAX, AUTH_WINDOW_DEFAULT_SECS, AUTH_WINDOW_MAX_SECS, AUTH_WINDOW_MIN_SECS,
    BACKGROUND_BUDGET_BYTES_PER_SEC, BACKGROUND_JITTER_MAX_SECS, BACKGROUND_JITTER_MIN_SECS,
    CARRIER_GRACE_SECS, CONTROL_QUEUE_BYTES, FLOW_WINDOW_BYTES, MAX_AUTH_CANDIDATES,
    MAX_UDP_PAYLOAD, SESSION_WINDOW_BYTES, UDP_MAX_PAYLOAD_DEFAULT, UDP_QUEUE_TTL_DEFAULT_MS,
    UDP_QUEUE_TTL_MAX_MS, UDP_QUEUE_TTL_MIN_MS,
};
use wsnet_routing::dest::is_slug;
use wsnet_routing::{
    validate_chain, AclError, AclRule, AclTable, Destination, DestinationError, Proto, RelayAllow,
    RouteError, Router, RouterTable,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything a configuration document can be rejected for.
///
/// The variants carry the field path (`server.listen`, `forwards[0].via`, ...) so
/// an operator can fix the document without re-reading the binary, and the
/// wrapped routing errors are kept whole rather than flattened to a string so a
/// caller can still match on the underlying rule.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The document is not valid TOML, or not shaped like the schema.
    #[error("invalid TOML: {0}")]
    Toml(String),
    /// The document could not be read from disk.
    #[error("cannot read `{path}`: {message}")]
    Io {
        /// Path that failed.
        path: String,
        /// Operating-system message.
        message: String,
    },
    /// `auth_window_secs` is outside the window DESIGN.md section 5.1 allows.
    #[error("server.auth_window_secs {value} is outside {min}..={max}")]
    AuthWindowOutOfRange {
        /// Configured value.
        value: u64,
        /// Inclusive minimum.
        min: u64,
        /// Inclusive maximum.
        max: u64,
    },
    /// A listener address was not `host:port`.
    #[error("{field}: `{value}` is not a `host:port` address")]
    InvalidListen {
        /// Field path.
        field: String,
        /// Offending value.
        value: String,
    },
    /// A fixed port was zero.
    #[error("{field}: port 0 is not usable in `{value}`")]
    ZeroPort {
        /// Field path.
        field: String,
        /// Offending value.
        value: String,
    },
    /// A service target was not a usable `host:port`.
    #[error("{field}: `{value}` is not a usable `host:port` target")]
    InvalidTarget {
        /// Field path.
        field: String,
        /// Offending value.
        value: String,
    },
    /// An `allow_from` entry was not a CIDR.
    #[error("{field}: `{value}` is not a valid CIDR")]
    InvalidCidr {
        /// Field path.
        field: String,
        /// Offending value.
        value: String,
    },
    /// A name that must be a normalised ASCII slug was not one.
    #[error("{field}: `{value}` is not a normalised ASCII slug")]
    NotASlug {
        /// Field path.
        field: String,
        /// Offending value.
        value: String,
    },
    /// A required string was empty.
    #[error("{field}: must not be empty")]
    EmptyField {
        /// Field path.
        field: String,
    },
    /// A `secret_file` was empty; the schema has no inline-secret alternative.
    #[error("{field}: must name a file; inline secrets are not accepted")]
    EmptySecretFile {
        /// Field path.
        field: String,
    },
    /// A name was used twice in one list.
    #[error("{field}: `{value}` appears more than once")]
    Duplicate {
        /// Field path.
        field: String,
        /// Repeated value.
        value: String,
    },
    /// Two `[[servers]]` entries named the same hub.
    #[error("servers: hub_id `{value}` is declared more than once")]
    DuplicateHubId {
        /// Repeated hub id.
        value: String,
    },
    /// A non-loopback listener had no source allowlist (USAGE.md section 12).
    #[error("{field}: `{value}` is not loopback, so allow_from must list source CIDRs")]
    NonLoopbackWithoutAllowlist {
        /// Field path.
        field: String,
        /// Offending listener.
        value: String,
    },
    /// A URL was not an absolute `http`/`https` URL.
    #[error("{field}: `{value}` must be an absolute http:// or https:// URL")]
    InvalidUrl {
        /// Field path.
        field: String,
        /// Offending value.
        value: String,
    },
    /// A forward named a hub that no `[[servers]]` entry declares.
    #[error("{field}: `{value}` is neither `auto` nor a declared [[servers]] hub_id")]
    UnknownHub {
        /// Field path.
        field: String,
        /// Offending hub name.
        value: String,
    },
    /// A number was outside the range its budget permits.
    #[error("{field}: {value} is outside {min}..={max}")]
    OutOfRange {
        /// Field path.
        field: String,
        /// Configured value.
        value: u64,
        /// Inclusive minimum.
        min: u64,
        /// Inclusive maximum.
        max: u64,
    },
    /// A value that must be strictly positive was zero.
    #[error("{field}: {value} must be at least 1")]
    NotPositive {
        /// Field path.
        field: String,
        /// Configured value.
        value: u64,
    },
    /// A per-session window exceeded the session window it is carved out of.
    #[error("{field}: {value} exceeds the session window {session}")]
    WindowExceedsSession {
        /// Field path.
        field: String,
        /// Configured value.
        value: u64,
        /// The session window it must fit inside.
        session: u64,
    },
    /// The decoy jitter range was inverted.
    #[error("decoy.interval_min_secs {min} must not exceed decoy.interval_max_secs {max}")]
    InvertedDecoyInterval {
        /// Configured minimum.
        min: u64,
        /// Configured maximum.
        max: u64,
    },
    /// The UDP payload bound was unusable.
    #[error("{field}: {value} is outside 1..={max}")]
    UdpPayloadOutOfRange {
        /// Field path.
        field: String,
        /// Configured value.
        value: usize,
        /// Largest payload DESIGN.md section 7.4 allows.
        max: usize,
    },
    /// A UDP flow was configured while the client has UDP disabled.
    #[error("{field} uses proto `udp` but client.udp_enabled is false")]
    UdpDisabled {
        /// Field path.
        field: String,
    },
    /// A `[[forwards]]` entry did not name a destination.
    #[error("{field}: a forward must name exactly one destination")]
    MissingDestination {
        /// Field path.
        field: String,
    },
    /// The carrier profile list was empty.
    #[error("{field}: at least one carrier profile is required")]
    EmptyProfiles {
        /// Field path.
        field: String,
    },
    /// A carrier profile name is not one DESIGN.md section 6.4 defines.
    #[error("{field}: `{value}` is not a known carrier profile")]
    UnknownProfile {
        /// Field path.
        field: String,
        /// Offending value.
        value: String,
    },
    /// The SOCKS service namespace suffix was malformed.
    #[error("{field}: `{value}` is not a valid DNS suffix")]
    InvalidSuffix {
        /// Field path.
        field: String,
        /// Offending value.
        value: String,
    },
    /// An `[[acl]]` rule could not be compiled.
    #[error("acl[{index}]: {source}")]
    Acl {
        /// Index of the offending rule.
        index: usize,
        /// The routing crate's diagnosis.
        #[source]
        source: AclError,
    },
    /// A `[router]` rule could not be compiled.
    #[error("router: {0}")]
    Router(#[source] RouteError),
    /// A hop chain was invalid.
    #[error("{name}: {source}")]
    Chain {
        /// Field path of the chain.
        name: String,
        /// The routing crate's diagnosis.
        #[source]
        source: RouteError,
    },
    /// A destination was invalid.
    #[error("{name}: {source}")]
    Destination {
        /// Field path of the destination.
        name: String,
        /// The routing crate's diagnosis.
        #[source]
        source: DestinationError,
    },
}

// ---------------------------------------------------------------------------
// Shared default values
// ---------------------------------------------------------------------------

/// Default Hub identity, so a document that omits `hub_id` still parses.
fn default_hub_id() -> String {
    "hub".to_string()
}

/// Default node identity, so a document that omits `node_id` still parses.
fn default_node_id() -> String {
    "node".to_string()
}

/// Default Hub listener: loopback only, because USAGE.md section 3.1 expects
/// nginx to be the public face of the Hub.
fn default_server_listen() -> String {
    "127.0.0.1:8443".to_string()
}

/// Default SOCKS listener, loopback only (DESIGN.md section 9.3).
fn default_socks_listen() -> String {
    "127.0.0.1:1080".to_string()
}

/// Default decoy site selector.
fn default_decoy_site() -> String {
    "builtin".to_string()
}

/// DESIGN.md section 5.1 default acceptance window.
fn default_auth_window() -> u64 {
    AUTH_WINDOW_DEFAULT_SECS
}

/// DESIGN.md section 5.1 default per-node nonce cap.
fn default_nonce_max() -> usize {
    AUTH_NONCE_PER_NODE_MAX
}

/// DESIGN.md section 7.4 default maximum payload accepted from SOCKS5.
fn default_udp_max_payload() -> usize {
    UDP_MAX_PAYLOAD_DEFAULT
}

/// DESIGN.md section 7.4 default queue TTL for relayed datagrams.
fn default_udp_queue_ttl() -> u64 {
    UDP_QUEUE_TTL_DEFAULT_MS
}

/// DESIGN.md section 6.4: a fallback carrier is required in v1.
fn default_data_fallback() -> bool {
    true
}

/// DESIGN.md section 6.7 default number of authentication candidates.
fn default_max_candidates() -> usize {
    MAX_AUTH_CANDIDATES
}

/// DESIGN.md section 5.3 default carrier recovery grace.
fn default_resume_grace() -> u64 {
    CARRIER_GRACE_SECS
}

/// DESIGN.md section 7.5 default per-stream flow window.
fn default_flow_window() -> u64 {
    FLOW_WINDOW_BYTES
}

/// DESIGN.md section 7.5 default session-wide window.
fn default_session_window() -> u64 {
    SESSION_WINDOW_BYTES
}

/// DESIGN.md section 7.5 default control reserve.
fn default_control_reserve() -> usize {
    CONTROL_QUEUE_BYTES
}

/// The conservative profile set: only the binary carrier is enabled unless a
/// deployment opts into the HTTP-shaped profiles, which need matching front-end
/// locations (DESIGN.md section 6.4).
fn default_profiles() -> Vec<String> {
    vec!["binary".to_string()]
}

/// Lower bound of the background-request jitter range (DESIGN.md section 6.4).
fn default_decoy_interval_min() -> u64 {
    BACKGROUND_JITTER_MIN_SECS
}

/// Upper bound of the background-request jitter range (DESIGN.md section 6.4).
fn default_decoy_interval_max() -> u64 {
    BACKGROUND_JITTER_MAX_SECS
}

/// Global background-request bandwidth budget (DESIGN.md section 6.4).
fn default_decoy_budget() -> u64 {
    BACKGROUND_BUDGET_BYTES_PER_SEC as u64
}

/// Default virtual-service suffix (USAGE.md section 10).
fn default_namespace_suffix() -> String {
    "wsnet.invalid".to_string()
}

/// Streams are the common case when a service does not say otherwise.
fn default_proto() -> Proto {
    Proto::Tcp
}

/// Hub selection is automatic unless a forward pins one.
fn default_hub() -> String {
    "auto".to_string()
}

/// Lower priority numbers are tried first (DESIGN.md section 8).
fn default_priority() -> u32 {
    1
}

/// Carrier profiles DESIGN.md section 6.4 gives a bounded encoding for.
const SUPPORTED_PROFILES: [&str; 5] = ["binary", "json", "html", "js", "css"];

// ---------------------------------------------------------------------------
// Field-level helpers
// ---------------------------------------------------------------------------

/// Splits `host:port`, accepting the bracketed `[v6]:port` form.
///
/// Returns `None` for anything that is not a listener-shaped address, including
/// a host carrying a scheme, path, userinfo, or whitespace: this is also the gate
/// that keeps a target like `tcp://127.0.0.1:80` out of the configuration.
fn parse_host_port(value: &str) -> Option<(String, u16)> {
    let (host, port_text) = if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        (host, tail.strip_prefix(':')?)
    } else {
        let (host, port_text) = value.rsplit_once(':')?;
        if host.contains(':') {
            // An unbracketed IPv6 literal is ambiguous with the port separator.
            return None;
        }
        (host, port_text)
    };
    if host.is_empty()
        || host
            .contains(|c: char| c.is_whitespace() || c == '/' || c == '@' || c == '?' || c == '#')
    {
        return None;
    }
    Some((host.to_string(), port_text.parse().ok()?))
}

/// Whether `host` denotes this machine.
///
/// `localhost` is accepted as a name for loopback so a developer document does
/// not need an allowlist it cannot meaningfully use. `127.0.0.0/8` and `::1` are
/// loopback; `0.0.0.0` and `::` are not, because binding them is what makes a
/// listener reachable off-host.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        })
        .unwrap_or(false)
}

/// Validates `allow_from` entries as CIDRs, reporting the offending index.
fn check_allow_from(field: &str, allow_from: &[String]) -> Result<(), ConfigError> {
    for (index, entry) in allow_from.iter().enumerate() {
        if entry.parse::<IpNet>().is_err() {
            return Err(ConfigError::InvalidCidr {
                field: format!("{field}.allow_from[{index}]"),
                value: entry.clone(),
            });
        }
    }
    Ok(())
}

/// Validates a listener address, its allowlist, and the USAGE.md section 12
/// non-loopback rule.
///
/// `port_zero_allowed` exists for `[[forwards]].listen` only: USAGE.md section
/// 5.1 documents `127.0.0.1:0` as "let the operating system assign the port",
/// while `[server].listen` and `[client].socks_listen` must name the port they
/// will be reached on.
fn check_listener(
    field: &str,
    value: &str,
    allow_from: &[String],
    port_zero_allowed: bool,
) -> Result<(), ConfigError> {
    let Some((host, port)) = parse_host_port(value) else {
        return Err(ConfigError::InvalidListen {
            field: field.to_string(),
            value: value.to_string(),
        });
    };
    if port == 0 && !port_zero_allowed {
        return Err(ConfigError::ZeroPort {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
    check_allow_from(field, allow_from)?;
    if !is_loopback_host(&host) && allow_from.is_empty() {
        return Err(ConfigError::NonLoopbackWithoutAllowlist {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
    Ok(())
}

/// Validates a name that DESIGN.md section 7.6 requires to be a normalised ASCII
/// slug.
fn check_slug(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::EmptyField {
            field: field.to_string(),
        });
    }
    if !is_slug(value) {
        return Err(ConfigError::NotASlug {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
    Ok(())
}

/// Validates a string that must carry something, such as a key id.
fn check_non_empty(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::EmptyField {
            field: field.to_string(),
        });
    }
    Ok(())
}

/// Validates a credential path. The configuration never carries the secret
/// itself, so an empty path means the entry has no usable credential.
fn check_secret_file(field: &str, path: &Path) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::EmptySecretFile {
            field: field.to_string(),
        });
    }
    Ok(())
}

/// Validates an absolute `http`/`https` URL.
fn check_url(field: &str, value: &str) -> Result<(), ConfigError> {
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    match authority {
        Some(authority)
            if !authority.is_empty()
                && !authority.starts_with('/')
                && !authority.contains(char::is_whitespace) =>
        {
            Ok(())
        }
        _ => Err(ConfigError::InvalidUrl {
            field: field.to_string(),
            value: value.to_string(),
        }),
    }
}

/// Validates one numeric bound, inclusive on both ends.
fn check_range(field: &str, value: u64, min: u64, max: u64) -> Result<(), ConfigError> {
    if !(min..=max).contains(&value) {
        return Err(ConfigError::OutOfRange {
            field: field.to_string(),
            value,
            min,
            max,
        });
    }
    Ok(())
}

/// Validates a window carved out of the session window (DESIGN.md section 7.5).
fn check_window(field: &str, value: u64, session: u64) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::NotPositive {
            field: field.to_string(),
            value,
        });
    }
    if value > session {
        return Err(ConfigError::WindowExceedsSession {
            field: field.to_string(),
            value,
            session,
        });
    }
    Ok(())
}

/// Whether `value` is a legal DNS suffix for the virtual service namespace
/// (USAGE.md section 10).
fn is_valid_dns_suffix(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Validates the shared `[[acl]]` list: slugs first, then the CIDR compile the
/// routing crate would perform (USAGE.md section 11).
fn check_acl(rules: &[AclRule]) -> Result<(), ConfigError> {
    for (index, rule) in rules.iter().enumerate() {
        check_slug(&format!("acl[{index}].caller"), &rule.caller)?;
        if let Some(node) = &rule.node {
            check_slug(&format!("acl[{index}].node"), node)?;
        }
        if let Some(service) = &rule.service {
            check_slug(&format!("acl[{index}].service"), service)?;
        }
        if let Some(cidr) = &rule.host_cidr {
            if cidr.parse::<IpNet>().is_err() {
                return Err(ConfigError::Acl {
                    index,
                    source: AclError::InvalidCidr(cidr.clone()),
                });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// server.toml
// ---------------------------------------------------------------------------

/// The `server.toml` document (DESIGN.md section 10).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// The `[server]` table.
    #[serde(default)]
    pub server: ServerSection,
    /// `[[nodes]]`: the identities and credential files the Hub accepts.
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
    /// `[[acl]]`: default-deny authorisation rules (DESIGN.md section 9.3).
    #[serde(default)]
    pub acl: Vec<AclRule>,
}

impl ServerConfig {
    /// Parses `server.toml` without validating it.
    ///
    /// Useful for tooling that must show what a document *says* even when it
    /// would be refused; anything that will serve traffic should call
    /// [`ServerConfig::from_toml`] instead.
    pub fn parse_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|error| ConfigError::Toml(error.to_string()))
    }

    /// Parses and validates `server.toml` (DESIGN.md section 10).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config = Self::parse_toml(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses, and validates a `server.toml` from disk.
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|error| ConfigError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        Self::from_toml(&text)
    }

    /// Enforces every load-time rule of DESIGN.md section 10 and USAGE.md
    /// section 12.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server.validate()?;

        let mut node_ids: Vec<&str> = Vec::with_capacity(self.nodes.len());
        for (index, node) in self.nodes.iter().enumerate() {
            node.validate(index)?;
            if node_ids.contains(&node.id.as_str()) {
                return Err(ConfigError::Duplicate {
                    field: format!("nodes[{index}].id"),
                    value: node.id.clone(),
                });
            }
            node_ids.push(node.id.as_str());
        }

        // `relay_allow` is a node-id list, so it obeys the same slug rule as any
        // other identity (DESIGN.md section 9.3).
        for (index, node) in self.server.relay_allow.iter().enumerate() {
            check_slug(&format!("server.relay_allow[{index}]"), node)?;
        }

        check_acl(&self.acl)
    }

    /// Compiles `[[acl]]` into the default-deny table of DESIGN.md section 9.3.
    pub fn acl_table(&self) -> Result<AclTable, AclError> {
        AclTable::new(self.acl.clone())
    }

    /// The Hub's relaying capability switch (DESIGN.md section 9.3).
    pub fn relay_allow(&self) -> RelayAllow {
        RelayAllow::new(self.server.relay_allow.clone())
    }
}

/// The `[server]` table (DESIGN.md section 10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Identity this Hub authenticates as.
    #[serde(default = "default_hub_id")]
    pub hub_id: String,
    /// Address the Hub backend listens on.
    #[serde(default = "default_server_listen")]
    pub listen: String,
    /// Source CIDRs permitted to connect.
    ///
    /// Required whenever `listen` is not loopback; see USAGE.md section 12.
    #[serde(default)]
    pub allow_from: Vec<String>,
    /// Node ids permitted to relay for others; empty means nobody may.
    #[serde(default)]
    pub relay_allow: Vec<String>,
    /// Accepted clock skew for `Auth.ts`, in seconds.
    #[serde(default = "default_auth_window")]
    pub auth_window_secs: u64,
    /// Per-node cap on retained authentication nonce records.
    #[serde(default = "default_nonce_max")]
    pub auth_nonce_max_per_node: usize,
    /// Where nonce records are persisted, if they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_nonce_store: Option<PathBuf>,
    /// Site served to unauthenticated or unrecognised requests.
    #[serde(default = "default_decoy_site")]
    pub decoy_site: String,
}

impl Default for ServerSection {
    fn default() -> Self {
        ServerSection {
            hub_id: default_hub_id(),
            listen: default_server_listen(),
            allow_from: Vec::new(),
            relay_allow: Vec::new(),
            auth_window_secs: default_auth_window(),
            auth_nonce_max_per_node: default_nonce_max(),
            auth_nonce_store: None,
            decoy_site: default_decoy_site(),
        }
    }
}

impl ServerSection {
    /// Validates the Hub's own listener, identity, and budgets.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_slug("server.hub_id", &self.hub_id)?;
        check_listener("server.listen", &self.listen, &self.allow_from, false)?;
        // The clock-skew window has its own variant because it is the budget an
        // operator is most likely to move, and the design fixes both ends
        // (DESIGN.md section 5.1).
        if !(AUTH_WINDOW_MIN_SECS..=AUTH_WINDOW_MAX_SECS).contains(&self.auth_window_secs) {
            return Err(ConfigError::AuthWindowOutOfRange {
                value: self.auth_window_secs,
                min: AUTH_WINDOW_MIN_SECS,
                max: AUTH_WINDOW_MAX_SECS,
            });
        }
        check_range(
            "server.auth_nonce_max_per_node",
            self.auth_nonce_max_per_node as u64,
            1,
            AUTH_NONCE_PER_NODE_MAX as u64,
        )?;
        if let Some(store) = &self.auth_nonce_store {
            if store.as_os_str().is_empty() {
                return Err(ConfigError::EmptyField {
                    field: "server.auth_nonce_store".to_string(),
                });
            }
        }
        check_non_empty("server.decoy_site", &self.decoy_site)
    }
}

/// One `[[nodes]]` entry: an accepted identity and where its PSK lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Node identity.
    #[serde(default = "default_node_id")]
    pub id: String,
    /// Key identifier presented during authentication.
    #[serde(default)]
    pub key_id: String,
    /// File holding the pre-shared key. The secret itself is never inline.
    #[serde(default)]
    pub secret_file: PathBuf,
}

impl NodeConfig {
    fn validate(&self, index: usize) -> Result<(), ConfigError> {
        check_slug(&format!("nodes[{index}].id"), &self.id)?;
        check_non_empty(&format!("nodes[{index}].key_id"), &self.key_id)?;
        check_secret_file(&format!("nodes[{index}].secret_file"), &self.secret_file)
    }
}

// ---------------------------------------------------------------------------
// client.toml
// ---------------------------------------------------------------------------

/// The `client.toml` document (DESIGN.md section 10).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// The `[client]` table.
    #[serde(default)]
    pub client: ClientSection,
    /// `[[servers]]`: the Hubs this node may connect to.
    #[serde(default)]
    pub servers: Vec<ServerEntry>,
    /// `[router]`: ordered route selection (DESIGN.md section 7.1).
    #[serde(default)]
    pub router: Router,
    /// `[[services]]`: services this node publishes.
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    /// `[[forwards]]`: local listeners bound to a destination (USAGE.md section
    /// 5).
    #[serde(default)]
    pub forwards: Vec<ForwardConfig>,
    /// `[[acl]]`: default-deny authorisation rules (USAGE.md section 11).
    #[serde(default)]
    pub acl: Vec<AclRule>,
    /// `[socks_service_namespace]`: the optional virtual domain layer.
    #[serde(default)]
    pub socks_service_namespace: SocksNamespace,
    /// `[transport]`: carrier selection and flow budgets.
    #[serde(default)]
    pub transport: TransportSection,
    /// `[decoy]`: background-request bounds (DESIGN.md section 6.4).
    #[serde(default)]
    pub decoy: DecoySection,
}

impl ClientConfig {
    /// Parses `client.toml` without validating it.
    pub fn parse_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|error| ConfigError::Toml(error.to_string()))
    }

    /// Parses and validates `client.toml` (DESIGN.md section 10).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config = Self::parse_toml(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses, and validates a `client.toml` from disk.
    pub fn load_from_path(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|error| ConfigError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        Self::from_toml(&text)
    }

    /// Enforces every load-time rule of DESIGN.md section 10, USAGE.md section
    /// 5, and USAGE.md section 12.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.client.validate()?;

        let mut hub_ids: Vec<&str> = Vec::with_capacity(self.servers.len());
        for (index, entry) in self.servers.iter().enumerate() {
            entry.validate(index)?;
            if hub_ids.contains(&entry.hub_id.as_str()) {
                return Err(ConfigError::DuplicateHubId {
                    value: entry.hub_id.clone(),
                });
            }
            hub_ids.push(entry.hub_id.as_str());
        }

        // Compiling the router now turns a bad match pattern into a load error
        // instead of a per-destination surprise (DESIGN.md section 7.1).
        RouterTable::new(&self.router).map_err(ConfigError::Router)?;
        // A rule picks intermediate hops before any destination is known, so the
        // hop rules run against a placeholder address destination. `Address`
        // names no node, which leaves exactly the self-loop, duplicate, slug, and
        // hop-count checks to apply (USAGE.md section 5.3).
        let placeholder = Destination::address("chain-check.invalid", 1);
        for (index, rule) in self.router.rules.iter().enumerate() {
            validate_chain(&self.client.node_id, &rule.via, &placeholder).map_err(|source| {
                ConfigError::Chain {
                    name: format!("router.rules[{index}].via"),
                    source,
                }
            })?;
        }

        let mut service_names: Vec<&str> = Vec::with_capacity(self.services.len());
        for (index, service) in self.services.iter().enumerate() {
            service.validate(index)?;
            if service.proto == Proto::Udp && !self.client.udp_enabled {
                return Err(ConfigError::UdpDisabled {
                    field: format!("services[{index}]"),
                });
            }
            if service_names.contains(&service.name.as_str()) {
                return Err(ConfigError::Duplicate {
                    field: format!("services[{index}].name"),
                    value: service.name.clone(),
                });
            }
            service_names.push(service.name.as_str());
        }

        let mut forward_names: Vec<&str> = Vec::with_capacity(self.forwards.len());
        let mut forward_listens: Vec<&str> = Vec::with_capacity(self.forwards.len());
        for (index, forward) in self.forwards.iter().enumerate() {
            forward.validate(
                index,
                &self.client.node_id,
                &hub_ids,
                self.client.udp_enabled,
            )?;
            if forward_names.contains(&forward.name.as_str()) {
                return Err(ConfigError::Duplicate {
                    field: format!("forwards[{index}].name"),
                    value: forward.name.clone(),
                });
            }
            forward_names.push(forward.name.as_str());
            // USAGE.md section 12 rejects a duplicate listener. Port 0 is
            // excluded because the operating system owns that choice (USAGE.md
            // section 5.1), so two such forwards do not actually collide.
            let chosen_port = parse_host_port(&forward.listen).map(|(_, port)| port);
            if chosen_port != Some(0) {
                if forward_listens.contains(&forward.listen.as_str()) {
                    return Err(ConfigError::Duplicate {
                        field: format!("forwards[{index}].listen"),
                        value: forward.listen.clone(),
                    });
                }
                forward_listens.push(forward.listen.as_str());
            }
        }

        check_acl(&self.acl)?;
        self.socks_service_namespace.validate()?;
        self.transport.validate()?;
        self.decoy.validate()
    }

    /// Compiles `[[acl]]` into the default-deny table of USAGE.md section 11.
    pub fn acl_table(&self) -> Result<AclTable, AclError> {
        AclTable::new(self.acl.clone())
    }

    /// Compiles `[router]` into a routing table (DESIGN.md section 7.1).
    pub fn router_table(&self) -> Result<RouterTable, RouteError> {
        RouterTable::new(&self.router)
    }
}

/// The `[client]` table (DESIGN.md section 10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSection {
    /// Identity this node authenticates as.
    #[serde(default = "default_node_id")]
    pub node_id: String,
    /// Address the local SOCKS5 listener binds.
    #[serde(default = "default_socks_listen")]
    pub socks_listen: String,
    /// Source CIDRs permitted to use the SOCKS listener.
    ///
    /// Required whenever `socks_listen` is not loopback; see USAGE.md section 12
    /// and DESIGN.md section 9.3.
    #[serde(default)]
    pub allow_from: Vec<String>,
    /// Whether datagram flows are permitted at all.
    ///
    /// Off unless a deployment asks for it, in keeping with the design's
    /// default-deny posture; DESIGN.md section 10's sample sets it explicitly.
    #[serde(default)]
    pub udp_enabled: bool,
    /// Largest payload accepted from SOCKS5, leaving room for headers.
    #[serde(default = "default_udp_max_payload")]
    pub udp_max_payload_bytes: usize,
    /// Remaining TTL for a queued datagram.
    #[serde(default = "default_udp_queue_ttl")]
    pub udp_queue_ttl_ms: u64,
}

impl Default for ClientSection {
    fn default() -> Self {
        ClientSection {
            node_id: default_node_id(),
            socks_listen: default_socks_listen(),
            allow_from: Vec::new(),
            udp_enabled: false,
            udp_max_payload_bytes: default_udp_max_payload(),
            udp_queue_ttl_ms: default_udp_queue_ttl(),
        }
    }
}

impl ClientSection {
    /// Validates the node's identity, local listener, and datagram budgets.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_slug("client.node_id", &self.node_id)?;
        check_listener(
            "client.socks_listen",
            &self.socks_listen,
            &self.allow_from,
            false,
        )?;
        if self.udp_max_payload_bytes == 0 || self.udp_max_payload_bytes > MAX_UDP_PAYLOAD {
            return Err(ConfigError::UdpPayloadOutOfRange {
                field: "client.udp_max_payload_bytes".to_string(),
                value: self.udp_max_payload_bytes,
                max: MAX_UDP_PAYLOAD,
            });
        }
        check_range(
            "client.udp_queue_ttl_ms",
            self.udp_queue_ttl_ms,
            UDP_QUEUE_TTL_MIN_MS,
            UDP_QUEUE_TTL_MAX_MS,
        )
    }
}

/// One `[[servers]]` entry: a Hub this node may connect to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerEntry {
    /// Hub identity, matched against the Hub's own `hub_id`.
    #[serde(default = "default_hub_id")]
    pub hub_id: String,
    /// Absolute `http`/`https` base URL of the Hub.
    #[serde(default)]
    pub url: String,
    /// Key identifier presented during authentication.
    #[serde(default)]
    pub key_id: String,
    /// File holding the pre-shared key for this hub.
    #[serde(default)]
    pub secret_file: PathBuf,
    /// Failover order; lower is tried first (DESIGN.md section 8).
    #[serde(default = "default_priority")]
    pub priority: u32,
}

impl ServerEntry {
    fn validate(&self, index: usize) -> Result<(), ConfigError> {
        check_slug(&format!("servers[{index}].hub_id"), &self.hub_id)?;
        check_url(&format!("servers[{index}].url"), &self.url)?;
        check_non_empty(&format!("servers[{index}].key_id"), &self.key_id)?;
        check_secret_file(&format!("servers[{index}].secret_file"), &self.secret_file)
    }
}

/// One `[[services]]` entry: a local target published to authorised callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Service name callers use; a normalised ASCII slug.
    #[serde(default)]
    pub name: String,
    /// Protocol of the published service.
    #[serde(default = "default_proto")]
    pub proto: Proto,
    /// Fixed local `host:port` the service maps to. Publishing grants no caller
    /// permission by itself (DESIGN.md section 10).
    #[serde(default)]
    pub target: String,
}

impl ServiceConfig {
    fn validate(&self, index: usize) -> Result<(), ConfigError> {
        check_slug(&format!("services[{index}].name"), &self.name)?;
        let field = format!("services[{index}].target");
        let Some((_, port)) = parse_host_port(&self.target) else {
            return Err(ConfigError::InvalidTarget {
                field,
                value: self.target.clone(),
            });
        };
        if port == 0 {
            return Err(ConfigError::ZeroPort {
                field,
                value: self.target.clone(),
            });
        }
        Ok(())
    }
}

/// One `[[forwards]]` entry: a local listener bound to a destination
/// (USAGE.md section 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// Forward name, unique within the document.
    #[serde(default)]
    pub name: String,
    /// Local listener address. Port 0 asks the operating system to choose.
    #[serde(default)]
    pub listen: String,
    /// Protocol of the forwarded flow.
    #[serde(default = "default_proto")]
    pub proto: Proto,
    /// `auto`, or a `hub_id` declared in `[[servers]]`.
    #[serde(default = "default_hub")]
    pub hub: String,
    /// Intermediate nodes; the destination's own node is the final leg and must
    /// not be listed here (USAGE.md section 5.3).
    #[serde(default)]
    pub via: Vec<String>,
    /// Source CIDRs permitted to use this listener; required when it is not
    /// loopback (USAGE.md section 12).
    #[serde(default)]
    pub allow_from: Vec<String>,
    /// What the listener reaches.
    ///
    /// Optional in the type only so an omitted key becomes a typed
    /// [`ConfigError::MissingDestination`] instead of a raw TOML error; a forward
    /// without a destination is not usable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<Destination>,
}

impl ForwardConfig {
    fn validate(
        &self,
        index: usize,
        node_id: &str,
        hub_ids: &[&str],
        udp_enabled: bool,
    ) -> Result<(), ConfigError> {
        let field = format!("forwards[{index}]");
        check_slug(&format!("{field}.name"), &self.name)?;
        // A forward may ask the operating system for its port (USAGE.md section
        // 5.1), unlike the always-known server and SOCKS listeners.
        check_listener(
            &format!("{field}.listen"),
            &self.listen,
            &self.allow_from,
            true,
        )?;
        if self.hub != "auto" && !hub_ids.contains(&self.hub.as_str()) {
            return Err(ConfigError::UnknownHub {
                field: format!("{field}.hub"),
                value: self.hub.clone(),
            });
        }
        let Some(destination) = &self.destination else {
            return Err(ConfigError::MissingDestination {
                field: format!("{field}.destination"),
            });
        };
        destination
            .validate()
            .map_err(|source| ConfigError::Destination {
                name: format!("{field}.destination"),
                source,
            })?;
        if self.proto == Proto::Udp && !udp_enabled {
            return Err(ConfigError::UdpDisabled { field });
        }
        // The calling node is the start of the chain, which is what makes a
        // self-loop and a repeated hop detectable (USAGE.md section 5.3).
        validate_chain(node_id, &self.via, destination).map_err(|source| ConfigError::Chain {
            name: format!("forwards[{index}].via"),
            source,
        })
    }
}

/// The `[socks_service_namespace]` table (USAGE.md section 10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksNamespace {
    /// Whether `svc.<node>.<service>.<suffix>` is interpreted as a service
    /// destination. Off by default; it is a convenience layer, not a permission.
    #[serde(default)]
    pub enabled: bool,
    /// Suffix that marks the namespace.
    #[serde(default = "default_namespace_suffix")]
    pub suffix: String,
}

impl Default for SocksNamespace {
    fn default() -> Self {
        SocksNamespace {
            enabled: false,
            suffix: default_namespace_suffix(),
        }
    }
}

impl SocksNamespace {
    /// Validates the suffix when the namespace is enabled.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !is_valid_dns_suffix(&self.suffix) {
            return Err(ConfigError::InvalidSuffix {
                field: "socks_service_namespace.suffix".to_string(),
                value: self.suffix.clone(),
            });
        }
        Ok(())
    }
}

/// The `[transport]` table (DESIGN.md section 6.4, section 6.7, section 7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportSection {
    /// Whether a fallback carrier may be used when the primary stalls.
    #[serde(default = "default_data_fallback")]
    pub data_fallback: bool,
    /// How many authentication candidates may run concurrently.
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
    /// Grace period for recovering a degraded carrier, in seconds.
    #[serde(default = "default_resume_grace")]
    pub resume_grace_secs: u64,
    /// Per-stream flow-control window, in bytes.
    #[serde(default = "default_flow_window")]
    pub flow_window_bytes: u64,
    /// Session-wide cap on unconsumed business bytes.
    #[serde(default = "default_session_window")]
    pub session_window_bytes: u64,
    /// Bytes a saturated data queue must leave free for control messages.
    #[serde(default = "default_control_reserve")]
    pub control_reserve_bytes: usize,
    /// Carrier profiles this deployment serves. Each enabled profile needs a
    /// matching front-end location (DESIGN.md section 6.4).
    #[serde(default = "default_profiles")]
    pub profiles: Vec<String>,
}

impl Default for TransportSection {
    fn default() -> Self {
        TransportSection {
            data_fallback: default_data_fallback(),
            max_candidates: default_max_candidates(),
            resume_grace_secs: default_resume_grace(),
            flow_window_bytes: default_flow_window(),
            session_window_bytes: default_session_window(),
            control_reserve_bytes: default_control_reserve(),
            profiles: default_profiles(),
        }
    }
}

impl TransportSection {
    /// Validates carrier counts, windows, and profile names.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range(
            "transport.max_candidates",
            self.max_candidates as u64,
            1,
            MAX_AUTH_CANDIDATES as u64,
        )?;
        check_range(
            "transport.resume_grace_secs",
            self.resume_grace_secs,
            1,
            CARRIER_GRACE_SECS,
        )?;
        if self.session_window_bytes == 0 {
            return Err(ConfigError::NotPositive {
                field: "transport.session_window_bytes".to_string(),
                value: 0,
            });
        }
        check_window(
            "transport.flow_window_bytes",
            self.flow_window_bytes,
            self.session_window_bytes,
        )?;
        check_window(
            "transport.control_reserve_bytes",
            self.control_reserve_bytes as u64,
            self.session_window_bytes,
        )?;

        if self.profiles.is_empty() {
            return Err(ConfigError::EmptyProfiles {
                field: "transport.profiles".to_string(),
            });
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.profiles.len());
        for (index, profile) in self.profiles.iter().enumerate() {
            let field = format!("transport.profiles[{index}]");
            if !SUPPORTED_PROFILES.contains(&profile.as_str()) {
                return Err(ConfigError::UnknownProfile {
                    field,
                    value: profile.clone(),
                });
            }
            if seen.contains(&profile.as_str()) {
                return Err(ConfigError::Duplicate {
                    field,
                    value: profile.clone(),
                });
            }
            seen.push(profile.as_str());
        }
        Ok(())
    }
}

/// The `[decoy]` table: bounds on background requests (DESIGN.md section 6.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoySection {
    /// Whether background requests run at all. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Lower bound of the request interval, in seconds.
    #[serde(default = "default_decoy_interval_min")]
    pub interval_min_secs: u64,
    /// Upper bound of the request interval, in seconds.
    #[serde(default = "default_decoy_interval_max")]
    pub interval_max_secs: u64,
    /// Bandwidth budget for background requests, in bytes per second.
    #[serde(default = "default_decoy_budget")]
    pub max_bytes_per_sec: u64,
    /// Origins the background requests may be sent to.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

impl Default for DecoySection {
    fn default() -> Self {
        DecoySection {
            enabled: false,
            interval_min_secs: default_decoy_interval_min(),
            interval_max_secs: default_decoy_interval_max(),
            max_bytes_per_sec: default_decoy_budget(),
            allowed_origins: Vec::new(),
        }
    }
}

impl DecoySection {
    /// Validates the jitter range, the bandwidth budget, and the origins.
    ///
    /// Runs even when the section is disabled: a document that only looks wrong
    /// while switched off is a trap for the operator who later enables it.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range(
            "decoy.interval_min_secs",
            self.interval_min_secs,
            BACKGROUND_JITTER_MIN_SECS,
            BACKGROUND_JITTER_MAX_SECS,
        )?;
        check_range(
            "decoy.interval_max_secs",
            self.interval_max_secs,
            BACKGROUND_JITTER_MIN_SECS,
            BACKGROUND_JITTER_MAX_SECS,
        )?;
        if self.interval_min_secs > self.interval_max_secs {
            return Err(ConfigError::InvertedDecoyInterval {
                min: self.interval_min_secs,
                max: self.interval_max_secs,
            });
        }
        check_range(
            "decoy.max_bytes_per_sec",
            self.max_bytes_per_sec,
            1,
            BACKGROUND_BUDGET_BYTES_PER_SEC as u64,
        )?;
        for (index, origin) in self.allowed_origins.iter().enumerate() {
            check_url(&format!("decoy.allowed_origins[{index}]"), origin)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wsnet_limits::MAX_CHAIN_HOPS;

    /// The exact `server.toml` sample of DESIGN.md section 10.
    const DESIGN_SERVER: &str = r#"
[server]
hub_id = "hub-a"
listen = "127.0.0.1:8443"
relay_allow = []
auth_window_secs = 120
auth_nonce_max_per_node = 65536
auth_nonce_store = "state/auth-nonces.sqlite"
decoy_site = "builtin"

[[nodes]]
id = "client-a"
key_id = "a-1"
secret_file = "secrets/client-a.key"
"#;

    /// The exact `client.toml` sample of DESIGN.md section 10.
    const DESIGN_CLIENT: &str = r#"
[client]
node_id = "client-a"
socks_listen = "127.0.0.1:1080"
udp_enabled = true
udp_max_payload_bytes = 61440
udp_queue_ttl_ms = 1000

[[servers]]
hub_id = "hub-a"
url = "https://a.example.com"
key_id = "a-1"
secret_file = "secrets/client-a-hub-a.key"
priority = 1

[[servers]]
hub_id = "hub-b"
url = "https://b.example.com"
key_id = "a-2"
secret_file = "secrets/client-a-hub-b.key"
priority = 2

[router]
final = "server" # direct/server；节点链用显式数组

[[router.rules]]
match = ["domain:*.internal.example"]
via = ["client-b", "client-c"]

[[services]]
name = "web"
proto = "tcp"
target = "127.0.0.1:8080" # 发布并不自动授权调用者

[[forwards]]
name = "a-web"
listen = "127.0.0.1:18080"
proto = "tcp"
hub = "auto"
via = []
destination = { type = "service", node = "client-a", name = "web" }

[socks_service_namespace]
enabled = false
suffix = "wsnet.invalid"

[transport]
data_fallback = true
max_candidates = 2
resume_grace_secs = 10
flow_window_bytes = 262144
session_window_bytes = 8388608
control_reserve_bytes = 65536
profiles = ["binary", "json", "html", "js", "css"]

[decoy]
enabled = false
interval_min_secs = 2
interval_max_secs = 15
max_bytes_per_sec = 4096
allowed_origins = ["https://a.example.com", "https://b.example.com"]
"#;

    /// Builds a client document with one forward, parameterised by `via` and
    /// `destination`, so the chain rules can be exercised in isolation.
    fn forward_doc(listen: &str, via: &str, destination: &str) -> String {
        format!(
            "[client]\nnode_id = \"caller\"\n\n[[forwards]]\nname = \"a-web\"\nlisten = \"{listen}\"\nproto = \"tcp\"\nhub = \"auto\"\nvia = [{via}]\ndestination = {destination}\n"
        )
    }

    fn server_err(text: &str) -> ConfigError {
        ServerConfig::from_toml(text).expect_err("document should be rejected")
    }

    fn client_err(text: &str) -> ConfigError {
        ClientConfig::from_toml(text).expect_err("document should be rejected")
    }

    // ------------------------------------------------------------ samples

    #[test]
    fn design_server_sample_parses() {
        let config = ServerConfig::from_toml(DESIGN_SERVER).expect("design sample must load");
        assert_eq!(config.server.hub_id, "hub-a");
        assert_eq!(config.server.listen, "127.0.0.1:8443");
        assert!(config.server.relay_allow.is_empty());
        assert_eq!(config.server.auth_window_secs, 120);
        assert_eq!(config.server.auth_nonce_max_per_node, 65_536);
        assert_eq!(
            config.server.auth_nonce_store.as_deref(),
            Some(Path::new("state/auth-nonces.sqlite"))
        );
        assert_eq!(config.server.decoy_site, "builtin");
        assert_eq!(config.nodes.len(), 1);
        assert_eq!(config.nodes[0].id, "client-a");
        assert_eq!(config.nodes[0].key_id, "a-1");
        assert_eq!(
            config.nodes[0].secret_file,
            PathBuf::from("secrets/client-a.key")
        );
        assert!(!config.relay_allow().is_enabled());
        assert!(config.acl_table().unwrap().is_empty());
    }

    #[test]
    fn design_client_sample_parses() {
        let config = ClientConfig::from_toml(DESIGN_CLIENT).expect("design sample must load");
        assert_eq!(config.client.node_id, "client-a");
        assert_eq!(config.client.socks_listen, "127.0.0.1:1080");
        assert!(config.client.udp_enabled);
        assert_eq!(config.client.udp_max_payload_bytes, 61_440);
        assert_eq!(config.client.udp_queue_ttl_ms, 1_000);

        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.servers[0].hub_id, "hub-a");
        assert_eq!(config.servers[0].url, "https://a.example.com");
        assert_eq!(config.servers[0].priority, 1);
        assert_eq!(config.servers[1].priority, 2);

        assert_eq!(config.router.rules.len(), 1);
        assert_eq!(
            config.router.rules[0].matchers,
            ["domain:*.internal.example"]
        );
        assert_eq!(config.router.rules[0].via, ["client-b", "client-c"]);
        assert!(config.router_table().is_ok());

        assert_eq!(config.services.len(), 1);
        assert_eq!(config.services[0].proto, Proto::Tcp);
        assert_eq!(config.services[0].target, "127.0.0.1:8080");

        assert_eq!(config.forwards.len(), 1);
        assert_eq!(config.forwards[0].hub, "auto");
        assert_eq!(
            config.forwards[0].destination,
            Some(Destination::service("client-a", "web"))
        );

        assert!(!config.socks_service_namespace.enabled);
        assert_eq!(config.socks_service_namespace.suffix, "wsnet.invalid");
        assert_eq!(config.transport.profiles.len(), 5);
        assert_eq!(config.transport.flow_window_bytes, 262_144);
        assert_eq!(config.transport.session_window_bytes, 8_388_608);
        assert_eq!(config.transport.control_reserve_bytes, 65_536);
        assert!(!config.decoy.enabled);
        assert_eq!(config.decoy.allowed_origins.len(), 2);
    }

    /// The `[[forwards]]` samples of USAGE.md section 5.
    #[test]
    fn usage_forward_samples_parse() {
        // The caller is `client-x`: the section 5.3 chain relays *through*
        // `client-b`, so a document that called itself `client-b` would be a
        // self-loop and is correct to reject.
        let text = r#"
[client]
node_id = "client-x"
socks_listen = "127.0.0.1:1080"

[[servers]]
hub_id = "hub-a"
url = "https://a.example.com"
key_id = "x-1"
secret_file = "secrets/client-x-hub-a.key"

[[forwards]]
name = "a-web"
listen = "127.0.0.1:18080"
proto = "tcp"
hub = "auto"
via = []
destination = { type = "service", node = "client-a", name = "web" }

[[forwards]]
name = "a-ssh"
listen = "127.0.0.1:10022"
proto = "tcp"
hub = "hub-a"
destination = { type = "node_address", node = "client-a", host = "127.0.0.1", port = 22 }

[[forwards]]
name = "a-web-via-b-c"
listen = "127.0.0.1:18081"
proto = "tcp"
hub = "hub-a"
via = ["client-b", "client-c"]
destination = { type = "service", node = "client-a", name = "web" }
"#;
        let config = ClientConfig::from_toml(text).expect("USAGE forwards must load");
        assert_eq!(config.forwards.len(), 3);
        assert_eq!(
            config.forwards[1].destination,
            Some(Destination::NodeAddress {
                node: "client-a".into(),
                host: "127.0.0.1".into(),
                port: 22,
            })
        );
        assert_eq!(config.forwards[2].via, ["client-b", "client-c"]);
    }

    /// The `[[acl]]` samples of USAGE.md section 11.
    #[test]
    fn usage_acl_sample_parses() {
        let text = r#"
[client]
node_id = "client-b"

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
"#;
        let config = ClientConfig::from_toml(text).expect("USAGE acl sample must load");
        assert_eq!(config.acl.len(), 2);
        assert_eq!(config.acl_table().unwrap().len(), 2);

        let server_text = r#"
[server]
hub_id = "hub-a"

[[acl]]
caller = "client-b"
action = "relay"
allow = true
"#;
        assert!(ServerConfig::from_toml(server_text).is_ok());
    }

    // ------------------------------------------------------------ defaults

    #[test]
    fn minimal_documents_use_defaults() {
        let server = ServerConfig::from_toml("").expect("an empty document must parse");
        assert_eq!(server.server, ServerSection::default());
        assert_eq!(server.server.hub_id, "hub");
        assert_eq!(server.server.listen, "127.0.0.1:8443");
        assert_eq!(server.server.auth_window_secs, AUTH_WINDOW_DEFAULT_SECS);
        assert_eq!(
            server.server.auth_nonce_max_per_node,
            AUTH_NONCE_PER_NODE_MAX
        );
        assert!(server.server.auth_nonce_store.is_none());
        assert!(server.nodes.is_empty());
        assert!(server.acl.is_empty());

        let client = ClientConfig::from_toml("").expect("an empty document must parse");
        assert_eq!(client.client, ClientSection::default());
        assert_eq!(client.transport, TransportSection::default());
        assert_eq!(client.decoy, DecoySection::default());
        assert_eq!(client.socks_service_namespace, SocksNamespace::default());
        assert_eq!(client.router, Router::default());
        assert!(!client.client.udp_enabled);
        assert_eq!(client.client.udp_max_payload_bytes, UDP_MAX_PAYLOAD_DEFAULT);
        assert_eq!(client.client.udp_queue_ttl_ms, UDP_QUEUE_TTL_DEFAULT_MS);
        assert_eq!(client.transport.profiles, ["binary"]);
        assert_eq!(client.transport.max_candidates, MAX_AUTH_CANDIDATES);
        assert_eq!(client.transport.flow_window_bytes, FLOW_WINDOW_BYTES);
        assert_eq!(client.transport.session_window_bytes, SESSION_WINDOW_BYTES);
        assert_eq!(client.transport.control_reserve_bytes, CONTROL_QUEUE_BYTES);
        assert_eq!(client.decoy.interval_min_secs, BACKGROUND_JITTER_MIN_SECS);
        assert_eq!(client.decoy.interval_max_secs, BACKGROUND_JITTER_MAX_SECS);
        assert_eq!(
            client.decoy.max_bytes_per_sec,
            BACKGROUND_BUDGET_BYTES_PER_SEC as u64
        );
        assert!(client.decoy.allowed_origins.is_empty());

        // The per-field serde defaults and the manual `Default` impls must agree,
        // otherwise a whole omitted table would differ from an empty one.
        let section: ServerSection = toml::from_str("").unwrap();
        assert_eq!(section, ServerSection::default());
        let section: ClientSection = toml::from_str("").unwrap();
        assert_eq!(section, ClientSection::default());
        let section: TransportSection = toml::from_str("").unwrap();
        assert_eq!(section, TransportSection::default());
        let section: DecoySection = toml::from_str("").unwrap();
        assert_eq!(section, DecoySection::default());
    }

    // ------------------------------------------------------------ auth window

    #[test]
    fn auth_window_bounds_are_enforced() {
        let doc = |secs: u64| format!("[server]\nhub_id = \"hub-a\"\nauth_window_secs = {secs}\n");
        assert_eq!(
            server_err(&doc(AUTH_WINDOW_MIN_SECS - 1)),
            ConfigError::AuthWindowOutOfRange {
                value: AUTH_WINDOW_MIN_SECS - 1,
                min: AUTH_WINDOW_MIN_SECS,
                max: AUTH_WINDOW_MAX_SECS,
            }
        );
        assert_eq!(
            server_err(&doc(AUTH_WINDOW_MAX_SECS + 1)),
            ConfigError::AuthWindowOutOfRange {
                value: AUTH_WINDOW_MAX_SECS + 1,
                min: AUTH_WINDOW_MIN_SECS,
                max: AUTH_WINDOW_MAX_SECS,
            }
        );
        assert!(ServerConfig::from_toml(&doc(AUTH_WINDOW_MIN_SECS)).is_ok());
        assert!(ServerConfig::from_toml(&doc(AUTH_WINDOW_MAX_SECS)).is_ok());
        // A value that parses but is unusable must be caught by validation.
        assert!(ServerConfig::parse_toml(&doc(1)).is_ok());
    }

    #[test]
    fn nonce_cap_must_fit_the_design_bound() {
        let doc =
            |cap: u64| format!("[server]\nhub_id = \"hub-a\"\nauth_nonce_max_per_node = {cap}\n");
        assert_eq!(
            server_err(&doc(0)),
            ConfigError::OutOfRange {
                field: "server.auth_nonce_max_per_node".into(),
                value: 0,
                min: 1,
                max: AUTH_NONCE_PER_NODE_MAX as u64,
            }
        );
        assert_eq!(
            server_err(&doc(AUTH_NONCE_PER_NODE_MAX as u64 + 1)),
            ConfigError::OutOfRange {
                field: "server.auth_nonce_max_per_node".into(),
                value: AUTH_NONCE_PER_NODE_MAX as u64 + 1,
                min: 1,
                max: AUTH_NONCE_PER_NODE_MAX as u64,
            }
        );
        assert!(ServerConfig::from_toml(&doc(AUTH_NONCE_PER_NODE_MAX as u64)).is_ok());
    }

    // ------------------------------------------------------------ listeners

    #[test]
    fn listeners_must_be_host_port_with_a_fixed_port() {
        for bad in [
            "127.0.0.1",
            "127.0.0.1:not-a-port",
            ":8443",
            "127.0.0.1:",
            "a b:1",
        ] {
            let doc = format!("[server]\nhub_id = \"hub-a\"\nlisten = \"{bad}\"\n");
            assert!(
                matches!(server_err(&doc), ConfigError::InvalidListen { .. }),
                "`{bad}` should not parse as a listener"
            );
        }

        let zero = "[server]\nhub_id = \"hub-a\"\nlisten = \"127.0.0.1:0\"\n";
        assert_eq!(
            server_err(zero),
            ConfigError::ZeroPort {
                field: "server.listen".into(),
                value: "127.0.0.1:0".into(),
            }
        );

        let socks = "[client]\nnode_id = \"client-a\"\nsocks_listen = \"127.0.0.1:0\"\n";
        assert_eq!(
            client_err(socks),
            ConfigError::ZeroPort {
                field: "client.socks_listen".into(),
                value: "127.0.0.1:0".into(),
            }
        );

        let socks = "[client]\nnode_id = \"client-a\"\nsocks_listen = \"::1:1080\"\n";
        assert!(matches!(
            client_err(socks),
            ConfigError::InvalidListen { .. }
        ));
    }

    /// USAGE.md section 5.1 allows `127.0.0.1:0` so the operating system picks
    /// the port; two such forwards do not collide.
    #[test]
    fn a_forward_listener_may_ask_the_os_for_its_port() {
        let doc = r#"
[client]
node_id = "client-a"

[[forwards]]
name = "one"
listen = "127.0.0.1:0"
destination = { type = "service", node = "client-a", name = "web" }

[[forwards]]
name = "two"
listen = "127.0.0.1:0"
destination = { type = "service", node = "client-a", name = "web" }
"#;
        let config = ClientConfig::from_toml(doc).expect("port 0 is a legal forward listener");
        assert_eq!(config.forwards.len(), 2);
    }

    #[test]
    fn loopback_forms_are_recognised() {
        for good in [
            "127.0.0.1:1080",
            "127.0.0.2:1080",
            "localhost:1080",
            "[::1]:1080",
        ] {
            let doc = format!("[client]\nnode_id = \"client-a\"\nsocks_listen = \"{good}\"\n");
            assert!(
                ClientConfig::from_toml(&doc).is_ok(),
                "{good} should count as loopback"
            );
        }
        for bad in [
            "0.0.0.0:1080",
            "[::]:1080",
            "10.0.0.1:1080",
            "example.com:1080",
        ] {
            let doc = format!("[client]\nnode_id = \"client-a\"\nsocks_listen = \"{bad}\"\n");
            assert_eq!(
                client_err(&doc),
                ConfigError::NonLoopbackWithoutAllowlist {
                    field: "client.socks_listen".into(),
                    value: bad.into(),
                },
                "{bad} should need an allowlist"
            );
        }
    }

    #[test]
    fn non_loopback_listeners_need_an_allowlist() {
        let server = "[server]\nhub_id = \"hub-a\"\nlisten = \"0.0.0.0:8443\"\n";
        assert_eq!(
            server_err(server),
            ConfigError::NonLoopbackWithoutAllowlist {
                field: "server.listen".into(),
                value: "0.0.0.0:8443".into(),
            }
        );
        let with_allowlist = format!("{server}allow_from = [\"10.0.0.0/8\", \"fd00::/8\"]\n");
        let config =
            ServerConfig::from_toml(&with_allowlist).expect("allowlisted listener is fine");
        assert_eq!(config.server.allow_from.len(), 2);

        let socks = "[client]\nnode_id = \"client-a\"\nsocks_listen = \"0.0.0.0:1080\"\n";
        assert_eq!(
            client_err(socks),
            ConfigError::NonLoopbackWithoutAllowlist {
                field: "client.socks_listen".into(),
                value: "0.0.0.0:1080".into(),
            }
        );
        let socks_ok = format!("{socks}allow_from = [\"192.168.0.0/16\"]\n");
        assert!(ClientConfig::from_toml(&socks_ok).is_ok());

        let forward = forward_doc(
            "0.0.0.0:18080",
            "",
            "{ type = \"service\", node = \"client-a\", name = \"web\" }",
        );
        assert_eq!(
            client_err(&forward),
            ConfigError::NonLoopbackWithoutAllowlist {
                field: "forwards[0].listen".into(),
                value: "0.0.0.0:18080".into(),
            }
        );
        let forward_ok = format!("{forward}allow_from = [\"10.1.0.0/16\"]\n");
        assert!(ClientConfig::from_toml(&forward_ok).is_ok());
    }

    #[test]
    fn allow_from_entries_must_be_cidrs() {
        let doc =
            "[server]\nhub_id = \"hub-a\"\nlisten = \"0.0.0.0:8443\"\nallow_from = [\"nonsense\"]\n";
        assert_eq!(
            server_err(doc),
            ConfigError::InvalidCidr {
                field: "server.listen.allow_from[0]".into(),
                value: "nonsense".into(),
            }
        );
        // A bad CIDR is reported even when the listener itself is loopback.
        let doc = "[server]\nhub_id = \"hub-a\"\nallow_from = [\"10.0.0.0/33\"]\n";
        assert!(matches!(server_err(doc), ConfigError::InvalidCidr { .. }));
    }

    // ------------------------------------------------------------ slugs

    #[test]
    fn slug_validity_is_enforced() {
        let node = "[server]\nhub_id = \"hub-a\"\n\n[[nodes]]\nid = \"client/a\"\nkey_id = \"a-1\"\nsecret_file = \"s\"\n";
        assert_eq!(
            server_err(node),
            ConfigError::NotASlug {
                field: "nodes[0].id".into(),
                value: "client/a".into(),
            }
        );

        let hub = "[server]\nhub_id = \"hub a\"\n";
        assert_eq!(
            server_err(hub),
            ConfigError::NotASlug {
                field: "server.hub_id".into(),
                value: "hub a".into(),
            }
        );

        let empty_hub = "[server]\nhub_id = \"\"\n";
        assert_eq!(
            server_err(empty_hub),
            ConfigError::EmptyField {
                field: "server.hub_id".into(),
            }
        );

        let service = "[client]\nnode_id = \"client-a\"\n\n[[services]]\nname = \"a b\"\nproto = \"tcp\"\ntarget = \"127.0.0.1:80\"\n";
        assert_eq!(
            client_err(service),
            ConfigError::NotASlug {
                field: "services[0].name".into(),
                value: "a b".into(),
            }
        );

        let forward = forward_doc(
            "127.0.0.1:18080",
            "",
            "{ type = \"service\", node = \"client-a\", name = \"web\" }",
        )
        .replace("name = \"a-web\"", "name = \"-bad\"");
        assert_eq!(
            client_err(&forward),
            ConfigError::NotASlug {
                field: "forwards[0].name".into(),
                value: "-bad".into(),
            }
        );

        let relay = "[server]\nhub_id = \"hub-a\"\nrelay_allow = [\"client a\"]\n";
        assert_eq!(
            server_err(relay),
            ConfigError::NotASlug {
                field: "server.relay_allow[0]".into(),
                value: "client a".into(),
            }
        );

        // A slug longer than the routing crate's bound is rejected too.
        let long = "a".repeat(wsnet_routing::MAX_SLUG_LEN + 1);
        let node = format!(
            "[server]\nhub_id = \"hub-a\"\n\n[[nodes]]\nid = \"{long}\"\nkey_id = \"a-1\"\nsecret_file = \"s\"\n"
        );
        assert!(matches!(server_err(&node), ConfigError::NotASlug { .. }));
    }

    #[test]
    fn service_targets_must_be_usable() {
        let service = |target: &str| {
            format!("[client]\nnode_id = \"client-a\"\n\n[[services]]\nname = \"web\"\nproto = \"tcp\"\ntarget = \"{target}\"\n")
        };
        assert!(matches!(
            client_err(&service("127.0.0.1")),
            ConfigError::InvalidTarget { .. }
        ));
        assert!(matches!(
            client_err(&service("tcp://127.0.0.1:80")),
            ConfigError::InvalidTarget { .. }
        ));
        assert_eq!(
            client_err(&service("127.0.0.1:0")),
            ConfigError::ZeroPort {
                field: "services[0].target".into(),
                value: "127.0.0.1:0".into(),
            }
        );
        assert!(ClientConfig::from_toml(&service("127.0.0.1:8080")).is_ok());
        assert!(ClientConfig::from_toml(&service("example.internal:443")).is_ok());
    }

    // ------------------------------------------------------------ duplicates

    #[test]
    fn duplicate_names_and_listeners_are_rejected() {
        let services = r#"
[client]
node_id = "client-a"

[[services]]
name = "web"
proto = "tcp"
target = "127.0.0.1:8080"

[[services]]
name = "web"
proto = "tcp"
target = "127.0.0.1:8081"
"#;
        assert_eq!(
            client_err(services),
            ConfigError::Duplicate {
                field: "services[1].name".into(),
                value: "web".into(),
            }
        );

        let forwards = r#"
[client]
node_id = "client-a"

[[forwards]]
name = "a-web"
listen = "127.0.0.1:18080"
destination = { type = "service", node = "client-a", name = "web" }

[[forwards]]
name = "web"
listen = "127.0.0.1:18080"
destination = { type = "service", node = "client-a", name = "web" }
"#;
        assert_eq!(
            client_err(forwards),
            ConfigError::Duplicate {
                field: "forwards[1].listen".into(),
                value: "127.0.0.1:18080".into(),
            }
        );

        let same_name = forwards.replace("name = \"web\"", "name = \"a-web\"");
        assert_eq!(
            client_err(&same_name),
            ConfigError::Duplicate {
                field: "forwards[1].name".into(),
                value: "a-web".into(),
            }
        );

        let servers = r#"
[client]
node_id = "client-a"

[[servers]]
hub_id = "hub-a"
url = "https://a.example.com"
key_id = "a-1"
secret_file = "s1"

[[servers]]
hub_id = "hub-a"
url = "https://b.example.com"
key_id = "a-2"
secret_file = "s2"
"#;
        assert_eq!(
            client_err(servers),
            ConfigError::DuplicateHubId {
                value: "hub-a".into(),
            }
        );

        let nodes = r#"
[server]
hub_id = "hub-a"

[[nodes]]
id = "client-a"
key_id = "a-1"
secret_file = "s1"

[[nodes]]
id = "client-a"
key_id = "a-2"
secret_file = "s2"
"#;
        assert_eq!(
            server_err(nodes),
            ConfigError::Duplicate {
                field: "nodes[1].id".into(),
                value: "client-a".into(),
            }
        );
    }

    // ------------------------------------------------------------ chains

    #[test]
    fn forward_chains_are_validated() {
        let service = "{ type = \"service\", node = \"client-a\", name = \"web\" }";

        let loop_back = forward_doc("127.0.0.1:18080", "\"caller\"", service);
        assert_eq!(
            client_err(&loop_back),
            ConfigError::Chain {
                name: "forwards[0].via".into(),
                source: RouteError::SelfLoop("caller".into()),
            }
        );

        let repeated = forward_doc("127.0.0.1:18080", "\"client-b\", \"client-b\"", service);
        assert_eq!(
            client_err(&repeated),
            ConfigError::Chain {
                name: "forwards[0].via".into(),
                source: RouteError::DuplicateHop("client-b".into()),
            }
        );

        let too_long = forward_doc(
            "127.0.0.1:18080",
            "\"b1\", \"b2\", \"b3\", \"b4\", \"b5\"",
            service,
        );
        assert_eq!(
            client_err(&too_long),
            ConfigError::Chain {
                name: "forwards[0].via".into(),
                source: RouteError::TooManyHops {
                    actual: 5,
                    limit: MAX_CHAIN_HOPS,
                },
            }
        );

        let bad_slug = forward_doc("127.0.0.1:18080", "\"bad hop\"", service);
        assert_eq!(
            client_err(&bad_slug),
            ConfigError::Chain {
                name: "forwards[0].via".into(),
                source: RouteError::NotASlug("bad hop".into()),
            }
        );

        // USAGE.md section 5.3: the publisher is the final leg, not a hop.
        let publisher_as_hop = forward_doc("127.0.0.1:18080", "\"client-a\"", service);
        assert_eq!(
            client_err(&publisher_as_hop),
            ConfigError::Chain {
                name: "forwards[0].via".into(),
                source: RouteError::DestinationInPath("client-a".into()),
            }
        );

        let good = forward_doc("127.0.0.1:18080", "\"client-b\", \"client-c\"", service);
        assert!(ClientConfig::from_toml(&good).is_ok());
    }

    #[test]
    fn router_rule_chains_are_validated() {
        let doc = r#"
[client]
node_id = "caller"

[router]
final = "server"

[[router.rules]]
match = ["domain:*.internal.example"]
via = ["caller"]
"#;
        assert_eq!(
            client_err(doc),
            ConfigError::Chain {
                name: "router.rules[0].via".into(),
                source: RouteError::SelfLoop("caller".into()),
            }
        );

        let bad_pattern = r#"
[client]
node_id = "caller"

[router]
final = "server"

[[router.rules]]
match = ["nocolon"]
via = []
"#;
        assert_eq!(
            client_err(bad_pattern),
            ConfigError::Router(RouteError::InvalidPattern("nocolon".into()))
        );
    }

    #[test]
    fn destinations_are_validated() {
        let bad_node = forward_doc(
            "127.0.0.1:18080",
            "",
            "{ type = \"service\", node = \"client/a\", name = \"web\" }",
        );
        assert_eq!(
            client_err(&bad_node),
            ConfigError::Destination {
                name: "forwards[0].destination".into(),
                source: DestinationError::NotASlug("client/a".into()),
            }
        );

        let zero_port = forward_doc(
            "127.0.0.1:18080",
            "",
            "{ type = \"address\", host = \"127.0.0.1\", port = 0 }",
        );
        assert_eq!(
            client_err(&zero_port),
            ConfigError::Destination {
                name: "forwards[0].destination".into(),
                source: DestinationError::ZeroPort,
            }
        );

        let empty_host = forward_doc(
            "127.0.0.1:18080",
            "",
            "{ type = \"address\", host = \"\", port = 80 }",
        );
        assert_eq!(
            client_err(&empty_host),
            ConfigError::Destination {
                name: "forwards[0].destination".into(),
                source: DestinationError::EmptyHost,
            }
        );

        let missing = r#"
[client]
node_id = "client-a"

[[forwards]]
name = "a-web"
listen = "127.0.0.1:18080"
"#;
        assert_eq!(
            client_err(missing),
            ConfigError::MissingDestination {
                field: "forwards[0].destination".into(),
            }
        );
    }

    #[test]
    fn forward_hubs_must_be_declared() {
        let undeclared = forward_doc(
            "127.0.0.1:18080",
            "",
            "{ type = \"service\", node = \"client-a\", name = \"web\" }",
        )
        .replace("hub = \"auto\"", "hub = \"hub-z\"");
        assert_eq!(
            client_err(&undeclared),
            ConfigError::UnknownHub {
                field: "forwards[0].hub".into(),
                value: "hub-z".into(),
            }
        );

        let declared = "[client]\nnode_id = \"caller\"\n\n[[servers]]\nhub_id = \"hub-z\"\nurl = \"https://z.example.com\"\nkey_id = \"k\"\nsecret_file = \"s\"\n\n[[forwards]]\nname = \"a-web\"\nlisten = \"127.0.0.1:18080\"\nhub = \"hub-z\"\ndestination = { type = \"service\", node = \"client-a\", name = \"web\" }\n";
        assert!(ClientConfig::from_toml(declared).is_ok());
    }

    // ------------------------------------------------------------ credentials

    #[test]
    fn secret_files_must_be_named() {
        let node = "[server]\nhub_id = \"hub-a\"\n\n[[nodes]]\nid = \"client-a\"\nkey_id = \"a-1\"\nsecret_file = \"\"\n";
        assert_eq!(
            server_err(node),
            ConfigError::EmptySecretFile {
                field: "nodes[0].secret_file".into(),
            }
        );

        let node =
            "[server]\nhub_id = \"hub-a\"\n\n[[nodes]]\nid = \"client-a\"\nsecret_file = \"s\"\n";
        assert_eq!(
            server_err(node),
            ConfigError::EmptyField {
                field: "nodes[0].key_id".into(),
            }
        );

        let server = "[client]\nnode_id = \"client-a\"\n\n[[servers]]\nhub_id = \"hub-a\"\nurl = \"https://a.example.com\"\nkey_id = \"a-1\"\n";
        assert_eq!(
            client_err(server),
            ConfigError::EmptySecretFile {
                field: "servers[0].secret_file".into(),
            }
        );
    }

    /// DESIGN.md section 9.3 keeps PSKs in permission-controlled files; an inline
    /// key must not be silently dropped.
    #[test]
    fn inline_secrets_are_rejected() {
        let node = "[server]\nhub_id = \"hub-a\"\n\n[[nodes]]\nid = \"client-a\"\nkey_id = \"a-1\"\nsecret_file = \"s\"\nsecret = \"inline\"\n";
        let error = server_err(node);
        assert!(matches!(error, ConfigError::Toml(_)), "{error:?}");
        assert!(error.to_string().contains("secret"), "{error}");

        let server = "[client]\n\n[[servers]]\nhub_id = \"hub-a\"\nurl = \"https://a.example.com\"\nkey_id = \"a-1\"\nsecret_file = \"s\"\nsecret = \"inline\"\n";
        assert!(matches!(client_err(server), ConfigError::Toml(_)));

        // Typos elsewhere are rejected just as loudly.
        let typo = "[server]\nlisten_addr = \"127.0.0.1:8443\"\n";
        assert!(matches!(server_err(typo), ConfigError::Toml(_)));
    }

    #[test]
    fn server_urls_must_be_absolute_http() {
        let doc = |url: &str| {
            format!("[client]\nnode_id = \"client-a\"\n\n[[servers]]\nhub_id = \"hub-a\"\nurl = \"{url}\"\nkey_id = \"a-1\"\nsecret_file = \"s\"\n")
        };
        for bad in ["", "a.example.com", "ftp://a.example.com", "https://"] {
            assert!(
                matches!(client_err(&doc(bad)), ConfigError::InvalidUrl { .. }),
                "`{bad}` should not be a Hub URL"
            );
        }
        assert!(ClientConfig::from_toml(&doc("https://a.example.com")).is_ok());
        assert!(ClientConfig::from_toml(&doc("http://127.0.0.1:8443/base")).is_ok());
    }

    // ------------------------------------------------------------ udp

    #[test]
    fn udp_bounds_and_opt_in_are_enforced() {
        let payload = format!(
            "[client]\nnode_id = \"client-a\"\nudp_enabled = true\nudp_max_payload_bytes = {}\n",
            MAX_UDP_PAYLOAD + 1
        );
        assert_eq!(
            client_err(&payload),
            ConfigError::UdpPayloadOutOfRange {
                field: "client.udp_max_payload_bytes".into(),
                value: MAX_UDP_PAYLOAD + 1,
                max: MAX_UDP_PAYLOAD,
            }
        );
        let zero_payload = "[client]\nnode_id = \"client-a\"\nudp_max_payload_bytes = 0\n";
        assert!(matches!(
            client_err(zero_payload),
            ConfigError::UdpPayloadOutOfRange { value: 0, .. }
        ));

        let short_ttl = "[client]\nnode_id = \"client-a\"\nudp_queue_ttl_ms = 99\n";
        assert_eq!(
            client_err(short_ttl),
            ConfigError::OutOfRange {
                field: "client.udp_queue_ttl_ms".into(),
                value: 99,
                min: UDP_QUEUE_TTL_MIN_MS,
                max: UDP_QUEUE_TTL_MAX_MS,
            }
        );
        let long_ttl = format!(
            "[client]\nnode_id = \"client-a\"\nudp_queue_ttl_ms = {}\n",
            UDP_QUEUE_TTL_MAX_MS + 1
        );
        assert!(matches!(
            client_err(&long_ttl),
            ConfigError::OutOfRange { .. }
        ));

        let udp_service = "[client]\nnode_id = \"client-a\"\n\n[[services]]\nname = \"dns\"\nproto = \"udp\"\ntarget = \"127.0.0.1:53\"\n";
        assert_eq!(
            client_err(udp_service),
            ConfigError::UdpDisabled {
                field: "services[0]".into(),
            }
        );

        let udp_forward = "[client]\nnode_id = \"caller\"\n\n[[forwards]]\nname = \"a-dns\"\nlisten = \"127.0.0.1:15353\"\nproto = \"udp\"\nhub = \"auto\"\ndestination = { type = \"service\", node = \"client-a\", name = \"dns\" }\n";
        assert_eq!(
            client_err(udp_forward),
            ConfigError::UdpDisabled {
                field: "forwards[0]".into(),
            }
        );
        let enabled = "[client]\nnode_id = \"caller\"\nudp_enabled = true\n\n[[forwards]]\nname = \"a-dns\"\nlisten = \"127.0.0.1:15353\"\nproto = \"udp\"\nhub = \"auto\"\ndestination = { type = \"service\", node = \"client-a\", name = \"dns\" }\n";
        assert!(ClientConfig::from_toml(enabled).is_ok());
    }

    // ------------------------------------------------------------ transport

    #[test]
    fn transport_bounds_are_enforced() {
        let candidates = |value: usize| {
            format!("[client]\nnode_id = \"client-a\"\n\n[transport]\nmax_candidates = {value}\n")
        };
        for bad in [0usize, MAX_AUTH_CANDIDATES + 1] {
            assert_eq!(
                client_err(&candidates(bad)),
                ConfigError::OutOfRange {
                    field: "transport.max_candidates".into(),
                    value: bad as u64,
                    min: 1,
                    max: MAX_AUTH_CANDIDATES as u64,
                }
            );
        }

        let grace = format!(
            "[client]\nnode_id = \"client-a\"\n\n[transport]\nresume_grace_secs = {}\n",
            CARRIER_GRACE_SECS + 1
        );
        assert_eq!(
            client_err(&grace),
            ConfigError::OutOfRange {
                field: "transport.resume_grace_secs".into(),
                value: CARRIER_GRACE_SECS + 1,
                min: 1,
                max: CARRIER_GRACE_SECS,
            }
        );

        let flow = "[client]\nnode_id = \"client-a\"\n\n[transport]\nflow_window_bytes = 8388609\nsession_window_bytes = 8388608\n";
        assert_eq!(
            client_err(flow),
            ConfigError::WindowExceedsSession {
                field: "transport.flow_window_bytes".into(),
                value: 8_388_609,
                session: 8_388_608,
            }
        );

        let zero_flow = "[client]\nnode_id = \"client-a\"\n\n[transport]\nflow_window_bytes = 0\n";
        assert_eq!(
            client_err(zero_flow),
            ConfigError::NotPositive {
                field: "transport.flow_window_bytes".into(),
                value: 0,
            }
        );

        let reserve =
            "[client]\nnode_id = \"client-a\"\n\n[transport]\ncontrol_reserve_bytes = 16777216\n";
        assert_eq!(
            client_err(reserve),
            ConfigError::WindowExceedsSession {
                field: "transport.control_reserve_bytes".into(),
                value: 16_777_216,
                session: SESSION_WINDOW_BYTES,
            }
        );

        let empty = "[client]\nnode_id = \"client-a\"\n\n[transport]\nprofiles = []\n";
        assert_eq!(
            client_err(empty),
            ConfigError::EmptyProfiles {
                field: "transport.profiles".into(),
            }
        );

        let unknown =
            "[client]\nnode_id = \"client-a\"\n\n[transport]\nprofiles = [\"binary\", \"xml\"]\n";
        assert_eq!(
            client_err(unknown),
            ConfigError::UnknownProfile {
                field: "transport.profiles[1]".into(),
                value: "xml".into(),
            }
        );

        let duplicated =
            "[client]\nnode_id = \"client-a\"\n\n[transport]\nprofiles = [\"binary\", \"binary\"]\n";
        assert_eq!(
            client_err(duplicated),
            ConfigError::Duplicate {
                field: "transport.profiles[1]".into(),
                value: "binary".into(),
            }
        );
    }

    #[test]
    fn decoy_bounds_are_enforced() {
        let min = "[client]\nnode_id = \"client-a\"\n\n[decoy]\ninterval_min_secs = 1\n";
        assert_eq!(
            client_err(min),
            ConfigError::OutOfRange {
                field: "decoy.interval_min_secs".into(),
                value: 1,
                min: BACKGROUND_JITTER_MIN_SECS,
                max: BACKGROUND_JITTER_MAX_SECS,
            }
        );

        let max = "[client]\nnode_id = \"client-a\"\n\n[decoy]\ninterval_max_secs = 16\n";
        assert_eq!(
            client_err(max),
            ConfigError::OutOfRange {
                field: "decoy.interval_max_secs".into(),
                value: 16,
                min: BACKGROUND_JITTER_MIN_SECS,
                max: BACKGROUND_JITTER_MAX_SECS,
            }
        );

        let inverted = "[client]\nnode_id = \"client-a\"\n\n[decoy]\ninterval_min_secs = 10\ninterval_max_secs = 5\n";
        assert_eq!(
            client_err(inverted),
            ConfigError::InvertedDecoyInterval { min: 10, max: 5 }
        );

        let budget = format!(
            "[client]\nnode_id = \"client-a\"\n\n[decoy]\nmax_bytes_per_sec = {}\n",
            BACKGROUND_BUDGET_BYTES_PER_SEC as u64 * 2
        );
        assert_eq!(
            client_err(&budget),
            ConfigError::OutOfRange {
                field: "decoy.max_bytes_per_sec".into(),
                value: BACKGROUND_BUDGET_BYTES_PER_SEC as u64 * 2,
                min: 1,
                max: BACKGROUND_BUDGET_BYTES_PER_SEC as u64,
            }
        );

        let origin = "[client]\nnode_id = \"client-a\"\n\n[decoy]\nallowed_origins = [\"ftp://a.example.com\"]\n";
        assert_eq!(
            client_err(origin),
            ConfigError::InvalidUrl {
                field: "decoy.allowed_origins[0]".into(),
                value: "ftp://a.example.com".into(),
            }
        );
    }

    // ------------------------------------------------------------ namespace

    #[test]
    fn namespace_suffix_is_validated() {
        let ok = "[client]\nnode_id = \"client-a\"\n\n[socks_service_namespace]\nenabled = true\nsuffix = \"wsnet.invalid\"\n";
        assert!(ClientConfig::from_toml(ok).is_ok());

        // A disabled namespace is inert, so a suffix no one can reach is fine.
        let disabled = "[client]\nnode_id = \"client-a\"\n\n[socks_service_namespace]\nenabled = false\nsuffix = \"not a suffix\"\n";
        assert!(ClientConfig::from_toml(disabled).is_ok());

        let bad = "[client]\nnode_id = \"client-a\"\n\n[socks_service_namespace]\nenabled = true\nsuffix = \"not a suffix\"\n";
        assert_eq!(
            client_err(bad),
            ConfigError::InvalidSuffix {
                field: "socks_service_namespace.suffix".into(),
                value: "not a suffix".into(),
            }
        );

        let leading_dash = "[client]\nnode_id = \"client-a\"\n\n[socks_service_namespace]\nenabled = true\nsuffix = \"-bad.invalid\"\n";
        assert!(matches!(
            client_err(leading_dash),
            ConfigError::InvalidSuffix { .. }
        ));
    }

    // ------------------------------------------------------------ acl

    #[test]
    fn acl_rules_are_compiled_at_load() {
        let bad_cidr = r#"
[client]
node_id = "client-b"

[[acl]]
caller = "client-b"
action = "connect_node_address"
node = "client-a"
host_cidr = "not-a-cidr"
allow = true
"#;
        assert_eq!(
            client_err(bad_cidr),
            ConfigError::Acl {
                index: 0,
                source: AclError::InvalidCidr("not-a-cidr".into()),
            }
        );

        let bad_caller = r#"
[server]
hub_id = "hub-a"

[[acl]]
caller = "client/b"
action = "relay"
allow = true
"#;
        assert_eq!(
            server_err(bad_caller),
            ConfigError::NotASlug {
                field: "acl[0].caller".into(),
                value: "client/b".into(),
            }
        );
    }

    // ------------------------------------------------------------ io

    #[test]
    fn load_from_path_reads_and_validates() {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "wsnet-config-test-{}-{unique}.toml",
            std::process::id()
        ));

        fs::write(&path, DESIGN_CLIENT).unwrap();
        let config = ClientConfig::load_from_path(&path).expect("file must load");
        assert_eq!(config.client.node_id, "client-a");
        fs::remove_file(&path).unwrap();

        let missing = path.join("does-not-exist.toml");
        let error = ClientConfig::load_from_path(&missing).expect_err("missing file must fail");
        assert!(matches!(error, ConfigError::Io { .. }), "{error:?}");

        // A file that parses but fails validation must report the typed error,
        // not an I/O error.
        let bad = std::env::temp_dir().join(format!(
            "wsnet-config-test-{}-{unique}-bad.toml",
            std::process::id()
        ));
        fs::write(&bad, "[server]\nhub_id = \"hub-a\"\nauth_window_secs = 1\n").unwrap();
        assert!(matches!(
            ServerConfig::load_from_path(&bad),
            Err(ConfigError::AuthWindowOutOfRange { .. })
        ));
        fs::remove_file(&bad).unwrap();
    }

    // ------------------------------------------------------------ round trip

    #[test]
    fn documents_round_trip_through_toml() {
        let server = ServerConfig::from_toml(DESIGN_SERVER).unwrap();
        let text = toml::to_string(&server).expect("server config must serialise");
        let reparsed = ServerConfig::from_toml(&text).expect("serialised server config must load");
        assert_eq!(server, reparsed);

        let client = ClientConfig::from_toml(DESIGN_CLIENT).unwrap();
        let text = toml::to_string(&client).expect("client config must serialise");
        let reparsed = ClientConfig::from_toml(&text).expect("serialised client config must load");
        assert_eq!(client, reparsed);

        // A default-filled document must survive the same trip.
        let minimal = ClientConfig::from_toml("").unwrap();
        let text = toml::to_string(&minimal).unwrap();
        assert_eq!(ClientConfig::from_toml(&text).unwrap(), minimal);
    }
}
