//! Listener configuration and credential material for the inbound SOCKS5 server.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use wsnet_limits::{
    HANDSHAKE_TIMEOUT_MS, MAX_UNAUTH_CONNECTIONS_PER_IP, UDP_ASSOCIATION_IDLE_SECS,
    UDP_MAX_PAYLOAD_DEFAULT, UDP_QUEUE_TTL_DEFAULT_MS, UDP_QUEUE_TTL_MAX_MS, UDP_QUEUE_TTL_MIN_MS,
};

use crate::error::SocksError;

/// The maximum SOCKS5 UDP header, used to keep the payload bound inside the
/// datagram bound the limits crate asserts (`UDP_MAX_PAYLOAD_DEFAULT + 264 <=
/// MAX_UDP_PAYLOAD`).
pub(crate) const UDP_HEADER_MARGIN: usize = 264;

/// One entry of the source allowlist: an IP address plus a prefix length.
///
/// The workspace's `ipnet` dependency belongs to the routing crate's ACL model;
/// the inbound listener only needs a membership test, so it carries its own
/// tiny prefix type and adds no dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpPrefix {
    /// Builds a prefix, rejecting a length that does not fit the address family.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, SocksError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(SocksError::InvalidIpPrefix(format!("{addr}/{prefix_len}")));
        }
        Ok(Self { addr, prefix_len })
    }

    /// Builds a single-host entry.
    pub fn host(addr: IpAddr) -> Self {
        let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
        Self { addr, prefix_len }
    }

    /// The network address of the entry.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length of the entry.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `ip` falls inside this entry. Address families never match.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = v4_mask(self.prefix_len);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = v6_mask(self.prefix_len);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    }
}

impl FromStr for IpPrefix {
    type Err = SocksError;

    /// Parses `10.0.0.0/8`, `::1`, or a bare address.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.split_once('/') {
            None => IpAddr::from_str(text)
                .map(IpPrefix::host)
                .map_err(|_| SocksError::InvalidIpPrefix(text.to_string())),
            Some((addr, len)) => {
                let addr = IpAddr::from_str(addr)
                    .map_err(|_| SocksError::InvalidIpPrefix(text.to_string()))?;
                let prefix_len = len
                    .parse::<u8>()
                    .map_err(|_| SocksError::InvalidIpPrefix(text.to_string()))?;
                IpPrefix::new(addr, prefix_len)
                    .map_err(|_| SocksError::InvalidIpPrefix(text.to_string()))
            }
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// A username/password pair used for RFC 1929 negotiation.
#[derive(Clone, PartialEq, Eq)]
pub struct UserPass {
    /// The expected username sent as `UNAME`.
    pub username: String,
    /// The expected password sent as `PASSWD`.
    pub password: String,
}

impl UserPass {
    /// Builds a pair, enforcing the RFC 1929 field limits.
    ///
    /// Empty values are rejected: an empty username is never a credential, and
    /// RFC 1929 carries both fields in a single length-prefixed byte.
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, SocksError> {
        let username = username.into();
        let password = password.into();
        if username.is_empty() || password.is_empty() {
            return Err(SocksError::Config(
                "username and password must both be non-empty",
            ));
        }
        if username.len() > 255 || password.len() > 255 {
            return Err(SocksError::Config(
                "username and password must be at most 255 bytes (RFC 1929)",
            ));
        }
        Ok(Self { username, password })
    }

    /// Compares a received credential without leaking it through early exit.
    ///
    /// The comparison cost must not depend on how many leading bytes matched,
    /// because a remote client can measure that timing.
    pub(crate) fn matches(&self, username: &str, password: &str) -> bool {
        let mut diff = 0u8;
        diff |= ct_eq_bytes(self.username.as_bytes(), username.as_bytes());
        diff |= ct_eq_bytes(self.password.as_bytes(), password.as_bytes());
        diff == 0
    }
}

/// Length-independent byte comparison; a length mismatch is folded into the
/// accumulated difference instead of returning early.
fn ct_eq_bytes(expected: &[u8], received: &[u8]) -> u8 {
    let mut diff = (expected.len() ^ received.len()) as u8;
    let n = expected.len().max(received.len());
    for i in 0..n {
        let a = expected.get(i).copied().unwrap_or(0);
        let b = received.get(i).copied().unwrap_or(0);
        diff |= a ^ b;
    }
    diff
}

impl fmt::Debug for UserPass {
    /// Keeps the password out of logs and test output (section 9.3 requires
    /// secrets to stay out of logs).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserPass")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Everything the inbound SOCKS5 server needs to police its own listener.
///
/// Defaults are the safe ones the design asks for: loopback only, no
/// credentials, and every numeric bound taken from `wsnet-limits` rather than
/// chosen here.
#[derive(Debug, Clone)]
pub struct SocksConfig {
    /// Refuse to start when the listener is not on a loopback address
    /// (section 9.3). Set to `false` only together with credentials and a
    /// source allowlist.
    pub loopback_only: bool,
    /// Source addresses allowed to connect. Empty means "any source", which
    /// section 9.3 only permits on a loopback listener.
    pub source_allowlist: Vec<IpPrefix>,
    /// Whether `CMD=0x03` (UDP ASSOCIATE) is accepted (section 7.4).
    pub udp_enabled: bool,
    /// Largest UDP payload accepted from a client, in bytes. The SOCKS5 UDP
    /// header must still fit the record bound, so this is capped at
    /// `UDP_MAX_PAYLOAD_DEFAULT`.
    pub max_udp_payload: usize,
    /// Credentials for RFC 1929. When set, no-auth is never accepted
    /// (section 9.3).
    pub userpass: Option<UserPass>,
    /// Explicit address advertised as `BND.ADDR` for UDP associations, for
    /// multi-homed or NAT deployments (section 7.4). The port is always the
    /// real bound port.
    pub udp_advertise: Option<SocketAddr>,
    /// How long a datagram may sit in the per-association send queue.
    pub udp_queue_ttl: Duration,
    /// Upper bound on association inactivity.
    pub udp_idle_timeout: Duration,
    /// Deadline for method negotiation and request parsing (section 9.2).
    pub handshake_timeout: Duration,
    /// Concurrent unauthenticated connections allowed per source address
    /// (section 9.2).
    pub max_unauth_connections_per_ip: usize,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            loopback_only: true,
            source_allowlist: Vec::new(),
            udp_enabled: true,
            max_udp_payload: UDP_MAX_PAYLOAD_DEFAULT,
            userpass: None,
            udp_advertise: None,
            udp_queue_ttl: Duration::from_millis(UDP_QUEUE_TTL_DEFAULT_MS),
            udp_idle_timeout: Duration::from_secs(UDP_ASSOCIATION_IDLE_SECS),
            handshake_timeout: Duration::from_millis(HANDSHAKE_TIMEOUT_MS),
            max_unauth_connections_per_ip: MAX_UNAUTH_CONNECTIONS_PER_IP,
        }
    }
}

impl SocksConfig {
    /// Creates a configuration with the documented defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches RFC 1929 credentials.
    pub fn with_credentials(mut self, userpass: UserPass) -> Self {
        self.userpass = Some(userpass);
        self
    }

    /// Parses and installs a source allowlist.
    pub fn with_source_allowlist<I, S>(mut self, entries: I) -> Result<Self, SocksError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allowlist = Vec::new();
        for entry in entries {
            allowlist.push(IpPrefix::from_str(entry.as_ref())?);
        }
        self.source_allowlist = allowlist;
        Ok(self)
    }

    /// Whether a TCP or UDP source address is allowed to use this listener.
    pub fn source_allows(&self, ip: IpAddr) -> bool {
        self.source_allowlist.is_empty() || self.source_allowlist.iter().any(|p| p.contains(ip))
    }

    /// Validates values that must hold before any socket work starts.
    pub fn validate(&self) -> Result<(), SocksError> {
        if self.max_udp_payload == 0 {
            return Err(SocksError::Config("max_udp_payload must be positive"));
        }
        // Section 7.4 fixes the SOCKS5 UDP payload at 60 KiB and only requires
        // that the header still fits the datagram bound, so a configuration may
        // lower this bound but never raise it above the design's number.
        if self.max_udp_payload > UDP_MAX_PAYLOAD_DEFAULT {
            return Err(SocksError::Config(
                "max_udp_payload must not exceed UDP_MAX_PAYLOAD_DEFAULT",
            ));
        }
        if self.max_udp_payload + UDP_HEADER_MARGIN > wsnet_limits::MAX_UDP_PAYLOAD {
            return Err(SocksError::Config(
                "max_udp_payload plus the SOCKS5 UDP header exceeds MAX_UDP_PAYLOAD",
            ));
        }
        let ttl_ms = self.udp_queue_ttl.as_millis() as u64;
        if !(UDP_QUEUE_TTL_MIN_MS..=UDP_QUEUE_TTL_MAX_MS).contains(&ttl_ms) {
            return Err(SocksError::Config(
                "udp_queue_ttl must be inside UDP_QUEUE_TTL_MIN_MS..=UDP_QUEUE_TTL_MAX_MS",
            ));
        }
        if self.udp_idle_timeout.is_zero()
            || self.udp_idle_timeout > Duration::from_secs(UDP_ASSOCIATION_IDLE_SECS)
        {
            return Err(SocksError::Config(
                "udp_idle_timeout must be positive and at most UDP_ASSOCIATION_IDLE_SECS",
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(SocksError::Config("handshake_timeout must be positive"));
        }
        if self.max_unauth_connections_per_ip == 0 {
            return Err(SocksError::Config(
                "max_unauth_connections_per_ip must be positive",
            ));
        }
        if let Some(userpass) = &self.userpass {
            if userpass.username.is_empty()
                || userpass.password.is_empty()
                || userpass.username.len() > 255
                || userpass.password.len() > 255
            {
                return Err(SocksError::Config(
                    "credentials must be 1..=255 bytes in both fields (RFC 1929)",
                ));
            }
        }
        Ok(())
    }

    /// Validates the configuration against the address actually being listened
    /// on.
    ///
    /// DESIGN.md section 9.3: "listening on a non-loopback address requires
    /// username/password plus a source allowlist, otherwise startup is
    /// refused".
    pub fn validate_for(&self, local: SocketAddr) -> Result<(), SocksError> {
        self.validate()?;
        if !local.ip().is_loopback() {
            if self.loopback_only {
                return Err(SocksError::NonLoopbackListen(local));
            }
            if self.userpass.is_none() || self.source_allowlist.is_empty() {
                return Err(SocksError::UnsafeListenAddress(local));
            }
        }
        if let Some(advertise) = self.udp_advertise {
            if advertise.is_ipv4() != local.is_ipv4() && !local.ip().is_unspecified() {
                return Err(SocksError::Config(
                    "udp_advertise must use the same address family as the listen address",
                ));
            }
        }
        Ok(())
    }
}

/// The wildcard address matching `local`'s family, used when an exact bind is
/// impossible and the real reachable address must come from `local` instead.
pub(crate) fn wildcard_for(local: SocketAddr) -> IpAddr {
    if local.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_membership_respects_the_mask() {
        let net = IpPrefix::from_str("10.0.0.0/8").expect("valid prefix");
        assert!(net.contains(IpAddr::from_str("10.1.2.3").unwrap()));
        assert!(!net.contains(IpAddr::from_str("11.1.2.3").unwrap()));
        assert!(!net.contains(IpAddr::from_str("::1").unwrap()));

        let host = IpPrefix::from_str("127.0.0.1").expect("valid host prefix");
        assert_eq!(host.prefix_len(), 32);
        assert!(host.contains(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(!host.contains(IpAddr::from_str("127.0.0.2").unwrap()));

        let all = IpPrefix::from_str("0.0.0.0/0").expect("valid default prefix");
        assert!(all.contains(IpAddr::from_str("203.0.113.9").unwrap()));

        let v6 = IpPrefix::from_str("fd00::/8").expect("valid prefix");
        assert!(v6.contains(IpAddr::from_str("fd12::1").unwrap()));
        assert!(!v6.contains(IpAddr::from_str("fe80::1").unwrap()));
    }

    #[test]
    fn prefix_parsing_rejects_nonsense() {
        assert!(IpPrefix::from_str("not-an-address").is_err());
        assert!(IpPrefix::from_str("10.0.0.0/33").is_err());
        assert!(IpPrefix::from_str("10.0.0.0/x").is_err());
        assert!(IpPrefix::from_str("fd00::/129").is_err());
    }

    #[test]
    fn credentials_compare_without_length_shortcuts() {
        let expected = UserPass::new("alice", "s3cret").expect("valid");
        assert!(expected.matches("alice", "s3cret"));
        assert!(!expected.matches("alice", "s3cres"));
        assert!(!expected.matches("alice", "s3cret-longer"));
        assert!(!expected.matches("alice2", "s3cret"));
        assert!(!expected.matches("", "s3cret"));
        assert!(!expected.matches("alice", ""));
        // The password must not be printable through Debug.
        assert!(!format!("{expected:?}").contains("s3cret"));
    }

    #[test]
    fn credentials_reject_empty_and_oversized_fields() {
        assert!(UserPass::new("", "x").is_err());
        assert!(UserPass::new("x", "").is_err());
        assert!(UserPass::new("x".repeat(256), "y").is_err());
        assert!(UserPass::new("x", "y".repeat(256)).is_err());
        assert!(UserPass::new("x".repeat(255), "y".repeat(255)).is_ok());
    }

    #[test]
    fn non_loopback_listen_requires_the_section_9_3_protections() {
        let non_loopback: SocketAddr = "0.0.0.0:1080".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:1080".parse().unwrap();

        assert!(SocksConfig::new().validate_for(loopback).is_ok());
        assert!(matches!(
            SocksConfig::new().validate_for(non_loopback),
            Err(SocksError::NonLoopbackListen(_))
        ));

        let mut open = SocksConfig::new();
        open.loopback_only = false;
        assert!(matches!(
            open.validate_for(non_loopback),
            Err(SocksError::UnsafeListenAddress(_))
        ));

        // Credentials alone are not enough: section 9.3 demands the allowlist too.
        open.userpass = Some(UserPass::new("alice", "s3cret").unwrap());
        assert!(matches!(
            open.validate_for(non_loopback),
            Err(SocksError::UnsafeListenAddress(_))
        ));

        open.source_allowlist = vec![IpPrefix::from_str("10.0.0.0/8").unwrap()];
        assert!(open.validate_for(non_loopback).is_ok());
    }

    #[test]
    fn numeric_bounds_come_from_the_limits_crate() {
        let mut config = SocksConfig::new();
        config.max_udp_payload = UDP_MAX_PAYLOAD_DEFAULT + 1;
        assert!(config.validate().is_err());

        let mut config = SocksConfig::new();
        config.udp_queue_ttl = Duration::from_millis(UDP_QUEUE_TTL_MIN_MS - 1);
        assert!(config.validate().is_err());

        let mut config = SocksConfig::new();
        config.udp_queue_ttl = Duration::from_millis(UDP_QUEUE_TTL_MAX_MS + 1);
        assert!(config.validate().is_err());

        let mut config = SocksConfig::new();
        config.udp_idle_timeout = Duration::from_secs(UDP_ASSOCIATION_IDLE_SECS + 1);
        assert!(config.validate().is_err());

        let mut config = SocksConfig::new();
        config.udp_idle_timeout = Duration::from_millis(100);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn advertise_family_must_match_the_listener() {
        let loopback_v4: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let loopback_v6: SocketAddr = "[::1]:0".parse().unwrap();

        let mut config = SocksConfig::new();
        config.udp_advertise = Some("127.0.0.5:0".parse().unwrap());
        assert!(config.validate_for(loopback_v4).is_ok());

        // section 7.4 asks for IPv4/IPv6 to match, so a cross-family override is
        // a configuration error rather than a surprise at association time.
        config.udp_advertise = Some("[::1]:0".parse().unwrap());
        assert!(config.validate_for(loopback_v4).is_err());
        assert!(config.validate_for(loopback_v6).is_ok());

        let mut config = SocksConfig::new();
        config.udp_advertise = Some("127.0.0.5:0".parse().unwrap());
        assert!(config
            .validate_for(loopback_v6)
            .is_err_and(|e| matches!(e, SocksError::Config(_))));
    }

    #[test]
    fn empty_allowlist_allows_every_source() {
        let config = SocksConfig::new();
        assert!(config.source_allows(IpAddr::from_str("198.51.100.4").unwrap()));
    }
}
