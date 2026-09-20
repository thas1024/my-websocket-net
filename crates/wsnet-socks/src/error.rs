//! Errors of the inbound SOCKS5 server, and their mapping to RFC 1928 replies.

use std::net::{IpAddr, SocketAddr};

use crate::wire::ReplyCode;

/// Every way the inbound SOCKS5 server can refuse work.
///
/// The variants are deliberately coarse: a client must not be able to probe
/// internal policy through error text, so the reply carrying a code carries no
/// detail and the detail stays in the local log (DESIGN.md section 9.1).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SocksError {
    /// Reading from or writing to a socket failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The greeting or request did not announce SOCKS version 5.
    #[error("unsupported SOCKS version 0x{0:02x}, expected 5")]
    BadVersion(u8),
    /// A field was structurally invalid for the message being read.
    #[error("malformed SOCKS message: {0}")]
    Malformed(&'static str),
    /// `ATYP` was neither 1 (IPv4), 3 (domain), nor 4 (IPv6).
    #[error("unsupported address type 0x{0:02x}")]
    UnsupportedAtyp(u8),
    /// `CMD` was not a command this server implements.
    #[error("unsupported command 0x{0:02x}")]
    UnsupportedCommand(u8),
    /// The destination port was 0, which is not a legal destination.
    #[error("port 0 is not a valid destination port")]
    PortZero,
    /// The client offered no authentication method this server accepts.
    #[error("no acceptable authentication method offered by the client")]
    AuthRejected,
    /// RFC 1929 credentials did not match the configured username/password.
    #[error("invalid username or password")]
    AuthFailed,
    /// The TCP peer is not in the configured source allowlist (section 9.3).
    #[error("peer {0} is not in the source allowlist")]
    SourceDenied(IpAddr),
    /// The listen address is not loopback while `loopback_only` is set.
    #[error("refusing to listen on non-loopback {0} with `loopback_only` set")]
    NonLoopbackListen(SocketAddr),
    /// The listen address is not loopback without the section 9.3 protections.
    #[error(
        "refusing to listen on non-loopback {0}: section 9.3 requires username/password and a \
         source allowlist, or an explicit `loopback_only = false` with both configured"
    )]
    UnsafeListenAddress(SocketAddr),
    /// A configuration value is outside the bounds the design allows.
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    /// A source allowlist entry was not an IP address or a CIDR.
    #[error("`{0}` is not an IP address or a CIDR prefix")]
    InvalidIpPrefix(String),
    /// `CMD=0x03` arrived while UDP ASSOCIATE is disabled.
    #[error("UDP ASSOCIATE is disabled on this listener")]
    UdpDisabled,
    /// The UDP association ended before the handler could use it.
    #[error("the UDP association has already ended")]
    AssociationClosed,
    /// A UDP payload exceeded the configured bound (section 7.4).
    #[error("UDP payload of {0} bytes exceeds the configured bound")]
    PayloadTooLarge(usize),
    /// A handler refused the target.
    #[error("target refused the connection")]
    ConnectRefused,
    /// A handler failed for a reason it wants kept local (section 9.1).
    #[error("handler failed: {0}")]
    Handler(String),
}

impl SocksError {
    /// The RFC 1928 reply code that presents this failure to a client.
    ///
    /// Section 9.1 asks for a uniform, bounded failure appearance, so anything
    /// without a more specific RFC code becomes a general failure rather than a
    /// reason-specific one.
    pub fn reply_code(&self) -> ReplyCode {
        match self {
            SocksError::UnsupportedAtyp(_) => ReplyCode::AddressTypeNotSupported,
            SocksError::UnsupportedCommand(_) | SocksError::UdpDisabled => {
                ReplyCode::CommandNotSupported
            }
            SocksError::ConnectRefused => ReplyCode::ConnectionRefused,
            SocksError::Io(_)
            | SocksError::BadVersion(_)
            | SocksError::Malformed(_)
            | SocksError::PortZero
            | SocksError::AuthRejected
            | SocksError::AuthFailed
            | SocksError::SourceDenied(_)
            | SocksError::NonLoopbackListen(_)
            | SocksError::UnsafeListenAddress(_)
            | SocksError::Config(_)
            | SocksError::InvalidIpPrefix(_)
            | SocksError::PayloadTooLarge(_)
            | SocksError::AssociationClosed
            | SocksError::Handler(_) => ReplyCode::GeneralFailure,
        }
    }
}
