//! RFC 1928 and RFC 1929 wire messages.
//!
//! These types are public on purpose: they are the pieces a test can drive
//! without a socket, and the pieces another crate needs when it has to speak the
//! same protocol on a different transport.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::UserPass;
use crate::error::SocksError;

/// `ATYP` for a 4-byte IPv4 address.
pub const ATYP_IPV4: u8 = 0x01;
/// `ATYP` for a length-prefixed domain name.
pub const ATYP_DOMAIN: u8 = 0x03;
/// `ATYP` for a 16-byte IPv6 address.
pub const ATYP_IPV6: u8 = 0x04;

/// Longest possible SOCKS5 UDP header: `RSV(2) FRAG(1) ATYP(1) LEN(1) 255 PORT(2)`.
pub const UDP_HEADER_MAX: usize = 262;

/// One parsed SOCKS5 request target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SocksTarget {
    /// `ATYP=DOMAIN`. The host must be resolved at the exit, never locally
    /// (section 7.1): the client chose remote DNS, so the proxy must not leak
    /// the name into its own resolver.
    Domain(String),
    /// `ATYP=IPV4` or `ATYP=IPV6`.
    Ip(IpAddr),
}

impl SocksTarget {
    /// The `ATYP` byte this target is encoded with.
    pub fn atyp(&self) -> u8 {
        match self {
            SocksTarget::Domain(_) => ATYP_DOMAIN,
            SocksTarget::Ip(IpAddr::V4(_)) => ATYP_IPV4,
            SocksTarget::Ip(IpAddr::V6(_)) => ATYP_IPV6,
        }
    }

    /// The domain, when the target is one.
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            SocksTarget::Domain(host) => Some(host),
            SocksTarget::Ip(_) => None,
        }
    }
}

impl std::fmt::Display for SocksTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksTarget::Domain(host) => f.write_str(host),
            SocksTarget::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// One parsed SOCKS5 request target with its port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocksRequest {
    /// Where the client wants to go.
    pub target: SocksTarget,
    /// The destination port; never 0, because port 0 is rejected during parsing.
    pub port: u16,
}

impl std::fmt::Display for SocksRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.target, self.port)
    }
}

/// The `CMD` field of a SOCKS5 request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    /// `CONNECT` (0x01): a TCP stream.
    Connect = 0x01,
    /// `BIND` (0x02): defined by RFC 1928, not implemented here.
    Bind = 0x02,
    /// `UDP ASSOCIATE` (0x03).
    UdpAssociate = 0x03,
}

impl Command {
    /// Parses the `CMD` byte.
    pub fn from_u8(value: u8) -> Result<Self, SocksError> {
        match value {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociate),
            other => Err(SocksError::UnsupportedCommand(other)),
        }
    }

    /// The wire value of this command.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// An authentication method from the greeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    /// `0x00`: no authentication.
    NoAuth,
    /// `0x02`: RFC 1929 username/password.
    UserPass,
    /// Any other method the client offered.
    Unknown(u8),
}

impl AuthMethod {
    /// Maps a method byte.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => AuthMethod::NoAuth,
            0x02 => AuthMethod::UserPass,
            other => AuthMethod::Unknown(other),
        }
    }

    /// The wire value of this method.
    pub fn as_u8(self) -> u8 {
        match self {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::UserPass => 0x02,
            AuthMethod::Unknown(other) => other,
        }
    }
}

/// The client's `VER, NMETHODS, METHODS` greeting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// The methods the client offered, in the order it sent them.
    pub methods: Vec<AuthMethod>,
}

impl Greeting {
    /// Reads and validates the greeting.
    pub async fn read<R>(reader: &mut R) -> Result<Self, SocksError>
    where
        R: AsyncRead + Unpin,
    {
        let mut head = [0u8; 2];
        reader.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(SocksError::BadVersion(head[0]));
        }
        if head[1] == 0 {
            return Err(SocksError::Malformed(
                "greeting offered no authentication methods",
            ));
        }
        let mut methods = vec![0u8; head[1] as usize];
        reader.read_exact(&mut methods).await?;
        Ok(Self {
            methods: methods.into_iter().map(AuthMethod::from_u8).collect(),
        })
    }

    /// Whether the client offered `method`.
    pub fn offers(&self, method: AuthMethod) -> bool {
        self.methods.contains(&method)
    }

    /// Picks the method to answer with.
    ///
    /// Section 9.3 makes the server refuse no-auth whenever credentials are
    /// configured, so the configured credential is the only acceptable method in
    /// that case; with no configured credential the server cannot verify an
    /// RFC 1929 exchange and only no-auth is acceptable.
    pub fn choose(&self, credentials: Option<&UserPass>) -> Option<AuthMethod> {
        let acceptable = match credentials {
            Some(_) => AuthMethod::UserPass,
            None => AuthMethod::NoAuth,
        };
        self.offers(acceptable).then_some(acceptable)
    }
}

/// The RFC 1929 username/password sub-negotiation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// The `UNAME` field.
    pub username: String,
    /// The `PASSWD` field.
    pub password: String,
}

impl Credentials {
    /// Reads `VER=1, ULEN, UNAME, PLEN, PASSWD`.
    pub async fn read<R>(reader: &mut R) -> Result<Self, SocksError>
    where
        R: AsyncRead + Unpin,
    {
        let version = reader.read_u8().await?;
        if version != 0x01 {
            return Err(SocksError::Malformed(
                "RFC 1929 sub-negotiation version must be 1",
            ));
        }
        let username = read_length_prefixed(reader).await?;
        let password = read_length_prefixed(reader).await?;
        Ok(Self { username, password })
    }

    /// Checks these against the configured pair in constant time.
    pub fn verify(&self, expected: &UserPass) -> bool {
        expected.matches(&self.username, &self.password)
    }
}

async fn read_length_prefixed<R>(reader: &mut R) -> Result<String, SocksError>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u8().await?;
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    // The two RFC 1929 fields are opaque octets; rejecting non-UTF-8 keeps the
    // comparison deterministic instead of lossily decoding.
    String::from_utf8(buf).map_err(|_| SocksError::Malformed("RFC 1929 field is not valid UTF-8"))
}

/// A parsed SOCKS5 request: one command plus one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The requested command.
    pub command: Command,
    /// The requested target.
    pub target: SocksTarget,
    /// The requested port.
    pub port: u16,
}

impl Request {
    /// Reads `VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT`.
    ///
    /// `ATYP`, `CMD`, and port 0 are rejected here so that a caller only ever
    /// replies, and never allocates a target for, a request the design forbids.
    pub async fn read<R>(reader: &mut R) -> Result<Self, SocksError>
    where
        R: AsyncRead + Unpin,
    {
        let mut head = [0u8; 4];
        reader.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(SocksError::BadVersion(head[0]));
        }
        let command = Command::from_u8(head[1])?;
        if head[2] != 0x00 {
            return Err(SocksError::Malformed("request RSV must be zero"));
        }
        let (target, port) = read_target(reader, head[3]).await?;
        Ok(Self {
            command,
            target,
            port,
        })
    }

    /// The handler-facing view of this request.
    pub fn socks_request(&self) -> SocksRequest {
        SocksRequest {
            target: self.target.clone(),
            port: self.port,
        }
    }
}

/// Reads `DST.ADDR, DST.PORT` for a known `ATYP`.
pub async fn read_target<R>(reader: &mut R, atyp: u8) -> Result<(SocksTarget, u16), SocksError>
where
    R: AsyncRead + Unpin,
{
    let target = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            SocksTarget::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            SocksTarget::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        ATYP_DOMAIN => {
            let len = reader.read_u8().await?;
            if len == 0 {
                return Err(SocksError::Malformed("domain name is empty"));
            }
            let mut buf = vec![0u8; len as usize];
            reader.read_exact(&mut buf).await?;
            let host = String::from_utf8(buf)
                .map_err(|_| SocksError::Malformed("domain name is not valid UTF-8"))?;
            SocksTarget::Domain(host)
        }
        other => return Err(SocksError::UnsupportedAtyp(other)),
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        // Port 0 cannot be dialled and is a classic way to smuggle a wildcard
        // intent into a proxy, so it is refused as a request rather than as a
        // later connection failure.
        return Err(SocksError::PortZero);
    }
    Ok((target, port))
}

/// Appends the `ATYP, ADDR` encoding of a target.
pub fn encode_target(target: &SocksTarget, out: &mut Vec<u8>) -> Result<(), SocksError> {
    match target {
        SocksTarget::Ip(IpAddr::V4(ip)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        SocksTarget::Ip(IpAddr::V6(ip)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        SocksTarget::Domain(host) => {
            let bytes = host.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(SocksError::Malformed(
                    "domain name must be 1..=255 bytes to be encodable",
                ));
            }
            out.push(ATYP_DOMAIN);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}

/// The `REP` field of a SOCKS5 reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReplyCode {
    /// `0x00` succeeded.
    Succeeded = 0x00,
    /// `0x01` general SOCKS server failure.
    GeneralFailure = 0x01,
    /// `0x02` connection not allowed by ruleset.
    ConnectionNotAllowed = 0x02,
    /// `0x03` network unreachable.
    NetworkUnreachable = 0x03,
    /// `0x04` host unreachable.
    HostUnreachable = 0x04,
    /// `0x05` connection refused.
    ConnectionRefused = 0x05,
    /// `0x06` TTL expired.
    TtlExpired = 0x06,
    /// `0x07` command not supported.
    CommandNotSupported = 0x07,
    /// `0x08` address type not supported.
    AddressTypeNotSupported = 0x08,
}

impl ReplyCode {
    /// The wire value of this reply code.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Maps a wire value, rejecting the unassigned range.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(ReplyCode::Succeeded),
            0x01 => Some(ReplyCode::GeneralFailure),
            0x02 => Some(ReplyCode::ConnectionNotAllowed),
            0x03 => Some(ReplyCode::NetworkUnreachable),
            0x04 => Some(ReplyCode::HostUnreachable),
            0x05 => Some(ReplyCode::ConnectionRefused),
            0x06 => Some(ReplyCode::TtlExpired),
            0x07 => Some(ReplyCode::CommandNotSupported),
            0x08 => Some(ReplyCode::AddressTypeNotSupported),
            _ => None,
        }
    }
}

/// A SOCKS5 reply, carrying the bound address the client should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// The `REP` byte.
    pub code: ReplyCode,
    /// The `BND.ADDR`/`BND.PORT` pair.
    pub bind: SocketAddr,
}

impl Reply {
    /// Builds a reply from a code and a bound address.
    pub fn new(code: ReplyCode, bind: SocketAddr) -> Self {
        Self { code, bind }
    }

    /// Builds a failure reply; the bound address is meaningless and left zero.
    pub fn failure(code: ReplyCode) -> Self {
        Self {
            code,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }

    /// Writes `VER, REP, RSV, ATYP, BND.ADDR, BND.PORT`.
    pub async fn write<W>(&self, writer: &mut W) -> Result<(), SocksError>
    where
        W: AsyncWrite + Unpin,
    {
        let mut out = Vec::with_capacity(22);
        out.push(0x05);
        out.push(self.code.as_u8());
        out.push(0x00);
        encode_target(&SocksTarget::Ip(self.bind.ip()), &mut out)?;
        out.extend_from_slice(&self.bind.port().to_be_bytes());
        writer.write_all(&out).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// A parsed SOCKS5 UDP request header (`RSV, FRAG, ATYP, DST.ADDR, DST.PORT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    /// The `FRAG` byte. Anything other than 0 means a fragment, which version 1
    /// of this design does not reassemble (section 7.4).
    pub frag: u8,
    /// The datagram destination.
    pub target: SocksTarget,
    /// The datagram destination port.
    pub port: u16,
}

impl UdpHeader {
    /// Parses a header, returning it with the offset of the payload.
    ///
    /// A non-zero `FRAG` is returned rather than rejected so that the caller can
    /// count the drop for the reason it happened.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), SocksError> {
        if buf.len() < 4 {
            return Err(SocksError::Malformed(
                "UDP datagram shorter than its header",
            ));
        }
        if buf[0] != 0x00 || buf[1] != 0x00 {
            return Err(SocksError::Malformed("UDP RSV must be zero"));
        }
        let frag = buf[2];
        let atyp = buf[3];
        let (target, offset) = match atyp {
            ATYP_IPV4 => {
                if buf.len() < 4 + 4 + 2 {
                    return Err(SocksError::Malformed("truncated IPv4 UDP header"));
                }
                let octets: [u8; 4] = buf[4..8].try_into().unwrap_or([0; 4]);
                (SocksTarget::Ip(IpAddr::V4(Ipv4Addr::from(octets))), 4 + 4)
            }
            ATYP_IPV6 => {
                if buf.len() < 4 + 16 + 2 {
                    return Err(SocksError::Malformed("truncated IPv6 UDP header"));
                }
                let octets: [u8; 16] = buf[4..20].try_into().unwrap_or([0; 16]);
                (SocksTarget::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 4 + 16)
            }
            ATYP_DOMAIN => {
                if buf.len() < 5 {
                    return Err(SocksError::Malformed("truncated domain UDP header"));
                }
                let len = buf[4] as usize;
                if len == 0 {
                    return Err(SocksError::Malformed("domain name is empty"));
                }
                let end = 5 + len;
                if buf.len() < end + 2 {
                    return Err(SocksError::Malformed("truncated domain UDP header"));
                }
                let host = String::from_utf8(buf[5..end].to_vec())
                    .map_err(|_| SocksError::Malformed("domain name is not valid UTF-8"))?;
                (SocksTarget::Domain(host), end)
            }
            other => return Err(SocksError::UnsupportedAtyp(other)),
        };
        let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        if port == 0 {
            return Err(SocksError::PortZero);
        }
        Ok((Self { frag, target, port }, offset + 2))
    }

    /// Appends this header, always written with `FRAG = 0` on the return path:
    /// version 1 never forwards a fragment.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), SocksError> {
        out.push(0x00);
        out.push(0x00);
        out.push(0x00);
        encode_target(&self.target, out)?;
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }
}

/// Encodes a complete SOCKS5 UDP datagram: header followed by the payload.
pub fn encode_udp_datagram(
    target: &SocksTarget,
    port: u16,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), SocksError> {
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    encode_target(target, out)?;
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Encodes a datagram whose source is a socket address, which is the only shape
/// a relayed reply can have.
pub fn encode_udp_reply(
    source: SocketAddr,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), SocksError> {
    encode_udp_datagram(&SocksTarget::Ip(source.ip()), source.port(), payload, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_from(bytes: &[u8]) -> &[u8] {
        bytes
    }

    #[tokio::test]
    async fn greeting_requires_version_five_and_at_least_one_method() {
        let mut ok = read_from(&[0x05, 0x02, 0x00, 0x02]);
        let greeting = Greeting::read(&mut ok).await.expect("valid greeting");
        assert_eq!(
            greeting.methods,
            vec![AuthMethod::NoAuth, AuthMethod::UserPass]
        );

        let mut wrong_version = read_from(&[0x04, 0x01, 0x00]);
        assert!(matches!(
            Greeting::read(&mut wrong_version).await,
            Err(SocksError::BadVersion(0x04))
        ));

        let mut empty = read_from(&[0x05, 0x00]);
        assert!(matches!(
            Greeting::read(&mut empty).await,
            Err(SocksError::Malformed(_))
        ));

        let mut truncated = read_from(&[0x05, 0x02, 0x00]);
        assert!(matches!(
            Greeting::read(&mut truncated).await,
            Err(SocksError::Io(_))
        ));
    }

    #[tokio::test]
    async fn method_choice_never_accepts_no_auth_with_credentials_configured() {
        let greeting = Greeting {
            methods: vec![AuthMethod::NoAuth],
        };
        let creds = UserPass::new("alice", "s3cret").expect("valid");
        assert_eq!(greeting.choose(Some(&creds)), None);
        assert_eq!(greeting.choose(None), Some(AuthMethod::NoAuth));

        let greeting = Greeting {
            methods: vec![AuthMethod::Unknown(0x7f), AuthMethod::UserPass],
        };
        assert_eq!(greeting.choose(Some(&creds)), Some(AuthMethod::UserPass));
        // Without configured credentials an RFC 1929 offer cannot be verified.
        assert_eq!(greeting.choose(None), None);
    }

    #[tokio::test]
    async fn credentials_round_trip() {
        let wire = [
            0x01, 0x05, b'a', b'l', b'i', b'c', b'e', 0x06, b's', b'3', b'c', b'r', b'e', b't',
        ];
        let creds = Credentials::read(&mut read_from(&wire))
            .await
            .expect("valid");
        assert_eq!(creds.username, "alice");
        assert_eq!(creds.password, "s3cret");
        assert!(creds.verify(&UserPass::new("alice", "s3cret").unwrap()));
        assert!(!creds.verify(&UserPass::new("alice", "other").unwrap()));

        let mut wrong_version = read_from(&[0x02, 0x01, b'a', 0x01, b'b']);
        assert!(matches!(
            Credentials::read(&mut wrong_version).await,
            Err(SocksError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn requests_parse_every_address_type() {
        let mut ipv4 = read_from(&[0x05, 0x01, 0x00, 0x01, 192, 0, 2, 5, 0x00, 0x50]);
        let request = Request::read(&mut ipv4).await.expect("valid IPv4 request");
        assert_eq!(request.command, Command::Connect);
        assert_eq!(
            request.target,
            SocksTarget::Ip("192.0.2.5".parse().unwrap())
        );
        assert_eq!(request.port, 80);

        let mut domain = Vec::from([0x05u8, 0x03, 0x00, 0x03, 11]);
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&443u16.to_be_bytes());
        let request = Request::read(&mut read_from(&domain))
            .await
            .expect("valid domain request");
        assert_eq!(request.command, Command::UdpAssociate);
        assert_eq!(
            request.target,
            SocksTarget::Domain("example.com".to_string())
        );
        assert_eq!(request.port, 443);

        let mut ipv6_bytes = Vec::from([0x05u8, 0x01, 0x00, 0x04]);
        ipv6_bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        ipv6_bytes.extend_from_slice(&53u16.to_be_bytes());
        let request = Request::read(&mut read_from(&ipv6_bytes))
            .await
            .expect("valid IPv6 request");
        assert_eq!(
            request.target,
            SocksTarget::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(request.port, 53);
    }

    #[tokio::test]
    async fn requests_reject_bad_version_reserved_atyp_and_port() {
        let mut bad_version = read_from(&[0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]);
        assert!(matches!(
            Request::read(&mut bad_version).await,
            Err(SocksError::BadVersion(0x04))
        ));

        let mut bad_rsv = read_from(&[0x05, 0x01, 0x07, 0x01, 1, 2, 3, 4, 0, 80]);
        assert!(matches!(
            Request::read(&mut bad_rsv).await,
            Err(SocksError::Malformed(_))
        ));

        let mut bad_atyp = read_from(&[0x05, 0x01, 0x00, 0x02, 1, 2, 3, 4, 0, 80]);
        assert!(matches!(
            Request::read(&mut bad_atyp).await,
            Err(SocksError::UnsupportedAtyp(0x02))
        ));

        let mut bad_command = read_from(&[0x05, 0x09, 0x00, 0x01, 1, 2, 3, 4, 0, 80]);
        assert!(matches!(
            Request::read(&mut bad_command).await,
            Err(SocksError::UnsupportedCommand(0x09))
        ));

        let mut port_zero = read_from(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 0]);
        assert!(matches!(
            Request::read(&mut port_zero).await,
            Err(SocksError::PortZero)
        ));

        let mut empty_domain = read_from(&[0x05, 0x01, 0x00, 0x03, 0x00, 0, 80]);
        assert!(matches!(
            Request::read(&mut empty_domain).await,
            Err(SocksError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn replies_encode_ipv4_and_ipv6_bounds() {
        let mut out = Vec::new();
        Reply::new(ReplyCode::Succeeded, "127.0.0.1:1080".parse().unwrap())
            .write(&mut out)
            .await
            .expect("write");
        assert_eq!(out, vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]);

        let mut out = Vec::new();
        Reply::failure(ReplyCode::AddressTypeNotSupported)
            .write(&mut out)
            .await
            .expect("write");
        assert_eq!(out[0..4], [0x05, 0x08, 0x00, 0x01]);
        assert_eq!(out.len(), 10);

        let mut out = Vec::new();
        Reply::new(ReplyCode::ConnectionRefused, "[::1]:9".parse().unwrap())
            .write(&mut out)
            .await
            .expect("write");
        assert_eq!(out[0..4], [0x05, 0x05, 0x00, 0x04]);
        assert_eq!(out.len(), 4 + 16 + 2);
    }

    #[test]
    fn reply_codes_map_both_ways() {
        for code in [
            ReplyCode::Succeeded,
            ReplyCode::GeneralFailure,
            ReplyCode::ConnectionNotAllowed,
            ReplyCode::NetworkUnreachable,
            ReplyCode::HostUnreachable,
            ReplyCode::ConnectionRefused,
            ReplyCode::TtlExpired,
            ReplyCode::CommandNotSupported,
            ReplyCode::AddressTypeNotSupported,
        ] {
            assert_eq!(ReplyCode::from_u8(code.as_u8()), Some(code));
        }
        assert_eq!(ReplyCode::from_u8(0x09), None);
    }

    #[test]
    fn udp_headers_round_trip_for_every_address_type() {
        let mut out = Vec::new();
        encode_udp_datagram(
            &SocksTarget::Ip("198.51.100.7".parse().unwrap()),
            53,
            b"query",
            &mut out,
        )
        .expect("encode");
        let (header, offset) = UdpHeader::parse(&out).expect("parse");
        assert_eq!(header.frag, 0);
        assert_eq!(header.port, 53);
        assert_eq!(
            header.target,
            SocksTarget::Ip("198.51.100.7".parse().unwrap())
        );
        assert_eq!(&out[offset..], b"query");

        let mut out = Vec::new();
        encode_udp_datagram(
            &SocksTarget::Domain("example.com".into()),
            53,
            b"q",
            &mut out,
        )
        .expect("encode");
        let (header, offset) = UdpHeader::parse(&out).expect("parse");
        assert_eq!(header.target, SocksTarget::Domain("example.com".into()));
        assert_eq!(&out[offset..], b"q");

        let mut out = Vec::new();
        encode_udp_datagram(
            &SocksTarget::Ip("2001:db8::1".parse().unwrap()),
            443,
            b"",
            &mut out,
        )
        .expect("encode");
        let (header, offset) = UdpHeader::parse(&out).expect("parse");
        assert_eq!(header.port, 443);
        assert_eq!(offset, out.len());
    }

    #[test]
    fn udp_headers_reject_malformed_input() {
        assert!(matches!(
            UdpHeader::parse(&[0x00, 0x00, 0x00]),
            Err(SocksError::Malformed(_))
        ));
        assert!(matches!(
            UdpHeader::parse(&[0x00, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 53]),
            Err(SocksError::Malformed(_))
        ));
        assert!(matches!(
            UdpHeader::parse(&[0x00, 0x00, 0x00, 0x07, 1, 2, 3, 4, 0, 53]),
            Err(SocksError::UnsupportedAtyp(0x07))
        ));
        assert!(matches!(
            UdpHeader::parse(&[0x00, 0x00, 0x00, 0x01, 1, 2, 3]),
            Err(SocksError::Malformed(_))
        ));
        assert!(matches!(
            UdpHeader::parse(&[0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4, 0, 53]),
            Err(SocksError::Malformed(_))
        ));
        assert!(matches!(
            UdpHeader::parse(&[0x00, 0x00, 0x00, 0x03, 0x00, 0, 53]),
            Err(SocksError::Malformed(_))
        ));
        assert!(matches!(
            UdpHeader::parse(&[0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 0]),
            Err(SocksError::PortZero)
        ));
    }

    #[test]
    fn frag_is_reported_rather_than_hidden() {
        let (header, _) = UdpHeader::parse(&[0x00, 0x00, 0x03, 0x01, 1, 2, 3, 4, 0, 53])
            .expect("parses so the caller can count the fragment");
        assert_eq!(header.frag, 3);
    }

    #[test]
    fn long_domain_is_not_silently_truncated() {
        let mut out = Vec::new();
        let long = SocksTarget::Domain("a".repeat(256));
        assert!(encode_target(&long, &mut out).is_err());
        assert!(out.is_empty());
    }
}
