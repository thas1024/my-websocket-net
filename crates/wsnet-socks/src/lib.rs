#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Inbound SOCKS5 (RFC 1928) for a wsnet node: TCP CONNECT, UDP ASSOCIATE, and
//! RFC 1929 username/password negotiation.
//!
//! The crate is the *local* entry point of the data plane. It owns everything
//! the design fixes about the client-facing protocol and nothing about the
//! tunnel:
//!
//! * method negotiation, request parsing, and the RFC reply codes;
//! * the loopback-by-default and allowlist policy of DESIGN.md section 9.3,
//!   enforced at construction, not at first use;
//! * the UDP association state machine of section 7.4, including source
//!   locking, the bounded target map, the bounded send queue, the monotonic
//!   queue TTL, and header rewriting;
//! * counters for every drop reason, so a caller can expose statistics.
//!
//! The caller supplies a [`SocksHandler`]. It resolves and dials targets, owns
//! the outbound tunnel, and therefore remains the only place that can leak a
//! name into a resolver (section 7.1: a domain must be resolved at the exit).
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use wsnet_socks::{
//!     BoxDuplex, BoxFuture, Socks5Server, SocksConfig, SocksError, SocksHandler, SocksRequest,
//!     UdpControl,
//! };
//!
//! struct Direct;
//!
//! impl SocksHandler for Direct {
//!     fn connect(&self, _request: SocksRequest) -> BoxFuture<'static, Result<BoxDuplex, SocksError>> {
//!         Box::pin(async { Err(SocksError::ConnectRefused) })
//!     }
//!
//!     fn udp_associate(&self, mut control: UdpControl) -> BoxFuture<'static, Result<(), SocksError>> {
//!         Box::pin(async move {
//!             while control.recv().await.is_some() {}
//!             Ok(())
//!         })
//!     }
//! }
//!
//! # async fn run() -> Result<(), SocksError> {
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:1080").await?;
//! let server = Socks5Server::new(listener, Arc::new(Direct), SocksConfig::new())?;
//! server.run().await
//! # }
//! ```

mod config;
mod error;
mod server;
mod stats;
mod udp;
mod wire;

pub use config::{IpPrefix, SocksConfig, UserPass};
pub use error::SocksError;
pub use server::Socks5Server;
pub use stats::{Counter, SocksStats, StatsHandle};
pub use udp::{UdpControl, UdpDatagram, UdpReply, UdpReplySender};
pub use wire::{
    encode_target, encode_udp_datagram, encode_udp_reply, read_target, AuthMethod, Command,
    Credentials, Greeting, Reply, ReplyCode, Request, SocksRequest, SocksTarget, UdpHeader,
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, UDP_HEADER_MAX,
};

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

/// Any byte stream the server can proxy: the client's TCP connection on one
/// side, whatever the handler opened on the other.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A boxed duplex stream, which is all the server needs to relay bytes.
pub type BoxDuplex = Box<dyn Duplex>;

/// A boxed, `Send`, borrowing future.
///
/// The handler trait is object-safe through this alias: without it, an `async
/// fn` in the trait would leave the trait unusable behind `dyn`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the proxy must provide for every accepted client.
pub trait SocksHandler: Send + Sync + 'static {
    /// Opens the target for one CONNECT.
    ///
    /// A `Domain` target must be resolved where the exit is, not here
    /// (section 7.1). The returned stream is relayed in both directions until
    /// either side closes.
    fn connect(&self, request: SocksRequest) -> BoxFuture<'static, Result<BoxDuplex, SocksError>>;

    /// Serves one UDP ASSOCIATE (section 7.4).
    ///
    /// The implementation owns the tunnel: it consumes [`UdpDatagram`]s that
    /// already passed source, header, and payload validation, and answers with
    /// [`UdpReply`]s that the server rewrites into SOCKS5 UDP datagrams for the
    /// client. The association is bound to the controlling TCP connection, so
    /// the returned future should resolve once [`UdpControl::closed`] does; the
    /// server tears the local mapping down first and only then gives the future
    /// a short grace to finish.
    fn udp_associate(&self, control: UdpControl) -> BoxFuture<'static, Result<(), SocksError>>;
}

impl<H: SocksHandler + ?Sized> SocksHandler for Arc<H> {
    fn connect(&self, request: SocksRequest) -> BoxFuture<'static, Result<BoxDuplex, SocksError>> {
        (**self).connect(request)
    }

    fn udp_associate(&self, control: UdpControl) -> BoxFuture<'static, Result<(), SocksError>> {
        (**self).udp_associate(control)
    }
}
