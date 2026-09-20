//! The inbound SOCKS5 listener: method negotiation, CONNECT, and the UDP
//! ASSOCIATE dispatch.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::config::SocksConfig;
use crate::error::SocksError;
use crate::stats::{Counter, Counters, SocksStats, StatsHandle};
use crate::udp::{self, UdpAssociation};
use crate::wire::{AuthMethod, Command, Credentials, Greeting, Reply, ReplyCode, Request};
use crate::SocksHandler;

/// How long the refusal path waits for the client to close after its reply.
///
/// A socket closed while unread request bytes are still buffered makes the
/// kernel answer with RST, and Windows drops the already-written reply when it
/// does, so the server half-closes, drains briefly, and only then lets the
/// connection go. This is a close courtesy, not a protocol budget: every budget
/// below comes from `wsnet-limits`.
const CLOSE_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_millis(250);

/// Accepts SOCKS5 clients from one bound listener.
///
/// The listener's own address decides whether the configuration is acceptable:
/// a non-loopback address needs credentials and a source allowlist, and the
/// constructor refuses anything else (section 9.3) instead of starting in a
/// state the design calls unsafe.
pub struct Socks5Server<H> {
    listener: TcpListener,
    inner: Arc<ServerInner<H>>,
}

struct ServerInner<H> {
    handler: Arc<H>,
    config: Arc<SocksConfig>,
    counters: Arc<Counters>,
    unauth: Arc<UnauthLimiter>,
    associations: AtomicU64,
}

impl<H: SocksHandler> Socks5Server<H> {
    /// Binds a handler and a configuration to an already-listening socket.
    ///
    /// Returns an error when the configuration contradicts the listen address,
    /// so a misconfigured node fails at startup rather than at first use
    /// (section 9.3).
    pub fn new(listener: TcpListener, handler: H, config: SocksConfig) -> Result<Self, SocksError> {
        let local = listener.local_addr()?;
        config.validate_for(local)?;
        let unauth = Arc::new(UnauthLimiter::new(config.max_unauth_connections_per_ip));
        Ok(Self {
            listener,
            inner: Arc::new(ServerInner {
                handler: Arc::new(handler),
                config: Arc::new(config),
                counters: Arc::new(Counters::new()),
                unauth,
                associations: AtomicU64::new(0),
            }),
        })
    }

    /// The address actually bound, which is what a caller advertises.
    pub fn local_addr(&self) -> Result<SocketAddr, SocksError> {
        Ok(self.listener.local_addr()?)
    }

    /// A cloneable handle for reading statistics while the server runs.
    pub fn stats_handle(&self) -> StatsHandle {
        StatsHandle::new(Arc::clone(&self.inner.counters))
    }

    /// A snapshot of the current statistics.
    pub fn stats(&self) -> SocksStats {
        self.inner.counters.snapshot()
    }

    /// The configuration in force.
    pub fn config(&self) -> &SocksConfig {
        &self.inner.config
    }

    /// Runs the accept loop until the listener fails.
    ///
    /// Each connection is served in its own task, so one slow or hostile client
    /// cannot stall the accept path.
    pub async fn run(self) -> Result<(), SocksError> {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer)) => {
                    self.inner.counters.inc(Counter::ConnectionsAccepted);
                    let inner = Arc::clone(&self.inner);
                    tokio::spawn(async move { serve_connection(inner, stream, peer).await });
                }
                // Per-connection accept errors are reported to that connection
                // only; treating them as fatal would let one aborted handshake
                // stop the whole listener.
                Err(error) if is_transient_accept_error(&error) => continue,
                Err(error) => return Err(SocksError::Io(error)),
            }
        }
    }
}

/// Whether an accept error describes one aborted connection rather than a dead
/// listener.
fn is_transient_accept_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
    )
}

/// Negotiates one accepted connection to the point where a request can be read.
async fn serve_connection<H: SocksHandler>(
    inner: Arc<ServerInner<H>>,
    mut stream: TcpStream,
    peer: SocketAddr,
) {
    let counters = Arc::clone(&inner.counters);
    if !inner.config.source_allows(peer.ip()) {
        counters.inc(Counter::SourceDenied);
        debug!(peer = %peer, "socks5: source address is not in the allowlist");
        return;
    }
    let Some(mut slot) = inner.unauth.acquire(peer.ip()) else {
        counters.inc(Counter::ConnectionLimitDropped);
        debug!(peer = %peer, "socks5: unauthenticated connection budget for this source is spent");
        return;
    };
    let Ok(local) = stream.local_addr() else {
        return;
    };
    let handshake_timeout = inner.config.handshake_timeout;

    match timeout(handshake_timeout, negotiate(&inner, &mut stream, peer)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            debug!(peer = %peer, %error, "socks5: negotiation failed");
            return;
        }
        Err(_) => {
            counters.inc(Counter::HandshakeTimeout);
            debug!(peer = %peer, "socks5: negotiation deadline expired");
            return;
        }
    }
    // The peer proved it can complete a handshake, so it no longer counts
    // against the unauthenticated budget (section 9.2).
    slot.release();

    let request = match timeout(handshake_timeout, Request::read(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            count_request_error(&counters, &error);
            debug!(peer = %peer, %error, "socks5: refusing request");
            refuse(&mut stream, error.reply_code()).await;
            return;
        }
        Err(_) => {
            counters.inc(Counter::HandshakeTimeout);
            debug!(peer = %peer, "socks5: request deadline expired");
            return;
        }
    };

    match request.command {
        Command::Connect => connect(inner, stream, peer, local, request).await,
        Command::UdpAssociate => {
            if !inner.config.udp_enabled {
                counters.inc(Counter::UnsupportedCommand);
                debug!(peer = %peer, "socks5: UDP ASSOCIATE is disabled");
                refuse(&mut stream, ReplyCode::CommandNotSupported).await;
                return;
            }
            let association_id = inner.associations.fetch_add(1, Ordering::Relaxed) + 1;
            let association = UdpAssociation {
                handler: Arc::clone(&inner.handler),
                config: Arc::clone(&inner.config),
                counters: Arc::clone(&counters),
                association_id,
                peer,
                local,
            };
            udp::run(association, stream).await;
        }
        // BIND is a legal RFC 1928 command that this design does not implement,
        // so it is answered with the RFC's "command not supported" code.
        Command::Bind => {
            counters.inc(Counter::UnsupportedCommand);
            debug!(peer = %peer, "socks5: BIND is not supported");
            refuse(&mut stream, ReplyCode::CommandNotSupported).await;
        }
    }
}

/// Writes a failure reply and closes the connection without destroying it.
async fn refuse(stream: &mut TcpStream, code: ReplyCode) {
    let _ = Reply::failure(code).write(stream).await;
    let _ = stream.shutdown().await;
    let mut scratch = [0u8; 512];
    let _ = timeout(CLOSE_DRAIN_GRACE, async {
        loop {
            match stream.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    })
    .await;
}

/// Runs one CONNECT through the handler and relays both directions.
async fn connect<H: SocksHandler>(
    inner: Arc<ServerInner<H>>,
    mut stream: TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    request: Request,
) {
    let counters = Arc::clone(&inner.counters);
    match inner.handler.connect(request.socks_request()).await {
        Ok(mut upstream) => {
            counters.inc(Counter::ConnectSucceeded);
            // RFC 1928 wants the address the proxy bound towards the target, but
            // the handler owns that socket and never exposes it; the client's own
            // local address is a reachable, honest substitute and every real
            // client ignores BND for CONNECT.
            if Reply::new(ReplyCode::Succeeded, local)
                .write(&mut stream)
                .await
                .is_err()
            {
                return;
            }
            match copy_bidirectional(&mut stream, &mut upstream).await {
                Ok((to_target, to_client)) => {
                    trace!(peer = %peer, to_target, to_client, "socks5: CONNECT finished")
                }
                Err(error) => {
                    debug!(peer = %peer, %error, "socks5: CONNECT relay ended with an error")
                }
            }
        }
        Err(error) => {
            counters.inc(Counter::ConnectFailed);
            debug!(peer = %peer, %error, "socks5: CONNECT failed");
            let _ = Reply::failure(error.reply_code()).write(&mut stream).await;
        }
    }
}

/// Completes method negotiation, writing the replies the RFC requires.
async fn negotiate<H: SocksHandler>(
    inner: &ServerInner<H>,
    stream: &mut TcpStream,
    peer: SocketAddr,
) -> Result<(), SocksError> {
    let counters = &inner.counters;
    let greeting = Greeting::read(stream).await?;
    let Some(method) = greeting.choose(inner.config.userpass.as_ref()) else {
        counters.inc(Counter::MethodRejected);
        debug!(peer = %peer, "socks5: client offered no acceptable authentication method");
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(SocksError::AuthRejected);
    };
    stream.write_all(&[0x05, method.as_u8()]).await?;
    match method {
        AuthMethod::NoAuth => {
            counters.inc(Counter::MethodNoAuthAccepted);
            Ok(())
        }
        AuthMethod::UserPass => {
            let credentials = Credentials::read(stream).await?;
            let accepted = inner
                .config
                .userpass
                .as_ref()
                .is_some_and(|expected| credentials.verify(expected));
            stream
                .write_all(&[0x01, if accepted { 0x00 } else { 0x01 }])
                .await?;
            if accepted {
                counters.inc(Counter::MethodUserPassAccepted);
                Ok(())
            } else {
                // RFC 1929 only carries a status byte; the reason stays local so
                // the failure appearance is uniform (section 9.1).
                counters.inc(Counter::AuthFailed);
                debug!(peer = %peer, "socks5: RFC 1929 credentials rejected");
                Err(SocksError::AuthFailed)
            }
        }
        // `choose` only returns the two methods above; answering an unknown
        // method with 0xFF keeps this exhaustive without a panic.
        AuthMethod::Unknown(_) => {
            counters.inc(Counter::MethodRejected);
            stream.write_all(&[0x05, 0xFF]).await?;
            Err(SocksError::AuthRejected)
        }
    }
}

/// Attributes a request-level failure to its counter.
fn count_request_error(counters: &Counters, error: &SocksError) {
    match error {
        SocksError::UnsupportedAtyp(_) => counters.inc(Counter::UnsupportedAtyp),
        SocksError::UnsupportedCommand(_) | SocksError::UdpDisabled => {
            counters.inc(Counter::UnsupportedCommand)
        }
        SocksError::PortZero => counters.inc(Counter::PortZeroRejected),
        SocksError::AuthRejected => counters.inc(Counter::MethodRejected),
        SocksError::AuthFailed => counters.inc(Counter::AuthFailed),
        _ => counters.inc(Counter::RequestMalformed),
    }
}

/// Concurrent unauthenticated connections per source address (section 9.2).
struct UnauthLimiter {
    max: usize,
    inflight: Mutex<HashMap<IpAddr, usize>>,
}

impl UnauthLimiter {
    fn new(max: usize) -> Self {
        Self {
            max,
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Takes one slot for `ip`, or `None` when the source already holds `max`.
    fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<UnauthSlot> {
        // The guard is never held across an await, so a `std` mutex is fine and
        // keeps the accept path free of async bookkeeping.
        let mut inflight = self
            .inflight
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let count = inflight.entry(ip).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        drop(inflight);
        Some(UnauthSlot {
            limiter: Arc::clone(self),
            ip,
            held: true,
        })
    }

    fn release(&self, ip: IpAddr) {
        let mut inflight = self
            .inflight
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let last = match inflight.get_mut(&ip) {
            Some(count) => {
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => false,
        };
        if last {
            // Dropping empty entries keeps the map bounded by live sources
            // instead of by every address ever seen.
            inflight.remove(&ip);
        }
    }
}

/// One held unauthenticated connection slot.
struct UnauthSlot {
    limiter: Arc<UnauthLimiter>,
    ip: IpAddr,
    held: bool,
}

impl UnauthSlot {
    fn release(&mut self) {
        if self.held {
            self.held = false;
            self.limiter.release(self.ip);
        }
    }
}

impl Drop for UnauthSlot {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unauthenticated_budget_is_per_source_and_released() {
        let limiter = Arc::new(UnauthLimiter::new(2));
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();

        let a = limiter.acquire(first).expect("first slot");
        let b = limiter.acquire(first).expect("second slot");
        assert!(limiter.acquire(first).is_none());
        assert!(limiter.acquire(second).is_some());

        drop(a);
        assert!(limiter.acquire(first).is_some());
        drop(b);
        assert!(limiter.acquire(first).is_some());
        // Every slot was released, so no empty entry is left behind.
        assert!(limiter.inflight.lock().unwrap().is_empty());
    }

    #[test]
    fn a_released_slot_is_not_released_twice() {
        let limiter = Arc::new(UnauthLimiter::new(1));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut slot = limiter.acquire(ip).expect("slot");
        slot.release();
        slot.release();
        assert_eq!(limiter.inflight.lock().unwrap().get(&ip), None);
        let other = limiter.acquire(ip).expect("slot after release");
        drop(other);
    }

    #[test]
    fn request_failures_are_counted_under_their_reason() {
        let counters = Counters::new();
        count_request_error(&counters, &SocksError::UnsupportedAtyp(0x02));
        count_request_error(&counters, &SocksError::UnsupportedCommand(0x09));
        count_request_error(&counters, &SocksError::PortZero);
        count_request_error(&counters, &SocksError::Malformed("rsv"));
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.get(Counter::UnsupportedAtyp), 1);
        assert_eq!(snapshot.get(Counter::UnsupportedCommand), 1);
        assert_eq!(snapshot.get(Counter::PortZeroRejected), 1);
        assert_eq!(snapshot.get(Counter::RequestMalformed), 1);
    }
}
