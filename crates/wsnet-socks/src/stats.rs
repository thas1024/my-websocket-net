//! Shared counters for the inbound SOCKS5 server.
//!
//! DESIGN.md section 7.4 requires every dropped datagram to be counted and
//! section 9.2 requires the entry point to keep its own budgets, so outcomes are
//! recorded in cheap atomics instead of only being logged. A caller exposes them
//! through [`SocksStats`]; the data path never allocates to count.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// One observable outcome of the inbound SOCKS5 server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Counter {
    /// A TCP connection was accepted by the listener.
    ConnectionsAccepted,
    /// A connection was refused because one source address already held
    /// `MAX_UNAUTH_CONNECTIONS_PER_IP` unauthenticated connections (section 9.2).
    ConnectionLimitDropped,
    /// A connection was refused because its source address is not allowlisted
    /// (section 9.3).
    SourceDenied,
    /// Method negotiation or the request did not arrive inside the handshake
    /// deadline (section 9.2).
    HandshakeTimeout,
    /// The client was admitted without authentication.
    MethodNoAuthAccepted,
    /// The client authenticated with RFC 1929 username/password.
    MethodUserPassAccepted,
    /// The client offered no method this server can accept.
    MethodRejected,
    /// RFC 1929 credentials did not match the configured pair.
    AuthFailed,
    /// A version, reserved-field, or framing violation.
    RequestMalformed,
    /// `ATYP` was neither 1, 3, nor 4.
    UnsupportedAtyp,
    /// `CMD` was neither CONNECT nor an enabled UDP ASSOCIATE.
    UnsupportedCommand,
    /// The requested destination port was 0.
    PortZeroRejected,
    /// A CONNECT was established and proxied.
    ConnectSucceeded,
    /// The handler refused or failed a CONNECT.
    ConnectFailed,
    /// A UDP association was established.
    UdpAssociateStarted,
    /// A UDP association ended, for any reason.
    UdpAssociationEnded,
    /// A datagram was handed to the handler for relaying.
    UdpRelayed,
    /// A relayed reply was rewritten and sent back to the client.
    UdpRepliesSent,
    /// Sending a rewritten reply on the association socket failed.
    UdpSendFailed,
    /// `FRAG != 0`: SOCKS5 UDP fragmentation is not supported (section 7.4).
    UdpFragDropped,
    /// The datagram header was not a valid SOCKS5 UDP header.
    UdpMalformedDropped,
    /// A datagram or reply exceeded the configured payload bound.
    UdpOversizedDropped,
    /// The datagram source address matched neither the TCP peer nor the
    /// allowlist (section 7.4).
    UdpSourceMismatchDropped,
    /// The datagram source endpoint changed after the first datagram locked it
    /// (section 7.4).
    UdpSourceDriftDropped,
    /// The association already tracked `MAX_UDP_TARGETS_PER_ASSOCIATION` targets.
    UdpTargetLimitDropped,
    /// The bounded send queue was full.
    UdpQueueOverflowDropped,
    /// A queued datagram passed its monotonic TTL before it could be handed over.
    UdpTtlExpiredDropped,
    /// A reply named a target this association never mapped.
    UdpUnmappedReplyDropped,
    /// A reply claimed a source address that is not the mapped target.
    UdpUnexpectedSourceDropped,
}

impl Counter {
    /// Number of counters, equal to [`Counter::ALL`]'s length.
    pub const COUNT: usize = 29;

    /// Every counter, in discriminant order.
    pub const ALL: [Counter; Counter::COUNT] = [
        Counter::ConnectionsAccepted,
        Counter::ConnectionLimitDropped,
        Counter::SourceDenied,
        Counter::HandshakeTimeout,
        Counter::MethodNoAuthAccepted,
        Counter::MethodUserPassAccepted,
        Counter::MethodRejected,
        Counter::AuthFailed,
        Counter::RequestMalformed,
        Counter::UnsupportedAtyp,
        Counter::UnsupportedCommand,
        Counter::PortZeroRejected,
        Counter::ConnectSucceeded,
        Counter::ConnectFailed,
        Counter::UdpAssociateStarted,
        Counter::UdpAssociationEnded,
        Counter::UdpRelayed,
        Counter::UdpRepliesSent,
        Counter::UdpSendFailed,
        Counter::UdpFragDropped,
        Counter::UdpMalformedDropped,
        Counter::UdpOversizedDropped,
        Counter::UdpSourceMismatchDropped,
        Counter::UdpSourceDriftDropped,
        Counter::UdpTargetLimitDropped,
        Counter::UdpQueueOverflowDropped,
        Counter::UdpTtlExpiredDropped,
        Counter::UdpUnmappedReplyDropped,
        Counter::UdpUnexpectedSourceDropped,
    ];

    /// Index of this counter inside the statistics arrays.
    pub fn index(self) -> usize {
        self as usize
    }

    /// Stable name, used by [`SocksStats`]'s `Debug` output and by logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Counter::ConnectionsAccepted => "connections_accepted",
            Counter::ConnectionLimitDropped => "connection_limit_dropped",
            Counter::SourceDenied => "source_denied",
            Counter::HandshakeTimeout => "handshake_timeout",
            Counter::MethodNoAuthAccepted => "method_no_auth_accepted",
            Counter::MethodUserPassAccepted => "method_userpass_accepted",
            Counter::MethodRejected => "method_rejected",
            Counter::AuthFailed => "auth_failed",
            Counter::RequestMalformed => "request_malformed",
            Counter::UnsupportedAtyp => "unsupported_atyp",
            Counter::UnsupportedCommand => "unsupported_command",
            Counter::PortZeroRejected => "port_zero_rejected",
            Counter::ConnectSucceeded => "connect_succeeded",
            Counter::ConnectFailed => "connect_failed",
            Counter::UdpAssociateStarted => "udp_associate_started",
            Counter::UdpAssociationEnded => "udp_association_ended",
            Counter::UdpRelayed => "udp_relayed",
            Counter::UdpRepliesSent => "udp_replies_sent",
            Counter::UdpSendFailed => "udp_send_failed",
            Counter::UdpFragDropped => "udp_frag_dropped",
            Counter::UdpMalformedDropped => "udp_malformed_dropped",
            Counter::UdpOversizedDropped => "udp_oversized_dropped",
            Counter::UdpSourceMismatchDropped => "udp_source_mismatch_dropped",
            Counter::UdpSourceDriftDropped => "udp_source_drift_dropped",
            Counter::UdpTargetLimitDropped => "udp_target_limit_dropped",
            Counter::UdpQueueOverflowDropped => "udp_queue_overflow_dropped",
            Counter::UdpTtlExpiredDropped => "udp_ttl_expired_dropped",
            Counter::UdpUnmappedReplyDropped => "udp_unmapped_reply_dropped",
            Counter::UdpUnexpectedSourceDropped => "udp_unexpected_source_dropped",
        }
    }
}

/// The shared atomic counters of one server instance.
#[derive(Debug)]
pub(crate) struct Counters {
    slots: [AtomicU64; Counter::COUNT],
}

impl Counters {
    /// Creates a zeroed counter set.
    pub(crate) fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Adds one to `counter`.
    pub(crate) fn inc(&self, counter: Counter) {
        self.add(counter, 1);
    }

    /// Adds `n` to `counter`.
    pub(crate) fn add(&self, counter: Counter, n: u64) {
        // Relaxed is enough: these are monotone tallies read for reporting, not
        // synchronisation that orders any other memory.
        self.slots[counter.index()].fetch_add(n, Ordering::Relaxed);
    }

    /// Reads one counter.
    pub(crate) fn get(&self, counter: Counter) -> u64 {
        self.slots[counter.index()].load(Ordering::Relaxed)
    }

    /// Copies the whole set.
    pub(crate) fn snapshot(&self) -> SocksStats {
        SocksStats {
            slots: std::array::from_fn(|i| self.slots[i].load(Ordering::Relaxed)),
        }
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

/// A consistent-enough copy of all counters.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SocksStats {
    slots: [u64; Counter::COUNT],
}

impl SocksStats {
    /// Reads one counter out of the snapshot.
    pub fn get(&self, counter: Counter) -> u64 {
        self.slots[counter.index()]
    }
}

impl fmt::Debug for SocksStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_map();
        for counter in Counter::ALL {
            let value = self.get(counter);
            if value != 0 {
                out.entry(&counter.as_str(), &value);
            }
        }
        out.finish()
    }
}

/// A cloneable handle that keeps reading live statistics from a running server.
///
/// [`crate::Socks5Server::run`] consumes the server, so this handle is taken
/// beforehand when a caller wants to report statistics while it runs.
#[derive(Clone, Debug)]
pub struct StatsHandle(Arc<Counters>);

impl StatsHandle {
    /// Creates a handle over an existing counter set.
    pub(crate) fn new(counters: Arc<Counters>) -> Self {
        Self(counters)
    }

    /// Copies every counter.
    pub fn snapshot(&self) -> SocksStats {
        self.0.snapshot()
    }

    /// Reads one counter.
    pub fn get(&self, counter: Counter) -> u64 {
        self.0.get(counter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gapped or reordered `ALL` would silently alias two counters onto one
    /// slot, so the mapping from variant to array index is pinned here.
    #[test]
    fn counter_indices_are_dense_and_in_order() {
        assert_eq!(Counter::ALL.len(), Counter::COUNT);
        for (expected, counter) in Counter::ALL.iter().enumerate() {
            assert_eq!(counter.index(), expected, "{counter:?}");
            assert!(!counter.as_str().is_empty());
        }
    }

    #[test]
    fn counters_are_independent() {
        let counters = Counters::new();
        counters.inc(Counter::UdpFragDropped);
        counters.add(Counter::UdpRelayed, 3);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.get(Counter::UdpFragDropped), 1);
        assert_eq!(snapshot.get(Counter::UdpRelayed), 3);
        assert_eq!(snapshot.get(Counter::SourceDenied), 0);
    }
}
