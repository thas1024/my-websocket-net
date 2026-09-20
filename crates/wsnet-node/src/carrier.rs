//! Carrier channels: sealed envelopes in, sealed envelopes out.
//!
//! A carrier moves the bytes [`wsnet_crypto::seal`] produced and nothing else, so
//! the node's session driver never learns whether an envelope arrived over a
//! WebSocket, a `POST /m` response, or an SSE event. What it does learn is the
//! carrier's *kind*, because section 6.1 makes uplink capability a property of
//! the carrier rather than a convention the scheduler is trusted to remember.

use tokio::sync::mpsc;

/// Which carrier implementation a [`CarrierIo`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CarrierKind {
    /// A WebSocket binary message per envelope.
    Ws,
    /// `POST /m` request or response bodies.
    Post,
    /// A server-sent event stream.
    Sse,
}

impl CarrierKind {
    /// A stable, log-safe name.
    pub const fn name(self) -> &'static str {
        match self {
            CarrierKind::Ws => "ws",
            CarrierKind::Post => "post",
            CarrierKind::Sse => "sse",
        }
    }

    /// Whether this carrier may carry client-to-server business data.
    ///
    /// DESIGN.md section 6.1: "C→S 可选 WS 或 HTTPS POST ... 不可选择 SSE". SSE is
    /// a downlink-only carrier, so an SSE channel is never drained into an uplink.
    pub const fn is_uplink_capable(self) -> bool {
        !matches!(self, CarrierKind::Sse)
    }
}

/// One established carrier, as a pair of sealed-envelope channels.
///
/// The transport owns the socket or HTTP request and pumps it; the node owns the
/// two channels. Dropping the whole value (or the receiver half) ends the
/// carrier, which is how a failed carrier is torn down.
pub struct CarrierIo {
    /// Which carrier this is.
    pub kind: CarrierKind,
    /// Sealed envelopes arriving from the Hub.
    pub inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Sealed envelopes the carrier must send.
    ///
    /// This half is unused, and therefore dropped, for a carrier that is not
    /// uplink capable.
    pub outbound: mpsc::UnboundedSender<Vec<u8>>,
}

impl CarrierIo {
    /// Builds a carrier from both halves.
    pub fn new(
        kind: CarrierKind,
        inbound: mpsc::UnboundedReceiver<Vec<u8>>,
        outbound: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        CarrierIo {
            kind,
            inbound,
            outbound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Section 6.1: SSE must never be selected as an uplink.
    #[test]
    fn sse_is_downlink_only() {
        assert!(!CarrierKind::Sse.is_uplink_capable());
        assert!(CarrierKind::Ws.is_uplink_capable());
        assert!(CarrierKind::Post.is_uplink_capable());
    }

    #[test]
    fn names_are_distinct() {
        let names = [
            CarrierKind::Ws.name(),
            CarrierKind::Post.name(),
            CarrierKind::Sse.name(),
        ];
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
    }
}
