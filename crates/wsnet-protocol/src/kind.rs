//! Protocol version and message kinds (DESIGN.md §4.1).

use wsnet_limits::{MAX_TCP_PAYLOAD, MAX_UDP_PAYLOAD};

/// Protocol version bound into the handshake and into the AEAD associated data.
pub use wsnet_limits::PROTOCOL_VERSION;

/// Constant prefix of the AEAD associated data (§4.2).
pub use wsnet_limits::AAD_CONTEXT;

/// The `kind` discriminant of one wsnet record.
///
/// The numbering is part of the wire contract: it is authenticated inside the
/// envelope, so the values must never be reordered or reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum MessageKind {
    /// TLS-inner authentication bootstrap; no session key exists yet.
    Auth = 1,
    /// Authentication response whose MAC binds the full request digest.
    AuthOk = 2,
    /// Registration completion barrier.
    Hello = 3,
    /// Registration acknowledgement; business `Open` is refused before this.
    HelloOk = 4,
    /// Idempotent stream establishment.
    Open = 5,
    /// Result of a cached or freshly executed `Open`.
    OpenResult = 6,
    /// Caller-initiated query of a cached operation result.
    QueryResult = 7,
    /// Both receive halves are installed; target-originated data may flow.
    Ready = 8,
    /// Cumulative receive acknowledgement and byte credit (§7.5).
    Progress = 9,
    /// In-session carrier recovery; never opens a second target socket.
    Resume = 10,
    /// Releases a losing authentication/binding candidate.
    CancelCandidate = 11,
    /// Session close.
    Bye = 12,
    /// Keepalive.
    Ping = 13,
    /// Keepalive response.
    Pong = 14,
    /// Versioned registration snapshot, scoped to what the caller may see.
    PeerList = 15,
    /// Ordered TCP stream bytes.
    Data = 16,
    /// One complete UDP datagram.
    Datagram = 17,
    /// Half-close carrying the final offset.
    Fin = 18,
    /// Termination. Never a substitute for a half-close.
    Reset = 19,
}

impl MessageKind {
    /// Every kind, in wire order.
    pub const ALL: [MessageKind; 19] = [
        MessageKind::Auth,
        MessageKind::AuthOk,
        MessageKind::Hello,
        MessageKind::HelloOk,
        MessageKind::Open,
        MessageKind::OpenResult,
        MessageKind::QueryResult,
        MessageKind::Ready,
        MessageKind::Progress,
        MessageKind::Resume,
        MessageKind::CancelCandidate,
        MessageKind::Bye,
        MessageKind::Ping,
        MessageKind::Pong,
        MessageKind::PeerList,
        MessageKind::Data,
        MessageKind::Datagram,
        MessageKind::Fin,
        MessageKind::Reset,
    ];

    /// The wire discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decodes a wire discriminant, rejecting unknown kinds instead of
    /// guessing at a downgrade (§4.1: unknown required capability is refused).
    pub const fn from_u8(value: u8) -> Option<MessageKind> {
        Some(match value {
            1 => MessageKind::Auth,
            2 => MessageKind::AuthOk,
            3 => MessageKind::Hello,
            4 => MessageKind::HelloOk,
            5 => MessageKind::Open,
            6 => MessageKind::OpenResult,
            7 => MessageKind::QueryResult,
            8 => MessageKind::Ready,
            9 => MessageKind::Progress,
            10 => MessageKind::Resume,
            11 => MessageKind::CancelCandidate,
            12 => MessageKind::Bye,
            13 => MessageKind::Ping,
            14 => MessageKind::Pong,
            15 => MessageKind::PeerList,
            16 => MessageKind::Data,
            17 => MessageKind::Datagram,
            18 => MessageKind::Fin,
            19 => MessageKind::Reset,
            _ => return None,
        })
    }

    /// Whether this kind is part of the pre-session authentication bootstrap.
    pub const fn is_bootstrap(self) -> bool {
        matches!(self, MessageKind::Auth | MessageKind::AuthOk)
    }

    /// Whether this kind carries an opaque payload at all.
    pub const fn carries_payload(self) -> bool {
        matches!(self, MessageKind::Data | MessageKind::Datagram)
    }

    /// The largest payload this kind may carry (§4.1, §7.4).
    ///
    /// Every other kind is metadata-only, so a non-empty payload is a protocol
    /// error rather than something to truncate.
    pub const fn max_payload(self) -> usize {
        match self {
            MessageKind::Data => MAX_TCP_PAYLOAD,
            MessageKind::Datagram => MAX_UDP_PAYLOAD,
            _ => 0,
        }
    }

    /// A stable, log-safe name.
    pub const fn name(self) -> &'static str {
        match self {
            MessageKind::Auth => "Auth",
            MessageKind::AuthOk => "AuthOk",
            MessageKind::Hello => "Hello",
            MessageKind::HelloOk => "HelloOk",
            MessageKind::Open => "Open",
            MessageKind::OpenResult => "OpenResult",
            MessageKind::QueryResult => "QueryResult",
            MessageKind::Ready => "Ready",
            MessageKind::Progress => "Progress",
            MessageKind::Resume => "Resume",
            MessageKind::CancelCandidate => "CancelCandidate",
            MessageKind::Bye => "Bye",
            MessageKind::Ping => "Ping",
            MessageKind::Pong => "Pong",
            MessageKind::PeerList => "PeerList",
            MessageKind::Data => "Data",
            MessageKind::Datagram => "Datagram",
            MessageKind::Fin => "Fin",
            MessageKind::Reset => "Reset",
        }
    }
}

impl core::fmt::Display for MessageKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_are_stable_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for (i, kind) in MessageKind::ALL.iter().enumerate() {
            assert_eq!(kind.as_u8() as usize, i + 1, "{kind} moved");
            assert!(
                seen.insert(kind.as_u8()),
                "duplicate discriminant for {kind}"
            );
        }
        assert_eq!(seen.len(), MessageKind::ALL.len());
    }

    #[test]
    fn round_trip_through_u8() {
        for kind in MessageKind::ALL {
            assert_eq!(MessageKind::from_u8(kind.as_u8()), Some(kind));
        }
        assert_eq!(MessageKind::from_u8(0), None);
        assert_eq!(MessageKind::from_u8(20), None);
        assert_eq!(MessageKind::from_u8(255), None);
    }

    #[test]
    fn only_data_and_datagram_carry_payload() {
        for kind in MessageKind::ALL {
            match kind {
                MessageKind::Data => assert_eq!(kind.max_payload(), MAX_TCP_PAYLOAD),
                MessageKind::Datagram => assert_eq!(kind.max_payload(), MAX_UDP_PAYLOAD),
                other => {
                    assert!(!other.carries_payload(), "{other} must be metadata-only");
                    assert_eq!(other.max_payload(), 0);
                }
            }
        }
    }

    #[test]
    fn bootstrap_kinds_are_exactly_auth_and_authok() {
        let bootstrap: Vec<_> = MessageKind::ALL
            .into_iter()
            .filter(|k| k.is_bootstrap())
            .collect();
        assert_eq!(bootstrap, vec![MessageKind::Auth, MessageKind::AuthOk]);
    }
}
