//! wsnet v1 cryptography.
//!
//! Implements exactly the primitives `docs/DESIGN.md` §4.2/§5.1 specifies, using
//! established constructions and no bespoke cryptography:
//!
//! * HMAC-SHA256 for handshake and binding MACs ([`mac`]);
//! * HKDF-SHA256 for direction-isolated message keys ([`keys`]);
//! * ChaCha20-Poly1305 for the record envelope ([`envelope`]).
//!
//! Two invariants are enforced by the type system rather than by convention:
//!
//! * [`keys::Psk`] is fixed at 32 bytes and never prints its contents.
//! * [`packet_no::PacketNo`] cannot be built from an arbitrary integer, so a
//!   caller cannot accidentally reuse an AEAD nonce; [`open`] only yields one
//!   after authentication succeeds.
//!
//! Out of scope by design: this crate does not implement TLS. §5.4 keeps the
//! outer standard TLS stack, with certificate verification and forward secrecy
//! enabled, as the transport's job.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod keys;
pub mod mac;
pub mod packet_no;

pub use envelope::{
    build_aad, build_nonce, open, seal, EnvelopeContext, EnvelopeError, OpenedEnvelope, AAD_DOMAIN,
};
pub use keys::{Direction, KeyError, Psk, SessionKeys};
pub use mac::{bind_mac, psk_mac, verify_bind_mac, verify_psk_mac, SignedFields, MAC_LEN};
pub use packet_no::{PacketNo, PacketNoAllocator, PacketNoError, PACKET_NO_CEILING};

/// `HMAC-SHA256(key, message)`.
///
/// Re-exported at the crate root for callers that already hold raw key bytes.
pub use mac::mac;

/// Protocol version this build speaks.
pub use wsnet_limits::PROTOCOL_VERSION;
