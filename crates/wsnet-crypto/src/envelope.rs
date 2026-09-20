//! The protected-record envelope (DESIGN.md §4.2).
//!
//! ```text
//! version:u8 | session_epoch:16B | packet_no:u64be | ciphertext_and_tag
//! ```
//!
//! Associated data binds the record to its session, so a record lifted out of one
//! `(hub_id, session_id, session_epoch)` context — or replayed back in the other
//! direction — fails authentication rather than being decrypted (T01).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::keys::Direction;
use crate::packet_no::PacketNo;
use wsnet_limits::{AEAD_TAG_LEN, ENVELOPE_HEADER_LEN, NONCE_LEN, SESSION_EPOCH_LEN};

/// Domain-separation constant prefixed to every AAD (§4.2).
///
/// Aliased to the single definition in `wsnet-limits` so that the protocol and
/// crypto crates can never drift apart on the domain string.
pub const AAD_DOMAIN: &[u8] = wsnet_limits::AAD_CONTEXT;

/// Errors from sealing or opening an envelope.
///
/// Decryption failures are deliberately collapsed into [`EnvelopeError::AuthFailed`]:
/// distinguishing "wrong key" from "tampered ciphertext" would hand an attacker a
/// decryption oracle.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The envelope is shorter than its fixed header plus the AEAD tag.
    #[error("envelope is {actual} bytes, minimum is {minimum}")]
    TooShort {
        /// Observed length.
        actual: usize,
        /// Header plus tag.
        minimum: usize,
    },
    /// The version byte is not the one this build speaks.
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    /// The cleartext epoch does not match the session's epoch.
    #[error("session epoch mismatch")]
    EpochMismatch,
    /// Authentication failed: wrong key, wrong context, or modified ciphertext.
    #[error("envelope authentication failed")]
    AuthFailed,
}

/// The `(hub_id, session_id, session_epoch)` triple an envelope is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeContext {
    /// Stable identifier of the Hub this session belongs to.
    pub hub_id: String,
    /// Session identifier; a routing label, never a bearer credential (§4.4).
    pub session_id: [u8; 16],
    /// Epoch of this session's key material.
    pub session_epoch: [u8; SESSION_EPOCH_LEN],
}

impl EnvelopeContext {
    /// Builds a context.
    pub fn new(
        hub_id: impl Into<String>,
        session_id: [u8; 16],
        session_epoch: [u8; SESSION_EPOCH_LEN],
    ) -> Self {
        EnvelopeContext {
            hub_id: hub_id.into(),
            session_id,
            session_epoch,
        }
    }
}

/// Builds the AEAD associated data.
///
/// Every variable-length field is length-prefixed so that no two distinct
/// `(hub_id, session_id, session_epoch, direction)` tuples can produce the same
/// bytes ("上述明文头的长度前缀编码").
pub fn build_aad(ctx: &EnvelopeContext, direction: Direction) -> Vec<u8> {
    let hub = ctx.hub_id.as_bytes();
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 8 + hub.len() + 16 + 16 + 3);
    aad.extend_from_slice(AAD_DOMAIN);
    push_len_prefixed(&mut aad, &[crate::PROTOCOL_VERSION]);
    push_len_prefixed(&mut aad, hub);
    push_len_prefixed(&mut aad, &ctx.session_id);
    push_len_prefixed(&mut aad, &ctx.session_epoch);
    push_len_prefixed(&mut aad, &[direction.as_u8()]);
    aad
}

fn push_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    // A u16 prefix is enough for every field bound to the AAD (hub_id is itself
    // bounded by configuration), and keeps the encoding unambiguous.
    debug_assert!(field.len() <= u16::MAX as usize);
    out.extend_from_slice(&(field.len() as u16).to_be_bytes());
    out.extend_from_slice(field);
}

/// Builds the `0x00000000:u32 | packet_no:u64be` AEAD nonce (§4.2).
pub fn build_nonce(packet_no: PacketNo) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&packet_no.to_be_bytes());
    nonce
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    // The key is a `[u8; 32]`, so `from_slice` cannot panic here.
    ChaCha20Poly1305::new(Key::from_slice(key))
}

/// Seals one record plaintext into a full envelope.
///
/// `packet_no` comes from the direction's allocator, so the nonce can never
/// repeat for a given key.
pub fn seal(
    key: &[u8; 32],
    ctx: &EnvelopeContext,
    direction: Direction,
    packet_no: PacketNo,
    plaintext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let aad = build_aad(ctx, direction);
    // `build_nonce` always returns exactly NONCE_LEN bytes, so `from_slice`
    // cannot panic here.
    let nonce_bytes = build_nonce(packet_no);
    let ciphertext = cipher(key)
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::AuthFailed)?;

    let mut out = Vec::with_capacity(ENVELOPE_HEADER_LEN + ciphertext.len());
    out.push(crate::PROTOCOL_VERSION);
    out.extend_from_slice(&ctx.session_epoch);
    out.extend_from_slice(&packet_no.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// A successfully opened envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedEnvelope {
    /// The counter value carried in the cleartext header.
    ///
    /// It is only trustworthy *after* authentication succeeds, which is why it is
    /// returned from here rather than parsed separately by the replay window.
    pub packet_no: u64,
    /// The decrypted record plaintext.
    pub plaintext: Vec<u8>,
}

/// Opens an envelope, verifying version, epoch, and AEAD tag.
pub fn open(
    key: &[u8; 32],
    ctx: &EnvelopeContext,
    direction: Direction,
    envelope: &[u8],
) -> Result<OpenedEnvelope, EnvelopeError> {
    let minimum = ENVELOPE_HEADER_LEN + AEAD_TAG_LEN;
    if envelope.len() < minimum {
        return Err(EnvelopeError::TooShort {
            actual: envelope.len(),
            minimum,
        });
    }
    let version = envelope[0];
    if version != crate::PROTOCOL_VERSION {
        return Err(EnvelopeError::UnsupportedVersion(version));
    }
    let epoch = &envelope[1..1 + SESSION_EPOCH_LEN];
    if epoch != ctx.session_epoch {
        return Err(EnvelopeError::EpochMismatch);
    }
    let mut packet_bytes = [0u8; 8];
    packet_bytes.copy_from_slice(&envelope[1 + SESSION_EPOCH_LEN..ENVELOPE_HEADER_LEN]);
    let packet_no = u64::from_be_bytes(packet_bytes);

    let aad = build_aad(ctx, direction);
    let nonce_bytes = build_nonce(PacketNo::from_raw(packet_no));
    let plaintext = cipher(key)
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &envelope[ENVELOPE_HEADER_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::AuthFailed)?;

    Ok(OpenedEnvelope {
        packet_no,
        plaintext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Psk, SessionKeys};
    use crate::packet_no::PacketNoAllocator;

    const KEY: [u8; 32] = [0x42; 32];

    fn ctx() -> EnvelopeContext {
        EnvelopeContext::new("hub-a", [1u8; 16], [2u8; 16])
    }

    fn alloc() -> PacketNoAllocator {
        PacketNoAllocator::new()
    }

    #[test]
    fn nonce_layout_is_four_zero_bytes_then_big_endian_counter() {
        let a = alloc();
        let nonce = build_nonce(a.reserve_exact(0x0102_0304_0506_0708).unwrap());
        assert_eq!(
            nonce,
            [0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(&build_nonce(a.allocate().unwrap())[0..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn seal_open_round_trip() {
        let a = alloc();
        let n = a.allocate().unwrap();
        let envelope = seal(&KEY, &ctx(), Direction::ClientToServer, n, b"record bytes").unwrap();
        let opened = open(&KEY, &ctx(), Direction::ClientToServer, &envelope).unwrap();
        assert_eq!(opened.packet_no, 0);
        assert_eq!(opened.plaintext, b"record bytes");
    }

    #[test]
    fn header_layout_matches_the_documented_order() {
        let a = alloc();
        let n = a.reserve_exact(7).unwrap();
        let envelope = seal(&KEY, &ctx(), Direction::ClientToServer, n, b"x").unwrap();
        assert_eq!(envelope[0], crate::PROTOCOL_VERSION);
        assert_eq!(&envelope[1..17], &[2u8; 16]);
        assert_eq!(&envelope[17..25], &7u64.to_be_bytes());
        // ciphertext + 16-byte tag
        assert_eq!(envelope.len(), ENVELOPE_HEADER_LEN + 1 + AEAD_TAG_LEN);
    }

    #[test]
    fn empty_plaintext_is_representable() {
        let a = alloc();
        let n = a.allocate().unwrap();
        let envelope = seal(&KEY, &ctx(), Direction::ClientToServer, n, b"").unwrap();
        assert_eq!(envelope.len(), ENVELOPE_HEADER_LEN + AEAD_TAG_LEN);
        assert!(open(&KEY, &ctx(), Direction::ClientToServer, &envelope)
            .unwrap()
            .plaintext
            .is_empty());
    }

    /// T01: a record cannot be reflected back at its sender.
    #[test]
    fn opposite_direction_fails_authentication() {
        let a = alloc();
        let n = a.allocate().unwrap();
        let envelope = seal(&KEY, &ctx(), Direction::ClientToServer, n, b"business").unwrap();
        assert_eq!(
            open(&KEY, &ctx(), Direction::ServerToClient, &envelope).unwrap_err(),
            EnvelopeError::AuthFailed
        );
    }

    /// T01: separate direction keys mean reflection fails even with symmetric
    /// AAD handling.
    #[test]
    fn separate_direction_keys_cannot_cross_open() {
        let psk = Psk::from_bytes([3u8; 32]);
        let keys = SessionKeys::derive(&psk, b"auth", b"authok");
        let a = alloc();
        let n = a.allocate().unwrap();
        let envelope = seal(
            keys.message_key(Direction::ClientToServer),
            &ctx(),
            Direction::ClientToServer,
            n,
            b"business",
        )
        .unwrap();
        assert_eq!(
            open(
                keys.message_key(Direction::ServerToClient),
                &ctx(),
                Direction::ClientToServer,
                &envelope
            )
            .unwrap_err(),
            EnvelopeError::AuthFailed
        );
    }

    /// T01: changing the Hub or the epoch must break verification.
    #[test]
    fn aad_binds_hub_session_and_epoch() {
        let a = alloc();
        let n = a.allocate().unwrap();
        let envelope = seal(&KEY, &ctx(), Direction::ClientToServer, n, b"business").unwrap();

        let other_hub = EnvelopeContext::new("hub-b", [1u8; 16], [2u8; 16]);
        assert_eq!(
            open(&KEY, &other_hub, Direction::ClientToServer, &envelope).unwrap_err(),
            EnvelopeError::AuthFailed
        );

        let other_session = EnvelopeContext::new("hub-a", [9u8; 16], [2u8; 16]);
        assert_eq!(
            open(&KEY, &other_session, Direction::ClientToServer, &envelope).unwrap_err(),
            EnvelopeError::AuthFailed
        );

        // A different epoch is rejected on the cleartext header, before decryption.
        let other_epoch = EnvelopeContext::new("hub-a", [1u8; 16], [9u8; 16]);
        assert_eq!(
            open(&KEY, &other_epoch, Direction::ClientToServer, &envelope).unwrap_err(),
            EnvelopeError::EpochMismatch
        );
    }

    /// Distinct hub ids of different lengths must not collide in the AAD.
    #[test]
    fn aad_length_prefixing_is_unambiguous() {
        let a = build_aad(
            &EnvelopeContext::new("ab", [1u8; 16], [2u8; 16]),
            Direction::ClientToServer,
        );
        let b = build_aad(
            &EnvelopeContext::new("a", [0xb1u8; 16], [2u8; 16]),
            Direction::ClientToServer,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn tampering_is_detected() {
        let a = alloc();
        let n = a.allocate().unwrap();
        let envelope = seal(&KEY, &ctx(), Direction::ClientToServer, n, b"business").unwrap();

        for i in 0..envelope.len() {
            let mut tampered = envelope.clone();
            tampered[i] ^= 0x01;
            // Flipping the version byte or epoch is caught before decryption;
            // everything else must fail authentication.
            assert!(
                open(&KEY, &ctx(), Direction::ClientToServer, &tampered).is_err(),
                "tampering at byte {i} was not detected"
            );
        }
    }

    #[test]
    fn wrong_key_fails() {
        let a = alloc();
        let n = a.allocate().unwrap();
        let envelope = seal(&KEY, &ctx(), Direction::ClientToServer, n, b"business").unwrap();
        assert_eq!(
            open(&[0x43; 32], &ctx(), Direction::ClientToServer, &envelope).unwrap_err(),
            EnvelopeError::AuthFailed
        );
    }

    #[test]
    fn short_and_empty_envelopes_are_rejected() {
        for len in 0..(ENVELOPE_HEADER_LEN + AEAD_TAG_LEN) {
            let input = vec![0u8; len];
            assert!(matches!(
                open(&KEY, &ctx(), Direction::ClientToServer, &input).unwrap_err(),
                EnvelopeError::TooShort { .. }
            ));
        }
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut envelope = vec![0u8; ENVELOPE_HEADER_LEN + AEAD_TAG_LEN];
        envelope[0] = 99;
        assert_eq!(
            open(&KEY, &ctx(), Direction::ClientToServer, &envelope).unwrap_err(),
            EnvelopeError::UnsupportedVersion(99)
        );
    }

    /// §4.2: a fresh nonce per record means identical plaintext produces
    /// different ciphertext.
    #[test]
    fn each_packet_no_produces_a_distinct_envelope() {
        let a = alloc();
        let first = seal(
            &KEY,
            &ctx(),
            Direction::ClientToServer,
            a.allocate().unwrap(),
            b"same",
        )
        .unwrap();
        let second = seal(
            &KEY,
            &ctx(),
            Direction::ClientToServer,
            a.allocate().unwrap(),
            b"same",
        )
        .unwrap();
        assert_ne!(first, second);
        assert_ne!(
            &first[ENVELOPE_HEADER_LEN..],
            &second[ENVELOPE_HEADER_LEN..]
        );
    }

    #[test]
    fn packet_no_is_only_trusted_after_authentication() {
        // Rewriting the cleartext counter changes the nonce, so the tag no
        // longer verifies: the reported counter cannot be attacker-controlled.
        let a = alloc();
        let n = a.allocate().unwrap();
        let mut envelope = seal(&KEY, &ctx(), Direction::ClientToServer, n, b"business").unwrap();
        envelope[ENVELOPE_HEADER_LEN - 1] = 9;
        assert_eq!(
            open(&KEY, &ctx(), Direction::ClientToServer, &envelope).unwrap_err(),
            EnvelopeError::AuthFailed
        );
    }
}
