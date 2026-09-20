//! Message authentication for the handshake and request binding (DESIGN.md §5.1, §4.4).
//!
//! §4.1 requires that "签名输入字段有明确长度前缀" — every field that feeds a MAC
//! is length-prefixed, so that `("ab", "c")` and `("a", "bc")` cannot produce the
//! same input. [`SignedFields`] is the single encoder used for both the `Auth`
//! bootstrap MAC and the per-request `BindProof` MAC.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::keys::Psk;

type HmacSha256 = Hmac<Sha256>;

/// Length of a MAC tag in bytes (HMAC-SHA256).
pub const MAC_LEN: usize = 32;

/// A length-prefixed MAC input.
///
/// The encoding is `u32be(len) || bytes` for every field. A `u32` prefix is used
/// uniformly (even for single-byte fields) so that the encoding is trivially
/// unambiguous and cannot be confused with a differently-typed field.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SignedFields {
    buf: Vec<u8>,
}

impl SignedFields {
    /// An empty signing input.
    pub fn new() -> Self {
        SignedFields { buf: Vec::new() }
    }

    /// Appends a variable-length field.
    pub fn push_bytes(mut self, field: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&(field.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(field);
        self
    }

    /// Appends a string field.
    pub fn push_str(self, field: &str) -> Self {
        self.push_bytes(field.as_bytes())
    }

    /// Appends an unsigned integer field in big-endian form.
    pub fn push_u64(mut self, value: u64) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a 32-bit field in big-endian form.
    pub fn push_u32(mut self, value: u32) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a 16-bit field in big-endian form.
    pub fn push_u16(mut self, value: u16) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Appends a single byte.
    pub fn push_u8(mut self, value: u8) -> Self {
        self.buf.push(value);
        self
    }

    /// The encoded signing input.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consumes the builder and returns the encoded signing input.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// `HMAC-SHA256(key, message)`.
pub fn mac(key: &[u8], message: &[u8]) -> [u8; MAC_LEN] {
    // HMAC accepts a key of any length.
    let mut hasher = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    hasher.update(message);
    hasher.finalize().into_bytes().into()
}

/// MACs one signing input with the pre-shared key.
///
/// The `Auth` bootstrap runs before any session key exists, so it is keyed
/// directly by the node PSK (§5.1).
pub fn psk_mac(psk: &Psk, fields: &SignedFields) -> [u8; MAC_LEN] {
    mac(psk.as_bytes(), fields.as_bytes())
}

/// Verifies a PSK MAC in constant time.
pub fn verify_psk_mac(psk: &Psk, fields: &SignedFields, tag: &[u8]) -> bool {
    verify(tag, &psk_mac(psk, fields))
}

/// MACs one signing input with the binding key `K_bind` (§4.4).
pub fn bind_mac(bind_key: &[u8; 32], fields: &SignedFields) -> [u8; MAC_LEN] {
    mac(bind_key, fields.as_bytes())
}

/// Verifies a binding MAC in constant time.
pub fn verify_bind_mac(bind_key: &[u8; 32], fields: &SignedFields, tag: &[u8]) -> bool {
    verify(tag, &bind_mac(bind_key, fields))
}

/// Constant-time tag comparison.
///
/// §5.1 requires "恒定时间校验 MAC". A length mismatch is a fast, non-secret
/// rejection; comparison of equal-length tags is constant time.
fn verify(candidate: &[u8], expected: &[u8; MAC_LEN]) -> bool {
    if candidate.len() != MAC_LEN {
        return false;
    }
    candidate.ct_eq(expected.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> Psk {
        Psk::from_bytes([5u8; 32])
    }

    #[test]
    fn mac_is_deterministic_and_keyed() {
        let fields = SignedFields::new().push_str("node-a");
        let a = psk_mac(&psk(), &fields);
        assert_eq!(a, psk_mac(&psk(), &fields));
        let other = Psk::from_bytes([6u8; 32]);
        assert_ne!(a, psk_mac(&other, &fields));
    }

    /// The whole point of length prefixing: field boundaries must be significant.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let split_left = SignedFields::new().push_str("ab").push_str("c");
        let split_right = SignedFields::new().push_str("a").push_str("bc");
        assert_ne!(split_left.as_bytes(), split_right.as_bytes());
        assert_ne!(psk_mac(&psk(), &split_left), psk_mac(&psk(), &split_right));
    }

    /// A variable-length field must not be able to masquerade as a fixed-width one.
    #[test]
    fn variable_and_fixed_fields_do_not_collide() {
        let as_bytes = SignedFields::new().push_bytes(&[0, 0, 0, 1]);
        let as_u32 = SignedFields::new().push_u32(1);
        assert_ne!(as_bytes.as_bytes(), as_u32.as_bytes());
    }

    #[test]
    fn verification_accepts_the_correct_tag() {
        let fields = SignedFields::new()
            .push_str("client-a")
            .push_u64(1_700_000_000);
        let tag = psk_mac(&psk(), &fields);
        assert!(verify_psk_mac(&psk(), &fields, &tag));
    }

    #[test]
    fn verification_rejects_a_modified_tag() {
        let fields = SignedFields::new().push_str("client-a");
        let mut tag = psk_mac(&psk(), &fields);
        for i in 0..MAC_LEN {
            let original = tag[i];
            tag[i] ^= 0x01;
            assert!(
                !verify_psk_mac(&psk(), &fields, &tag),
                "byte {i} not covered"
            );
            tag[i] = original;
        }
    }

    #[test]
    fn verification_rejects_a_modified_field() {
        let fields = SignedFields::new().push_str("client-a").push_u64(1);
        let tag = psk_mac(&psk(), &fields);
        let tampered = SignedFields::new().push_str("client-b").push_u64(1);
        assert!(!verify_psk_mac(&psk(), &tampered, &tag));
        let tampered = SignedFields::new().push_str("client-a").push_u64(2);
        assert!(!verify_psk_mac(&psk(), &tampered, &tag));
    }

    /// A truncated or oversized tag must be a clean rejection, not a panic.
    #[test]
    fn malformed_tag_lengths_are_rejected() {
        let fields = SignedFields::new().push_str("x");
        let tag = psk_mac(&psk(), &fields);
        assert!(!verify_psk_mac(&psk(), &fields, &[]));
        assert!(!verify_psk_mac(&psk(), &fields, &tag[..MAC_LEN - 1]));
        let mut long = tag.to_vec();
        long.push(0);
        assert!(!verify_psk_mac(&psk(), &fields, &long));
    }

    #[test]
    fn binding_mac_uses_the_binding_key() {
        let bind_key = [0x11u8; 32];
        let fields = SignedFields::new()
            .push_str("POST")
            .push_str("/m")
            .push_str("hub-a")
            .push_u64(1_700_000_000);
        let tag = bind_mac(&bind_key, &fields);
        assert!(verify_bind_mac(&bind_key, &fields, &tag));
        assert!(!verify_bind_mac(&[0x12u8; 32], &fields, &tag));
    }

    /// The binding key and the message keys are independent.
    #[test]
    fn binding_and_psk_macs_differ() {
        let fields = SignedFields::new().push_str("same input");
        let bind_key = [0x11u8; 32];
        assert_ne!(bind_mac(&bind_key, &fields), psk_mac(&psk(), &fields));
    }

    #[test]
    fn empty_signing_input_is_well_defined() {
        let fields = SignedFields::new();
        assert!(fields.as_bytes().is_empty());
        let tag = psk_mac(&psk(), &fields);
        assert!(verify_psk_mac(&psk(), &fields, &tag));
    }

    #[test]
    fn push_bytes_records_the_length_prefix() {
        let fields = SignedFields::new().push_bytes(b"abc");
        assert_eq!(fields.as_bytes(), &[0, 0, 0, 3, b'a', b'b', b'c']);
    }
}
