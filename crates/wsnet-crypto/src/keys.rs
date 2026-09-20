//! Directional key derivation and the pre-shared key (DESIGN.md §4.2, §5.1).
//!
//! The design fixes the derivation so that both ends compute identical keys from
//! the handshake transcript:
//!
//! ```text
//! transcript = SHA256(canonical(Auth without mac) || canonical(AuthOk without mac))
//! PRK        = HKDF-Extract(salt = transcript, IKM = node_PSK)
//! K_c2s      = HKDF-Expand(PRK, "wsnet/v1/msg/c2s" || transcript, 32)
//! K_s2c      = HKDF-Expand(PRK, "wsnet/v1/msg/s2c" || transcript, 32)
//! K_bind     = HKDF-Expand(PRK, "wsnet/v1/bind"    || transcript, 32)
//! ```

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use wsnet_limits::{BIND_KEY_LEN, MSG_KEY_LEN, PSK_LEN};

/// HKDF labels, verbatim from §4.2. These are part of the wire contract: changing
/// one silently breaks interoperability with an existing peer.
mod labels {
    /// Client-to-server message key label.
    pub const MSG_C2S: &[u8] = b"wsnet/v1/msg/c2s";
    /// Server-to-client message key label.
    pub const MSG_S2C: &[u8] = b"wsnet/v1/msg/s2c";
    /// Request-binding key label.
    pub const BIND: &[u8] = b"wsnet/v1/bind";
}

/// The direction a protected record travels in.
///
/// Directions have separate keys, so a record can never be reflected back at its
/// sender and accepted (T01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Node to Hub.
    ClientToServer,
    /// Hub to node.
    ServerToClient,
}

impl Direction {
    /// The domain-separation byte mixed into the AAD.
    pub const fn as_u8(self) -> u8 {
        match self {
            Direction::ClientToServer => 0,
            Direction::ServerToClient => 1,
        }
    }

    /// The opposite direction.
    pub const fn peer(self) -> Direction {
        match self {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        }
    }
}

/// Errors from key derivation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// The supplied key material was not the required length.
    #[error("pre-shared key must be {PSK_LEN} bytes, got {0}")]
    BadPskLength(usize),
}

/// A per-node pre-shared key.
///
/// §4.2 requires "每节点独立至少 32 随机字节，非弱口令". The length is enforced
/// by the type, and the bytes are zeroized on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Psk([u8; PSK_LEN]);

impl Psk {
    /// Wraps exactly 32 bytes of key material.
    pub fn from_bytes(bytes: [u8; PSK_LEN]) -> Self {
        Psk(bytes)
    }

    /// Copies a key from a slice, rejecting any other length.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, KeyError> {
        let arr: [u8; PSK_LEN] = bytes
            .try_into()
            .map_err(|_| KeyError::BadPskLength(bytes.len()))?;
        Ok(Psk(arr))
    }

    /// Generates a fresh key from the operating system CSPRNG.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; PSK_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Psk(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; PSK_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Psk {
    /// Never prints key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Psk(<redacted>)")
    }
}

/// The three keys derived from one handshake transcript.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    transcript: [u8; 32],
    c2s: [u8; MSG_KEY_LEN],
    s2c: [u8; MSG_KEY_LEN],
    bind: [u8; BIND_KEY_LEN],
}

impl SessionKeys {
    /// Derives the session keys from the pre-shared key and both canonical
    /// handshake halves.
    ///
    /// `auth_without_mac` and `authok_without_mac` are the canonical metadata
    /// bytes of `Auth` and `AuthOk` with the `mac` field removed, in that order.
    pub fn derive(psk: &Psk, auth_without_mac: &[u8], authok_without_mac: &[u8]) -> Self {
        let transcript = transcript(auth_without_mac, authok_without_mac);
        let hk = Hkdf::<Sha256>::new(Some(&transcript), psk.as_bytes());
        SessionKeys {
            transcript,
            c2s: expand(&hk, labels::MSG_C2S, &transcript),
            s2c: expand(&hk, labels::MSG_S2C, &transcript),
            bind: expand(&hk, labels::BIND, &transcript),
        }
    }

    /// The message key for one direction.
    pub fn message_key(&self, direction: Direction) -> &[u8; MSG_KEY_LEN] {
        match direction {
            Direction::ClientToServer => &self.c2s,
            Direction::ServerToClient => &self.s2c,
        }
    }

    /// The request-binding key `K_bind`.
    pub fn bind_key(&self) -> &[u8; BIND_KEY_LEN] {
        &self.bind
    }

    /// The handshake transcript this session was bound to.
    pub fn transcript(&self) -> &[u8; 32] {
        &self.transcript
    }
}

impl core::fmt::Debug for SessionKeys {
    /// Never prints key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys(<redacted>)")
    }
}

/// `SHA256(auth_without_mac || authok_without_mac)`.
pub fn transcript(auth_without_mac: &[u8], authok_without_mac: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(auth_without_mac);
    hasher.update(authok_without_mac);
    hasher.finalize().into()
}

/// `HKDF-Expand(PRK, label || transcript, 32)`.
fn expand(hk: &Hkdf<Sha256>, label: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
    let mut info = Vec::with_capacity(label.len() + transcript.len());
    info.extend_from_slice(label);
    info.extend_from_slice(transcript);
    let mut okm = [0u8; 32];
    // 32 bytes is far below the 255 * HashLen HKDF ceiling, so this cannot fail.
    hk.expand(&info, &mut okm)
        .expect("32-byte OKM is always within HKDF limits");
    info.zeroize();
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH: &[u8] = br#"{"key_id":"k1","node_id":"client-a","ts":"1700000000","version":1}"#;
    const AUTHOK: &[u8] = br#"{"session_id":"00112233445566778899aabbccddeeff","session_epoch":"ffeeddccbbaa99887766554433221100"}"#;

    /// T01: both ends derive the same c2s/s2c keys from the same transcript.
    #[test]
    fn both_ends_agree_on_derived_keys() {
        let psk = Psk::from_bytes([7u8; PSK_LEN]);
        let client = SessionKeys::derive(&psk, AUTH, AUTHOK);
        let server = SessionKeys::derive(&psk, AUTH, AUTHOK);
        assert_eq!(
            client.message_key(Direction::ClientToServer),
            server.message_key(Direction::ClientToServer)
        );
        assert_eq!(client.bind_key(), server.bind_key());
        assert_eq!(client.transcript(), server.transcript());
    }

    /// T01: the two directions must never share a key.
    #[test]
    fn directions_use_different_keys() {
        let keys = SessionKeys::derive(&Psk::from_bytes([7u8; PSK_LEN]), AUTH, AUTHOK);
        assert_ne!(
            keys.message_key(Direction::ClientToServer),
            keys.message_key(Direction::ServerToClient)
        );
        // The binding key is a third, distinct key.
        assert_ne!(
            &keys.bind_key()[..],
            &keys.message_key(Direction::ClientToServer)[..]
        );
    }

    /// A different transcript must produce a different key set.
    #[test]
    fn transcript_changes_the_keys() {
        let psk = Psk::from_bytes([7u8; PSK_LEN]);
        let a = SessionKeys::derive(&psk, AUTH, AUTHOK);
        let b = SessionKeys::derive(&psk, AUTH, b"{\"session_id\":\"different\"}");
        assert_ne!(a.transcript(), b.transcript());
        assert_ne!(
            a.message_key(Direction::ClientToServer),
            b.message_key(Direction::ClientToServer)
        );
    }

    /// A different PSK must produce a different key set.
    #[test]
    fn psk_changes_the_keys() {
        let a = SessionKeys::derive(&Psk::from_bytes([1u8; PSK_LEN]), AUTH, AUTHOK);
        let b = SessionKeys::derive(&Psk::from_bytes([2u8; PSK_LEN]), AUTH, AUTHOK);
        assert_eq!(a.transcript(), b.transcript());
        assert_ne!(
            a.message_key(Direction::ClientToServer),
            b.message_key(Direction::ClientToServer)
        );
    }

    #[test]
    fn psk_length_is_enforced() {
        assert!(Psk::try_from_slice(&[0u8; 32]).is_ok());
        assert_eq!(
            Psk::try_from_slice(&[0u8; 16]).unwrap_err(),
            KeyError::BadPskLength(16)
        );
        assert_eq!(
            Psk::try_from_slice(&[]).unwrap_err(),
            KeyError::BadPskLength(0)
        );
    }

    #[test]
    fn debug_output_never_leaks_key_material() {
        let keys = SessionKeys::derive(&Psk::from_bytes([0xAB; PSK_LEN]), AUTH, AUTHOK);
        assert_eq!(format!("{keys:?}"), "SessionKeys(<redacted>)");
        assert_eq!(format!("{:?}", Psk::from_bytes([0xAB; PSK_LEN])), "Psk(<redacted>)");
    }

    /// The transcript is order-sensitive: swapping the two halves must change it.
    #[test]
    fn transcript_is_order_sensitive() {
        assert_ne!(transcript(AUTH, AUTHOK), transcript(AUTHOK, AUTH));
    }

    /// Key derivation is deterministic across calls.
    #[test]
    fn derivation_is_deterministic() {
        let psk = Psk::from_bytes([9u8; PSK_LEN]);
        let a = SessionKeys::derive(&psk, AUTH, AUTHOK).c2s;
        let b = SessionKeys::derive(&psk, AUTH, AUTHOK).c2s;
        assert_eq!(a, b);
    }
}
