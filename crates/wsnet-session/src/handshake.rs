//! Authentication handshake (DESIGN.md sections 4.2 and 5.1).
//!
//! Two derivations happen here and they are easy to confuse, so they are kept
//! side by side:
//!
//! * The **MAC** over `Auth` and `AuthOk` uses length-prefixed fields
//!   ("签名输入字段有明确长度前缀"), keyed directly by the node PSK because no
//!   session key exists yet.
//! * The **transcript** uses the canonical JSON bytes of both messages with the
//!   `mac` field removed, and feeds HKDF to produce the three session keys.
//!
//! Both start from the same canonical encoding, so a peer that agrees on the
//! metadata bytes automatically agrees on the keys.

use wsnet_crypto::{mac, verify_psk_mac, Psk, SessionKeys, SignedFields, MAC_LEN};
use wsnet_protocol::Canonical;

use crate::message::{AuthFields, AuthOkFields, MessageError};

/// Errors from the handshake.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HandshakeError {
    /// The metadata was malformed.
    #[error("handshake metadata is invalid: {0}")]
    Message(#[from] MessageError),
    /// The presented MAC did not verify.
    #[error("handshake MAC did not verify")]
    BadMac,
    /// The accepted candidate is not the one this side offered.
    #[error("AuthOk answers a different candidate than the one offered")]
    AttemptMismatch,
    /// The Hub id in the response does not match the one that was addressed.
    #[error("AuthOk names a different hub")]
    HubMismatch,
}

/// The length-prefixed MAC input for `Auth`.
///
/// Field names are included so that a value cannot be reinterpreted as a
/// different field with the same bytes.
pub fn auth_signing_fields(auth: &AuthFields) -> SignedFields {
    SignedFields::new()
        .push_str("attempt_id")
        .push_bytes(&auth.attempt_id)
        .push_str("capabilities")
        .push_u32(auth.capabilities.len() as u32)
        .pipe(|fields| {
            auth.capabilities
                .iter()
                .fold(fields, |fields, capability| fields.push_str(capability))
        })
        .push_str("hub_id")
        .push_str(&auth.hub_id)
        .push_str("key_id")
        .push_str(&auth.key_id)
        .push_str("node_id")
        .push_str(&auth.node_id)
        .push_str("nonce")
        .push_bytes(&auth.nonce)
        .push_str("ts")
        .push_u64(auth.ts.max(0) as u64)
        .push_str("version")
        .push_u8(auth.version)
}

/// The length-prefixed MAC input for `AuthOk`, bound to the `Auth` MAC.
pub fn authok_signing_fields(auth_mac: &[u8; MAC_LEN], authok: &AuthOkFields) -> SignedFields {
    SignedFields::new()
        .push_str("auth_mac")
        .push_bytes(auth_mac)
        .push_str("attempt_id")
        .push_bytes(&authok.attempt_id)
        .push_str("capabilities")
        .push_u32(authok.capabilities.len() as u32)
        .pipe(|fields| {
            authok
                .capabilities
                .iter()
                .fold(fields, |fields, capability| fields.push_str(capability))
        })
        .push_str("expires_at")
        .push_u64(authok.expires_at.max(0) as u64)
        .push_str("server_nonce")
        .push_bytes(&authok.server_nonce)
        .push_str("session_epoch")
        .push_bytes(&authok.session_epoch)
        .push_str("session_id")
        .push_bytes(&authok.session_id)
}

/// Computes the `Auth` MAC.
pub fn auth_mac(psk: &Psk, auth: &AuthFields) -> [u8; MAC_LEN] {
    mac(psk.as_bytes(), auth_signing_fields(auth).as_bytes())
}

/// Verifies an `Auth` message and returns its fields.
pub fn verify_auth(psk: &Psk, value: &Canonical) -> Result<AuthFields, HandshakeError> {
    let (fields, presented) = AuthFields::from_canonical(value)?;
    if !verify_psk_mac(psk, &auth_signing_fields(&fields), &presented) {
        return Err(HandshakeError::BadMac);
    }
    Ok(fields)
}

/// Computes the `AuthOk` MAC, binding the full `Auth` MAC and response.
pub fn authok_mac(psk: &Psk, auth_mac: &[u8; MAC_LEN], authok: &AuthOkFields) -> [u8; MAC_LEN] {
    mac(psk.as_bytes(), authok_signing_fields(auth_mac, authok).as_bytes())
}

/// Verifies an `AuthOk` in the context of the `Auth` it answers.
pub fn verify_authok(
    psk: &Psk,
    offered_attempt: &[u8; 16],
    auth_mac: &[u8; MAC_LEN],
    value: &Canonical,
) -> Result<AuthOkFields, HandshakeError> {
    let (fields, presented) = AuthOkFields::from_canonical(value)?;
    if !verify_psk_mac(psk, &authok_signing_fields(auth_mac, &fields), &presented) {
        return Err(HandshakeError::BadMac);
    }
    // A response for a different candidate must not be accepted, or a losing
    // candidate could take ownership (§6.7).
    if fields.attempt_id != *offered_attempt {
        return Err(HandshakeError::AttemptMismatch);
    }
    Ok(fields)
}

/// Derives the session keys from both canonical halves (section 4.2).
pub fn session_keys(psk: &Psk, auth: &AuthFields, authok: &AuthOkFields) -> SessionKeys {
    SessionKeys::derive(
        psk,
        &auth.signing_canonical().to_bytes(),
        &authok.signing_canonical().to_bytes(),
    )
}

/// A fresh 16-byte session id.
pub fn fresh_session_id() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes
}

/// A fresh 16-byte session key epoch.
pub fn fresh_epoch() -> [u8; 16] {
    fresh_session_id()
}

/// A fresh 16-byte candidate id.
pub fn fresh_attempt_id() -> [u8; 16] {
    fresh_session_id()
}

/// A fresh 32-byte authentication nonce.
pub fn fresh_nonce() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    bytes
}

/// A tiny helper so the builders above can continue a chain with a closure.
trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}

impl Pipe for SignedFields {}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk() -> Psk {
        Psk::from_bytes([0x33; 32])
    }

    fn auth() -> AuthFields {
        AuthFields {
            version: 1,
            hub_id: "hub-a".into(),
            key_id: "a-1".into(),
            node_id: "client-a".into(),
            attempt_id: [1u8; 16],
            ts: 1_700_000_000,
            nonce: [2u8; 32],
            capabilities: vec!["flow.credit".into(), "carrier.ws".into()],
        }
    }

    fn authok(attempt: [u8; 16]) -> AuthOkFields {
        AuthOkFields {
            session_id: [3u8; 16],
            session_epoch: [4u8; 16],
            attempt_id: attempt,
            server_nonce: [5u8; 32],
            expires_at: 1_700_000_600,
            capabilities: vec!["flow.credit".into()],
        }
    }

    #[test]
    fn auth_mac_verifies_and_rejects_tampering() {
        let auth = auth();
        let mac = auth_mac(&psk(), &auth);
        let value = auth.to_canonical(&mac);
        assert_eq!(verify_auth(&psk(), &value).unwrap(), auth);

        // A different key must not verify.
        assert_eq!(
            verify_auth(&Psk::from_bytes([0x34; 32]), &value).unwrap_err(),
            HandshakeError::BadMac
        );

        // Every signed field must be covered.
        for (field, mutated) in [
            ("ts", AuthFields { ts: 1_700_000_001, ..auth.clone() }),
            ("nonce", AuthFields { nonce: [9u8; 32], ..auth.clone() }),
            ("node_id", AuthFields { node_id: "client-b".into(), ..auth.clone() }),
            ("hub_id", AuthFields { hub_id: "hub-b".into(), ..auth.clone() }),
            ("key_id", AuthFields { key_id: "a-2".into(), ..auth.clone() }),
            ("version", AuthFields { version: 2, ..auth.clone() }),
            ("attempt_id", AuthFields { attempt_id: [9u8; 16], ..auth.clone() }),
            (
                "capabilities",
                AuthFields {
                    capabilities: vec!["carrier.post".into()],
                    ..auth.clone()
                },
            ),
        ] {
            let forged = mutated.to_canonical(&mac);
            assert_eq!(
                verify_auth(&psk(), &forged).unwrap_err(),
                HandshakeError::BadMac,
                "mutating {field} did not invalidate the MAC"
            );
        }
    }

    #[test]
    fn authok_mac_binds_the_auth_mac() {
        let auth = auth();
        let auth_mac = auth_mac(&psk(), &auth);
        let authok = authok([1u8; 16]);
        let ok_mac = authok_mac(&psk(), &auth_mac, &authok);
        let value = authok.to_canonical(&ok_mac);

        assert_eq!(
            verify_authok(&psk(), &auth.attempt_id, &auth_mac, &value).unwrap(),
            authok
        );
        // A different Auth MAC must not validate the same AuthOk.
        assert_eq!(
            verify_authok(&psk(), &auth.attempt_id, &[0u8; MAC_LEN], &value).unwrap_err(),
            HandshakeError::BadMac
        );
    }

    /// Section 6.7: a response for a losing candidate must not be accepted.
    #[test]
    fn authok_for_a_different_candidate_is_rejected() {
        let auth = auth();
        let auth_mac = auth_mac(&psk(), &auth);
        let other = authok([9u8; 16]);
        let value = other.to_canonical(&authok_mac(&psk(), &auth_mac, &other));
        assert_eq!(
            verify_authok(&psk(), &auth.attempt_id, &auth_mac, &value).unwrap_err(),
            HandshakeError::AttemptMismatch
        );
    }

    /// Section 4.2: both ends derive identical keys from the same transcript.
    #[test]
    fn both_ends_derive_the_same_keys() {
        let auth = auth();
        let authok = authok(auth.attempt_id);
        let node = session_keys(&psk(), &auth, &authok);
        let hub = session_keys(&psk(), &auth, &authok);
        assert_eq!(node.transcript(), hub.transcript());
        assert_eq!(
            node.message_key(wsnet_crypto::Direction::ClientToServer),
            hub.message_key(wsnet_crypto::Direction::ClientToServer)
        );
    }

    /// Section 4.2: the transcript covers both halves, so changing either one
    /// changes the keys.
    #[test]
    fn the_transcript_covers_both_halves() {
        let auth = auth();
        let authok = authok(auth.attempt_id);
        let baseline = session_keys(&psk(), &auth, &authok);

        let other_auth = AuthFields {
            ts: 1_700_000_001,
            ..auth.clone()
        };
        let changed_auth = session_keys(&psk(), &other_auth, &authok);
        assert_ne!(baseline.transcript(), changed_auth.transcript());

        let other_authok = AuthOkFields {
            server_nonce: [8u8; 32],
            ..authok.clone()
        };
        let changed_authok = session_keys(&psk(), &auth, &other_authok);
        assert_ne!(baseline.transcript(), changed_authok.transcript());
    }

    /// A different PSK must change the keys even with an identical transcript.
    #[test]
    fn a_different_psk_changes_the_keys() {
        let auth = auth();
        let authok = authok(auth.attempt_id);
        let a = session_keys(&psk(), &auth, &authok);
        let b = session_keys(&Psk::from_bytes([0x34; 32]), &auth, &authok);
        assert_eq!(a.transcript(), b.transcript());
        assert_ne!(
            a.message_key(wsnet_crypto::Direction::ClientToServer),
            b.message_key(wsnet_crypto::Direction::ClientToServer)
        );
    }

    #[test]
    fn fresh_values_have_the_right_widths_and_differ() {
        assert_ne!(fresh_session_id(), fresh_session_id());
        assert_ne!(fresh_epoch(), fresh_epoch());
        assert_ne!(fresh_attempt_id(), fresh_attempt_id());
        assert_ne!(fresh_nonce(), fresh_nonce());
        assert_eq!(fresh_nonce().len(), 32);
    }
}
