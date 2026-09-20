//! One-time request binding credentials (DESIGN.md section 4.4).
//!
//! A session id is a routing label, never a bearer credential, so every
//! authenticated carrier request must additionally present a `BindProof`:
//!
//! > 认证后每个 POST 带 sid 与 `BindProof` 请求头：`channel_id, bind_nonce,
//! > expires_at, mac`，MAC 使用 K_bind，绑定 method、规范化 path、hub/session/epoch、
//! > channel_id、body hash 与到期时间。
//!
//! The MAC input is defined **once**, by [`BindTarget`] and [`binding_mac`], so the
//! server and any client cannot disagree about the bytes being signed. The body
//! hash covers the request body, which is what stops a proof captured on one
//! request from being replayed onto another; the canonical path is signed for the
//! same reason, which is what makes a proof for `/m` unusable on `/transport/page`.
//!
//! The header is a semicolon-separated `key=value` list so that the proof carries
//! its own session id:
//!
//! ```text
//! BindProof: v=v1;sid=<32 hex>;channel=<32 hex>;nonce=<32 hex>;expires=<unix>;mac=<64 hex>
//! ```
//!
//! Section 4.4 does not fix the header's syntax, only its fields and its MAC
//! input. Carrying `sid` *inside* the proof (rather than in a second header) keeps
//! the credential in one place and makes "the proof names the session it was made
//! for" a property of the signed bytes.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use wsnet_auth_store::Now;
use wsnet_crypto::{bind_mac, verify_bind_mac, SignedFields};
use wsnet_limits::BIND_PROOF_TTL_SECS;

/// The request header carrying a [`BindProof`].
pub const BIND_PROOF_HEADER: &str = "bindproof";

/// The only accepted proof version.
pub const BIND_PROOF_VERSION: &str = "v1";

/// Bounded number of retained `bind_nonce` records.
///
/// Section 9.2 requires a capacity bound on every anti-replay structure, and
/// section 4.4 makes a nonce single-use, so the set only has to hold "proofs that
/// could still be presented". A full set refuses new claims rather than evicting a
/// nonce that is still inside its validity window.
pub const BIND_NONCE_MAX: usize = 65_536;

/// Errors while reading a proof header.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindProofError {
    /// A required field was absent.
    #[error("bind proof is missing the `{0}` field")]
    MissingField(&'static str),
    /// A field was present but not the expected value.
    #[error("bind proof field `{field}` is not {expected}")]
    BadField {
        /// Offending field.
        field: &'static str,
        /// What was expected.
        expected: &'static str,
    },
    /// The header carried a version this build does not speak.
    #[error("bind proof version `{0}` is not supported")]
    UnsupportedVersion(String),
    /// The same key appeared twice, which makes the encoding ambiguous.
    #[error("bind proof repeats the `{0}` field")]
    DuplicateField(&'static str),
}

/// Everything a `BindProof` MAC commits to (section 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindTarget<'a> {
    /// HTTP method, uppercased as it appears on the wire.
    pub method: &'a str,
    /// Canonical request path, without a query string.
    pub path: &'a str,
    /// Hub the session belongs to.
    pub hub_id: &'a str,
    /// Session the proof names.
    pub session_id: [u8; 16],
    /// Session key epoch the proof is valid for.
    pub session_epoch: [u8; 16],
    /// Carrier channel the proof was issued for.
    pub channel_id: [u8; 16],
    /// Single-use nonce.
    pub bind_nonce: [u8; 16],
    /// SHA-256 of the request body (empty for `GET`).
    pub body_hash: [u8; 32],
    /// Absolute expiry, UTC Unix seconds.
    pub expires_at: i64,
}

/// Builds the length-prefixed MAC input of a binding proof.
///
/// Every field is length-prefixed by [`SignedFields`], so moving a byte from one
/// field into the next cannot produce the same signing input.
pub fn binding_fields(target: &BindTarget<'_>) -> SignedFields {
    SignedFields::new()
        .push_str("body_hash")
        .push_bytes(&target.body_hash)
        .push_str("bind_nonce")
        .push_bytes(&target.bind_nonce)
        .push_str("channel_id")
        .push_bytes(&target.channel_id)
        .push_str("expires_at")
        .push_u64(target.expires_at.max(0) as u64)
        .push_str("hub_id")
        .push_str(target.hub_id)
        .push_str("method")
        .push_str(target.method)
        .push_str("path")
        .push_str(target.path)
        .push_str("session_epoch")
        .push_bytes(&target.session_epoch)
        .push_str("session_id")
        .push_bytes(&target.session_id)
}

/// `MAC(K_bind, binding_fields(target))`.
pub fn binding_mac(bind_key: &[u8; 32], target: &BindTarget<'_>) -> [u8; 32] {
    bind_mac(bind_key, &binding_fields(target))
}

/// Whether a presented tag is the correct binding MAC.
pub fn verify_binding_mac(bind_key: &[u8; 32], target: &BindTarget<'_>, presented: &[u8]) -> bool {
    verify_bind_mac(bind_key, &binding_fields(target), presented)
}

/// SHA-256 of a request body.
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.finalize().into()
}

/// A parsed `BindProof` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindProof {
    /// Session the proof was issued for.
    pub session_id: [u8; 16],
    /// Carrier channel identity; rotated per request by section 4.4.
    pub channel_id: [u8; 16],
    /// Single-use nonce.
    pub bind_nonce: [u8; 16],
    /// Absolute expiry, UTC Unix seconds.
    pub expires_at: i64,
    /// The MAC over the [`BindTarget`] the client signed.
    pub mac: [u8; 32],
}

impl BindProof {
    /// Renders the header value.
    pub fn encode(&self) -> String {
        format!(
            "v={BIND_PROOF_VERSION};sid={};channel={};nonce={};expires={};mac={}",
            hex::encode(self.session_id),
            hex::encode(self.channel_id),
            hex::encode(self.bind_nonce),
            self.expires_at,
            hex::encode(self.mac),
        )
    }

    /// Parses a header value.
    ///
    /// Unknown keys are rejected rather than ignored: a proof that carries a field
    /// this build does not sign is a proof from a different protocol version, and
    /// accepting it would mean accepting bytes nobody authenticated.
    pub fn parse(value: &str) -> Result<BindProof, BindProofError> {
        let mut version: Option<&str> = None;
        let mut sid: Option<[u8; 16]> = None;
        let mut channel: Option<[u8; 16]> = None;
        let mut nonce: Option<[u8; 16]> = None;
        let mut expires: Option<i64> = None;
        let mut mac: Option<[u8; 32]> = None;

        for part in value.split(';') {
            let (key, raw) = part.split_once('=').ok_or(BindProofError::BadField {
                field: "field",
                expected: "a `key=value` pair",
            })?;
            match key.trim() {
                // The version is checked as soon as it is seen: a header from a
                // different version may encode every other field differently, so
                // parsing it first would be reading a shape nobody agreed on.
                "v" | "version" => {
                    let value = raw.trim();
                    if value != BIND_PROOF_VERSION {
                        return Err(BindProofError::UnsupportedVersion(value.to_string()));
                    }
                    version = Some(value);
                }
                "sid" => set_once(&mut sid, "sid", parse_hex::<16>("sid", raw)?)?,
                "channel" => set_once(&mut channel, "channel", parse_hex::<16>("channel", raw)?)?,
                "nonce" => set_once(&mut nonce, "nonce", parse_hex::<16>("nonce", raw)?)?,
                "expires" => {
                    let value =
                        raw.trim()
                            .parse::<i64>()
                            .map_err(|_| BindProofError::BadField {
                                field: "expires",
                                expected: "a decimal Unix timestamp",
                            })?;
                    set_once(&mut expires, "expires", value)?;
                }
                "mac" => set_once(&mut mac, "mac", parse_hex::<32>("mac", raw)?)?,
                _ => {
                    return Err(BindProofError::BadField {
                        field: "field",
                        expected: "one of v, sid, channel, nonce, expires, mac",
                    })
                }
            }
        }

        match version.ok_or(BindProofError::MissingField("v"))? {
            BIND_PROOF_VERSION => {}
            other => return Err(BindProofError::UnsupportedVersion(other.to_string())),
        }

        Ok(BindProof {
            session_id: sid.ok_or(BindProofError::MissingField("sid"))?,
            channel_id: channel.ok_or(BindProofError::MissingField("channel"))?,
            bind_nonce: nonce.ok_or(BindProofError::MissingField("nonce"))?,
            expires_at: expires.ok_or(BindProofError::MissingField("expires"))?,
            mac: mac.ok_or(BindProofError::MissingField("mac"))?,
        })
    }
}

fn set_once<T>(slot: &mut Option<T>, field: &'static str, value: T) -> Result<(), BindProofError> {
    if slot.is_some() {
        return Err(BindProofError::DuplicateField(field));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_hex<const N: usize>(field: &'static str, raw: &str) -> Result<[u8; N], BindProofError> {
    let bytes = hex::decode(raw.trim()).map_err(|_| BindProofError::BadField {
        field,
        expected: "lowercase hex",
    })?;
    bytes.try_into().map_err(|_| BindProofError::BadField {
        field,
        expected: "the fixed width this version defines",
    })
}

/// How many claims may pass between two pruning passes.
///
/// Pruning on every claim would make claiming quadratic in the number of retained
/// nonces; pruning on a budget keeps a claim O(1) while still bounding how long an
/// expired record can linger. A lingering record only ever *refuses* a claim, so
/// the worst case is fail-closed.
const PRUNE_INTERVAL: u32 = 1024;

/// The single-use `bind_nonce` set (section 4.4).
///
/// A nonce is retained until one second past the last moment its proof could still
/// be accepted, measured on the monotonic clock so that a wall-clock adjustment
/// cannot resurrect it. Section 5.1's rule for authentication nonces applies here
/// unchanged: a full set refuses new claims rather than evicting a record that is
/// still valid.
#[derive(Debug, Default)]
pub struct BindProofRegistry {
    used: HashMap<[u8; 16], u64>,
    claims_since_prune: u32,
}

impl BindProofRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        BindProofRegistry::default()
    }

    /// Number of retained nonces, after pruning expired ones.
    pub fn len(&mut self, now: Now) -> usize {
        self.prune(now);
        self.used.len()
    }

    /// Whether no nonce is currently retained.
    pub fn is_empty(&mut self, now: Now) -> bool {
        self.len(now) == 0
    }

    /// Claims a nonce, returning whether this caller is the first to use it.
    ///
    /// The caller must already have verified the proof's MAC: registering an
    /// unauthenticated nonce would let an attacker burn entries.
    pub fn claim(&mut self, nonce: [u8; 16], expires_at: i64, now: Now) -> bool {
        if self.used.len() >= BIND_NONCE_MAX || self.claims_since_prune >= PRUNE_INTERVAL {
            self.prune(now);
            self.claims_since_prune = 0;
        }
        self.claims_since_prune = self.claims_since_prune.saturating_add(1);

        if self.used.contains_key(&nonce) {
            return false;
        }
        if self.used.len() >= BIND_NONCE_MAX {
            return false;
        }
        let retain_secs =
            (expires_at.saturating_add(1).saturating_sub(now.wall_secs)).max(0) as u64;
        let retain_until_ms = now
            .monotonic_ms
            .saturating_add(retain_secs.saturating_mul(1_000));
        self.used.insert(nonce, retain_until_ms);
        true
    }

    /// Drops nonces whose whole validity window has passed.
    pub fn prune(&mut self, now: Now) -> usize {
        let before = self.used.len();
        self.used.retain(|_, until| *until > now.monotonic_ms);
        before - self.used.len()
    }
}

/// The longest a proof may be valid, for validation at the call site.
pub const MAX_PROOF_LIFETIME_SECS: i64 = BIND_PROOF_TTL_SECS as i64;

#[cfg(test)]
mod tests {
    use super::*;

    fn target(expires_at: i64) -> BindTarget<'static> {
        BindTarget {
            method: "POST",
            path: "/m",
            hub_id: "hub-a",
            session_id: [1u8; 16],
            session_epoch: [2u8; 16],
            channel_id: [3u8; 16],
            bind_nonce: [4u8; 16],
            body_hash: body_hash(b"body"),
            expires_at,
        }
    }

    fn proof(expires_at: i64) -> BindProof {
        let target = target(expires_at);
        let mac = binding_mac(&[9u8; 32], &target);
        BindProof {
            session_id: target.session_id,
            channel_id: target.channel_id,
            bind_nonce: target.bind_nonce,
            expires_at,
            mac,
        }
    }

    #[test]
    fn a_header_round_trips() {
        let proof = proof(1_700_000_030);
        let text = proof.encode();
        assert_eq!(BindProof::parse(&text).unwrap(), proof);
    }

    #[test]
    fn a_missing_or_unknown_field_is_refused() {
        let hex16 = "00".repeat(16);
        let hex32 = "00".repeat(32);

        // A well-formed header missing its MAC.
        assert!(matches!(
            BindProof::parse(&format!(
                "v=v1;sid={hex16};channel={hex16};nonce={hex16};expires=1"
            )),
            Err(BindProofError::MissingField("mac"))
        ));
        // An unknown field, which a different version might have signed.
        assert!(matches!(
            BindProof::parse(&format!(
                "v=v1;sid={hex16};channel={hex16};nonce={hex16};expires=1;mac={hex32};extra=1"
            )),
            Err(BindProofError::BadField { .. })
        ));
        // Repeated fields are ambiguous rather than last-wins.
        assert!(matches!(
            BindProof::parse(&format!(
                "v=v1;sid={hex16};sid={hex16};channel={hex16};nonce={hex16};expires=1;mac={hex32}"
            )),
            Err(BindProofError::DuplicateField("sid"))
        ));
        assert!(matches!(
            BindProof::parse("v=v2;sid=00;channel=00;nonce=00;expires=1;mac=00"),
            Err(BindProofError::UnsupportedVersion(_))
        ));
        assert!(matches!(
            BindProof::parse("nonsense"),
            Err(BindProofError::BadField { .. })
        ));
    }

    #[test]
    fn a_wrong_width_field_is_refused() {
        let text = format!(
            "v=v1;sid={};channel=00;nonce=00;expires=1;mac=00",
            "aa".repeat(16)
        );
        assert!(matches!(
            BindProof::parse(&text),
            Err(BindProofError::BadField {
                field: "channel",
                ..
            })
        ));
    }

    /// Section 4.4: the MAC covers the method, the path, and the body hash, so a
    /// proof cannot be moved to another request.
    #[test]
    fn every_bound_field_changes_the_mac() {
        let baseline = target(1_700_000_030);
        let key = [9u8; 32];
        let original = binding_mac(&key, &baseline);

        let mut other = baseline;
        other.method = "GET";
        assert_ne!(binding_mac(&key, &other), original);
        other = baseline;
        other.path = "/e";
        assert_ne!(binding_mac(&key, &other), original);
        other = baseline;
        other.body_hash = body_hash(b"other");
        assert_ne!(binding_mac(&key, &other), original);
        other = baseline;
        other.session_epoch = [7u8; 16];
        assert_ne!(binding_mac(&key, &other), original);
        other = baseline;
        other.expires_at += 1;
        assert_ne!(binding_mac(&key, &other), original);
        other = baseline;
        other.channel_id = [8u8; 16];
        assert_ne!(binding_mac(&key, &other), original);
    }

    /// A nonce may be claimed exactly once, and only while it is retained.
    #[test]
    fn a_nonce_is_single_use_and_expires() {
        let mut registry = BindProofRegistry::new();
        let now = Now::new(1_000, 1_000_000);
        assert!(registry.claim([1u8; 16], 1_030, now));
        assert!(!registry.claim([1u8; 16], 1_030, now));
        assert!(!registry.claim([1u8; 16], 1_030, Now::new(1_020, 1_020_000)));
        // A different nonce is independent.
        assert!(registry.claim([2u8; 16], 1_030, now));

        // Once past the expiry the record is reclaimed...
        assert_eq!(registry.len(Now::new(1_090, 1_090_000)), 0);
        // ...but the caller must not treat that as permission to reuse it: the
        // proof itself is expired, which the session layer checks first.
        assert!(registry.claim([1u8; 16], 1_090, Now::new(1_090, 1_090_000)));
    }

    #[test]
    fn a_full_registry_refuses_rather_than_evicting() {
        let mut registry = BindProofRegistry::new();
        let now = Now::new(1_000, 1_000_000);
        for i in 0..BIND_NONCE_MAX {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert!(registry.claim(nonce, 1_030, now), "claim {i} failed");
        }
        assert!(
            !registry.claim([0xFFu8; 16], 1_030, now),
            "a full registry must refuse new claims"
        );
    }

    #[test]
    fn body_hash_is_stable_and_content_sensitive() {
        assert_eq!(body_hash(b"abc"), body_hash(b"abc"));
        assert_ne!(body_hash(b"abc"), body_hash(b"abd"));
        assert_ne!(body_hash(b""), body_hash(b" "));
        assert_eq!(body_hash(b"").len(), 32);
    }
}
