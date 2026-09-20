//! wsnet anti-replay state.
//!
//! Two distinct replay problems that `docs/DESIGN.md` deliberately keeps apart:
//!
//! * **Transport replay** ([`replay::ReplayWindow`]) — a sealed record delivered
//!   twice. Caught per direction by a 65,536-entry sliding window after AEAD
//!   verification. §4.2: "传输重放不是业务幂等".
//! * **Authentication replay** ([`nonce::NonceStore`]) — the same `Auth`
//!   bootstrap replayed, possibly on a different carrier. Caught by an exact,
//!   capacity-bounded nonce set with monotonic retention.
//!
//! Neither one is business idempotency; that lives in `wsnet-operation`.

#![forbid(unsafe_code)]

pub mod nonce;
pub mod replay;

pub use nonce::{
    AuthStoreError, CapacityScope, NonceKey, NonceStore, NonceStoreConfig, Now,
    STORAGE_RECOVERY_MARGIN_SECS,
};
pub use replay::{ReplayError, ReplayWindow};
