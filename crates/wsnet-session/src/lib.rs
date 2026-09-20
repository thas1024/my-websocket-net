//! The wsnet session: handshake, engine, and message schemas.
//!
//! Three layers, kept apart on purpose:
//!
//! * [`message`] knows the canonical-JSON schema of every message kind. It is
//!   pure data, so a schema mistake is a unit-test failure rather than an
//!   interoperability bug.
//! * [`handshake`] turns `Auth` and `AuthOk` into session keys. This is the only
//!   place that touches the pre-shared key.
//! * [`engine`] is the session itself: sealing, replay, stream ids, credit, and
//!   bounded reorder. It is transport-free, so it can be tested by moving
//!   envelopes between two engines in-process.
//!
//! The split matters for the design's threat model. The engine never sees the
//! PSK, and it never decides business idempotency: section 4.2 requires transport
//! replay and business replay to be handled separately, so the engine drops a
//! duplicated envelope and surfaces `Open` as an event for `wsnet-operation` to
//! arbitrate.

#![forbid(unsafe_code)]

pub mod engine;
pub mod handshake;
pub mod message;

pub use engine::{
    Session, SessionConfig, SessionError, SessionEvent, SessionHandle, SessionState, Side,
};
pub use handshake::{
    auth_mac, auth_signing_fields, authok_mac, authok_signing_fields, fresh_attempt_id,
    fresh_epoch, fresh_nonce, fresh_session_id, session_keys, verify_auth, verify_authok,
    HandshakeError,
};
pub use message::{
    empty_metadata, negotiate_capabilities, AuthFields, AuthOkFields, ByeFields,
    CancelCandidateFields, DataFields, FinFields, HelloFields, HelloOkFields, MessageError,
    OpenFields, OpenResultFields, OpenStatus, ProgressFields, ReadyFields, ResetFields,
    ResetReason, ResumeFields, ServiceRegistration, SUPPORTED_CAPABILITIES,
};
