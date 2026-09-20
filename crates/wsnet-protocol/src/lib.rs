//! wsnet v1 protocol primitives.
//!
//! This crate implements the parts of `docs/DESIGN.md` §4 that are pure data:
//! the canonical metadata encoding, the message-kind registry, and the record
//! framing. It performs no I/O and holds no session state, so it can be unit
//! tested and fuzzed directly.
//!
//! Deliberate boundaries:
//!
//! * **No cryptography.** AEAD sealing lives in `wsnet-crypto`, which consumes
//!   the record plaintext produced here.
//! * **No carrier encoding.** WebSocket/POST/SSE framing lives in
//!   `wsnet-transport`, which wraps encoded records.
//! * **No `serde_json`.** Metadata is an authenticated input, so canonical
//!   encoding is implemented explicitly (see [`canon`]).

#![forbid(unsafe_code)]

pub mod canon;
pub mod kind;
pub mod record;

pub use canon::{CanonError, Canonical};
pub use kind::{MessageKind, AAD_CONTEXT, PROTOCOL_VERSION};
pub use record::{Record, RecordError, RECORD_OVERHEAD};
