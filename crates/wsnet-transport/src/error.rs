//! Errors shared by every carrier codec.

use wsnet_limits::{MAX_HTTP_BODY, MAX_POST_BATCH_RECORDS, MAX_SSE_EVENT};

/// Why a carrier body could not be encoded or decoded.
///
/// Every variant is a clean refusal: §4.3 requires that "遇截断、超长、非法
/// base64/重复 JSON key 时不执行部分业务命令", so a decoder returns an error
/// instead of a partially applied batch.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CarrierError {
    /// More records than the carrier permits in one body.
    #[error("carrier batch has {actual} records, limit is {limit}")]
    TooManyRecords {
        /// Observed count.
        actual: usize,
        /// Enforced count.
        limit: usize,
    },
    /// A whole body exceeds its bound.
    #[error("carrier body is {actual} bytes, limit is {limit}")]
    BodyTooLarge {
        /// Observed length.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
    /// One envelope exceeds the largest legal record.
    #[error("envelope is {actual} bytes, limit is {limit}")]
    EnvelopeTooLarge {
        /// Observed length.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
    /// A length-prefixed field ran past the end of the body.
    #[error("carrier body truncated while reading {field}")]
    Truncated {
        /// Which field ran off the end.
        field: &'static str,
    },
    /// Bytes remained after the carrier body.
    #[error("{0} trailing bytes after the carrier body")]
    TrailingData(usize),
    /// A base64 field was not valid base64.
    #[error("invalid base64 in {field}")]
    InvalidBase64 {
        /// Which field.
        field: &'static str,
    },
    /// A text carrier was not valid UTF-8 where UTF-8 was required.
    #[error("invalid UTF-8 in {field}")]
    InvalidUtf8 {
        /// Which field.
        field: &'static str,
    },
    /// An SSE event exceeded the single-event bound.
    #[error("SSE event is {actual} bytes, limit is {limit}")]
    SseEventTooLarge {
        /// Observed length.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
    /// The decoder was handed a complete-body call while a partial event was open.
    #[error("SSE stream ended with an incomplete event")]
    IncompleteEvent,
    /// A site profile body did not have the expected shape.
    #[error("malformed {profile} profile: {reason}")]
    MalformedProfile {
        /// The profile kind.
        profile: &'static str,
        /// What was wrong.
        reason: &'static str,
    },
    /// The profile's declared version is not the one this build speaks.
    #[error("unsupported {profile} profile version {found}")]
    UnsupportedProfileVersion {
        /// The profile kind.
        profile: &'static str,
        /// The version found in the body.
        found: u64,
    },
}

impl CarrierError {
    /// The design's whole-body bound, for callers that need it in a message.
    pub const HTTP_BODY_LIMIT: usize = MAX_HTTP_BODY;
    /// The design's per-batch record bound.
    pub const RECORD_LIMIT: usize = MAX_POST_BATCH_RECORDS;
    /// The design's single-SSE-event bound.
    pub const SSE_EVENT_LIMIT: usize = MAX_SSE_EVENT;
}
