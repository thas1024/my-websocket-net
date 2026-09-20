//! Shared budget and bound constants.
//!
//! Every value here is a *design starting budget* from `docs/DESIGN.md`, not a
//! measured optimum. The design repeatedly requires "bound the length before you
//! allocate or decode" (§4.1) and "budgets are checked, never silently exceeded"
//! (§6.7, §7.5), so all parsers in this workspace take their bounds from here
//! rather than hard-coding them at the call site.

#![forbid(unsafe_code)]

/// KiB helper so the constants below read like the design document.
const fn kib(n: usize) -> usize {
    n * 1024
}

/// KiB helper for budgets measured in `u64` byte counters.
const fn kib64(n: u64) -> u64 {
    n * 1024
}

// ---------------------------------------------------------------------------
// §4 protocol version and domain separation
// ---------------------------------------------------------------------------

/// Protocol version bound into the handshake, the record, and the AEAD AAD.
///
/// Kept here rather than in `wsnet-protocol` because `wsnet-crypto` seals the
/// envelope and must agree on the version without depending on the protocol crate.
pub const PROTOCOL_VERSION: u8 = 1;

/// Constant domain-separation prefix for the AEAD associated data (§4.2).
pub const AAD_CONTEXT: &[u8] = b"wsnet/v1";

// ---------------------------------------------------------------------------
// §4.1 record framing
// ---------------------------------------------------------------------------

/// Maximum size of one record plaintext, including framing and padding.
pub const MAX_RECORD_PLAINTEXT: usize = kib(96);

/// Default maximum TCP `Data` payload carried by one record.
pub const MAX_TCP_PAYLOAD: usize = kib(16);

/// Maximum size of the canonical metadata blob.
pub const MAX_METADATA: usize = kib(4);

/// Maximum padding appended to one record.
pub const MAX_PADDING: usize = kib(1);

/// Maximum total length of the authentication bootstrap record.
pub const MAX_AUTH_BOOTSTRAP: usize = kib(4);

/// Fixed size of the envelope plaintext header:
/// `version:u8 | session_epoch:16B | packet_no:u64be`.
pub const ENVELOPE_HEADER_LEN: usize = 1 + 16 + 8;

/// Poly1305 tag length appended by ChaCha20-Poly1305.
pub const AEAD_TAG_LEN: usize = 16;

/// Length of a session epoch identifier in bytes.
pub const SESSION_EPOCH_LEN: usize = 16;

/// Length of a per-node pre-shared key, in bytes (at least 32 random bytes).
pub const PSK_LEN: usize = 32;

/// Length of a derived directional message key.
pub const MSG_KEY_LEN: usize = 32;

/// Length of the binding key `K_bind`.
pub const BIND_KEY_LEN: usize = 32;

/// AEAD nonce length: `0x00000000:u32 | packet_no:u64be`.
pub const NONCE_LEN: usize = 12;

// ---------------------------------------------------------------------------
// §4.2 replay window and scheduler
// ---------------------------------------------------------------------------

/// Packets of history retained per direction for transport replay rejection.
///
/// 65_536 bits is ~8 KiB per direction, matching §4.2.
pub const REPLAY_WINDOW: u64 = 65_536;

/// Maximum number of sealed records the scheduler may have in flight.
///
/// Must stay below [`REPLAY_WINDOW`] so a burst can never push still-valid
/// control records out of the window (§4.2).
pub const MAX_IN_FLIGHT_RECORDS: u64 = 4_096;

/// Largest forward jump beyond the high-water mark that is still accepted.
pub const REPLAY_MAX_FORWARD_JUMP: u64 = REPLAY_WINDOW;

/// packet_no values are refused once allocation would approach the u64 ceiling.
///
/// §4.2 forbids counter wrap and forbids replaying an old session: a session
/// must re-authenticate with a fresh transcript/epoch well before the ceiling.
pub const PACKET_NO_EXHAUSTION_MARGIN: u64 = 1 << 20;

// ---------------------------------------------------------------------------
// §4.3 carrier encoding
// ---------------------------------------------------------------------------

/// Maximum encoded HTTP body (POST request or response) after carrier encoding.
pub const MAX_HTTP_BODY: usize = kib(1024);

/// Maximum size of one SSE event (the base64 payload plus its framing).
pub const MAX_SSE_EVENT: usize = kib(160);

/// Maximum decoded size of one POST batch.
pub const MAX_POST_BATCH_BYTES: usize = kib(256);

/// Maximum number of records carried by one POST batch.
pub const MAX_POST_BATCH_RECORDS: usize = 64;

/// Maximum length of a single decoded record inside any carrier.
pub const MAX_CARRIER_RECORD: usize = MAX_RECORD_PLAINTEXT + ENVELOPE_HEADER_LEN + AEAD_TAG_LEN;

// ---------------------------------------------------------------------------
// §5.1 authentication
// ---------------------------------------------------------------------------

/// Default acceptance window for `Auth.ts`, in seconds.
pub const AUTH_WINDOW_DEFAULT_SECS: u64 = 120;

/// Minimum configurable acceptance window.
pub const AUTH_WINDOW_MIN_SECS: u64 = 60;

/// Maximum configurable acceptance window.
pub const AUTH_WINDOW_MAX_SECS: u64 = 300;

/// Length of an authentication nonce.
pub const AUTH_NONCE_LEN: usize = 32;

/// Per-node cap on retained nonce records.
pub const AUTH_NONCE_PER_NODE_MAX: usize = 65_536;

/// Hub-wide memory budget for nonce records (~64 MiB), per §5.1.
pub const AUTH_NONCE_MEMORY_BUDGET: usize = 64 * 1024 * 1024;

/// Approximate retained bytes charged for each nonce record.
///
/// The design requires the real structure cost to be measured under load; this
/// is the accounting constant used until that measurement exists.
pub const AUTH_NONCE_ENTRY_COST: usize = 256;

// ---------------------------------------------------------------------------
// §5.2 operation idempotency
// ---------------------------------------------------------------------------

/// Maximum concurrent request_id records per session.
pub const OPERATION_MAX_PENDING: usize = 4_096;

/// `Open` completion deadline, in seconds.
pub const OPERATION_OPEN_TIMEOUT_SECS: u64 = 10;

/// Retention for `Complete`/`Failed` results, in seconds.
pub const OPERATION_RESULT_RETENTION_SECS: u64 = 120;

/// Cap on retired request_id tombstones per session.
pub const OPERATION_TOMBSTONE_MAX: usize = 65_536;

// ---------------------------------------------------------------------------
// §5.3 / §6.7 carrier health
// ---------------------------------------------------------------------------

/// Recovery grace for a degraded carrier inside one session epoch, in seconds.
pub const CARRIER_GRACE_SECS: u64 = 10;

/// No control progress for this long moves the session to `Degraded`, in ms.
pub const NO_CONTROL_PROGRESS_DEGRADED_MS: u64 = 2_000;

/// Maximum concurrent authentication candidates per session (§6.7).
pub const MAX_AUTH_CANDIDATES: usize = 2;

/// Hedge delay before starting the second authentication candidate, in ms.
pub const AUTH_HEDGE_DELAY_MS: u64 = 250;

/// TTL for a losing candidate before it is reclaimed, in seconds.
pub const CANDIDATE_TTL_SECS: u64 = 10;

/// Maximum in-flight data POSTs per session (§6.7).
pub const MAX_IN_FLIGHT_DATA_POSTS: usize = 2;

/// Extra cross-carrier retransmit budget as a percentage of the last 10s of traffic.
pub const CROSS_CARRIER_BUDGET_PERCENT: u64 = 20;

/// Initial cross-carrier probe burst cap, in bytes.
pub const CROSS_CARRIER_PROBE_BURST: usize = kib(64);

/// Maximum backup control POST poll wait, in ms (§6.2).
pub const CONTROL_POST_POLL_MAX_MS: u64 = 250;

/// BindProof validity, in seconds (§4.4).
pub const BIND_PROOF_TTL_SECS: u64 = 30;

/// Window in which a freshly upgraded `/w` must send its Auth text frame (§4.4).
pub const WS_AUTH_DEADLINE_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// §7.1 / §7.4 / §7.5 data plane
// ---------------------------------------------------------------------------

/// Maximum number of relay hops in a chain (§7.1).
pub const MAX_CHAIN_HOPS: usize = 4;

/// Bounded reorder buffer per direction, in bytes.
pub const REORDER_BUFFER_BYTES: usize = kib(256);

/// Default per-stream byte credit granted at open.
pub const STREAM_INITIAL_CREDIT: u64 = kib64(256);

/// Maximum outstanding byte credit granted to a peer.
pub const STREAM_MAX_CREDIT: u64 = kib64(1024);

/// Control reserve, in bytes, that a saturated data queue must leave free.
pub const CONTROL_RESERVE_BYTES: usize = kib(8);

/// Maximum UDP payload accepted for one datagram (§7.4).
pub const MAX_UDP_PAYLOAD: usize = 65_507;

/// Default remaining-TTL for relayed datagrams, in ms.
pub const DATAGRAM_DEFAULT_TTL_MS: u64 = 30_000;

/// Maximum concurrently tracked UDP associations per session.
pub const MAX_UDP_ASSOCIATIONS: usize = 256;

/// Maximum queued datagrams per association.
pub const MAX_DATAGRAM_QUEUE: usize = 256;

// ---------------------------------------------------------------------------
// §6.4 background requests
// ---------------------------------------------------------------------------

/// Background requests default to off and stay inside this jitter range, in seconds.
pub const BACKGROUND_JITTER_MIN_SECS: u64 = 2;
/// Upper bound of the background-request jitter range.
pub const BACKGROUND_JITTER_MAX_SECS: u64 = 15;
/// Per-session cap on concurrent background requests.
pub const BACKGROUND_MAX_PER_SESSION: usize = 1;
/// Global background-request bandwidth budget, in bytes per second.
pub const BACKGROUND_BUDGET_BYTES_PER_SEC: usize = kib(4);

// ---------------------------------------------------------------------------
// Compile-time invariants
// ---------------------------------------------------------------------------
//
// These are `const` assertions rather than `#[test]`s on purpose: each one is a
// relationship between two of the budgets above, so a future edit that breaks it
// should fail the build for everyone, not only fail `cargo test`.

/// §4.2: the scheduler must not be able to push valid control records out of the
/// replay window, so in-flight sealed records must fit strictly inside it.
const _: () = assert!(MAX_IN_FLIGHT_RECORDS < REPLAY_WINDOW);

/// §4.1: the worst-case record (maximum payload, metadata, and padding, plus the
/// longest plausible integer metadata) must still fit one record plaintext.
const _: () = assert!(MAX_TCP_PAYLOAD + MAX_METADATA + MAX_PADDING + 64 <= MAX_RECORD_PLAINTEXT);

/// §4.2: a counter may only be allocated below the ceiling.
const _: () = assert!(PACKET_NO_EXHAUSTION_MARGIN > 0);

/// §4.3: an encoded carrier body can never exceed the HTTP body bound.
const _: () = assert!(MAX_POST_BATCH_BYTES <= MAX_HTTP_BODY);

/// §4.3: the byte cap must still admit the largest legal record, or the carrier
/// could not carry it at all.
const _: () = assert!(MAX_POST_BATCH_BYTES >= MAX_CARRIER_RECORD);

/// §4.3: the record count and the byte total are *independent* caps. A 64-record
/// batch of maximum-size records deliberately does not fit — the byte total
/// binds for large records, the count binds for small ones, and a parser must
/// apply both rather than assume either implies the other.
const _: () = assert!(MAX_POST_BATCH_RECORDS * MAX_CARRIER_RECORD > MAX_POST_BATCH_BYTES);

/// The per-record allowance inside a full 64-record batch.
const _: () = assert!(MAX_POST_BATCH_BYTES / MAX_POST_BATCH_RECORDS == kib(4));

/// §5.1: the default auth window must sit inside the documented range.
const _: () = assert!(AUTH_WINDOW_DEFAULT_SECS >= AUTH_WINDOW_MIN_SECS);
const _: () = assert!(AUTH_WINDOW_DEFAULT_SECS <= AUTH_WINDOW_MAX_SECS);

/// §5.1: the nonce memory budget must admit at least one node's worth of records.
const _: () = assert!(AUTH_NONCE_MEMORY_BUDGET / AUTH_NONCE_ENTRY_COST >= AUTH_NONCE_PER_NODE_MAX);

/// §6.4: the background-request jitter range must be ordered.
const _: () = assert!(BACKGROUND_JITTER_MIN_SECS <= BACKGROUND_JITTER_MAX_SECS);

/// §7.4: a single UDP payload must fit one record after framing.
const _: () = assert!(MAX_UDP_PAYLOAD <= MAX_RECORD_PLAINTEXT);

/// §7.5: the initial credit must not exceed the maximum window.
const _: () = assert!(STREAM_INITIAL_CREDIT <= STREAM_MAX_CREDIT);
