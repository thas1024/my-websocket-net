//! Adversarial budget suite (DESIGN.md §4.1–§4.3, §5.1, §7.3–§7.5).
//!
//! The README states that the budgets in `wsnet-limits` are *design starting
//! budgets*, not measured optima, and that they are not stress-tested. Every
//! budget nevertheless claims the same property: "budgets are checked, never
//! silently exceeded" (§6.7, §7.5). This suite drives each bound to its exact
//! edge and asserts the three things that property means:
//!
//! * input *at* the limit is accepted,
//! * input *one past* the limit is refused,
//! * and the structure's own size (slots, entries, buffered bytes) can never
//!   grow past the declared capacity, however much hostile input it is fed.
//!
//! Bounds are always named by their `wsnet_limits` constant and never re-spelled
//! as a literal, so changing a budget cannot silently detach a test from the
//! value it guards. Test-scale values that are *not* budgets (framing overhead,
//! a small cap used to keep an O(n) expiry sweep cheap) are written as such and
//! labelled.
//!
//! §7.3 gives the out-of-order part of one direction three budgets —
//! [`REORDER_MAX_OUT_OF_ORDER_BYTES`] bytes, [`REORDER_MAX_BLOCKS`] blocks, and a
//! bounded distance ahead of the next expected offset inside
//! [`REORDER_BUFFER_BYTES`] — and all three are enforced by
//! `wsnet_stream::ReorderBuffer` and asserted below.

#![forbid(unsafe_code)]

use wsnet_auth_store::nonce::{
    AuthStoreError, CapacityScope, NonceKey, NonceStore, NonceStoreConfig, Now,
};
use wsnet_auth_store::replay::{ReplayError, ReplayWindow};
use wsnet_limits::{
    AUTH_NONCE_ENTRY_COST, AUTH_NONCE_LEN, AUTH_NONCE_MEMORY_BUDGET, AUTH_NONCE_PER_NODE_MAX,
    MAX_CARRIER_RECORD, MAX_METADATA, MAX_POST_BATCH_BYTES, MAX_POST_BATCH_RECORDS,
    MAX_RECORD_PLAINTEXT, MAX_SSE_EVENT, MAX_TCP_PAYLOAD, REPLAY_MAX_FORWARD_JUMP, REPLAY_WINDOW,
    REORDER_BUFFER_BYTES, REORDER_MAX_BLOCKS, REORDER_MAX_OUT_OF_ORDER_BYTES, STREAM_INITIAL_CREDIT,
    STREAM_MAX_CREDIT,
};
use wsnet_protocol::canon::{CanonError, Canonical, MAX_CANON_DEPTH};
use wsnet_protocol::record::{Record, RecordError};
use wsnet_protocol::MessageKind;
use wsnet_stream::{CreditAccount, ReorderBuffer, StreamError};
use wsnet_transport::sse::{self, SseDecoder};
use wsnet_transport::{post, ws, CarrierError};

/// A deliberately small test-scale capacity.
///
/// It is *not* a budget: it only exists to keep the nonce store's O(n) expiry
/// sweep cheap while the cap-enforcement path is exercised many times. The
/// default capacity really is the declared constant, which
/// `nonce_store_default_capacities_are_the_declared_budgets` asserts separately.
const TEST_CAP: usize = 32;

/// One fixed wall/monotonic reading for the nonce tests.
fn nonce_now() -> Now {
    Now::new(1_700_000_000, 1_700_000_000_000)
}

/// A distinct nonce for `index`, on one node, so a per-node cap binds.
fn nonce_key(index: u64) -> NonceKey {
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    nonce[..8].copy_from_slice(&index.to_be_bytes());
    NonceKey::new("hub-a", "key-1", "node-1", nonce)
}

// ---------------------------------------------------------------------------
// §4.2 transport replay window
// ---------------------------------------------------------------------------

/// A replayed `packet_no` loses; after the window slides, the newest value is
/// still accepted and the value that fell out is refused rather than revived.
#[test]
fn replay_window_rejects_a_replay_and_accepts_the_newest_after_the_window_slides() {
    let mut window = ReplayWindow::new();
    for n in 0..(REPLAY_WINDOW * 2) {
        window
            .check_and_record(n)
            .unwrap_or_else(|e| panic!("in-order packet {n} was refused: {e}"));
    }
    let newest = REPLAY_WINDOW * 2 - 1;
    assert_eq!(window.highest(), Some(newest));

    // A replay of an already-accepted value inside the window is a duplicate.
    assert_eq!(
        window.check_and_record(newest),
        Err(ReplayError::Duplicate(newest))
    );
    assert_eq!(
        window.check_and_record(newest - 1),
        Err(ReplayError::Duplicate(newest - 1))
    );

    // A value the window has slid past is unjudgeable, never re-accepted.
    assert!(matches!(
        window.check_and_record(0),
        Err(ReplayError::TooOld { .. })
    ));

    // The window still admits exactly the declared forward jump...
    let next = newest + REPLAY_MAX_FORWARD_JUMP;
    assert!(window.check_and_record(next).is_ok());
    assert_eq!(window.highest(), Some(next));
    // ...and after that jump the older value is out of the window for good.
    assert_eq!(
        window.check_and_record(newest),
        Err(ReplayError::TooOld {
            packet_no: newest,
            highest: next,
        })
    );
    // The newest value is accepted after the slide.
    assert!(window.check_and_record(next + 1).is_ok());
    assert_eq!(window.highest(), Some(next + 1));
}

/// The window owns exactly `REPLAY_WINDOW` slots, and that never changes no
/// matter how many packet numbers flow through it (§4.2: the window is a fixed
/// ~8 KiB per direction, so a long-lived session cannot grow it).
#[test]
fn replay_window_never_tracks_more_than_the_declared_capacity() {
    // The bitmap is private, so the observable slot count is the public fixed
    // footprint accessor: one bit per tracked packet_no.
    let slots = ReplayWindow::memory_bytes() * 8;
    assert_eq!(
        slots, REPLAY_WINDOW as usize,
        "the window tracks a different number of slots than REPLAY_WINDOW declares"
    );

    let mut window = ReplayWindow::new();
    for n in 0..(REPLAY_WINDOW * 4) {
        let _ = window.check_and_record(n);
    }
    // Four windows' worth of packets later, the footprint is unchanged.
    assert_eq!(ReplayWindow::memory_bytes() * 8, REPLAY_WINDOW as usize);
    assert_eq!(window.highest(), Some(REPLAY_WINDOW * 4 - 1));
    // And it is still a *window*: the old end is refused, the new end is live.
    assert!(matches!(
        window.check_and_record(REPLAY_WINDOW),
        Err(ReplayError::TooOld { .. })
    ));
    assert_eq!(
        window.check_and_record(REPLAY_WINDOW * 4 - 1),
        Err(ReplayError::Duplicate(REPLAY_WINDOW * 4 - 1))
    );
}

/// The declared forward-jump bound accepts the limit exactly and refuses one
/// past it, leaving no trace behind.
#[test]
fn replay_window_refuses_one_past_the_declared_forward_jump() {
    let mut window = ReplayWindow::new();
    window.check_and_record(0).unwrap();
    assert!(window.check_and_record(REPLAY_MAX_FORWARD_JUMP).is_ok());
    assert_eq!(window.highest(), Some(REPLAY_MAX_FORWARD_JUMP));

    let mut window = ReplayWindow::new();
    window.check_and_record(0).unwrap();
    let over = REPLAY_MAX_FORWARD_JUMP + 1;
    assert_eq!(
        window.check_and_record(over),
        Err(ReplayError::TooFarAhead {
            packet_no: over,
            highest: 0,
            jump: over,
            limit: REPLAY_MAX_FORWARD_JUMP,
        })
    );
    assert_eq!(
        window.highest(),
        Some(0),
        "a refused jump moved the high-water mark"
    );
    assert!(window.check_and_record(1).is_ok());
}

// ---------------------------------------------------------------------------
// §5.1 authentication nonce store
// ---------------------------------------------------------------------------

/// The store's default capacities *are* the declared budgets, so the tests
/// below are testing the shipped configuration and not a private copy of it.
#[test]
fn nonce_store_default_capacities_are_the_declared_budgets() {
    let config = NonceStoreConfig::default();
    assert_eq!(config.per_node_max, AUTH_NONCE_PER_NODE_MAX);
    assert_eq!(
        config.global_max,
        AUTH_NONCE_MEMORY_BUDGET / AUTH_NONCE_ENTRY_COST
    );
    assert!(
        config.per_node_max <= config.global_max,
        "the per-node cap cannot exceed the Hub-wide cap"
    );

    let store = NonceStore::new(config).unwrap();
    assert_eq!(store.config().per_node_max, AUTH_NONCE_PER_NODE_MAX);
    assert_eq!(
        store.config().global_max,
        AUTH_NONCE_MEMORY_BUDGET / AUTH_NONCE_ENTRY_COST
    );
}

/// §5.1: "a full store must not evict still-valid records". At the *declared*
/// per-node capacity the next nonce must be refused, the store must not grow,
/// and nothing may have been dropped to make room.
#[test]
fn nonce_store_refuses_new_nonces_once_the_declared_cap_is_full() {
    let config = NonceStoreConfig::default();
    let now = nonce_now();

    // Fill to the declared cap through the documented restart path. `restore`
    // is O(n) whereas repeatedly calling `register` is O(n²) because of the
    // expiry sweep, and the cap being exercised is still the shipped
    // AUTH_NONCE_PER_NODE_MAX for one node.
    let snapshot: Vec<(NonceKey, i64)> = (0..AUTH_NONCE_PER_NODE_MAX as u64)
        .map(|i| {
            (
                nonce_key(i),
                now.wall_secs + config.window_secs as i64,
            )
        })
        .collect();
    let mut store = NonceStore::restore(config, snapshot, now).unwrap();
    assert_eq!(store.len(), AUTH_NONCE_PER_NODE_MAX);
    assert_eq!(store.node_len("hub-a", "node-1"), AUTH_NONCE_PER_NODE_MAX);

    // Every retained record is still inside its window, so a fresh nonce loses.
    let fresh = nonce_key(AUTH_NONCE_PER_NODE_MAX as u64);
    assert_eq!(
        store.register(fresh.clone(), now.wall_secs, now).unwrap_err(),
        AuthStoreError::CapacityExceeded(CapacityScope::PerNode)
    );
    assert_eq!(
        store.len(),
        AUTH_NONCE_PER_NODE_MAX,
        "a refused registration changed the store size"
    );
    assert!(!store.contains(&fresh));

    // Nothing was evicted to make room: the oldest record is still a replay.
    assert!(store.contains(&nonce_key(0)));
    assert_eq!(
        store.register(nonce_key(0), now.wall_secs, now).unwrap_err(),
        AuthStoreError::Duplicate
    );
    assert_eq!(store.len(), AUTH_NONCE_PER_NODE_MAX);
}

/// Under sustained pressure the store's record count never exceeds its declared
/// capacity, and the records that were admitted stay admitted (so a later
/// nonce can never ride over an earlier one).
#[test]
fn nonce_store_count_never_exceeds_its_declared_capacity() {
    let config = NonceStoreConfig {
        per_node_max: TEST_CAP,
        ..NonceStoreConfig::default()
    };
    assert_eq!(config.global_max, AUTH_NONCE_MEMORY_BUDGET / AUTH_NONCE_ENTRY_COST);
    let cap = config.per_node_max;
    let mut store = NonceStore::new(config).unwrap();
    let now = nonce_now();

    let mut accepted = 0usize;
    let mut refused = 0usize;
    for i in 0..(cap as u64 * 8) {
        match store.register(nonce_key(i), now.wall_secs, now) {
            Ok(()) => accepted += 1,
            Err(AuthStoreError::CapacityExceeded(CapacityScope::PerNode)) => refused += 1,
            Err(other) => panic!("unexpected error for nonce {i}: {other}"),
        }
        assert!(
            store.len() <= cap,
            "store holds {} records, declared capacity is {cap}",
            store.len()
        );
    }
    assert_eq!(accepted, cap, "the store did not admit exactly its capacity");
    assert_eq!(refused, cap * 8 - cap);

    // Every admitted record is still present and still a replay.
    assert_eq!(store.len(), cap);
    for i in 0..cap as u64 {
        assert_eq!(
            store.register(nonce_key(i), now.wall_secs, now).unwrap_err(),
            AuthStoreError::Duplicate,
            "nonce {i} was evicted and became reusable"
        );
    }
}

// ---------------------------------------------------------------------------
// §7.3 / §7.5 reorder buffer
// ---------------------------------------------------------------------------

/// The declared byte cap is reached exactly and one byte past it is refused
/// without changing the buffered total.
///
/// The cap that binds is §7.3's out-of-order budget: bytes held out of order are
/// by definition buffered, so `REORDER_MAX_OUT_OF_ORDER_BYTES` (128 KiB) is
/// reached long before the per-direction total `REORDER_BUFFER_BYTES` (256 KiB).
#[test]
fn reorder_buffer_refuses_one_byte_past_the_declared_byte_cap() {
    let mut buffer = ReorderBuffer::new(0);
    let cap = buffer.byte_limit();
    assert_eq!(
        cap, REORDER_MAX_OUT_OF_ORDER_BYTES,
        "the default out-of-order budget must be section 7.3's"
    );
    assert!(
        cap < REORDER_BUFFER_BYTES,
        "the out-of-order part is a strict subset of the per-direction total"
    );

    // Leave offset 0 empty so everything else stays out of order and buffered.
    let held = vec![0u8; cap];
    assert!(buffer
        .insert(1, &held)
        .expect("a block exactly at the byte cap was refused")
        .is_empty());
    assert_eq!(buffer.buffered(), cap);

    let offset = 1 + cap as u64;
    assert_eq!(
        buffer.insert(offset, &[0u8; 1]).unwrap_err(),
        StreamError::ReorderOverflow {
            would_hold: cap + 1,
            limit: cap,
        }
    );
    assert_eq!(
        buffer.buffered(),
        cap,
        "a refused block changed the buffered total"
    );

    // A caller cannot raise the budget past the per-direction total.
    assert_eq!(
        ReorderBuffer::with_limit(0, usize::MAX).byte_limit(),
        REORDER_BUFFER_BYTES
    );
}

/// Feeding far more bytes than the budget, in gapped blocks, never grows the
/// buffered total past the declared cap.
#[test]
fn reorder_buffer_buffered_total_never_exceeds_the_declared_cap() {
    let mut buffer = ReorderBuffer::new(0);
    let cap = buffer.byte_limit();
    let block = cap / 8;
    let data = vec![0u8; block];
    let mut offset = 1u64; // one-byte hole at 0, so nothing ever drains
    let mut accepted = 0usize;

    // Eight blocks of cap/8 fill the budget exactly; every later block is
    // refused.
    for _ in 0..64 {
        if buffer.insert(offset, &data).is_ok() {
            accepted += 1;
        }
        assert!(
            buffer.buffered() <= cap,
            "buffered {} bytes, declared cap is {cap}",
            buffer.buffered()
        );
        offset += block as u64 + 1;
    }
    assert_eq!(accepted, 8, "the byte cap admitted the wrong number of blocks");
    assert_eq!(buffer.buffered(), cap);
}

/// §7.3's out-of-order *shape* budgets: the block count and the offset look-ahead.
///
/// Reorder is bounded by offset as well as by bytes ("接收按 offset 有限重排"), so
/// a peer that sends few bytes but at an absurd offset, or many tiny gapped
/// blocks, is refused instead of making the receiver remember an unbounded hole.
#[test]
fn reorder_buffer_offset_look_ahead_and_block_bounds_are_enforced() {
    // A single block an arbitrary distance ahead of the next expected offset.
    let mut buffer = ReorderBuffer::new(0);
    let far = 1u64 << 40;
    assert_eq!(
        buffer.insert(far, b"tiny").unwrap_err(),
        StreamError::TooFarAhead {
            offset: far,
            next: 0,
            ahead: far,
            limit: REORDER_BUFFER_BYTES as u64,
        }
    );

    // One byte further than the look-ahead budget is refused; exactly at it is
    // accepted, because a legal credit window always fits.
    let mut buffer = ReorderBuffer::new(0);
    let edge = REORDER_BUFFER_BYTES as u64;
    assert!(buffer.insert(edge, b"tiny").is_ok());
    let mut buffer = ReorderBuffer::new(0);
    assert!(matches!(
        buffer
            .insert(edge + 1, b"tiny")
            .expect_err("one byte past the look-ahead bound must be refused"),
        StreamError::TooFarAhead { .. }
    ));

    // More out-of-order blocks than REORDER_MAX_BLOCKS allows.
    let mut buffer = ReorderBuffer::new(0);
    let mut offset = 1u64;
    let mut refused = 0usize;
    for _ in 0..(REORDER_MAX_BLOCKS + 1) {
        if buffer.insert(offset, b"x").is_err() {
            refused += 1;
        }
        offset += 2;
    }
    assert_eq!(
        refused, 1,
        "the block budget must refuse exactly the block past REORDER_MAX_BLOCKS"
    );
    assert_eq!(buffer.buffered_blocks(), REORDER_MAX_BLOCKS);
    assert_eq!(buffer.block_limit(), REORDER_MAX_BLOCKS);

    // And the two budgets stay independent: a small block budget refuses the
    // second gapped block even when the byte budget is still wide open.
    let mut tiny = ReorderBuffer::new(0).with_block_limit(1);
    assert!(tiny.insert(1, b"x").is_ok());
    assert_eq!(
        tiny.insert(3, b"x").unwrap_err(),
        StreamError::TooManyBlocks {
            would_hold: 2,
            limit: 1
        }
    );

    // More out-of-order bytes than REORDER_MAX_OUT_OF_ORDER_BYTES allows.
    let mut buffer = ReorderBuffer::new(0);
    let big = vec![0u8; REORDER_MAX_OUT_OF_ORDER_BYTES + 1];
    assert!(
        buffer.insert(1, &big).is_err(),
        "held {} out-of-order bytes, past the declared REORDER_MAX_OUT_OF_ORDER_BYTES",
        big.len()
    );
}

// ---------------------------------------------------------------------------
// §7.5 byte credit
// ---------------------------------------------------------------------------

/// A peer cannot talk its way past the credit it was granted, and the window is
/// capped by the declared maximum.
#[test]
fn credit_account_refuses_an_acknowledgement_past_the_granted_limit() {
    // A window configured far past the declared maximum is clamped to it.
    assert_eq!(
        CreditAccount::new(STREAM_INITIAL_CREDIT, STREAM_MAX_CREDIT * 4).window(),
        STREAM_MAX_CREDIT
    );

    let mut account = CreditAccount::new(STREAM_INITIAL_CREDIT, STREAM_MAX_CREDIT);
    assert_eq!(account.window(), STREAM_MAX_CREDIT);
    assert_eq!(account.limit(), STREAM_INITIAL_CREDIT);

    // Exactly the granted limit is accepted.
    let limit = account.limit();
    account
        .record_received(0, limit as usize)
        .expect("a block exactly at the granted limit was refused");
    assert_eq!(account.received(), limit);
    assert_eq!(account.outstanding(), 0);

    // One byte past it is refused, and the limit does not move.
    assert_eq!(
        account.record_received(limit, 1).unwrap_err(),
        StreamError::CreditExceeded {
            sent_to: limit + 1,
            limit,
        }
    );
    assert_eq!(account.limit(), limit);
    assert_eq!(account.received(), limit);
}

/// However much the peer "acknowledges", outstanding credit never exceeds the
/// configured window, and credit is only replenished from what the application
/// actually consumed (§7.5).
#[test]
fn credit_never_exceeds_the_configured_window() {
    let mut account = CreditAccount::new(STREAM_INITIAL_CREDIT, STREAM_MAX_CREDIT);
    let window = account.window();

    // A peer that claims far more than it ever sent gains nothing.
    for _ in 0..64 {
        assert!(account
            .record_received(0, STREAM_INITIAL_CREDIT as usize + 1)
            .is_err());
        assert!(account.consume(u64::MAX).is_err());
        assert_eq!(account.received(), 0);
        assert_eq!(account.limit(), STREAM_INITIAL_CREDIT);
        assert!(account.outstanding() <= window);
    }

    // Real traffic inside the window, consumed as it arrives: the outstanding
    // credit stays pinned at the window and never exceeds it.
    let chunk = STREAM_INITIAL_CREDIT / 4;
    let mut offset = 0u64;
    for step in 0..16 {
        account
            .record_received(offset, chunk as usize)
            .unwrap_or_else(|e| panic!("in-order block {step} was refused: {e}"));
        offset += chunk;
        account.consume(chunk).unwrap();
        let outstanding = account.limit() - account.consumed();
        assert!(
            outstanding <= window,
            "outstanding credit {outstanding} exceeds the window {window}"
        );
    }
    assert!(account.limit() <= account.consumed() + window);
    assert!(account.window() <= STREAM_MAX_CREDIT);
}

// ---------------------------------------------------------------------------
// §4.3 carrier bounds
// ---------------------------------------------------------------------------

/// A POST body exactly at the declared byte cap decodes; one byte past it is
/// refused before any record is examined.
#[test]
fn post_decode_accepts_a_body_at_the_declared_byte_cap_and_rejects_one_past() {
    // 4 bytes of length prefix per record, so a full batch of this size lands
    // exactly on MAX_POST_BATCH_BYTES.
    let per_record = MAX_POST_BATCH_BYTES / MAX_POST_BATCH_RECORDS - 4;
    assert!(per_record <= MAX_CARRIER_RECORD);
    let batch: Vec<Vec<u8>> = vec![vec![7u8; per_record]; MAX_POST_BATCH_RECORDS];

    let body = post::encode(&batch).unwrap();
    assert_eq!(body.len(), MAX_POST_BATCH_BYTES);
    let decoded = post::decode(&body).unwrap();
    assert_eq!(decoded.len(), MAX_POST_BATCH_RECORDS);
    assert!(decoded.iter().all(|e| e.len() == per_record));

    let mut over = body;
    over.push(0);
    assert_eq!(
        post::decode(&over).unwrap_err(),
        CarrierError::BodyTooLarge {
            actual: MAX_POST_BATCH_BYTES + 1,
            limit: MAX_POST_BATCH_BYTES,
        }
    );
}

/// The record *count* cap and the per-record cap are independent of the byte
/// cap and are both enforced at their declared values.
#[test]
fn post_decode_enforces_the_declared_count_and_record_bounds() {
    // At the count cap: accepted.
    let at_cap: Vec<Vec<u8>> = vec![Vec::new(); MAX_POST_BATCH_RECORDS];
    let body = post::encode(&at_cap).unwrap();
    assert_eq!(body.len(), 4 * MAX_POST_BATCH_RECORDS);
    assert_eq!(post::decode(&body).unwrap().len(), MAX_POST_BATCH_RECORDS);

    // One past the count cap: refused on the encoder and the decoder.
    assert_eq!(
        post::encode(&vec![Vec::new(); MAX_POST_BATCH_RECORDS + 1]).unwrap_err(),
        CarrierError::TooManyRecords {
            actual: MAX_POST_BATCH_RECORDS + 1,
            limit: MAX_POST_BATCH_RECORDS,
        }
    );
    let mut over = body;
    over.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        post::decode(&over).unwrap_err(),
        CarrierError::TooManyRecords {
            actual: MAX_POST_BATCH_RECORDS + 1,
            limit: MAX_POST_BATCH_RECORDS,
        }
    );

    // A declared envelope length past the record bound is refused from the
    // declared number alone, before any slice is taken.
    let mut hostile = Vec::new();
    hostile.extend_from_slice(&((MAX_CARRIER_RECORD + 1) as u32).to_be_bytes());
    assert_eq!(
        post::decode(&hostile).unwrap_err(),
        CarrierError::EnvelopeTooLarge {
            actual: MAX_CARRIER_RECORD + 1,
            limit: MAX_CARRIER_RECORD,
        }
    );
}

/// The SSE decoder refuses an unterminated event one byte past the declared
/// event bound and accepts one exactly at it, and it also refuses an event
/// assembled from several `data:` lines past that bound.
#[test]
fn sse_decoder_enforces_the_declared_event_bound() {
    // Exactly at the bound: still legal, because it may yet be terminated.
    let mut decoder = SseDecoder::new();
    assert!(decoder.feed(&vec![b'A'; MAX_SSE_EVENT]).unwrap().is_empty());
    // One byte past it: refused, so `pending` cannot grow without limit.
    assert_eq!(
        decoder.feed(b"A").unwrap_err(),
        CarrierError::SseEventTooLarge {
            actual: MAX_SSE_EVENT + 1,
            limit: MAX_SSE_EVENT,
        }
    );

    // An event built from several individually-legal `data:` lines is bounded
    // by the accumulated size, not by the longest line.
    let piece = vec![b'A'; MAX_SSE_EVENT / 2];
    let mut line = b"data: ".to_vec();
    line.extend_from_slice(&piece);
    line.push(b'\n');
    let mut decoder = SseDecoder::new();
    assert!(decoder.feed(&line).unwrap().is_empty());
    assert_eq!(
        decoder.feed(&line).unwrap_err(),
        CarrierError::SseEventTooLarge {
            actual: piece.len() * 2 + 1,
            limit: MAX_SSE_EVENT,
        }
    );
}

/// The SSE carrier accepts an envelope exactly at the declared record bound and
/// refuses one byte past it.
#[test]
fn sse_encode_enforces_the_declared_carrier_record_bound() {
    let at_bound = vec![0u8; MAX_CARRIER_RECORD];
    let body = sse::encode(std::slice::from_ref(&at_bound)).unwrap();
    assert_eq!(sse::decode(&body).unwrap(), vec![at_bound]);

    let over = vec![0u8; MAX_CARRIER_RECORD + 1];
    assert_eq!(
        sse::encode(&[over]).unwrap_err(),
        CarrierError::EnvelopeTooLarge {
            actual: MAX_CARRIER_RECORD + 1,
            limit: MAX_CARRIER_RECORD,
        }
    );
}

/// The WS carrier accepts one message exactly at the declared record bound,
/// borrows it without copying, and refuses one byte past it.
#[test]
fn ws_decode_ref_enforces_the_declared_carrier_record_bound() {
    let at_bound = vec![0u8; MAX_CARRIER_RECORD];
    let borrowed = ws::decode_ref(&at_bound).unwrap();
    assert_eq!(
        borrowed.as_ptr(),
        at_bound.as_ptr(),
        "decode_ref copied the message instead of borrowing it"
    );
    assert_eq!(borrowed.len(), MAX_CARRIER_RECORD);
    assert_eq!(ws::decode(&at_bound).unwrap(), at_bound);
    assert_eq!(ws::encode(&at_bound).unwrap(), at_bound);

    let over = vec![0u8; MAX_CARRIER_RECORD + 1];
    let expected = CarrierError::EnvelopeTooLarge {
        actual: MAX_CARRIER_RECORD + 1,
        limit: MAX_CARRIER_RECORD,
    };
    assert_eq!(ws::decode_ref(&over).unwrap_err(), expected);
    assert_eq!(ws::decode(&over).unwrap_err(), expected);
    assert_eq!(ws::encode(&over).unwrap_err(), expected);
}

// ---------------------------------------------------------------------------
// §4.1 canonical metadata
// ---------------------------------------------------------------------------

/// A metadata document exactly at the declared size bound is accepted, one byte
/// past it is refused, and the refusal happens on the length alone — before any
/// parsing or allocation (§4.1: "先限长再分配/解码").
#[test]
fn canonical_metadata_at_the_declared_bound_is_accepted_and_one_past_refused() {
    // `{"k":"..."}` adds 8 bytes of framing around the string body.
    let body_len = MAX_METADATA - 8;
    let at_bound = Canonical::object([("k", Canonical::str("a".repeat(body_len)))]);
    let bytes = at_bound.to_bytes();
    assert_eq!(bytes.len(), MAX_METADATA);
    assert_eq!(Canonical::from_bytes(&bytes).unwrap(), at_bound);
    assert_eq!(at_bound.to_bounded_bytes().unwrap(), bytes);
    assert!(Canonical::is_canonical(&bytes).unwrap());

    let over = Canonical::object([("k", Canonical::str("a".repeat(body_len + 1)))]);
    let over_bytes = over.to_bytes();
    assert_eq!(over_bytes.len(), MAX_METADATA + 1);
    let too_large = CanonError::TooLarge {
        actual: MAX_METADATA + 1,
        limit: MAX_METADATA,
    };
    assert_eq!(Canonical::from_bytes(&over_bytes).unwrap_err(), too_large);
    assert_eq!(over.to_bounded_bytes().unwrap_err(), too_large);

    // Hostile bytes over the bound report the size error, not a parse error:
    // the bound is applied before the decoder looks at a single byte.
    let hostile = vec![0xffu8; MAX_METADATA * 4];
    assert_eq!(
        Canonical::from_bytes(&hostile).unwrap_err(),
        CanonError::TooLarge {
            actual: MAX_METADATA * 4,
            limit: MAX_METADATA,
        }
    );
}

/// The canonical decoder refuses the inputs that would let two implementations
/// disagree about the signed bytes: over-limit integers, duplicate keys, floats,
/// and nesting past the declared depth.
#[test]
fn canonical_json_refuses_hostile_values() {
    // Integers that do not fit i64 must travel as decimal strings (§4.1).
    for text in [
        "9223372036854775808",
        "-9223372036854775809",
        "18446744073709551615",
    ] {
        assert_eq!(
            Canonical::from_bytes(text.as_bytes()).unwrap_err(),
            CanonError::IntegerTooLarge(text.to_string()),
            "`{text}` was accepted as an i64"
        );
    }
    // The i64 edges themselves are exact.
    assert_eq!(
        Canonical::from_bytes(b"9223372036854775807").unwrap(),
        Canonical::Int(i64::MAX)
    );
    assert_eq!(
        Canonical::from_bytes(b"-9223372036854775808").unwrap(),
        Canonical::Int(i64::MIN)
    );

    // A duplicate key would give one signed field two values.
    assert_eq!(
        Canonical::from_bytes(br#"{"packet_no":"1","packet_no":"2"}"#).unwrap_err(),
        CanonError::DuplicateKey("packet_no".into())
    );
    assert_eq!(
        Canonical::try_object([("a", Canonical::int(1)), ("a", Canonical::int(2))]).unwrap_err(),
        CanonError::DuplicateKey("a".into())
    );

    // A float cannot round-trip byte-stably, so it is refused outright.
    assert!(matches!(
        Canonical::from_bytes(br#"{"n":1.0}"#).unwrap_err(),
        CanonError::FloatNotAllowed(_)
    ));
    assert!(matches!(
        Canonical::from_bytes(br#"{"n":1e3}"#).unwrap_err(),
        CanonError::FloatNotAllowed(_)
    ));

    // Nesting exactly at the declared depth is accepted; one past is refused.
    let at_depth = "[".repeat(MAX_CANON_DEPTH) + &"]".repeat(MAX_CANON_DEPTH);
    assert_eq!(
        Canonical::from_bytes(at_depth.as_bytes()).unwrap().depth(),
        MAX_CANON_DEPTH
    );
    let too_deep = "[".repeat(MAX_CANON_DEPTH + 1) + &"]".repeat(MAX_CANON_DEPTH + 1);
    assert_eq!(
        Canonical::from_bytes(too_deep.as_bytes()).unwrap_err(),
        CanonError::TooDeep
    );
}

/// The record layer applies the metadata, per-kind payload, and plaintext bounds
/// from `wsnet-limits` to *declared* lengths before it slices or allocates.
#[test]
fn record_decoding_refuses_declared_lengths_past_the_declared_bounds() {
    // metadata_len one past the metadata bound.
    let mut encoded = Vec::new();
    encoded.push(MessageKind::Ping.as_u8());
    encoded.extend_from_slice(&((MAX_METADATA + 1) as u32).to_be_bytes());
    assert_eq!(
        Record::decode_prefix(&encoded).unwrap_err(),
        RecordError::MetadataTooLarge(MAX_METADATA + 1)
    );

    // payload_len one past the per-kind limit.
    let mut encoded = Vec::new();
    encoded.push(MessageKind::Data.as_u8());
    encoded.extend_from_slice(&2u32.to_be_bytes());
    encoded.extend_from_slice(b"{}");
    encoded.extend_from_slice(&((MAX_TCP_PAYLOAD + 1) as u32).to_be_bytes());
    assert_eq!(
        Record::decode_prefix(&encoded).unwrap_err(),
        RecordError::PayloadTooLarge {
            kind: MessageKind::Data,
            actual: MAX_TCP_PAYLOAD + 1,
            limit: MAX_TCP_PAYLOAD,
        }
    );

    // A frame one byte past the record plaintext bound is refused up front.
    let over = vec![0u8; MAX_RECORD_PLAINTEXT + 1];
    assert_eq!(
        Record::decode_prefix(&over).unwrap_err(),
        RecordError::TooLarge {
            actual: MAX_RECORD_PLAINTEXT + 1,
            limit: MAX_RECORD_PLAINTEXT,
        }
    );
}
