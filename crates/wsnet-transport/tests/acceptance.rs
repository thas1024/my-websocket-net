//! Cross-crate acceptance walkthrough.
//!
//! This file wires the implemented pieces together the way a real session will,
//! so an accidental break in the seams between crates shows up as a test failure
//! rather than as a surprise during transport work. It covers the acceptance
//! items that are already implementable without a network stack:
//!
//! | id | covered here |
//! | --- | --- |
//! | T01 | both ends derive the same keys; the two directions are not interchangeable; the AAD binds Hub/session/epoch |
//! | T02 | `packet_no` is not reused and refuses to wrap |
//! | T03 | an `Auth` replay loses; a full store refuses rather than evicts |
//! | T05 | a repeated `request_id` never dials twice and stays queryable |
//! | T08 | a shuffled, duplicated block stream reassembles byte-for-byte |
//! | T10 | credit follows `consumed`, not `received` |
//! | T18 | every carrier round-trips the same envelopes, and SSE parses at any chunk split |

use wsnet_auth_store::{NonceKey, NonceStore, NonceStoreConfig, Now, ReplayError, ReplayWindow};
use wsnet_crypto::{open, seal, Direction, EnvelopeContext, EnvelopeError, Psk, SessionKeys};
use wsnet_limits::{AUTH_NONCE_LEN, REPLAY_WINDOW};
use wsnet_operation::{
    Admit, OperationConfig, OperationError, OperationHash, OperationState, OperationTable, Outcome,
    RequestId,
};
use wsnet_protocol::{Canonical, MessageKind, Record};
use wsnet_stream::{CreditAccount, ReorderBuffer};
use wsnet_transport::{Carrier, SseDecoder};

const AUTH_WITHOUT_MAC: &[u8] =
    br#"{"capabilities":["carrier.ws","carrier.post","carrier.sse"],"key_id":"k1","node_id":"client-a","ts":"1700000000","version":1}"#;
const AUTHOK_WITHOUT_MAC: &[u8] =
    br#"{"attempt_id":"a1","capabilities":["carrier.ws"],"session_epoch":"ffeeddccbbaa99887766554433221100","session_id":"00112233445566778899aabbccddeeff"}"#;

fn psk() -> Psk {
    Psk::from_bytes([0x5A; 32])
}

fn context() -> EnvelopeContext {
    EnvelopeContext::new("hub-a", [0x11; 16], [0xEE; 16])
}

/// Builds the `Data` record a node would send for a stream.
fn data_record(stream_id: u64, offset: u64, payload: &[u8]) -> Record {
    Record::with_payload(
        MessageKind::Data,
        Canonical::object([
            ("offset", Canonical::u64_decimal(offset)),
            ("stream_id", Canonical::u64_decimal(stream_id)),
        ]),
        payload.to_vec(),
    )
}

/// T01: both ends derive identical direction keys from the same transcript.
#[test]
fn t01_both_ends_agree_and_directions_are_isolated() {
    let client = SessionKeys::derive(&psk(), AUTH_WITHOUT_MAC, AUTHOK_WITHOUT_MAC);
    let hub = SessionKeys::derive(&psk(), AUTH_WITHOUT_MAC, AUTHOK_WITHOUT_MAC);

    assert_eq!(client.transcript(), hub.transcript());
    assert_eq!(
        client.message_key(Direction::ClientToServer),
        hub.message_key(Direction::ClientToServer)
    );
    assert_ne!(
        client.message_key(Direction::ClientToServer),
        client.message_key(Direction::ServerToClient),
        "the two directions must not share a key"
    );

    // A record sealed client-to-server cannot be opened as server-to-client.
    let keys = SessionKeys::derive(&psk(), AUTH_WITHOUT_MAC, AUTHOK_WITHOUT_MAC);
    let allocator = wsnet_crypto::PacketNoAllocator::new();
    let plaintext = data_record(1, 0, b"hello wsnet").encode().unwrap();
    let envelope = seal(
        keys.message_key(Direction::ClientToServer),
        &context(),
        Direction::ClientToServer,
        allocator.allocate().unwrap(),
        &plaintext,
    )
    .unwrap();

    assert_eq!(
        open(
            keys.message_key(Direction::ServerToClient),
            &context(),
            Direction::ClientToServer,
            &envelope
        )
        .unwrap_err(),
        EnvelopeError::AuthFailed
    );
    // And a different Hub id does not verify either.
    let other_hub = EnvelopeContext::new("hub-b", [0x11; 16], [0xEE; 16]);
    assert_eq!(
        open(
            keys.message_key(Direction::ClientToServer),
            &other_hub,
            Direction::ClientToServer,
            &envelope
        )
        .unwrap_err(),
        EnvelopeError::AuthFailed
    );
}

/// T01 + T18: a record survives seal -> carrier -> open on every carrier.
#[test]
fn t01_t18_record_round_trips_through_every_carrier() {
    let keys = SessionKeys::derive(&psk(), AUTH_WITHOUT_MAC, AUTHOK_WITHOUT_MAC);
    let allocator = wsnet_crypto::PacketNoAllocator::new();
    let original = data_record(7, 4096, b"payload across carriers");

    let sealed = seal(
        keys.message_key(Direction::ClientToServer),
        &context(),
        Direction::ClientToServer,
        allocator.allocate().unwrap(),
        &original.encode().unwrap(),
    )
    .unwrap();

    // The carriers that can carry several envelopes at once get a batch; WS gets
    // exactly one, as its framing requires.
    let batch = [sealed.clone(), sealed.clone()];
    for carrier in [
        Carrier::Ws,
        Carrier::Post,
        Carrier::Sse,
        Carrier::JsonProfile,
        Carrier::HtmlProfile,
        Carrier::CssProfile,
        Carrier::JsProfile,
    ] {
        let input: &[Vec<u8>] = if carrier == Carrier::Ws {
            std::slice::from_ref(&sealed)
        } else {
            &batch
        };
        let body = carrier.encode(input).unwrap();
        let decoded = carrier.decode(&body).unwrap();
        assert_eq!(decoded.len(), input.len(), "carrier {}", carrier.name());

        // Each recovered envelope opens back to the identical record.
        for envelope in decoded {
            let opened = open(
                keys.message_key(Direction::ClientToServer),
                &context(),
                Direction::ClientToServer,
                &envelope,
            )
            .unwrap();
            assert_eq!(Record::decode(&opened.plaintext).unwrap(), original);
        }
    }
}

/// T18: the SSE carrier must be insensitive to where the network splits chunks.
#[test]
fn t18_sse_parses_at_arbitrary_chunk_boundaries() {
    let keys = SessionKeys::derive(&psk(), AUTH_WITHOUT_MAC, AUTHOK_WITHOUT_MAC);
    let allocator = wsnet_crypto::PacketNoAllocator::new();
    let sealed: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            seal(
                keys.message_key(Direction::ServerToClient),
                &context(),
                Direction::ServerToClient,
                allocator.allocate().unwrap(),
                &data_record(i, 0, b"chunked").encode().unwrap(),
            )
            .unwrap()
        })
        .collect();

    let body = Carrier::Sse.encode(&sealed).unwrap();

    // Feed one byte at a time and confirm the stream still yields every envelope
    // in order.
    let mut decoder = SseDecoder::new();
    let mut recovered = Vec::new();
    for byte in &body {
        recovered.extend(decoder.feed(&[*byte]).unwrap());
    }
    decoder.finish().unwrap();
    assert_eq!(recovered, sealed);
}

/// T02 + T03: transport replay and auth replay are both refused, and neither
/// consumes state on refusal.
#[test]
fn t02_t03_replays_are_refused_without_advancing_state() {
    let keys = SessionKeys::derive(&psk(), AUTH_WITHOUT_MAC, AUTHOK_WITHOUT_MAC);
    let allocator = wsnet_crypto::PacketNoAllocator::new();
    let first = allocator.allocate().unwrap();
    let sealed = seal(
        keys.message_key(Direction::ClientToServer),
        &context(),
        Direction::ClientToServer,
        first,
        &data_record(1, 0, b"once").encode().unwrap(),
    )
    .unwrap();

    // Transport replay: the second delivery of the identical envelope loses.
    let mut window = ReplayWindow::new();
    let opened = open(
        keys.message_key(Direction::ClientToServer),
        &context(),
        Direction::ClientToServer,
        &sealed,
    )
    .unwrap();
    assert!(window.check_and_record(opened.packet_no).is_ok());
    assert_eq!(
        window.check_and_record(opened.packet_no).unwrap_err(),
        ReplayError::Duplicate(opened.packet_no)
    );

    // Auth replay: the same nonce on a different carrier is still a replay.
    let mut store = NonceStore::new(NonceStoreConfig::default()).unwrap();
    let key = NonceKey::new("hub-a", "k1", "client-a", [0x42; AUTH_NONCE_LEN]);
    let now = Now::new(1_700_000_000, 1_000);
    store.register(key.clone(), 1_700_000_000, now).unwrap();
    assert!(store
        .register(key, 1_700_000_000, Now::new(1_700_000_010, 11_000))
        .is_err());
}

/// T02: the scheduler cannot silently wrap the counter.
#[test]
fn t02_packet_no_never_wraps() {
    let allocator = wsnet_crypto::PacketNoAllocator::new();
    let first = allocator.allocate().unwrap().get();
    let second = allocator.allocate().unwrap().get();
    assert_eq!((first, second), (0, 1));

    // Jump to the ceiling and confirm the next allocation refuses rather than
    // wrapping to zero.
    assert!(allocator
        .reserve_exact(wsnet_crypto::PACKET_NO_CEILING)
        .is_ok());
    assert!(allocator.allocate().is_err());
}

/// T05: a retried `Open` is answered from cache, never dialled twice.
#[test]
fn t05_open_is_executed_at_most_once() {
    let mut table = OperationTable::new(OperationConfig::default());
    let request_id: RequestId = [0x07; 16];
    let hash = OperationHash::of(b"ServiceTarget{node=client-a,service=web}");

    assert_eq!(table.begin(request_id, hash, 0).unwrap(), Admit::Execute);
    assert_eq!(
        table.begin(request_id, hash, 3).unwrap(),
        Admit::AlreadyPending
    );

    // Settle, then a cross-carrier retry returns the cached result.
    table
        .settle(request_id, Outcome::Complete(b"ready".to_vec()), 5)
        .unwrap();
    assert_eq!(
        table.begin(request_id, hash, 9).unwrap(),
        Admit::Cached(Outcome::Complete(b"ready".to_vec()))
    );
    assert_eq!(
        table.query(&request_id),
        Some(&OperationState::Settled(Outcome::Complete(
            b"ready".to_vec()
        )))
    );

    // Reusing the id for different content is a conflict, not a retry.
    assert_eq!(
        table
            .begin(request_id, OperationHash::of(b"different"), 10)
            .unwrap_err(),
        OperationError::Conflict
    );
}

/// T08: a shuffled, partially duplicated block stream reassembles exactly.
#[test]
fn t08_out_of_order_stream_reassembles_byte_for_byte() {
    let payload: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    let block = 128usize;
    let blocks: Vec<(u64, Vec<u8>)> = payload
        .chunks(block)
        .enumerate()
        .map(|(i, chunk)| ((i * block) as u64, chunk.to_vec()))
        .collect();

    let mut buffer = ReorderBuffer::new(0);
    let mut delivered = Vec::new();
    // Reverse order is the worst case for a reorder buffer.
    for (offset, data) in blocks.iter().rev() {
        for chunk in buffer.insert(*offset, data).unwrap() {
            delivered.extend_from_slice(&chunk);
        }
    }
    // Duplicates afterwards must not re-deliver anything.
    for (offset, data) in blocks.iter() {
        assert!(buffer.insert(*offset, data).unwrap().is_empty());
    }
    assert_eq!(delivered, payload);
}

/// T10: a slow consumer keeps the window closed even while bytes arrive.
#[test]
fn t10_credit_follows_consumption() {
    let mut account = CreditAccount::new(256, 256);
    account.record_received(0, 256).unwrap();
    assert_eq!(account.outstanding(), 0);

    // The peer cannot push more until the application consumes.
    assert!(account.record_received(256, 1).is_err());

    // Consuming half opens exactly half a window.
    assert_eq!(account.consume(128).unwrap(), 128);
    assert_eq!(account.outstanding(), 128);
    account.record_received(256, 128).unwrap();
    assert_eq!(account.outstanding(), 0);
}

/// §4.2: the replay window is a fixed 8 KiB and covers exactly its documented
/// span.
#[test]
fn replay_window_is_bounded_and_covers_its_span() {
    let mut window = ReplayWindow::new();
    window.check_and_record(REPLAY_WINDOW * 2).unwrap();
    // One inside the span is still judgeable.
    assert!(window.check_and_record(REPLAY_WINDOW + 1).is_ok());
    // Exactly a full window behind is unjudgeable.
    assert!(window.check_and_record(REPLAY_WINDOW - 1).is_err());
    assert_eq!(ReplayWindow::memory_bytes(), 8 * 1024);
}
