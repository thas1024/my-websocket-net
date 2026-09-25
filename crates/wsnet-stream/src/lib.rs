//! Stream offsets, byte credit, and bounded reorder (DESIGN.md §7.3, §7.5).
//!
//! Two cooperating pieces:
//!
//! * [`ReorderBuffer`] turns possibly out-of-order, possibly duplicated blocks
//!   into an in-order byte stream. §7.3 requires "TCP 不静默丢字节", so a gap is
//!   held rather than skipped, and a conflicting overlap is a protocol error
//!   rather than something to paper over.
//! * [`CreditAccount`] tracks the flow-control window. §7.5 is specific:
//!   "按 `consumed_offset` 补credit；received确认不增加消费额度" — credit is
//!   replenished from what the *application consumed*, never merely from what
//!   arrived, so a slow consumer cannot be flooded by a fast network.
//!
//! Both are pure state machines with no I/O, so the failure injection T08/T10/
//! T12 ask for is a unit test rather than a network experiment.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use wsnet_limits::{
    CONTROL_RESERVE_BYTES, REORDER_BUFFER_BYTES, REORDER_MAX_BLOCKS, REORDER_MAX_OUT_OF_ORDER_BYTES,
    STREAM_MAX_CREDIT,
};

/// Errors from the stream state machines.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StreamError {
    /// The peer sent past the credit it was granted.
    #[error("peer sent to offset {sent_to}, which exceeds the granted limit {limit}")]
    CreditExceeded {
        /// Offset just past the offending block.
        sent_to: u64,
        /// The cumulative limit the peer was granted.
        limit: u64,
    },
    /// A block was already delivered in order.
    #[error("offset {offset} is below the next expected offset {next}")]
    AlreadyReceived {
        /// The offending offset.
        offset: u64,
        /// The next expected offset.
        next: u64,
    },
    /// A block arrived ahead of a gap; it must be buffered first.
    #[error("offset {offset} is ahead of the expected offset {next}")]
    OutOfOrder {
        /// The offending offset.
        offset: u64,
        /// The next expected offset.
        next: u64,
    },
    /// The application consumed more than it had received.
    #[error("cannot consume to {consumed_to}: only {received} bytes have been received")]
    ConsumeBeyondReceived {
        /// Offset just past the consumed block.
        consumed_to: u64,
        /// Bytes received in order.
        received: u64,
    },
    /// An offset or length overflowed the 64-bit offset space.
    #[error("stream offset overflow")]
    OffsetOverflow,
    /// The reorder buffer would exceed its byte budget.
    #[error("reorder buffer would hold {would_hold} bytes, limit is {limit}")]
    ReorderOverflow {
        /// Bytes the buffer would hold.
        would_hold: usize,
        /// Configured budget.
        limit: usize,
    },
    /// The reorder buffer would hold more out-of-order blocks than §7.3 allows.
    #[error("reorder buffer would hold {would_hold} blocks, limit is {limit}")]
    TooManyBlocks {
        /// Blocks the buffer would hold.
        would_hold: usize,
        /// Configured block budget.
        limit: usize,
    },
    /// A block starts further ahead of the next expected offset than §7.3 allows.
    ///
    /// §7.3 bounds reorder *by offset* ("接收按 offset 有限重排"), not only by
    /// bytes: without this, a peer could park a single tiny block at an arbitrary
    /// distance and force the receiver to remember an unbounded hole.
    #[error(
        "offset {offset} is {ahead} bytes ahead of the next expected offset {next}, past the {limit} bound"
    )]
    TooFarAhead {
        /// Offset the offending block starts at.
        offset: u64,
        /// The next expected offset.
        next: u64,
        /// How far ahead the block starts.
        ahead: u64,
        /// The configured look-ahead bound.
        limit: u64,
    },
    /// A block partially overlapped data that was already delivered, or
    /// overlapped a buffered block with different boundaries.
    #[error("block at offset {offset} length {length} conflicts with neighbouring data")]
    ConflictingOverlap {
        /// The offending offset.
        offset: u64,
        /// The offending length.
        length: usize,
    },
}

/// Reassembles an ordered byte stream from possibly out-of-order blocks.
///
/// §7.3 fixes three budgets for the out-of-order part of one direction: at most
/// [`REORDER_MAX_OUT_OF_ORDER_BYTES`] bytes, at most [`REORDER_MAX_BLOCKS`]
/// blocks, and — inside the per-direction total of [`REORDER_BUFFER_BYTES`] — a
/// bounded distance ahead of the next expected offset. All three are enforced
/// here rather than left as documentation, because a peer can choose any of them
/// adversarially.
#[derive(Debug)]
pub struct ReorderBuffer {
    next: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    buffered: usize,
    limit_bytes: usize,
    /// §7.3's block budget for the out-of-order part.
    limit_blocks: usize,
    /// §7.3's per-direction total, which also bounds how far ahead a block may
    /// start: the credit window never lets the peer legitimately send past it.
    look_ahead_bytes: u64,
}

impl ReorderBuffer {
    /// Creates a buffer that expects `start_offset` next.
    pub fn new(start_offset: u64) -> Self {
        ReorderBuffer::with_limit(start_offset, REORDER_MAX_OUT_OF_ORDER_BYTES)
    }

    /// Creates a buffer with an explicit byte budget.
    ///
    /// The explicit budget is clamped to [`REORDER_BUFFER_BYTES`], §7.3's
    /// per-direction total unconsumed budget: the out-of-order part is a subset of
    /// the total, so a caller cannot raise it past the design's own ceiling.
    pub fn with_limit(start_offset: u64, limit_bytes: usize) -> Self {
        ReorderBuffer {
            next: start_offset,
            pending: BTreeMap::new(),
            buffered: 0,
            limit_bytes: limit_bytes.min(REORDER_BUFFER_BYTES),
            limit_blocks: REORDER_MAX_BLOCKS,
            look_ahead_bytes: REORDER_BUFFER_BYTES as u64,
        }
    }

    /// Overrides §7.3's block budget, for tests that need a small buffer.
    pub fn with_block_limit(mut self, limit_blocks: usize) -> Self {
        self.limit_blocks = limit_blocks;
        self
    }

    /// The next offset that will be delivered.
    pub fn next_offset(&self) -> u64 {
        self.next
    }

    /// Bytes currently held out of order.
    pub fn buffered(&self) -> usize {
        self.buffered
    }

    /// Blocks currently held out of order.
    pub fn buffered_blocks(&self) -> usize {
        self.pending.len()
    }

    /// The out-of-order byte budget in force.
    pub fn byte_limit(&self) -> usize {
        self.limit_bytes
    }

    /// The out-of-order block budget in force (§7.3).
    pub fn block_limit(&self) -> usize {
        self.limit_blocks
    }

    /// Bytes of control queue a saturated data buffer must leave free (§7.5).
    pub const fn control_reserve() -> usize {
        CONTROL_RESERVE_BYTES
    }

    /// Inserts one block and returns the blocks, in order, that became
    /// deliverable.
    ///
    /// * A block entirely below the next expected offset is a retransmit and is
    ///   dropped: §7.3 allows recovery but requires "只交付一次".
    /// * A block straddling the boundary is a conflicting overlap, because §4.1
    ///   requires retransmission to "保持已分配分块边界"; a partial overlap means
    ///   the peer's block boundaries disagree with ours and cannot be verified.
    /// * A gap is buffered, bounded by the byte budget.
    pub fn insert(&mut self, offset: u64, data: &[u8]) -> Result<Vec<Vec<u8>>, StreamError> {
        Ok(self
            .insert_offsets(offset, data)?
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect())
    }

    /// Like [`ReorderBuffer::insert`], but each delivered block carries the
    /// absolute offset it starts at.
    ///
    /// The session engine needs those offsets: they are what it puts into the
    /// `Data` metadata of the next hop, and §4.1 requires an offset to mean "the
    /// start of this direction's original business bytes, excluding framing".
    pub fn insert_offsets(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> Result<Vec<(u64, Vec<u8>)>, StreamError> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(StreamError::OffsetOverflow)?;

        // Already delivered in full: a pure retransmit.
        if end <= self.next {
            return Ok(Vec::new());
        }
        // Straddles the delivered boundary: unverifiable overlap.
        if offset < self.next {
            return Err(StreamError::ConflictingOverlap {
                offset,
                length: data.len(),
            });
        }
        // §7.3 bounds reorder by offset as well as by bytes: a block arbitrarily
        // far ahead would force the receiver to remember an unbounded hole, and
        // §7.5's credit window means the peer could never have sent it honestly.
        let ahead = offset - self.next;
        if ahead > self.look_ahead_bytes {
            return Err(StreamError::TooFarAhead {
                offset,
                next: self.next,
                ahead,
                limit: self.look_ahead_bytes,
            });
        }

        // Any buffered block starting at or before this offset must not overlap.
        if let Some((&prev_offset, prev_data)) = self.pending.range(..=offset).next_back() {
            let prev_end = prev_offset + prev_data.len() as u64;
            if prev_offset == offset {
                // Same start: identical content is a duplicate, anything else is
                // a conflict.
                if prev_data.as_slice() == data {
                    return Ok(Vec::new());
                }
                return Err(StreamError::ConflictingOverlap {
                    offset,
                    length: data.len(),
                });
            }
            if prev_end > offset {
                return Err(StreamError::ConflictingOverlap {
                    offset,
                    length: data.len(),
                });
            }
        }
        // And no later buffered block may be overlapped by this one.
        if let Some((&next_offset, _)) = self.pending.range(offset..).next() {
            if next_offset < end {
                return Err(StreamError::ConflictingOverlap {
                    offset,
                    length: data.len(),
                });
            }
        }

        // A block that starts at the next expected offset is delivered at once and
        // never buffered, so the block budget applies only to the out-of-order
        // part; checking it unconditionally would refuse a legal in-order block
        // once the buffer happened to be full.
        let would_hold = self.buffered + data.len();
        if would_hold > self.limit_bytes {
            return Err(StreamError::ReorderOverflow {
                would_hold,
                limit: self.limit_bytes,
            });
        }
        if offset != self.next {
            let blocks = self.pending.len() + 1;
            if blocks > self.limit_blocks {
                return Err(StreamError::TooManyBlocks {
                    would_hold: blocks,
                    limit: self.limit_blocks,
                });
            }
        }

        self.buffered += data.len();
        self.pending.insert(offset, data.to_vec());

        // Drain everything that is now contiguous.
        let mut delivered = Vec::new();
        while let Some(block) = self.pending.remove(&self.next) {
            let start = self.next;
            self.next += block.len() as u64;
            self.buffered -= block.len();
            delivered.push((start, block));
        }
        Ok(delivered)
    }
}

/// Cumulative byte-credit accounting for one direction of one stream.
#[derive(Debug, Clone)]
pub struct CreditAccount {
    window: u64,
    received: u64,
    consumed: u64,
    limit: u64,
}

impl CreditAccount {
    /// Creates an account that has granted `initial_credit` bytes.
    pub fn new(initial_credit: u64, window: u64) -> Self {
        let window = window.min(STREAM_MAX_CREDIT).max(initial_credit);
        CreditAccount {
            window,
            received: 0,
            consumed: 0,
            limit: initial_credit,
        }
    }

    /// Bytes received in order.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Bytes handed to the application.
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// The cumulative offset the peer is allowed to reach.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Unused credit.
    pub fn outstanding(&self) -> u64 {
        self.limit.saturating_sub(self.received)
    }

    /// The configured maximum outstanding credit.
    pub fn window(&self) -> u64 {
        self.window
    }

    /// Records a block that arrived in order.
    ///
    /// Out-of-order blocks must go through [`ReorderBuffer`] first; this account
    /// deliberately rejects them so that the two concerns stay separate.
    pub fn record_received(&mut self, offset: u64, len: usize) -> Result<(), StreamError> {
        if len == 0 {
            return Ok(());
        }
        let end = offset
            .checked_add(len as u64)
            .ok_or(StreamError::OffsetOverflow)?;
        if end > self.limit {
            return Err(StreamError::CreditExceeded {
                sent_to: end,
                limit: self.limit,
            });
        }
        if offset < self.received {
            return Err(StreamError::AlreadyReceived {
                offset,
                next: self.received,
            });
        }
        if offset > self.received {
            return Err(StreamError::OutOfOrder {
                offset,
                next: self.received,
            });
        }
        self.received = end;
        Ok(())
    }

    /// Records that the application consumed `bytes`, and returns the credit to
    /// grant the peer.
    ///
    /// Credit is derived from `consumed`, not from `received` (§7.5), which is
    /// what prevents a slow application from being flooded.
    pub fn consume(&mut self, bytes: u64) -> Result<u64, StreamError> {
        let consumed_to = self
            .consumed
            .checked_add(bytes)
            .ok_or(StreamError::OffsetOverflow)?;
        if consumed_to > self.received {
            return Err(StreamError::ConsumeBeyondReceived {
                consumed_to,
                received: self.received,
            });
        }
        self.consumed = consumed_to;

        let desired = self.consumed.saturating_add(self.window);
        let grant = desired.saturating_sub(self.limit);
        self.limit = self.limit.saturating_add(grant);
        Ok(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------- reorder

    #[test]
    fn in_order_blocks_are_delivered_immediately() {
        let mut buffer = ReorderBuffer::new(0);
        assert_eq!(buffer.insert(0, b"abc").unwrap(), vec![b"abc".to_vec()]);
        assert_eq!(buffer.insert(3, b"def").unwrap(), vec![b"def".to_vec()]);
        assert_eq!(buffer.next_offset(), 6);
        assert_eq!(buffer.buffered(), 0);
    }

    /// T08: out-of-order blocks are held and then released in order.
    #[test]
    fn out_of_order_blocks_are_released_in_order() {
        let mut buffer = ReorderBuffer::new(0);
        assert!(buffer.insert(3, b"def").unwrap().is_empty());
        assert!(buffer.insert(6, b"ghi").unwrap().is_empty());
        assert_eq!(buffer.buffered(), 6);

        // The missing head releases the whole run at once.
        assert_eq!(
            buffer.insert(0, b"abc").unwrap(),
            vec![b"abc".to_vec(), b"def".to_vec(), b"ghi".to_vec()]
        );
        assert_eq!(buffer.next_offset(), 9);
        assert_eq!(buffer.buffered(), 0);
    }

    /// T08: duplicates are dropped, never delivered twice.
    #[test]
    fn duplicates_are_dropped() {
        let mut buffer = ReorderBuffer::new(0);
        buffer.insert(0, b"abc").unwrap();
        // Fully below the next offset.
        assert!(buffer.insert(0, b"abc").unwrap().is_empty());
        assert!(buffer.insert(1, b"bc").unwrap().is_empty());
        assert_eq!(buffer.next_offset(), 3);
    }

    /// T08: a duplicate of a *buffered* block is dropped.
    #[test]
    fn duplicate_buffered_block_is_dropped() {
        let mut buffer = ReorderBuffer::new(0);
        buffer.insert(3, b"def").unwrap();
        assert_eq!(buffer.buffered(), 3);
        assert!(buffer.insert(3, b"def").unwrap().is_empty());
        assert_eq!(buffer.buffered(), 3, "a duplicate must not accumulate");
    }

    /// T08: conflicting overlaps are explicit errors, not silent corruption.
    #[test]
    fn conflicting_overlaps_are_rejected() {
        // Straddling the delivered boundary.
        let mut buffer = ReorderBuffer::new(0);
        buffer.insert(0, b"abc").unwrap();
        assert_eq!(
            buffer.insert(2, b"cde").unwrap_err(),
            StreamError::ConflictingOverlap {
                offset: 2,
                length: 3
            }
        );

        // Same offset, different content.
        let mut buffer = ReorderBuffer::new(0);
        buffer.insert(4, b"abcd").unwrap();
        assert_eq!(
            buffer.insert(4, b"wxyz").unwrap_err(),
            StreamError::ConflictingOverlap {
                offset: 4,
                length: 4
            }
        );

        // Different boundaries overlapping a buffered block.
        let mut buffer = ReorderBuffer::new(0);
        buffer.insert(4, b"abcd").unwrap();
        assert_eq!(
            buffer.insert(6, b"cdef").unwrap_err(),
            StreamError::ConflictingOverlap {
                offset: 6,
                length: 4
            }
        );
    }

    /// T08/T12: the buffer is bounded, and an overflow is explicit.
    #[test]
    fn reorder_buffer_is_bounded() {
        let mut buffer = ReorderBuffer::with_limit(0, 10);
        buffer.insert(2, &[0u8; 8]).unwrap();
        assert_eq!(buffer.buffered(), 8);
        assert_eq!(
            buffer.insert(12, &[0u8; 4]).unwrap_err(),
            StreamError::ReorderOverflow {
                would_hold: 12,
                limit: 10
            }
        );
        // The refused block left no trace.
        assert_eq!(buffer.buffered(), 8);
    }

    /// A byte stream reassembled from arbitrary order and duplication must equal
    /// the original, exactly once.
    #[test]
    fn shuffled_blocks_reassemble_byte_for_byte() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let block = 64usize;
        let blocks: Vec<(u64, Vec<u8>)> = payload
            .chunks(block)
            .enumerate()
            .map(|(i, chunk)| ((i * block) as u64, chunk.to_vec()))
            .collect();

        let mut seed = 0xDEAD_BEEF_CAFE_F00Du64;
        let mut order: Vec<usize> = (0..blocks.len()).collect();
        for i in (1..order.len()).rev() {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let j = (seed % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }

        let mut buffer = ReorderBuffer::new(0);
        let mut delivered = Vec::new();
        for index in order {
            let (offset, data) = &blocks[index];
            for chunk in buffer.insert(*offset, data).unwrap() {
                delivered.extend_from_slice(&chunk);
            }
            // Occasionally replay an already-sent block.
            let _ = buffer.insert(*offset, data);
        }
        assert_eq!(
            delivered, payload,
            "reassembled stream differs from the source"
        );
    }

    #[test]
    fn zero_length_blocks_are_no_ops() {
        let mut buffer = ReorderBuffer::new(5);
        assert!(buffer.insert(5, b"").unwrap().is_empty());
        assert_eq!(buffer.next_offset(), 5);
    }

    #[test]
    fn offset_overflow_is_rejected() {
        let mut buffer = ReorderBuffer::new(0);
        assert_eq!(
            buffer.insert(u64::MAX, b"ab").unwrap_err(),
            StreamError::OffsetOverflow
        );
    }

    /// §7.3 fixes all three out-of-order budgets, so the defaults must be the
    /// declared constants rather than the per-direction total.
    #[test]
    fn the_default_out_of_order_budgets_are_the_designs() {
        let buffer = ReorderBuffer::new(0);
        assert_eq!(buffer.byte_limit(), REORDER_MAX_OUT_OF_ORDER_BYTES);
        assert_eq!(buffer.block_limit(), REORDER_MAX_BLOCKS);
        assert!(
            buffer.byte_limit() < REORDER_BUFFER_BYTES,
            "the out-of-order part is a strict subset of the per-direction total"
        );
        // The explicit budget is clamped to the per-direction total, so a caller
        // cannot raise the out-of-order budget past the design's ceiling.
        assert_eq!(
            ReorderBuffer::with_limit(0, REORDER_BUFFER_BYTES * 4).byte_limit(),
            REORDER_BUFFER_BYTES
        );
    }

    /// §7.3: reorder is bounded by offset, not only by bytes.
    #[test]
    fn a_block_far_ahead_of_the_expected_offset_is_refused() {
        let mut buffer = ReorderBuffer::new(0);
        assert_eq!(
            buffer.insert(REORDER_BUFFER_BYTES as u64 + 1, b"tiny").unwrap_err(),
            StreamError::TooFarAhead {
                offset: REORDER_BUFFER_BYTES as u64 + 1,
                next: 0,
                ahead: REORDER_BUFFER_BYTES as u64 + 1,
                limit: REORDER_BUFFER_BYTES as u64,
            }
        );
        // Exactly at the bound is still accepted, because a peer that respects its
        // credit window can legitimately be that far ahead.
        assert!(buffer
            .insert(REORDER_BUFFER_BYTES as u64, b"tiny")
            .is_ok());
    }

    /// The block budget counts buffered blocks, not delivered ones: closing a hole
    /// must never be refused because the buffer happens to be full.
    #[test]
    fn the_block_budget_never_refuses_an_in_order_block() {
        let mut buffer = ReorderBuffer::new(0).with_block_limit(2);
        assert!(buffer.insert(1, b"b").unwrap().is_empty());
        assert!(buffer.insert(3, b"d").unwrap().is_empty());
        assert_eq!(buffer.buffered_blocks(), 2, "the budget is exactly full");
        assert_eq!(
            buffer.insert(0, b"a").unwrap(),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        assert_eq!(buffer.next_offset(), 2);
        assert_eq!(buffer.buffered_blocks(), 1);
        assert_eq!(
            buffer.insert(2, b"c").unwrap(),
            vec![b"c".to_vec(), b"d".to_vec()]
        );
        assert_eq!(buffer.buffered_blocks(), 0);

        // The block past the budget is refused, and leaves no trace.
        let mut buffer = ReorderBuffer::new(0).with_block_limit(1);
        assert!(buffer.insert(1, b"b").unwrap().is_empty());
        assert_eq!(
            buffer.insert(3, b"d").unwrap_err(),
            StreamError::TooManyBlocks {
                would_hold: 2,
                limit: 1
            }
        );
        assert_eq!(buffer.buffered_blocks(), 1);
        assert_eq!(buffer.buffered(), 1);
    }

    // ------------------------------------------------------------------ credit

    #[test]
    fn initial_credit_is_granted_up_front() {
        let account = CreditAccount::new(1024, 4096);
        assert_eq!(account.limit(), 1024);
        assert_eq!(account.outstanding(), 1024);
        assert_eq!(account.received(), 0);
    }

    #[test]
    fn in_order_receipt_is_recorded() {
        let mut account = CreditAccount::new(100, 100);
        account.record_received(0, 40).unwrap();
        assert_eq!(account.received(), 40);
        account.record_received(40, 60).unwrap();
        assert_eq!(account.received(), 100);
        assert_eq!(account.outstanding(), 0);
    }

    /// T10: a peer may not send past its credit.
    #[test]
    fn sending_past_the_granted_credit_is_rejected() {
        let mut account = CreditAccount::new(100, 100);
        assert_eq!(
            account.record_received(0, 101).unwrap_err(),
            StreamError::CreditExceeded {
                sent_to: 101,
                limit: 100
            }
        );
        assert_eq!(
            account.received(),
            0,
            "a refused block must not advance state"
        );
    }

    /// T10: credit is replenished from `consumed`, not from `received`.
    #[test]
    fn credit_follows_consumed_not_received() {
        let mut account = CreditAccount::new(100, 100);
        account.record_received(0, 100).unwrap();

        // Received but not yet consumed: no new credit may be granted.
        assert_eq!(account.consume(0).unwrap(), 0);
        assert_eq!(account.limit(), 100);

        // Consuming 40 grants exactly 40 more.
        assert_eq!(account.consume(40).unwrap(), 40);
        assert_eq!(account.limit(), 140);
        assert_eq!(account.outstanding(), 40);

        // Consuming the rest restores a full window.
        assert_eq!(account.consume(60).unwrap(), 60);
        assert_eq!(account.limit(), 200);
        assert_eq!(account.outstanding(), 100);
    }

    #[test]
    fn consuming_more_than_received_is_rejected() {
        let mut account = CreditAccount::new(100, 100);
        account.record_received(0, 10).unwrap();
        assert_eq!(
            account.consume(11).unwrap_err(),
            StreamError::ConsumeBeyondReceived {
                consumed_to: 11,
                received: 10
            }
        );
        assert_eq!(account.consumed(), 0);
    }

    /// T10: a slow consumer keeps the window closed no matter how much arrives.
    #[test]
    fn a_slow_consumer_never_opens_the_window() {
        let mut account = CreditAccount::new(100, 100);
        // The peer fills the window but the application consumes nothing.
        account.record_received(0, 100).unwrap();
        for _ in 0..10 {
            assert_eq!(account.consume(0).unwrap(), 0);
        }
        assert_eq!(account.outstanding(), 0);
        // Any further send is refused, so the peer must wait.
        assert!(account.record_received(100, 1).is_err());
    }

    /// T10: duplicate or late `Progress` must not over-grant.
    #[test]
    fn duplicate_and_late_receipts_do_not_over_grant() {
        let mut account = CreditAccount::new(100, 100);
        account.record_received(0, 50).unwrap();
        assert_eq!(
            account.record_received(0, 50).unwrap_err(),
            StreamError::AlreadyReceived {
                offset: 0,
                next: 50
            }
        );
        assert_eq!(
            account.record_received(60, 10).unwrap_err(),
            StreamError::OutOfOrder {
                offset: 60,
                next: 50
            }
        );
        assert_eq!(account.received(), 50);
        assert_eq!(account.limit(), 100);
    }

    #[test]
    fn the_window_is_capped() {
        let account = CreditAccount::new(100, STREAM_MAX_CREDIT * 4);
        assert_eq!(account.window(), STREAM_MAX_CREDIT);
    }

    #[test]
    fn zero_length_receipts_are_no_ops() {
        let mut account = CreditAccount::new(100, 100);
        account.record_received(0, 0).unwrap();
        assert_eq!(account.received(), 0);
    }

    /// The two pieces compose: reorder first, then credit.
    #[test]
    fn reorder_then_credit_composes() {
        let mut buffer = ReorderBuffer::new(0);
        let mut account = CreditAccount::new(64, 64);

        // Second block arrives first.
        assert!(buffer.insert(32, &[7u8; 32]).unwrap().is_empty());
        // Then the first block; both become deliverable.
        let delivered = buffer.insert(0, &[3u8; 32]).unwrap();
        assert_eq!(delivered.len(), 2);

        for chunk in &delivered {
            account
                .record_received(account.received(), chunk.len())
                .unwrap();
        }
        assert_eq!(account.received(), 64);

        // Consuming the 64 bytes grants 64 more.
        assert_eq!(account.consume(64).unwrap(), 64);
        assert_eq!(account.limit(), 128);
    }
}
