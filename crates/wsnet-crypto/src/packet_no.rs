//! The per-direction `packet_no` allocator (DESIGN.md §4.2).
//!
//! §4.2 requires one atomic counter per direction shared by *every* carrier:
//!
//! > 每方向全部载体共用一个原子 `packet_no:u64` 分配器（初值 0）... 禁止按
//! > WS/POST/SSE 各自从零计数，禁止计数回绕或恢复已失去计数状态的会话。
//!
//! Because the counter is also the AEAD nonce, a repeated value is catastrophic.
//! [`PacketNo`] is therefore opaque: the only ways to obtain one are
//! [`PacketNoAllocator::allocate`] and the explicit, still-monotonic
//! [`PacketNoAllocator::reserve_exact`]. Neither can ever hand out a value twice,
//! including under concurrent use.

use core::sync::atomic::{AtomicU64, Ordering};

use wsnet_limits::PACKET_NO_EXHAUSTION_MARGIN;

/// Highest `packet_no` that may ever be allocated.
///
/// §4.2 says allocation must stop "接近 u64 上限前" and that the session must be
/// re-established with a fresh transcript/epoch rather than wrapping.
pub const PACKET_NO_CEILING: u64 = u64::MAX - PACKET_NO_EXHAUSTION_MARGIN;

/// Sentinel meaning "this allocator is spent and must never produce another value".
const EXHAUSTED: u64 = u64::MAX;

/// Errors from the `packet_no` allocator.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PacketNoError {
    /// The counter reached the ceiling; the session must re-authenticate.
    #[error("packet_no space exhausted; the session must be re-established")]
    Exhausted,
    /// A caller asked for a value that has already been used in this direction.
    #[error("packet_no {requested} was already allocated (next unused is {next})")]
    WouldReuse {
        /// The value the caller asked for.
        requested: u64,
        /// The next unused value.
        next: u64,
    },
}

/// A `packet_no` that is guaranteed unique within its direction.
///
/// The inner value is private so that a nonce cannot be assembled from an
/// arbitrary integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PacketNo(u64);

impl PacketNo {
    /// Rebuilds a `PacketNo` from a value already read off the wire.
    ///
    /// Crate-internal on purpose: a `PacketNo` decoded from an envelope must only
    /// be produced *after* AEAD authentication succeeds, so that an attacker
    /// cannot choose a nonce. External callers go through the allocator.
    pub(crate) const fn from_raw(value: u64) -> Self {
        PacketNo(value)
    }

    /// The raw counter value, for the wire header and the replay window.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The big-endian wire encoding used in the envelope header and the nonce.
    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

impl core::fmt::Display for PacketNo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One atomic allocator per direction, shared by every carrier.
#[derive(Debug, Default)]
pub struct PacketNoAllocator {
    next: AtomicU64,
}

impl PacketNoAllocator {
    /// Creates an allocator whose first value is 0, as §4.2 specifies.
    pub const fn new() -> Self {
        PacketNoAllocator {
            next: AtomicU64::new(0),
        }
    }

    /// The next value that would be allocated, or `None` once exhausted.
    pub fn next_unused(&self) -> Option<u64> {
        let current = self.next.load(Ordering::Acquire);
        if current == EXHAUSTED || current > PACKET_NO_CEILING {
            None
        } else {
            Some(current)
        }
    }

    /// Returns `true` once the allocator can no longer hand out values.
    pub fn is_exhausted(&self) -> bool {
        let current = self.next.load(Ordering::Acquire);
        current == EXHAUSTED || current > PACKET_NO_CEILING
    }

    /// Allocates the next `packet_no`, or fails once the ceiling is reached.
    ///
    /// This never wraps and never returns a value twice, even if several carrier
    /// tasks call it concurrently.
    pub fn allocate(&self) -> Result<PacketNo, PacketNoError> {
        let mut current = self.next.load(Ordering::Acquire);
        loop {
            if current == EXHAUSTED || current > PACKET_NO_CEILING {
                // Latch the terminal state so later callers fail fast.
                let _ = self.next.compare_exchange(
                    current,
                    EXHAUSTED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                return Err(PacketNoError::Exhausted);
            }
            // `current <= PACKET_NO_CEILING < u64::MAX`, so this cannot overflow.
            match self.next.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(PacketNo(current)),
                Err(observed) => current = observed,
            }
        }
    }

    /// Reserves exactly `value`, for deterministic test vectors and for recovery
    /// paths that have already negotiated a number.
    ///
    /// The allocator stays monotonic: asking for a value that was already handed
    /// out is an error rather than a silent nonce reuse.
    pub fn reserve_exact(&self, value: u64) -> Result<PacketNo, PacketNoError> {
        if value > PACKET_NO_CEILING {
            return Err(PacketNoError::Exhausted);
        }
        let mut current = self.next.load(Ordering::Acquire);
        loop {
            if current == EXHAUSTED {
                return Err(PacketNoError::Exhausted);
            }
            if value < current {
                return Err(PacketNoError::WouldReuse {
                    requested: value,
                    next: current,
                });
            }
            match self.next.compare_exchange_weak(
                current,
                value + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(PacketNo(value)),
                Err(observed) => current = observed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_starts_at_zero_and_increments() {
        let alloc = PacketNoAllocator::new();
        assert_eq!(alloc.allocate().unwrap().get(), 0);
        assert_eq!(alloc.allocate().unwrap().get(), 1);
        assert_eq!(alloc.allocate().unwrap().get(), 2);
        assert_eq!(alloc.next_unused(), Some(3));
    }

    #[test]
    fn reserve_exact_can_jump_forward_then_continues() {
        let alloc = PacketNoAllocator::new();
        assert_eq!(alloc.reserve_exact(1000).unwrap().get(), 1000);
        assert_eq!(alloc.next_unused(), Some(1001));
        assert_eq!(alloc.allocate().unwrap().get(), 1001);
    }

    /// T02: a value already handed out must never be issued again.
    #[test]
    fn reserve_exact_refuses_to_reuse() {
        let alloc = PacketNoAllocator::new();
        alloc.allocate().unwrap(); // 0
        alloc.allocate().unwrap(); // 1
        assert_eq!(
            alloc.reserve_exact(0).unwrap_err(),
            PacketNoError::WouldReuse {
                requested: 0,
                next: 2
            }
        );
        // The current value is still available, and the failed call did not move it.
        assert_eq!(alloc.reserve_exact(2).unwrap().get(), 2);
    }

    /// T02: the counter must refuse to wrap and must latch the terminal state.
    #[test]
    fn ceiling_is_enforced_and_never_wraps() {
        let alloc = PacketNoAllocator::new();
        assert_eq!(
            alloc.reserve_exact(PACKET_NO_CEILING).unwrap().get(),
            PACKET_NO_CEILING
        );
        assert_eq!(alloc.allocate().unwrap_err(), PacketNoError::Exhausted);
        assert_eq!(alloc.allocate().unwrap_err(), PacketNoError::Exhausted);
        assert!(alloc.is_exhausted());
        assert_eq!(alloc.next_unused(), None);
        // Even a jump past the ceiling is refused rather than wrapped.
        assert_eq!(
            alloc.reserve_exact(PACKET_NO_CEILING + 1).unwrap_err(),
            PacketNoError::Exhausted
        );
        assert_eq!(
            alloc.reserve_exact(0).unwrap_err(),
            PacketNoError::Exhausted
        );
    }

    #[test]
    fn reserve_exact_past_ceiling_is_refused_from_a_fresh_allocator() {
        let alloc = PacketNoAllocator::new();
        assert_eq!(
            alloc.reserve_exact(PACKET_NO_CEILING + 1).unwrap_err(),
            PacketNoError::Exhausted
        );
    }

    /// §4.2: several carriers share one allocator, so concurrent allocation must
    /// still produce every value exactly once.
    #[test]
    fn concurrent_allocation_never_duplicates() {
        use std::collections::BTreeSet;
        use std::sync::Arc;

        let alloc = Arc::new(PacketNoAllocator::new());
        let per_thread = 2_000;
        let threads = 8;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let alloc = Arc::clone(&alloc);
            handles.push(std::thread::spawn(move || {
                (0..per_thread)
                    .map(|_| alloc.allocate().unwrap().get())
                    .collect::<Vec<_>>()
            }));
        }

        let mut seen = BTreeSet::new();
        for handle in handles {
            for value in handle.join().unwrap() {
                assert!(seen.insert(value), "packet_no {value} was handed out twice");
            }
        }
        assert_eq!(seen.len(), threads * per_thread);
        // The set must be exactly 0..n with no gaps, since every allocation wins
        // a compare-exchange on a monotonic counter.
        assert_eq!(seen.iter().copied().min(), Some(0));
        assert_eq!(
            seen.iter().copied().max(),
            Some((threads * per_thread - 1) as u64)
        );
    }

    #[test]
    fn wire_encoding_is_big_endian() {
        let alloc = PacketNoAllocator::new();
        let value = alloc.reserve_exact(0x0102_0304_0506_0708).unwrap();
        assert_eq!(
            value.to_be_bytes(),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }
}
