//! Per-direction transport replay window (DESIGN.md §4.2).
//!
//! > 传输 replay 窗口：每方向维护高水位与最近 65,536 个 packet_no 位图（约 8 KiB/
//! > 方向）；先验 AEAD，再原子检查/登记，允许窗口内未见乱序。已见或落后窗口的包不
//! > 进入业务状态机；不能定期清空位图后重接受旧包。
//!
//! Two properties matter and are both tested below:
//!
//! * **No reuse of memory for a stale number.** The bitmap slot for a number is
//!   cleared exactly when that number leaves the window, so an old packet can
//!   never be re-accepted just because its slot was recycled.
//! * **Bounded state.** The window is a fixed 8 KiB regardless of how many
//!   packets flow, so a long-lived session cannot grow it.
//!
//! This window rejects *transport* replays only. §4.2 is explicit that transport
//! replay is not business idempotency: a legitimate client that needs a response
//! again re-seals the same `request_id` under a fresh `packet_no`, which this
//! window accepts and `wsnet-operation` then collapses.

use wsnet_limits::{REPLAY_MAX_FORWARD_JUMP, REPLAY_WINDOW};

/// Number of 64-bit words backing a window.
const WORDS: usize = (REPLAY_WINDOW as usize) / 64;

/// Why a `packet_no` was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayError {
    /// This exact `packet_no` was already accepted in this direction.
    #[error("packet_no {0} was already accepted")]
    Duplicate(u64),
    /// The packet is older than the window and can no longer be judged.
    #[error("packet_no {packet_no} is below the replay window (highest {highest})")]
    TooOld {
        /// The refused value.
        packet_no: u64,
        /// The current high-water mark.
        highest: u64,
    },
    /// The packet is too far ahead of the high-water mark.
    #[error("packet_no {packet_no} is {jump} ahead of {highest}, limit is {limit}")]
    TooFarAhead {
        /// The refused value.
        packet_no: u64,
        /// The current high-water mark.
        highest: u64,
        /// The largest permitted jump.
        jump: u64,
        /// The configured limit.
        limit: u64,
    },
}

/// A sliding-window replay filter for one direction.
///
/// Callers must run AEAD verification *before* [`ReplayWindow::check_and_record`],
/// as §4.2 requires ("先验 AEAD，再原子检查/登记"); recording an unauthenticated
/// value would let an attacker burn counter space.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: Vec<u64>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow::new()
    }
}

impl ReplayWindow {
    /// An empty window.
    pub fn new() -> Self {
        ReplayWindow {
            highest: None,
            seen: vec![0u64; WORDS],
        }
    }

    /// The high-water mark, or `None` before the first packet.
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// The fixed in-memory footprint of one window, in bytes.
    pub const fn memory_bytes() -> usize {
        WORDS * core::mem::size_of::<u64>()
    }

    /// Checks and records one authenticated `packet_no`.
    pub fn check_and_record(&mut self, packet_no: u64) -> Result<(), ReplayError> {
        match self.highest {
            None => {
                self.highest = Some(packet_no);
                self.set(packet_no);
                Ok(())
            }
            Some(highest) if packet_no > highest => {
                let jump = packet_no - highest;
                if jump > REPLAY_MAX_FORWARD_JUMP {
                    return Err(ReplayError::TooFarAhead {
                        packet_no,
                        highest,
                        jump,
                        limit: REPLAY_MAX_FORWARD_JUMP,
                    });
                }
                // Every number in (highest, packet_no] owns a slot, and each of
                // those slots previously held a number that has just left the
                // window. Clearing them is what makes slot recycling safe.
                if jump >= REPLAY_WINDOW {
                    // The whole window turned over; no old bit is still valid.
                    self.seen.fill(0);
                } else {
                    for n in (highest + 1)..=packet_no {
                        self.clear(n);
                    }
                }
                self.highest = Some(packet_no);
                self.set(packet_no);
                Ok(())
            }
            Some(highest) => {
                if highest - packet_no >= REPLAY_WINDOW {
                    return Err(ReplayError::TooOld {
                        packet_no,
                        highest,
                    });
                }
                let (word, mask) = Self::locate(packet_no);
                if self.seen[word] & mask != 0 {
                    return Err(ReplayError::Duplicate(packet_no));
                }
                self.seen[word] |= mask;
                Ok(())
            }
        }
    }

    /// Indexes the slot owned by `packet_no` within the current window.
    fn locate(packet_no: u64) -> (usize, u64) {
        let slot = (packet_no % REPLAY_WINDOW) as usize;
        (slot / 64, 1u64 << (slot % 64))
    }

    fn set(&mut self, packet_no: u64) {
        let (word, mask) = Self::locate(packet_no);
        self.seen[word] |= mask;
    }

    fn clear(&mut self, packet_no: u64) {
        let (word, mask) = Self::locate(packet_no);
        self.seen[word] &= !mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift so the shuffle tests need no dev-dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    #[test]
    fn first_packet_is_accepted_and_sets_the_high_water_mark() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.highest(), None);
        assert!(window.check_and_record(0).is_ok());
        assert_eq!(window.highest(), Some(0));
    }

    #[test]
    fn in_order_packets_are_accepted() {
        let mut window = ReplayWindow::new();
        for n in 0..10_000 {
            assert!(window.check_and_record(n).is_ok(), "packet {n} refused");
        }
        assert_eq!(window.highest(), Some(9_999));
    }

    #[test]
    fn immediate_duplicate_is_rejected() {
        let mut window = ReplayWindow::new();
        window.check_and_record(5).unwrap();
        assert_eq!(
            window.check_and_record(5).unwrap_err(),
            ReplayError::Duplicate(5)
        );
    }

    /// §4.2 allows out-of-order delivery inside the window.
    #[test]
    fn out_of_order_inside_the_window_is_accepted_once() {
        let mut window = ReplayWindow::new();
        window.check_and_record(100).unwrap();
        for n in [90u64, 95, 99, 91, 0, 50] {
            assert!(window.check_and_record(n).is_ok(), "packet {n} refused");
        }
        // None of them may be accepted a second time.
        for n in [90u64, 95, 99, 91, 0, 50, 100] {
            assert!(
                matches!(
                    window.check_and_record(n),
                    Err(ReplayError::Duplicate(_))
                ),
                "packet {n} was accepted twice"
            );
        }
    }

    /// A number that has fallen out of the window must be refused, never
    /// re-accepted via a recycled slot.
    #[test]
    fn numbers_below_the_window_are_too_old() {
        let mut window = ReplayWindow::new();
        window.check_and_record(REPLAY_WINDOW * 3).unwrap();

        // Exactly at the boundary: highest - WINDOW is outside.
        let boundary = REPLAY_WINDOW * 3 - REPLAY_WINDOW;
        assert_eq!(
            window.check_and_record(boundary).unwrap_err(),
            ReplayError::TooOld {
                packet_no: boundary,
                highest: REPLAY_WINDOW * 3
            }
        );
        // One inside the boundary is still judgeable.
        assert!(window.check_and_record(boundary + 1).is_ok());
    }

    #[test]
    fn jumps_up_to_the_limit_are_accepted() {
        let mut window = ReplayWindow::new();
        window.check_and_record(0).unwrap();
        assert!(window.check_and_record(REPLAY_MAX_FORWARD_JUMP).is_ok());

        // One past the limit is refused.
        let mut window = ReplayWindow::new();
        window.check_and_record(0).unwrap();
        assert!(matches!(
            window.check_and_record(REPLAY_MAX_FORWARD_JUMP + 1),
            Err(ReplayError::TooFarAhead { .. })
        ));
        // The refused jump must not have moved the high-water mark.
        assert_eq!(window.highest(), Some(0));
    }

    /// The decisive property: after the window slides, a stale number must never
    /// be re-accepted through a recycled bitmap slot.
    #[test]
    fn sliding_the_window_never_revives_a_stale_number() {
        let mut window = ReplayWindow::new();
        for n in 0..(REPLAY_WINDOW * 2) {
            window.check_and_record(n).unwrap();
        }

        // `REPLAY_WINDOW` and `2 * REPLAY_WINDOW` share bitmap slot 0. The live
        // record for slot 0 is still `REPLAY_WINDOW`, so this is exactly the
        // aliasing case the clearing logic must get right.
        let stale = REPLAY_WINDOW;
        assert_eq!(stale % REPLAY_WINDOW, (REPLAY_WINDOW * 2) % REPLAY_WINDOW);
        assert!(
            window.check_and_record(stale).is_err(),
            "stale number aliasing a live slot was re-accepted"
        );

        // Advance until the stale number has left the window entirely; it must
        // then be reported as unjudgeable rather than silently accepted.
        for n in (REPLAY_WINDOW * 2)..(REPLAY_WINDOW * 3) {
            window.check_and_record(n).unwrap();
        }
        assert_eq!(
            window.check_and_record(stale),
            Err(ReplayError::TooOld {
                packet_no: stale,
                highest: REPLAY_WINDOW * 3 - 1,
            })
        );
    }

    /// TooFarAhead must not corrupt the window: a refused packet leaves the
    /// high-water mark and every recorded bit untouched.
    #[test]
    fn a_refused_packet_leaves_no_trace() {
        let mut window = ReplayWindow::new();
        window.check_and_record(10).unwrap();
        let before = window.clone();
        assert!(window.check_and_record(10 + REPLAY_MAX_FORWARD_JUMP + 1).is_err());
        assert_eq!(window.highest(), before.highest());
        assert_eq!(window.seen, before.seen);
    }

    /// T02/T08: a long, shuffled stream must deliver every number exactly once.
    #[test]
    fn randomised_stream_delivers_each_number_exactly_once() {
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let mut window = ReplayWindow::new();
        let total = 20_000u64;

        // Deliver in shuffled order in chunks small enough to stay inside the
        // window, then verify nothing can be delivered twice.
        let chunk = 4_000u64;
        let mut next = 0u64;
        while next < total {
            let end = (next + chunk).min(total);
            let mut batch: Vec<u64> = (next..end).collect();
            // Fisher-Yates with the deterministic RNG.
            for i in (1..batch.len()).rev() {
                let j = rng.below(i as u64 + 1) as usize;
                batch.swap(i, j);
            }
            for value in batch {
                assert!(
                    window.check_and_record(value).is_ok(),
                    "value {value} refused during shuffled delivery"
                );
            }
            next = end;
        }

        // Everything is now either a duplicate or too old, never accepted again.
        for value in 0..total {
            match window.check_and_record(value) {
                Err(ReplayError::Duplicate(_)) | Err(ReplayError::TooOld { .. }) => {}
                other => panic!("value {value} re-accepted: {other:?}"),
            }
        }
    }

    /// State stays at the documented 8 KiB per direction, forever.
    #[test]
    fn memory_footprint_is_fixed() {
        assert_eq!(ReplayWindow::memory_bytes(), 8 * 1024);
        let mut window = ReplayWindow::new();
        for n in 0..100_000u64 {
            let _ = window.check_and_record(n);
        }
        assert_eq!(window.seen.len(), WORDS);
    }

    /// A jump that exactly turns the window over must discard every earlier bit.
    #[test]
    fn full_window_turnover_clears_all_bits() {
        let mut window = ReplayWindow::new();
        window.check_and_record(0).unwrap();
        window.check_and_record(REPLAY_WINDOW).unwrap();

        // Exactly one number is recorded after the turnover, and it is the new
        // high-water mark; slot 0 must no longer claim that 0 was seen.
        assert_eq!(
            window.check_and_record(REPLAY_WINDOW),
            Err(ReplayError::Duplicate(REPLAY_WINDOW))
        );
        // A different slot inside the window is still free.
        assert!(window.check_and_record(REPLAY_WINDOW - 1).is_ok());
    }

    #[test]
    fn huge_packet_numbers_do_not_wrap() {
        let mut window = ReplayWindow::new();
        let start = u64::MAX - 10;
        window.check_and_record(start).unwrap();
        for n in (start + 1)..=u64::MAX {
            assert!(window.check_and_record(n).is_ok(), "packet {n} refused");
        }
        assert_eq!(window.highest(), Some(u64::MAX));
        assert_eq!(
            window.check_and_record(u64::MAX),
            Err(ReplayError::Duplicate(u64::MAX))
        );
    }
}
