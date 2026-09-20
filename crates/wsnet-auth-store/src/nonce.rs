//! Atomic authentication-nonce registry (DESIGN.md §5.1).
//!
//! The design's binding requirements, each mapped to code below:
//!
//! | §5.1 requirement | implementation |
//! | --- | --- |
//! | UTC seconds, default window W=120s, configurable 60–300s | [`NonceStoreConfig::window_secs`] |
//! | Check rate/length/fields/MAC first, *then* atomically dedupe and record | [`NonceStore::register`] is the single atomic step; MAC verification is the caller's earlier step |
//! | Retain past `ts + W + 1` | `retain_until_ms` |
//! | Monotonic retention; pause new auth on wall-clock rollback | [`NonceStore::register`] returns [`AuthStoreError::ClockRollback`] |
//! | Per-node cap and a global memory cap | [`NonceStoreConfig::per_node_max`], [`NonceStoreConfig::global_max`] |
//! | **A full store must not evict still-valid records** | capacity exhaustion returns [`AuthStoreError::CapacityExceeded`] |
//! | Forgetting the store invalidates the replay claim | [`NonceStore::mark_storage_lost`] |
//!
//! Only an exact set is used. §5.1 permits a Bloom filter as an optimisation but
//! is explicit that it "不能代替精确集合或授权判定", so v1 does not use one.

use std::collections::HashMap;

use wsnet_limits::{
    AUTH_NONCE_ENTRY_COST, AUTH_NONCE_LEN, AUTH_NONCE_MEMORY_BUDGET, AUTH_NONCE_PER_NODE_MAX,
    AUTH_WINDOW_DEFAULT_SECS, AUTH_WINDOW_MAX_SECS, AUTH_WINDOW_MIN_SECS,
};

/// Extra safety margin, in seconds, added to `2W` before authentication resumes
/// after the backing store is known to be lost or corrupt (§5.1).
pub const STORAGE_RECOVERY_MARGIN_SECS: u64 = 10;

/// A clock reading, supplied by the caller.
///
/// Both a wall clock and a monotonic clock are needed: the design uses wall time
/// for the acceptance window but monotonic time for retention, so that a wall
/// clock adjustment cannot resurrect an expired nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    /// UTC Unix seconds.
    pub wall_secs: i64,
    /// A monotonic millisecond counter.
    pub monotonic_ms: u64,
}

impl Now {
    /// Builds a clock reading.
    pub const fn new(wall_secs: i64, monotonic_ms: u64) -> Self {
        Now {
            wall_secs,
            monotonic_ms,
        }
    }
}

/// The tuple that identifies one authentication attempt.
///
/// §5.1 dedupes on `(hub_id, key_id, node_id, nonce)`. Note that the carrier is
/// *not* part of the key: "同 Auth 在 POST 和 WS 重放仍是重放".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonceKey {
    /// Hub that received the authentication.
    pub hub_id: String,
    /// Key generation the node authenticated with.
    pub key_id: String,
    /// The node's stable identity.
    pub node_id: String,
    /// The 32-byte CSPRNG nonce.
    pub nonce: [u8; AUTH_NONCE_LEN],
}

impl NonceKey {
    /// Builds a key.
    pub fn new(
        hub_id: impl Into<String>,
        key_id: impl Into<String>,
        node_id: impl Into<String>,
        nonce: [u8; AUTH_NONCE_LEN],
    ) -> Self {
        NonceKey {
            hub_id: hub_id.into(),
            key_id: key_id.into(),
            node_id: node_id.into(),
            nonce,
        }
    }
}

/// Which cap was hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityScope {
    /// The per-node record cap.
    PerNode,
    /// The Hub-wide memory budget.
    Global,
}

/// Errors from the nonce store.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthStoreError {
    /// The configuration is outside the documented range.
    #[error("auth window {0}s is outside the supported {min}..={max}s range", min = AUTH_WINDOW_MIN_SECS, max = AUTH_WINDOW_MAX_SECS)]
    WindowOutOfRange(u64),
    /// The timestamp is outside the acceptance window.
    #[error("timestamp {ts} is outside the +/-{window}s window around {now}")]
    TimestampOutOfWindow {
        /// The presented timestamp.
        ts: i64,
        /// The current wall clock.
        now: i64,
        /// The configured window.
        window: u64,
    },
    /// This nonce was already registered.
    #[error("authentication nonce was already used")]
    Duplicate,
    /// The store is full of still-valid records and refuses new authentication.
    #[error("nonce store is full ({0:?} cap); refusing new authentication")]
    CapacityExceeded(CapacityScope),
    /// The wall clock moved backwards; new authentication is paused.
    #[error("wall clock moved backwards from {last} to {now}; pausing new authentication")]
    ClockRollback {
        /// Last observed wall time.
        last: i64,
        /// Newly observed wall time.
        now: i64,
    },
    /// The backing store was lost; the anti-replay claim does not hold yet.
    #[error("nonce storage unavailable until monotonic {resume_at_ms}ms")]
    StorageUnavailable {
        /// Monotonic time before which authentication stays closed.
        resume_at_ms: u64,
    },
}

/// Nonce-store configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceStoreConfig {
    /// Acceptance window `W`, in seconds.
    pub window_secs: u64,
    /// Maximum retained records for one node.
    pub per_node_max: usize,
    /// Maximum retained records across the Hub.
    pub global_max: usize,
    /// Backwards wall-clock movement tolerated before authentication pauses.
    pub rollback_tolerance_secs: i64,
}

impl Default for NonceStoreConfig {
    fn default() -> Self {
        NonceStoreConfig {
            window_secs: AUTH_WINDOW_DEFAULT_SECS,
            per_node_max: AUTH_NONCE_PER_NODE_MAX,
            global_max: AUTH_NONCE_MEMORY_BUDGET / AUTH_NONCE_ENTRY_COST,
            rollback_tolerance_secs: 1,
        }
    }
}

impl NonceStoreConfig {
    /// Validates the window against the documented range.
    pub fn validate(&self) -> Result<(), AuthStoreError> {
        if self.window_secs < AUTH_WINDOW_MIN_SECS || self.window_secs > AUTH_WINDOW_MAX_SECS {
            return Err(AuthStoreError::WindowOutOfRange(self.window_secs));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    /// Monotonic deadline after which this record may be dropped.
    retain_until_ms: u64,
    /// Last wall-clock moment at which this nonce would still be acceptable.
    last_acceptable_wall: i64,
}

/// The atomic nonce registry.
#[derive(Debug)]
pub struct NonceStore {
    config: NonceStoreConfig,
    entries: HashMap<NonceKey, Entry>,
    per_node: HashMap<(String, String), usize>,
    /// Highest wall time seen, for rollback detection.
    last_wall_secs: Option<i64>,
    /// Monotonic time before which authentication is refused.
    paused_until_ms: Option<u64>,
}

impl NonceStore {
    /// Creates a store, validating the configuration.
    pub fn new(config: NonceStoreConfig) -> Result<Self, AuthStoreError> {
        config.validate()?;
        Ok(NonceStore {
            config,
            entries: HashMap::new(),
            per_node: HashMap::new(),
            last_wall_secs: None,
            paused_until_ms: None,
        })
    }

    /// The active configuration.
    pub fn config(&self) -> &NonceStoreConfig {
        &self.config
    }

    /// Number of retained records.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no records are retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records retained for one node.
    pub fn node_len(&self, hub_id: &str, node_id: &str) -> usize {
        self.per_node
            .get(&(hub_id.to_string(), node_id.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Whether this exact key is retained.
    pub fn contains(&self, key: &NonceKey) -> bool {
        self.entries.contains_key(key)
    }

    /// Whether the timestamp is inside the acceptance window.
    ///
    /// Kept public so a caller can reject on timestamp before spending work on
    /// MAC verification, without duplicating the window arithmetic.
    pub fn timestamp_acceptable(&self, ts: i64, now_wall_secs: i64) -> bool {
        (ts - now_wall_secs).unsigned_abs() <= self.config.window_secs
    }

    /// Atomically checks and registers one authentication nonce.
    ///
    /// The caller must already have verified field bounds and the `Auth` MAC
    /// (§5.1: "先限流/限长、校验字段和 HMAC，再在 ... 上原子查重并登记").
    ///
    /// A concurrent duplicate loses here: exactly one caller observes `Ok`.
    pub fn register(&mut self, key: NonceKey, ts: i64, now: Now) -> Result<(), AuthStoreError> {
        if !self.timestamp_acceptable(ts, now.wall_secs) {
            return Err(AuthStoreError::TimestampOutOfWindow {
                ts,
                now: now.wall_secs,
                window: self.config.window_secs,
            });
        }

        // A backwards wall clock makes every retention deadline suspect.
        if let Some(last) = self.last_wall_secs {
            if now.wall_secs < last - self.config.rollback_tolerance_secs {
                self.last_wall_secs = Some(last.max(now.wall_secs));
                return Err(AuthStoreError::ClockRollback {
                    last,
                    now: now.wall_secs,
                });
            }
        }
        self.last_wall_secs = Some(match self.last_wall_secs {
            Some(last) => last.max(now.wall_secs),
            None => now.wall_secs,
        });

        if let Some(resume_at_ms) = self.paused_until_ms {
            if now.monotonic_ms < resume_at_ms {
                return Err(AuthStoreError::StorageUnavailable { resume_at_ms });
            }
            self.paused_until_ms = None;
        }

        // Only ever drop records whose entire acceptable interval has passed.
        self.purge_expired(now);

        if self.entries.contains_key(&key) {
            return Err(AuthStoreError::Duplicate);
        }

        if self.entries.len() >= self.config.global_max {
            return Err(AuthStoreError::CapacityExceeded(CapacityScope::Global));
        }
        let node_key = (key.hub_id.clone(), key.node_id.clone());
        let node_count = self.per_node.get(&node_key).copied().unwrap_or(0);
        if node_count >= self.config.per_node_max {
            return Err(AuthStoreError::CapacityExceeded(CapacityScope::PerNode));
        }

        // Retain until one second past the last wall moment at which this
        // timestamp would still be acceptable, measured monotonically.
        let last_acceptable_wall = ts.saturating_add(self.config.window_secs as i64);
        let delta_secs = (last_acceptable_wall + 1 - now.wall_secs).max(0) as u64;
        let retain_until_ms = now
            .monotonic_ms
            .saturating_add(delta_secs.saturating_mul(1_000));

        self.entries.insert(
            key,
            Entry {
                retain_until_ms,
                last_acceptable_wall,
            },
        );
        *self.per_node.entry(node_key).or_insert(0) += 1;
        Ok(())
    }

    /// Drops records whose acceptable interval has fully passed.
    ///
    /// Returns the number removed. This never removes a still-valid record.
    pub fn purge_expired(&mut self, now: Now) -> usize {
        let before = self.entries.len();
        let per_node = &mut self.per_node;
        self.entries.retain(|key, entry| {
            if entry.retain_until_ms <= now.monotonic_ms {
                let node_key = (key.hub_id.clone(), key.node_id.clone());
                // Read-then-write keeps this free of overlapping borrows.
                let remaining = per_node
                    .get(&node_key)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(1);
                if remaining == 0 {
                    per_node.remove(&node_key);
                } else {
                    per_node.insert(node_key, remaining);
                }
                false
            } else {
                true
            }
        });
        before - self.entries.len()
    }

    /// Declares the backing store lost or corrupt (§5.1).
    ///
    /// Authentication stays closed for at least `2W + margin`, because no
    /// retained record can be trusted to still be present.
    pub fn mark_storage_lost(&mut self, now: Now) {
        self.entries.clear();
        self.per_node.clear();
        let hold_secs = self.config.window_secs.saturating_mul(2) + STORAGE_RECOVERY_MARGIN_SECS;
        self.paused_until_ms = Some(now.monotonic_ms.saturating_add(hold_secs * 1_000));
    }

    /// Snapshot of the unexpired records, expressed in wall time so that it
    /// survives a restart (the monotonic clock does not).
    pub fn snapshot(&self) -> Vec<(NonceKey, i64)> {
        self.entries
            .iter()
            .map(|(key, entry)| (key.clone(), entry.last_acceptable_wall))
            .collect()
    }

    /// Rebuilds a store from a snapshot, dropping records whose acceptable
    /// interval has already passed (§5.1: "重启先加载未过期记录").
    pub fn restore(
        config: NonceStoreConfig,
        snapshot: Vec<(NonceKey, i64)>,
        now: Now,
    ) -> Result<Self, AuthStoreError> {
        let mut store = NonceStore::new(config)?;
        for (key, last_acceptable_wall) in snapshot {
            let delta_secs = (last_acceptable_wall + 1 - now.wall_secs).max(0) as u64;
            if delta_secs == 0 {
                continue;
            }
            let node_key = (key.hub_id.clone(), key.node_id.clone());
            store.entries.insert(
                key,
                Entry {
                    retain_until_ms: now.monotonic_ms.saturating_add(delta_secs * 1_000),
                    last_acceptable_wall,
                },
            );
            *store.per_node.entry(node_key).or_insert(0) += 1;
        }
        store.last_wall_secs = Some(now.wall_secs);
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> NonceStore {
        NonceStore::new(NonceStoreConfig::default()).unwrap()
    }

    fn key(nonce_byte: u8) -> NonceKey {
        NonceKey::new("hub-a", "k1", "client-a", [nonce_byte; AUTH_NONCE_LEN])
    }

    fn at(secs: i64) -> Now {
        Now::new(secs, (secs as u64) * 1_000)
    }

    #[test]
    fn first_registration_succeeds() {
        let mut store = store();
        assert!(store.register(key(1), 1_000, at(1_000)).is_ok());
        assert_eq!(store.len(), 1);
        assert!(store.contains(&key(1)));
    }

    /// T03: a replayed `Auth` must lose, whatever carrier it arrives on.
    #[test]
    fn replayed_nonce_is_rejected() {
        let mut store = store();
        store.register(key(1), 1_000, at(1_000)).unwrap();
        assert_eq!(
            store.register(key(1), 1_000, at(1_000)).unwrap_err(),
            AuthStoreError::Duplicate
        );
        // Later wall time, same nonce, still inside the window: still a replay.
        assert_eq!(
            store.register(key(1), 1_000, at(1_030)).unwrap_err(),
            AuthStoreError::Duplicate
        );
        // Once the original timestamp ages out of the window it is refused
        // earlier, by the timestamp check rather than by the dedupe set.
        assert!(matches!(
            store.register(key(1), 1_000, at(1_121)).unwrap_err(),
            AuthStoreError::TimestampOutOfWindow { .. }
        ));
    }

    /// T03: a replay stays rejected for the whole acceptable interval of the
    /// original timestamp.
    #[test]
    fn replay_is_rejected_for_the_entire_acceptable_interval() {
        let mut store = store();
        let ts = 1_000;
        store.register(key(1), ts, at(ts)).unwrap();
        // Walk forward to the last moment the original ts is still acceptable.
        for offset in [1i64, 60, 119, 120] {
            let now = at(ts + offset);
            assert!(
                store.timestamp_acceptable(ts, now.wall_secs),
                "ts should still be acceptable at +{offset}"
            );
            assert_eq!(
                store.register(key(1), ts, now).unwrap_err(),
                AuthStoreError::Duplicate,
                "replay slipped through at +{offset}"
            );
        }
    }

    /// T03: a future timestamp's retention must cover its full acceptable
    /// interval, so it cannot be replayed once wall time catches up.
    #[test]
    fn future_timestamp_retention_covers_its_whole_window() {
        let mut store = store();
        let now = at(1_000);
        let future = 1_000 + 120; // the maximum accepted skew
        store.register(key(7), future, now).unwrap();

        // Wall time reaches the future timestamp; the record must still be there.
        assert!(store.contains(&key(7)));
        assert_eq!(
            store.register(key(7), future, at(future)).unwrap_err(),
            AuthStoreError::Duplicate
        );

        // And at the last acceptable moment for that timestamp.
        let last = future + 120;
        assert_eq!(
            store.register(key(7), future, at(last)).unwrap_err(),
            AuthStoreError::Duplicate
        );
        assert!(store.contains(&key(7)));
    }

    #[test]
    fn timestamps_outside_the_window_are_rejected() {
        let mut store = store();
        assert!(matches!(
            store.register(key(1), 1_000 - 121, at(1_000)).unwrap_err(),
            AuthStoreError::TimestampOutOfWindow { .. }
        ));
        assert!(matches!(
            store.register(key(1), 1_000 + 121, at(1_000)).unwrap_err(),
            AuthStoreError::TimestampOutOfWindow { .. }
        ));
        // Exactly on the boundary is inside.
        assert!(store.register(key(1), 1_000 - 120, at(1_000)).is_ok());
        assert!(store.register(key(2), 1_000 + 120, at(1_000)).is_ok());
    }

    #[test]
    fn different_keys_are_independent() {
        let mut store = store();
        assert!(store.register(key(1), 1_000, at(1_000)).is_ok());
        assert!(store.register(key(2), 1_000, at(1_000)).is_ok());
        // Same nonce on a different node is a different authentication.
        let other_node = NonceKey::new("hub-a", "k1", "client-b", [1u8; AUTH_NONCE_LEN]);
        assert!(store.register(other_node, 1_000, at(1_000)).is_ok());
        // Same node on a different Hub is a different authentication (§5.5).
        let other_hub = NonceKey::new("hub-b", "k1", "client-a", [1u8; AUTH_NONCE_LEN]);
        assert!(store.register(other_hub, 1_000, at(1_000)).is_ok());
    }

    /// T03: a full store must refuse new authentication rather than evict a
    /// record that is still inside its window.
    #[test]
    fn a_full_store_never_evicts_valid_records() {
        let config = NonceStoreConfig {
            per_node_max: 4,
            ..NonceStoreConfig::default()
        };
        let mut store = NonceStore::new(config).unwrap();

        for i in 0..4u8 {
            store.register(key(i), 1_000, at(1_000)).unwrap();
        }
        assert_eq!(store.len(), 4);
        assert_eq!(
            store.register(key(9), 1_000, at(1_000)).unwrap_err(),
            AuthStoreError::CapacityExceeded(CapacityScope::PerNode)
        );
        // Every original record survived, and is still a replay.
        assert_eq!(store.len(), 4);
        for i in 0..4u8 {
            assert_eq!(
                store.register(key(i), 1_000, at(1_000)).unwrap_err(),
                AuthStoreError::Duplicate
            );
        }
    }

    /// The global cap behaves the same way.
    #[test]
    fn global_capacity_is_enforced() {
        let config = NonceStoreConfig {
            per_node_max: 100,
            global_max: 3,
            ..NonceStoreConfig::default()
        };
        let mut store = NonceStore::new(config).unwrap();
        for i in 0..3u8 {
            store.register(key(i), 1_000, at(1_000)).unwrap();
        }
        assert_eq!(
            store.register(key(9), 1_000, at(1_000)).unwrap_err(),
            AuthStoreError::CapacityExceeded(CapacityScope::Global)
        );
        assert_eq!(store.len(), 3);
    }

    /// Once records genuinely expire, capacity is reclaimed.
    #[test]
    fn expired_records_are_reclaimed() {
        let config = NonceStoreConfig {
            per_node_max: 2,
            ..NonceStoreConfig::default()
        };
        let mut store = NonceStore::new(config).unwrap();
        store.register(key(1), 1_000, at(1_000)).unwrap();
        store.register(key(2), 1_000, at(1_000)).unwrap();
        assert!(store.register(key(3), 1_000, at(1_000)).is_err());

        // Jump past ts + W + 1 on the monotonic clock.
        let later = Now::new(1_000 + 200, 1_000_000 + 200_000);
        assert_eq!(store.purge_expired(later), 2);
        assert_eq!(store.len(), 0);
        assert!(store.register(key(3), 1_000 + 200, later).is_ok());
        assert_eq!(store.node_len("hub-a", "client-a"), 1);
    }

    /// A record inside its retention window must survive a purge.
    #[test]
    fn purge_keeps_records_that_are_still_valid() {
        let mut store = store();
        store.register(key(1), 1_000, at(1_000)).unwrap();
        // Monotonic time advances a little; wall time has not reached ts + W.
        assert_eq!(store.purge_expired(Now::new(1_100, 1_000_000 + 100_000)), 0);
        assert!(store.contains(&key(1)));
    }

    /// T03: a backwards wall clock pauses new authentication.
    #[test]
    fn clock_rollback_pauses_authentication() {
        let mut store = store();
        store.register(key(1), 2_000, at(2_000)).unwrap();
        assert_eq!(
            store.register(key(2), 1_000, at(1_000)).unwrap_err(),
            AuthStoreError::ClockRollback {
                last: 2_000,
                now: 1_000
            }
        );
    }

    /// T04: losing the store must close authentication for at least 2W + margin.
    #[test]
    fn storage_loss_closes_authentication_for_two_windows() {
        let mut store = store();
        store.register(key(1), 1_000, at(1_000)).unwrap();
        store.mark_storage_lost(Now::new(1_000, 1_000_000));
        assert_eq!(store.len(), 0);

        // Just before the hold expires, everything is refused.
        let almost = Now::new(1_000, 1_000_000 + (2 * 120 + 9) * 1_000);
        assert!(matches!(
            store.register(key(2), 1_000, almost).unwrap_err(),
            AuthStoreError::StorageUnavailable { .. }
        ));

        // After it, authentication resumes.
        let after = Now::new(1_100, 1_000_000 + (2 * 120 + 10) * 1_000);
        assert!(store.register(key(2), 1_100, after).is_ok());
    }

    /// T04: a restart reloads unexpired records, so a replay still fails.
    #[test]
    fn snapshot_and_restore_preserve_replay_rejection() {
        let mut store = store();
        store.register(key(1), 1_000, at(1_000)).unwrap();
        let snapshot = store.snapshot();
        assert_eq!(snapshot.len(), 1);

        // Restart 100s later: the record is still inside its window.
        let restarted_at = Now::new(1_100, 5_000);
        let mut restored =
            NonceStore::restore(NonceStoreConfig::default(), snapshot.clone(), restarted_at)
                .unwrap();
        assert_eq!(
            restored.register(key(1), 1_000, restarted_at).unwrap_err(),
            AuthStoreError::Duplicate
        );

        // Restart after the interval has passed: the record is dropped, and the
        // stale timestamp is refused by the window check anyway.
        let much_later = Now::new(1_000 + 121, 9_000);
        let restored2 =
            NonceStore::restore(NonceStoreConfig::default(), snapshot, much_later).unwrap();
        assert!(restored2.is_empty());
    }

    #[test]
    fn configuration_window_is_validated() {
        for bad in [0u64, 59, 301, 1_000] {
            let config = NonceStoreConfig {
                window_secs: bad,
                ..NonceStoreConfig::default()
            };
            assert_eq!(
                NonceStore::new(config).unwrap_err(),
                AuthStoreError::WindowOutOfRange(bad)
            );
        }
        for good in [60u64, 120, 300] {
            let config = NonceStoreConfig {
                window_secs: good,
                ..NonceStoreConfig::default()
            };
            assert!(NonceStore::new(config).is_ok());
        }
    }

    #[test]
    fn per_node_counting_is_maintained() {
        let mut store = store();
        store.register(key(1), 1_000, at(1_000)).unwrap();
        store.register(key(2), 1_000, at(1_000)).unwrap();
        assert_eq!(store.node_len("hub-a", "client-a"), 2);
        assert_eq!(store.node_len("hub-a", "client-b"), 0);

        let later = Now::new(1_000 + 130, 1_000_000 + 130_000);
        store.purge_expired(later);
        assert_eq!(store.node_len("hub-a", "client-a"), 0);
    }

    /// Exactly one of many concurrent duplicates may win.
    #[test]
    fn concurrent_duplicate_registration_has_exactly_one_winner() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let store = Arc::new(Mutex::new(store()));
        let winners = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            let winners = Arc::clone(&winners);
            handles.push(std::thread::spawn(move || {
                let mut guard = store.lock().unwrap();
                if guard.register(key(1), 1_000, at(1_000)).is_ok() {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(winners.load(Ordering::SeqCst), 1);
        assert_eq!(store.lock().unwrap().len(), 1);
    }
}
