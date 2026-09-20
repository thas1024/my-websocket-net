//! At-most-once business operation table (DESIGN.md §5.2).
//!
//! §5.2 separates three identities that are easy to conflate:
//!
//! | identity | scope | cannot replace |
//! | --- | --- | --- |
//! | `packet_no` | per session direction, all carriers | `request_id`, TCP offset |
//! | `request_id` | one operation within one Hub epoch | a durable transaction |
//! | `attempt_id` | one auth/binding candidate | the auth nonce |
//!
//! This crate implements the middle one. It provides *at most once execution plus
//! a queryable result* inside a bounded window — explicitly **not** exactly-once:
//!
//! > 去重只能提供上述窗口内至多一次执行及可查询结果，**不是恰好一次**。
//!
//! Two rules drive the design:
//!
//! * A full table refuses new operations rather than evicting a result that is
//!   still inside its idempotency window (§5.2).
//! * Once a result's retention expires, its `request_id` is *retired* into a
//!   bounded tombstone set, so the same id can never be re-executed as if it were
//!   new. When the tombstone set fills, the session must be rebuilt.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use wsnet_limits::{
    OPERATION_MAX_PENDING, OPERATION_OPEN_TIMEOUT_SECS, OPERATION_RESULT_RETENTION_SECS,
    OPERATION_TOMBSTONE_MAX,
};

/// A 128-bit operation identifier (§5.2: "Open/Hello 使用 128-bit request_id").
pub type RequestId = [u8; 16];

/// SHA-256 of an operation's canonical description.
///
/// The hash exists so that reusing a `request_id` for *different* content is
/// detectable: §5.2 requires "同 ID 异内容返回认证后的冲突错误".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationHash([u8; 32]);

impl OperationHash {
    /// Hashes the canonical bytes of an operation.
    pub fn of(canonical: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(canonical);
        OperationHash(hasher.finalize().into())
    }

    /// The raw digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The terminal outcome of an operation, kept opaque to this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The operation succeeded; the bytes are its serialized result.
    Complete(Vec<u8>),
    /// The operation failed; the bytes describe why.
    Failed(Vec<u8>),
}

/// The state of one `request_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationState {
    /// Execution is in flight.
    Pending,
    /// Execution finished; the result is cached for the retention window.
    Settled(Outcome),
}

/// What the caller should do with an incoming operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admit {
    /// This `request_id` is new: execute it, exactly once.
    Execute,
    /// The same operation is already in flight; do not dial again.
    AlreadyPending,
    /// The result is known; return it instead of executing again.
    Cached(Outcome),
}

/// Errors from the operation table.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OperationError {
    /// The same `request_id` arrived with different content.
    #[error("request_id was already used for a different operation")]
    Conflict,
    /// The table is full of records that are still inside their window.
    #[error("operation table is full ({0} records); refusing new operations")]
    CapacityExceeded(usize),
    /// The retired-id tombstone set is full; the session must be re-established.
    #[error("retired request_id set is full; a new session is required")]
    SessionExhausted,
    /// This `request_id` was already retired and must not be re-executed.
    #[error("request_id is retired and must not be re-executed")]
    Retired,
    /// No such operation is known.
    #[error("unknown request_id")]
    Unknown,
    /// The operation is already settled.
    #[error("operation is already settled")]
    AlreadySettled,
}

/// Operation-table configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationConfig {
    /// Maximum concurrent records per session.
    pub max_records: usize,
    /// `Open` completion deadline in milliseconds.
    pub open_timeout_ms: u64,
    /// Retention for settled results in milliseconds.
    pub result_retention_ms: u64,
    /// Maximum retired `request_id` tombstones.
    pub tombstone_max: usize,
}

impl Default for OperationConfig {
    fn default() -> Self {
        OperationConfig {
            max_records: OPERATION_MAX_PENDING,
            open_timeout_ms: OPERATION_OPEN_TIMEOUT_SECS * 1_000,
            result_retention_ms: OPERATION_RESULT_RETENTION_SECS * 1_000,
            tombstone_max: OPERATION_TOMBSTONE_MAX,
        }
    }
}

#[derive(Debug, Clone)]
struct Slot {
    hash: OperationHash,
    state: OperationState,
    /// When the operation was admitted, or when it settled.
    since_ms: u64,
}

/// The bounded, per-session operation table.
#[derive(Debug)]
pub struct OperationTable {
    config: OperationConfig,
    slots: BTreeMap<RequestId, Slot>,
    /// Ids whose retention expired; these must never be re-executed.
    retired: BTreeSet<RequestId>,
    /// Set once `retired` reaches `tombstone_max`.
    exhausted: bool,
}

impl OperationTable {
    /// Creates an empty table.
    pub fn new(config: OperationConfig) -> Self {
        OperationTable {
            config,
            slots: BTreeMap::new(),
            retired: BTreeSet::new(),
            exhausted: false,
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &OperationConfig {
        &self.config
    }

    /// Number of live records.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no records are live.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Number of retired ids.
    pub fn retired_len(&self) -> usize {
        self.retired.len()
    }

    /// Whether the session can still accept new operations.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Admits an operation, executing it at most once per `request_id`.
    pub fn begin(
        &mut self,
        request_id: RequestId,
        hash: OperationHash,
        now_ms: u64,
    ) -> Result<Admit, OperationError> {
        if self.exhausted || self.retired.contains(&request_id) {
            return Err(OperationError::Retired);
        }

        if let Some(slot) = self.slots.get(&request_id) {
            if slot.hash != hash {
                return Err(OperationError::Conflict);
            }
            return Ok(match &slot.state {
                OperationState::Pending => Admit::AlreadyPending,
                OperationState::Settled(outcome) => Admit::Cached(outcome.clone()),
            });
        }

        if self.slots.len() >= self.config.max_records {
            return Err(OperationError::CapacityExceeded(self.config.max_records));
        }

        self.slots.insert(
            request_id,
            Slot {
                hash,
                state: OperationState::Pending,
                since_ms: now_ms,
            },
        );
        Ok(Admit::Execute)
    }

    /// Settles a pending operation with a terminal outcome.
    pub fn settle(
        &mut self,
        request_id: RequestId,
        outcome: Outcome,
        now_ms: u64,
    ) -> Result<(), OperationError> {
        let slot = self
            .slots
            .get_mut(&request_id)
            .ok_or(OperationError::Unknown)?;
        if matches!(slot.state, OperationState::Settled(_)) {
            return Err(OperationError::AlreadySettled);
        }
        slot.state = OperationState::Settled(outcome);
        slot.since_ms = now_ms;
        Ok(())
    }

    /// Looks up the current state of an operation, for `QueryResult`.
    pub fn query(&self, request_id: &RequestId) -> Option<&OperationState> {
        self.slots.get(request_id).map(|slot| &slot.state)
    }

    /// Whether this id has been retired.
    pub fn is_retired(&self, request_id: &RequestId) -> bool {
        self.retired.contains(request_id)
    }

    /// Advances time: fails timed-out pending operations and retires expired
    /// results.
    ///
    /// Returns `(timed_out, retired)` counts. A pending operation that exceeds
    /// the open deadline becomes a `Failed` result rather than disappearing, so
    /// a client that queries it learns the operation did not succeed instead of
    /// having to guess whether it ran.
    pub fn tick(&mut self, now_ms: u64) -> (usize, usize) {
        let mut timed_out = 0usize;
        for slot in self.slots.values_mut() {
            if matches!(slot.state, OperationState::Pending)
                && now_ms.saturating_sub(slot.since_ms) >= self.config.open_timeout_ms
            {
                slot.state = OperationState::Settled(Outcome::Failed(b"timeout".to_vec()));
                slot.since_ms = now_ms;
                timed_out += 1;
            }
        }

        let expired: Vec<RequestId> = self
            .slots
            .iter()
            .filter(|(_, slot)| {
                matches!(slot.state, OperationState::Settled(_))
                    && now_ms.saturating_sub(slot.since_ms) >= self.config.result_retention_ms
            })
            .map(|(id, _)| *id)
            .collect();

        let mut retired = 0usize;
        for id in expired {
            self.slots.remove(&id);
            // Retire rather than forget: the same id must never run again.
            if self.retired.len() >= self.config.tombstone_max {
                self.exhausted = true;
            } else {
                self.retired.insert(id);
                retired += 1;
            }
        }
        (timed_out, retired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> OperationTable {
        OperationTable::new(OperationConfig::default())
    }

    fn id(n: u8) -> RequestId {
        [n; 16]
    }

    /// T05: a repeat of the same operation is never dialled twice.
    #[test]
    fn same_id_same_hash_never_executes_twice() {
        let mut table = table();
        let hash = OperationHash::of(b"open-client-a-web");

        assert_eq!(table.begin(id(1), hash, 0).unwrap(), Admit::Execute);
        assert_eq!(table.begin(id(1), hash, 5).unwrap(), Admit::AlreadyPending);

        table
            .settle(id(1), Outcome::Complete(vec![1, 2, 3]), 10)
            .unwrap();
        assert_eq!(
            table.begin(id(1), hash, 20).unwrap(),
            Admit::Cached(Outcome::Complete(vec![1, 2, 3]))
        );
        assert_eq!(table.len(), 1);
    }

    /// T05: the same id with different content is a conflict, not a retry.
    #[test]
    fn same_id_different_hash_is_a_conflict() {
        let mut table = table();
        table
            .begin(id(1), OperationHash::of(b"service web"), 0)
            .unwrap();
        assert_eq!(
            table
                .begin(id(1), OperationHash::of(b"service db"), 1)
                .unwrap_err(),
            OperationError::Conflict
        );
    }

    /// T05: a lost response can be re-queried rather than re-executed.
    #[test]
    fn a_lost_response_is_answerable_from_cache() {
        let mut table = table();
        let hash = OperationHash::of(b"op");
        table.begin(id(1), hash, 0).unwrap();
        table
            .settle(id(1), Outcome::Failed(b"refused".to_vec()), 1)
            .unwrap();

        assert_eq!(
            table.query(&id(1)),
            Some(&OperationState::Settled(Outcome::Failed(
                b"refused".to_vec()
            )))
        );
        // And a retransmit on another carrier still does not re-execute.
        assert_eq!(
            table.begin(id(1), hash, 2).unwrap(),
            Admit::Cached(Outcome::Failed(b"refused".to_vec()))
        );
    }

    /// T05: a full table refuses new work instead of evicting valid results.
    #[test]
    fn a_full_table_refuses_new_operations() {
        let config = OperationConfig {
            max_records: 3,
            ..OperationConfig::default()
        };
        let mut table = OperationTable::new(config);
        for n in 0..3u8 {
            assert_eq!(
                table.begin(id(n), OperationHash::of(&[n]), 0).unwrap(),
                Admit::Execute
            );
        }
        assert_eq!(
            table.begin(id(9), OperationHash::of(b"x"), 0).unwrap_err(),
            OperationError::CapacityExceeded(3)
        );
        // Every existing record survived.
        assert_eq!(table.len(), 3);
        for n in 0..3u8 {
            assert_eq!(table.query(&id(n)), Some(&OperationState::Pending));
        }
    }

    /// T05: after the window closes, the id must not be re-executed.
    #[test]
    fn an_expired_id_is_retired_and_never_re_executed() {
        let mut table = table();
        let hash = OperationHash::of(b"op");
        table.begin(id(1), hash, 0).unwrap();
        table.settle(id(1), Outcome::Complete(vec![7]), 0).unwrap();

        let window_ms = OPERATION_RESULT_RETENTION_SECS * 1_000;
        let (timed_out, retired) = table.tick(window_ms);
        assert_eq!((timed_out, retired), (0, 1));
        assert!(table.is_retired(&id(1)));
        assert!(table.is_empty());

        // The same id must not be treated as new work.
        assert_eq!(
            table.begin(id(1), hash, window_ms + 1),
            Err(OperationError::Retired)
        );
    }

    /// T05: a pending operation that times out becomes a queryable failure.
    #[test]
    fn a_timed_out_open_becomes_a_failed_result() {
        let mut table = table();
        table.begin(id(1), OperationHash::of(b"op"), 0).unwrap();

        let timeout_ms = OPERATION_OPEN_TIMEOUT_SECS * 1_000;
        assert_eq!(table.tick(timeout_ms), (1, 0));
        assert_eq!(
            table.query(&id(1)),
            Some(&OperationState::Settled(Outcome::Failed(
                b"timeout".to_vec()
            )))
        );
        // It is still cached, so it can be answered rather than re-dialled.
        assert!(matches!(
            table
                .begin(id(1), OperationHash::of(b"op"), timeout_ms + 1)
                .unwrap(),
            Admit::Cached(_)
        ));
    }

    #[test]
    fn a_pending_operation_inside_its_deadline_is_untouched() {
        let mut table = table();
        table.begin(id(1), OperationHash::of(b"op"), 0).unwrap();
        assert_eq!(table.tick(OPERATION_OPEN_TIMEOUT_SECS * 1_000 - 1), (0, 0));
        assert_eq!(table.query(&id(1)), Some(&OperationState::Pending));
    }

    /// T05: when the tombstone set fills, the session stops accepting work.
    #[test]
    fn a_full_tombstone_set_exhausts_the_session() {
        let config = OperationConfig {
            tombstone_max: 2,
            result_retention_ms: 100,
            open_timeout_ms: 10,
            max_records: 100,
        };
        let mut table = OperationTable::new(config);
        for n in 0..4u8 {
            table.begin(id(n), OperationHash::of(&[n]), 0).unwrap();
            table.settle(id(n), Outcome::Complete(vec![n]), 0).unwrap();
        }
        let (_, retired) = table.tick(100);
        assert_eq!(retired, 2);
        assert!(table.is_exhausted());
        assert_eq!(
            table
                .begin(id(9), OperationHash::of(b"x"), 100)
                .unwrap_err(),
            OperationError::Retired
        );
    }

    #[test]
    fn settling_an_unknown_or_settled_operation_is_an_error() {
        let mut table = table();
        assert_eq!(
            table
                .settle(id(1), Outcome::Complete(vec![]), 0)
                .unwrap_err(),
            OperationError::Unknown
        );
        table.begin(id(1), OperationHash::of(b"op"), 0).unwrap();
        table.settle(id(1), Outcome::Complete(vec![]), 0).unwrap();
        assert_eq!(
            table
                .settle(id(1), Outcome::Complete(vec![]), 1)
                .unwrap_err(),
            OperationError::AlreadySettled
        );
    }

    #[test]
    fn operation_hash_is_content_sensitive() {
        assert_ne!(
            OperationHash::of(b"a"),
            OperationHash::of(b"b"),
            "different operations must hash differently"
        );
        assert_eq!(OperationHash::of(b"a"), OperationHash::of(b"a"));
    }

    /// Distinct ids are independent.
    #[test]
    fn distinct_ids_do_not_interfere() {
        let mut table = table();
        let hash = OperationHash::of(b"op");
        assert_eq!(table.begin(id(1), hash, 0).unwrap(), Admit::Execute);
        assert_eq!(table.begin(id(2), hash, 0).unwrap(), Admit::Execute);
        table.settle(id(1), Outcome::Complete(vec![1]), 0).unwrap();
        assert_eq!(table.query(&id(2)), Some(&OperationState::Pending));
        assert_eq!(
            table.query(&id(1)),
            Some(&OperationState::Settled(Outcome::Complete(vec![1])))
        );
    }
}
