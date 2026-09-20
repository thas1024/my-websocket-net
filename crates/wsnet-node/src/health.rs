//! Hub health accounting (DESIGN.md section 5.5).
//!
//! > 连续 3 次超时才切换，新成功稳定 30 秒后才考虑回切，避免抖动。
//!
//! The tracker is a pure state machine over injected timestamps, so the
//! thresholds can be tested without waiting thirty seconds, and the node only
//! has to feed it the outcome of each bounded health round trip.

use std::time::{Duration, Instant};

use wsnet_limits::{HEALTH_FAILURES_BEFORE_FAILOVER, HEALTH_STABLE_BEFORE_FAILBACK_SECS};

/// The stability window a recovered Hub must hold before it is preferred again.
pub fn stable_before_failback() -> Duration {
    Duration::from_secs(HEALTH_STABLE_BEFORE_FAILBACK_SECS)
}

/// Consecutive-failure and stability accounting for one Hub.
#[derive(Debug, Clone)]
pub struct HealthTracker {
    failures: u32,
    healthy: bool,
    /// When the current uninterrupted run of successes started, while unhealthy.
    succeeding_since: Option<Instant>,
}

impl Default for HealthTracker {
    fn default() -> Self {
        HealthTracker {
            failures: 0,
            // A Hub that has never been probed is assumed usable: section 5.5
            // fails over on evidence, never on the absence of it.
            healthy: true,
            succeeding_since: None,
        }
    }
}

impl HealthTracker {
    /// A tracker for a Hub that has not been probed yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the Hub may currently be selected.
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    /// The current consecutive-failure count.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Records one successful bounded round trip.
    pub fn record_success(&mut self, now: Instant) {
        self.failures = 0;
        if self.healthy {
            self.succeeding_since = None;
            return;
        }
        match self.succeeding_since {
            None => self.succeeding_since = Some(now),
            Some(since) => {
                if now.saturating_duration_since(since) >= stable_before_failback() {
                    self.healthy = true;
                    self.succeeding_since = None;
                }
            }
        }
    }

    /// Records one failed or timed-out round trip.
    pub fn record_failure(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        let _ = now;
        if self.failures >= HEALTH_FAILURES_BEFORE_FAILOVER {
            self.healthy = false;
            // The stability run restarts: success before the threshold was
            // reached is not evidence that the Hub has recovered.
            self.succeeding_since = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Section 5.5: two failures must not move the Hub, the third must.
    #[test]
    fn failover_needs_three_consecutive_failures() {
        let start = Instant::now();
        let mut tracker = HealthTracker::new();
        assert!(tracker.is_healthy());

        for n in 1..HEALTH_FAILURES_BEFORE_FAILOVER {
            tracker.record_failure(start + Duration::from_secs(u64::from(n)));
            assert!(tracker.is_healthy(), "failure {n} moved the Hub too early");
        }
        tracker.record_failure(start + Duration::from_secs(3));
        assert!(!tracker.is_healthy());
        assert_eq!(tracker.failures(), HEALTH_FAILURES_BEFORE_FAILOVER);
    }

    /// A single success in between resets the run, so the Hub is not failed over
    /// on a flapping carrier.
    #[test]
    fn a_success_resets_the_failure_run() {
        let start = Instant::now();
        let mut tracker = HealthTracker::new();
        tracker.record_failure(start);
        tracker.record_failure(start + Duration::from_secs(1));
        tracker.record_success(start + Duration::from_secs(2));
        assert_eq!(tracker.failures(), 0);
        tracker.record_failure(start + Duration::from_secs(3));
        tracker.record_failure(start + Duration::from_secs(4));
        assert!(tracker.is_healthy());
    }

    /// Section 5.5: a recovered Hub is only preferred again after 30 stable
    /// seconds, so an intermittent Hub cannot cause fail-back thrash.
    #[test]
    fn failback_waits_for_thirty_stable_seconds() {
        let start = Instant::now();
        let mut tracker = HealthTracker::new();
        for n in 0..HEALTH_FAILURES_BEFORE_FAILOVER {
            tracker.record_failure(start + Duration::from_secs(u64::from(n)));
        }
        assert!(!tracker.is_healthy());

        let first_success = start + Duration::from_secs(10);
        tracker.record_success(first_success);
        tracker.record_success(first_success + Duration::from_secs(29));
        assert!(!tracker.is_healthy(), "failback happened before 30 seconds");

        tracker.record_success(first_success + Duration::from_secs(30));
        assert!(tracker.is_healthy());
    }

    /// A failure during the stability run restarts the clock.
    #[test]
    fn a_failure_restarts_the_stability_run() {
        let start = Instant::now();
        let mut tracker = HealthTracker::new();
        for n in 0..HEALTH_FAILURES_BEFORE_FAILOVER {
            tracker.record_failure(start + Duration::from_secs(u64::from(n)));
        }
        let base = start + Duration::from_secs(10);
        tracker.record_success(base);
        tracker.record_success(base + Duration::from_secs(20));
        tracker.record_failure(base + Duration::from_secs(25));
        tracker.record_success(base + Duration::from_secs(26));
        // Only one second of stable success since the restart.
        tracker.record_success(base + Duration::from_secs(27));
        assert!(!tracker.is_healthy());
    }
}
