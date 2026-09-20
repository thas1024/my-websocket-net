//! Connection and authentication budgets (DESIGN.md section 9.2).
//!
//! Section 9.2 fixes two per-source-IP budgets that must be enforced by the
//! application as well as by nginx:
//!
//! > 每 IP 20 个未认证连接、5 次认证/秒（burst10）、握手超时5秒
//!
//! The source address is the *socket* peer address. Section 9.2 is explicit that
//! `X-Real-IP`/`X-Forwarded-For` must not be trusted ("不信任外部伪造 X-Real-IP/
//! X-Forwarded-For"), so no header is ever consulted here.
//!
//! Both budgets answer a refusal with the deployment's ordinary failure
//! appearance: section 9.2 asks for "普通过载响应/关闭", not for a distinctive
//! error that would be a more useful signal to an attacker than to an operator.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use wsnet_limits::{AUTH_BURST, AUTH_RATE_PER_SEC, MAX_UNAUTH_CONNECTIONS_PER_IP};

/// Why a request was refused before authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardError {
    /// The source already holds the maximum number of unauthenticated
    /// connections.
    TooManyConnections,
    /// The source exceeded its authentication rate.
    RateLimited,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_ms: u64,
}

/// Per-source budgets shared by every carrier.
#[derive(Debug, Default)]
pub(crate) struct DosGuards {
    connections: Mutex<HashMap<IpAddr, usize>>,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl DosGuards {
    /// An empty budget set.
    pub(crate) fn new() -> Self {
        DosGuards::default()
    }

    /// Charges one unauthenticated connection to `ip`.
    ///
    /// The returned guard releases the charge on drop, so a connection that is
    /// closed abruptly cannot leak budget. Once a connection authenticates, the
    /// caller drops the guard: section 9.2's budget is about *unauthenticated*
    /// connections, not about sessions.
    pub(crate) fn begin_unauthenticated(
        self: &Arc<Self>,
        ip: IpAddr,
    ) -> Result<UnauthenticatedConnection, GuardError> {
        let mut connections = self.connections.lock().expect("guard mutex");
        let count = connections.entry(ip).or_insert(0);
        if *count >= MAX_UNAUTH_CONNECTIONS_PER_IP {
            return Err(GuardError::TooManyConnections);
        }
        *count += 1;
        drop(connections);
        Ok(UnauthenticatedConnection {
            guards: Arc::clone(self),
            ip,
        })
    }

    /// Spends one authentication token for `ip`.
    pub(crate) fn spend_auth_token(&self, ip: IpAddr, now_ms: u64) -> Result<(), GuardError> {
        let mut buckets = self.buckets.lock().expect("guard mutex");
        let bucket = buckets.entry(ip).or_insert(Bucket {
            // A new source starts with a full burst allowance.
            tokens: AUTH_BURST as f64,
            last_ms: now_ms,
        });
        let elapsed_ms = now_ms.saturating_sub(bucket.last_ms);
        bucket.tokens = (bucket.tokens + elapsed_ms as f64 / 1_000.0 * AUTH_RATE_PER_SEC as f64)
            .min(AUTH_BURST as f64);
        bucket.last_ms = now_ms;
        if bucket.tokens < 1.0 {
            return Err(GuardError::RateLimited);
        }
        bucket.tokens -= 1.0;
        Ok(())
    }

    /// Number of unauthenticated connections currently charged to `ip`.
    #[cfg(test)]
    pub(crate) fn unauthenticated_for(&self, ip: IpAddr) -> usize {
        self.connections
            .lock()
            .expect("guard mutex")
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }
}

/// A charged unauthenticated connection; releases the charge when dropped.
#[derive(Debug)]
pub(crate) struct UnauthenticatedConnection {
    guards: Arc<DosGuards>,
    ip: IpAddr,
}

impl Drop for UnauthenticatedConnection {
    fn drop(&mut self) {
        let mut connections = self.guards.connections.lock().expect("guard mutex");
        if let Some(count) = connections.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                connections.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    /// Section 9.2: the per-IP unauthenticated connection cap is enforced, and
    /// closing a connection returns its budget.
    #[test]
    fn the_unauthenticated_connection_cap_is_charged_and_released() {
        let guards = Arc::new(DosGuards::new());
        let mut held = Vec::new();
        for _ in 0..MAX_UNAUTH_CONNECTIONS_PER_IP {
            held.push(guards.begin_unauthenticated(ip()).unwrap());
        }
        assert_eq!(
            guards.unauthenticated_for(ip()),
            MAX_UNAUTH_CONNECTIONS_PER_IP
        );
        assert_eq!(
            guards.begin_unauthenticated(ip()).unwrap_err(),
            GuardError::TooManyConnections
        );

        // A different source has its own budget.
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(guards.begin_unauthenticated(other).is_ok());

        held.pop();
        assert!(guards.begin_unauthenticated(ip()).is_ok());
    }

    /// Section 9.2: 5 authentications per second with a burst of 10.
    #[test]
    fn the_authentication_rate_is_a_token_bucket() {
        let guards = DosGuards::new();
        for i in 0..AUTH_BURST {
            assert!(
                guards.spend_auth_token(ip(), 1_000).is_ok(),
                "burst token {i} was refused"
            );
        }
        assert_eq!(
            guards.spend_auth_token(ip(), 1_000).unwrap_err(),
            GuardError::RateLimited
        );

        // A second of elapsed time refills exactly the sustained rate.
        for i in 0..AUTH_RATE_PER_SEC {
            assert!(
                guards.spend_auth_token(ip(), 2_000).is_ok(),
                "refilled token {i} was refused"
            );
        }
        assert_eq!(
            guards.spend_auth_token(ip(), 2_000).unwrap_err(),
            GuardError::RateLimited
        );

        // Long idle time must not accumulate more than the burst allowance.
        for _ in 0..AUTH_BURST {
            assert!(guards.spend_auth_token(ip(), 60_000).is_ok());
        }
        assert!(guards.spend_auth_token(ip(), 60_000).is_err());
    }

    #[test]
    fn budgets_are_per_source() {
        let guards = DosGuards::new();
        for _ in 0..AUTH_BURST {
            guards.spend_auth_token(ip(), 1_000).unwrap();
        }
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(guards.spend_auth_token(other, 1_000).is_ok());
    }
}
