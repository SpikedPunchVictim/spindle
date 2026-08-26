//! Per-caller token-bucket rate limiting on the VFS RPC entry point (DESIGN.md §A5: "per-`from_fp`
//! token bucket" — that paragraph describes the pre-auth NATS-connect-time limiter; this module
//! adapts the same mechanism to the post-auth, per-session VFS-RPC layer the task brief scopes to
//! this slice, distinct from §A5's own limiter and from §A3's callout rate limits).
//!
//! One bucket per caller key (`SessionContext::device_fp` when present, else a key derived from
//! `member_id` — see `crate::server::VfsRpcServer::rate_limit_key`), refilled at a configurable
//! rate and checked on every [`crate::server::VfsRpcServer::handle`] call, before any store access
//! (task brief: "the RPC entry point"). Time is the caller-supplied `ts: u64` (seconds), exactly
//! like every other timestamp in this pipeline — never a wall clock — so throttling stays
//! deterministic and testable without any I/O framework, matching this crate's established
//! convention (see `crate::server`'s module doc comment on `ts`).

use std::cell::RefCell;
use std::collections::HashMap;

/// Token-bucket parameters. Defaults are generous-but-bounded placeholders (DESIGN.md does not
/// specify numbers for this layer's limiter, only that one must exist) — documented here, like
/// `spindle_vfs::store::StoreLimits`, so a later slice can retune without hunting through
/// `crate::server`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum tokens a bucket can hold (i.e. the largest instantaneous burst one caller may make
    /// after being idle). Default: 200 requests.
    pub burst: f64,
    /// Tokens refilled per second. Default: 50 requests/sec — generous for interactive
    /// browsing/listing traffic, still bounded.
    pub refill_per_sec: f64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            burst: 200.0,
            refill_per_sec: 50.0,
        }
    }
}

struct Bucket {
    tokens: f64,
    last_refill_ts: u64,
}

/// The rate limiter's per-server state — one bucket per caller key, lazily created on first use.
pub(crate) struct RateLimiter {
    config: RateLimitConfig,
    buckets: RefCell<HashMap<Vec<u8>, Bucket>>,
}

impl RateLimiter {
    pub(crate) fn new(config: RateLimitConfig) -> Self {
        RateLimiter {
            config,
            buckets: RefCell::new(HashMap::new()),
        }
    }

    /// Attempts to spend one token for `key` at time `ts`; returns `true` if the caller may
    /// proceed (a token was available and has been spent), `false` if the caller is currently
    /// throttled. Refill is computed from elapsed time since the bucket's last touch — a caller
    /// seen for the first time starts with a full bucket (`burst` tokens), never empty, so a
    /// brand-new session is not immediately throttled.
    pub(crate) fn try_acquire(&self, key: &[u8], ts: u64) -> bool {
        let mut buckets = self.buckets.borrow_mut();
        let bucket = buckets.entry(key.to_vec()).or_insert_with(|| Bucket {
            tokens: self.config.burst,
            last_refill_ts: ts,
        });

        let elapsed = ts.saturating_sub(bucket.last_refill_ts) as f64;
        bucket.tokens =
            (bucket.tokens + elapsed * self.config.refill_per_sec).min(self.config.burst);
        bucket.last_refill_ts = ts;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_burst_then_throttles() {
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: 2.0,
            refill_per_sec: 0.0,
        });
        assert!(limiter.try_acquire(b"caller-a", 0));
        assert!(limiter.try_acquire(b"caller-a", 0));
        assert!(
            !limiter.try_acquire(b"caller-a", 0),
            "third call at the same instant must be throttled"
        );
    }

    #[test]
    fn refills_over_time() {
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: 1.0,
            refill_per_sec: 1.0,
        });
        assert!(limiter.try_acquire(b"caller-a", 0));
        assert!(!limiter.try_acquire(b"caller-a", 0));
        // One second later, one token has refilled.
        assert!(limiter.try_acquire(b"caller-a", 1));
    }

    #[test]
    fn buckets_are_independent_per_caller() {
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: 1.0,
            refill_per_sec: 0.0,
        });
        assert!(limiter.try_acquire(b"caller-a", 0));
        assert!(!limiter.try_acquire(b"caller-a", 0));
        // A different caller has its own untouched bucket.
        assert!(limiter.try_acquire(b"caller-b", 0));
    }
}
