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
use std::sync::Mutex;

use spindle_core::Fingerprint;

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

impl RateLimitConfig {
    /// Returns this config with any non-finite (`NaN`/`inf`) or negative `burst`/`refill_per_sec`
    /// replaced by `0.0`. Both fields are `pub` on a `pub` type reachable from
    /// `HostConnectAuthorizer::with_connect_rate_limit`, so nothing upstream of construction can
    /// be trusted to have validated them — sanitizing once, here, is the only place that is
    /// guaranteed to run no matter how the config arrived.
    ///
    /// `0.0` is the correct replacement for BOTH fields, not merely a convenient one: a bucket
    /// with `burst: 0.0` starts, and stays, empty (`refill_and_spend`'s `tokens >= 1.0` check
    /// never passes), and `refill_per_sec: 0.0` never adds anything back — so a sanitized field
    /// denies every request through it, fails CLOSED. That direction is deliberate: a
    /// misconfigured limiter that refuses connects is loud, breaks the first test or smoke run,
    /// and gets fixed immediately; one that silently permits everything is invisible and defeats
    /// the control it exists to be, with no test short of one built to specifically probe for it
    /// (see `a_nan_refill_rate_cannot_disable_the_limiter` et al., below) ever noticing.
    ///
    /// The `NaN` case is not hypothetical carelessness — it defeats this type's own arithmetic
    /// specifically: `f64::min` returns the *non*-`NaN` operand, so in `refill`,
    /// `(bucket.tokens + NaN).min(config.burst)` evaluates to `config.burst` on every single call,
    /// refilling the bucket to full regardless of elapsed time. A `refill_per_sec` of `NaN` alone
    /// — no attacker control needed, just a bad config value — silently turns this limiter into a
    /// no-op while every doc comment in this module insists it cannot be. `burst: f64::INFINITY`
    /// fails open the same way without even needing `NaN`: `.min(inf)` never caps anything, so the
    /// bucket is effectively bottomless.
    ///
    /// Deliberately does NOT touch [`ConnectRateLimitConfig::max_tracked_fps`] — see that field's
    /// own doc comment for why `0` there already fails closed and needs no sanitizing.
    fn sanitized(self) -> Self {
        fn sanitize_one(parameter: &'static str, value: f64) -> f64 {
            if value.is_finite() && value >= 0.0 {
                return value;
            }
            // Only logged when sanitization actually changes something — the normal, correctly-
            // configured path never emits this.
            tracing::error!(
                parameter,
                value,
                "RateLimitConfig::sanitized: non-finite or negative parameter rejected and \
                 replaced with 0.0. 0.0 denies every request through this bucket (fails the \
                 limiter closed) rather than the alternative of silently permitting every \
                 request (failing it open) — check the caller that built this config"
            );
            0.0
        }
        RateLimitConfig {
            burst: sanitize_one("burst", self.burst),
            refill_per_sec: sanitize_one("refill_per_sec", self.refill_per_sec),
        }
    }
}

struct Bucket {
    tokens: f64,
    last_refill_ts: u64,
}

/// Advances `bucket` to `ts`: adds tokens for elapsed time at `config.refill_per_sec`, capped at
/// `config.burst`, and moves `last_refill_ts` forward. Split out from
/// [`refill_and_spend`]/`RateLimiter::try_acquire` so [`ConnectRateLimiter::try_acquire_fp`] can
/// refill a bucket without necessarily spending from it (its capacity-eviction sweep needs exactly
/// that: bring every tracked bucket up to date, then look at whether it is full, without charging
/// anyone a token for being swept).
///
/// The `last_refill_ts` write below is not bookkeeping incidental to the token math — it IS the
/// reason repeated calls at the same or a later `ts` don't keep re-granting tokens for time that
/// was already paid out. Drop it (or make it conditional on `elapsed > 0.0`, which amounts to the
/// same mistake) and every bucket keeps measuring `elapsed` from the moment it was *created*,
/// forever: a bucket touched twice a second real-time looks, ts-wise, like it has been idle since
/// creation on every call after the first, so it refills to `burst` almost immediately and never
/// throttles again. `cargo test` alone does not catch this — see
/// `refilling_advances_the_high_water_mark_so_a_repeat_call_at_the_same_ts_is_denied` below and
/// its `ConnectRateLimiter` twin, which are the only tests that call `try_acquire` twice at the
/// *same* `ts` after a refill has already happened, the one shape that tells correct and broken
/// apart.
///
/// The write only ever moves `last_refill_ts` forward, though. `ts.saturating_sub` above already
/// clamps `elapsed` to `0.0` when `ts` is behind `last_refill_ts` (a backward clock step), but
/// that alone does not stop the reference point itself from moving backwards too — and if it did,
/// a later call at the original, larger `ts` would measure `elapsed` from that earlier point and
/// hand a possibly-just-drained bucket a full burst's worth of tokens for time that never passed.
/// `last_refill_ts` is a monotonic high-water mark, not "the ts of the last call": a clock that
/// steps backwards must never be allowed to manufacture tokens. See
/// `a_backward_clock_step_does_not_grant_a_free_refill` below.
fn refill(bucket: &mut Bucket, config: &RateLimitConfig, ts: u64) {
    let elapsed = ts.saturating_sub(bucket.last_refill_ts) as f64;
    bucket.tokens = (bucket.tokens + elapsed * config.refill_per_sec).min(config.burst);
    if ts > bucket.last_refill_ts {
        bucket.last_refill_ts = ts;
    }
}

/// Refills `bucket` to `ts`, then attempts to spend one token. Returns `true` (token spent) or
/// `false` (bucket empty, caller throttled) — the shared arithmetic behind both
/// `RateLimiter::try_acquire`, [`ConnectRateLimiter::try_acquire_global`], and
/// [`ConnectRateLimiter::try_acquire_fp`].
fn refill_and_spend(bucket: &mut Bucket, config: &RateLimitConfig, ts: u64) -> bool {
    refill(bucket, config, ts);
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        false
    }
}

/// The rate limiter's per-server state — one bucket per caller key, lazily created on first use.
pub(crate) struct RateLimiter {
    config: RateLimitConfig,
    buckets: RefCell<HashMap<Vec<u8>, Bucket>>,
}

impl RateLimiter {
    pub(crate) fn new(config: RateLimitConfig) -> Self {
        RateLimiter {
            // Sanitize once, at construction — see `RateLimitConfig::sanitized`'s doc comment for
            // why an unsanitized `NaN`/`inf`/negative field would otherwise silently turn this
            // limiter into a no-op.
            config: config.sanitized(),
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

        refill_and_spend(bucket, &self.config, ts)
    }
}

/// Token-bucket parameters for [`ConnectRateLimiter`], the pre-authentication limiter in front of
/// `HostConnectAuthorizer` (DESIGN.md §A5: "per-`from_fp` token bucket"). These are, like
/// [`RateLimitConfig`]'s own defaults, retunable placeholders — DESIGN.md mandates that a token
/// bucket exist at this layer but specifies no numbers for it.
///
/// The defaults below are deliberately far tighter than [`RateLimitConfig::default`]'s
/// 200 burst / 50 per-sec: that limiter guards the post-auth VFS-RPC path, where the caller has
/// already proven a signature. This one guards a *pre-authentication* path — the connect
/// authorizer runs before any signature has been checked, so it is the first thing an attacker
/// with no valid credential at all can reach and hammer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ConnectRateLimitConfig {
    /// Per-`from_fp` bucket: bounds how fast one *identified* device (a specific claimed
    /// `from_fp`) may retry connects. Default: burst 10, refill 1/sec.
    pub per_fp: RateLimitConfig,
    /// Bucket shared across every `from_fp`: bounds total connect-lookup work regardless of how
    /// many distinct (and, pre-auth, unverified) fingerprints an attacker rotates through.
    /// Default: burst 200, refill 50/sec.
    pub global: RateLimitConfig,
    /// Upper bound on the number of per-fp buckets tracked at once, so an attacker who fabricates
    /// unboundedly many `from_fp` values cannot turn the limiter itself into an unbounded
    /// allocation. Default: 4096.
    ///
    /// Deliberately left out of the `sanitized()` treatment [`RateLimitConfig::burst`] and
    /// [`RateLimitConfig::refill_per_sec`] get in [`ConnectRateLimiter::new`]: `0` here already
    /// fails CLOSED on its own — `try_acquire`'s capacity check (`buckets.len() >=
    /// max_tracked_fps`) is `true` before any bucket exists, so with `0` no `from_fp`, ever, can
    /// be admitted into the map, and every connect from a not-yet-tracked fp is refused. That is
    /// the opposite failure direction from `burst`/`refill_per_sec`'s `NaN`/`inf` hazard, so do
    /// not "fix" a `0` here by giving it some nonzero fallback default under the assumption it
    /// must be a misconfiguration — that would turn an already-safe fail-closed value into a
    /// fail-open one.
    pub max_tracked_fps: usize,
}

impl Default for ConnectRateLimitConfig {
    fn default() -> Self {
        ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 10.0,
                refill_per_sec: 1.0,
            },
            global: RateLimitConfig {
                burst: 200.0,
                refill_per_sec: 50.0,
            },
            max_tracked_fps: 4096,
        }
    }
}

struct ConnectLimiterState {
    buckets: HashMap<Fingerprint, Bucket>,
    global: Bucket,
}

/// Pre-authentication rate limiter for `HostConnectAuthorizer`.
///
/// DESIGN.md §A5 calls for a "per-`from_fp` token bucket", but at the connect authorizer
/// `from_fp` is unverified and attacker-chosen: it is exactly the value the authorizer uses to
/// look up the `sign_pk` a signature would later be checked against, so nothing has vouched for
/// it yet. A limiter keyed only on `from_fp` is therefore defeated by an attacker who simply
/// rotates the claimed fingerprint on every connect attempt — and worse, each fabricated fp
/// allocates a new bucket, so the limiter's own state becomes an unbounded-allocation target.
///
/// This type resolves that tension by keeping both layers, and — since td-fc5a30 — by charging
/// them at two different points in the connect flow rather than in one call:
/// - a global bucket (`ConnectLimiterState::global`), charged by [`Self::try_acquire_global`] on
///   the **pre**-authentication path (`HostConnectAuthorizer::authorize`). It bounds total
///   connect-lookup work regardless of identity rotation, since a per-fp bucket alone cannot, and
///   it is the *only* thing charged while `from_fp` is still unverified;
/// - a per-fp bucket (`ConnectLimiterState::buckets`), charged by [`Self::try_acquire_fp`] on the
///   **post**-verification path (`HostConnectAuthorizer::on_verified`, reached only after the
///   offer's signature has verified). It bounds a single *identified* device the way §A5
///   describes, capped at `max_tracked_fps` entries: when full, every bucket that has refilled
///   back to full is swept out to make room (see `try_acquire_fp` step 2) — there is no recency
///   ordering, so a bucket is evicted purely because it is fully refilled (indistinguishable from
///   a never-created one), not because it is the "oldest" one.
///
/// Accepted cost: shared fate. A flood that exhausts the global bucket slows legitimate connects
/// too, not just the flooder — the alternative (no global bound) lets identity rotation defeat
/// throttling entirely, which is worse. This shape is recorded as a DESIGN.md amendment
/// (v0.9.24, §A5).
///
/// # td-fc5a30: why the two buckets are charged at different stages
///
/// An independent adversarial review (td-4bcf24) named two denial modes that both followed from
/// charging *per-identity* costs against an unverified, attacker-chosen `from_fp`. td-fc5a30
/// settled the open question that review left — whether those modes were reachable at all — and
/// the answer is **yes**: measured against nats-server 2.10, publish permissions are evaluated
/// against the publish *subject* only, never the reply subject, so a device holding
/// `pub host.<h>.connect` can publish an offer naming a victim's `from_fp` with
/// `reply = _INBOX_<victim_fp>.…` and it passes `spindle_net::signaling::subject::reply_prefix_ok`
/// unchallenged. (`spikes/s1-callout` had proven only that a device cannot SUBSCRIBE to another's
/// inbox, which is a different claim.)
///
/// **Mode 1 — targeted lockout of a named `from_fp`.** With the per-fp bucket charged pre-auth,
/// an attacker naming a *victim's* `from_fp` drained that victim's own bucket and locked that one
/// device out for as long as the flood ran. At the defaults above (`per_fp` burst 10, refill
/// 1/sec), roughly two offers per second sufficed. Measured by the review: a victim succeeded
/// 0/60 times during a sustained flood while a bystander fp was allowed 10/10 at the same instant.
/// Worse, the global bucket could not see it happening — the old single `try_acquire` returned
/// `false` on a per-fp refusal before the global bucket was ever consulted, so a flood aimed at
/// one victim spent zero global tokens and tripped no shared-fate signal at all.
///
/// **Mode 2 — outright refusal of untracked devices at capacity.** When the map is full
/// (`max_tracked_fps`, default 4096) and every tracked bucket is still throttled, the sweep in
/// `try_acquire_fp` step 2 frees nothing and the call returns `false` for any fp the map does not
/// already track. This is a *harder* denial than the shared-fate cost above — an outright refusal,
/// not a slowdown — and it is decoupled from the global bucket: it bites even while the global
/// bucket is completely full and untouched. The review measured 0/20 legitimate new devices
/// admitted while the map sat at capacity with the global bucket full, recovering only roughly 10
/// seconds after the flood stopped. Pre-auth, filling the map cost the attacker nothing but
/// fabricated names.
///
/// Failing closed at capacity is still the right call — the alternative is exactly the unbounded
/// allocation `max_tracked_fps` exists to prevent — but this cost must not be mistaken for the
/// shared-fate cost described above it: shared fate slows legitimate connects, this refuses them
/// outright.
///
/// Splitting the two charges across the signature-verification boundary is what defuses both
/// modes: an unauthenticated peer can now reach only [`Self::try_acquire_global`], whose cost is
/// shared by construction and names nobody, while [`Self::try_acquire_fp`] — the bucket, the map
/// slot, the eviction sweep — is reachable only by a peer that has proven it holds `fp`'s signing
/// key. **Do not merge these two methods back into one, and do not call `try_acquire_fp` from any
/// pre-verification path.** Either change reinstates a remote, attacker-directed lockout of an
/// arbitrary victim device.
///
/// What still bounds an unauthenticated flooder is therefore the global bucket alone (plus
/// `spindle_net::signaling::host::HostOptions::max_concurrent_connects`, and §A5's uniform silent
/// drop). That is a real reduction in per-identity granularity against unauthenticated traffic,
/// accepted deliberately: per-identity granularity over an identity nobody has proven is not
/// throttling, it is a targeting mechanism.
///
/// Uses `std::sync::Mutex`, not `RefCell` (unlike [`RateLimiter`]): this limiter lives inside
/// `HostConnectAuthorizer`, which must be `Send + Sync + 'static`.
pub(crate) struct ConnectRateLimiter {
    config: ConnectRateLimitConfig,
    state: Mutex<ConnectLimiterState>,
}

impl ConnectRateLimiter {
    pub(crate) fn new(config: ConnectRateLimitConfig) -> Self {
        // Sanitize both buckets' configs once, at construction — see `RateLimitConfig::sanitized`'s
        // doc comment. `max_tracked_fps` is passed through untouched; its own doc comment explains
        // why `0` already fails closed and must not be sanitized.
        let config = ConnectRateLimitConfig {
            per_fp: config.per_fp.sanitized(),
            global: config.global.sanitized(),
            max_tracked_fps: config.max_tracked_fps,
        };
        let global = Bucket {
            tokens: config.global.burst,
            last_refill_ts: 0,
        };
        ConnectRateLimiter {
            config,
            state: Mutex::new(ConnectLimiterState {
                buckets: HashMap::new(),
                global,
            }),
        }
    }

    /// Attempts to spend one token from the **global** bucket at time `ts`; returns `true` if the
    /// connect attempt may proceed, `false` if it must be refused. Charges nothing to any
    /// individual fingerprint, touches no per-fp state, and allocates nothing — it does not take a
    /// `Fingerprint` at all, so there is no name for a caller to accidentally charge.
    ///
    /// This is the half `HostConnectAuthorizer::authorize` calls, on the **pre**-authentication
    /// path where `from_fp` is unverified and attacker-chosen (see this type's doc comment, and
    /// `spindle_net::signaling::authorize::ConnectAuthorizer`'s). Everything it costs is bounded
    /// globally and shared by everyone, which is precisely why an attacker naming an arbitrary
    /// victim gains nothing from it beyond the shared-fate cost they could impose under any name.
    ///
    /// A poisoned lock (some other thread panicked while holding it) fails closed: this returns
    /// `false` rather than falling back to some "unlimited" behavior, since a limiter that stops
    /// limiting under stress is worse than one that stops connects.
    pub(crate) fn try_acquire_global(&self, ts: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        refill_and_spend(&mut state.global, &self.config.global, ts)
    }

    /// Attempts to spend one token from `fp`'s **own** bucket at time `ts`, creating and tracking
    /// that bucket if it is not tracked yet; returns `true` if the connect attempt may proceed,
    /// `false` if it must be refused. Includes the capacity-bounded map's sweep-and-refuse
    /// behaviour — see this type's doc comment.
    ///
    /// This is the half `HostConnectAuthorizer::on_verified` calls, and it must be called **only**
    /// after the offer's signature has verified under the key that `fp` names (td-fc5a30). Both
    /// costs here are charged to `fp` specifically — a token out of that fingerprint's bucket, and
    /// a slot in a bounded map keyed by it — so calling this with an unverified `fp` hands an
    /// attacker a remote "throttle this exact device" primitive plus a way to exhaust the map with
    /// fabricated names. Neither is reachable once the only caller is behind a signature check.
    ///
    /// Poisoned lock: fails closed, as [`Self::try_acquire_global`] does.
    pub(crate) fn try_acquire_fp(&self, fp: Fingerprint, ts: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };

        // Capacity-bounded per-fp map: only relevant when `fp` isn't already tracked and the map
        // is already at capacity.
        if !state.buckets.contains_key(&fp) && state.buckets.len() >= self.config.max_tracked_fps {
            // Sweep buckets that have refilled back to full. A full bucket is indistinguishable
            // from one that was never created — dropping it loses no throttling state, since the
            // next request from that fp will just recreate an identical fresh bucket.
            let per_fp = &self.config.per_fp;
            state.buckets.retain(|_, bucket| {
                refill(bucket, per_fp, ts);
                bucket.tokens < per_fp.burst
            });

            // Still full after sweeping: every tracked bucket is actively throttled. Refuse the
            // new fp rather than inserting anyway — the alternative turns this limiter into an
            // unbounded allocation, which is the exact failure mode it exists to prevent.
            if state.buckets.len() >= self.config.max_tracked_fps {
                return false;
            }
        }

        let per_fp_config = self.config.per_fp;
        let bucket = state.buckets.entry(fp).or_insert_with(|| Bucket {
            // A first-seen fp starts with a full bucket, never empty, so it isn't immediately
            // throttled — same rule as `RateLimiter::try_acquire`.
            tokens: per_fp_config.burst,
            last_refill_ts: ts,
        });
        refill_and_spend(bucket, &per_fp_config, ts)
    }

    #[cfg(test)]
    pub(crate) fn tracked_fps(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.buckets.len(),
            Err(_) => 0,
        }
    }

    /// Test-only: poisons `state`'s lock by panicking while holding it, so tests can exercise the
    /// fail-closed path in `try_acquire`.
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let _state = self.state.lock().unwrap();
        panic!("deliberate poison for test");
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

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    #[test]
    fn connect_limiter_allows_up_to_the_per_fp_burst_then_throttles_that_fp() {
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 2.0,
                refill_per_sec: 0.0,
            },
            global: RateLimitConfig {
                burst: 200.0,
                refill_per_sec: 50.0,
            },
            max_tracked_fps: 4096,
        });
        let a = fp(b"connect-fp-a");
        assert!(limiter.try_acquire_fp(a, 0));
        assert!(limiter.try_acquire_fp(a, 0));
        assert!(
            !limiter.try_acquire_fp(a, 0),
            "third call at the same instant must be throttled by the per-fp bucket"
        );
    }

    // td-fc5a30 replaced `connect_limiter_does_not_let_a_throttled_fp_drain_the_global_budget`
    // with the test below. The old test is recorded here rather than silently deleted, because it
    // pinned a real security property and the replacement pins a different one.
    //
    // WHAT THE OLD TEST PROVED. `try_acquire` charged the per-fp bucket FIRST and consulted the
    // global bucket only once the per-fp bucket had allowed. So an already-throttled flooder's
    // repeated attempts were rejected by its own bucket without ever spending a token from the
    // shared global budget. The test pinned that ordering by giving the global bucket exactly
    // enough budget (3) for one flooder success plus two legitimate ones, letting the flooder be
    // denied nine times, and then requiring both legitimate fps to still succeed.
    //
    // WHY THE NEW DESIGN MAKES IT MOOT. There is no ordering left to pin. The two buckets are now
    // charged by two separate methods, called at two different stages of the connect flow by two
    // different `HostConnectAuthorizer` entry points: `try_acquire_global` from `authorize`
    // (pre-signature-verification) and `try_acquire_fp` from `on_verified` (post-verification).
    // "Which one is consulted first" is no longer a property of this type at all — it is a
    // property of a caller that no longer makes both calls at the same moment.
    //
    // That ordering was, moreover, the mechanism behind the defect td-fc5a30 fixes. Because a
    // per-fp refusal short-circuited before the global bucket, a flood aimed at ONE victim's
    // `from_fp` spent zero global tokens and tripped no shared signal whatsoever — the property
    // the old test celebrated is the same property that made a targeted lockout invisible. See
    // `ConnectRateLimiter`'s doc comment, "td-fc5a30: why the two buckets are charged at different
    // stages".
    //
    // WHAT BOUNDS A FLOODER NOW. The global bucket, and only the global bucket, plus
    // `spindle_net::signaling::host::HostOptions::max_concurrent_connects` above it. Every connect
    // offer — forged or genuine — charges `try_acquire_global` before any signature is checked, so
    // a flood is bounded no matter what `from_fp` it claims (pinned by
    // `connect_limiter_global_bucket_throttles_a_flood_that_rotates_from_fp`, rewritten for the
    // same reason). The per-fp bucket no longer bounds unauthenticated traffic at all; it bounds
    // how fast an *authenticated* device may complete connects, and it is unreachable without that
    // device's signing key.
    //
    // WHAT THIS TEST PINS INSTEAD. That the two buckets are genuinely independent: spending one
    // never spends the other. That independence is what makes the staged split meaningful rather
    // than a rename — if `try_acquire_fp` still charged the global bucket, a flood aimed at one
    // victim would be back to draining the shared budget too, and if `try_acquire_global` still
    // touched per-fp state, the targeted lockout would be back outright.
    #[test]
    fn connect_limiter_charges_the_global_and_per_fp_buckets_independently() {
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 1.0,
                refill_per_sec: 0.0,
            },
            global: RateLimitConfig {
                burst: 2.0,
                refill_per_sec: 0.0,
            },
            max_tracked_fps: 4096,
        });
        let a = fp(b"connect-fp-staged-a");
        let b = fp(b"connect-fp-staged-b");

        // Drain one fp's own bucket completely (burst 1, no refill), then keep hammering it.
        assert!(limiter.try_acquire_fp(a, 0), "a's bucket starts full");
        for _ in 0..9 {
            assert!(
                !limiter.try_acquire_fp(a, 0),
                "a's own bucket is spent and does not refill at a frozen clock"
            );
        }

        // None of that touched the global bucket: both of its two tokens are still there.
        assert!(
            limiter.try_acquire_global(0),
            "global token 1 of 2 -- try_acquire_fp must not spend global tokens"
        );
        assert!(
            limiter.try_acquire_global(0),
            "global token 2 of 2 -- ten per-fp calls spent none of the shared budget"
        );
        assert!(
            !limiter.try_acquire_global(0),
            "global burst of 2 is now genuinely spent, so this test is observing the real bucket \
             rather than an unbounded one"
        );

        // And draining the global bucket did not touch b's per-fp bucket either.
        assert!(
            limiter.try_acquire_fp(b, 0),
            "b's own bucket is full and independent of the exhausted global one -- \
             try_acquire_global must not spend per-fp tokens"
        );
    }

    /// The bounded-map half of the same independence claim: `try_acquire_global` must not create,
    /// touch, or grow the per-fp tracking map. This is what makes a flood of fabricated `from_fp`
    /// values harmless pre-verification — every one of them reaches only the global bucket, so the
    /// map that `max_tracked_fps` bounds never sees them at all.
    #[test]
    fn connect_limiter_global_acquires_never_grow_the_tracked_fp_map() {
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 10.0,
                refill_per_sec: 0.0,
            },
            global: RateLimitConfig {
                burst: 1000.0,
                refill_per_sec: 0.0,
            },
            max_tracked_fps: 4096,
        });
        for _ in 0..100 {
            assert!(limiter.try_acquire_global(0));
        }
        assert_eq!(
            limiter.tracked_fps(),
            0,
            "100 pre-verification acquires must leave the per-fp map completely empty -- \
             try_acquire_global takes no Fingerprint at all, so there is nothing for it to key on"
        );

        // One post-verification acquire, by contrast, does track its fp.
        assert!(limiter.try_acquire_fp(fp(b"connect-fp-tracked"), 0));
        assert_eq!(
            limiter.tracked_fps(),
            1,
            "try_acquire_fp is the only method that inserts into the bounded map"
        );
    }

    #[test]
    fn connect_limiter_global_bucket_throttles_a_flood_that_rotates_from_fp() {
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 10.0,
                refill_per_sec: 0.0,
            },
            global: RateLimitConfig {
                burst: 3.0,
                refill_per_sec: 0.0,
            },
            max_tracked_fps: 4096,
        });
        // Four offers arriving pre-verification, each naming a different fabricated `from_fp`.
        // Rotation is now irrelevant to this call by construction -- `try_acquire_global` does not
        // take a fingerprint at all -- which is exactly the property being pinned: the global
        // bucket is the ONLY thing bounding an unauthenticated flood, so it must bound it
        // regardless of what names the flood invents.
        assert!(limiter.try_acquire_global(0));
        assert!(limiter.try_acquire_global(0));
        assert!(limiter.try_acquire_global(0));
        assert!(
            !limiter.try_acquire_global(0),
            "a fourth offer must be denied once the global bucket is spent, whatever from_fp it \
             claims -- with the per-fp bucket now charged only post-verification, nothing else \
             bounds a rotating flood"
        );
    }

    #[test]
    fn connect_limiter_refuses_a_new_fp_rather_than_growing_past_capacity() {
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 1.0,
                refill_per_sec: 0.0,
            },
            global: RateLimitConfig {
                burst: 1000.0,
                refill_per_sec: 1000.0,
            },
            max_tracked_fps: 2,
        });
        assert!(limiter.try_acquire_fp(fp(b"capacity-fp-1"), 0));
        assert!(limiter.try_acquire_fp(fp(b"capacity-fp-2"), 0));
        assert!(
            !limiter.try_acquire_fp(fp(b"capacity-fp-3"), 0),
            "a third distinct fp must be refused once the map is at capacity and no bucket has \
             refilled to full"
        );
        assert_eq!(limiter.tracked_fps(), 2);
    }

    #[test]
    fn connect_limiter_evicts_refilled_buckets_to_admit_a_new_fp() {
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 1.0,
                refill_per_sec: 1.0,
            },
            global: RateLimitConfig {
                burst: 1000.0,
                refill_per_sec: 1000.0,
            },
            max_tracked_fps: 2,
        });
        assert!(limiter.try_acquire_fp(fp(b"evict-fp-1"), 0));
        assert!(limiter.try_acquire_fp(fp(b"evict-fp-2"), 0));
        // Five seconds later both buckets have refilled to full (burst 1.0, refill 1.0/sec), so
        // the capacity sweep should evict them and admit a third fp.
        assert!(
            limiter.try_acquire_fp(fp(b"evict-fp-3"), 5),
            "fully-refilled buckets must be evicted to admit a new fp at capacity"
        );
        assert!(limiter.tracked_fps() <= 2);
    }

    #[test]
    fn connect_limiter_denies_when_its_lock_is_poisoned() {
        let limiter =
            std::sync::Arc::new(ConnectRateLimiter::new(ConnectRateLimitConfig::default()));
        let poisoner = std::sync::Arc::clone(&limiter);
        let result = std::thread::spawn(move || poisoner.poison_for_test()).join();
        assert!(
            result.is_err(),
            "poison_for_test must panic while holding the lock"
        );
        assert!(
            !limiter.try_acquire_global(0),
            "a poisoned limiter must fail closed on the global bucket, never become unlimited"
        );
        assert!(
            !limiter.try_acquire_fp(fp(b"poison-fp"), 0),
            "a poisoned limiter must fail closed on the per-fp bucket too -- both halves of the \
             td-fc5a30 split share one Mutex, and both must refuse rather than fall back to \
             unlimited"
        );
    }

    // --- td-4bcf24: regression coverage for defects an independent adversarial review found in
    // this module's `refill` and config handling. See that task's notes for the full analysis;
    // each test below is named for the specific defect it pins.

    #[test]
    fn refilling_advances_the_high_water_mark_so_a_repeat_call_at_the_same_ts_is_denied() {
        // Deleting `refill`'s `last_refill_ts` advance leaves this exact suite green everywhere
        // except here: the two pre-existing `refills_over_time` tests each advance the clock
        // exactly once from bucket creation, which is the one case where the correct and the
        // neutered `refill` agree. The fourth call below — a SECOND `try_acquire` at the same
        // ts=1 that just granted a token — is the whole point: under the neuter, `last_refill_ts`
        // never left `0` (bucket creation), so this call re-measures elapsed time as `1 - 0 = 1`
        // all over again and wrongly hands out a second token.
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: 1.0,
            refill_per_sec: 1.0,
        });
        assert!(
            limiter.try_acquire(b"caller-a", 0),
            "ts=0: bucket starts full"
        );
        assert!(
            !limiter.try_acquire(b"caller-a", 0),
            "ts=0 again: no time has passed, bucket is empty"
        );
        assert!(
            limiter.try_acquire(b"caller-a", 1),
            "ts=1: exactly one second/token has elapsed"
        );
        assert!(
            !limiter.try_acquire(b"caller-a", 1),
            "ts=1 AGAIN must be denied — no time passed since the previous call, so no token \
             should have refilled. An `Allow` here means `last_refill_ts` was not advanced and \
             elapsed time is still being measured from bucket creation"
        );
    }

    #[test]
    fn connect_limiter_refilling_advances_the_high_water_mark_so_a_repeat_call_at_the_same_ts_is_denied(
    ) {
        // `ConnectRateLimiter::try_acquire_fp` spends through the same `refill` this module's
        // `RateLimiter` uses (for its per-fp bucket) — see the sibling test above for the full
        // reasoning. A generous global bucket keeps this test isolated to the per-fp path.
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 1.0,
                refill_per_sec: 1.0,
            },
            global: RateLimitConfig {
                burst: 1000.0,
                refill_per_sec: 1000.0,
            },
            max_tracked_fps: 4096,
        });
        let a = fp(b"connect-fp-repeat-ts");
        assert!(limiter.try_acquire_fp(a, 0), "ts=0: bucket starts full");
        assert!(!limiter.try_acquire_fp(a, 0), "ts=0 again: bucket is empty");
        assert!(limiter.try_acquire_fp(a, 1), "ts=1: one token refilled");
        assert!(
            !limiter.try_acquire_fp(a, 1),
            "ts=1 AGAIN must be denied — a second token here means `last_refill_ts` was never \
             advanced past bucket creation"
        );
    }

    #[test]
    fn connect_limiter_global_bucket_refills_over_time() {
        // Pins the global bucket's own refill specifically: replacing the config
        // `ConnectRateLimiter::try_acquire_global`'s `refill_and_spend(&mut state.global, ...)`
        // call is given with one whose `refill_per_sec` is `0.0` leaves every other test in this
        // module green, because none of them advance the clock far enough, on a global bucket
        // that has not already been exhausted, to observe a refill. This test drains the global
        // bucket, advances the clock, and requires the refill to actually have happened.
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            // Generous enough that the per-fp bucket never interferes with the global assertions.
            per_fp: RateLimitConfig {
                burst: 1000.0,
                refill_per_sec: 1000.0,
            },
            global: RateLimitConfig {
                burst: 2.0,
                refill_per_sec: 1.0,
            },
            max_tracked_fps: 4096,
        });
        assert!(
            limiter.try_acquire_global(0),
            "global burst is 2: first spend allowed"
        );
        assert!(
            limiter.try_acquire_global(0),
            "global burst is 2: second spend allowed"
        );
        assert!(
            !limiter.try_acquire_global(0),
            "global bucket is drained at ts=0: a third offer must be denied"
        );
        assert!(
            limiter.try_acquire_global(1),
            "one second later, at 1 token/sec, exactly one global token has refilled — this \
             specifically fails if the global bucket's refill_per_sec is not actually wired to \
             refill_and_spend"
        );
    }

    #[test]
    fn a_backward_clock_step_does_not_grant_a_free_refill() {
        // `saturating_sub` clamps `elapsed` to `0` when `ts` is behind `last_refill_ts`, but that
        // alone does not stop `last_refill_ts` itself from being written backwards. If it were,
        // a later call at the ORIGINAL, larger ts would measure elapsed time from the backward-
        // stepped point and hand out a full burst — not just the one token that time actually
        // earned.
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: 5.0,
            refill_per_sec: 1.0,
        });
        // Drain the bucket at a large ts.
        for _ in 0..5 {
            assert!(limiter.try_acquire(b"caller-a", 1000));
        }
        assert!(
            !limiter.try_acquire(b"caller-a", 1000),
            "bucket must be fully drained"
        );
        // Clock steps backwards. Must still be empty — and must not move last_refill_ts backwards.
        assert!(
            !limiter.try_acquire(b"caller-a", 10),
            "a backward clock step must not itself grant a token"
        );
        // Clock resumes forward from the ORIGINAL high point, one second later: exactly one token
        // should have refilled (1 elapsed second at 1/sec since ts=1000), not a full burst of 5
        // (which is what measuring elapsed from the backward-stepped ts=10 would produce: 991
        // apparent elapsed seconds, capped at burst).
        assert!(
            limiter.try_acquire(b"caller-a", 1001),
            "exactly one second has passed since the bucket was last legitimately touched at \
             ts=1000, so exactly one token should be available"
        );
        assert!(
            !limiter.try_acquire(b"caller-a", 1001),
            "a second token here means the backward step at ts=10 was allowed to move \
             last_refill_ts backwards, manufacturing a free near-full-burst refill"
        );
    }

    #[test]
    fn a_nan_refill_rate_cannot_disable_the_limiter() {
        // `f64::min` returns the non-NaN operand, so an unsanitized `(tokens + NaN).min(burst)`
        // evaluates to `burst` on every call — a silent, permanent full refill regardless of
        // elapsed time. `RateLimitConfig::sanitized` must replace this with `0.0` instead, which
        // denies everything rather than allowing everything.
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: 2.0,
            refill_per_sec: f64::NAN,
        });
        assert!(limiter.try_acquire(b"caller-a", 0));
        assert!(limiter.try_acquire(b"caller-a", 0));
        assert!(
            !limiter.try_acquire(b"caller-a", 0),
            "burst of 2 exhausted; a NaN refill_per_sec must not silently refill to full"
        );
        assert!(
            !limiter.try_acquire(b"caller-a", 1_000_000),
            "sanitized refill_per_sec is 0.0: no amount of elapsed time should refill this bucket"
        );
    }

    #[test]
    fn an_infinite_burst_cannot_disable_the_limiter() {
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: f64::INFINITY,
            refill_per_sec: 1.0,
        });
        assert!(
            !limiter.try_acquire(b"caller-a", 0),
            "an infinite burst must be sanitized to 0.0 (denying immediately), not left as a \
             bottomless bucket"
        );
    }

    #[test]
    fn a_negative_config_value_cannot_disable_the_limiter() {
        let limiter = RateLimiter::new(RateLimitConfig {
            burst: -5.0,
            refill_per_sec: -1.0,
        });
        assert!(
            !limiter.try_acquire(b"caller-a", 0),
            "negative burst/refill_per_sec must be sanitized to 0.0, not treated as unlimited or \
             inverted"
        );
    }

    #[test]
    fn connect_limiter_sanitizes_a_nan_per_fp_refill_rate() {
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 2.0,
                refill_per_sec: f64::NAN,
            },
            global: RateLimitConfig {
                burst: 1000.0,
                refill_per_sec: 1000.0,
            },
            max_tracked_fps: 4096,
        });
        let a = fp(b"connect-fp-nan-per-fp");
        assert!(limiter.try_acquire_fp(a, 0));
        assert!(limiter.try_acquire_fp(a, 0));
        assert!(
            !limiter.try_acquire_fp(a, 0),
            "a NaN per_fp refill_per_sec must be sanitized to 0.0, not defeat the per-fp bucket"
        );
    }

    #[test]
    fn connect_limiter_sanitizes_an_infinite_global_burst() {
        let limiter = ConnectRateLimiter::new(ConnectRateLimitConfig {
            per_fp: RateLimitConfig {
                burst: 1000.0,
                refill_per_sec: 1000.0,
            },
            global: RateLimitConfig {
                burst: f64::INFINITY,
                refill_per_sec: 1.0,
            },
            max_tracked_fps: 4096,
        });
        assert!(
            !limiter.try_acquire_global(0),
            "an infinite global burst must be sanitized to 0.0, denying immediately, rather than \
             granting a bottomless global bucket"
        );
    }
}
