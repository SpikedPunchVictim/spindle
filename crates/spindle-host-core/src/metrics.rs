//! The host's process-level metrics contract for rate limiting, sessions, and transfers
//! (DESIGN.md:707 "Observability contract", td-323db0 slice 2).
//!
//! This module owns every metric **name** and every allowed label value, so the recording sites in
//! `server.rs`, `authorize.rs`, and `session.rs` cannot invent either ad hoc. It depends only on
//! the `metrics` facade: recording is cheap and is a no-op when no recorder is installed.
//!
//! # Layering rule (owner decision 2026-10-24)
//! The facade may appear in libraries; an **exporter may not**. Nothing in this crate installs a
//! global recorder, starts a listener, or depends on `metrics-exporter-prometheus`. Exporter wiring
//! lands with the host binary that owns the process's observability endpoint (td-539ffa); this
//! crate only records.
//!
//! # Naming scheme
//! Metric names are `host_<area>_<measure>_<unit>` in `snake_case`, matching the helper's
//! `helper_<area>_<measure>_<unit>` scheme. Dots are not valid in Prometheus metric names, so
//! none appear; counters end in `_total`, per Prometheus convention.
//!
//! | Name | Type | Labels | Meaning |
//! |------|------|--------|---------|
//! | `host_ratelimit_hits_total` | counter | `scope` = `global`/`per_fp` | One per token-bucket denial. `global` is the connect path's shared pre-verification bucket; `per_fp` is any bucket keyed by one device fingerprint (the connect path's post-verification bucket and the VFS request-path limiter). |
//! | `host_sessions_live` | gauge | none | Live authorized VFS control-stream sessions currently being served by `VfsSessionHandler`. |
//! | `host_uploads_completed_total` | counter | none | Upload sessions that committed a file. |
//! | `host_uploads_aborted_total` | counter | none | Upload sessions destroyed before commit: explicit `upload_abort`, entitlement-change aborts, commit failures that discard the session, and TTL GC. |
//!
//! # Redaction (td-6c9d95 policy)
//! No label ever carries a path, group name, member name, subject, endpoint, or fingerprint —
//! fixed low-cardinality literals only. The `scope` label deliberately names a *bucket class*, not
//! the key a bucket is keyed by: the VFS request limiter and the connect limiter both key on a
//! device fingerprint, and putting that value in a label would make label cardinality itself a
//! membership leak. Per-identity detail belongs in a log line, never a metric label.
//!
//! # Session attestation / clock failures
//! DESIGN.md:707 names host-side session/transfer counts, not attestation or clock-skew signals.
//! There is no session-attestation decision in this crate or in `spindle-net`'s host path today
//! (and the connect path's clock-skew rejection is an envelope-verification reason, counted by
//! `spindle_net::metrics`), so no such metric is invented here.

use metrics::{counter, gauge};

/// One increment per token-bucket denial, split by bucket scope.
pub const RATELIMIT_HITS_TOTAL: &str = "host_ratelimit_hits_total";

/// The label key used to split rate-limit denials by bucket scope.
pub const SCOPE_LABEL: &str = "scope";

/// Live authorized VFS control-stream sessions.
pub const SESSIONS_LIVE: &str = "host_sessions_live";

/// Upload sessions that committed a file.
pub const UPLOADS_COMPLETED_TOTAL: &str = "host_uploads_completed_total";

/// Upload sessions destroyed before commit (abort, entitlement change, commit failure, TTL GC).
pub const UPLOADS_ABORTED_TOTAL: &str = "host_uploads_aborted_total";

/// Which bucket class a rate-limit denial came from — the only spelling that reaches a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    /// `ConnectRateLimiter::try_acquire_global`, charged before envelope verification.
    Global,
    /// Any bucket keyed by one device fingerprint: `ConnectRateLimiter::try_acquire_fp` after
    /// verification, and `RateLimiter::try_acquire` on the post-auth VFS request path.
    PerFingerprint,
}

impl RateLimitScope {
    /// The fixed label value. Never derive this from a caller's key.
    pub const fn label(self) -> &'static str {
        match self {
            RateLimitScope::Global => "global",
            RateLimitScope::PerFingerprint => "per_fp",
        }
    }
}

/// Records one denied token acquisition.
pub fn record_ratelimit_hit(scope: RateLimitScope) {
    counter!(RATELIMIT_HITS_TOTAL, SCOPE_LABEL => scope.label()).increment(1);
}

/// Records one successfully committed upload.
pub fn record_upload_completed() {
    counter!(UPLOADS_COMPLETED_TOTAL).increment(1);
}

/// Records one upload session destroyed before commit.
pub fn record_upload_aborted() {
    counter!(UPLOADS_ABORTED_TOTAL).increment(1);
}

/// RAII handle for the live-session gauge: increments on construction and decrements exactly once
/// on drop, so every return path out of `VfsSessionHandler::handle_session` — clean EOF, protocol
/// violation, and a future early return — is covered without repeating a decrement at each one.
///
/// Zero-sized, hence `Send`; that matters because the guard is held across the session's await
/// points and the enclosing future must stay `Send` (`spindle_net::signaling::host::SessionHandler`
/// requires it).
#[must_use = "dropping the guard immediately would emit a live-session count of zero"]
pub struct LiveSessionGuard(());

impl LiveSessionGuard {
    /// Marks one session live until the returned guard is dropped.
    pub fn track() -> Self {
        gauge!(SESSIONS_LIVE).increment(1.0);
        LiveSessionGuard(())
    }
}

impl Drop for LiveSessionGuard {
    fn drop(&mut self) {
        gauge!(SESSIONS_LIVE).decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    /// One captured metric series, flattened out of the recorder's snapshot.
    struct Captured {
        name: String,
        labels: Vec<(String, String)>,
        value: DebugValue,
    }

    /// Flattens a recorder snapshot into one entry per series.
    fn flatten(snapshot: metrics_util::debugging::Snapshot) -> Vec<Captured> {
        snapshot
            .into_vec()
            .into_iter()
            .map(|(key, _, _, value)| Captured {
                name: key.key().name().to_string(),
                labels: key
                    .key()
                    .labels()
                    .map(|label| (label.key().to_string(), label.value().to_string()))
                    .collect(),
                value,
            })
            .collect()
    }

    /// Runs `body` against a thread-local recorder and returns one snapshot of every series. No
    /// global recorder or exporter is installed — `with_local_recorder` shadows only this thread.
    fn snapshot_of(body: impl FnOnce()) -> Vec<Captured> {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, body);
        flatten(snapshotter.snapshot())
    }

    fn counter_value(snapshot: &[Captured], name: &str) -> u64 {
        let mut found = snapshot.iter().filter(|metric| metric.name == name);
        let metric = found
            .next()
            .unwrap_or_else(|| panic!("no metric named {name}"));
        assert!(found.next().is_none(), "more than one series for {name}");
        match &metric.value {
            DebugValue::Counter(count) => *count,
            other => panic!("{name} is not a counter: {other:?}"),
        }
    }

    fn labelled_counter_value(snapshot: &[Captured], name: &str, value: &str) -> u64 {
        let matched: Vec<_> = snapshot
            .iter()
            .filter(|metric| {
                metric.name == name
                    && metric
                        .labels
                        .iter()
                        .any(|(key, label_value)| key == SCOPE_LABEL && label_value == value)
            })
            .collect();
        assert_eq!(
            matched.len(),
            1,
            "expected exactly one {name} series for {SCOPE_LABEL}={value}"
        );
        match &matched[0].value {
            DebugValue::Counter(count) => *count,
            other => panic!("{name} is not a counter: {other:?}"),
        }
    }

    fn gauge_value(snapshot: &[Captured], name: &str) -> f64 {
        let metric = snapshot
            .iter()
            .find(|metric| metric.name == name)
            .unwrap_or_else(|| panic!("no metric named {name}"));
        match &metric.value {
            DebugValue::Gauge(gauge) => gauge.into_inner(),
            other => panic!("{name} is not a gauge: {other:?}"),
        }
    }

    /// Both scopes map to their fixed label, and nothing else reaches the label value.
    #[test]
    fn rate_limit_scope_labels_are_the_two_fixed_strings() {
        assert_eq!(RateLimitScope::Global.label(), "global");
        assert_eq!(RateLimitScope::PerFingerprint.label(), "per_fp");
    }

    /// Each scope records under its own series, and repeat denials accumulate.
    #[test]
    fn record_ratelimit_hit_splits_by_scope() {
        let snapshot = snapshot_of(|| {
            record_ratelimit_hit(RateLimitScope::Global);
            record_ratelimit_hit(RateLimitScope::Global);
            record_ratelimit_hit(RateLimitScope::PerFingerprint);
        });
        assert_eq!(
            labelled_counter_value(&snapshot, RATELIMIT_HITS_TOTAL, "global"),
            2
        );
        assert_eq!(
            labelled_counter_value(&snapshot, RATELIMIT_HITS_TOTAL, "per_fp"),
            1
        );
    }

    /// The RAII guard tracks a live count: after two sessions start and one ends, one is left.
    /// The snapshot is taken while the remaining guard is still alive (`DebuggingRecorder::snapshot`
    /// swaps a gauge's storage to zero, so a later snapshot cannot observe the same accumulation).
    #[test]
    fn live_session_guard_increments_and_decrements() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            let ended = LiveSessionGuard::track();
            let live = LiveSessionGuard::track();
            drop(ended);
            let snapshot = flatten(snapshotter.snapshot());
            assert_eq!(gauge_value(&snapshot, SESSIONS_LIVE), 1.0);
            drop(live);
        });
    }

    /// Upload counters emit the documented names.
    #[test]
    fn upload_counters_emit_documented_names() {
        let snapshot = snapshot_of(|| {
            record_upload_completed();
            record_upload_completed();
            record_upload_aborted();
        });
        assert_eq!(counter_value(&snapshot, UPLOADS_COMPLETED_TOTAL), 2);
        assert_eq!(counter_value(&snapshot, UPLOADS_ABORTED_TOTAL), 1);
    }

    /// With no global recorder installed (this test does not install one), every recording helper
    /// must be a no-op rather than a panic. This is the production default until a host binary
    /// installs a recorder (td-539ffa).
    #[test]
    fn recording_without_a_recorder_is_a_noop() {
        record_ratelimit_hit(RateLimitScope::Global);
        record_ratelimit_hit(RateLimitScope::PerFingerprint);
        record_upload_completed();
        record_upload_aborted();
        drop(LiveSessionGuard::track());
    }

    /// Every name is Prometheus-safe snake_case with the host prefix.
    #[test]
    fn metric_names_are_prometheus_safe_snake_case() {
        for name in [
            RATELIMIT_HITS_TOTAL,
            SESSIONS_LIVE,
            UPLOADS_COMPLETED_TOTAL,
            UPLOADS_ABORTED_TOTAL,
        ] {
            assert!(
                name.starts_with("host_"),
                "{name} must use the host_ prefix"
            );
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{name} must be lowercase snake_case (no dots or dashes)"
            );
        }
        assert_eq!(SCOPE_LABEL, "scope");
    }
}
