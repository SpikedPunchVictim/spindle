//! The audit chain's metrics contract (DESIGN.md:707 "Observability contract", td-323db0 slice 2).
//!
//! This module owns the metric **names**, so `audit/mod.rs`'s recording sites cannot invent them
//! ad hoc. It depends only on the `metrics` facade: recording is cheap and is a no-op when no
//! recorder is installed.
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
//! | `host_audit_head_seq` | gauge | none | The `seq` of the most recently committed audit row. |
//! | `host_audit_append_failures_total` | counter | none | One per `Audit::append` call that did not commit a row. |
//!
//! # Redaction (td-6c9d95 policy)
//! Neither series has a label, so nothing here can carry a path, action, subject, or fingerprint.
//! The audit *entry* fields are deliberately not broken out by label: `action`/`outcome` are
//! bounded today but are still per-row detail, and the DESIGN.md:707 contract asks for the chain
//! head, not a per-operation audit mirror.

use metrics::{counter, gauge};

/// The `seq` of the most recently committed audit row.
pub const AUDIT_HEAD_SEQ: &str = "host_audit_head_seq";

/// One increment per `Audit::append` that failed to commit.
pub const AUDIT_APPEND_FAILURES_TOTAL: &str = "host_audit_append_failures_total";

/// Sets the audit head gauge after a row commits. `seq` is the row's own `audit_log.seq`, so it
/// grows monotonically for the life of the store (it is SQLite's `rowid`).
pub fn record_audit_head_seq(seq: u64) {
    gauge!(AUDIT_HEAD_SEQ).set(seq as f64);
}

/// Records one failed audit append — every error return in [`crate::audit::Audit::append`],
/// including a poisoned connection, a failed `BEGIN`/`COMMIT`, and any failure inside the append
/// itself.
pub fn record_audit_append_failure() {
    counter!(AUDIT_APPEND_FAILURES_TOTAL).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    /// One captured metric series, flattened out of the recorder's snapshot.
    struct Captured {
        name: String,
        value: DebugValue,
    }

    /// Runs `body` against a thread-local recorder and returns one snapshot of every series. No
    /// global recorder or exporter is installed — `with_local_recorder` shadows only this thread.
    fn snapshot_of(body: impl FnOnce()) -> Vec<Captured> {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, body);
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(key, _, _, value)| Captured {
                name: key.key().name().to_string(),
                value,
            })
            .collect()
    }

    fn counter_value(snapshot: &[Captured], name: &str) -> u64 {
        let metric = snapshot
            .iter()
            .find(|metric| metric.name == name)
            .unwrap_or_else(|| panic!("no metric named {name}"));
        match &metric.value {
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

    /// The head gauge is set (not incremented), so the latest committed sequence wins.
    #[test]
    fn audit_head_gauge_reflects_the_latest_sequence() {
        let snapshot = snapshot_of(|| {
            record_audit_head_seq(1);
            record_audit_head_seq(7);
        });
        assert_eq!(gauge_value(&snapshot, AUDIT_HEAD_SEQ), 7.0);
    }

    /// Append failures accumulate.
    #[test]
    fn append_failure_counter_accumulates() {
        let snapshot = snapshot_of(|| {
            record_audit_append_failure();
            record_audit_append_failure();
        });
        assert_eq!(counter_value(&snapshot, AUDIT_APPEND_FAILURES_TOTAL), 2);
    }

    /// With no global recorder installed (this test does not install one), both helpers must be a
    /// no-op rather than a panic. This is the production default until a host binary installs a
    /// recorder (td-539ffa).
    #[test]
    fn recording_without_a_recorder_is_a_noop() {
        record_audit_head_seq(3);
        record_audit_append_failure();
    }

    /// Both names are Prometheus-safe snake_case with the host prefix.
    #[test]
    fn metric_names_are_prometheus_safe_snake_case() {
        for name in [AUDIT_HEAD_SEQ, AUDIT_APPEND_FAILURES_TOTAL] {
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
    }
}
