//! The helper's metrics contract (DESIGN.md:707 "Observability contract", td-323db0).
//!
//! This module owns every metric **name** and every allowed label value, so recording sites in
//! `authz.rs`, `turn.rs`, and `src/bin/helper.rs` cannot invent either ad hoc. It depends only on
//! the `metrics` facade: recording is cheap and is a no-op when no recorder is installed.
//!
//! # Layering rule (owner decision 2026-10-24)
//! The facade may appear in libraries; an **exporter may not**. Nothing in this crate's library
//! modules installs a global recorder, starts a listener, or depends on
//! `metrics-exporter-prometheus`. Only `src/bin/helper.rs` installs
//! [`metrics_exporter_prometheus::PrometheusBuilder`], and only when `METRICS_ADDR` is set.
//!
//! # Naming scheme
//! Metric names are `helper_<area>_<measure>_<unit>` in `snake_case`, not dotted: dots are not
//! valid in Prometheus metric names, and the exporter writes names through unchanged. Units are
//! part of the name for histograms (`_seconds`); counters end in `_total`, per Prometheus
//! convention.
//!
//! | Name | Type | Labels | Meaning |
//! |------|------|--------|---------|
//! | `helper_callout_duration_seconds` | histogram | none | Wall time spent inside `handle_one`. |
//! | `helper_callout_decisions_total` | counter | `outcome` = `allow`/`deny`/`refused`/`error` | One per callout request. |
//! | `helper_revocation_propagation_seconds` | histogram | none | `now - record.ts`, clamped at 0, for an accepted revocation (registry or self-revocation). |
//! | `helper_presence_hosts` | gauge | none | Distinct `host_fp`s in the presence map (online and offline). |
//! | `helper_replica_divergence_rows` | gauge | none | Startup CONNZ rows this process could not reconcile locally — the only divergence signal available without a cross-replica view. |
//! | `helper_nonce_burn_conflicts_total` | counter | none | Admission-token nonce already burned (`AdmissionTokenAlreadyUsed`). |
//! | `helper_turn_issuance_total` | counter | `outcome` = `success`/`quota_exceeded` | `record_turn_issuance` results; `quota_exceeded` is the `TurnQuotaExceeded` signal. |
//!
//! Histograms render through `metrics-exporter-prometheus`'s default quantile set, which includes
//! 0.99 — the p99 callout SLO (p99 < 250 ms) and the revoke cut-off SLO are therefore measurable
//! from these two series without a custom bucket configuration.
//!
//! # Redaction (td-6c9d95 policy)
//! No label ever carries a path, group name, member name, subject, endpoint, or fingerprint —
//! fixed low-cardinality literals only. Per-identity detail belongs in a log line, never a metric
//! label: label cardinality is itself a leak. There are deliberately **no** per-identity labels
//! anywhere in this module, so nothing here needs a redacted variant.

use std::time::Duration;

use metrics::{counter, gauge, histogram};

/// Wall time spent handling one callout request.
pub const CALLOUT_DURATION_SECONDS: &str = "helper_callout_duration_seconds";

/// One increment per callout request, labelled by the decision reached.
pub const CALLOUT_DECISIONS_TOTAL: &str = "helper_callout_decisions_total";

/// Time between a revocation record's own `ts` and this helper accepting it.
pub const REVOCATION_PROPAGATION_SECONDS: &str = "helper_revocation_propagation_seconds";

/// Distinct hosts currently tracked by the presence map.
pub const PRESENCE_HOSTS: &str = "helper_presence_hosts";

/// CONNZ rows observed at startup that could not be reconciled into local presence state.
pub const REPLICA_DIVERGENCE_ROWS: &str = "helper_replica_divergence_rows";

/// Admission-token nonce burn conflicts.
pub const NONCE_BURN_CONFLICTS_TOTAL: &str = "helper_nonce_burn_conflicts_total";

/// TURN credential issuance outcomes.
pub const TURN_ISSUANCE_TOTAL: &str = "helper_turn_issuance_total";

/// The label key used by counters that split by outcome. The only label key this crate emits.
pub const OUTCOME_LABEL: &str = "outcome";

/// The callout decision `handle_one` reached. `label` is the only spelling that reaches a metric.
///
/// - `Allow` — a device or host was authorized and an `authorization_response` with a User JWT
///   is returned.
/// - `Deny` — `authz::decide_device_connect`/`decide_host_connect` returned
///   `AuthzDecision::Refused` (a policy decision: revoked subject, bad signature, burned nonce,
///   etc.). The wire reply is still the uniform refusal.
/// - `Refused` — the request never reached a policy decision: no/malformed auth token, bad
///   embedded key, or an unparseable presented nkey. Also the uniform refusal path.
/// - `Error` — `handle_one` returned `HandleError` (malformed request claims or an internal
///   JWT/build failure), or the decision it reached could not be encoded into a response at all;
///   in the latter case the caller falls back to `encode_refusal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalloutOutcome {
    Allow,
    Deny,
    Refused,
    Error,
}

impl CalloutOutcome {
    /// The fixed low-cardinality label value. Never derive this from request data.
    pub const fn label(self) -> &'static str {
        match self {
            CalloutOutcome::Allow => "allow",
            CalloutOutcome::Deny => "deny",
            CalloutOutcome::Refused => "refused",
            CalloutOutcome::Error => "error",
        }
    }
}

/// TURN issuance outcome — the two arms of `HelperView::record_turn_issuance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnIssuanceOutcome {
    Success,
    /// The per-root monthly quota was already exhausted (`Err` from `record_turn_issuance`).
    QuotaExceeded,
}

impl TurnIssuanceOutcome {
    const fn label(self) -> &'static str {
        match self {
            TurnIssuanceOutcome::Success => "success",
            TurnIssuanceOutcome::QuotaExceeded => "quota_exceeded",
        }
    }
}

/// Records one callout's latency and decision. Call once per request, after `handle_one`.
pub fn record_callout(outcome: CalloutOutcome, elapsed: Duration) {
    counter!(CALLOUT_DECISIONS_TOTAL, OUTCOME_LABEL => outcome.label()).increment(1);
    histogram!(CALLOUT_DURATION_SECONDS).record(elapsed.as_secs_f64());
}

/// Records propagation delay for an accepted revocation record. A record timestamp in the future
/// (clock skew between issuer and helper) clamps to 0 rather than emitting a negative duration;
/// a malformed timestamp is not a metric concern and is handled by the record's decoder.
pub fn record_revocation_propagation(now: u64, record_ts: u64) {
    let delay_secs = now.saturating_sub(record_ts);
    histogram!(REVOCATION_PROPAGATION_SECONDS).record(delay_secs as f64);
}

/// Sets the presence-map size gauge. `hosts` is the number of distinct `host_fp`s the map tracks,
/// including hosts currently offline.
pub fn record_presence_hosts(hosts: usize) {
    gauge!(PRESENCE_HOSTS).set(hosts as f64);
}

/// Sets the startup CONNZ divergence gauge. See [`REPLICA_DIVERGENCE_ROWS`] and
/// `src/bin/helper.rs`'s `seed_maps` for why this is a startup-only signal today.
pub fn record_replica_divergence_rows(rows: usize) {
    gauge!(REPLICA_DIVERGENCE_ROWS).set(rows as f64);
}

/// Records one admission-token nonce burn conflict.
pub fn record_nonce_burn_conflict() {
    counter!(NONCE_BURN_CONFLICTS_TOTAL).increment(1);
}

/// Records one TURN issuance result.
pub fn record_turn_issuance(outcome: TurnIssuanceOutcome) {
    counter!(TURN_ISSUANCE_TOTAL, OUTCOME_LABEL => outcome.label()).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    /// One captured metric series, flattened out of the recorder's snapshot so tests can query it
    /// more than once (a second `Snapshotter::snapshot` swaps counters/gauges to zero and clears
    /// histograms).
    struct Captured {
        name: String,
        labels: Vec<(String, String)>,
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
                labels: key
                    .key()
                    .labels()
                    .map(|label| (label.key().to_string(), label.value().to_string()))
                    .collect(),
                value,
            })
            .collect()
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

    fn labelled_counter_value(snapshot: &[Captured], name: &str, label: &str, value: &str) -> u64 {
        let matched: Vec<_> = snapshot
            .iter()
            .filter(|metric| {
                metric.name == name
                    && metric
                        .labels
                        .iter()
                        .any(|(key, label_value)| key == OUTCOME_LABEL && label_value == value)
            })
            .collect();
        assert_eq!(
            matched.len(),
            1,
            "expected exactly one {name} series for {label}={value}"
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

    fn histogram_values(snapshot: &[Captured], name: &str) -> Vec<f64> {
        let metric = snapshot
            .iter()
            .find(|metric| metric.name == name)
            .unwrap_or_else(|| panic!("no metric named {name}"));
        match &metric.value {
            DebugValue::Histogram(values) => {
                values.iter().map(|value| value.into_inner()).collect()
            }
            other => panic!("{name} is not a histogram: {other:?}"),
        }
    }

    /// Every outcome maps to a distinct fixed label, and nothing else reaches the label value.
    #[test]
    fn callout_outcome_labels_are_the_four_fixed_strings() {
        assert_eq!(CalloutOutcome::Allow.label(), "allow");
        assert_eq!(CalloutOutcome::Deny.label(), "deny");
        assert_eq!(CalloutOutcome::Refused.label(), "refused");
        assert_eq!(CalloutOutcome::Error.label(), "error");
    }

    /// With no global recorder installed (this test does not install one), every recording helper
    /// must be a no-op rather than a panic. This is the production default when `METRICS_ADDR` is
    /// unset, so it also pins the "unset means metrics disabled" contract.
    #[test]
    fn recording_without_a_recorder_is_a_noop() {
        record_callout(CalloutOutcome::Allow, Duration::from_secs(1));
        record_revocation_propagation(10, 20);
        record_presence_hosts(7);
        record_replica_divergence_rows(1);
        record_nonce_burn_conflict();
        record_turn_issuance(TurnIssuanceOutcome::Success);
    }

    /// The recording helper must emit the documented name, label set, and both metric types for
    /// each outcome. Also proves the histogram records the elapsed seconds.
    #[test]
    fn record_callout_emits_one_labelled_counter_and_one_histogram_sample() {
        for (outcome, label) in [
            (CalloutOutcome::Allow, "allow"),
            (CalloutOutcome::Deny, "deny"),
            (CalloutOutcome::Refused, "refused"),
            (CalloutOutcome::Error, "error"),
        ] {
            let snapshot = snapshot_of(|| {
                record_callout(outcome, Duration::from_millis(250));
            });
            assert_eq!(
                labelled_counter_value(&snapshot, CALLOUT_DECISIONS_TOTAL, "outcome", label),
                1
            );
            assert_eq!(
                histogram_values(&snapshot, CALLOUT_DURATION_SECONDS),
                vec![0.25]
            );
        }
    }

    /// Negative propagation (record timestamp after `now`) clamps to 0; a normal delay is exact.
    #[test]
    fn record_revocation_propagation_clamps_negative_delay_to_zero() {
        let snapshot = snapshot_of(|| {
            record_revocation_propagation(100, 100);
            record_revocation_propagation(110, 100);
            record_revocation_propagation(100, 150);
        });
        assert_eq!(
            histogram_values(&snapshot, REVOCATION_PROPAGATION_SECONDS),
            vec![0.0, 10.0, 0.0]
        );
    }

    /// Both TURN outcomes emit one labelled counter under the documented name.
    #[test]
    fn record_turn_issuance_emits_success_and_quota_exceeded_series() {
        let snapshot = snapshot_of(|| {
            record_turn_issuance(TurnIssuanceOutcome::Success);
            record_turn_issuance(TurnIssuanceOutcome::QuotaExceeded);
        });
        assert_eq!(
            labelled_counter_value(&snapshot, TURN_ISSUANCE_TOTAL, "outcome", "success"),
            1
        );
        assert_eq!(
            labelled_counter_value(&snapshot, TURN_ISSUANCE_TOTAL, "outcome", "quota_exceeded"),
            1
        );
    }

    /// Gauges and the unlabelled conflict counter emit the documented names/values.
    #[test]
    fn gauges_and_nonce_conflict_counter_emit_documented_names() {
        let snapshot = snapshot_of(|| {
            record_presence_hosts(3);
            record_replica_divergence_rows(2);
            record_nonce_burn_conflict();
        });
        assert_eq!(gauge_value(&snapshot, PRESENCE_HOSTS), 3.0);
        assert_eq!(gauge_value(&snapshot, REPLICA_DIVERGENCE_ROWS), 2.0);
        assert_eq!(counter_value(&snapshot, NONCE_BURN_CONFLICTS_TOTAL), 1);
    }

    /// Names must be Prometheus-safe and carry no separator/label-like spelling. This is a cheap
    /// guard against someone renaming a constant to the ticket's illustrative dotted spelling.
    #[test]
    fn metric_names_are_prometheus_safe_snake_case() {
        for name in [
            CALLOUT_DURATION_SECONDS,
            CALLOUT_DECISIONS_TOTAL,
            REVOCATION_PROPAGATION_SECONDS,
            PRESENCE_HOSTS,
            REPLICA_DIVERGENCE_ROWS,
            NONCE_BURN_CONFLICTS_TOTAL,
            TURN_ISSUANCE_TOTAL,
        ] {
            assert!(
                name.starts_with("helper_"),
                "{name} must use the helper_ prefix"
            );
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{name} must be lowercase snake_case (no dots or dashes)"
            );
        }
        assert_eq!(OUTCOME_LABEL, "outcome");
    }
}
