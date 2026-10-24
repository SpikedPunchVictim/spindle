//! The host's envelope-verification metrics contract (DESIGN.md:707 "Observability contract",
//! td-323db0 slice 2).
//!
//! This module owns the metric **name** and every allowed label value, so the recording site in
//! `signaling/host.rs` cannot invent either ad hoc. It depends only on the `metrics` facade:
//! recording is cheap and is a no-op when no recorder is installed.
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
//! | `host_envelope_failures_total` | counter | `reason` = `bad_signature`/`version`/`skew`/`payload`/`decrypt`/`other` | One per inbound connect offer rejected by §A7 envelope decode/verification in `signaling/host.rs`'s `process_offer`, before authorization succeeds. |
//!
//! # What this deliberately does *not* count
//!
//! Only the connect-offer path records here. Rejections that are *not* envelope verification —
//! a bad `_INBOX_` reply prefix, an authorizer `Deny`/`Drop`, a signed-inbox mismatch — are
//! policy/routing decisions and are not failures of the envelope, so they never reach this
//! counter. Trickled ICE envelopes are verified by `signaling::bridge_incoming_ice`, which is
//! shared by both peer roles; recording there would emit a `host_` series from a client process,
//! so it is intentionally left out until a role-aware recording point exists.
//!
//! # Redaction (td-6c9d95 policy)
//! The only label is a fixed rejection *category* drawn from this crate's own error variants. No
//! label carries a subject, fingerprint, path, subject string, or any other peer-chosen value:
//! label cardinality is itself a leak. The same rule as the helper's module.

use metrics::counter;

use crate::signaling::SignalingError;
use spindle_core::envelope::EnvelopeError;

/// One increment per inbound connect offer rejected before acceptance, split by rejection reason.
pub const ENVELOPE_FAILURES_TOTAL: &str = "host_envelope_failures_total";

/// The label key used to split envelope failures by rejection reason.
pub const REASON_LABEL: &str = "reason";

/// The fixed, low-cardinality reason categories.
///
/// The variant set is deliberately drawn from the existing [`EnvelopeError`]/[`SignalingError`]
/// variants — see [`EnvelopeFailureReason::from_signaling_error`] for the exact mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeFailureReason {
    /// The signature did not verify, or was not a well-formed 64-byte signature.
    BadSignature,
    /// The envelope's `v` or `alg_id` is outside the accepted floor/ceiling.
    Version,
    /// `|ts - now|` exceeded the allowed clock-skew window.
    Skew,
    /// The bytes did not decode as an envelope/signaling payload, or a required field was absent
    /// or malformed (`eph_pk`, a fingerprint field).
    Payload,
    /// The AEAD tag did not verify.
    Decrypt,
    /// Any other §A7 MUST-check (wrong recipient, revoked sender, `sid` binding, replay, kind) —
    /// all of which are still envelope rejections, just not ones worth a dedicated series.
    Other,
}

impl EnvelopeFailureReason {
    /// The fixed label value. Never derive this from request data.
    pub const fn label(self) -> &'static str {
        match self {
            EnvelopeFailureReason::BadSignature => "bad_signature",
            EnvelopeFailureReason::Version => "version",
            EnvelopeFailureReason::Skew => "skew",
            EnvelopeFailureReason::Payload => "payload",
            EnvelopeFailureReason::Decrypt => "decrypt",
            EnvelopeFailureReason::Other => "other",
        }
    }

    /// Classifies a rejection returned by the inbound connect-offer path.
    ///
    /// `Envelope` carries the §A7 receiver checks, so it is split by [`EnvelopeError`] variant;
    /// `EnvelopeDecode`/`Payload`/`Fingerprint`/`MissingEphPk`/`BadEphPk` are all malformed-input
    /// failures and map to [`Self::Payload`]. Anything else is [`Self::Other`] — in practice the
    /// `process_offer` call sites never pass those, but the mapping must stay total.
    pub fn from_signaling_error(error: &SignalingError) -> Self {
        match error {
            SignalingError::Envelope(envelope_error) => match envelope_error {
                EnvelopeError::BadSignature | EnvelopeError::InvalidSignatureEncoding => {
                    EnvelopeFailureReason::BadSignature
                }
                EnvelopeError::VersionTooLow { .. }
                | EnvelopeError::VersionTooHigh { .. }
                | EnvelopeError::AlgIdTooLow { .. } => EnvelopeFailureReason::Version,
                EnvelopeError::ClockSkew => EnvelopeFailureReason::Skew,
                EnvelopeError::DecryptFailed => EnvelopeFailureReason::Decrypt,
                EnvelopeError::WrongRecipient
                | EnvelopeError::SenderRevoked
                | EnvelopeError::SidMismatch
                | EnvelopeError::SidBoundToDifferentSender
                | EnvelopeError::ReplaySeq
                | EnvelopeError::KindMismatch
                | EnvelopeError::InvalidFingerprint(_) => EnvelopeFailureReason::Other,
            },
            SignalingError::EnvelopeDecode(_)
            | SignalingError::Payload(_)
            | SignalingError::Fingerprint(_)
            | SignalingError::MissingEphPk
            | SignalingError::BadEphPk(_) => EnvelopeFailureReason::Payload,
            _ => EnvelopeFailureReason::Other,
        }
    }
}

/// Records one rejected inbound connect offer. Call exactly once per verification failure, with
/// the error the verification step produced.
pub fn record_envelope_failure(reason: EnvelopeFailureReason) {
    counter!(ENVELOPE_FAILURES_TOTAL, REASON_LABEL => reason.label()).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use spindle_proto::artifacts::ProtoError;
    use spindle_proto::signaling::SignalingError as ProtoSignalingError;

    /// One captured metric series, flattened out of the recorder's snapshot.
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

    fn labelled_counter_value(snapshot: &[Captured], name: &str, label: &str, value: &str) -> u64 {
        let matched: Vec<_> = snapshot
            .iter()
            .filter(|metric| {
                metric.name == name
                    && metric
                        .labels
                        .iter()
                        .any(|(key, label_value)| key == label && label_value == value)
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

    /// Every reason maps to a distinct fixed label, and nothing else reaches the label value.
    #[test]
    fn envelope_failure_reason_labels_are_the_six_fixed_strings() {
        assert_eq!(EnvelopeFailureReason::BadSignature.label(), "bad_signature");
        assert_eq!(EnvelopeFailureReason::Version.label(), "version");
        assert_eq!(EnvelopeFailureReason::Skew.label(), "skew");
        assert_eq!(EnvelopeFailureReason::Payload.label(), "payload");
        assert_eq!(EnvelopeFailureReason::Decrypt.label(), "decrypt");
        assert_eq!(EnvelopeFailureReason::Other.label(), "other");
    }

    /// Every `EnvelopeError` variant lands in its documented category, including the "still an
    /// envelope rejection, just not its own series" arm.
    #[test]
    fn classifies_every_envelope_error_variant() {
        let cases: [(EnvelopeError, EnvelopeFailureReason); 13] = [
            (
                EnvelopeError::BadSignature,
                EnvelopeFailureReason::BadSignature,
            ),
            (
                EnvelopeError::InvalidSignatureEncoding,
                EnvelopeFailureReason::BadSignature,
            ),
            (
                EnvelopeError::VersionTooLow {
                    actual: 0,
                    minimum: 1,
                },
                EnvelopeFailureReason::Version,
            ),
            (
                EnvelopeError::VersionTooHigh {
                    actual: 9,
                    maximum: 1,
                },
                EnvelopeFailureReason::Version,
            ),
            (
                EnvelopeError::AlgIdTooLow {
                    actual: 0,
                    minimum: 1,
                },
                EnvelopeFailureReason::Version,
            ),
            (EnvelopeError::ClockSkew, EnvelopeFailureReason::Skew),
            (EnvelopeError::DecryptFailed, EnvelopeFailureReason::Decrypt),
            (EnvelopeError::WrongRecipient, EnvelopeFailureReason::Other),
            (EnvelopeError::SenderRevoked, EnvelopeFailureReason::Other),
            (EnvelopeError::SidMismatch, EnvelopeFailureReason::Other),
            (
                EnvelopeError::SidBoundToDifferentSender,
                EnvelopeFailureReason::Other,
            ),
            (EnvelopeError::ReplaySeq, EnvelopeFailureReason::Other),
            (EnvelopeError::KindMismatch, EnvelopeFailureReason::Other),
        ];

        for (envelope_error, expected) in cases {
            assert_eq!(
                EnvelopeFailureReason::from_signaling_error(&SignalingError::Envelope(
                    envelope_error
                )),
                expected
            );
        }
        // The 14th variant is `InvalidFingerprint(..)`, which needs an inner error; it is
        // explicitly `Other` like the other §A7 MUST-check rejections.
        assert_eq!(
            EnvelopeFailureReason::from_signaling_error(&SignalingError::Envelope(
                EnvelopeError::InvalidFingerprint(
                    spindle_core::fingerprint::FingerprintError::WrongLength(3)
                )
            )),
            EnvelopeFailureReason::Other
        );
    }

    /// Malformed-input failures — envelope decode, signaling payload decode, a malformed
    /// fingerprint field, a missing/undersized `eph_pk` — all share the `payload` series.
    #[test]
    fn malformed_input_failures_classify_as_payload() {
        let cases = [
            SignalingError::EnvelopeDecode(ProtoError::UnknownField("secret-key".into())),
            SignalingError::Payload(ProtoSignalingError::TooLong {
                field: "ufrag",
                max: 8,
                actual: 9,
            }),
            SignalingError::Fingerprint(spindle_core::fingerprint::FingerprintError::WrongLength(
                17,
            )),
            SignalingError::MissingEphPk,
            SignalingError::BadEphPk(17),
        ];
        for error in cases {
            assert_eq!(
                EnvelopeFailureReason::from_signaling_error(&error),
                EnvelopeFailureReason::Payload
            );
        }
    }

    /// With no global recorder installed (this test does not install one), every recording helper
    /// must be a no-op rather than a panic. This is the production default until a host binary
    /// installs a recorder (td-539ffa), so it also pins "unset means metrics disabled".
    #[test]
    fn recording_without_a_recorder_is_a_noop() {
        for reason in [
            EnvelopeFailureReason::BadSignature,
            EnvelopeFailureReason::Version,
            EnvelopeFailureReason::Skew,
            EnvelopeFailureReason::Payload,
            EnvelopeFailureReason::Decrypt,
            EnvelopeFailureReason::Other,
        ] {
            record_envelope_failure(reason);
        }
    }

    /// The recording helper emits the documented name, label key, and value.
    #[test]
    fn record_envelope_failure_emits_one_labelled_counter() {
        let snapshot = snapshot_of(|| {
            record_envelope_failure(EnvelopeFailureReason::BadSignature);
            record_envelope_failure(EnvelopeFailureReason::BadSignature);
            record_envelope_failure(EnvelopeFailureReason::Skew);
        });
        assert_eq!(
            labelled_counter_value(
                &snapshot,
                ENVELOPE_FAILURES_TOTAL,
                REASON_LABEL,
                "bad_signature"
            ),
            2
        );
        assert_eq!(
            labelled_counter_value(&snapshot, ENVELOPE_FAILURES_TOTAL, REASON_LABEL, "skew"),
            1
        );
    }

    /// The name is Prometheus-safe snake_case with the host prefix.
    #[test]
    fn metric_name_is_prometheus_safe_snake_case() {
        assert!(ENVELOPE_FAILURES_TOTAL.starts_with("host_"));
        assert!(ENVELOPE_FAILURES_TOTAL
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'));
        assert_eq!(REASON_LABEL, "reason");
    }
}
