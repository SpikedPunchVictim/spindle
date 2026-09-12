//! DESIGN.md §A10.42 "Cold-clock diagnostics" leg (1) — the **always-on local bound check**
//! (td-7e3556).
//!
//! A client (or host) refused for clock skew today cannot tell that refusal from revocation or
//! from a stolen bundle: all three surface as the same uniform message (§A7 "Clock skew"). This
//! module closes that gap without putting a single new byte on the wire. It compares the caller's
//! notion of local time against bounds the caller has **already verified** — every
//! [`Capability`](spindle_proto::artifacts::Capability) embeds its `op_cert`, and
//! [`HostOpKeyCert`](spindle_proto::artifacts::HostOpKeyCert) carries `ts`, a *signed lower bound*
//! on true time, since a certificate cannot have been issued before it was signed.
//!
//! # This module reads no clock
//!
//! Every notion of "now" arrives as a caller-supplied `local_now: u64` (Unix seconds), exactly
//! like the rest of `spindle-core`. `tests/clock_source_guard.rs` scans this file — along with the
//! whole `src` tree — for ambient clock APIs and fails if one appears.
//!
//! # Resolution, stated honestly
//!
//! Per §A10.42 this check is only as tight as the age of the credentials on hand: it catches a
//! device with **no working notion of real time**, not one merely off by three minutes — which is
//! the case that actually trips the ±2 min `SessionAttestation` window. It costs nothing (no
//! network round trip, and it trusts nothing it did not already verify), which is why it runs
//! always rather than only when a connect has already failed.
//!
//! Leg (2) of §A10.42 — the OPTIONAL operator-configured HTTPS `Date` time source — is not
//! implemented here. [`ClockOffset`] is the type it will report through when it lands.

use spindle_proto::artifacts::{Capability, HostOpKeyCert, ProtoError};
use thiserror::Error;

/// A **diagnostic-only** signed offset in seconds.
///
/// The entire point of this type is that it CANNOT be turned into a validity timestamp. It has
/// exactly one accessor — [`ClockOffset::diagnostic_seconds`] — named so that feeding it into a
/// signing time, an `exp` check, or a revocation check reads as obviously wrong at the call site.
///
/// **No conversions exist, deliberately**: no `From`/`Into`, no `Deref`, no `Add`/`Sub`, no
/// `as_timestamp`/`as_now`/`apply_to`. §A10.42: a time source is not an authenticated channel.
/// Folding one into a validity check would let anyone who shifts a client's perceived time turn a
/// safe refusal (wrong or compromised clock) into an **acceptance** of an expired or revoked
/// artifact. A refusal is a safe failure; an acceptance is not.
///
/// **This is a type-level speed bump, not a proof.** A caller can still call
/// `diagnostic_seconds()` and do arithmetic on the resulting `i64`; nothing in the type system
/// stops that. That residual hole is exactly why `tests/clock_source_guard.rs` *also* scans the
/// artifact validity paths for the literal symbol `ClockOffset` (and its siblings). The two
/// defences are layered on purpose: neither is sufficient alone.
///
/// # Sign convention
///
/// A [`ClockDiagnosis::ProvablyBehind`] offset is **positive seconds behind** — the number of
/// seconds the local clock must advance to reach the signed lower bound. See
/// [`diagnose_clock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockOffset(i64);

impl ClockOffset {
    /// The offset in seconds, for **display and logging only**.
    ///
    /// §A10.42: this value MUST NOT be added to, subtracted from, or otherwise folded into any
    /// value used as `now` in an artifact validity check. It exists so a client can say "your
    /// clock is 41 days behind" instead of repeating the uniform refusal message.
    pub fn diagnostic_seconds(&self) -> i64 {
        self.0
    }
}

/// What the local bound check could prove about the caller's clock (DESIGN.md §A10.42 leg (1)).
///
/// This is a *diagnosis*, never a time value — see [`ClockOffset`] for why that distinction is
/// load-bearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockDiagnosis {
    /// Local time is earlier than a timestamp that was already signed, so the local clock is
    /// **provably** behind true time by at least `behind_by` seconds. A certificate cannot have
    /// been issued before it was signed, so `bound_ts` is a hard lower bound on true time and no
    /// honest clock can precede it.
    ///
    /// `behind_by` is positive seconds-behind; `bound_ts` is the `max(op_cert.ts)` that produced
    /// it, reported so a caller can show its basis rather than an unexplained number.
    ProvablyBehind {
        behind_by: ClockOffset,
        bound_ts: u64,
    },
    /// Local time is past `exp` for **every** capability held. §A10.42 requires this be reported
    /// honestly as ambiguous: the clock may be ahead, **or** every membership genuinely expired.
    ///
    /// **The "clock is ahead" direction is NOT provable and must not be claimed.**
    /// `spindle_proto::artifacts::Capability`'s fields are
    /// `{v, host_fp, host_root_pk, op_cert, kind, subject, cap_epoch, exp, nonce, sig}` — `exp`,
    /// never `ts`. Without an issue time there is nothing to compare local time *against* in that
    /// direction, so this variant states the two possibilities and resolves neither.
    ///
    /// `latest_cap_exp` is the largest `exp` held — the point local time is past.
    Ambiguous { latest_cap_exp: u64 },
    /// Nothing was proven. Either there was no signed lower bound to check against, or local time
    /// sits at or after the bound with at least one capability still unexpired.
    ///
    /// This is explicitly **not** a clean bill of health for the clock: §A10.42's check is only as
    /// tight as the age of the credentials on hand.
    NoEvidenceOfSkew,
}

/// Errors from [`diagnose_clock_from_capabilities`] (DESIGN.md §A10.42, td-7e3556).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClockDiagnosticError {
    /// A capability's embedded `op_cert` bytes did not decode as a
    /// [`HostOpKeyCert`](spindle_proto::artifacts::HostOpKeyCert). The index is reported because
    /// a bundle holds many capabilities and "one of them is malformed" is not an actionable
    /// message; this mirrors `ArtifactError::MalformedOpCert`, which fires on the same bytes in
    /// the verification path.
    #[error("capability at index {index} has an op_cert that does not decode: {source}")]
    MalformedOpCert { index: usize, source: ProtoError },
}

/// The core local bound check, pure over plain integers (DESIGN.md §A10.42 leg (1)).
///
/// `local_now` is the caller's Unix-seconds notion of now — this crate never reads a clock.
/// `op_cert_timestamps` are `HostOpKeyCert.ts` values the caller has **already verified**;
/// `capability_exps` are `Capability.exp` values from the same bundle.
///
/// Decision order, which is itself normative:
///
/// 1. **Provably-behind runs FIRST**, because it is the only direction that can be *proven*. If
///    both conditions hold at once, reporting the ambiguous one would throw away a fact in favour
///    of a maybe.
/// 2. Ambiguous second, reported honestly as ambiguous (see [`ClockDiagnosis::Ambiguous`]).
/// 3. Otherwise nothing was proven.
///
/// # Empty input proves nothing
///
/// An empty `op_cert_timestamps` slice means there is **no signed lower bound at all**, so the
/// provably-behind leg is skipped entirely and, with no expired capabilities either, the result is
/// [`ClockDiagnosis::NoEvidenceOfSkew`]. That is the absence of evidence, not evidence of a good
/// clock — an attacker who could strip the bundle would otherwise be handed a clean verdict for
/// free. Skipping that leg does **not** suppress the ambiguous case: per §A10.42 the ambiguous
/// case rests on `exp` alone, so expired capabilities with no op-cert bound on hand still report
/// [`ClockDiagnosis::Ambiguous`].
///
/// # Arithmetic
///
/// `bound` and `local_now` are both `u64`, and `bound - local_now` can exceed `i64::MAX` for an
/// absurd (corrupt or hostile) `ts`. The difference is computed in `u64` first — it is known
/// non-negative inside the provably-behind branch — and converted with `i64::try_from`,
/// **saturating at `i64::MAX`** rather than wrapping. Saturating rather than erroring is chosen
/// deliberately: the caller has already learned the one thing that matters ("your clock is
/// behind"), and an absurd magnitude is still absurd at `i64::MAX`, so turning a diagnostic into
/// a `Result` here would buy nothing. It must never silently wrap, because a wrapped value would
/// print as a *negative* offset and read as "your clock is ahead" — the exact direction §A10.42
/// says cannot be proven.
pub fn diagnose_clock(
    local_now: u64,
    op_cert_timestamps: &[u64],
    capability_exps: &[u64],
) -> ClockDiagnosis {
    // Checked first: this is the direction A10.42 can prove, so it wins over the ambiguous case.
    // An empty slice is no signed lower bound at all, so this leg is skipped rather than faked —
    // but the ambiguous leg below still runs, since it rests on `exp` alone.
    if let Some(&bound) = op_cert_timestamps.iter().max() {
        if local_now < bound {
            return ClockDiagnosis::ProvablyBehind {
                behind_by: ClockOffset(seconds_behind(bound, local_now)),
                bound_ts: bound,
            };
        }
    }

    // `all`, not `any`: one still-valid capability means expiry explains nothing about the clock.
    if !capability_exps.is_empty() && capability_exps.iter().all(|&exp| local_now > exp) {
        if let Some(&latest_cap_exp) = capability_exps.iter().max() {
            return ClockDiagnosis::Ambiguous { latest_cap_exp };
        }
    }

    ClockDiagnosis::NoEvidenceOfSkew
}

/// Runs [`diagnose_clock`] over a held bundle of verified artifacts (DESIGN.md §A10.42 leg (1),
/// td-7e3556).
///
/// Collects the `ts` of every capability's embedded `op_cert` (decoded from
/// `Capability.op_cert`'s opaque canonical bytes), plus the `ts` of every certificate in
/// `extra_op_certs`, plus every capability's `exp`, and delegates the decision.
///
/// `extra_op_certs` exists for the **host** path. td-7e3556 records the scope widening from
/// td-e8b79f: td-583db5 gave the host the same cold-bootstrap exposure the device has, and a host
/// holds its own [`HostOpKeyCert`] while it may hold no capabilities at all. Passing that
/// certificate here gives the host exactly the same check the device gets, through the same code.
///
/// # This function verifies NOTHING
///
/// It does **not** check a single signature. It reads `ts` out of bytes the caller must have
/// ALREADY verified — via [`crate::artifacts::verify_capability`] and
/// [`crate::artifacts::verify_host_op_key_cert`]. If a caller passes unverified input, the
/// "signed lower bound" property does not hold and the resulting diagnosis is
/// attacker-controlled.
///
/// The blast radius of a false diagnosis is bounded on purpose: this is a *diagnostic*, so the
/// worst outcome is a **wrong message**, never an acceptance of an expired or revoked artifact.
/// That is precisely why the return type is a [`ClockDiagnosis`] and not a time value — there is
/// no path from this output into any validity check (see [`ClockOffset`]).
pub fn diagnose_clock_from_capabilities(
    local_now: u64,
    capabilities: &[Capability],
    extra_op_certs: &[HostOpKeyCert],
) -> Result<ClockDiagnosis, ClockDiagnosticError> {
    let mut op_cert_timestamps = Vec::with_capacity(capabilities.len() + extra_op_certs.len());
    let mut capability_exps = Vec::with_capacity(capabilities.len());

    for (index, cap) in capabilities.iter().enumerate() {
        let op_cert = HostOpKeyCert::from_canonical_bytes(&cap.op_cert)
            .map_err(|source| ClockDiagnosticError::MalformedOpCert { index, source })?;
        op_cert_timestamps.push(op_cert.ts);
        capability_exps.push(cap.exp);
    }
    for cert in extra_op_certs {
        op_cert_timestamps.push(cert.ts);
    }

    Ok(diagnose_clock(
        local_now,
        &op_cert_timestamps,
        &capability_exps,
    ))
}

/// `bound - local_now` as a **positive** seconds-behind `i64`, saturating at `i64::MAX`.
///
/// Both inputs are `u64`; the subtraction happens in `u64` (where the caller has established
/// `bound >= local_now`) and the narrowing is explicit. See [`diagnose_clock`]'s "Arithmetic"
/// section for why wrapping here would be a correctness bug and not merely an odd number.
fn seconds_behind(bound: u64, local_now: u64) -> i64 {
    i64::try_from(bound.saturating_sub(local_now)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{issue_capability, issue_host_op_key_cert};
    use crate::fingerprint::{Fingerprint, FINGERPRINT_LEN};
    use crate::identity::RootKey;
    use ed25519_dalek::SigningKey;
    use spindle_proto::artifacts::CapKind;

    /// Mints a real capability with a real embedded `op_cert` whose `ts` is `op_cert_ts`, the
    /// same way `artifacts::capability`'s own tests build one — so the extraction path under test
    /// reads production bytes, not a hand-assembled struct.
    fn real_capability(op_cert_ts: u64, cap_exp: u64) -> Capability {
        let root = RootKey::from_seed([0x21; 32]);
        let op_signer = SigningKey::from_bytes(&[0x22; 32]);
        let op_cert =
            issue_host_op_key_cert(&root, &op_signer.verifying_key(), op_cert_ts, u64::MAX);
        issue_capability(
            &root.public_key(),
            &op_cert,
            &op_signer,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            1,
            cap_exp,
            vec![0xAA; FINGERPRINT_LEN],
        )
    }

    #[test]
    fn local_time_before_the_signed_bound_is_provably_behind() {
        let diagnosis = diagnose_clock(1_000, &[5_000], &[]);
        match diagnosis {
            ClockDiagnosis::ProvablyBehind {
                behind_by,
                bound_ts,
            } => {
                assert_eq!(behind_by.diagnostic_seconds(), 4_000);
                assert_eq!(bound_ts, 5_000);
            }
            other => panic!("expected ProvablyBehind, got {other:?}"),
        }
    }

    /// The bound is `max(op_cert.ts)` per A10.42. The max sits in the MIDDLE position, so a `[0]`
    /// or a `.min()` implementation picks a different value and this test fails.
    #[test]
    fn the_bound_is_the_max_op_cert_ts_not_the_first_or_the_min() {
        let diagnosis = diagnose_clock(1_000, &[2_000, 9_000, 3_000], &[]);
        match diagnosis {
            ClockDiagnosis::ProvablyBehind {
                behind_by,
                bound_ts,
            } => {
                assert_eq!(bound_ts, 9_000);
                assert_eq!(behind_by.diagnostic_seconds(), 8_000);
            }
            other => panic!("expected ProvablyBehind against the max ts, got {other:?}"),
        }
    }

    /// Boundary: "earlier than" is strict. A clock exactly at the bound is consistent with a
    /// certificate signed at that instant, so nothing is proven.
    #[test]
    fn local_time_exactly_at_the_bound_is_not_provably_behind() {
        assert_eq!(
            diagnose_clock(5_000, &[5_000], &[]),
            ClockDiagnosis::NoEvidenceOfSkew
        );
    }

    #[test]
    fn local_time_one_second_past_the_bound_is_not_provably_behind() {
        assert_eq!(
            diagnose_clock(5_001, &[5_000], &[]),
            ClockDiagnosis::NoEvidenceOfSkew
        );
    }

    #[test]
    fn every_capability_expired_is_ambiguous_with_the_latest_exp() {
        assert_eq!(
            diagnose_clock(9_000, &[1_000], &[4_000, 8_000, 6_000]),
            ClockDiagnosis::Ambiguous {
                latest_cap_exp: 8_000
            }
        );
    }

    /// Order is normative (A10.42): the provable direction wins over the ambiguous one when both
    /// conditions hold at once.
    #[test]
    fn provably_behind_wins_over_ambiguous_when_both_hold() {
        let diagnosis = diagnose_clock(500, &[5_000], &[100, 200]);
        match diagnosis {
            ClockDiagnosis::ProvablyBehind {
                behind_by,
                bound_ts,
            } => {
                assert_eq!(behind_by.diagnostic_seconds(), 4_500);
                assert_eq!(bound_ts, 5_000);
            }
            other => panic!("expected ProvablyBehind to win over Ambiguous, got {other:?}"),
        }
    }

    /// `all`, not `any`: one unexpired capability means expiry explains nothing about the clock.
    #[test]
    fn one_still_valid_capability_yields_no_evidence_not_ambiguous() {
        assert_eq!(
            diagnose_clock(5_000, &[1_000], &[100, 200, 9_999]),
            ClockDiagnosis::NoEvidenceOfSkew
        );
    }

    /// An empty op-cert slice is the absence of a lower bound, not a good clock — but it does not
    /// suppress the ambiguous case, which rests on `exp` alone.
    #[test]
    fn empty_op_cert_slice_with_expired_caps_is_ambiguous() {
        assert_eq!(
            diagnose_clock(9_000, &[], &[4_000, 8_000]),
            ClockDiagnosis::Ambiguous {
                latest_cap_exp: 8_000
            }
        );
    }

    #[test]
    fn empty_everything_proves_nothing() {
        assert_eq!(
            diagnose_clock(9_000, &[], &[]),
            ClockDiagnosis::NoEvidenceOfSkew
        );
    }

    /// The extraction path: a REAL capability's embedded `op_cert` bytes must yield the same
    /// diagnosis `diagnose_clock` gives for the same raw numbers.
    #[test]
    fn capability_path_extracts_ts_from_a_real_embedded_op_cert() {
        let cap = real_capability(7_000, 8_000);
        let diagnosis = diagnose_clock_from_capabilities(1_000, std::slice::from_ref(&cap), &[])
            .expect("a real capability's op_cert decodes");
        assert_eq!(diagnosis, diagnose_clock(1_000, &[7_000], &[8_000]));
        assert_eq!(
            diagnosis,
            ClockDiagnosis::ProvablyBehind {
                behind_by: ClockOffset(6_000),
                bound_ts: 7_000,
            }
        );
    }

    #[test]
    fn garbage_op_cert_bytes_report_the_offending_index() {
        let mut caps = vec![real_capability(7_000, 8_000), real_capability(7_000, 8_000)];
        caps[1].op_cert = vec![0xFF, 0xFF, 0xFF];
        let err = diagnose_clock_from_capabilities(1_000, &caps, &[])
            .expect_err("garbage op_cert bytes must not decode");
        match err {
            ClockDiagnosticError::MalformedOpCert { index, .. } => assert_eq!(index, 1),
        }
    }

    /// The host path (td-583db5 scope widening): a host holds its own `HostOpKeyCert` and may
    /// hold no capabilities at all, and must still get the check.
    #[test]
    fn extra_op_certs_alone_drive_the_host_path() {
        let root = RootKey::from_seed([0x31; 32]);
        let op_signer = SigningKey::from_bytes(&[0x32; 32]);
        let op_cert = issue_host_op_key_cert(&root, &op_signer.verifying_key(), 7_000, u64::MAX);
        let diagnosis = diagnose_clock_from_capabilities(1_000, &[], &[op_cert])
            .expect("no capabilities to decode");
        assert_eq!(
            diagnosis,
            ClockDiagnosis::ProvablyBehind {
                behind_by: ClockOffset(6_000),
                bound_ts: 7_000,
            }
        );
    }

    /// An absurd bound must saturate at `i64::MAX`, never wrap: a wrapped value would print as a
    /// negative offset and read as "your clock is ahead", the one direction A10.42 says cannot be
    /// proven.
    #[test]
    fn an_absurd_bound_saturates_instead_of_wrapping() {
        let diagnosis = diagnose_clock(0, &[u64::MAX], &[]);
        match diagnosis {
            ClockDiagnosis::ProvablyBehind {
                behind_by,
                bound_ts,
            } => {
                assert_eq!(behind_by.diagnostic_seconds(), i64::MAX);
                assert_eq!(bound_ts, u64::MAX);
            }
            other => panic!("expected a saturated ProvablyBehind, got {other:?}"),
        }
    }
}
