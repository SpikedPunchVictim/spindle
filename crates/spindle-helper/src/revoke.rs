//! `registry.revoke.<hfp>` ingestion — the broker helper's uptake of host-signed revocation
//! records (DESIGN.md §A4/§A5/§A7b/§A9b). This closes leg 2 of §A4's revoke -> kick -> reject
//! chain (S9/S14): a host issues a `RevocationRecord`
//! (`spindle_core::artifacts::issue_revocation_record`), publishes it on its own `registry.
//! revoke.<own_host_fp>` subject, and this module durably records it via
//! [`HelperView::record_revocation`] so a later CONNECT's callout check
//! (`authz::decide_device_connect`'s `view.is_revoked` lookups, `authz.rs:363`) can see it.
//! Follows `presence.rs`/`turn.rs`'s shape closely: pure/NATS-free, no `async-nats` type appears
//! anywhere in this module's API — `src/bin/helper.rs` is the only caller that ever touches an
//! actual subscription.
//!
//! # Identity check: subject token == record `host_fp`, NOT a signature check [deliberate]
//! DESIGN.md §A5's subject table states the admission rule for this subject verbatim: "helper
//! asserts subject token == record `host_fp`". [`ingest_revocation`] implements exactly that
//! comparison and nothing more — it never calls
//! `spindle_core::artifacts::verify_revocation_record`. That is not an oversight; it is the only
//! check this helper is *able* to make. [`crate::authz::AdmissionRecord`] is `{host_fp, label,
//! admitted_at, quota_profile}` (`authz.rs:147`) — the helper never persists a host's root public
//! key anywhere, so given only a `host_fp` (a hash) recovered from a subject token, there is no
//! key on hand to verify a signature against.
//!
//! Trust instead comes from NATS's own subject-space scoping: the callout only ever grants a host
//! connection `pub registry.revoke.<own_host_fp>`, scoped to its own fingerprint alone
//! (`permissions::host_permissions`, `permissions.rs:87`) — so by the time a message reaches this
//! handler, "which subject it arrived on" is a fact NATS itself already enforced, the same
//! load-bearing property `turn.rs`/`presence.rs` lean on for their own `<...fp>` subjects. A host
//! physically cannot publish a revocation scoped to a `host_fp` it doesn't own. The record's own
//! `sig` field exists for onward consumption by devices/hosts re-deriving trust from the record
//! once relayed onward — DESIGN.md §A4 says this outright: this helper-side check is
//! "best-effort" and "the authoritative check is the host's per-request enforcement" — not for
//! this helper to verify, which it couldn't do anyway without the host's public key.
//!
//! # Epoch handling: never reject on a stale epoch [deliberate]
//! [`HelperView::record_revocation`] already applies max-wins to the stored epoch counter itself
//! (`memory_store.rs`'s `.max(epoch)`, `pg_store.rs`'s `GREATEST(...)` upsert) — see
//! `spindle_core::artifacts::revocation::is_newer_epoch` for the same rule stated as a pure
//! function. This module does not call it and does not compare the incoming epoch against the
//! stored high-water mark at all: revocation is a one-way lattice (a subject, once genuinely
//! revoked, stays revoked forever), so a *replayed* older-epoch record can only ever re-apply
//! subjects that were genuinely revoked at some point in the past — it can never remove one, and
//! it can never roll anything back, because the epoch counter itself is protected separately by
//! the store's own max-wins upsert. Rejecting a stale-epoch record here would silently drop real
//! revocations on replay (e.g. a redelivered/duplicated durable message, or an operator
//! re-publishing an old record during recovery) for no security benefit whatsoever — the epoch
//! counter can't move backward either way. So: this module always applies `record.revoked` and
//! always calls `record_revocation` with whatever epoch the record carries, unconditionally,
//! leaving the store's own max-wins rule — not this module — as the single place epoch
//! monotonicity is enforced.
//!
//! # Wire schema
//! ```text
//! subject: registry.revoke.<hfp>   (hfp = base32 Display of the publishing host's own host_fp —
//!                                    the callout grants a host `pub registry.revoke.<own_host_fp>`
//!                                    only; see permissions::host_permissions)
//! payload: canonical CBOR encoding of a spindle_proto::artifacts::RevocationRecord
//!          (`{host_fp, epoch, revoked: [fp...], ts, sig}`, DESIGN.md §A4/§A7b), decoded via
//!          RevocationRecord::from_canonical_bytes — strict decoding: that type's `from_cbor`
//!          calls `MapReader::deny_unknown_fields`, so an unrecognized field is a decode error,
//!          not silently ignored (matching how every other wire artifact in this codebase decodes).
//! reply:   none. This subject is publish-only (DESIGN.md §A5's subject table lists no reply for
//!          it), so `ingest_revocation` returns a `RevokeOutcome` for `src/bin/helper.rs` to log,
//!          never a payload to publish back.
//! ```
//!
//! # Out of scope (DESIGN.md items this module deliberately does not implement)
//! **Per-host token bucket rate limiting.** DESIGN.md §A5's subject-table row for `registry.
//! revoke.<hfp>` specifies one explicitly ("per-host token bucket"). This crate has no rate
//! limiter of any kind today — no token-bucket type, no `ratelimit` module anywhere under
//! `crates/spindle-helper` (grep confirms it). The obvious graduation candidate is
//! `crates/spindle-host-core/src/ratelimit.rs`, which already implements one for a different
//! crate, but porting or sharing it across crates is undone work, not something to silently
//! assume is unnecessary. Flagged here rather than omitted without comment: every revocation on a
//! well-formed, correctly-scoped subject is accepted and stored today, with no limit whatsoever on
//! how often a host may publish them.
//!
//! **Signature verification** — see the section above; not a gap, a documented non-goal for this
//! specific helper-side check.

use spindle_core::Fingerprint;
use spindle_proto::artifacts::RevocationRecord;

use crate::authz::HelperView;

/// The `registry.revoke.` subject prefix; `<hfp>` follows it as the final subject token (same
/// shape as `turn.rs`'s `helper.turn.get.` / `presence.rs`'s `helper.presence.get.` prefixes).
const SUBJECT_PREFIX: &str = "registry.revoke.";

/// Why an incoming `registry.revoke.<hfp>` message was refused. **Internal use only** (logging,
/// this module's own test suite) — there is no reply on this subject to put a message on at all
/// (see the module doc's wire schema), so unlike `authz::RefusalReason` this never needs a
/// uniform-wire concern; each variant's `Display` is exactly what `src/bin/helper.rs` should log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RevokeRejection {
    #[error("malformed subject")]
    MalformedSubject,
    #[error("payload did not decode as a RevocationRecord")]
    UndecodablePayload,
    #[error("record host_fp does not match the publishing subject's own host_fp")]
    HostFpMismatch,
}

/// The result of [`ingest_revocation`]: either the record was accepted and durably stored, or it
/// was refused for one specific, distinguishable reason (see [`RevokeRejection`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Accepted and written via [`HelperView::record_revocation`]. `revoked_count` is the number
    /// of `record.revoked` entries that decoded as a [`Fingerprint`] and were actually applied
    /// (see [`ingest_revocation`]'s doc comment on why a malformed entry is dropped rather than
    /// failing the whole record) — reported for the caller's log line.
    Accepted {
        host_fp: Fingerprint,
        epoch: u64,
        revoked_count: usize,
    },
    Rejected(RevokeRejection),
}

/// Parses the publishing host's `host_fp` out of a `registry.revoke.<hfp>` subject, via the
/// shared [`crate::parse_fp_after_prefix`] helper `turn.rs`/`presence.rs` also use.
fn parse_subject_host_fp(subject: &str) -> Option<Fingerprint> {
    crate::parse_fp_after_prefix(subject, SUBJECT_PREFIX)
}

/// Decodes and admits one `registry.revoke.<hfp>` publish: durably records the revocation via
/// `view` if, and only if, the payload decodes as a [`RevocationRecord`] whose `host_fp` field
/// equals the subject token's `<hfp>` (see the module doc's "Identity check" section for why that
/// equality — not a signature check — is the whole of this admission rule). Pure with respect to
/// NATS — `src/bin/helper.rs` is the only caller that touches an actual subscription; there is no
/// reply to publish back (see the module doc's wire schema), so this returns an outcome for
/// logging, not payload bytes.
///
/// A `RevocationRecord::revoked` entry that doesn't decode as a 32-byte [`Fingerprint`] is
/// dropped silently rather than failing the whole record — the same "a malformed piece
/// contributes nothing, rather than poisoning the whole message" tolerance
/// `authz::decide_device_connect` already shows for an individual capability's
/// `host_fp`/`subject` fields (`cap_host_fp`/`cap_subject_fp`, `authz.rs:304-310`).
pub fn ingest_revocation(
    subject: &str,
    payload: &[u8],
    view: &mut impl HelperView,
) -> RevokeOutcome {
    let Some(subject_host_fp) = parse_subject_host_fp(subject) else {
        return RevokeOutcome::Rejected(RevokeRejection::MalformedSubject);
    };

    let Ok(record) = RevocationRecord::from_canonical_bytes(payload) else {
        return RevokeOutcome::Rejected(RevokeRejection::UndecodablePayload);
    };

    let Ok(record_host_fp) = Fingerprint::from_slice(&record.host_fp) else {
        return RevokeOutcome::Rejected(RevokeRejection::UndecodablePayload);
    };

    // The security-load-bearing check (see the module doc's "Identity check" section): the record
    // is trusted *because* NATS itself only ever let this subject's publisher reach `registry.
    // revoke.<subject_host_fp>`. A record whose own `host_fp` field names a different host is
    // refused outright, before anything is written to the store.
    if record_host_fp != subject_host_fp {
        return RevokeOutcome::Rejected(RevokeRejection::HostFpMismatch);
    }

    // Epoch is applied unconditionally here — see the module doc's "Epoch handling" section for
    // why a stale epoch is never, by itself, a rejection reason.
    let revoked_subjects: Vec<Fingerprint> = record
        .revoked
        .iter()
        .filter_map(|bytes| Fingerprint::from_slice(bytes).ok())
        .collect();

    view.record_revocation(record_host_fp, record.epoch, &revoked_subjects);

    RevokeOutcome::Accepted {
        host_fp: record_host_fp,
        epoch: record.epoch,
        revoked_count: revoked_subjects.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::AdmissionMode;
    use crate::memory_store::InMemoryHelperView;
    use spindle_core::artifacts::issue_revocation_record;
    use spindle_core::SigningKey;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    fn store() -> InMemoryHelperView {
        InMemoryHelperView::new(
            AdmissionMode::Open,
            SigningKey::from_bytes(&[0x44; 32]).verifying_key(),
        )
    }

    fn subject_for(host_fp: &Fingerprint) -> String {
        format!("registry.revoke.{host_fp}")
    }

    /// Builds canonical CBOR bytes for a `RevocationRecord`. The signer here is a throwaway key —
    /// this module never verifies the signature (see the module doc), so any signer suffices to
    /// produce a "well-formed, decodable" record for these tests.
    fn record_bytes(host_fp: Fingerprint, epoch: u64, revoked: Vec<Fingerprint>) -> Vec<u8> {
        let signer = SigningKey::from_bytes(&[0x55; 32]);
        let rec = issue_revocation_record(&signer, host_fp, epoch, revoked, 1_000);
        rec.to_canonical_bytes()
    }

    // ---- ingest_revocation: happy path -----------------------------------------------------

    #[test]
    fn well_formed_record_on_matching_subject_is_stored() {
        let mut s = store();
        let host_fp = fp(b"host-a");
        let subject_a = fp(b"revoked-subject-a");
        let subject_b = fp(b"revoked-subject-b");
        let bytes = record_bytes(host_fp, 3, vec![subject_a, subject_b]);

        let outcome = ingest_revocation(&subject_for(&host_fp), &bytes, &mut s);

        assert_eq!(
            outcome,
            RevokeOutcome::Accepted {
                host_fp,
                epoch: 3,
                revoked_count: 2,
            }
        );
        assert!(s.is_revoked(&host_fp, &subject_a));
        assert!(s.is_revoked(&host_fp, &subject_b));
        assert_eq!(s.revocation_epoch(&host_fp), 3);
    }

    // ---- ingest_revocation: the isolating negative test ------------------------------------

    #[test]
    fn host_fp_mismatch_is_rejected_and_stores_nothing() {
        let mut s = store();
        let subject_host_fp = fp(b"subject-token-host");
        let record_host_fp = fp(b"a-totally-different-host");
        let victim_subject = fp(b"innocent-bystander-subject");
        let bytes = record_bytes(record_host_fp, 1, vec![victim_subject]);

        let outcome = ingest_revocation(&subject_for(&subject_host_fp), &bytes, &mut s);

        assert_eq!(
            outcome,
            RevokeOutcome::Rejected(RevokeRejection::HostFpMismatch),
            "a record claiming a different host_fp than the subject token must be refused"
        );
        assert!(
            !s.is_revoked(&subject_host_fp, &victim_subject),
            "nothing must be stored under the subject's own host_fp"
        );
        assert!(
            !s.is_revoked(&record_host_fp, &victim_subject),
            "nothing must be stored under the record's claimed host_fp either"
        );
        assert_eq!(s.revocation_epoch(&subject_host_fp), 0);
        assert_eq!(s.revocation_epoch(&record_host_fp), 0);
    }

    // ---- ingest_revocation: malformed subject ----------------------------------------------

    #[test]
    fn malformed_subject_is_rejected() {
        let mut s = store();
        let bytes = record_bytes(fp(b"whatever-host"), 1, vec![]);

        assert_eq!(
            ingest_revocation("registry.revoke.", &bytes, &mut s),
            RevokeOutcome::Rejected(RevokeRejection::MalformedSubject),
            "empty token after the prefix must be refused"
        );
        assert_eq!(
            ingest_revocation("registry.revoke.not-a-fingerprint!!", &bytes, &mut s),
            RevokeOutcome::Rejected(RevokeRejection::MalformedSubject),
            "a token that doesn't decode as a Fingerprint must be refused"
        );
        assert_eq!(
            ingest_revocation("registry.revoke", &bytes, &mut s),
            RevokeOutcome::Rejected(RevokeRejection::MalformedSubject),
            "missing the trailing <hfp> token entirely must be refused"
        );
    }

    // ---- ingest_revocation: undecodable payload --------------------------------------------

    #[test]
    fn undecodable_payload_is_rejected() {
        let mut s = store();
        let host_fp = fp(b"host-with-garbage-payload");

        let outcome = ingest_revocation(&subject_for(&host_fp), b"not cbor at all", &mut s);

        assert_eq!(
            outcome,
            RevokeOutcome::Rejected(RevokeRejection::UndecodablePayload)
        );
        assert_eq!(s.revocation_epoch(&host_fp), 0);
    }

    // ---- ingest_revocation: replay / epoch handling ----------------------------------------

    #[test]
    fn replayed_older_epoch_record_still_applies_subjects_without_decreasing_stored_epoch() {
        let mut s = store();
        let host_fp = fp(b"host-replay");
        let newer_subject = fp(b"subject-revoked-at-epoch-5");
        let older_subject = fp(b"subject-revoked-at-epoch-2");

        let newer_bytes = record_bytes(host_fp, 5, vec![newer_subject]);
        let outcome1 = ingest_revocation(&subject_for(&host_fp), &newer_bytes, &mut s);
        assert_eq!(
            outcome1,
            RevokeOutcome::Accepted {
                host_fp,
                epoch: 5,
                revoked_count: 1,
            }
        );
        assert_eq!(s.revocation_epoch(&host_fp), 5);

        // A replay of an *older* epoch record (e.g. redelivery, or an operator re-publishing
        // during recovery) — must still apply its own revoked subjects.
        let older_bytes = record_bytes(host_fp, 2, vec![older_subject]);
        let outcome2 = ingest_revocation(&subject_for(&host_fp), &older_bytes, &mut s);
        assert_eq!(
            outcome2,
            RevokeOutcome::Accepted {
                host_fp,
                epoch: 2,
                revoked_count: 1,
            },
            "a stale-epoch record must still be accepted, not rejected"
        );
        assert!(
            s.is_revoked(&host_fp, &older_subject),
            "the replayed record's own revoked subject must still be applied"
        );
        assert!(
            s.is_revoked(&host_fp, &newer_subject),
            "the earlier, newer-epoch record's subject must remain revoked"
        );
        assert_eq!(
            s.revocation_epoch(&host_fp),
            5,
            "the stored epoch must never decrease on replay of an older record"
        );
    }

    // ---- parse_subject_host_fp --------------------------------------------------------------

    #[test]
    fn parse_subject_round_trips_a_fingerprint() {
        let host_fp = fp(b"parse-round-trip-host");
        assert_eq!(parse_subject_host_fp(&subject_for(&host_fp)), Some(host_fp));
    }

    #[test]
    fn parse_subject_rejects_wrong_prefix() {
        let host_fp = fp(b"parse-wrong-prefix-host");
        assert_eq!(parse_subject_host_fp("registry.revoke"), None);
        assert_eq!(
            parse_subject_host_fp(&format!("helper.turn.get.{host_fp}")),
            None
        );
    }

    #[test]
    fn parse_subject_rejects_empty_token() {
        assert_eq!(parse_subject_host_fp("registry.revoke."), None);
    }

    #[test]
    fn parse_subject_rejects_a_token_that_does_not_decode_as_a_fingerprint() {
        assert_eq!(
            parse_subject_host_fp("registry.revoke.not-a-fingerprint!!"),
            None
        );
        assert_eq!(parse_subject_host_fp("registry.revoke.my"), None);
    }
}
