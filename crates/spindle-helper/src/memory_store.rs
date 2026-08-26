//! The dev-mode default [`authz::HelperView`] store: entirely in-memory, not durable.
//!
//! Graduated from `spikes/s1-callout/src/bin/responder.rs`'s `InMemoryHelperView` (S1 — PASS,
//! 19/19, `spikes/s1-callout/RESULTS.md`). `src/bin/helper.rs` constructs one of these at startup
//! and hands it to the callout-handling loop behind the [`authz::HelperView`] trait object — see
//! that trait's own doc comment for the durability/consistency contract a real (Postgres-backed,
//! Stage 4 slice 3) implementation must additionally satisfy (durable writes, the
//! burn-admission-token idempotency contract, `≤ 2s` staleness bound per DESIGN.md §A9b). This
//! type exists so **swapping the store is a one-line change** at the call site that constructs
//! it, not a change to `authz.rs`, `natsjwt.rs`, or the responder loop.
//!
//! Every fact this store holds (revocations, admission records, burned admission-token nonces) is
//! lost on process restart — acceptable for `open`-admission dev/demo use (docs/DESIGN.md §A9b:
//! "dev mode runs helper in `open` admission with a local CA") where hosts don't need pre-durable
//! admission records to reconnect, but never appropriate for a production deployment.

use spindle_core::{Fingerprint, VerifyingKey};
use std::collections::HashMap;

use crate::authz::{AdmissionMode, AdmissionRecord, HelperView};
use crate::session::SessionRecord;

/// Bucket width for [`InMemoryHelperView`]'s TURN-usage counter — see
/// [`HelperView::record_turn_issuance`]'s doc comment for why this is a fixed 30-day rolling
/// window rather than a calendar month.
const TURN_PERIOD_SECS: u64 = 30 * 86_400;

/// The in-memory [`HelperView`]. Construct with [`InMemoryHelperView::new`], passing the
/// [`AdmissionMode`] to run under and the operator key used to verify presented admission tokens.
pub struct InMemoryHelperView {
    admission_mode: AdmissionMode,
    operator_pk: VerifyingKey,
    revoked: HashMap<(Fingerprint, Fingerprint), bool>,
    epochs: HashMap<Fingerprint, u64>,
    admitted: HashMap<Fingerprint, AdmissionRecord>,
    /// Keyed by nonce **alone** (not `(host_fp, nonce)`) — this is what makes cross-host reuse of
    /// the same single-use nonce detectable at all. A bug found while graduating this module: the
    /// S1 spike's own `InMemoryHelperView` (`spikes/s1-callout/src/bin/responder.rs`) keyed this
    /// map by `(host_fp, nonce)`, under which a different host presenting the *same* nonce would
    /// look up a distinct map entry and be burned fresh instead of rejected — silently defeating
    /// [`HelperView::burn_admission_token`]'s single-use contract. Not caught by S1's suite (its
    /// own doc comment already flags the admission-mode matrix as out of scope, "that's S16's
    /// job"); caught here by this module's own
    /// `burn_admission_token_is_idempotent_for_the_same_host_and_rejects_a_different_one` test,
    /// which mirrors `authz.rs`'s `MockView` — the correct reference implementation — nonce-only
    /// keying all along.
    burned_nonces: HashMap<Vec<u8>, AdmissionRecord>,
    /// `nats_fp -> SessionRecord` (DESIGN.md §A5), added in Stage 4 slice 3 — see
    /// [`HelperView::put_session_record`]'s doc comment for why this didn't exist before.
    sessions: HashMap<Fingerprint, SessionRecord>,
    /// `(root_fp, period) -> mint count`, added in Stage 4 slice 3 — see
    /// [`HelperView::record_turn_issuance`]'s doc comment for the period definition.
    turn_usage: HashMap<(Fingerprint, u64), u64>,
}

impl InMemoryHelperView {
    pub fn new(admission_mode: AdmissionMode, operator_pk: VerifyingKey) -> Self {
        Self {
            admission_mode,
            operator_pk,
            revoked: HashMap::new(),
            epochs: HashMap::new(),
            admitted: HashMap::new(),
            burned_nonces: HashMap::new(),
            sessions: HashMap::new(),
            turn_usage: HashMap::new(),
        }
    }
}

impl HelperView for InMemoryHelperView {
    fn revocation_epoch(&mut self, host_fp: &Fingerprint) -> u64 {
        self.epochs.get(host_fp).copied().unwrap_or(0)
    }

    fn is_revoked(&mut self, host_fp: &Fingerprint, subject: &Fingerprint) -> bool {
        self.revoked
            .get(&(*host_fp, *subject))
            .copied()
            .unwrap_or(false)
    }

    fn admission_mode(&mut self) -> AdmissionMode {
        self.admission_mode
    }

    fn admission_record(&mut self, host_fp: &Fingerprint) -> Option<AdmissionRecord> {
        self.admitted.get(host_fp).cloned()
    }

    fn operator_pk(&mut self) -> VerifyingKey {
        self.operator_pk
    }

    fn burn_admission_token(
        &mut self,
        host_fp: Fingerprint,
        nonce: Vec<u8>,
        label: String,
        quota_profile: String,
        admitted_at: u64,
    ) -> Option<AdmissionRecord> {
        if let Some(existing) = self.burned_nonces.get(&nonce) {
            return if existing.host_fp == host_fp {
                Some(existing.clone())
            } else {
                None
            };
        }
        let record = AdmissionRecord {
            host_fp,
            label,
            admitted_at,
            quota_profile,
        };
        self.burned_nonces.insert(nonce, record.clone());
        self.admitted.insert(host_fp, record.clone());
        Some(record)
    }

    fn put_session_record(&mut self, record: SessionRecord) {
        self.sessions.insert(record.nats_fp, record);
    }

    fn session_record(&mut self, nats_fp: &Fingerprint, now: u64) -> Option<SessionRecord> {
        self.sessions.get(nats_fp).filter(|r| r.exp > now).cloned()
    }

    fn record_turn_issuance(
        &mut self,
        root_fp: &Fingerprint,
        now: u64,
        monthly_quota: u64,
    ) -> Result<u64, u64> {
        let period = now / TURN_PERIOD_SECS;
        let count = self.turn_usage.entry((*root_fp, period)).or_insert(0);
        if *count >= monthly_quota {
            Err(*count)
        } else {
            *count += 1;
            Ok(*count)
        }
    }

    fn record_revocation(
        &mut self,
        host_fp: Fingerprint,
        epoch: u64,
        revoked_subjects: &[Fingerprint],
    ) {
        let entry = self.epochs.entry(host_fp).or_insert(0);
        *entry = (*entry).max(epoch);
        for subject in revoked_subjects {
            self.revoked.insert((host_fp, *subject), true);
        }
    }

    fn purge_expired_sessions(&mut self, now: u64) {
        self.sessions.retain(|_, r| r.exp > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::SigningKey;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    fn view(mode: AdmissionMode) -> InMemoryHelperView {
        let operator_pk = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        InMemoryHelperView::new(mode, operator_pk)
    }

    #[test]
    fn fresh_store_has_no_revocations_or_admissions() {
        let mut v = view(AdmissionMode::Open);
        let host = fp(b"host-a");
        let subject = fp(b"device-a");
        assert_eq!(v.revocation_epoch(&host), 0);
        assert!(!v.is_revoked(&host, &subject));
        assert!(v.admission_record(&host).is_none());
    }

    #[test]
    fn admission_mode_reports_the_constructed_value() {
        assert_eq!(
            view(AdmissionMode::Open).admission_mode(),
            AdmissionMode::Open
        );
        assert_eq!(
            view(AdmissionMode::Invite).admission_mode(),
            AdmissionMode::Invite
        );
        assert_eq!(
            view(AdmissionMode::Closed).admission_mode(),
            AdmissionMode::Closed
        );
    }

    #[test]
    fn burn_admission_token_is_idempotent_for_the_same_host_and_rejects_a_different_one() {
        let mut v = view(AdmissionMode::Invite);
        let host_a = fp(b"host-a");
        let host_b = fp(b"host-b");
        let nonce = vec![0x01, 0x02];

        let first = v.burn_admission_token(
            host_a,
            nonce.clone(),
            "label".to_string(),
            "default".to_string(),
            1_000,
        );
        assert!(first.is_some());
        assert_eq!(v.admission_record(&host_a), first);

        let replay = v.burn_admission_token(
            host_a,
            nonce.clone(),
            "label".to_string(),
            "default".to_string(),
            1_000,
        );
        assert_eq!(
            replay, first,
            "same host replaying the same nonce is idempotent"
        );

        let stolen = v.burn_admission_token(
            host_b,
            nonce,
            "label".to_string(),
            "default".to_string(),
            1_000,
        );
        assert_eq!(
            stolen, None,
            "a different host reusing the same nonce must be rejected"
        );
    }

    // ---- Stage 4 slice 3: session records, TURN counters, revocation writes -------------------

    #[test]
    fn session_record_round_trips_and_is_absent_before_write() {
        let mut v = view(AdmissionMode::Open);
        let nats_fp = fp(b"nats-a");
        assert!(v.session_record(&nats_fp, 1_000).is_none());

        let record = SessionRecord::new(nats_fp, fp(b"root-a"), vec![fp(b"host-a")], "member".to_string(), 2_000);
        v.put_session_record(record.clone());
        assert_eq!(v.session_record(&nats_fp, 1_000), Some(record));
    }

    #[test]
    fn session_record_is_absent_once_expired() {
        let mut v = view(AdmissionMode::Open);
        let nats_fp = fp(b"nats-b");
        let record = SessionRecord::new(nats_fp, fp(b"root-b"), vec![], "member".to_string(), 1_000);
        v.put_session_record(record);
        assert!(v.session_record(&nats_fp, 999).is_some());
        assert!(
            v.session_record(&nats_fp, 1_000).is_none(),
            "exp is exclusive: at/after exp the record must read as absent"
        );
    }

    #[test]
    fn put_session_record_upserts_by_nats_fp() {
        let mut v = view(AdmissionMode::Open);
        let nats_fp = fp(b"nats-c");
        v.put_session_record(SessionRecord::new(
            nats_fp,
            fp(b"root-old"),
            vec![],
            "member".to_string(),
            1_000,
        ));
        v.put_session_record(SessionRecord::new(
            nats_fp,
            fp(b"root-new"),
            vec![],
            "member".to_string(),
            2_000,
        ));
        let got = v.session_record(&nats_fp, 0).expect("record present");
        assert_eq!(got.root_fp, fp(b"root-new"), "later write must replace the earlier one");
    }

    #[test]
    fn turn_issuance_is_admitted_until_quota_then_refused() {
        let mut v = view(AdmissionMode::Open);
        let root = fp(b"root-turn");
        assert_eq!(v.record_turn_issuance(&root, 1_000, 2), Ok(1));
        assert_eq!(v.record_turn_issuance(&root, 1_000, 2), Ok(2));
        assert_eq!(
            v.record_turn_issuance(&root, 1_000, 2),
            Err(2),
            "third mint in the same period must be refused once at quota"
        );
    }

    #[test]
    fn turn_issuance_counters_are_independent_per_root_fp() {
        let mut v = view(AdmissionMode::Open);
        let a = fp(b"root-turn-a");
        let b = fp(b"root-turn-b");
        assert_eq!(v.record_turn_issuance(&a, 1_000, 1), Ok(1));
        assert_eq!(
            v.record_turn_issuance(&b, 1_000, 1),
            Ok(1),
            "a different root_fp must have its own independent counter"
        );
    }

    #[test]
    fn turn_issuance_counter_resets_in_a_new_period() {
        let mut v = view(AdmissionMode::Open);
        let root = fp(b"root-turn-period");
        assert_eq!(v.record_turn_issuance(&root, 0, 1), Ok(1));
        assert_eq!(
            v.record_turn_issuance(&root, 0, 1),
            Err(1),
            "quota exhausted in period 0"
        );
        let next_period_now = TURN_PERIOD_SECS; // first instant of the next 30-day bucket
        assert_eq!(
            v.record_turn_issuance(&root, next_period_now, 1),
            Ok(1),
            "a new period must start with a fresh counter"
        );
    }

    #[test]
    fn record_revocation_is_max_wins_and_never_decreases() {
        let mut v = view(AdmissionMode::Open);
        let host = fp(b"host-rev");
        v.record_revocation(host, 5, &[]);
        assert_eq!(v.revocation_epoch(&host), 5);
        v.record_revocation(host, 2, &[]);
        assert_eq!(
            v.revocation_epoch(&host),
            5,
            "a lower epoch must never roll the stored epoch backward"
        );
        v.record_revocation(host, 9, &[]);
        assert_eq!(v.revocation_epoch(&host), 9);
    }

    #[test]
    fn purge_expired_sessions_removes_only_expired_rows() {
        let mut v = view(AdmissionMode::Open);
        let live_fp = fp(b"nats-live");
        let expired_fp = fp(b"nats-expired");
        v.put_session_record(SessionRecord::new(live_fp, fp(b"root"), vec![], "member".to_string(), 5_000));
        v.put_session_record(SessionRecord::new(expired_fp, fp(b"root"), vec![], "member".to_string(), 1_000));
        v.purge_expired_sessions(2_000);
        assert!(v.session_record(&live_fp, 0).is_some());
        assert!(!v.sessions.contains_key(&expired_fp));
    }

    #[test]
    fn record_revocation_adds_revoked_subjects() {
        let mut v = view(AdmissionMode::Open);
        let host = fp(b"host-rev-2");
        let subject = fp(b"subject-a");
        assert!(!v.is_revoked(&host, &subject));
        v.record_revocation(host, 1, &[subject]);
        assert!(v.is_revoked(&host, &subject));
    }
}
