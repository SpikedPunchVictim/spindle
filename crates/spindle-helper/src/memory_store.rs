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
}
