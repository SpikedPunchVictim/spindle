//! Root-scoped self-revocation (`spindle-self-rev-v1`, DESIGN.md §A4/§A7b).
//!
//! A person's identity root revokes keys under its own root. Unlike a host-scoped
//! [`RevocationRecord`](spindle_proto::artifacts::RevocationRecord), the record carries no
//! `host_fp` and no host-scoped `cap_epoch`: it is not scoped to one host, and a person's root
//! can revoke a lost device regardless of which host it last talked to.
//!
//! **Replay/ingestion rule (state this, do not implement it here):** the accepted revoked set is
//! the **monotone union** of every accepted record's `revoked` entries. The per-root epoch
//! high-water mark (via [`is_newer_epoch`](super::is_newer_epoch)) only gates whether a record is
//! accepted; it never shrinks the set. A later record with an empty `revoked` list is therefore
//! not an "un-revoke everything" instruction — it adds nothing and leaves the union unchanged.

use super::{parse_signature, ArtifactError};
use crate::fingerprint::Fingerprint;
use crate::identity::root_fp_of;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use spindle_proto::artifacts::SelfRevocationRecord;

/// Issues a root-signed self-revocation record (DESIGN.md §A4/§A7b).
///
/// `root_fp` is **derived from `signer`**, never accepted from the caller, so a record whose
/// `root_fp` disagrees with its own signer cannot be minted through this API. The helper's
/// `helper.revoke.<nfp>` deposit checks the same relationship against the caller's session record
/// (DESIGN.md §A4); deriving it here means a well-formed record always names the root that
/// actually signed it.
pub fn issue_self_revocation(
    signer: &SigningKey,
    epoch: u64,
    revoked: Vec<Fingerprint>,
    ts: u64,
) -> SelfRevocationRecord {
    let mut rec = SelfRevocationRecord {
        root_fp: root_fp_of(&signer.verifying_key()).to_vec(),
        epoch,
        revoked: revoked.iter().map(|fp| fp.to_vec()).collect(),
        ts,
        sig_root: Vec::new(),
    };
    rec.sig_root = signer.sign(&rec.signing_input()).to_bytes().to_vec();
    rec
}

/// Verifies a self-revocation record (DESIGN.md §A4/§A7b).
///
/// Checks, in order:
/// 1. `root_fp_of(root_pk) == rec.root_fp` — the record names the root key it is verified under.
///    A record carrying the `root_fp` of a different root cannot be accepted even if its
///    signature happens to verify under some other key the caller holds.
/// 2. `sig_root` is valid under `root_pk` over `rec.signing_input()`.
///
/// Self-revocations carry **no expiry and no `ts` freshness check** (A7b: "none (permanent)") —
/// an arbitrarily old record remains valid. The per-root max-wins replay rule is a separate
/// concern: see [`is_newer_epoch`](super::is_newer_epoch) in the `revocation` module, which is
/// generic over the candidate/current epoch pair and applies to both revocation kinds. Epoch is
/// only an acceptance gate: the accepted revoked set is the **monotone union** of every accepted
/// record's entries and never shrinks (module doc above).
///
/// `revoked` entries are carried opaquely, exactly like [`RevocationRecord`]'s
/// (spindle_proto::artifacts::RevocationRecord): this crate neither requires nor enforces a
/// 32-byte length on them, because `alg_id` governs identity encoding and ingestion may see
/// entries of another suite. Ingestion must not assume a length either.
pub fn verify_self_revocation(
    rec: &SelfRevocationRecord,
    root_pk: &VerifyingKey,
) -> Result<(), ArtifactError> {
    if !root_fp_of(root_pk).matches(&rec.root_fp) {
        return Err(ArtifactError::RootFingerprintMismatch);
    }
    let sig = parse_signature(&rec.sig_root)?;
    root_pk
        .verify(&rec.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_a() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    fn root_b() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let s = root_a();
        let rec = issue_self_revocation(
            &s,
            4,
            vec![Fingerprint::of_parts(&[b"lost-device"])],
            1_755_907_200,
        );
        verify_self_revocation(&rec, &s.verifying_key()).expect("valid record");
    }

    #[test]
    fn issued_root_fp_equals_root_fp_of_signer() {
        let s = root_a();
        let rec = issue_self_revocation(&s, 4, vec![], 1_000);
        assert_eq!(
            rec.root_fp,
            root_fp_of(&s.verifying_key()).to_vec(),
            "issue_self_revocation must derive root_fp from its signer"
        );
    }

    #[test]
    fn rejects_bad_signature() {
        let s = root_a();
        let mut rec = issue_self_revocation(&s, 4, vec![Fingerprint::of_parts(&[b"x"])], 1_000);
        rec.sig_root[0] ^= 0xff;
        let err = verify_self_revocation(&rec, &s.verifying_key()).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_a_different_root_key() {
        // A genuine record under root A must not verify under root B, even though B is a valid
        // Ed25519 key: the root_fp check fires first.
        let rec = issue_self_revocation(&root_a(), 4, vec![], 1_000);
        let err = verify_self_revocation(&rec, &root_b().verifying_key()).unwrap_err();
        assert_eq!(err, ArtifactError::RootFingerprintMismatch);
    }

    #[test]
    fn rejects_root_fp_that_disagrees_with_the_verifying_key() {
        // Signed by root B but carrying root A's fingerprint: the record is internally
        // inconsistent and must be rejected on the fingerprint, not waved through by a signature
        // that would otherwise be valid under B.
        let b = root_b();
        let mut rec = issue_self_revocation(&b, 4, vec![], 1_000);
        rec.root_fp = root_fp_of(&root_a().verifying_key()).to_vec();
        let err = verify_self_revocation(&rec, &b.verifying_key()).unwrap_err();
        assert_eq!(err, ArtifactError::RootFingerprintMismatch);
    }

    #[test]
    fn accepts_an_arbitrarily_old_timestamp() {
        // A7b: self-revocations are permanent ("none (permanent)") — `ts` is informational, not
        // an expiry or freshness rule. A record from 1970 must still verify.
        let s = root_a();
        let rec = issue_self_revocation(&s, 1, vec![], 1);
        verify_self_revocation(&rec, &s.verifying_key())
            .expect("permanent records have no time rule");
    }
}
