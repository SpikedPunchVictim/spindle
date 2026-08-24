use super::{parse_signature, ArtifactError};
use crate::fingerprint::Fingerprint;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use spindle_proto::artifacts::RevocationRecord;

/// Issues a revocation record. The signer is either the host operating key or an identity root
/// (DESIGN.md §A4/§A7b) — this crate does not distinguish which, since both are plain Ed25519
/// signing keys; the caller supplies whichever is appropriate for the revocation being made
/// (host revoking a member/device, vs. a person self-revoking a lost device's root).
pub fn issue_revocation_record(
    signer: &SigningKey,
    host_fp: Fingerprint,
    epoch: u64,
    revoked: Vec<Fingerprint>,
    ts: u64,
) -> RevocationRecord {
    let mut rec = RevocationRecord {
        host_fp: host_fp.to_vec(),
        epoch,
        revoked: revoked.iter().map(|fp| fp.to_vec()).collect(),
        ts,
        sig: Vec::new(),
    };
    rec.sig = signer.sign(&rec.signing_input()).to_bytes().to_vec();
    rec
}

/// Verifies `sig` under `signer_pk` (host op key or identity root — caller resolves which).
/// Revocation records carry **no expiry** (A7b: "none (permanent)") — only the signature is
/// checked here. The max-wins replay rule is a separate concern: see [`is_newer_epoch`].
pub fn verify_revocation_record(
    rec: &RevocationRecord,
    signer_pk: &VerifyingKey,
) -> Result<(), ArtifactError> {
    let sig = parse_signature(&rec.sig)?;
    signer_pk
        .verify(&rec.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)
}

/// A7b's max-wins replay rule for revocation records: a candidate epoch only takes effect if it
/// is strictly greater than the current high-water mark. Never decreases, never rolls back
/// (DESIGN.md §A7b / ADR-004 consequences: "closing rollback via a replayed old record or a
/// restored backup").
pub fn is_newer_epoch(candidate_epoch: u64, current_max_epoch: u64) -> bool {
    candidate_epoch > current_max_epoch
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[0x31; 32])
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let s = signer();
        let rec = issue_revocation_record(
            &s,
            Fingerprint::of_parts(&[b"host"]),
            3,
            vec![Fingerprint::of_parts(&[b"device"])],
            1_000,
        );
        verify_revocation_record(&rec, &s.verifying_key()).expect("valid record");
    }

    #[test]
    fn rejects_bad_signature() {
        let s = signer();
        let mut rec = issue_revocation_record(
            &s,
            Fingerprint::of_parts(&[b"host"]),
            3,
            vec![Fingerprint::of_parts(&[b"device"])],
            1_000,
        );
        rec.sig[0] ^= 0xff;
        let err = verify_revocation_record(&rec, &s.verifying_key()).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn max_wins_epoch_comparison() {
        assert!(is_newer_epoch(5, 3));
        assert!(!is_newer_epoch(3, 5));
        assert!(!is_newer_epoch(3, 3), "equal epoch is not newer (strict >)");
    }
}
