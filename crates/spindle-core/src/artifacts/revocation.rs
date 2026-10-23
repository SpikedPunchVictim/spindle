use super::{parse_signature, ArtifactError};
use crate::fingerprint::Fingerprint;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use spindle_proto::artifacts::RevocationRecord;

/// Issues a host-scoped revocation record. The signer is the **host operating key only**
/// (DESIGN.md §A7b, amended v0.9.18): `spindle-rev-v1` carries a `host_fp` and a host-scoped
/// `cap_epoch`, neither of which means anything for a person's root. A person's root revokes
/// keys under its own root with [`issue_self_revocation`](super::issue_self_revocation)
/// (`spindle-self-rev-v1`) instead.
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

/// Verifies `sig` under `host_op_pk` — the host operating key, the only signer of a
/// `spindle-rev-v1` record (DESIGN.md §A7b, amended v0.9.18). A person's root signs
/// [`SelfRevocationRecord`](spindle_proto::artifacts::SelfRevocationRecord) instead, verified by
/// [`verify_self_revocation`](super::verify_self_revocation). Revocation records carry **no
/// expiry** (A7b: "none (permanent)") — only the signature is checked here. The max-wins replay
/// rule is a separate concern: see [`is_newer_epoch`].
pub fn verify_revocation_record(
    rec: &RevocationRecord,
    host_op_pk: &VerifyingKey,
) -> Result<(), ArtifactError> {
    let sig = parse_signature(&rec.sig)?;
    host_op_pk
        .verify(&rec.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)
}

/// A7b's max-wins replay rule for revocation records: a candidate epoch only takes effect if it
/// is strictly greater than the current high-water mark. Never decreases, never rolls back
/// (DESIGN.md §A7b / ADR-004 consequences: "closing rollback via a replayed old record or a
/// restored backup").
///
/// Generic over the artifact kind and shared by both revocation records: host-scoped
/// [`RevocationRecord`]s (max-wins) and root-scoped
/// [`SelfRevocationRecord`](spindle_proto::artifacts::SelfRevocationRecord)s (max-wins **per
/// root**, DESIGN.md §A7b). Callers must key the high-water mark by `host_fp` or `root_fp`
/// respectively; this function only compares the epoch pair.
///
/// The epoch is an **acceptance gate only**, never a replacement instruction. An accepted
/// record's `revoked` entries are added to the stored set — the accepted set is a monotone union
/// that never shrinks — so a higher-epoch record with an empty `revoked` list accepts cleanly and
/// changes nothing, rather than clearing everything revoked earlier.
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
