use super::{check_exp, parse_signature, parse_verifying_key, ArtifactError};
use crate::fingerprint::Fingerprint;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use spindle_proto::artifacts::{CapKind, Capability};

/// Issues a capability signed by `signer` — DESIGN.md §A4's "host-signed, self-verifying"
/// capability. Operationally the host signs with its **operating key** (never the root directly;
/// the operating key is itself chained to the root via `HostOpKeyCert` — see
/// [`super::issue_host_op_key_cert`]), which is what `signer` is here. `host_pk`/`host_fp` are
/// derived from `signer`, not supplied by the caller, so the self-verifying property
/// (`host_fp == SHA-256(host_pk)`) holds by construction.
pub fn issue_capability(
    signer: &SigningKey,
    kind: CapKind,
    subject: Fingerprint,
    cap_epoch: u64,
    exp: u64,
    nonce: Vec<u8>,
) -> Capability {
    let host_pk = signer.verifying_key();
    let host_fp = Fingerprint::of_parts(&[host_pk.as_bytes()]);
    let mut cap = Capability {
        v: 1,
        host_fp: host_fp.to_vec(),
        host_pk: host_pk.as_bytes().to_vec(),
        kind,
        subject: subject.to_vec(),
        cap_epoch,
        exp,
        nonce,
        sig_host: Vec::new(),
    };
    cap.sig_host = signer.sign(&cap.signing_input()).to_bytes().to_vec();
    cap
}

/// Verifies a capability's self-verifying property (`host_fp == SHA-256(host_pk)` — no external
/// root or registry lookup needed, DESIGN.md §A4: "the callout needs no registry of hosts or
/// members"), `sig_host`, and `exp`.
///
/// **Ambiguity flagged, not resolved**: DESIGN.md §A7b / ADR-003's signed-artifact table lists
/// `nbf = issue ts` as part of a capability's time rule, but `spindle_proto::artifacts::Capability`
/// — the schema of record per its own module docs — has no `nbf` field. This function therefore
/// checks only `exp`, matching the wire schema that actually exists, rather than inventing a
/// substitute `nbf` check (e.g. treating `cap_epoch` or `nonce` as a stand-in).
pub fn verify_capability(cap: &Capability, now: u64) -> Result<(), ArtifactError> {
    let host_pk = parse_verifying_key(&cap.host_pk)?;
    let expected_fp = Fingerprint::of_parts(&[host_pk.as_bytes()]);
    if !expected_fp.matches(&cap.host_fp) {
        return Err(ArtifactError::HostFingerprintMismatch);
    }
    let sig = parse_signature(&cap.sig_host)?;
    host_pk
        .verify(&cap.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)?;
    check_exp(now, cap.exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn host_op_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    #[test]
    fn issue_and_verify_round_trip_both_kinds() {
        for kind in [CapKind::Invite, CapKind::Member] {
            let signer = host_op_key();
            let cap = issue_capability(
                &signer,
                kind,
                Fingerprint::of_parts(&[b"subject"]),
                3,
                2_000,
                vec![0xAA; 16],
            );
            verify_capability(&cap, 1_500).expect("valid capability");
        }
    }

    #[test]
    fn rejects_host_fingerprint_mismatch() {
        let signer = host_op_key();
        let mut cap = issue_capability(
            &signer,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
            vec![0xAA; 16],
        );
        cap.host_fp[0] ^= 0xff;
        let err = verify_capability(&cap, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::HostFingerprintMismatch);
    }

    #[test]
    fn rejects_bad_signature() {
        let signer = host_op_key();
        let mut cap = issue_capability(
            &signer,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
            vec![0xAA; 16],
        );
        cap.sig_host[0] ^= 0xff;
        let err = verify_capability(&cap, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_expired() {
        let signer = host_op_key();
        let cap = issue_capability(
            &signer,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            0,
            2_000,
            vec![0xAA; 16],
        );
        let err = verify_capability(&cap, 2_001).unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }
}
