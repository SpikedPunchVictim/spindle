use super::{check_exp, parse_signature, ArtifactError};
use crate::fingerprint::Fingerprint;
use crate::identity::{root_fp_of, RootKey};
use ed25519_dalek::{Verifier, VerifyingKey};
use spindle_proto::artifacts::HostOpKeyCert;

/// Issues `sig_host_root(host_op_pk, nats_fp, ts, exp)` — the host root certifying its operating
/// key (DESIGN.md §A4).
pub fn issue_host_op_key_cert(
    host_root: &RootKey,
    host_op_pk: &VerifyingKey,
    nats_fp: Fingerprint,
    ts: u64,
    exp: u64,
) -> HostOpKeyCert {
    let mut cert = HostOpKeyCert {
        host_op_pk: host_op_pk.as_bytes().to_vec(),
        nats_fp: nats_fp.to_vec(),
        ts,
        exp,
        sig_host_root: Vec::new(),
    };
    cert.sig_host_root = host_root.sign(&cert.signing_input()).to_bytes().to_vec();
    cert
}

/// Verifies a host operating-key certificate chains to `expected_root_fp`, that
/// `sig_host_root` is valid, and `now` is within `exp` (A7b: `exp` 90 d; replay rule: n/a,
/// rotation).
pub fn verify_host_op_key_cert(
    cert: &HostOpKeyCert,
    host_root_pk: &VerifyingKey,
    expected_root_fp: &Fingerprint,
    now: u64,
) -> Result<(), ArtifactError> {
    if root_fp_of(host_root_pk) != *expected_root_fp {
        return Err(ArtifactError::RootFingerprintMismatch);
    }
    let sig = parse_signature(&cert.sig_host_root)?;
    host_root_pk
        .verify(&cert.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)?;
    check_exp(now, cert.exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_round_trip() {
        let host_root = RootKey::from_seed([0x21; 32]);
        let op_signing = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
        let op_pk = op_signing.verifying_key();
        let cert = issue_host_op_key_cert(
            &host_root,
            &op_pk,
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        verify_host_op_key_cert(&cert, &host_root.public_key(), &host_root.root_fp(), 1_500)
            .expect("valid cert");
    }

    #[test]
    fn rejects_wrong_root_fp() {
        let host_root = RootKey::from_seed([0x23; 32]);
        let other_root = RootKey::from_seed([0x24; 32]);
        let op_pk = ed25519_dalek::SigningKey::from_bytes(&[0x25; 32]).verifying_key();
        let cert = issue_host_op_key_cert(
            &host_root,
            &op_pk,
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        let err =
            verify_host_op_key_cert(&cert, &host_root.public_key(), &other_root.root_fp(), 1_500)
                .unwrap_err();
        assert_eq!(err, ArtifactError::RootFingerprintMismatch);
    }

    #[test]
    fn rejects_bad_signature() {
        let host_root = RootKey::from_seed([0x26; 32]);
        let op_pk = ed25519_dalek::SigningKey::from_bytes(&[0x27; 32]).verifying_key();
        let mut cert = issue_host_op_key_cert(
            &host_root,
            &op_pk,
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        cert.sig_host_root[0] ^= 0xff;
        let err =
            verify_host_op_key_cert(&cert, &host_root.public_key(), &host_root.root_fp(), 1_500)
                .unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_expired() {
        let host_root = RootKey::from_seed([0x28; 32]);
        let op_pk = ed25519_dalek::SigningKey::from_bytes(&[0x29; 32]).verifying_key();
        let cert = issue_host_op_key_cert(
            &host_root,
            &op_pk,
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        let err =
            verify_host_op_key_cert(&cert, &host_root.public_key(), &host_root.root_fp(), 2_001)
                .unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }
}
