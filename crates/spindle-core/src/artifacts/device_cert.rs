use super::{check_exp, parse_signature, ArtifactError};
use crate::fingerprint::Fingerprint;
use crate::identity::{root_fp_of, RootKey};
use ed25519_dalek::{Verifier, VerifyingKey};
use spindle_proto::artifacts::DeviceCertificate;

/// Issues `sig_root(device_fp, nats_fp, ts, exp)` (DESIGN.md §A4) — only an identity root may
/// sign a device certificate ("secondary devices cannot mint devices").
pub fn issue_device_certificate(
    root: &RootKey,
    device_fp: Fingerprint,
    nats_fp: Fingerprint,
    ts: u64,
    exp: u64,
) -> DeviceCertificate {
    let mut cert = DeviceCertificate {
        device_fp: device_fp.to_vec(),
        nats_fp: nats_fp.to_vec(),
        ts,
        exp,
        sig_root: Vec::new(),
    };
    cert.sig_root = root.sign(&cert.signing_input()).to_bytes().to_vec();
    cert
}

/// Verifies a device certificate chains to `expected_root_fp` under `root_pk`, that `sig_root`
/// is valid, and that `now` is within `exp` (A7b time rule: `exp` 1 y, re-signed on contact;
/// replay rule: n/a, revocable).
pub fn verify_device_certificate(
    cert: &DeviceCertificate,
    root_pk: &VerifyingKey,
    expected_root_fp: &Fingerprint,
    now: u64,
) -> Result<(), ArtifactError> {
    if root_fp_of(root_pk) != *expected_root_fp {
        return Err(ArtifactError::RootFingerprintMismatch);
    }
    let sig = parse_signature(&cert.sig_root)?;
    root_pk
        .verify(&cert.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)?;
    check_exp(now, cert.exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify_round_trip() {
        let root = RootKey::from_seed([0x01; 32]);
        let device_fp = Fingerprint::of_parts(&[b"device"]);
        let nats_fp = Fingerprint::of_parts(&[b"nats"]);
        let cert = issue_device_certificate(&root, device_fp, nats_fp, 1_000, 2_000);
        verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .expect("valid certificate");
    }

    #[test]
    fn rejects_wrong_root_fp() {
        let root = RootKey::from_seed([0x02; 32]);
        let other_root = RootKey::from_seed([0x03; 32]);
        let cert = issue_device_certificate(
            &root,
            Fingerprint::of_parts(&[b"d"]),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        let err =
            verify_device_certificate(&cert, &root.public_key(), &other_root.root_fp(), 1_500)
                .unwrap_err();
        assert_eq!(err, ArtifactError::RootFingerprintMismatch);
    }

    #[test]
    fn rejects_bad_signature() {
        let root = RootKey::from_seed([0x04; 32]);
        let mut cert = issue_device_certificate(
            &root,
            Fingerprint::of_parts(&[b"d"]),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        cert.sig_root[0] ^= 0xff;
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_expired() {
        let root = RootKey::from_seed([0x05; 32]);
        let cert = issue_device_certificate(
            &root,
            Fingerprint::of_parts(&[b"d"]),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 2_001)
            .unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }
}
