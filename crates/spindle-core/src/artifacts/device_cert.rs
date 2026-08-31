use super::{check_exp, parse_signature, parse_verifying_key, ArtifactError};
use crate::fingerprint::Fingerprint;
use crate::identity::{self, device_fp_of, root_fp_of, RootKey};
use ed25519_dalek::{Verifier, VerifyingKey};
use spindle_proto::artifacts::DeviceCertificate;
use x25519_dalek::PublicKey as X25519PublicKey;

/// Issues `sig_root(device_fp, alg_id, sign_pk, agree_pk, nats_fp, ts)` (DESIGN.md §A4, as
/// amended v0.9.16 A10.34) — only an identity root may sign a device certificate ("secondary
/// devices cannot mint devices").
///
/// `device_fp` is derived here from `(alg_id, sign_pk, agree_pk)` via
/// [`crate::identity::device_fp_of`] rather than accepted from the caller: an inconsistent
/// certificate (one whose `device_fp` does not match its own preimage) is unconstructible through
/// this API.
pub fn issue_device_certificate(
    root: &RootKey,
    alg_id: u8,
    sign_pk: &VerifyingKey,
    agree_pk: &X25519PublicKey,
    nats_fp: Fingerprint,
    ts: u64,
    exp: u64,
) -> DeviceCertificate {
    let device_fp = device_fp_of(alg_id, sign_pk, agree_pk);
    let mut cert = DeviceCertificate {
        device_fp: device_fp.to_vec(),
        alg_id,
        sign_pk: sign_pk.as_bytes().to_vec(),
        agree_pk: agree_pk.as_bytes().to_vec(),
        nats_fp: nats_fp.to_vec(),
        ts,
        exp,
        sig_root: Vec::new(),
    };
    cert.sig_root = root.sign(&cert.signing_input()).to_bytes().to_vec();
    cert
}

/// Verifies a device certificate: `alg_id` is supported, `sign_pk`/`agree_pk` parse, the
/// certificate's own `device_fp` matches the recomputed fingerprint of its
/// `(alg_id, sign_pk, agree_pk)` (§A7b clarification 6 — the binding this v0.9.16 change exists
/// to enforce), it chains to `expected_root_fp` under `root_pk`, `sig_root` is valid, and `now` is
/// within `exp` (A7b time rule: `exp` 1 y, re-signed on contact; replay rule: n/a, revocable).
///
/// Checks run cheap-structural-before-crypto (§A6): `alg_id` first (nothing else can even be
/// interpreted if it's wrong), then key parsing, then the `device_fp` binding recompute, and only
/// then the root-fingerprint/signature/`exp` checks.
pub fn verify_device_certificate(
    cert: &DeviceCertificate,
    root_pk: &VerifyingKey,
    expected_root_fp: &Fingerprint,
    now: u64,
) -> Result<(), ArtifactError> {
    if cert.alg_id != identity::ALG_ID_V1 {
        return Err(ArtifactError::UnsupportedAlgId);
    }
    let sign_pk = parse_verifying_key(&cert.sign_pk)?;
    let agree_pk_bytes: [u8; 32] = cert
        .agree_pk
        .as_slice()
        .try_into()
        .map_err(|_| ArtifactError::InvalidPublicKey)?;
    let agree_pk = X25519PublicKey::from(agree_pk_bytes);

    let recomputed_device_fp = device_fp_of(cert.alg_id, &sign_pk, &agree_pk);
    if !recomputed_device_fp.matches(&cert.device_fp) {
        return Err(ArtifactError::DeviceFingerprintMismatch);
    }

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
    use crate::identity::DeviceKey;

    /// A real, self-consistent device identity for tests — `issue_device_certificate` derives
    /// `device_fp` from these keys, so a genuinely valid certificate needs a genuine `DeviceKey`
    /// rather than a fabricated fingerprint (an inconsistent one can no longer be constructed
    /// through the issuing API at all).
    fn device(seed: u8) -> DeviceKey {
        DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let root = RootKey::from_seed([0x01; 32]);
        let dev = device(0x50);
        let nats_fp = Fingerprint::of_parts(&[b"nats"]);
        let cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            nats_fp,
            1_000,
            2_000,
        );
        verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .expect("valid certificate");
    }

    #[test]
    fn rejects_tampered_device_fp() {
        let root = RootKey::from_seed([0x02; 32]);
        let dev = device(0x51);
        let mut cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        // Tamper device_fp only — sig_root still covers the original (now-mismatched) value, so
        // this certificate is ALSO badly signed. That means this test cannot, by itself, prove the
        // binding recompute exists: deleting that check would still fail here on the signature
        // check. See `rejects_correctly_signed_but_inconsistent_certificate` below for the test
        // that isolates the binding check by keeping the signature genuinely valid.
        cert.device_fp = Fingerprint::of_parts(&[b"not-the-real-device-fp"]).to_vec();
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .unwrap_err();
        assert_eq!(err, ArtifactError::DeviceFingerprintMismatch);
    }

    #[test]
    fn rejects_sign_pk_swapped_for_another_valid_key() {
        let root = RootKey::from_seed([0x03; 32]);
        let dev = device(0x52);
        let other = device(0x53);
        let mut cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        // Swap in a different, perfectly valid Ed25519 key — device_fp is left alone, so it now
        // commits to `dev`'s sign_pk while the certificate carries `other`'s.
        cert.sign_pk = other.sign_public_key().as_bytes().to_vec();
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .unwrap_err();
        assert_eq!(err, ArtifactError::DeviceFingerprintMismatch);
    }

    #[test]
    fn rejects_agree_pk_swapped_for_another_valid_key() {
        let root = RootKey::from_seed([0x04; 32]);
        let dev = device(0x54);
        let other = device(0x55);
        let mut cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        cert.agree_pk = other.agree_public_key().as_bytes().to_vec();
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .unwrap_err();
        assert_eq!(err, ArtifactError::DeviceFingerprintMismatch);
    }

    /// The three tests above (`rejects_tampered_device_fp`, `rejects_sign_pk_swapped_...`,
    /// `rejects_agree_pk_swapped_...`) all mutate a certificate *after* `issue_device_certificate`
    /// signed it. In every one of those, `sig_root` still covers the pre-mutation bytes, so
    /// `verify_device_certificate` would reject them on the signature check alone even if the
    /// `device_fp` recompute-and-compare in `verify_device_certificate` were deleted entirely.
    /// They exercise the signature check, not the binding check, and give no coverage of the
    /// latter.
    ///
    /// This test isolates the binding check: it builds a `DeviceCertificate` whose `device_fp`
    /// names device A while `(alg_id, sign_pk, agree_pk)` are device B's, and then signs *that*
    /// exact, internally-inconsistent content with a real root key — exactly as
    /// `issue_device_certificate` would sign genuine content. `sig_root` is therefore completely
    /// valid over the certificate's bytes; the only thing wrong with the certificate is the
    /// device_fp/key binding. `issue_device_certificate` can never produce this shape (it derives
    /// `device_fp` from the keys itself), so the literal must be constructed by hand here.
    ///
    /// Why it matters: envelope verification pins peers by `device_fp`. A root that is malicious,
    /// or merely buggy, could issue exactly this certificate. Without the recompute check, device
    /// B would present device A's `device_fp` and be accepted as device A — full impersonation —
    /// while still holding and using its own (B's) signing and agreement keys.
    #[test]
    fn rejects_correctly_signed_but_inconsistent_certificate() {
        let root = RootKey::from_seed([0x05; 32]);
        let device_a = device(0x5c);
        let device_b = device(0x5d);

        let mut cert = DeviceCertificate {
            device_fp: device_a.device_fp().to_vec(),
            alg_id: device_b.alg_id(),
            sign_pk: device_b.sign_public_key().as_bytes().to_vec(),
            agree_pk: device_b.agree_public_key().as_bytes().to_vec(),
            nats_fp: Fingerprint::of_parts(&[b"n"]).to_vec(),
            ts: 1_000,
            exp: 2_000,
            sig_root: Vec::new(),
        };
        // Sign the exact (inconsistent) content above, the same way issue_device_certificate does
        // — sig_root is therefore genuinely valid over this certificate's bytes.
        cert.sig_root = root.sign(&cert.signing_input()).to_bytes().to_vec();

        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .unwrap_err();
        assert_eq!(err, ArtifactError::DeviceFingerprintMismatch);
    }

    #[test]
    fn rejects_unsupported_alg_id() {
        let root = RootKey::from_seed([0x06; 32]);
        let dev = device(0x56);
        let mut cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        cert.alg_id = 2;
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .unwrap_err();
        assert_eq!(err, ArtifactError::UnsupportedAlgId);
    }

    #[test]
    fn rejects_wrong_length_sign_pk() {
        let root = RootKey::from_seed([0x07; 32]);
        let dev = device(0x57);
        let mut cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        cert.sign_pk = vec![0x01; 31]; // one byte short
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .unwrap_err();
        assert_eq!(err, ArtifactError::InvalidPublicKey);
    }

    #[test]
    fn rejects_wrong_length_agree_pk() {
        let root = RootKey::from_seed([0x08; 32]);
        let dev = device(0x58);
        let mut cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        cert.agree_pk = vec![0x02; 33]; // one byte long
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 1_500)
            .unwrap_err();
        assert_eq!(err, ArtifactError::InvalidPublicKey);
    }

    #[test]
    fn rejects_wrong_root_fp() {
        let root = RootKey::from_seed([0x09; 32]);
        let other_root = RootKey::from_seed([0x0a; 32]);
        let dev = device(0x59);
        let cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
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
        let root = RootKey::from_seed([0x0b; 32]);
        let dev = device(0x5a);
        let mut cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
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
        let root = RootKey::from_seed([0x0c; 32]);
        let dev = device(0x5b);
        let cert = issue_device_certificate(
            &root,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            Fingerprint::of_parts(&[b"n"]),
            1_000,
            2_000,
        );
        let err = verify_device_certificate(&cert, &root.public_key(), &root.root_fp(), 2_001)
            .unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }
}
