use super::{
    check_exp, parse_signature, parse_verifying_key, verify_host_op_key_cert, ArtifactError,
};
use crate::fingerprint::Fingerprint;
use crate::identity::{self, device_fp_of};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use spindle_proto::artifacts::{HostDeviceCert, HostOpKeyCert};
use x25519_dalek::PublicKey as X25519PublicKey;

/// Issues `sig_host_op(host_fp, host_root_pk, op_cert, host_device_fp, alg_id, sign_pk, agree_pk,
/// ts, exp)` (DESIGN.md §A4, decision A10.35) — the host **operating** key certifying the host's
/// dedicated envelope-identity device key, chaining root → op → device. `op_signer` (here
/// `host_op`) is expected to be the same operating key `op_cert` certifies — the caller is
/// responsible for that (this function does not cross-check the two, mirroring
/// [`super::issue_capability`]'s `op_signer` discipline: a mismatch here simply produces a
/// certificate that fails [`verify_host_device_cert`]'s step 7, not a panic).
///
/// `host_device_fp` is derived here from `(alg_id, sign_pk, agree_pk)` via
/// [`crate::identity::device_fp_of`] rather than accepted from the caller, mirroring
/// [`super::issue_device_certificate`]'s discipline: an inconsistent certificate (one whose
/// `host_device_fp` does not match its own preimage) is unconstructible through this API.
#[allow(clippy::too_many_arguments)]
pub fn issue_host_device_cert(
    host_op: &SigningKey,
    host_fp: Fingerprint,
    host_root_pk: &VerifyingKey,
    op_cert: &HostOpKeyCert,
    alg_id: u8,
    sign_pk: &VerifyingKey,
    agree_pk: &X25519PublicKey,
    ts: u64,
    exp: u64,
) -> HostDeviceCert {
    let host_device_fp = device_fp_of(alg_id, sign_pk, agree_pk);
    let mut cert = HostDeviceCert {
        host_fp: host_fp.to_vec(),
        host_root_pk: host_root_pk.as_bytes().to_vec(),
        op_cert: op_cert.to_canonical_bytes(),
        host_device_fp: host_device_fp.to_vec(),
        alg_id,
        sign_pk: sign_pk.as_bytes().to_vec(),
        agree_pk: agree_pk.as_bytes().to_vec(),
        ts,
        exp,
        sig_host_op: Vec::new(),
    };
    cert.sig_host_op = host_op.sign(&cert.signing_input()).to_bytes().to_vec();
    cert
}

/// Verifies a host device certificate's full root → operating-key → device chain (DESIGN.md §A4,
/// decision A10.35): self-verifying exactly like [`super::verify_capability`] (decision A10.30) —
/// no external root or registry lookup needed beyond the certificate's own embedded fields.
///
/// **Deliberately stricter than [`super::verify_capability`]**: `expected_host_fp` is a
/// **required** parameter here, not left to the caller to check separately. A client fetches this
/// certificate from the helper (`helper.devcert.get.<nfp>`) specifically to learn the host's
/// envelope identity, and it already pinned `host_fp` at enrollment — making the pin check a
/// required argument means a caller cannot forget to verify the certificate actually names the
/// host it thinks it is talking to. `verify_capability` has no equivalent parameter because a
/// capability's `host_fp` typically *is* the value the caller is trying to look up, not a value
/// it already holds and must cross-check.
///
/// Checks run cheap-structural-before-crypto (§A6), in this order:
/// 1. `alg_id` is a supported suite.
/// 2. `sign_pk` parses as Ed25519; `agree_pk` is exactly 32 bytes.
/// 3. `host_device_fp` recomputed from `(alg_id, sign_pk, agree_pk)` matches the certificate's own
///    field (§A7b clarification 6's binding discipline, mirrored from `DeviceCertificate`/A10.34).
/// 4. `host_fp` matches the caller's pinned `expected_host_fp`.
/// 5. `host_fp == SHA-256(host_root_pk)` — self-consistency of the certificate's own fields (the
///    same check [`super::verify_capability`]'s step 1 performs).
/// 6. The embedded `op_cert` decodes as a [`HostOpKeyCert`] and chains to `host_root_pk`
///    (including its own `exp`), via [`verify_host_op_key_cert`].
/// 7. `sig_host_op` verifies under the op cert's own certified operating key.
/// 8. `now` is within `exp`.
pub fn verify_host_device_cert(
    cert: &HostDeviceCert,
    expected_host_fp: &Fingerprint,
    now: u64,
) -> Result<(), ArtifactError> {
    // 1. alg_id supported.
    if cert.alg_id != identity::ALG_ID_V1 {
        return Err(ArtifactError::UnsupportedAlgId);
    }

    // 2. sign_pk / agree_pk parse.
    let sign_pk = parse_verifying_key(&cert.sign_pk)?;
    let agree_pk_bytes: [u8; 32] = cert
        .agree_pk
        .as_slice()
        .try_into()
        .map_err(|_| ArtifactError::InvalidPublicKey)?;
    let agree_pk = X25519PublicKey::from(agree_pk_bytes);

    // 3. host_device_fp binding — recompute from the certificate's own preimage.
    let recomputed_device_fp = device_fp_of(cert.alg_id, &sign_pk, &agree_pk);
    if !recomputed_device_fp.matches(&cert.host_device_fp) {
        return Err(ArtifactError::DeviceFingerprintMismatch);
    }

    // 4. host_fp matches the caller's pinned expectation (required parameter — see doc comment).
    if !expected_host_fp.matches(&cert.host_fp) {
        return Err(ArtifactError::HostFingerprintMismatch);
    }

    // 5. host_fp is self-consistent with the embedded host_root_pk.
    let host_root_pk = parse_verifying_key(&cert.host_root_pk)?;
    let recomputed_host_fp = Fingerprint::of_parts(&[host_root_pk.as_bytes()]);
    if !recomputed_host_fp.matches(&cert.host_fp) {
        return Err(ArtifactError::HostFingerprintMismatch);
    }
    let host_fp = Fingerprint::from_slice(&cert.host_fp)
        .map_err(|_| ArtifactError::HostFingerprintMismatch)?;

    // 6. Decode + verify the embedded op cert chains to host_root_pk, including its own exp.
    let op_cert = HostOpKeyCert::from_canonical_bytes(&cert.op_cert)
        .map_err(|_| ArtifactError::MalformedOpCert)?;
    verify_host_op_key_cert(&op_cert, &host_root_pk, &host_fp, now)?;

    // 7. sig_host_op verifies under the op cert's own certified operating key.
    let op_pk = parse_verifying_key(&op_cert.host_op_pk)?;
    let sig = parse_signature(&cert.sig_host_op)?;
    op_pk
        .verify(&cert.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)?;

    // 8. exp check.
    check_exp(now, cert.exp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::issue_host_op_key_cert;
    use crate::identity::{DeviceKey, RootKey};

    /// A full test host: identity root + operating key + the root's certificate for that
    /// operating key — same shape as `capability.rs`'s `TestHost`.
    struct TestHost {
        root: RootKey,
        op_signer: SigningKey,
        op_cert: HostOpKeyCert,
    }

    fn test_host(root_seed: [u8; 32], op_seed: [u8; 32], op_cert_exp: u64) -> TestHost {
        let root = RootKey::from_seed(root_seed);
        let op_signer = SigningKey::from_bytes(&op_seed);
        let op_cert = issue_host_op_key_cert(
            &root,
            &op_signer.verifying_key(),
            Fingerprint::of_parts(&[b"host-device-cert-test:nats"]),
            0,
            op_cert_exp,
        );
        TestHost {
            root,
            op_signer,
            op_cert,
        }
    }

    /// A real, self-consistent host device identity for tests — `issue_host_device_cert` derives
    /// `host_device_fp` from these keys, so a genuinely valid certificate needs a genuine
    /// `DeviceKey` rather than a fabricated fingerprint.
    fn host_device(seed: u8) -> DeviceKey {
        DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
    }

    fn issue(host: &TestHost, dev: &DeviceKey, ts: u64, exp: u64) -> HostDeviceCert {
        issue_host_device_cert(
            &host.op_signer,
            host.root.root_fp(),
            &host.root.public_key(),
            &host.op_cert,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            ts,
            exp,
        )
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let dev = host_device(0x60);
        let cert = issue(&host, &dev, 1_000, 2_000);
        verify_host_device_cert(&cert, &host.root.root_fp(), 1_500)
            .expect("valid host device certificate: full chain round-trip");
    }

    #[test]
    fn rejects_unsupported_alg_id() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let dev = host_device(0x61);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        cert.alg_id = 2;
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::UnsupportedAlgId);
    }

    #[test]
    fn rejects_wrong_length_sign_pk() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let dev = host_device(0x62);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        cert.sign_pk = vec![0x01; 31]; // one byte short
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::InvalidPublicKey);
    }

    #[test]
    fn rejects_wrong_length_agree_pk() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let dev = host_device(0x63);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        cert.agree_pk = vec![0x02; 33]; // one byte long
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::InvalidPublicKey);
    }

    #[test]
    fn rejects_tampered_host_device_fp() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let dev = host_device(0x64);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        // Tamper host_device_fp only — sig_host_op still covers the original (now-mismatched)
        // value, so this certificate is ALSO badly signed. Like `device_cert.rs`'s equivalent
        // test, this alone cannot prove the binding recompute exists: deleting that check would
        // still fail here, just on the signature check instead. See
        // `rejects_correctly_signed_but_inconsistent_certificate` below for the test that
        // isolates the binding check by keeping the signature genuinely valid.
        cert.host_device_fp = Fingerprint::of_parts(&[b"not-the-real-host-device-fp"]).to_vec();
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::DeviceFingerprintMismatch);
    }

    #[test]
    fn rejects_sign_pk_swapped_for_another_valid_key() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let dev = host_device(0x65);
        let other = host_device(0x66);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        // Swap in a different, perfectly valid Ed25519 key — host_device_fp is left alone, so it
        // now commits to `dev`'s sign_pk while the certificate carries `other`'s.
        cert.sign_pk = other.sign_public_key().as_bytes().to_vec();
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::DeviceFingerprintMismatch);
    }

    #[test]
    fn rejects_agree_pk_swapped_for_another_valid_key() {
        let host = test_host([0x11; 32], [0x12; 32], 10_000);
        let dev = host_device(0x67);
        let other = host_device(0x68);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        cert.agree_pk = other.agree_public_key().as_bytes().to_vec();
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::DeviceFingerprintMismatch);
    }

    /// **The most important test in this module.** The three tests above all mutate a certificate
    /// *after* `issue_host_device_cert` signed it, so `sig_host_op` still covers the pre-mutation
    /// bytes and each would be rejected on the signature check alone even if the `host_device_fp`
    /// recompute-and-compare in `verify_host_device_cert` (step 3) were deleted entirely. They
    /// exercise the signature check, not the binding check, and give no real coverage of it.
    ///
    /// This test isolates the binding check: it builds a `HostDeviceCert` whose `host_device_fp`
    /// names host device A while `(alg_id, sign_pk, agree_pk)` are host device B's, and then signs
    /// *that* exact, internally-inconsistent content with a real, valid host operating key —
    /// exactly as `issue_host_device_cert` would sign genuine content. `sig_host_op` is therefore
    /// completely valid over the certificate's bytes; the only thing wrong with the certificate is
    /// the host_device_fp/key binding. `issue_host_device_cert` can never produce this shape (it
    /// derives `host_device_fp` from the keys itself), so the literal must be constructed by hand
    /// here.
    ///
    /// Why it matters: envelope verification pins the host's peer identity by `device_fp`
    /// (DESIGN.md §A4/A10.35: the host device fingerprint *is* the host's §A7 envelope identity).
    /// A host op key that is malicious, or merely buggy, could issue exactly this certificate.
    /// Without the recompute check, host device B would present host device A's `host_device_fp`
    /// and be accepted as the host's envelope identity A — full impersonation of the host — while
    /// still holding and using its own (B's) signing and agreement keys.
    #[test]
    fn rejects_correctly_signed_but_inconsistent_certificate() {
        let host = test_host([0x13; 32], [0x14; 32], 10_000);
        let device_a = host_device(0x6c);
        let device_b = host_device(0x6d);

        let mut cert = HostDeviceCert {
            host_fp: host.root.root_fp().to_vec(),
            host_root_pk: host.root.public_key().as_bytes().to_vec(),
            op_cert: host.op_cert.to_canonical_bytes(),
            host_device_fp: device_a.device_fp().to_vec(),
            alg_id: device_b.alg_id(),
            sign_pk: device_b.sign_public_key().as_bytes().to_vec(),
            agree_pk: device_b.agree_public_key().as_bytes().to_vec(),
            ts: 1_000,
            exp: 2_000,
            sig_host_op: Vec::new(),
        };
        // Sign the exact (inconsistent) content above, the same way issue_host_device_cert does —
        // sig_host_op is therefore genuinely valid over this certificate's bytes.
        cert.sig_host_op = host
            .op_signer
            .sign(&cert.signing_input())
            .to_bytes()
            .to_vec();

        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::DeviceFingerprintMismatch);
    }

    #[test]
    fn rejects_host_fp_not_the_expected_pinned_fp() {
        // The certificate is fully valid and self-consistent (host_fp really is
        // SHA-256(host_root_pk), the chain and signature are genuine) — but the caller pinned a
        // DIFFERENT host_fp than the one this certificate declares. A client that fetched this
        // certificate for a host it did not intend to talk to must reject it.
        let host = test_host([0x15; 32], [0x16; 32], 10_000);
        let dev = host_device(0x69);
        let cert = issue(&host, &dev, 1_000, 2_000);

        let other_host_fp = RootKey::from_seed([0x99; 32]).root_fp();
        let err = verify_host_device_cert(&cert, &other_host_fp, 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::HostFingerprintMismatch);
    }

    #[test]
    fn rejects_tampered_host_root_pk() {
        // host_fp is unchanged, but host_root_pk is swapped for a *different* (validly-encoded)
        // root's public key — SHA-256(host_root_pk) no longer matches the declared host_fp. Mirrors
        // `capability.rs`'s `rejects_tampered_root_pk`.
        let host = test_host([0x17; 32], [0x18; 32], 10_000);
        let dev = host_device(0x6a);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        let other_root = RootKey::from_seed([0x9a; 32]);
        cert.host_root_pk = other_root.public_key().as_bytes().to_vec();
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::HostFingerprintMismatch);
    }

    #[test]
    fn rejects_malformed_op_cert() {
        let host = test_host([0x19; 32], [0x1a; 32], 10_000);
        let dev = host_device(0x6b);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        cert.op_cert = vec![0xff; 4]; // not valid canonical CBOR
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::MalformedOpCert);
    }

    #[test]
    fn rejects_op_cert_signed_by_wrong_root() {
        // The op cert is validly signed, but by a DIFFERENT root than the one the certificate
        // declares as host_root_pk — so verify_host_op_key_cert's own signature check must fail
        // when re-run against the declared host_root_pk. Mirrors `capability.rs`'s
        // `rejects_op_cert_signed_by_wrong_root`.
        let real_host = test_host([0x1b; 32], [0x1c; 32], 10_000);
        let impostor_root = RootKey::from_seed([0x7a; 32]);
        let dev = host_device(0x6e);
        let cert = issue_host_device_cert(
            &real_host.op_signer,
            impostor_root.root_fp(), // host_fp/host_root_pk declare the impostor root...
            &impostor_root.public_key(),
            &real_host.op_cert, // ...but op_cert was actually signed by real_host's root
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            1_000,
            2_000,
        );
        let err = verify_host_device_cert(&cert, &impostor_root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_sig_by_non_certified_key() {
        // The op cert genuinely certifies host.op_signer, but the certificate is signed by some
        // other key instead — step 7 must reject even though steps 1-6 all pass.
        let host = test_host([0x1d; 32], [0x1e; 32], 10_000);
        let impostor_signer = SigningKey::from_bytes(&[0x6f; 32]);
        let dev = host_device(0x70);
        let cert = issue_host_device_cert(
            &impostor_signer, // not the key op_cert.host_op_pk names
            host.root.root_fp(),
            &host.root.public_key(),
            &host.op_cert,
            dev.alg_id(),
            &dev.sign_public_key(),
            &dev.agree_public_key(),
            1_000,
            2_000,
        );
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_bad_signature() {
        let host = test_host([0x1f; 32], [0x2a; 32], 10_000);
        let dev = host_device(0x71);
        let mut cert = issue(&host, &dev, 1_000, 2_000);
        cert.sig_host_op[0] ^= 0xff;
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_expired() {
        let host = test_host([0x2b; 32], [0x2c; 32], 10_000);
        let dev = host_device(0x72);
        let cert = issue(&host, &dev, 1_000, 2_000);
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 2_001).unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }

    #[test]
    fn rejects_expired_op_cert() {
        // op_cert itself expires at 1_000, well before the certificate's own exp (2_000) — step 6
        // of the chain must catch this even though the certificate's own exp check would pass.
        let host = test_host([0x2d; 32], [0x2e; 32], 1_000);
        let dev = host_device(0x73);
        let cert = issue(&host, &dev, 0, 2_000);
        let err = verify_host_device_cert(&cert, &host.root.root_fp(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }
}
