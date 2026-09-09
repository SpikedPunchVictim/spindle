use super::{check_skew, parse_signature, ArtifactError};
use crate::fingerprint::Fingerprint;
use crate::identity::DeviceKey;
use ed25519_dalek::{Verifier, VerifyingKey};
use spindle_proto::artifacts::SessionAttestation;

/// A7b time rule for `SessionAttestation`: `ts` ±2 min against helper server time, the same
/// window as every other `ts` in this crate (mirrors [`super::admin_command::ADMIN_COMMAND_CLOCK_SKEW_SECS`]).
pub const SESSION_ATTESTATION_CLOCK_SKEW_SECS: u64 = 120;

/// Issues `sig_device(nats_fp, ts)` (DESIGN.md §A3/§A4 step 2/§A7b, added v0.9.29, td-0bcab4) —
/// the per-session attestation by which a device's **identity** key authorizes one NATS session
/// nkey.
///
/// This is the fix for td-0bcab4: before this artifact existed, `{root_pk, device_cert, caps}`
/// was a pure bearer bundle — the device identity key was never exercised at CONNECT, so anyone
/// holding a copy of the bundle could connect from any nkey. `sig_device(nats_fp, ts)` binds the
/// two together: a copy of the bundle is useless without also holding the identity signing key.
/// The callout still proves possession of the *session* nkey separately, via the server-nonce
/// signature, so the two signatures together bind identity to session.
///
/// Signer: the device's own identity (`sign`) key — not the root, and not the operating key of
/// any host. Time rule: `ts` ±2 min (see [`SESSION_ATTESTATION_CLOCK_SKEW_SECS`]). Replay rule:
/// n/a — the artifact carries no `nonce`; it is inert without the nkey secret it names, and the
/// callout proves possession of that nkey separately (the server-nonce signature above), so a
/// replayed `SessionAttestation` alone authorizes nothing. No `v` field — per §A7b the domain tag
/// `spindle-sess-attest-v1` is the version discriminant. No `exp` — the `ts` skew window above is
/// the sole time bound.
pub fn issue_session_attestation(
    device: &DeviceKey,
    nats_fp: Fingerprint,
    ts: u64,
) -> SessionAttestation {
    let mut attestation = SessionAttestation {
        nats_fp: nats_fp.to_vec(),
        ts,
        sig_device: Vec::new(),
    };
    attestation.sig_device = device
        .sign(&attestation.signing_input())
        .to_bytes()
        .to_vec();
    attestation
}

/// Verifies a session attestation: it names `expected_nats_fp`, `ts` is within the ±2 min skew
/// window, and `sig_device` is valid under `device_sign_pk` (DESIGN.md §A3/§A4 step 2/§A7b).
///
/// **`expected_nats_fp` is a required argument, deliberately and non-negotiably.** This function
/// exists (td-0bcab4) because a previous binding field — `DeviceCertificate.nats_fp` — was
/// carried on the wire and compared by nobody, which is exactly how the bundle
/// `{root_pk, device_cert, caps}` became a bearer token. A `verify_session_attestation(attestation,
/// device_sign_pk, now)` that returned `Ok` for a well-signed attestation naming somebody else's
/// session key would reproduce that defect exactly, one artifact later. There is no valid caller
/// that wants to verify the signature without checking the binding, so this API does not offer
/// one.
///
/// Checks run cheap-structural-before-crypto (§A6):
/// 1. `expected_nats_fp` vs `attestation.nats_fp` — a byte comparison, cheapest possible check and
///    the one this function exists to enforce. On mismatch: [`ArtifactError::SessionKeyMismatch`].
/// 2. Clock skew (`ts` ±2 min) — cheaper than a signature verification.
/// 3. `sig_device` — Ed25519 verification under `device_sign_pk`, last because it's the most
///    expensive check.
pub fn verify_session_attestation(
    attestation: &SessionAttestation,
    device_sign_pk: &VerifyingKey,
    expected_nats_fp: &Fingerprint,
    now: u64,
) -> Result<(), ArtifactError> {
    if !expected_nats_fp.matches(&attestation.nats_fp) {
        return Err(ArtifactError::SessionKeyMismatch);
    }
    check_skew(now, attestation.ts, SESSION_ATTESTATION_CLOCK_SKEW_SECS)?;
    let sig = parse_signature(&attestation.sig_device)?;
    device_sign_pk
        .verify(&attestation.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(seed: u8) -> DeviceKey {
        DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32])
    }

    fn nats_fp(byte: u8) -> Fingerprint {
        Fingerprint::of_parts(&[&[byte; 4]])
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let dev = device(0x60);
        let fp = nats_fp(0x01);
        let att = issue_session_attestation(&dev, fp, 1_000);
        verify_session_attestation(&att, &dev.sign_public_key(), &fp, 1_000)
            .expect("valid attestation");
    }

    /// Pins td-0bcab4 closed: a well-signed attestation that names a *different* session key than
    /// the one presenting it must be rejected. This is the exact shape of the original defect —
    /// `DeviceCertificate.nats_fp` was carried on the wire and compared by nobody — reproduced one
    /// artifact later were this check ever removed.
    #[test]
    fn rejects_wrong_nats_fp() {
        let dev = device(0x61);
        let signed_fp = nats_fp(0x02);
        let att = issue_session_attestation(&dev, signed_fp, 1_000);
        let connecting_fp = nats_fp(0x03);
        let err = verify_session_attestation(&att, &dev.sign_public_key(), &connecting_fp, 1_000)
            .unwrap_err();
        assert_eq!(err, ArtifactError::SessionKeyMismatch);
    }

    #[test]
    fn rejects_bad_signature() {
        let dev = device(0x62);
        let fp = nats_fp(0x04);
        let mut att = issue_session_attestation(&dev, fp, 1_000);
        att.sig_device[0] ^= 0xff;
        let err = verify_session_attestation(&att, &dev.sign_public_key(), &fp, 1_000).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    /// A well-formed attestation from device B, verified against device A's `sign_pk`: the
    /// signature does not belong to that key, so this must fail as a bad signature, not silently
    /// verify against the wrong identity.
    #[test]
    fn rejects_a_different_device_key() {
        let device_a = device(0x63);
        let device_b = device(0x64);
        let fp = nats_fp(0x05);
        let att = issue_session_attestation(&device_b, fp, 1_000);
        let err =
            verify_session_attestation(&att, &device_a.sign_public_key(), &fp, 1_000).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_ts_too_far_in_the_past() {
        let dev = device(0x65);
        let fp = nats_fp(0x06);
        let att = issue_session_attestation(&dev, fp, 1_000);
        let now = 1_000 + SESSION_ATTESTATION_CLOCK_SKEW_SECS + 1;
        let err = verify_session_attestation(&att, &dev.sign_public_key(), &fp, now).unwrap_err();
        assert_eq!(err, ArtifactError::TimestampSkew);
    }

    #[test]
    fn rejects_ts_too_far_in_the_future() {
        let dev = device(0x66);
        let fp = nats_fp(0x07);
        let ts = 10_000;
        let att = issue_session_attestation(&dev, fp, ts);
        let now = ts - SESSION_ATTESTATION_CLOCK_SKEW_SECS - 1;
        let err = verify_session_attestation(&att, &dev.sign_public_key(), &fp, now).unwrap_err();
        assert_eq!(err, ArtifactError::TimestampSkew);
    }

    #[test]
    fn accepts_ts_exactly_at_the_skew_boundary() {
        let dev = device(0x67);
        let fp = nats_fp(0x08);
        let ts = 10_000;
        let att = issue_session_attestation(&dev, fp, ts);

        let now_late = ts + SESSION_ATTESTATION_CLOCK_SKEW_SECS;
        verify_session_attestation(&att, &dev.sign_public_key(), &fp, now_late)
            .expect("+120s boundary must be accepted");

        let now_early = ts - SESSION_ATTESTATION_CLOCK_SKEW_SECS;
        verify_session_attestation(&att, &dev.sign_public_key(), &fp, now_early)
            .expect("-120s boundary must be accepted");
    }
}
