use super::{check_skew, parse_signature, ArtifactError};
use crate::fingerprint::Fingerprint;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use spindle_proto::artifacts::HostSessionAttestation;

/// A7b time rule for `HostSessionAttestation`: `ts` ±2 min against helper server time, the same
/// window as every other `ts` in this crate (mirrors its device-side twin,
/// [`super::session_attest::SESSION_ATTESTATION_CLOCK_SKEW_SECS`]).
pub const HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS: u64 = 120;

/// Issues `sig_op(nats_fp, ts)` (DESIGN.md §A4 step 3/§A7b, added v0.9.31, td-583db5) — the
/// per-connect attestation by which a host's **operating** key authorizes one NATS session nkey.
///
/// This is the host-side mirror of [`super::session_attest::issue_session_attestation`]
/// (td-0bcab4, added v0.9.29): `HostOpKeyCert` used to carry a `nats_fp` field meant to bind a
/// host's operating key to the NATS session it would connect with, but `verify_host_op_key_cert`
/// never read it — the same shape of defect td-0bcab4 closed for `DeviceCertificate.nats_fp`, one
/// artifact over. `HostSessionAttestation` moves that binding into its own artifact, signed fresh
/// at CONNECT time rather than baked into the long-lived issuance certificate: `HostOpKeyCert` now
/// carries no `nats_fp` at all (`spindle-host-cert-v1` → `spindle-host-cert-v2`; see
/// [`super::issue_host_op_key_cert`]'s doc comment), so the issuance chain and the per-connect
/// binding are two artifacts that cannot be confused for one another again.
///
/// Signer: the host's own **operating** key — not the host root. DESIGN.md §A4 keeps the host
/// root cold; the operating key is warm by design because it already signs every `Capability`
/// (decision A10.30) and `HostDeviceCert` (decision A10.35), and that is what makes a *per-connect*
/// host artifact possible at all — a root-signed one would need the cold key on every connect.
/// Time rule: `ts` ±2 min (see [`HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS`]). Replay rule: n/a —
/// the artifact carries no `nonce`; it is inert without the nkey secret it names, and the callout
/// proves possession of that nkey separately (the server-nonce signature), so a replayed
/// `HostSessionAttestation` alone authorizes nothing. No `v` field — per §A7b the domain tag
/// `spindle-host-sess-attest-v1` is the version discriminant. No `exp` — the `ts` skew window
/// above is the sole time bound.
pub fn issue_host_session_attestation(
    op_signing: &SigningKey,
    nats_fp: Fingerprint,
    ts: u64,
) -> HostSessionAttestation {
    let mut attestation = HostSessionAttestation {
        nats_fp: nats_fp.to_vec(),
        ts,
        sig_op: Vec::new(),
    };
    attestation.sig_op = op_signing
        .sign(&attestation.signing_input())
        .to_bytes()
        .to_vec();
    attestation
}

/// Verifies a host session attestation: it names `expected_nats_fp`, `ts` is within the ±2 min
/// skew window, and `sig_op` is valid under `host_op_pk` (DESIGN.md §A4 step 3/§A7b).
///
/// **`expected_nats_fp` is a required argument, deliberately and non-negotiably.** This function
/// exists (td-583db5) because the field it replaces — `HostOpKeyCert.nats_fp` — *was* compared
/// against the connecting session, but by exactly one manual byte comparison at exactly one call
/// site (`spindle-helper::authz::decide_host_connect`), whose own comment noted that no other
/// caller did the same check. That is one level less protected than the device path
/// ([`super::verify_session_attestation`]): there, the binding is a required argument no caller
/// can omit; here, the binding was one helper function's discipline away from silently not
/// happening at all — the exact bearer-token shape td-0bcab4 closed for
/// `DeviceCertificate.nats_fp`, reproduced with a thinner margin one layer down. A
/// `verify_host_session_attestation(attestation, host_op_pk, now)` that returned `Ok` for a
/// well-signed attestation naming somebody else's session key would still be strictly worse than
/// that one manual comparison, not merely no better. There is no valid caller that wants to verify
/// the signature without checking the binding, so this API does not offer one.
///
/// Checks run cheap-structural-before-crypto (§A6):
/// 1. `expected_nats_fp` vs `attestation.nats_fp` — a byte comparison, cheapest possible check and
///    the one this function exists to enforce. On mismatch: [`ArtifactError::HostSessionKeyMismatch`].
/// 2. Clock skew (`ts` ±2 min) — cheaper than a signature verification.
/// 3. `sig_op` — Ed25519 verification under `host_op_pk`, last because it's the most expensive
///    check.
pub fn verify_host_session_attestation(
    attestation: &HostSessionAttestation,
    host_op_pk: &VerifyingKey,
    expected_nats_fp: &Fingerprint,
    now: u64,
) -> Result<(), ArtifactError> {
    if !expected_nats_fp.matches(&attestation.nats_fp) {
        return Err(ArtifactError::HostSessionKeyMismatch);
    }
    check_skew(
        now,
        attestation.ts,
        HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS,
    )?;
    let sig = parse_signature(&attestation.sig_op)?;
    host_op_pk
        .verify(&attestation.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op_signing(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn nats_fp(byte: u8) -> Fingerprint {
        Fingerprint::of_parts(&[&[byte; 4]])
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let op = op_signing(0xA0);
        let fp = nats_fp(0xC1);
        let att = issue_host_session_attestation(&op, fp, 1_000);
        verify_host_session_attestation(&att, &op.verifying_key(), &fp, 1_000)
            .expect("valid attestation");
    }

    /// Pins td-583db5 closed: a well-signed attestation that names a *different* session key than
    /// the one presenting it must be rejected. This is the exact shape of the original defect —
    /// `HostOpKeyCert.nats_fp` was compared by exactly one caller, and no other — reproduced with
    /// the required-argument fix `verify_session_attestation` already applies on the device side.
    #[test]
    fn rejects_wrong_nats_fp() {
        let op = op_signing(0xA1);
        let signed_fp = nats_fp(0xC2);
        let att = issue_host_session_attestation(&op, signed_fp, 1_000);
        let connecting_fp = nats_fp(0xC3);
        let err = verify_host_session_attestation(&att, &op.verifying_key(), &connecting_fp, 1_000)
            .unwrap_err();
        assert_eq!(err, ArtifactError::HostSessionKeyMismatch);
    }

    #[test]
    fn rejects_bad_signature() {
        let op = op_signing(0xA2);
        let fp = nats_fp(0xC4);
        let mut att = issue_host_session_attestation(&op, fp, 1_000);
        att.sig_op[0] ^= 0xff;
        let err =
            verify_host_session_attestation(&att, &op.verifying_key(), &fp, 1_000).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    /// A well-formed attestation from operating key B, verified against operating key A's
    /// `verifying_key`: the signature does not belong to that key, so this must fail as a bad
    /// signature, not silently verify against the wrong identity.
    #[test]
    fn rejects_a_different_op_key() {
        let op_a = op_signing(0xA3);
        let op_b = op_signing(0xA4);
        let fp = nats_fp(0xC5);
        let att = issue_host_session_attestation(&op_b, fp, 1_000);
        let err =
            verify_host_session_attestation(&att, &op_a.verifying_key(), &fp, 1_000).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_ts_too_far_in_the_past() {
        let op = op_signing(0xA5);
        let fp = nats_fp(0xC6);
        let att = issue_host_session_attestation(&op, fp, 1_000);
        let now = 1_000 + HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS + 1;
        let err = verify_host_session_attestation(&att, &op.verifying_key(), &fp, now).unwrap_err();
        assert_eq!(err, ArtifactError::TimestampSkew);
    }

    #[test]
    fn rejects_ts_too_far_in_the_future() {
        let op = op_signing(0xA6);
        let fp = nats_fp(0xC7);
        let ts = 10_000;
        let att = issue_host_session_attestation(&op, fp, ts);
        let now = ts - HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS - 1;
        let err = verify_host_session_attestation(&att, &op.verifying_key(), &fp, now).unwrap_err();
        assert_eq!(err, ArtifactError::TimestampSkew);
    }

    #[test]
    fn accepts_ts_exactly_at_the_skew_boundary() {
        let op = op_signing(0xA7);
        let fp = nats_fp(0xC8);
        let ts = 10_000;
        let att = issue_host_session_attestation(&op, fp, ts);

        let now_late = ts + HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS;
        verify_host_session_attestation(&att, &op.verifying_key(), &fp, now_late)
            .expect("+120s boundary must be accepted");

        let now_early = ts - HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS;
        verify_host_session_attestation(&att, &op.verifying_key(), &fp, now_early)
            .expect("-120s boundary must be accepted");
    }
}
