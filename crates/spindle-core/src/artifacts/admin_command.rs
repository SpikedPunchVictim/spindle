use super::{check_min_v, check_skew, parse_signature, ArtifactError};
use crate::fingerprint::Fingerprint;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use spindle_proto::artifacts::{AdminCommand, ADMIN_COMMAND_MIN_V};
use spindle_proto::canonical::CborValue;

/// `|ts - now| <= 2 min` (DESIGN.md §A7b), same window as the envelope's clock-skew rule.
pub const ADMIN_COMMAND_CLOCK_SKEW_SECS: u64 = 120;

/// Issues an admin command signed by the operator admission key (DESIGN.md §A3b/§A7b).
#[allow(clippy::too_many_arguments)]
pub fn issue_admin_command(
    operator: &SigningKey,
    v: u8,
    cmd: String,
    args: CborValue,
    signer_fp: Vec<u8>,
    seq: u64,
    nonce: Vec<u8>,
    ts: u64,
) -> AdminCommand {
    let mut command = AdminCommand {
        v,
        cmd,
        args,
        signer_fp,
        seq,
        nonce,
        ts,
        sig: Vec::new(),
    };
    command.sig = operator.sign(&command.signing_input()).to_bytes().to_vec();
    command
}

/// Verifies an admin command: it names `expected_signer_fp`, `sig` is valid under `operator_pk`,
/// and `|ts - now| <= 2 min` (A7b). Per-signer monotonic `seq` plus nonce replay tracking is
/// durable caller-owned state (helper/host audit chain), not this crate's concern.
///
/// **`expected_signer_fp` is a required argument, deliberately and non-negotiably.** This used to
/// be exactly the API shape that produced td-0bcab4: `command.signer_fp` is carried inside the
/// *signed* preimage — a well-signed command has skin in the game about who it claims to be
/// from — but `verify_admin_command(command, operator_pk, now)` never compared it against
/// anything, so a command bearing a valid signature from *some* key the caller trusted verified
/// regardless of whose `signer_fp` it named. That is the same bearer-token shape
/// `SessionAttestation` exists to close for `DeviceCertificate.nats_fp`: a signed binding field
/// that no verifier actually reads. There is no valid caller that wants the signature checked
/// without the binding, so this API does not offer one.
///
/// Checks run cheap-structural-before-crypto (§A6):
/// 1. Version floor — cheapest possible rejection, checked before any other work (DESIGN.md §A7b:
///    "Unknown `v` ⇒ reject").
/// 2. `expected_signer_fp` vs `command.signer_fp` — a byte comparison, cheaper than a signature
///    verification and the check this function exists to enforce. On mismatch:
///    [`ArtifactError::SignerFingerprintMismatch`].
/// 3. `sig` — Ed25519 verification under `operator_pk`.
/// 4. Clock skew (`ts` ±2 min) — cheaper than the signature check above, but ordered last here
///    (unchanged from before this fix) since the signed preimage must already be trusted before
///    its own `ts` is worth inspecting.
pub fn verify_admin_command(
    command: &AdminCommand,
    operator_pk: &VerifyingKey,
    expected_signer_fp: &Fingerprint,
    now: u64,
) -> Result<(), ArtifactError> {
    // 1. Version floor — cheapest possible rejection, checked before any signature, binding, or
    // timestamp work (DESIGN.md §A7b: "Unknown `v` ⇒ reject").
    check_min_v(command.v, ADMIN_COMMAND_MIN_V)?;

    // 2. signer_fp binding — the check this function exists to enforce (td-0bcab4's API shape).
    // Must run before the signature check: naming the wrong signer is a structural mismatch,
    // cheaper to reject than the crypto below.
    if !expected_signer_fp.matches(&command.signer_fp) {
        return Err(ArtifactError::SignerFingerprintMismatch);
    }

    // 3. Signature.
    let sig = parse_signature(&command.sig)?;
    operator_pk
        .verify(&command.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)?;

    // 4. Clock skew.
    check_skew(now, command.ts, ADMIN_COMMAND_CLOCK_SKEW_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[0x51; 32])
    }

    /// The `signer_fp` every `sample()` command names — matches `Fingerprint::matches`'s
    /// expectations in the round-trip tests below.
    fn signer_fp() -> Fingerprint {
        Fingerprint::new([0xDD; 32])
    }

    fn sample(operator: &SigningKey, ts: u64) -> AdminCommand {
        issue_admin_command(
            operator,
            1,
            "evict_host".to_string(),
            CborValue::map(vec![("host_fp", CborValue::bytes(vec![0xCC; 32]))]),
            signer_fp().to_vec(),
            5,
            vec![0xEE; 16],
            ts,
        )
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let op = operator();
        let cmd = sample(&op, 1_000);
        verify_admin_command(&cmd, &op.verifying_key(), &signer_fp(), 1_000)
            .expect("valid command");
    }

    /// Pins td-0bcab4's exact API shape closed: a well-signed admin command that names a
    /// *different* `signer_fp` than the operator identity the caller expects must be rejected.
    /// Before `expected_signer_fp` became a required argument, `verify_admin_command` never
    /// compared `signer_fp` against anything, so this command would have verified.
    #[test]
    fn rejects_wrong_signer_fp() {
        let op = operator();
        let cmd = sample(&op, 1_000);
        let someone_elses_fp = Fingerprint::new([0xFF; 32]);
        let err =
            verify_admin_command(&cmd, &op.verifying_key(), &someone_elses_fp, 1_000).unwrap_err();
        assert_eq!(err, ArtifactError::SignerFingerprintMismatch);
    }

    #[test]
    fn rejects_bad_signature() {
        let op = operator();
        let mut cmd = sample(&op, 1_000);
        cmd.sig[0] ^= 0xff;
        let err = verify_admin_command(&cmd, &op.verifying_key(), &signer_fp(), 1_000).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_clock_skew() {
        let op = operator();
        let cmd = sample(&op, 1_000);
        let err = verify_admin_command(
            &cmd,
            &op.verifying_key(),
            &signer_fp(),
            1_000 + ADMIN_COMMAND_CLOCK_SKEW_SECS + 1,
        )
        .unwrap_err();
        assert_eq!(err, ArtifactError::TimestampSkew);
    }

    #[test]
    fn rejects_v_below_floor() {
        let op = operator();
        let mut cmd = sample(&op, 1_000);
        cmd.v = 0;
        let err = verify_admin_command(&cmd, &op.verifying_key(), &signer_fp(), 1_000).unwrap_err();
        assert_eq!(
            err,
            ArtifactError::VersionTooLow {
                found: 0,
                minimum: ADMIN_COMMAND_MIN_V
            }
        );
    }

    #[test]
    fn accepts_v_at_floor() {
        let op = operator();
        let cmd = sample(&op, 1_000);
        assert_eq!(cmd.v, ADMIN_COMMAND_MIN_V);
        verify_admin_command(&cmd, &op.verifying_key(), &signer_fp(), 1_000)
            .expect("v == floor must verify");
    }

    #[test]
    fn version_check_fires_before_signature_check() {
        // v below the floor AND a corrupted signature — the version error must win, pinning the
        // "cheapest rejection first" ordering against a future refactor.
        let op = operator();
        let mut cmd = sample(&op, 1_000);
        cmd.v = 0;
        cmd.sig[0] ^= 0xff;
        let err = verify_admin_command(&cmd, &op.verifying_key(), &signer_fp(), 1_000).unwrap_err();
        assert_eq!(
            err,
            ArtifactError::VersionTooLow {
                found: 0,
                minimum: ADMIN_COMMAND_MIN_V
            }
        );
    }

    #[test]
    fn signer_fp_check_fires_before_signature_check() {
        // A wrong signer_fp AND a corrupted signature — the binding-mismatch error must win,
        // pinning the "cheapest rejection first" ordering (§A6) against a future refactor.
        let op = operator();
        let mut cmd = sample(&op, 1_000);
        cmd.sig[0] ^= 0xff;
        let someone_elses_fp = Fingerprint::new([0xFF; 32]);
        let err =
            verify_admin_command(&cmd, &op.verifying_key(), &someone_elses_fp, 1_000).unwrap_err();
        assert_eq!(err, ArtifactError::SignerFingerprintMismatch);
    }
}
