use super::{check_min_v, check_skew, parse_signature, ArtifactError};
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

/// Verifies `sig` and `|ts - now| <= 2 min` (A7b). Per-signer monotonic `seq` plus nonce replay
/// tracking is durable caller-owned state (helper/host audit chain), not this crate's concern.
pub fn verify_admin_command(
    command: &AdminCommand,
    operator_pk: &VerifyingKey,
    now: u64,
) -> Result<(), ArtifactError> {
    // Version floor — cheapest possible rejection, checked before any signature or timestamp
    // work (DESIGN.md §A7b: "Unknown `v` ⇒ reject").
    check_min_v(command.v, ADMIN_COMMAND_MIN_V)?;

    let sig = parse_signature(&command.sig)?;
    operator_pk
        .verify(&command.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)?;
    check_skew(now, command.ts, ADMIN_COMMAND_CLOCK_SKEW_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[0x51; 32])
    }

    fn sample(operator: &SigningKey, ts: u64) -> AdminCommand {
        issue_admin_command(
            operator,
            1,
            "evict_host".to_string(),
            CborValue::map(vec![("host_fp", CborValue::bytes(vec![0xCC; 32]))]),
            vec![0xDD; 32],
            5,
            vec![0xEE; 16],
            ts,
        )
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let op = operator();
        let cmd = sample(&op, 1_000);
        verify_admin_command(&cmd, &op.verifying_key(), 1_000).expect("valid command");
    }

    #[test]
    fn rejects_bad_signature() {
        let op = operator();
        let mut cmd = sample(&op, 1_000);
        cmd.sig[0] ^= 0xff;
        let err = verify_admin_command(&cmd, &op.verifying_key(), 1_000).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_clock_skew() {
        let op = operator();
        let cmd = sample(&op, 1_000);
        let err = verify_admin_command(
            &cmd,
            &op.verifying_key(),
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
        let err = verify_admin_command(&cmd, &op.verifying_key(), 1_000).unwrap_err();
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
        verify_admin_command(&cmd, &op.verifying_key(), 1_000).expect("v == floor must verify");
    }

    #[test]
    fn version_check_fires_before_signature_check() {
        // v below the floor AND a corrupted signature — the version error must win, pinning the
        // "cheapest rejection first" ordering against a future refactor.
        let op = operator();
        let mut cmd = sample(&op, 1_000);
        cmd.v = 0;
        cmd.sig[0] ^= 0xff;
        let err = verify_admin_command(&cmd, &op.verifying_key(), 1_000).unwrap_err();
        assert_eq!(
            err,
            ArtifactError::VersionTooLow {
                found: 0,
                minimum: ADMIN_COMMAND_MIN_V
            }
        );
    }
}
