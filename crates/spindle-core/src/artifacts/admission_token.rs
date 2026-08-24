use super::{check_exp, parse_signature, ArtifactError};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use spindle_proto::artifacts::AdmissionToken;

/// Issues an admission token signed by the operator admission key (DESIGN.md §A3b).
pub fn issue_admission_token(
    operator: &SigningKey,
    nonce: Vec<u8>,
    exp: u64,
    label: String,
    quota_profile: String,
) -> AdmissionToken {
    let mut tok = AdmissionToken {
        nonce,
        exp,
        label,
        quota_profile,
        sig_operator: Vec::new(),
    };
    tok.sig_operator = operator.sign(&tok.signing_input()).to_bytes().to_vec();
    tok
}

/// Verifies `sig_operator` and `exp` (A7b: `exp` days-scale, encoded as an absolute Unix-seconds
/// timestamp on the wire — see the schema table in `spindle_proto::lib`). Nonce-burn replay
/// enforcement is durable helper-side state (CAS), not this crate's concern.
pub fn verify_admission_token(
    tok: &AdmissionToken,
    operator_pk: &VerifyingKey,
    now: u64,
) -> Result<(), ArtifactError> {
    let sig = parse_signature(&tok.sig_operator)?;
    operator_pk
        .verify(&tok.signing_input(), &sig)
        .map_err(|_| ArtifactError::BadSignature)?;
    check_exp(now, tok.exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[0x41; 32])
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let op = operator();
        let tok = issue_admission_token(
            &op,
            vec![0xBB; 16],
            2_000,
            "workshop-nas".to_string(),
            "default".to_string(),
        );
        verify_admission_token(&tok, &op.verifying_key(), 1_500).expect("valid token");
    }

    #[test]
    fn rejects_bad_signature() {
        let op = operator();
        let mut tok = issue_admission_token(
            &op,
            vec![0xBB; 16],
            2_000,
            "workshop-nas".to_string(),
            "default".to_string(),
        );
        tok.sig_operator[0] ^= 0xff;
        let err = verify_admission_token(&tok, &op.verifying_key(), 1_500).unwrap_err();
        assert_eq!(err, ArtifactError::BadSignature);
    }

    #[test]
    fn rejects_expired() {
        let op = operator();
        let tok = issue_admission_token(
            &op,
            vec![0xBB; 16],
            2_000,
            "workshop-nas".to_string(),
            "default".to_string(),
        );
        let err = verify_admission_token(&tok, &op.verifying_key(), 2_001).unwrap_err();
        assert_eq!(err, ArtifactError::Expired);
    }
}
