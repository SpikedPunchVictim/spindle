//! Issue/verify functions for the A7b signed-artifact catalog, excluding `Envelope` (which lives
//! in [`crate::envelope`] since it has its own session/AEAD machinery). Each submodule wraps one
//! `spindle_proto::artifacts` type: it builds the unsigned fields, computes `signing_input()` via
//! spindle-proto's canonical encoder (already carrying the correct A7b domain tag — see
//! `spindle_proto::tags`), and signs/verifies with the correct key for that artifact kind per
//! DESIGN.md §A7b:
//!
//! | Artifact | Signer |
//! |---|---|
//! | [`DeviceCertificate`](spindle_proto::artifacts::DeviceCertificate) | identity root |
//! | [`Capability`](spindle_proto::artifacts::Capability) | host operating key, chained to the host root via an embedded `op_cert` (decision A10.30; `host_fp` is root-derived, self-verifying) |
//! | [`HostOpKeyCert`](spindle_proto::artifacts::HostOpKeyCert) | host root |
//! | [`HostDeviceCert`](spindle_proto::artifacts::HostDeviceCert) | host operating key, chained to the host root via an embedded `op_cert` (decision A10.35; self-verifying like `Capability`, but `verify_host_device_cert` additionally *requires* a pinned `host_fp` argument) |
//! | [`RevocationRecord`](spindle_proto::artifacts::RevocationRecord) | host op key or identity root |
//! | [`AdmissionToken`](spindle_proto::artifacts::AdmissionToken) | operator admission key |
//! | [`AdminCommand`](spindle_proto::artifacts::AdminCommand) | operator admission key |
//!
//! This crate never reads a system clock: every time check takes a caller-supplied `now: u64`
//! (Unix seconds), consistent with DESIGN.md §A7 ("clients compute an offset" from helper server
//! time — spindle-core has no opinion on how `now` was obtained).

mod admin_command;
mod admission_token;
mod capability;
mod device_cert;
mod host_device_cert;
mod host_op_key_cert;
mod revocation;

pub use admin_command::{issue_admin_command, verify_admin_command};
pub use admission_token::{issue_admission_token, verify_admission_token};
pub use capability::{issue_capability, verify_capability};
pub use device_cert::{issue_device_certificate, verify_device_certificate};
pub use host_device_cert::{issue_host_device_cert, verify_host_device_cert};
pub use host_op_key_cert::{issue_host_op_key_cert, verify_host_op_key_cert};
pub use revocation::{is_newer_epoch, issue_revocation_record, verify_revocation_record};

use thiserror::Error;

/// Errors from verifying any A7b signed artifact in this module (DESIGN.md §A7b). Every
/// artifact's `verify_*` function fails closed on the first check it fails — never silently.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactError {
    #[error("signature invalid")]
    BadSignature,
    #[error("malformed signature encoding (expected 64 bytes)")]
    InvalidSignatureEncoding,
    #[error("malformed public key encoding (expected 32 bytes)")]
    InvalidPublicKey,
    #[error("artifact expired (now > exp)")]
    Expired,
    #[error("timestamp outside the allowed clock-skew window")]
    TimestampSkew,
    #[error("host_fp does not match SHA-256(host_pk) — capability is not self-verifying")]
    HostFingerprintMismatch,
    #[error("root_fp does not match the expected pinned root")]
    RootFingerprintMismatch,
    #[error("capability's embedded op_cert does not decode as a valid HostOpKeyCert")]
    MalformedOpCert,
    /// [`device_cert::verify_device_certificate`] (§A7b clarification 6): `device_fp` recomputed
    /// from the certificate's own `(alg_id, sign_pk, agree_pk)` does not equal the certificate's
    /// `device_fp` field — the certificate is internally inconsistent.
    #[error(
        "device_fp does not match SHA-256 of the certificate's own (alg_id, sign_pk, agree_pk)"
    )]
    DeviceFingerprintMismatch,
    /// [`device_cert::verify_device_certificate`]: `alg_id` is not a suite this crate knows how to
    /// interpret `sign_pk`/`agree_pk` under (checked before any key parsing, per §A6 "cheap check
    /// before crypto").
    #[error("alg_id is not a supported device key suite")]
    UnsupportedAlgId,
}

pub(crate) fn check_exp(now: u64, exp: u64) -> Result<(), ArtifactError> {
    if now > exp {
        return Err(ArtifactError::Expired);
    }
    Ok(())
}

pub(crate) fn check_skew(now: u64, ts: u64, max_skew_secs: u64) -> Result<(), ArtifactError> {
    if now.abs_diff(ts) > max_skew_secs {
        return Err(ArtifactError::TimestampSkew);
    }
    Ok(())
}

pub(crate) fn parse_verifying_key(
    bytes: &[u8],
) -> Result<ed25519_dalek::VerifyingKey, ArtifactError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ArtifactError::InvalidPublicKey)?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|_| ArtifactError::InvalidPublicKey)
}

pub(crate) fn parse_signature(bytes: &[u8]) -> Result<ed25519_dalek::Signature, ArtifactError> {
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ArtifactError::InvalidSignatureEncoding)?;
    Ok(ed25519_dalek::Signature::from_bytes(&arr))
}
