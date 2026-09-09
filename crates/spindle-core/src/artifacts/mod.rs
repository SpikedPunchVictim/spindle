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
//!
//! [`bootstrap`] is the one exception to the table above: the device bootstrap state bundle
//! (DESIGN.md §A4 "Adding a device (device bootstrap)", :317-330) is deliberately **not** a signed
//! artifact — it has no signer, because its only consumer is the new device over the same local QR
//! channel that already conveys the root identity itself, so a signature here would have no
//! verifier that channel doesn't already establish (see `crates/spindle-proto/src/bootstrap.rs`'s
//! module doc for the full argument). This module still builds and verifies it, alongside
//! everything above, because building it correctly (the QR fit check) and verifying it correctly
//! (deriving `host_fp`/`device_fp`, running [`verify_capability`] per entry) both need the same
//! crypto this module already has and `spindle-proto` deliberately does not.

mod admin_command;
mod admission_token;
mod bootstrap;
mod capability;
mod device_cert;
mod host_device_cert;
mod host_op_key_cert;
mod revocation;

pub use admin_command::{issue_admin_command, verify_admin_command};
pub use admission_token::{issue_admission_token, verify_admission_token};
pub use bootstrap::{
    build_bootstrap_bundle, verify_bootstrap_bundle, BundleError, QrEcLevel, VerifiedBundle,
    VerifiedBundleEntry,
};
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
    /// [`capability::verify_capability`] / [`admin_command::verify_admin_command`] (DESIGN.md
    /// §A7b: "version byte `v`, ... Unknown `v` ⇒ reject"): the artifact's own `v` field is below
    /// the module's version floor (`CAPABILITY_MIN_V` / `ADMIN_COMMAND_MIN_V`). Checked first,
    /// before any signature or expiry work — the cheapest possible rejection, mirroring
    /// [`crate::envelope::EnvelopeError::VersionTooLow`]'s ordering.
    #[error("artifact version {found} is below the minimum {minimum}")]
    VersionTooLow { found: u8, minimum: u8 },
}

/// The version-floor check shared by [`capability::verify_capability`] and
/// [`admin_command::verify_admin_command`] — deliberately the very first check either function
/// runs (cheapest possible rejection, before any signature or expiry work).
pub(crate) fn check_min_v(found: u8, minimum: u8) -> Result<(), ArtifactError> {
    if found < minimum {
        return Err(ArtifactError::VersionTooLow { found, minimum });
    }
    Ok(())
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

/// The Ed25519 field prime `p = 2^255 - 19` (RFC 8032 §5.1.3), little-endian, used by
/// [`checked_verifying_key`] to reject a non-canonical point encoding.
///
/// `y = 0x7f...ed...` in the usual big-endian hex form; written here little-endian (byte 0 is the
/// least-significant byte) to match the encoding `checked_verifying_key` compares against.
const P_BYTES: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Compares two 32-byte little-endian unsigned integers, returning `true` if `a >= b`. Written as
/// an explicit byte-by-byte comparison (most-significant byte first) rather than bigint/u128
/// arithmetic — boring and obvious over clever, per this repo's house style.
fn ge_le_bytes(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true // every byte equal
}

/// Parses a 32-byte Ed25519 public key encoding, enforcing RFC 8032 §5.1.3's canonical-encoding
/// rule in addition to `VerifyingKey::from_bytes`'s point-decompression check.
///
/// `ed25519_dalek::VerifyingKey::from_bytes` is `CompressedEdwardsY::decompress`, which reads the
/// low 255 bits of the encoding as a `y`-coordinate and decompresses any `y < 2^255` — it never
/// checks `y < p`. A `y` in `[p, 2^255)` decodes to the same point as `y - p`, so two distinct byte
/// strings can name the same public key. td-b8c68a measured this against `@noble/curves`'
/// `ed25519.Point.fromBytes`, which does enforce `y < p` and rejects those non-canonical
/// encodings (e.g. `[0xff; 32]`, the non-canonical encoding of `y = 18`); this helper closes that
/// Rust/TS divergence by rejecting them here too, before decompression ever runs.
///
/// X25519 (`agree_pk`) has no equivalent check anywhere in this codebase, and must not gain one:
/// `x25519_dalek::PublicKey::from` is infallible by design (any 32 bytes are a valid Montgomery
/// u-coordinate candidate) and TS mirrors that deliberately — see td-b8c68a.
pub fn checked_verifying_key(bytes: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    // The sign bit (encoding the sign of the x-coordinate) lives in the top bit of the last byte
    // and plays no part in the canonicality check, which is purely about the magnitude of `y` —
    // mask it off in a scratch copy, but pass the original `bytes` (sign bit intact) to
    // `from_bytes` below.
    let mut y = *bytes;
    y[31] &= 0x7f;

    if ge_le_bytes(&y, &P_BYTES) {
        // y >= p: not the canonical encoding of any point. Reject before decompression.
        return None;
    }

    ed25519_dalek::VerifyingKey::from_bytes(bytes).ok()
}

pub(crate) fn parse_verifying_key(
    bytes: &[u8],
) -> Result<ed25519_dalek::VerifyingKey, ArtifactError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ArtifactError::InvalidPublicKey)?;
    checked_verifying_key(&arr).ok_or(ArtifactError::InvalidPublicKey)
}

pub(crate) fn parse_signature(bytes: &[u8]) -> Result<ed25519_dalek::Signature, ArtifactError> {
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| ArtifactError::InvalidSignatureEncoding)?;
    Ok(ed25519_dalek::Signature::from_bytes(&arr))
}

#[cfg(test)]
mod checked_verifying_key_tests {
    use super::checked_verifying_key;

    /// td-b8c68a's measured divergence: `[0xff; 32]` is the non-canonical encoding of `y = 18`
    /// (`p + 18` reduces mod `2^255` to `2^255 - 1`, which is exactly what `[0xff; 32]` with the
    /// sign bit masked off represents). Bare `VerifyingKey::from_bytes` accepts it (it only checks
    /// `y < 2^255`); `checked_verifying_key` must reject it (RFC 8032 requires `y < p`), matching
    /// noble's `ed25519.Point.fromBytes` on the TS side.
    #[test]
    fn all_ff_bytes_is_rejected_as_non_canonical() {
        assert!(
            checked_verifying_key(&[0xff; 32]).is_none(),
            "[0xff; 32] is the non-canonical encoding of y = 18 and must be rejected"
        );
    }

    /// `[0u8; 31] ++ 0xa9`: 32 bytes, canonical range, but not a valid compressed Ed25519 point at
    /// all (verified empirically against this workspace's pinned `ed25519-dalek` version, and
    /// already relied on by `spindle-host-core::device_keys`'s own test of the same byte pattern).
    /// This must be rejected for failing to decompress, not for canonicality.
    #[test]
    fn invalid_curve_point_is_rejected() {
        let mut bytes = [0u8; 32];
        bytes[31] = 0xa9;
        assert!(
            checked_verifying_key(&bytes).is_none(),
            "a byte string that does not decompress to any curve point must be rejected"
        );
    }

    /// `y = 0` (all-zero bytes) is on-curve and is the canonical encoding of its point (`0 < p`
    /// trivially), so it must be accepted by both the decompression and the canonicality check.
    #[test]
    fn all_zero_bytes_is_accepted() {
        assert!(
            checked_verifying_key(&[0u8; 32]).is_some(),
            "[0u8; 32] is a canonically-encoded, valid Ed25519 point and must be accepted"
        );
    }

    /// A real, freshly-derived signing key's public key must always be accepted: signing keys
    /// always produce canonically-encoded points, so this is what proves the canonicality check
    /// does not have false positives against ordinary, legitimately-generated keys.
    #[test]
    fn a_real_derived_key_is_accepted() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let bytes = signing_key.verifying_key().to_bytes();
        assert!(
            checked_verifying_key(&bytes).is_some(),
            "a genuinely derived verifying key must be accepted"
        );
    }
}
