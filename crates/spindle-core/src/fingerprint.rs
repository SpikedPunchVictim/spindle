//! [`Fingerprint`] — the 32-byte SHA-256 identifier shared by every principal in Spindle: a
//! person's `root_fp`, a device's `device_fp`, a host's `host_fp` (DESIGN.md §A4). The wire form
//! is always the 32 raw bytes (matching `spindle-proto`'s byte-string convention for
//! fingerprints/keys/signatures); base32 (RFC 4648, no padding, lowercase) is a *display-only*
//! encoding layered on top for UI/logs/vectors, never sent on the wire.

use crate::base32;
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Every Spindle fingerprint is a SHA-256 digest: 32 bytes.
pub const FINGERPRINT_LEN: usize = 32;

/// A 32-byte SHA-256 fingerprint (`root_fp`, `device_fp`, `host_fp`, ...). Displays as lowercase,
/// unpadded RFC 4648 base32.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    #[error("fingerprint must be exactly {FINGERPRINT_LEN} bytes, got {0}")]
    WrongLength(usize),
    /// The string wasn't valid lowercase RFC 4648 base32 (no padding) — see
    /// [`Fingerprint::from_str`] / DESIGN.md §A5 `helper.turn.get.<nfp>` (v0.9.7, A12 #45), the
    /// first place a fingerprint's string form must be parsed back rather than only displayed.
    #[error("invalid base32 fingerprint encoding")]
    InvalidEncoding,
}

impl Fingerprint {
    /// Wraps an already-computed 32-byte digest.
    pub fn new(bytes: [u8; FINGERPRINT_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses a fingerprint from a wire byte string (e.g. a decoded `spindle_proto` field),
    /// rejecting anything that isn't exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, FingerprintError> {
        let arr: [u8; FINGERPRINT_LEN] = bytes
            .try_into()
            .map_err(|_| FingerprintError::WrongLength(bytes.len()))?;
        Ok(Self(arr))
    }

    /// `SHA-256(parts[0] || parts[1] || ...)` — the shared construction behind `root_fp`,
    /// `device_fp`, and every other fingerprint in DESIGN.md §A4.
    pub fn of_parts(parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for p in parts {
            hasher.update(p);
        }
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// True if `bytes` (typically a decoded `spindle_proto` field) equals this fingerprint.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.0.as_slice() == bytes
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::encode_no_pad(&self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

/// Parses the exact inverse of [`Display`](fmt::Display): lowercase, unpadded RFC 4648 base32.
/// Used to recover a fingerprint from a NATS subject token (e.g. the `<nfp>` in
/// `helper.turn.get.<nfp>`, DESIGN.md §A5 v0.9.7) — the one place this crate round-trips the
/// display encoding instead of only producing it.
impl FromStr for Fingerprint {
    type Err = FingerprintError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base32::decode_no_pad(s).map_err(|_| FingerprintError::InvalidEncoding)?;
        Self::from_slice(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert_eq!(
            Fingerprint::from_slice(&[0u8; 31]).unwrap_err(),
            FingerprintError::WrongLength(31)
        );
        assert_eq!(
            Fingerprint::from_slice(&[0u8; 33]).unwrap_err(),
            FingerprintError::WrongLength(33)
        );
    }

    #[test]
    fn display_then_parse_round_trips() {
        let fp = Fingerprint::of_parts(&[b"subject-token-round-trip"]);
        let s = fp.to_string();
        let parsed: Fingerprint = s.parse().expect("parse");
        assert_eq!(parsed, fp);
    }

    #[test]
    fn from_str_rejects_invalid_base32() {
        assert_eq!(
            "not valid base32!!".parse::<Fingerprint>().unwrap_err(),
            FingerprintError::InvalidEncoding
        );
    }

    #[test]
    fn from_str_rejects_wrong_decoded_length() {
        // Valid base32 alphabet, but far too short to decode to 32 bytes.
        assert_eq!(
            "my".parse::<Fingerprint>().unwrap_err(),
            FingerprintError::WrongLength(1)
        );
    }

    #[test]
    fn round_trip_and_matches() {
        let fp = Fingerprint::of_parts(&[b"hello", b"world"]);
        let bytes = fp.to_vec();
        let decoded = Fingerprint::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, fp);
        assert!(fp.matches(&bytes));
    }

    #[test]
    fn display_is_lowercase_base32_no_padding() {
        let fp = Fingerprint::new([0xffu8; 32]);
        let s = fp.to_string();
        assert!(s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert!(!s.contains('='));
    }
}
