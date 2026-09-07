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

/// Number of leading base32 characters of a [`Fingerprint`]'s full [`Display`](fmt::Display)
/// form kept by [`RedactedFingerprint`]. See that type's doc comment for the policy this
/// implements and, importantly, what it does not protect against.
const REDACTED_PREFIX_LEN: usize = 8;

/// Appended after the kept prefix so a reader can tell the value has been truncated rather than
/// mistaking it for a short, complete fingerprint.
const REDACTED_ELISION_MARKER: &str = "..";

/// A [`Fingerprint`] whose [`Display`]/[`Debug`] show only the first
/// [`REDACTED_PREFIX_LEN`] characters of the full base32 [`Display`] form, followed by
/// [`REDACTED_ELISION_MARKER`]. Produced by [`Fingerprint::redacted`] for use in `tracing`
/// output.
///
/// This exists because Spindle's `Display` on [`Fingerprint`] is a load-bearing wire format (it
/// round-trips through [`FromStr`] to recover a fingerprint from a NATS subject token, e.g. the
/// `<nfp>` in `helper.turn.get.<nfp>`) and therefore cannot itself be made to truncate. Logging
/// code needs a *different* type to opt into truncated output — a bare `%fp`/`?fp` on
/// [`Fingerprint`] must keep emitting the full value so the wire-format contract stays intact,
/// which is exactly why leaving that emission unguarded is dangerous: see the
/// `redaction_guard` test in this crate's `tests/` directory, which scans `tracing::` call sites
/// across the crates that use it for exactly this mistake.
///
/// Policy: per DESIGN.md:850 (`[USER DECISION]` "connection logs 30 days; no payload logging")
/// and the fact that Spindle is zero-knowledge by design, log lines may carry identifiers only
/// in truncated form and must never carry virtual paths, file/group names, capability bytes,
/// key material, or payloads — a host log full of complete fingerprints and paths would itself
/// be a plaintext membership-and-content map sitting on disk.
///
/// # What this does and does not protect against
///
/// Truncating to the first 8 base32 characters (40 bits) prevents a log reader from
/// reconstructing the full identifier well enough to *reuse* it — as a NATS subject token, or to
/// impersonate the principal it names. It does **not** make the log anonymous: 40 bits is enough
/// to uniquely pick a single member out of any roster smaller than roughly a trillion entries,
/// so someone who already holds the roster (an admin's member list, the audit log below) can
/// still map a redacted fingerprint back to the principal it names by comparing prefixes.
/// Redaction here is a reduction in what an incidental log reader can do with a stolen or leaked
/// log, not a confidentiality boundary against a reader who already has membership data.
///
/// This type is for human eyes (log lines) only. It deliberately does not implement `FromStr`,
/// `PartialEq` against [`Fingerprint`], or anything else that would let a truncated value be
/// mistaken for, or misused as, an identifier.
///
/// This is also not, and must not become, a substitute for the audit log described at
/// DESIGN.md:413 (`{ts, member, device, action, virtual_path, bytes, outcome}`, hash-chained,
/// append-only) — that is a separate, deliberately-complete record of every VFS op and admin
/// change; `tracing` output redacted by this type must not duplicate what belongs there.
#[derive(Clone, Copy)]
pub struct RedactedFingerprint(Fingerprint);

impl fmt::Display for RedactedFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let full = self.0.to_string();
        let prefix: String = full.chars().take(REDACTED_PREFIX_LEN).collect();
        write!(f, "{prefix}{REDACTED_ELISION_MARKER}")
    }
}

/// Truncates the same as [`Display`](fmt::Display): a `?fp` in a `tracing` macro must be exactly
/// as safe as a `%fp`, so `Debug` cannot be allowed to fall back to the full value the way
/// [`Fingerprint`]'s own `Debug` deliberately does (it wraps the full `Display`, by design, since
/// that type is never meant to be logged truncated).
impl fmt::Debug for RedactedFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedactedFingerprint({self})")
    }
}

impl Fingerprint {
    /// Wraps `self` in a [`RedactedFingerprint`] whose `Display`/`Debug` emit only the first 8
    /// characters of the full base32 form. Use this at every `tracing`/log call site that would
    /// otherwise interpolate a bare fingerprint — `%fp.redacted()` or `?fp.redacted()` — instead
    /// of `%fp`/`?fp` on the fingerprint itself, which emits the complete identifier. See
    /// [`RedactedFingerprint`]'s doc comment for the policy this implements and its limits.
    pub fn redacted(self) -> RedactedFingerprint {
        RedactedFingerprint(self)
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

    #[test]
    fn redacted_display_omits_and_is_shorter_than_the_full_form() {
        let fp = Fingerprint::of_parts(&[b"redaction-fixture-one"]);
        let full = fp.to_string();
        let redacted = fp.redacted().to_string();
        assert!(redacted.len() < full.len());
        assert_ne!(redacted, full);
        assert!(!full.contains(&redacted), "full form must not contain the redacted form (which carries the elision marker the full form never does)");
    }

    #[test]
    fn redacted_display_is_a_prefix_of_the_full_display() {
        let fp = Fingerprint::of_parts(&[b"redaction-fixture-two"]);
        let full = fp.to_string();
        let redacted = fp.redacted().to_string();
        let kept = redacted
            .strip_suffix(REDACTED_ELISION_MARKER)
            .expect("redacted form ends with the elision marker");
        assert_eq!(kept.len(), REDACTED_PREFIX_LEN);
        assert!(
            full.starts_with(kept),
            "redacted prefix must correlate with the full form it was truncated from"
        );
    }

    #[test]
    fn redacted_debug_also_truncates() {
        let fp = Fingerprint::of_parts(&[b"redaction-fixture-three"]);
        let full = fp.to_string();
        let debugged = format!("{:?}", fp.redacted());
        assert!(
            !debugged.contains(&full),
            "Debug must be as safe as Display: `?fp.redacted()` must not leak the full value"
        );
    }

    #[test]
    fn redacted_forms_differ_for_different_fingerprints() {
        // Fixed seeds, not randomness — deterministic by construction.
        let a = Fingerprint::of_parts(&[b"redaction-fixture-four-a"]).redacted();
        let b = Fingerprint::of_parts(&[b"redaction-fixture-four-b"]).redacted();
        assert_ne!(a.to_string(), b.to_string());
    }

    #[test]
    fn full_display_and_from_str_round_trip_is_unchanged_by_redaction() {
        // Guards against a future edit to `redacted()`/`RedactedFingerprint` accidentally
        // touching `Fingerprint`'s own `Display`/`FromStr` — those remain the load-bearing wire
        // format (DESIGN.md §A5 `helper.turn.get.<nfp>`) and must round-trip exactly as before.
        let fp = Fingerprint::of_parts(&[b"redaction-fixture-five"]);
        let parsed: Fingerprint = fp.to_string().parse().expect("parse");
        assert_eq!(parsed, fp);
    }
}
