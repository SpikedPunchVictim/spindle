//! RFC 4648 base32, no padding, lowercase — the display-only encoding for [`crate::Fingerprint`]
//! (DESIGN.md §A4: "`device_fp = base32(SHA-256(...))`"). The wire form of every fingerprint
//! remains the 32 raw bytes (matching `spindle-proto`'s byte-string convention); this module only
//! renders bytes for humans (UI, logs, vectors) — and, since v0.9.7 (DESIGN.md §A5 `helper.turn.
//! get.<nfp>`, §A12 #45), parses that same rendering back out of a NATS subject token, because a
//! subject is the one place a fingerprint's *string* form is authoritative (NATS permissions bind
//! to the caller's own subject token, not to a payload field).
//!
//! Hand-rolled rather than pulling in a `base32` crate: the A9c dependency manifest for
//! `spindle-core` does not list one, and RFC 4648 base32 is small enough to implement directly
//! without adding a dependency.

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes `data` as lowercase RFC 4648 base32 with no `=` padding.
pub fn encode_no_pad(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let idx = (buffer >> bits_in_buffer) & 0x1f;
            out.push(ALPHABET[idx as usize] as char);
        }
    }
    if bits_in_buffer > 0 {
        let idx = (buffer << (5 - bits_in_buffer)) & 0x1f;
        out.push(ALPHABET[idx as usize] as char);
    }
    out
}

/// Why [`decode_no_pad`] rejected a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// A character outside the lowercase RFC 4648 alphabet (`a`-`z`, `2`-`7`).
    InvalidChar,
    /// The trailing bits carried non-zero data that [`encode_no_pad`] could never have produced —
    /// i.e. more than one string would decode to the same bytes. Rejected to keep the encoding
    /// canonical/byte-exact, the same discipline this crate applies to every other wire form.
    NonCanonicalPadding,
}

/// Decodes lowercase RFC 4648 base32 (no padding) back into bytes — the exact inverse of
/// [`encode_no_pad`]. Case-sensitive (lowercase only, matching what `encode_no_pad` ever
/// produces); uppercase input is rejected rather than silently normalized.
pub fn decode_no_pad(s: &str) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;

    for c in s.bytes() {
        let idx = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or(DecodeError::InvalidChar)?;
        buffer = (buffer << 5) | idx as u32;
        bits_in_buffer += 5;
        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            out.push((buffer >> bits_in_buffer) as u8);
        }
    }
    // Any leftover bits are the padding encode_no_pad appends to fill its last symbol; they must
    // be zero, or this string could never have come from encode_no_pad (non-canonical).
    if bits_in_buffer > 0 {
        let leftover_mask = (1u32 << bits_in_buffer) - 1;
        if buffer & leftover_mask != 0 {
            return Err(DecodeError::NonCanonicalPadding);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors_rfc4648_no_padding() {
        // RFC 4648 §10 test vectors, stripped of '=' padding, lowercased.
        assert_eq!(encode_no_pad(b""), "");
        assert_eq!(encode_no_pad(b"f"), "my");
        assert_eq!(encode_no_pad(b"fo"), "mzxq");
        assert_eq!(encode_no_pad(b"foo"), "mzxw6");
        assert_eq!(encode_no_pad(b"foob"), "mzxw6yq");
        assert_eq!(encode_no_pad(b"fooba"), "mzxw6ytb");
        assert_eq!(encode_no_pad(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn decode_known_vectors_rfc4648_no_padding() {
        assert_eq!(decode_no_pad("").unwrap(), b"");
        assert_eq!(decode_no_pad("my").unwrap(), b"f");
        assert_eq!(decode_no_pad("mzxq").unwrap(), b"fo");
        assert_eq!(decode_no_pad("mzxw6").unwrap(), b"foo");
        assert_eq!(decode_no_pad("mzxw6yq").unwrap(), b"foob");
        assert_eq!(decode_no_pad("mzxw6ytb").unwrap(), b"fooba");
        assert_eq!(decode_no_pad("mzxw6ytboi").unwrap(), b"foobar");
    }

    #[test]
    fn round_trips_thirty_two_random_looking_bytes() {
        let data: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let encoded = encode_no_pad(&data);
        let decoded = decode_no_pad(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_rejects_invalid_characters() {
        assert_eq!(
            decode_no_pad("mzx!w6").unwrap_err(),
            DecodeError::InvalidChar
        );
        // Uppercase is rejected too — encode_no_pad never produces it.
        assert_eq!(
            decode_no_pad("MZXW6").unwrap_err(),
            DecodeError::InvalidChar
        );
        // '0', '1', '8', '9' are not in the RFC 4648 base32 alphabet.
        assert_eq!(
            decode_no_pad("mzxw0").unwrap_err(),
            DecodeError::InvalidChar
        );
    }

    #[test]
    fn decode_rejects_non_canonical_trailing_bits() {
        // "my" decodes to "f" (1 byte); its last symbol carries 2 real bits + 3 padding bits that
        // must be zero. "mz" flips one of those padding bits, so it must be rejected even though
        // it superficially "looks like" valid base32.
        assert_eq!(
            decode_no_pad("mz").unwrap_err(),
            DecodeError::NonCanonicalPadding
        );
    }

    #[test]
    fn thirty_two_bytes_no_padding_no_equals() {
        let data = [0xabu8; 32];
        let s = encode_no_pad(&data);
        assert!(!s.contains('='));
        assert_eq!(s.len(), 52); // ceil(256/5) = 52, no padding
    }
}
