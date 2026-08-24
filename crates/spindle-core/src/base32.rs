//! RFC 4648 base32, no padding, lowercase — the display-only encoding for [`crate::Fingerprint`]
//! (DESIGN.md §A4: "`device_fp = base32(SHA-256(...))`"). The wire form of every fingerprint
//! remains the 32 raw bytes (matching `spindle-proto`'s byte-string convention); this module only
//! renders bytes for humans (UI, logs, vectors).
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
    fn thirty_two_bytes_no_padding_no_equals() {
        let data = [0xabu8; 32];
        let s = encode_no_pad(&data);
        assert!(!s.contains('='));
        assert_eq!(s.len(), 52); // ceil(256/5) = 52, no padding
    }
}
