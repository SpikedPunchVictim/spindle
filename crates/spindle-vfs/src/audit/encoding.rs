//! Deterministic field encoding for one [`super::AuditEntry`] — the input to the hash-chain
//! formula in `crate::audit`'s module doc comment. See that doc comment for why this hand-rolled
//! encoding was chosen over reusing `spindle-proto`'s canonical CBOR encoder.
//!
//! **Format**: fixed field order (matching `AuditEntry`'s declaration order), each field
//! self-delimiting so the whole encoding is unambiguous without an outer length/count prefix:
//! - `u64` fields: 8 bytes, big-endian.
//! - `Option<Fingerprint>`: 1 presence byte (`0`/`1`) then, if present, the 32 raw fingerprint
//!   bytes.
//! - `Option<u64>`: 1 presence byte then, if present, 8 bytes big-endian.
//! - `String`/`Option<&str>` fields: 1 presence byte for the `Option` case (omitted for the two
//!   always-present `String` fields, `action`/`outcome`), then a 4-byte big-endian length prefix,
//!   then the raw UTF-8 bytes.
//!
//! Two distinct entries can never encode to the same bytes unless every field is equal: each
//! variable-length field carries its own length, so there is no ambiguity about where one field
//! ends and the next begins (e.g. an `action` of `"ab"` + `outcome` of `"cd"` cannot collide with
//! `action` `"a"` + `outcome` `"bcd"` — the length prefixes differ).

use super::AuditEntry;
use spindle_core::Fingerprint;

pub(crate) fn encode_entry(entry: &AuditEntry) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u64(&mut buf, entry.ts);
    push_opt_fingerprint(&mut buf, entry.member);
    push_opt_fingerprint(&mut buf, entry.device);
    push_str(&mut buf, &entry.action);
    push_opt_str(&mut buf, entry.virtual_path.as_deref());
    push_opt_u64(&mut buf, entry.bytes);
    push_str(&mut buf, &entry.outcome);
    buf
}

fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn push_opt_u64(buf: &mut Vec<u8>, v: Option<u64>) {
    match v {
        Some(x) => {
            buf.push(1);
            push_u64(buf, x);
        }
        None => buf.push(0),
    }
}

fn push_opt_fingerprint(buf: &mut Vec<u8>, fp: Option<Fingerprint>) {
    match fp {
        Some(f) => {
            buf.push(1);
            buf.extend_from_slice(f.as_bytes());
        }
        None => buf.push(0),
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn push_opt_str(buf: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(x) => {
            buf.push(1);
            push_str(buf, x);
        }
        None => buf.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(action: &str, outcome: &str) -> AuditEntry {
        AuditEntry {
            ts: 1,
            member: None,
            device: None,
            action: action.to_string(),
            virtual_path: None,
            bytes: None,
            outcome: outcome.to_string(),
        }
    }

    #[test]
    fn same_fields_encode_identically() {
        assert_eq!(
            encode_entry(&entry("a", "b")),
            encode_entry(&entry("a", "b"))
        );
    }

    #[test]
    fn different_fields_encode_differently() {
        assert_ne!(
            encode_entry(&entry("a", "b")),
            encode_entry(&entry("x", "b"))
        );
    }

    #[test]
    fn length_prefixes_prevent_field_boundary_ambiguity() {
        // "ab" + "cd" must not collide with "a" + "bcd" despite the concatenation
        // ("abcd") being identical without length prefixes.
        assert_ne!(
            encode_entry(&entry("ab", "cd")),
            encode_entry(&entry("a", "bcd"))
        );
    }

    #[test]
    fn optional_fields_distinguish_none_from_present() {
        let mut with_member = entry("a", "b");
        with_member.member = Some(Fingerprint::of_parts(&[b"someone"]));
        assert_ne!(encode_entry(&entry("a", "b")), encode_entry(&with_member));
    }
}
