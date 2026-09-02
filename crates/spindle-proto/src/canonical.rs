//! Canonical CBOR (RFC 8949 §4.2.1) — a deliberately small, hand-rolled encoder/decoder.
//!
//! **Why hand-rolled instead of driving `minicbor`'s encoder/decoder** (A9c's dependency
//! manifest lists `minicbor` for this concern): the strictness this module exists to provide —
//! rejecting non-shortest-form integers/lengths, indefinite-length items, out-of-order map
//! keys, floats, and tags — requires inspecting the exact bytes an encoder chose to emit for
//! every item, and minicbor's decoder API abstracts that choice away. Getting canonical
//! rejection *exactly* right is the security property ADR-004 calls out (signature
//! malleability: two different byte strings must never decode to the "same" signed artifact),
//! so this module owns the full byte-for-byte contract itself rather than trusting a
//! general-purpose CBOR implementation's non-canonical-by-default decode path. It also keeps
//! `spindle-proto` dependency-free, consistent with its role at the bottom of the crate graph
//! (A9c boundary rule 3). This choice is intentionally left open by the task brief ("hand-rolled
//! writer if cleaner — your call, document it"); see `crates/spindle-proto/Cargo.toml` and the
//! crate-level docs in `lib.rs` for the corresponding note.
//!
//! Supported canonical CBOR subset (RFC 8949 §4.2.1, restricted further per DESIGN.md A7b):
//! - major type 0/1: unsigned/negative integers, shortest-form only
//! - major type 2/3: byte strings / UTF-8 text strings, definite length, shortest-form length
//! - major type 4/5: arrays / maps, definite length only; map keys sorted bytewise on their own
//!   canonical encoding (RFC 8949 §4.2.1) and rejected on decode if not strictly increasing
//!   (this also rejects duplicate keys, since duplicates cannot be strictly increasing)
//! - major type 7: only `false` (0xf4), `true` (0xf5), `null` (0xf6) — no floats, no `undefined`,
//!   no other simple values
//! - tags (major type 6): always rejected — no tagged items appear on Spindle's wire
//! - indefinite-length items and the `break` stop code: always rejected

use std::fmt;

/// Maximum number of enclosing arrays/maps a decoded item may sit inside.
///
/// `decode_one` recurses once per nesting level, so without a ceiling a small payload of
/// repeated `0x81` (array, count 1) bytes overflows the stack and **aborts the process** — an
/// abort, not a panic, so no caller can catch it. Both decode paths that reach this code are
/// pre-authentication, so the payload need not come from a peer that authenticated.
///
/// 32 is roughly ten times the deepest structure this protocol actually produces. Measured
/// across all 84 canonical vectors in `vectors/*.json` — every artifact type, including VFS RPC
/// listing replies and the codec's own torture cases — the deepest reaches `depth` 3 here, in
/// the same units this constant is compared against: the top-level item is decoded at `depth`
/// 0, so a `{"item": [{"id": 1}]}` chain reaches 3 at its innermost scalar. (Counting items
/// along that chain instead gives 4 — state which convention you mean if you re-derive this.)
pub const MAX_NESTING_DEPTH: usize = 32;

/// A canonical CBOR data item.
///
/// `NegInt(n)` represents the CBOR negative integer whose value is `-1 - n` (i.e. major type 1
/// with argument `n`), matching RFC 8949's own encoding of negative integers. None of Spindle's
/// wire structures currently use negative integers, but the primitive codec supports them so the
/// canonical-cbor golden vectors can exercise the full integer encoding rule set.
#[derive(Debug, Clone)]
pub enum CborValue {
    Uint(u64),
    NegInt(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    /// Key/value pairs in *insertion* order as constructed. `encode` sorts them into canonical
    /// (bytewise, on each key's own canonical encoding) order before emitting, so callers never
    /// need to pre-sort. `decode` only ever produces `Map`s whose entries are already in
    /// canonical order (it rejects anything else), so re-encoding a decoded value reproduces the
    /// original bytes.
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
}

/// Structural equality. `Map` is compared order-independently (as a set of key/value pairs) —
/// two `CborValue::Map`s built with the same entries in different insertion order are the same
/// logical CBOR map, even though only one insertion order (the canonical, bytewise-sorted one)
/// is ever actually written to the wire by [`canonical_encode`]. Every other variant compares
/// structurally, including `Array`, where element order is meaningful.
impl PartialEq for CborValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CborValue::Uint(a), CborValue::Uint(b)) => a == b,
            (CborValue::NegInt(a), CborValue::NegInt(b)) => a == b,
            (CborValue::Bytes(a), CborValue::Bytes(b)) => a == b,
            (CborValue::Text(a), CborValue::Text(b)) => a == b,
            (CborValue::Array(a), CborValue::Array(b)) => a == b,
            (CborValue::Map(a), CborValue::Map(b)) => {
                a.len() == b.len()
                    && a.iter().all(|pair| b.contains(pair))
                    && b.iter().all(|pair| a.contains(pair))
            }
            (CborValue::Bool(a), CborValue::Bool(b)) => a == b,
            (CborValue::Null, CborValue::Null) => true,
            _ => false,
        }
    }
}

impl CborValue {
    pub fn uint(v: u64) -> Self {
        CborValue::Uint(v)
    }

    pub fn bytes(v: impl Into<Vec<u8>>) -> Self {
        CborValue::Bytes(v.into())
    }

    pub fn text(v: impl Into<String>) -> Self {
        CborValue::Text(v.into())
    }

    pub fn array(v: Vec<CborValue>) -> Self {
        CborValue::Array(v)
    }

    /// Builds a `Map` from `(field name, value)` pairs. Field names become `Text` keys. Callers
    /// may pass entries in any order — `encode` sorts them canonically.
    pub fn map(entries: Vec<(&str, CborValue)>) -> Self {
        CborValue::Map(
            entries
                .into_iter()
                .map(|(k, v)| (CborValue::Text(k.to_string()), v))
                .collect(),
        )
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            CborValue::Uint(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CborValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            CborValue::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[CborValue]> {
        match self {
            CborValue::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(CborValue, CborValue)]> {
        match self {
            CborValue::Map(m) => Some(m),
            _ => None,
        }
    }
}

/// Errors produced by the canonical CBOR decoder. Every variant carries the byte offset at which
/// the violation was detected, to make golden-vector debugging tractable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// Input ended before a complete item could be read.
    UnexpectedEof { offset: usize },
    /// An indefinite-length item (byte/text string, array, map) or a `break` stop code was
    /// encountered. Canonical CBOR never uses indefinite lengths.
    IndefiniteLength { offset: usize },
    /// An integer, length, or count was not encoded in the shortest possible form (e.g. the
    /// value 5 encoded via the 1-byte-argument form instead of inline in the initial byte).
    NonShortestForm { offset: usize },
    /// Additional-info values 28–30 are reserved by RFC 8949 and never valid.
    ReservedAdditionalInfo { offset: usize },
    /// A floating-point item (major type 7, additional info 25/26/27) was encountered.
    /// Canonical Spindle CBOR never carries floats.
    FloatNotAllowed { offset: usize },
    /// A tagged item (major type 6) was encountered. Canonical Spindle CBOR never uses tags.
    TagNotAllowed { offset: usize },
    /// A major-type-7 simple value other than `false`/`true`/`null` was encountered.
    SimpleNotAllowed { offset: usize },
    /// A text string's bytes were not valid UTF-8.
    InvalidUtf8 { offset: usize },
    /// Map keys were not in strictly increasing canonical order (this also covers duplicate
    /// keys, which cannot be strictly increasing).
    MapKeyOrder { offset: usize },
    /// Extra bytes remained after decoding one complete top-level item.
    TrailingBytes { offset: usize },
    /// An item was nested inside more than [`MAX_NESTING_DEPTH`] enclosing arrays/maps.
    DepthLimitExceeded { offset: usize },
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::UnexpectedEof { offset } => {
                write!(f, "unexpected end of input at offset {offset}")
            }
            CborError::IndefiniteLength { offset } => write!(
                f,
                "indefinite-length items are not allowed in canonical CBOR (offset {offset})"
            ),
            CborError::NonShortestForm { offset } => write!(
                f,
                "integer/length not encoded in shortest form (offset {offset})"
            ),
            CborError::ReservedAdditionalInfo { offset } => {
                write!(f, "reserved additional-info value (offset {offset})")
            }
            CborError::FloatNotAllowed { offset } => {
                write!(f, "floating-point values are not allowed (offset {offset})")
            }
            CborError::TagNotAllowed { offset } => {
                write!(f, "CBOR tags are not allowed (offset {offset})")
            }
            CborError::SimpleNotAllowed { offset } => {
                write!(f, "simple value not allowed (offset {offset})")
            }
            CborError::InvalidUtf8 { offset } => {
                write!(f, "invalid UTF-8 in text string (offset {offset})")
            }
            CborError::MapKeyOrder { offset } => write!(
                f,
                "map keys are not in strictly increasing canonical order (offset {offset})"
            ),
            CborError::TrailingBytes { offset } => {
                write!(f, "trailing bytes after top-level item (offset {offset})")
            }
            CborError::DepthLimitExceeded { offset } => write!(
                f,
                "nesting deeper than {MAX_NESTING_DEPTH} levels (offset {offset})"
            ),
        }
    }
}

impl std::error::Error for CborError {}

/// Encodes a `CborValue` tree to canonical CBOR bytes.
pub fn canonical_encode(value: &CborValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// Decodes exactly one canonical CBOR item from `bytes`, rejecting the item (and any trailing
/// bytes) if it is not fully canonical per RFC 8949 §4.2.1.
pub fn canonical_decode(bytes: &[u8]) -> Result<CborValue, CborError> {
    let (value, consumed) = decode_one(bytes, 0, 0)?;
    if consumed != bytes.len() {
        return Err(CborError::TrailingBytes { offset: consumed });
    }
    Ok(value)
}

// ---- encode ----

fn write_header(out: &mut Vec<u8>, major: u8, value: u64) {
    let m = major << 5;
    if value < 24 {
        out.push(m | value as u8);
    } else if value <= 0xFF {
        out.push(m | 24);
        out.push(value as u8);
    } else if value <= 0xFFFF {
        out.push(m | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFF_FFFF {
        out.push(m | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_into(value: &CborValue, out: &mut Vec<u8>) {
    match value {
        CborValue::Uint(v) => write_header(out, 0, *v),
        CborValue::NegInt(v) => write_header(out, 1, *v),
        CborValue::Bytes(b) => {
            write_header(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        CborValue::Text(s) => {
            write_header(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        CborValue::Array(items) => {
            write_header(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        CborValue::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                .iter()
                .map(|(k, v)| {
                    let mut kb = Vec::new();
                    encode_into(k, &mut kb);
                    let mut vb = Vec::new();
                    encode_into(v, &mut vb);
                    (kb, vb)
                })
                .collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            debug_assert!(
                encoded.windows(2).all(|w| w[0].0 != w[1].0),
                "CborValue::Map constructed with duplicate keys"
            );
            write_header(out, 5, encoded.len() as u64);
            for (kb, vb) in encoded {
                out.extend_from_slice(&kb);
                out.extend_from_slice(&vb);
            }
        }
        CborValue::Bool(false) => out.push(0xf4),
        CborValue::Bool(true) => out.push(0xf5),
        CborValue::Null => out.push(0xf6),
    }
}

// ---- decode ----

/// Reads the argument (integer value / length / count) for a major type whose additional-info
/// byte lives at `bytes[offset - 1]` (already consumed by the caller) with value `info`.
/// Enforces shortest-form encoding.
fn read_arg(
    bytes: &[u8],
    offset: usize,
    info: u8,
    head_offset: usize,
) -> Result<(u64, usize), CborError> {
    match info {
        0..=23 => Ok((info as u64, offset)),
        24 => {
            let b = *bytes
                .get(offset)
                .ok_or(CborError::UnexpectedEof { offset })?;
            if b < 24 {
                return Err(CborError::NonShortestForm {
                    offset: head_offset,
                });
            }
            Ok((b as u64, offset + 1))
        }
        25 => {
            let end = offset + 2;
            let slice = bytes
                .get(offset..end)
                .ok_or(CborError::UnexpectedEof { offset })?;
            let v = u16::from_be_bytes(slice.try_into().unwrap());
            if v <= 0xFF {
                return Err(CborError::NonShortestForm {
                    offset: head_offset,
                });
            }
            Ok((v as u64, end))
        }
        26 => {
            let end = offset + 4;
            let slice = bytes
                .get(offset..end)
                .ok_or(CborError::UnexpectedEof { offset })?;
            let v = u32::from_be_bytes(slice.try_into().unwrap());
            if v <= 0xFFFF {
                return Err(CborError::NonShortestForm {
                    offset: head_offset,
                });
            }
            Ok((v as u64, end))
        }
        27 => {
            let end = offset + 8;
            let slice = bytes
                .get(offset..end)
                .ok_or(CborError::UnexpectedEof { offset })?;
            let v = u64::from_be_bytes(slice.try_into().unwrap());
            if v <= 0xFFFF_FFFF {
                return Err(CborError::NonShortestForm {
                    offset: head_offset,
                });
            }
            Ok((v, end))
        }
        28..=30 => Err(CborError::ReservedAdditionalInfo {
            offset: head_offset,
        }),
        31 => Err(CborError::IndefiniteLength {
            offset: head_offset,
        }),
        _ => unreachable!("additional info is a 5-bit field"),
    }
}

fn decode_one(bytes: &[u8], offset: usize, depth: usize) -> Result<(CborValue, usize), CborError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(CborError::DepthLimitExceeded { offset });
    }
    let head_offset = offset;
    let b = *bytes
        .get(offset)
        .ok_or(CborError::UnexpectedEof { offset })?;
    let major = b >> 5;
    let info = b & 0x1f;
    let offset = offset + 1;

    match major {
        0 => {
            let (v, off) = read_arg(bytes, offset, info, head_offset)?;
            Ok((CborValue::Uint(v), off))
        }
        1 => {
            let (v, off) = read_arg(bytes, offset, info, head_offset)?;
            Ok((CborValue::NegInt(v), off))
        }
        2 => {
            let (len, off) = read_arg(bytes, offset, info, head_offset)?;
            let len = len as usize;
            let end = off
                .checked_add(len)
                .ok_or(CborError::UnexpectedEof { offset: off })?;
            let slice = bytes
                .get(off..end)
                .ok_or(CborError::UnexpectedEof { offset: off })?;
            Ok((CborValue::Bytes(slice.to_vec()), end))
        }
        3 => {
            let (len, off) = read_arg(bytes, offset, info, head_offset)?;
            let len = len as usize;
            let end = off
                .checked_add(len)
                .ok_or(CborError::UnexpectedEof { offset: off })?;
            let slice = bytes
                .get(off..end)
                .ok_or(CborError::UnexpectedEof { offset: off })?;
            let s = std::str::from_utf8(slice)
                .map_err(|_| CborError::InvalidUtf8 { offset: off })?
                .to_string();
            Ok((CborValue::Text(s), end))
        }
        4 => {
            let (count, mut off) = read_arg(bytes, offset, info, head_offset)?;
            // Bound the count against the input before allocating against it. Every element
            // costs at least one byte, so a count exceeding the bytes remaining can never be
            // satisfied — and `count` is attacker-controlled, reached pre-authentication on
            // both the signaling and auth-callout decode paths. The byte- and text-string
            // branches above already bound their length the same way; this branch did not,
            // and a 9-byte payload could drive `Vec::with_capacity` to abort the process.
            // Compared in `u64` rather than via `count as usize` so a 32-bit target cannot
            // truncate a large count into a small, passing one.
            let remaining = bytes.len().saturating_sub(off) as u64;
            if count > remaining {
                return Err(CborError::UnexpectedEof { offset: off });
            }
            let mut items = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let (item, next) = decode_one(bytes, off, depth + 1)?;
                items.push(item);
                off = next;
            }
            Ok((CborValue::Array(items), off))
        }
        5 => {
            let (count, mut off) = read_arg(bytes, offset, info, head_offset)?;
            // Same bound as the array branch above, halved: a map entry is a key *and* a
            // value, so each costs at least two bytes. Written as `remaining / 2` rather than
            // `2 * count` so the comparison cannot itself overflow.
            let remaining = bytes.len().saturating_sub(off) as u64;
            if count > remaining / 2 {
                return Err(CborError::UnexpectedEof { offset: off });
            }
            let mut entries = Vec::with_capacity(count as usize);
            let mut prev_key_bytes: Option<&[u8]> = None;
            for _ in 0..count {
                let key_start = off;
                let (key, after_key) = decode_one(bytes, off, depth + 1)?;
                let key_bytes = &bytes[key_start..after_key];
                if let Some(prev) = prev_key_bytes {
                    if key_bytes <= prev {
                        return Err(CborError::MapKeyOrder { offset: key_start });
                    }
                }
                let (val, after_val) = decode_one(bytes, after_key, depth + 1)?;
                entries.push((key, val));
                prev_key_bytes = Some(&bytes[key_start..after_key]);
                off = after_val;
            }
            Ok((CborValue::Map(entries), off))
        }
        6 => Err(CborError::TagNotAllowed {
            offset: head_offset,
        }),
        7 => match info {
            20 => Ok((CborValue::Bool(false), offset)),
            21 => Ok((CborValue::Bool(true), offset)),
            22 => Ok((CborValue::Null, offset)),
            23 => Err(CborError::SimpleNotAllowed {
                offset: head_offset,
            }),
            24 => Err(CborError::SimpleNotAllowed {
                offset: head_offset,
            }),
            25..=27 => Err(CborError::FloatNotAllowed {
                offset: head_offset,
            }),
            28..=30 => Err(CborError::ReservedAdditionalInfo {
                offset: head_offset,
            }),
            31 => Err(CborError::IndefiniteLength {
                offset: head_offset,
            }),
            _ => unreachable!("additional info is a 5-bit field"),
        },
        _ => unreachable!("major type is a 3-bit field"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(v: &CborValue) -> Vec<u8> {
        let bytes = canonical_encode(v);
        let decoded = canonical_decode(&bytes).expect("round-trip decode");
        assert_eq!(&decoded, v, "decoded value differs from original");
        let re_encoded = canonical_encode(&decoded);
        assert_eq!(bytes, re_encoded, "re-encoding decoded value changed bytes");
        bytes
    }

    #[test]
    fn uint_shortest_form_boundaries() {
        assert_eq!(rt(&CborValue::Uint(0)), vec![0x00]);
        assert_eq!(rt(&CborValue::Uint(23)), vec![0x17]);
        assert_eq!(rt(&CborValue::Uint(24)), vec![0x18, 24]);
        assert_eq!(rt(&CborValue::Uint(255)), vec![0x18, 0xff]);
        assert_eq!(rt(&CborValue::Uint(256)), vec![0x19, 0x01, 0x00]);
        assert_eq!(rt(&CborValue::Uint(65535)), vec![0x19, 0xff, 0xff]);
        assert_eq!(
            rt(&CborValue::Uint(65536)),
            vec![0x1a, 0x00, 0x01, 0x00, 0x00]
        );
        assert_eq!(
            rt(&CborValue::Uint(4_294_967_295)),
            vec![0x1a, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            rt(&CborValue::Uint(4_294_967_296)),
            vec![0x1b, 0, 0, 0, 1, 0, 0, 0, 0]
        );
    }

    #[test]
    fn map_keys_sort_by_length_then_content() {
        // "z" (1 byte, header 0x61) sorts before "aa" (2 bytes, header 0x62), even though "aa" <
        // "z" lexicographically — canonical CBOR sorts by encoded bytes, which puts shorter keys
        // first.
        let v = CborValue::map(vec![("aa", CborValue::Uint(1)), ("z", CborValue::Uint(2))]);
        let bytes = rt(&v);
        // map(2) 61 'z' 02  62 'a' 'a' 01
        assert_eq!(bytes, vec![0xa2, 0x61, b'z', 0x02, 0x62, b'a', b'a', 0x01]);
    }

    #[test]
    fn rejects_non_shortest_form_int() {
        // 0x18 0x05 encodes 5 using the 1-byte-argument form; canonical form is 0x05.
        let err = canonical_decode(&[0x18, 0x05]).unwrap_err();
        assert_eq!(err, CborError::NonShortestForm { offset: 0 });
    }

    #[test]
    fn rejects_indefinite_length_array() {
        // 0x9f = indefinite-length array start.
        let err = canonical_decode(&[0x9f, 0x01, 0xff]).unwrap_err();
        assert_eq!(err, CborError::IndefiniteLength { offset: 0 });
    }

    #[test]
    fn rejects_out_of_order_map_keys() {
        // map(2) { "aa": 1, "z": 2 } on the wire, in that order. Canonical order requires the
        // shorter key "z" (1 byte) before the longer key "aa" (2 bytes), so this is invalid.
        let bytes = vec![0xa2, 0x62, b'a', b'a', 0x01, 0x61, b'z', 0x02];
        let err = canonical_decode(&bytes).unwrap_err();
        assert!(matches!(err, CborError::MapKeyOrder { .. }));
    }

    #[test]
    fn rejects_duplicate_map_keys() {
        let bytes = vec![0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
        let err = canonical_decode(&bytes).unwrap_err();
        assert!(matches!(err, CborError::MapKeyOrder { .. }));
    }

    #[test]
    fn rejects_float() {
        // 0xfa = float32 major type 7 info 26.
        let err = canonical_decode(&[0xfa, 0, 0, 0, 0]).unwrap_err();
        assert!(matches!(err, CborError::FloatNotAllowed { .. }));
    }

    #[test]
    fn rejects_tag() {
        // 0xc0 = tag(0).
        let err = canonical_decode(&[0xc0, 0x00]).unwrap_err();
        assert!(matches!(err, CborError::TagNotAllowed { .. }));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let err = canonical_decode(&[0x00, 0x00]).unwrap_err();
        assert_eq!(err, CborError::TrailingBytes { offset: 1 });
    }

    #[test]
    fn rejects_array_count_exceeding_input() {
        // 0x9b = array, 8-byte count. Count u64::MAX in nine total bytes. Before the count was
        // bounded this reached `Vec::with_capacity` and aborted the process; a payload this
        // shape is decoded pre-authentication on both the signaling and auth-callout paths.
        let err =
            canonical_decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap_err();
        assert!(matches!(err, CborError::UnexpectedEof { .. }));

        // An intermediate count is the more dangerous case: large enough to be a ~68 GB
        // allocation, small enough that the allocator may abort rather than panic.
        let err = canonical_decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]).unwrap_err();
        assert!(matches!(err, CborError::UnexpectedEof { .. }));
    }

    #[test]
    fn rejects_map_count_exceeding_input() {
        // 0xbb = map, 8-byte count.
        let err =
            canonical_decode(&[0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap_err();
        assert!(matches!(err, CborError::UnexpectedEof { .. }));

        // 0xbf is indefinite-length, so use the 4-byte-count form for the intermediate case.
        let err = canonical_decode(&[0xba, 0xff, 0xff, 0xff, 0xff]).unwrap_err();
        assert!(matches!(err, CborError::UnexpectedEof { .. }));
    }

    #[test]
    fn count_bound_admits_every_satisfiable_length() {
        // The bound must reject only counts that *cannot* be satisfied. array(3) of three
        // one-byte uints is exactly at the limit — three elements, three bytes remaining.
        let v = canonical_decode(&[0x83, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(
            v,
            CborValue::array(vec![
                CborValue::Uint(1),
                CborValue::Uint(2),
                CborValue::Uint(3)
            ])
        );

        // map(1) { 1: 2 } is exactly at the halved limit — one entry, two bytes remaining.
        let v = canonical_decode(&[0xa1, 0x01, 0x02]).unwrap();
        assert_eq!(
            v,
            CborValue::Map(vec![(CborValue::Uint(1), CborValue::Uint(2))])
        );

        // Empty array and empty map: count 0 with zero bytes remaining must still decode.
        assert_eq!(canonical_decode(&[0x80]).unwrap(), CborValue::array(vec![]));
        assert_eq!(canonical_decode(&[0xa0]).unwrap(), CborValue::Map(vec![]));
    }

    #[test]
    fn count_bound_rejects_one_past_the_limit() {
        // NOTE: this is a boundary test, not a regression test for the count bound — it passes
        // with the guard deleted, because the decode loop already runs out of bytes one element
        // short. `rejects_array_count_exceeding_input` / `rejects_map_count_exceeding_input` are
        // the tests that fail without the guard.
        // array(4) with only three bytes left, and map(2) with only three bytes left: both are
        // one past what the input can supply, and both must fail before allocating.
        let err = canonical_decode(&[0x84, 0x01, 0x02, 0x03]).unwrap_err();
        assert!(matches!(err, CborError::UnexpectedEof { .. }));
        let err = canonical_decode(&[0xa2, 0x01, 0x02, 0x03]).unwrap_err();
        assert!(matches!(err, CborError::UnexpectedEof { .. }));
    }

    #[test]
    fn accepts_nesting_up_to_the_limit() {
        // MAX_NESTING_DEPTH enclosing arrays, each count 1, then a terminal uint.
        let mut bytes = vec![0x81u8; MAX_NESTING_DEPTH];
        bytes.push(0x00);
        assert!(canonical_decode(&bytes).is_ok());
    }

    #[test]
    fn rejects_nesting_past_the_limit() {
        // One deeper. Without this guard a large N here aborts the process outright via stack
        // overflow — an abort, not a panic, so no test harness could catch it.
        let mut bytes = vec![0x81u8; MAX_NESTING_DEPTH + 1];
        bytes.push(0x00);
        let err = canonical_decode(&bytes).unwrap_err();
        assert!(matches!(err, CborError::DepthLimitExceeded { .. }));
    }

    #[test]
    fn deep_payload_that_previously_aborted_is_now_rejected() {
        // 20_000 nested arrays: measured to abort a release build on an 8 MiB stack, and a
        // debug build at a twentieth of that. Must now return an error instead.
        let mut bytes = vec![0x81u8; 20_000];
        bytes.push(0x00);
        let err = canonical_decode(&bytes).unwrap_err();
        assert!(matches!(err, CborError::DepthLimitExceeded { .. }));
    }

    #[test]
    fn depth_limit_applies_through_maps_too() {
        // map(1) { 0: <next> } repeated — the map branch recurses twice per level (key, value),
        // so it needs its own coverage.
        let mut bytes = Vec::new();
        for _ in 0..(MAX_NESTING_DEPTH + 1) {
            bytes.push(0xa1);
            bytes.push(0x00);
        }
        bytes.push(0x00);
        let err = canonical_decode(&bytes).unwrap_err();
        assert!(matches!(err, CborError::DepthLimitExceeded { .. }));
    }

    #[test]
    fn byte_string_and_array_round_trip() {
        rt(&CborValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef]));
        rt(&CborValue::array(vec![
            CborValue::Uint(1),
            CborValue::Uint(2),
            CborValue::Uint(3),
        ]));
        rt(&CborValue::Bool(true));
        rt(&CborValue::Bool(false));
        rt(&CborValue::Null);
    }
}
