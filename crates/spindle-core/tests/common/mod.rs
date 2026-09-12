//! Shared masker used by the text-scanning CI guards under `crates/spindle-core/tests/` (e.g.
//! `redaction_guard.rs`, `clock_source_guard.rs`) so a guard's scan can't mistake comment or
//! string prose for real code. `tests/common/mod.rs` is not itself an auto-discovered test
//! target; each guard pulls it in with `mod common;`.
//!
//! Unlike an earlier state-machine version of this masker, this one makes no attempt to track
//! "am I inside a string/comment" as persistent mode: each call below consumes one whole
//! construct (a comment, a string, a char literal) in a single step, which is easier to audit
//! construct-by-construct than a shared enum with a hidden escape flag.

/// Replaces the contents of `//` line comments, `/* */` block comments (which nest), string and
/// byte/C-string literals (both plain and raw, e.g. `"..."`, `b"..."`, `c"..."`, `r"..."`,
/// `r#"..."#`, `br#"..."#`), and char/byte-char literals with ASCII spaces.
///
/// Two invariants hold for every input, including malformed or unterminated ones:
/// - the output is exactly as long as the input;
/// - a byte is `b'\n'` in the output if and only if it is `b'\n'` in the input.
///
/// This is a lexical approximation, not a Rust parser: it does not track nesting of anything
/// other than block comments, and does not know about macros, `#[cfg]`, or tokenization.
pub fn mask_non_code(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;

    while i < src.len() {
        let b = src[i];
        let next = src.get(i + 1).copied();

        if b == b'/' && next == Some(b'/') {
            let start = i;
            while i < src.len() && src[i] != b'\n' {
                i += 1;
            }
            blank_span(src, start, i, &mut out);
            continue;
        }

        if b == b'/' && next == Some(b'*') {
            let start = i;
            let mut depth: usize = 1;
            i += 2;
            while i < src.len() && depth > 0 {
                if src[i] == b'/' && src.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if src[i] == b'*' && src.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            blank_span(src, start, i, &mut out);
            continue;
        }

        if let Some(len) = raw_string_len(src, i) {
            blank_span(src, i, i + len, &mut out);
            i += len;
            continue;
        }

        if let Some(len) = string_len(src, i) {
            blank_span(src, i, i + len, &mut out);
            i += len;
            continue;
        }

        if let Some(len) = char_literal_len(src, i) {
            blank_span(src, i, i + len, &mut out);
            i += len;
            continue;
        }

        out.push(b);
        i += 1;
    }

    out
}

/// Pushes `src[start..end]` into `out`, replacing every byte with `b' '` except `b'\n'`, which
/// is preserved so line numbers survive.
fn blank_span(src: &[u8], start: usize, end: usize, out: &mut Vec<u8>) {
    for &b in &src[start..end] {
        out.push(if b == b'\n' { b'\n' } else { b' ' });
    }
}

/// True for bytes that can appear inside a Rust identifier, used to guard against reading a
/// trailing `r`/`b`/`c` inside a longer identifier as a string prefix.
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// If `src[i]` begins a raw string (`r"..."`, `r#"..."#`, ..., or a `br`/`cr` prefixed form),
/// returns its total byte length; otherwise `None`. An unterminated raw string returns the
/// number of bytes remaining in `src`, so callers never run past the end of the buffer.
fn raw_string_len(src: &[u8], i: usize) -> Option<usize> {
    if i != 0 && is_ident_byte(src[i - 1]) {
        return None;
    }

    let mut j = i;
    if (src.get(j) == Some(&b'b') || src.get(j) == Some(&b'c')) && src.get(j + 1) == Some(&b'r') {
        j += 1;
    }
    if src.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;

    let mut hashes: usize = 0;
    while src.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if src.get(j) != Some(&b'"') {
        // A raw identifier like `r#type` lands here: after the hashes comes `t`, not `"`.
        return None;
    }
    j += 1;

    let mut k = j;
    loop {
        if k >= src.len() {
            return Some(src.len() - i);
        }
        if src[k] == b'"' {
            let terminator_ok = (0..hashes).all(|h| src.get(k + 1 + h) == Some(&b'#'));
            if terminator_ok {
                return Some(k + 1 + hashes - i);
            }
        }
        k += 1;
    }
}

/// If `src[i]` begins a plain, byte, or C string (`"..."`, `b"..."`, `c"..."`), returns its
/// total byte length; otherwise `None`. Raw strings are handled separately by
/// [`raw_string_len`], which callers must try first. An unterminated string returns the number
/// of bytes remaining in `src`.
fn string_len(src: &[u8], i: usize) -> Option<usize> {
    let content_start = if src[i] == b'"' {
        i + 1
    } else if (src[i] == b'b' || src[i] == b'c')
        && src.get(i + 1) == Some(&b'"')
        && (i == 0 || !is_ident_byte(src[i - 1]))
    {
        i + 2
    } else {
        return None;
    };

    let mut k = content_start;
    loop {
        if k >= src.len() {
            return Some(src.len() - i);
        }
        if src[k] == b'\\' {
            k += 2;
            continue;
        }
        if src[k] == b'"' {
            return Some(k + 1 - i);
        }
        k += 1;
    }
}

/// If `src[i]` begins a char or byte-char literal (`'x'`, `'\n'`, `'\''`, `'\x41'`, `'\u{2764}'`,
/// `b'x'`), returns its total byte length; otherwise `None` — in particular for a lifetime (`'a`,
/// `'static`, `'_`), which has no closing `'` in the position a char literal would have one.
fn char_literal_len(src: &[u8], i: usize) -> Option<usize> {
    if src[i] == b'b' && src.get(i + 1) == Some(&b'\'') && (i == 0 || !is_ident_byte(src[i - 1])) {
        return char_literal_len(src, i + 1).map(|len| len + 1);
    }

    if src[i] != b'\'' {
        return None;
    }

    // Parse the literal's body — one escape sequence or one UTF-8 character — then require
    // the closing `'` to sit immediately after it.
    let mut j = i + 1;
    if j >= src.len() {
        return None;
    }
    if src[j] == b'\\' {
        j += 1;
        if j >= src.len() {
            return None;
        }
        if src[j] == b'u' && src.get(j + 1) == Some(&b'{') {
            j += 2;
            while j < src.len() && src[j] != b'}' {
                j += 1;
            }
            if j >= src.len() {
                return None;
            }
            j += 1;
        } else if src[j] == b'x'
            && src.get(j + 1).is_some_and(|b| b.is_ascii_hexdigit())
            && src.get(j + 2).is_some_and(|b| b.is_ascii_hexdigit())
        {
            j += 3;
        } else {
            j += 1;
        }
    } else {
        j += utf8_char_len(src[j]);
    }
    if src.get(j) == Some(&b'\'') {
        Some(j + 1 - i)
    } else {
        None
    }
}

/// Byte length of the UTF-8 character starting with leading byte `b`, from its high bits.
/// Defaults to `1` for a continuation byte or another invalid leading byte, which cannot occur
/// in valid UTF-8 source text but keeps this defensive rather than panicking.
fn utf8_char_len(b: u8) -> usize {
    if b & 0x80 == 0 {
        1
    } else if b & 0xE0 == 0xC0 {
        2
    } else if b & 0xF0 == 0xE0 {
        3
    } else if b & 0xF8 == 0xF0 {
        4
    } else {
        1
    }
}
