//! Unit tests for `common::mask_non_code`, the masker shared by this crate's text-scanning CI
//! guards. Pins the two hard invariants (length preserved, newline positions preserved) and the
//! specific constructs the masker must recognize: line comments, nesting block comments, raw
//! strings (including the `br`/`cr` prefixed and multi-hash forms), plain/byte/C strings, char
//! and byte-char literals, and lifetimes staying visible as code.

mod common;

use common::mask_non_code;

fn masked(s: &str) -> String {
    String::from_utf8(mask_non_code(s.as_bytes())).unwrap()
}

#[test]
fn regression_td_5a459e_backslash_terminated_raw_string_does_not_swallow_later_code() {
    // td-5a459e: `crates/spindle-vfs/src/confine/windows.rs`'s
    // `relative.starts_with(r"\\?\")` is a raw string whose CONTENT ends in a backslash. A
    // masker that enters string mode at the opening `"` and treats that trailing backslash as
    // an escape swallows the real closing `"` and never recovers, hiding all following code.
    let src = r#"let v = relative.starts_with(r"\\?\");
tracing::warn!(%device_fp, "probe");
"#;
    let out = masked(src);
    assert!(
        out.contains("tracing::warn!"),
        "masked output lost real code after the backslash-terminated raw string: {out:?}"
    );
}

#[test]
fn raw_string_simple_is_masked_code_around_stays_visible() {
    let src = r##"before(); let s = r"simple"; after();"##;
    let out = masked(src);
    assert!(out.contains("before();"));
    assert!(out.contains("after();"));
    assert!(!out.contains("simple"));
}

#[test]
fn raw_string_hashed_with_inner_quotes_is_not_terminated_early() {
    let src = r###"before(); let s = r#"has "quotes" inside"#; after();"###;
    let out = masked(src);
    assert!(out.contains("before();"));
    assert!(out.contains("after();"));
    assert!(!out.contains("quotes"));
}

#[test]
fn raw_string_double_hash_with_single_inner_hash_quote_is_not_terminated_early() {
    let src = r#####"before(); let s = r##"contains "# not a terminator"##; after();"#####;
    let out = masked(src);
    assert!(out.contains("before();"));
    assert!(out.contains("after();"));
    assert!(!out.contains("terminator"));
}

#[test]
fn ident_boundary_guard_stops_a_trailing_r_becoming_a_raw_string_prefix() {
    // This shape is not valid Rust and does not occur in the scanned crates; the guard in
    // `raw_string_len` is defensive. The test pins the branch so it isn't silently removable.
    let src = r#"let sugar"x" = 1;"#;
    let out = masked(src);
    assert!(
        out.contains("sugar"),
        "the identifier's trailing r must stay visible: {out:?}"
    );
    assert!(
        !out.contains('x'),
        "the string literal \"x\" must be masked: {out:?}"
    );
}

#[test]
fn raw_byte_and_c_string_prefixed_forms_are_masked() {
    let src = r####"let a = br"bytes"; let b = br#"bytes"#; let c = cr#"cstr"#; after();"####;
    let out = masked(src);
    assert!(!out.contains("bytes"));
    assert!(!out.contains("cstr"));
    assert!(out.contains("after();"));
}

#[test]
fn byte_string_and_c_string_are_masked() {
    let src = r#"let a = b"byte string"; let c = c"c string"; after();"#;
    let out = masked(src);
    assert!(!out.contains("byte string"));
    assert!(!out.contains("c string"));
    assert!(out.contains("after();"));
}

#[test]
fn raw_identifier_stays_visible_but_following_string_is_masked() {
    let src = r#"let r#type = 1; let s = "x";"#;
    let out = masked(src);
    assert!(
        out.contains("r#type"),
        "raw identifier must remain visible as code: {out:?}"
    );
    assert!(
        !out.contains('x'),
        "the string literal \"x\" must be masked: {out:?}"
    );
}

#[test]
fn single_letter_r_string_content_does_not_desync_the_scanner() {
    // The real shape this guards against: a plain string whose content happens to be the
    // letter r, e.g. `"r".repeat(..)`, must not be mistaken for a raw-string prefix.
    let src = r#"let s = "r"; let t = 1;"#;
    let out = masked(src);
    assert!(
        out.contains("let t = 1;"),
        "code after the string must stay visible: {out:?}"
    );
}

#[test]
fn escaped_quote_inside_a_string_does_not_terminate_it() {
    let src = r#"let s = "a\"b"; after();"#;
    let out = masked(src);
    assert!(
        out.contains("after();"),
        "code after the string must stay visible: {out:?}"
    );
    // A masker that treats the escaped quote as a real terminator would end the string right
    // after it, leaving the trailing `b` (and the real `"` that follows it) as visible "code".
    assert!(
        !out.contains('b'),
        "escaped quote must not terminate the string: {out:?}"
    );
}

#[test]
fn char_literal_containing_a_quote_does_not_desync_the_scanner() {
    let src = r#"let c = '"'; after();"#;
    let out = masked(src);
    assert!(
        out.contains("after();"),
        "code after the char literal must stay visible: {out:?}"
    );
}

#[test]
fn char_and_byte_char_literals_are_masked_surrounding_code_visible() {
    let src = r#"let a = '\''; let b = '\\'; let c = '\u{2764}'; let d = 'x'; let e = b'x'; z();"#;
    let out = masked(src);
    assert!(out.contains("let a ="));
    assert!(out.contains("let b ="));
    assert!(out.contains("let c ="));
    assert!(out.contains("let d ="));
    assert!(out.contains("let e ="));
    assert!(out.contains("z();"));
    assert!(
        !out.contains("2764"),
        "char literal content must be masked: {out:?}"
    );
}

#[test]
fn lifetimes_stay_visible_as_code() {
    let src = "fn f<'a>(x: &'a str) -> &'static str { x } let _y: &'_ i32 = ptr;";
    let out = masked(src);
    // No comment, string, or char literal exists in this fixture, so nothing should be masked.
    assert_eq!(
        out, src,
        "lifetimes must never be treated as char literals: {out:?}"
    );
}

#[test]
fn nested_block_comment_is_fully_consumed_before_real_code() {
    let src = "/* outer /* inner */ still comment */ real_code();";
    let out = masked(src);
    assert!(out.contains("real_code();"));
    assert!(!out.contains("still comment"));
    assert!(!out.contains("outer"));
    assert!(!out.contains("inner"));
}

#[test]
fn line_comment_is_masked_and_its_trailing_newline_survives() {
    let src = "// comment\ncode();\n";
    let out = masked(src);
    assert!(!out.contains("comment"));
    assert!(out.contains("code();"));
    assert_eq!(out.as_bytes()[10], b'\n');
}

#[test]
fn doc_comment_containing_tracing_warn_is_fully_masked() {
    // The original reason this masker exists: a doc comment that quotes `tracing::warn!` as
    // prose must not itself look like the code a guard is scanning for.
    let src = "/// tracing::warn!(%x, \"y\");\ncode();\n";
    let out = masked(src);
    assert!(!out.contains("tracing::warn!"));
    assert!(out.contains("code();"));
}

#[test]
fn unterminated_literals_and_truncated_input_never_panic_and_preserve_length() {
    let cases: &[&str] = &[
        "\"abc",
        r####"r#"abc"####,
        "/* abc",
        "let x = 'a",
        "'",
        "",
        "b",
        "r",
        "b\"",
    ];
    for &src in cases {
        let out = mask_non_code(src.as_bytes());
        assert_eq!(
            out.len(),
            src.len(),
            "length must be preserved for unterminated input {src:?}"
        );
    }
}

#[test]
fn length_and_newline_positions_are_preserved_over_a_mixed_multiline_fixture() {
    // Newlines must also cross `blank_span` while masking constructs that span several
    // lines, so this fixture nests a comment and wraps a raw string and a plain string
    // across newlines, in addition to keeping the original single-line cases below.
    let src = r##"// line comment
/* block comment
spanning lines with a /* nested */ comment
still commented */
let a = r"raw \ content";
let raw_multi = r#"raw string
spanning
lines"#;
let b = "plain \"escaped\" string";
let multi_line = "plain string
spanning a line";
let c = '"';
let d = 'x';
let e: &'static str = "ok";
tracing::warn!(%device_fp, "still here");
"##;
    let out_bytes = mask_non_code(src.as_bytes());

    assert_eq!(out_bytes.len(), src.len());

    let src_bytes = src.as_bytes();
    for k in 0..src_bytes.len() {
        assert_eq!(
            out_bytes[k] == b'\n',
            src_bytes[k] == b'\n',
            "newline mismatch at byte offset {k}"
        );
    }

    let out = String::from_utf8(out_bytes).unwrap();
    assert!(out.contains("tracing::warn!"));
}

#[test]
fn line_numbers_survive_masking_of_multi_line_constructs() {
    // Guards derive a line number by counting newlines before a match offset in the
    // masked text. Pin that this count matches the original source even after a
    // multi-line comment and a multi-line raw string have been blanked out.
    let src = r##"/* block comment
spanning several
lines */
let raw_multi = r#"raw string
spanning
several lines"#;
tracing::warn!(%device_fp, "probe");
"##;
    let out_bytes = mask_non_code(src.as_bytes());
    let out = String::from_utf8(out_bytes).unwrap();

    let needle = "tracing::warn!";
    assert!(
        out.contains(needle),
        "masked output must still show the call: {out:?}"
    );

    let src_offset = src.find(needle).expect("needle must be present in source");
    let out_offset = out
        .find(needle)
        .expect("needle must be present in masked output");

    let src_line = src.as_bytes()[..src_offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count();
    let out_line = out.as_bytes()[..out_offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count();

    assert_eq!(
        src_line, out_line,
        "line number of tracing::warn! must survive masking"
    );
}
