//! Guards the mistake [`spindle_core::Fingerprint::redacted`] exists to prevent: a `tracing::`
//! macro call that interpolates an untruncated identifier or path via the `%ident`/`?ident`
//! field-shorthand syntax, in violation of DESIGN.md:850's "[USER DECISION] ... no payload
//! logging" and the fact that Spindle is zero-knowledge by design (a host log full of complete
//! fingerprints and paths would itself be a plaintext membership-and-content map on disk).
//!
//! This is a pure text scan over the `.rs` sources of the crates that use (or will use)
//! `tracing` — it does not compile or type-check anything, so it runs under a plain `cargo test
//! --workspace` with no extra setup, and does not care whether the scanned crates currently
//! build. Paths are derived from `env!("CARGO_MANIFEST_DIR")`, not the process's current
//! directory, so this also does not depend on where `cargo test` is invoked from.
//!
//! `spindle-core` itself is deliberately not in the scanned set: this ticket's scope is the
//! redaction primitive (`Fingerprint::redacted`), not adding `tracing` as a dependency of
//! `spindle-core`.
//!
//! # This is a heuristic, not a proof
//!
//! It cannot see through indirection: a fingerprint stringified two functions away from its
//! `tracing::` call site, or a `Display`/`Debug` impl on some other type that happens to embed a
//! full fingerprint, is invisible to a scan that only looks at the immediate `%ident`/`?ident`
//! text at the call site. It also cannot always tell that a name change downstream is safe (see
//! the escape hatch below). Treat a passing run as "no *obvious* new leak", not as a
//! confidentiality proof — that is exactly the same honesty [`spindle_core::fingerprint::
//! RedactedFingerprint`]'s own doc comment applies to what redaction protects against.
//!
//! # Escape hatch
//!
//! A binding name matching a suspicious pattern is not always actually unsafe to log (e.g. its
//! value may already have been redacted upstream, several lines before the `tracing::` call).
//! Rather than an allowlist of `file:line`s (which rots the moment a line above it is edited),
//! annotate the *specific line* with a trailing comment: `// redaction-ok: <reason>`. The
//! reason must be non-empty — it exists so the exception is visible in code review, not just to
//! silence this test. See `crates/spindle-helper/src/bin/helper.rs`'s `nats_fps = ?fingerprints`
//! call site for a real example (the `Vec<String>` it logs is built from
//! `Fingerprint::redacted()` output, not full fingerprints, but the binding is still named
//! `fingerprints`).
//!
//! # Neuter-verification
//!
//! This test has been manually confirmed to fail (and to name the offending file/line/binding)
//! when a line like `tracing::warn!(%device_fp, "test");` is added to one of the scanned crates,
//! and to pass again once it is removed. See the `td-6c9d95` step-1 handoff for the exact
//! before/after output; that manual check is not re-run automatically here because deliberately
//! breaking a scanned crate's source on every `cargo test` run would defeat the point of a CI
//! guard.

use std::fs;
use std::path::{Path, PathBuf};

/// Crates this guard scans. `spindle-net` and `spindle-helper` already use `tracing` today;
/// `spindle-host-core`, `spindle-vfs`, `spindle-hostd`, and `spindle-client-core` do not yet —
/// this guard exists to constrain the instrumentation those four crates are about to gain.
const IN_SCOPE_CRATES: &[&str] = &[
    "spindle-host-core",
    "spindle-vfs",
    "spindle-hostd",
    "spindle-client-core",
    "spindle-net",
    "spindle-helper",
];

/// The `tracing` macros this guard looks inside.
const MACRO_LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error"];

/// A trailing line comment that marks one specific interpolation as a deliberate, reviewed
/// exception. Must be followed by a non-empty reason — see this file's module doc comment.
const ESCAPE_HATCH_MARKER: &str = "// redaction-ok:";

/// A binding name is suspicious if its last dot-separated segment matches one of these — a
/// deliberately loose heuristic (see module doc comment), not a type check.
fn is_suspicious(binding: &str) -> bool {
    let last = binding
        .rsplit('.')
        .next()
        .unwrap_or(binding)
        .to_ascii_lowercase();
    last.ends_with("_fp")
        || last.contains("fingerprint")
        || last.contains("path")
        || last.contains("member_id")
        || last.contains("group")
        || last.contains("cap")
}

#[test]
fn tracing_calls_never_interpolate_untruncated_identifiers_or_paths() {
    let workspace_root = workspace_root();
    let mut violations = Vec::new();

    for crate_name in IN_SCOPE_CRATES {
        let src_dir = workspace_root.join("crates").join(crate_name).join("src");
        assert!(
            src_dir.is_dir(),
            "expected an in-scope crate's source directory to exist at {} — did the crate get \
             renamed or moved?",
            src_dir.display()
        );

        for file in rust_files_under(&src_dir) {
            let original = fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", file.display()));
            let masked_bytes = mask_non_code(original.as_bytes());
            let masked = String::from_utf8(masked_bytes)
                .expect("masking only replaces bytes with ASCII spaces/newlines, so UTF-8 validity is preserved");

            for (span_start, span_end) in find_macro_spans(&masked) {
                for (sigil_pos, binding, safe_via_redacted_call) in
                    scan_span_for_bindings(masked.as_bytes(), span_start, span_end)
                {
                    if safe_via_redacted_call || !is_suspicious(&binding) {
                        continue;
                    }
                    let line_no = line_number_at(&original, sigil_pos);
                    let line_text = original.lines().nth(line_no - 1).unwrap_or("");
                    if has_escape_hatch(line_text) {
                        continue;
                    }
                    violations.push(format!(
                        "{}:{line_no}: `tracing::` call interpolates `{binding}`, which looks \
                         like an untruncated identifier or path (matches this guard's \
                         suspicious-name heuristic). Fix with `.redacted()` (see \
                         `spindle_core::Fingerprint::redacted`), or if this specific \
                         interpolation is already safe, annotate the line with \
                         `{ESCAPE_HATCH_MARKER} <reason>`.",
                        file.display(),
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\nredaction_guard found {} untruncated identifier(s)/path(s) interpolated into a \
         `tracing::` call:\n\n{}\n",
        violations.len(),
        violations.join("\n"),
    );
}

/// `crates/spindle-core` sits two directories below the workspace root
/// (`<root>/crates/spindle-core`); derive `<root>` from `CARGO_MANIFEST_DIR` rather than the
/// process's current directory, so this test doesn't depend on where `cargo test` was invoked
/// from.
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| {
            panic!(
                "expected {} to be two directories below the workspace root",
                manifest_dir.display()
            )
        })
        .to_path_buf();
    assert!(
        root.join("Cargo.toml").is_file(),
        "derived workspace root {} has no Cargo.toml — CARGO_MANIFEST_DIR layout assumption is wrong",
        root.display()
    );
    root
}

/// Recursively collects `.rs` files under `dir`, sorted for deterministic reporting.
fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries =
            fs::read_dir(&d).unwrap_or_else(|e| panic!("failed to read dir {}: {e}", d.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("failed to read a dir entry under {}: {e}", d.display()))
                .path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Replaces the contents of `//` line comments, `/* */` block comments, and `"..."` string
/// literals with ASCII spaces, byte-for-byte (newlines are always preserved, everywhere), so
/// that later scanning never mistakes comment/string text for real syntax — e.g. a doc comment
/// mentioning `tracing::warn!(%device_fp, ...)` as an example must not itself be flagged — while
/// every byte offset in the output still lines up with the same offset (and line number) in the
/// original source.
///
/// Deliberately simple: this does not special-case raw strings (`r"..."`/`r#"..."#`) or char
/// literals/lifetimes (`'a`). Neither shape appears inside a `tracing::` call's arguments
/// anywhere in this workspace today; a heuristic guard test doesn't need a full Rust tokenizer.
fn mask_non_code(src: &[u8]) -> Vec<u8> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Code,
        LineComment,
        BlockComment,
        Str,
    }

    let mut mode = Mode::Code;
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    let mut escaped = false;

    while i < src.len() {
        let b = src[i];
        let next = src.get(i + 1).copied();
        match mode {
            Mode::Code => {
                if b == b'/' && next == Some(b'/') {
                    mode = Mode::LineComment;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                if b == b'/' && next == Some(b'*') {
                    mode = Mode::BlockComment;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                if b == b'"' {
                    mode = Mode::Str;
                    out.push(b' ');
                    i += 1;
                    continue;
                }
                out.push(b);
                i += 1;
            }
            Mode::LineComment => {
                out.push(if b == b'\n' {
                    mode = Mode::Code;
                    b'\n'
                } else {
                    b' '
                });
                i += 1;
            }
            Mode::BlockComment => {
                if b == b'*' && next == Some(b'/') {
                    mode = Mode::Code;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                out.push(if b == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            Mode::Str => {
                if escaped {
                    escaped = false;
                    out.push(if b == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                    continue;
                }
                if b == b'\\' {
                    escaped = true;
                    out.push(b' ');
                    i += 1;
                    continue;
                }
                if b == b'"' {
                    mode = Mode::Code;
                    out.push(b' ');
                    i += 1;
                    continue;
                }
                out.push(if b == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
        }
    }
    out
}

/// Finds every `tracing::{trace,debug,info,warn,error}!( ... )` call in `masked` (comments and
/// string contents already blanked out — see [`mask_non_code`]) and returns the byte range of
/// its argument list, exclusive of the enclosing parens.
fn find_macro_spans(masked: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let bytes = masked.as_bytes();
    let mut search_from = 0;

    while let Some(rel) = masked[search_from..].find("tracing::") {
        let after_kw = search_from + rel + "tracing::".len();
        let rest = &masked[after_kw..];
        let ident_len = rest.bytes().take_while(u8::is_ascii_alphabetic).count();
        let level = &rest[..ident_len];

        let mut next_search_from = after_kw;
        if MACRO_LEVELS.contains(&level) {
            let mut p = after_kw + ident_len;
            p += bytes[p..]
                .iter()
                .take_while(|b| b.is_ascii_whitespace())
                .count();
            if bytes.get(p) == Some(&b'!') {
                p += 1;
                p += bytes[p..]
                    .iter()
                    .take_while(|b| b.is_ascii_whitespace())
                    .count();
                if bytes.get(p) == Some(&b'(') {
                    if let Some(close) = find_matching_paren(bytes, p) {
                        spans.push((p + 1, close));
                        next_search_from = close + 1;
                    }
                }
            }
        }
        search_from = next_search_from.max(after_kw + 1);
    }
    spans
}

/// Returns the index of the `)` matching the `(` at `open_idx`, by depth counting. Safe to run
/// on [`mask_non_code`]'s output because parens inside strings/comments have already been
/// blanked out, so every remaining paren is real syntax.
fn find_matching_paren(bytes: &[u8], open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut idx = open_idx;
    while idx < bytes.len() {
        match bytes[idx] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

/// Scans `masked[span_start..span_end]` (one `tracing::` call's argument list) for the
/// `%binding` / `?binding` field-shorthand syntax, where `binding` is a bare identifier or a
/// dotted field-access path (e.g. `target.nats_fp`). Returns, for each one found: its absolute
/// byte offset (for line-number lookup), the binding text, and whether it is immediately
/// followed by a call to `.redacted()` (the one shape this guard treats as self-evidently safe
/// without needing an escape-hatch comment).
fn scan_span_for_bindings(
    masked: &[u8],
    span_start: usize,
    span_end: usize,
) -> Vec<(usize, String, bool)> {
    fn is_ident_start(b: u8) -> bool {
        b.is_ascii_alphabetic() || b == b'_'
    }
    fn is_ident_continue(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    let mut results = Vec::new();
    let mut i = span_start;
    while i < span_end {
        let c = masked[i];
        if (c == b'%' || c == b'?') && i + 1 < span_end && is_ident_start(masked[i + 1]) {
            let sigil_pos = i;
            let mut j = i + 1;
            let mut binding = String::new();
            loop {
                let seg_start = j;
                while j < span_end && is_ident_continue(masked[j]) {
                    j += 1;
                }
                binding.push_str(
                    std::str::from_utf8(&masked[seg_start..j]).expect("ident bytes are ASCII"),
                );
                if j < span_end
                    && masked[j] == b'.'
                    && j + 1 < span_end
                    && is_ident_start(masked[j + 1])
                {
                    binding.push('.');
                    j += 1;
                } else {
                    break;
                }
            }
            let followed_by_call = j < span_end && masked[j] == b'(';
            let last_segment = binding.rsplit('.').next().unwrap_or("");
            let safe_via_redacted_call = followed_by_call && last_segment == "redacted";
            results.push((sigil_pos, binding, safe_via_redacted_call));
            i = j;
            continue;
        }
        i += 1;
    }
    results
}

/// 1-based line number containing `byte_offset` in `src`.
fn line_number_at(src: &str, byte_offset: usize) -> usize {
    src.as_bytes()[..byte_offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Whether `line` carries the escape-hatch marker with a non-empty reason after it. See this
/// file's module doc comment for why this is a per-line comment rather than a `file:line`
/// allowlist.
fn has_escape_hatch(line: &str) -> bool {
    line.find(ESCAPE_HATCH_MARKER)
        .map(|pos| !line[pos + ESCAPE_HATCH_MARKER.len()..].trim().is_empty())
        .unwrap_or(false)
}
