//! Guards the invariant DESIGN.md §A10.42 (td-e8b79f) decided: a client may compute a clock
//! offset from a local bound check against a `HostOpKeyCert.ts` lower bound, and optionally from
//! a configured HTTPS `Date` header — but **both are diagnostic only**. Neither may be fed into
//! signing time, `exp` checks, or revocation checks, because a time source is not an
//! authenticated channel; folding one into a validity check would turn a safe refusal (wrong or
//! compromised clock) into an acceptance of an expired or revoked artifact.
//!
//! That property rests on every artifact validity check in `crates/spindle-core/src/artifacts/`
//! taking its notion of "now" from an explicit caller-supplied parameter, never from an ambient
//! system clock read inside this module. As of this guard's introduction there is no clock
//! source wired into Spindle at all (A10.42's cold-clock diagnostic is not yet implemented), so
//! this test's job is to hold that ground *before* one gets wired in, not to detect a violation
//! after the fact.
//!
//! This is a pure text scan over the `.rs` sources under `src/artifacts/` — it does not compile
//! or type-check anything, so it runs under a plain `cargo test -p spindle-core` with no extra
//! setup. The scan root is derived from `env!("CARGO_MANIFEST_DIR")`, not the process's current
//! directory, so this does not depend on where `cargo test` is invoked from.
//!
//! # This is a heuristic, not a proof
//!
//! It cannot see through indirection: a helper function two calls away that reads the clock and
//! hands the result down as a plain `u64`/`i64` parameter would look identical, at this module's
//! boundary, to a legitimately caller-supplied `now`. Nor can it see a clock read that happens in
//! another crate (e.g. inside a dependency) and is merely passed into `artifacts/` as data. This
//! guard only proves that the specific ambient-clock APIs it knows about — `SystemTime::now`,
//! `Instant::now`, `chrono`'s `Utc::now`/`Local::now`, and `time`/`OffsetDateTime::now_utc` —
//! are not spelled out, as real code, inside these eleven files. Treat a passing run as "no
//! *obvious* new ambient clock read", not as a proof that every `now` value flowing through this
//! module traces back to a caller argument.
//!
//! ## Comments and string literals
//!
//! Matches inside `//` line comments, `/* */` block comments, and `"..."` string literals are
//! deliberately excluded from failing the test: a doc comment that *describes* the forbidden
//! rule (e.g. this very file's own prose, or a doc comment in `artifacts/mod.rs` explaining why
//! `SystemTime::now` must never appear) would otherwise trip the guard it is trying to justify.
//! The masking pass below blanks out comment and string bytes before scanning, exactly as
//! `redaction_guard.rs` does for the same reason — see that file's `mask_non_code` for the
//! precedent this guard's version is copied from.
//!
//! # Neuter-verification
//!
//! Demonstrated on 2026-09-11, not assumed. Appending
//!
//! ```text
//! fn probe_ambient_clock() -> std::time::SystemTime {
//!     let now = std::time::SystemTime::now();
//!     now
//! }
//! ```
//!
//! to `src/artifacts/mod.rs` turned this test RED with
//! `artifacts/mod.rs:328: found `SystemTime::now` (`let now = std::time::SystemTime::now();`)`,
//! and removing it turned the test green again with the file byte-identical to its original
//! (`cmp` clean, `git diff --quiet` clean).
//!
//! The comment- and string-masking was neutered separately in the same run: a line comment
//! containing `SystemTime::now`, a block comment containing `Instant::now` and `chrono`, and a
//! `&str` constant containing `Utc::now` were all appended to the same file at once, and the
//! test stayed green. That is the evidence for the masking claim above — without it, "matches in
//! comments are excluded" would itself be an untested assertion about what this test catches.

use std::fs;
use std::path::{Path, PathBuf};

/// Ambient clock APIs this guard looks for. Matching is substring-based against masked (comment-
/// and string-stripped) source text, so `chrono::Utc::now()`, `use chrono::...`, and a bare
/// `Utc::now()` after a `use chrono::Utc` import all match via the `"chrono"` and `"Utc::now"`
/// entries respectively. `OffsetDateTime::now_utc`/`now_local` are the `time` crate's ambient
/// reads; `Instant::now` is monotonic rather than wall-clock but is included anyway since it is
/// still an ambient read this module has no legitimate reason to perform.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "SystemTime::now",
    "Instant::now",
    "chrono",
    "Utc::now",
    "Local::now",
    "OffsetDateTime::now",
];

/// Files this guard expects to find under `src/artifacts/`. Listed explicitly (rather than just
/// asserting a minimum count) so a renamed or removed file changes this guard's own diff, not
/// just a number.
const EXPECTED_FILES: &[&str] = &[
    "admin_command.rs",
    "admission_token.rs",
    "bootstrap.rs",
    "capability.rs",
    "device_cert.rs",
    "host_device_cert.rs",
    "host_op_key_cert.rs",
    "host_session_attest.rs",
    "mod.rs",
    "revocation.rs",
    "session_attest.rs",
];

#[test]
fn artifacts_never_read_an_ambient_clock() {
    let artifacts_dir = artifacts_dir();
    let files = rust_files_under(&artifacts_dir);

    assert!(
        files.len() >= EXPECTED_FILES.len(),
        "expected at least {} .rs file(s) under {}, found {} — did the artifacts directory get \
         moved, renamed, or emptied? A guard that silently scans zero files would pass for the \
         wrong reason.",
        EXPECTED_FILES.len(),
        artifacts_dir.display(),
        files.len()
    );
    for &expected in EXPECTED_FILES {
        let present = files
            .iter()
            .any(|f| f.file_name().and_then(|n| n.to_str()) == Some(expected));
        assert!(
            present,
            "expected {} to contain {expected}, but it was not found — did it get renamed?",
            artifacts_dir.display()
        );
    }

    let mut violations = Vec::new();
    for file in &files {
        let original = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", file.display()));
        assert!(
            !original.is_empty(),
            "{} was read as empty — refusing to treat an empty read as a clean scan",
            file.display()
        );
        let masked_bytes = mask_non_code(original.as_bytes());
        let masked = String::from_utf8(masked_bytes)
            .expect("masking only replaces bytes with ASCII spaces/newlines, so UTF-8 stays valid");

        for &pattern in FORBIDDEN_PATTERNS {
            let mut search_from = 0;
            while let Some(rel) = masked[search_from..].find(pattern) {
                let byte_offset = search_from + rel;
                let line_no = line_number_at(&original, byte_offset);
                let line_text = original.lines().nth(line_no - 1).unwrap_or("").trim();
                violations.push(format!(
                    "{}:{line_no}: found `{pattern}` (`{line_text}`) — A10.42 requires every \
                     artifact validity check to take a caller-supplied `now`, so that a wrong or \
                     compromised time source can only cause a refusal, never an acceptance. \
                     Reading an ambient clock here bypasses that.",
                    file.display(),
                ));
                search_from = byte_offset + pattern.len();
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n\nclock_source_guard found {} ambient clock read(s) under src/artifacts/:\n\n{}\n",
        violations.len(),
        violations.join("\n"),
    );
}

/// `crates/spindle-core/src/artifacts` sits directly under this crate's manifest directory;
/// derive it from `CARGO_MANIFEST_DIR` rather than the process's current directory, so this test
/// doesn't depend on where `cargo test` was invoked from.
fn artifacts_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest_dir.join("src").join("artifacts");
    assert!(
        dir.is_dir(),
        "expected {} to exist — did src/artifacts get moved or renamed? A guard that finds no \
         directory to scan must fail loudly, not silently pass.",
        dir.display()
    );
    dir
}

/// Collects `.rs` files directly under `dir` (non-recursive: `src/artifacts/` is a flat module,
/// not a tree), sorted for deterministic reporting.
fn rust_files_under(dir: &Path) -> Vec<PathBuf> {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("failed to read dir {}: {e}", dir.display()));
    let mut out: Vec<PathBuf> = entries
        .map(|entry| {
            entry
                .unwrap_or_else(|e| {
                    panic!("failed to read a dir entry under {}: {e}", dir.display())
                })
                .path()
        })
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    out.sort();
    out
}

/// Replaces the contents of `//` line comments, `/* */` block comments, and `"..."` string
/// literals with ASCII spaces, byte-for-byte (newlines are always preserved), so a scan of the
/// output cannot mistake comment/string text for real code — e.g. this very module's own doc
/// comments, which quote `SystemTime::now`, must not trip the guard they explain. Every byte
/// offset in the output lines up with the same offset (and line number) in the original source.
///
/// Copied from `redaction_guard.rs`'s `mask_non_code`, including its stated limits: it does not
/// special-case raw strings (`r"..."`/`r#"..."#`) or char literals/lifetimes (`'a`), because
/// neither shape appears anywhere in `src/artifacts/` today and a heuristic guard test doesn't
/// need a full Rust tokenizer.
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

/// 1-based line number containing `byte_offset` in `src`.
fn line_number_at(src: &str, byte_offset: usize) -> usize {
    src.as_bytes()[..byte_offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}
