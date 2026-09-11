//! Guards the invariant DESIGN.md §A10.42 (td-e8b79f) decided: a client may compute a clock
//! offset from a local bound check against a `HostOpKeyCert.ts` lower bound, and optionally from
//! a configured HTTPS `Date` header — but **both are diagnostic only**. Neither may be fed into
//! signing time, `exp` checks, or revocation checks, because a time source is not an
//! authenticated channel; folding one into a validity check would turn a safe refusal (wrong or
//! compromised clock) into an acceptance of an expired or revoked artifact.
//!
//! That property rests on every artifact validity check in `crates/spindle-core/src/artifacts/`
//! *plus* `src/envelope.rs`'s own clock-skew validity check taking its notion of "now" from an
//! explicit caller-supplied parameter, never from an ambient system clock read anywhere under
//! this crate's whole `src` tree, including `src/bin/`. `spindle-core` is the pure
//! artifact/envelope verification library: it takes every notion of "now" as a caller-supplied
//! parameter and has no legitimate reason to read a clock itself, so this guard scans the whole
//! `crates/spindle-core/src` tree recursively, not just `src/artifacts/` and `src/envelope.rs` by
//! name. The clock is supplied at the edge, by callers outside this crate —
//! `crates/spindle-net/src/signaling/wire.rs`'s `wire::now()` function (`wire.rs:44-49`) is
//! exactly such a legitimate caller: it reads `SystemTime::now()` and passes the result in as the
//! `now:` field to `envelope::open`. That is the intended layering, not a violation, and it is the
//! distinction this guard exists to enforce: the library stays clock-free; the edge supplies the
//! clock.
//!
//! `envelope.rs`'s own clock-skew check lives at the same layer as `src/artifacts/`'s checks: its
//! `open` function's `if skew > CLOCK_SKEW_SECS` at `envelope.rs:320` is a live clock-skew
//! validity check, exactly the shape this guard exists to hold ambient-clock-free. `spindle-core`
//! (and `packages/crypto`, its TypeScript twin) reads no ambient clock anywhere; `wire::now()`
//! (`wire.rs:44-49`) is exactly the kind of edge caller this layering expects, not a violation of
//! it. What does not exist yet is A10.42's *computed clock offset* — a configured time source
//! derived from the diagnostic bound checks described in this file's opening paragraph — and this
//! guard's job is to hold the ambient-clock-free ground in `spindle-core`'s own sources before and
//! after that diagnostic lands, not to detect a violation after the fact.
//!
//! This is a pure text scan over every `.rs` file under `crates/spindle-core/src` — it does not
//! compile or type-check anything, so it runs under a plain `cargo test -p spindle-core` with no
//! extra setup. The scan root is derived from `env!("CARGO_MANIFEST_DIR")`, not the process's
//! current directory, so this does not depend on where `cargo test` is invoked from.
//!
//! # This is a heuristic, not a proof
//!
//! It cannot see through indirection: a helper function two calls away that reads the clock and
//! hands the result down as a plain `u64`/`i64` parameter would look identical, at this module's
//! boundary, to a legitimately caller-supplied `now`. Nor can it see a clock read that happens in
//! another crate (e.g. inside a dependency) and is merely passed into `spindle-core` as data. This
//! guard only proves that the specific ambient-clock APIs it knows about — `SystemTime::now`,
//! `Instant::now`, `chrono`'s `Utc::now`/`Local::now`, and `time`/`OffsetDateTime::now_utc` —
//! are not spelled out, as real code, anywhere under `crates/spindle-core/src`. Treat a passing
//! run as "no *obvious* new ambient clock read", not as a proof that every `now` value flowing
//! through this crate traces back to a caller argument.
//!
//! A further hole, demonstrated rather than assumed: an aliased import —
//! `use std::time::SystemTime as Clock; Clock::now()` — is **not caught**, because the scan
//! matches the literal substring `SystemTime::now`, and an alias renames that text away before
//! this guard ever sees it. No such alias exists in this repo today; it is disclosed because a
//! heuristic that only lists its catches and not its misses invites more trust than it has earned.
//!
//! And another, also demonstrated: because the scan masks string literals before matching, a
//! position inside a multi-line string literal is invisible to it — a clock read planted there is
//! not caught. A `SystemTime::now()` read planted inside `artifacts/bootstrap.rs`'s multi-line
//! `#[error("bundle encodes to … dropped {} host(s) to fit")]` string passes this guard GREEN.
//! Such positions are not real code, so this is a limit on the guard's reach rather than a live
//! hole in what it protects, but it is a real limit, and the set of blind positions moves every
//! time the sources change. This file does not record a count of them: a measured figure in a
//! comment is correct only on the day it is written, and this file has already shipped one stale
//! inherited count that outlived its accuracy.
//!
//! ## Comments and string literals
//!
//! Matches inside `//` line comments, `/* */` block comments, and `"..."` string literals are
//! deliberately excluded from failing the test: a doc comment that *describes* the forbidden
//! rule (e.g. this very file's own prose, or a doc comment in `artifacts/mod.rs` explaining why
//! `SystemTime::now` must never appear) would otherwise trip the guard it is trying to justify.
//! The masking pass blanks out comment and string bytes before scanning; it lives in the shared
//! `common::mask_non_code` module, which both this guard and `redaction_guard.rs` use. Its
//! behaviour is pinned by `tests/rust_mask.rs`.
//!
//! # Neuter-verification
//!
//! Demonstrated on 2026-09-11, not assumed:
//!
//! - appending a `SystemTime::now()` read to `src/artifacts/mod.rs` turns this test RED; reverting
//!   it leaves the file byte-identical to its original (`cmp` clean, `git diff --quiet` clean).
//! - the comment- and string-masking was neutered separately: a line comment containing
//!   `SystemTime::now`, a block comment containing `Instant::now` and `chrono`, and a `&str`
//!   constant containing `Utc::now` were all appended to the same file at once, and the test
//!   stayed green. That is the evidence for the masking claim above — without it, "matches in
//!   comments and strings are excluded" would itself be an untested assertion about what this
//!   test catches.
//! - appending a `SystemTime::now()` read to `src/envelope.rs` turns this test RED. That file is
//!   scanned because it performs the envelope clock-skew validity check described above, and an
//!   earlier version of this guard did not cover it.
//! - appending a `SystemTime::now()` read to `src/bin/gen_crypto_vectors.rs` turns this test RED.
//!   That file sits in a subdirectory of `src/`, outside the old `artifacts/`-plus-`envelope.rs`
//!   scan, so reddening on it demonstrates both that the walk recurses and that it reaches files
//!   no hand-maintained list ever named.
//! - the char-literal handling in `mask_non_code` was neutered by planting probes immediately
//!   after `gen_crypto_vectors.rs`'s `out.push('"');` and again after its whole
//!   `match c { '"' => …, '\\' => …, '\n' => … }` block — both probes were reported. Before the
//!   char-literal handling existed, the first of those two passed GREEN: the closing `'"'` flipped
//!   the masker into `Str` mode over the real code that followed, hiding a real ambient-clock
//!   read.
//!
//! Every planted probe was reverted afterward, and each file was confirmed byte-identical to its
//! original (`cmp` clean, `git diff --quiet` clean).

mod common;

use common::mask_non_code;
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

/// Files that must be present among the scanned set, matched by path RELATIVE TO the scanned
/// `src` root (not by bare basename) — these four hold the A10.42 clock-skew validity checks
/// this guard exists to protect. Listed explicitly (rather than relying on the minimum count
/// alone) so a rename or removal of any one of them fails loudly by name, not just as a number
/// going down. Matching on the relative path rather than `file_name()` alone means a benign move
/// that keeps a file inside this tree (e.g. `envelope.rs` -> `envelope/mod.rs`) is reported
/// accurately as "moved to a different path" instead of being misdiagnosed as "renamed or moved
/// out of spindle-core", and a stub file that merely shares a basename somewhere else in the tree
/// can no longer satisfy this check by accident.
///
/// A10.42 also covers `exp` and revocation checks that live in `capability.rs`,
/// `host_op_key_cert.rs`, `device_cert.rs`, `host_device_cert.rs`, `admission_token.rs`, and
/// `revocation.rs` — those files are scanned because they sit under `src` like everything else,
/// but they are not name-pinned here the way the four ±120s skew-check files below are.
const MUST_BE_PRESENT: &[&str] = &[
    "artifacts/session_attest.rs",
    "artifacts/host_session_attest.rs",
    "artifacts/admin_command.rs",
    "envelope.rs",
];

/// Conservative floor on how many `.rs` files this scan should find under
/// `crates/spindle-core/src`. Derived by running
/// `find crates/spindle-core/src -name "*.rs" | wc -l` on 2026-09-11, which returned 17. Pinned at
/// that exact count (not "just under" it) because this guard's whole purpose is to catch a
/// silently-shrinking scan set — an off-by-a-few floor would let a dropped file slip through
/// unnoticed. Adding a new file under `src` raises the true count above this floor and stays
/// green; only a *drop* below 17 (a move, rename, or scan-logic regression) turns this red.
///
/// This is a floor, not a tight pin, and that is a real limitation: once the true count climbs
/// above 17 because a file was added without this constant being bumped to match, the floor stops
/// protecting against a later drop of up to that same margin — e.g. if the tree grows to 19 files
/// and this constant is left at 17, two files could later disappear and this assertion would stay
/// green. Bump this constant whenever a `.rs` file is added under `src`, rather than treating 17
/// as a permanent tripwire.
const MIN_RS_FILE_COUNT: usize = 17;

#[test]
fn artifacts_never_read_an_ambient_clock() {
    let src_dir = spindle_core_src_dir();
    let files = rust_files_under_recursive(&src_dir);

    assert!(
        files.len() >= MIN_RS_FILE_COUNT,
        "expected at least {MIN_RS_FILE_COUNT} .rs file(s) under {}, found {} — did files get \
         moved, renamed, or deleted? A guard that silently scans fewer files would pass for the \
         wrong reason.",
        src_dir.display(),
        files.len()
    );
    for &expected in MUST_BE_PRESENT {
        let present = files
            .iter()
            .any(|f| relative_path_str(&src_dir, f) == expected);
        assert!(
            present,
            "expected {expected} to be present in the scan set at that path relative to {} \
             — it is missing from the scan set at its expected path. It holds an A10.42 \
             clock-skew validity check this guard exists to protect.",
            src_dir.display()
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
        "\n\nclock_source_guard found {} ambient clock read(s) under \
         crates/spindle-core/src:\n\n{}\n",
        violations.len(),
        violations.join("\n"),
    );
}

/// `crates/spindle-core/src` sits directly under this crate's manifest directory; derive it from
/// `CARGO_MANIFEST_DIR` rather than the process's current directory, so this test doesn't depend
/// on where `cargo test` was invoked from.
fn spindle_core_src_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest_dir.join("src");
    assert!(
        dir.is_dir(),
        "expected {} to exist — did spindle-core's src directory get moved or renamed? A guard \
         that finds no directory to scan must fail loudly, not silently pass.",
        dir.display()
    );
    dir
}

/// Collects every `.rs` file under `dir`, descending into subdirectories (e.g. `src/artifacts/`,
/// `src/bin/`), sorted for deterministic reporting.
fn rust_files_under_recursive(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rust_files(dir, &mut out);
    out.sort();
    out
}

/// Recursive helper for [`rust_files_under_recursive`]: walks `dir`, pushing every `.rs` file it
/// finds into `out` and recursing into every subdirectory.
fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("failed to read dir {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|e| panic!("failed to read a dir entry under {}: {e}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// `file`'s path relative to `base`, with components joined by `/` regardless of the host OS's
/// native path separator, so a `MUST_BE_PRESENT` entry like `"artifacts/session_attest.rs"`
/// compares correctly on Windows (where `Path` would otherwise join components with `\`) as well
/// as on Unix.
fn relative_path_str(base: &Path, file: &Path) -> String {
    file.strip_prefix(base)
        .unwrap_or(file)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// 1-based line number containing `byte_offset` in `src`.
fn line_number_at(src: &str, byte_offset: usize) -> usize {
    src.as_bytes()[..byte_offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}
