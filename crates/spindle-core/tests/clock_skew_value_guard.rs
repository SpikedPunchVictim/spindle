//! Pins the *value* 120 of the four A10.42 clock-skew constants, in both Rust and TypeScript.
//! DESIGN.md's §A7 changelog for v0.9.30 states the decision this test enforces: "The ±2 min
//! window itself is deliberately left at 120s (td-e8b79f)" — later folded into A10.42's cold-clock
//! diagnostic (v0.9.32, closing td-e8b79f). That is one decision, applied to four constants across
//! two languages: [`spindle_core::envelope::CLOCK_SKEW_SECS`],
//! [`spindle_core::artifacts::ADMIN_COMMAND_CLOCK_SKEW_SECS`],
//! [`spindle_core::artifacts::SESSION_ATTESTATION_CLOCK_SKEW_SECS`], and
//! [`spindle_core::artifacts::HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS`] on the Rust side, and
//! their `packages/crypto/src/{artifacts,envelope}.ts` twins on the TypeScript side.
//!
//! What is pinned here is only the *value*. The *boundary semantics* — accept exactly at the
//! window edge, reject one second past it — are already pinned elsewhere, by this crate's existing
//! accept-at-boundary / reject-one-past-boundary tests, which exercise the symbolic constant
//! rather than restating `120` as a second literal. Neither set of tests alone is sufficient: a
//! boundary test that only ever compares against the symbolic constant cannot notice the constant
//! itself drifting, and a value pin with no boundary test cannot notice `>` becoming `>=`. This
//! file is the missing half.
//!
//! This test exists because it was demonstrated that widening
//! `SESSION_ATTESTATION_CLOCK_SKEW_SECS` from 120 to 3600 left the entire Rust workspace suite
//! and the whole crypto suite green — zero failures in either language. A device is refused when
//! its clock is off by more than this window; silently widening one language's copy of it loosens
//! a security bound in that language alone, and nothing before this test would have noticed.
//!
//! The TypeScript half of that guarantee is enforced here by `parse_bigint_const`, a plain text
//! scanner, *and* by `packages/crypto/test/clock-skew-value.test.ts`, which imports the real
//! TypeScript bindings and compares their runtime values directly. Both are needed: see
//! `parse_bigint_const`'s doc comment for a demonstrated false green this text scanner alone could
//! produce, and for why the TS-side real-import test is the actual backstop against it. Read this
//! file's cross-language coverage as a property of that pair, not of this file in isolation --
//! a Rust-only test run exercises only the text scanner half.
//!
//! # Neuter-verification
//!
//! Demonstrated on 2026-09-11, not assumed. Three perturbations, each reverted after measuring:
//!
//! - `SESSION_ATTESTATION_CLOCK_SKEW_SECS: u64 = 120` → `3600` turned this test RED naming the
//!   Rust constant. Before this guard existed, that same edit left the entire workspace green —
//!   zero failures — which is why the guard was written: the four boundary tests all use
//!   the symbolic constant, so they pin the inclusive/exclusive semantics and not the value.
//! - `HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS = 120n` → `3600n` in `artifacts.ts` turned this
//!   test RED naming the `HOST_`-prefixed twin, not the shorter `SESSION_…` name it contains as a
//!   suffix — the identifier-boundary check in `parse_bigint_const` is what makes that distinction.
//! - A second `export const CLOCK_SKEW_SECS = 120n;` appended to `envelope.ts` made this test
//!   refuse outright: "found 2 declarations … this guard refuses to guess by taking the first or
//!   last match". That refusal is deliberate. A first-match parser shipped a false green in this
//!   workspace once already (`nats_max_control_line_matches_deployed_conf`, where nats-server
//!   applies the LAST occurrence), so guessing is the one behaviour this parser must not have.

use std::fs;
use std::path::{Path, PathBuf};

/// The value DESIGN.md's §A7 changelog (v0.9.30, folded into A10.42, td-e8b79f) decided the ±2 min
/// clock-skew window stays at: 120 seconds, not widened.
const DECIDED_SKEW_SECS: u64 = 120;

/// Shared tail for every assertion failure in this file: states *why* the value matters, not just
/// that it changed.
fn why_it_matters(constant_name: &str) -> String {
    format!(
        "{constant_name} no longer equals {DECIDED_SKEW_SECS} -- the four A10.42 clock-skew \
         windows are one decision (DESIGN.md §A7 changelog v0.9.30, td-e8b79f: \"The ±2 min \
         window itself is deliberately left at 120s\") and must stay equal to each other and to \
         {DECIDED_SKEW_SECS} across both Rust and TypeScript. A device is refused when its clock \
         is off by more than this window, so a silent widening loosens a security bound -- and if \
         only one language's copy moved, it loosens that bound in one language only, splitting \
         what both sides of a CONNECT are supposed to enforce identically."
    )
}

#[test]
fn clock_skew_constants_pin_120_across_rust_and_typescript() {
    // (a) Rust: all four constants equal DECIDED_SKEW_SECS exactly.
    assert_eq!(
        spindle_core::envelope::CLOCK_SKEW_SECS,
        DECIDED_SKEW_SECS,
        "{}",
        why_it_matters("envelope::CLOCK_SKEW_SECS")
    );
    assert_eq!(
        spindle_core::artifacts::ADMIN_COMMAND_CLOCK_SKEW_SECS,
        DECIDED_SKEW_SECS,
        "{}",
        why_it_matters("artifacts::ADMIN_COMMAND_CLOCK_SKEW_SECS")
    );
    assert_eq!(
        spindle_core::artifacts::SESSION_ATTESTATION_CLOCK_SKEW_SECS,
        DECIDED_SKEW_SECS,
        "{}",
        why_it_matters("artifacts::SESSION_ATTESTATION_CLOCK_SKEW_SECS")
    );
    assert_eq!(
        spindle_core::artifacts::HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS,
        DECIDED_SKEW_SECS,
        "{}",
        why_it_matters("artifacts::HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS")
    );

    // (b) CROSS-LANGUAGE PARITY: the TypeScript twins declare the same value.
    let root = workspace_root();
    let artifacts_ts_path = root.join("packages/crypto/src/artifacts.ts");
    let envelope_ts_path = root.join("packages/crypto/src/envelope.ts");
    let artifacts_ts = read_nonempty(&artifacts_ts_path);
    let envelope_ts = read_nonempty(&envelope_ts_path);

    let ts_admin = parse_bigint_const(
        &artifacts_ts,
        &artifacts_ts_path,
        "ADMIN_COMMAND_CLOCK_SKEW_SECS",
    );
    let ts_session = parse_bigint_const(
        &artifacts_ts,
        &artifacts_ts_path,
        "SESSION_ATTESTATION_CLOCK_SKEW_SECS",
    );
    let ts_host_session = parse_bigint_const(
        &artifacts_ts,
        &artifacts_ts_path,
        "HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS",
    );
    let ts_envelope = parse_bigint_const(&envelope_ts, &envelope_ts_path, "CLOCK_SKEW_SECS");

    assert_eq!(
        ts_admin,
        DECIDED_SKEW_SECS,
        "{}",
        why_it_matters("artifacts.ts ADMIN_COMMAND_CLOCK_SKEW_SECS")
    );
    assert_eq!(
        ts_session,
        DECIDED_SKEW_SECS,
        "{}",
        why_it_matters("artifacts.ts SESSION_ATTESTATION_CLOCK_SKEW_SECS")
    );
    assert_eq!(
        ts_host_session,
        DECIDED_SKEW_SECS,
        "{}",
        why_it_matters("artifacts.ts HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS")
    );
    assert_eq!(
        ts_envelope,
        DECIDED_SKEW_SECS,
        "{}",
        why_it_matters("envelope.ts CLOCK_SKEW_SECS")
    );
}

/// `crates/spindle-core` sits two directories below the workspace root
/// (`<root>/crates/spindle-core`); derive `<root>` from `CARGO_MANIFEST_DIR` rather than the
/// process's current directory, so this test doesn't depend on where `cargo test` was invoked
/// from (mirrors `redaction_guard.rs`'s `workspace_root` and
/// `spindle-helper/src/auth_token.rs`'s twin of the same helper).
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
        "derived workspace root {} has no Cargo.toml -- CARGO_MANIFEST_DIR layout assumption is \
         wrong",
        root.display()
    );
    root
}

/// Reads `path` as UTF-8 text, refusing to treat a missing or empty file as a clean, vacuously
/// passing scan.
fn read_nonempty(path: &Path) -> String {
    assert!(
        path.is_file(),
        "expected {} to exist -- was it renamed or moved? A guard that finds nothing to read \
         must fail loudly, not silently pass.",
        path.display()
    );
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    assert!(
        !text.is_empty(),
        "{} was read as empty -- refusing to treat an empty read as a clean scan",
        path.display()
    );
    text
}

/// Scans `src` (the text of the TypeScript file at `path`) for `export const <name> = <digits>n;`
/// and returns the single declared value.
///
/// Lines whose trimmed form starts with `//` or `*` are skipped, so this cannot mistake a
/// commented-out declaration, or a doc-comment continuation line describing one, for a live
/// export. A `/* */` block comment is also tracked across lines, with a simple `in_block_comment`
/// flag toggled by `/*` and `*/`: a line that opens a block comment, lies inside one, or closes
/// one is skipped in full, at line granularity, the same way a `//`- or `*`-prefixed line is.
/// That flag closes a demonstrated false green: before it existed,
///
/// ```text
/// /**
/// export const CLOCK_SKEW_SECS = 120n;
/// */
/// export const CLOCK_SKEW_SECS =
///   3600n;
/// ```
///
/// found exactly one declaration -- the commented-out `120n` -- because nothing tracked
/// block-comment state across lines, and passed with the wrong value while the live export was
/// actually `3600n`. This scanner remains line-oriented, not a full TypeScript parser, and a
/// declaration split across lines (as `CLOCK_SKEW_SECS` is in that same example's last two lines)
/// is still not recognized: this function would find zero declarations of it, since each line is
/// matched independently. That is a documented limit, not fixed here -- closing it fully would
/// mean writing a TypeScript expression parser rather than a heuristic guard test. The actual
/// backstop for that shape is `packages/crypto/test/clock-skew-value.test.ts`, which does not
/// parse source text at all: it imports the real TypeScript binding and compares its runtime
/// value directly, so a value this scanner cannot follow is still caught there. The guarantee
/// that all four constants equal 120 in both languages is a property of *this pair of tests
/// together*, not of this file alone -- a Rust-only test run exercises only this file, and this
/// file alone would have been falsely green in the scenario demonstrated above.
///
/// This scanner also has no string- or template-literal state: it has no notion of being inside
/// a `"..."`, `'...'`, or `` `...` `` at all, so a decoy occurrence of the declaration text inside
/// a TypeScript template literal or string is read the same as a live declaration. An independent
/// review demonstrated this today with a template literal containing
/// `` `export const CLOCK_SKEW_SECS = 120n;` `` while the real binding was re-exported at
/// `3600n` elsewhere in the same file -- this Rust guard passed green. The backstop for that shape
/// is, again, `packages/crypto/test/clock-skew-value.test.ts`: it imports the real bindings rather
/// than reading source text, and it did catch that construction. This scanner and that test are a
/// pair for exactly this reason, not two copies of the same check.
///
/// Matching on `name` is exact, not substring: the character immediately before and after
/// the matched name must not be alphanumeric or an underscore, and the text immediately before the
/// match (trimmed) must end in `export const`. Both guards exist for the same reason --
/// `SESSION_ATTESTATION_CLOCK_SKEW_SECS` is a suffix of
/// `HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS`, and a plain substring search would count a
/// `HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS` declaration as a match for the shorter name too.
///
/// Panics naming `path` if zero declarations of `name` are found (renamed or moved -- a silently
/// absent constant must fail this test, never pass it vacuously), and also panics naming `path` if
/// more than one is found, listing every value seen: a duplicate declaration makes it ambiguous
/// which one the module actually exports, so this refuses to guess by taking the first (or last)
/// match. That refusal follows the precedent this guard is styled on --
/// `spindle-helper/src/auth_token.rs`'s `parse_max_control_line`, added for `nats-max-control-line`
/// (td-db47f9) after a first-match parser there shipped a false-green once already.
fn parse_bigint_const(src: &str, path: &Path, name: &str) -> u64 {
    let mut found: Vec<u64> = Vec::new();
    let mut in_block_comment = false;

    for line in src.lines() {
        let trimmed = line.trim();

        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.contains("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        let mut search_from = 0;
        while let Some(rel) = trimmed[search_from..].find(name) {
            let start = search_from + rel;
            let end = start + name.len();
            search_from = end;

            let prev_is_ident = start > 0 && is_ident_byte(trimmed.as_bytes()[start - 1]);
            let next_is_ident = trimmed
                .as_bytes()
                .get(end)
                .is_some_and(|&b| is_ident_byte(b));
            if prev_is_ident || next_is_ident {
                continue; // matched inside a longer identifier, e.g. the HOST_-prefixed twin
            }

            let before = trimmed[..start].trim_end();
            if !before.ends_with("export const") {
                continue; // same identifier text, not an `export const` declaration of it
            }

            let after = trimmed[end..].trim_start();
            let Some(after_eq) = after.strip_prefix('=') else {
                continue;
            };
            let after_eq = after_eq.trim_start();
            let Some(digits) = after_eq.strip_suffix("n;") else {
                continue;
            };
            let digits = digits.trim();
            let value: u64 = digits.parse().unwrap_or_else(|e| {
                panic!(
                    "{}: `export const {name} = {digits}n;` -- {digits:?} does not parse as a \
                     u64: {e}",
                    path.display()
                )
            });
            found.push(value);
        }
    }

    match found.len() {
        0 => panic!(
            "{}: no `export const {name} = <digits>n;` found -- was it renamed or moved? The \
             four A10.42 clock-skew windows must stay equal across Rust and TypeScript, and this \
             constant is one of the four; this guard cannot check a constant it cannot find.",
            path.display()
        ),
        1 => found[0],
        n => panic!(
            "{}: found {n} declarations of `{name}` (values: {found:?}) -- a duplicate \
             declaration makes it ambiguous which one the module actually exports, so this guard \
             refuses to guess by taking the first or last match; remove the duplicate before this \
             guard can run",
            path.display()
        ),
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
