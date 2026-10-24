//! Guards the `TransactionBehavior` split at every `Store` transaction call site (td-c7cd5a).
//!
//! Six `Store` methods must open `TransactionBehavior::Immediate` for documented
//! check-then-write race reasons — `add_share`, `add_share_exclude`, `record_upload`,
//! `remove_uploads_under`, `remove_upload_row`, and `reconcile_upload_counters` — and three must
//! open `TransactionBehavior::Deferred` because they are snapshot-consistency readers or write
//! under `Deferred`'s existing contract — `revoke_member_and_bump_epoch`,
//! `revoke_device_and_bump_epoch`, and `member_and_cap_epoch`.
//!
//! # Why a source-level guard
//!
//! Commit d40fea7 threaded the behavior through `Store::with_transaction` as an explicit
//! argument. That made the split survive, but it also reduced each decision to one enum token in
//! an argument list: a new method copied from a `Deferred` sibling silently inherits the wrong
//! isolation, and a review can miss it because the diff looks innocuous.
//!
//! The three concurrency tests that look like they pin this behaviour were measured **not** to
//! pin it. The independent review of td-c9b9bd swapped `add_share`'s `Immediate` to `Deferred`
//! and ran:
//!
//! - `concurrent_add_share_cannot_persist_overlapping_roots`
//! - `concurrent_add_share_exclude_cannot_exceed_the_cap`
//! - `member_and_cap_epoch_never_returns_a_torn_member_epoch_pair_under_a_concurrent_revoke`
//!
//! All three still passed (one run each). None of them forces the interleaving that would
//! distinguish the two behaviors:
//!
//! - the first two spawn two threads and align them on a barrier, but the barrier only aligns
//!   their *start*; the scan-then-write windows can still serialize without ever overlapping, so
//!   the `Deferred` loser is never forced to lose;
//! - the third interleaves deterministically through a rusqlite authorizer, but it accepts B's
//!   revoke failing with `SQLITE_BUSY` as a self-consistent `(Active, epoch_before)` outcome, so
//!   it passes under either behavior. It also never calls `add_share`, so the `add_share` neuter
//!   could not have affected it at all.
//!
//! Rewriting those tests to create real contention (direction 1 of td-c7cd5a) is deliberately out
//! of scope here. This guard is direction 2: total and deterministic rather than probabilistic.
//! It reads the crate's own source as text — no SQLite, threads, timing, or feature flag — and
//! fails on any swap in either direction.
//!
//! # Shape of the scan
//!
//! The scan is lexical, not a Rust parser:
//!
//! - comments are blanked (preserving newlines and byte offsets), while string literals are
//!   preserved because the context argument *is* a string;
//! - every `.with_transaction(` / `.with_mut_transaction(` occurrence is a candidate call site;
//! - the first argument's string literal is the context, and any
//!   `TransactionBehavior::Immediate` / `::Deferred` token in the argument list is the behavior;
//! - `with_mut_transaction` has no behavior argument: its one-line body hardcodes `Deferred`,
//!   and [`the_wrapper_delegations_keep_their_shape`] pins that body. Inferring `Deferred` for
//!   its callers is therefore sound;
//! - call sites whose first argument is not a string literal are the three one-line delegations
//!   (the two `*_for_test` seams and `with_mut_transaction`'s body). They are counted and shaped
//!   explicitly rather than silently ignored, so a new hidden delegation fails loudly.
//!
//! It matches this file's formatting — one-line and multi-line calls, comments between
//! arguments, parentheses/commas inside context strings — but it does not tokenise the whole
//! language. A call written as `with_transaction(concat!("a", "b"), ...)` or through an alias
//! would be classified as a delegation (no context literal) and the delegation-shape assertion
//! would fail rather than skip it. The scanned path is derived from `CARGO_MANIFEST_DIR`, not the
//! process's current directory.
//!
//! # Neuter verification
//!
//! Recorded on 2026-10-24, not assumed: swapping `add_share`'s `Immediate` to `Deferred` and
//! `member_and_cap_epoch`'s `Deferred` to `Immediate` each turned this guard red, naming the
//! method, line, and both behaviors. Restoring both left `mod.rs` byte-identical (`cmp` clean,
//! `git diff --quiet -- crates/spindle-vfs/src/store/mod.rs` clean).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// The source this guard scans, relative to the crate root, named in every failure message.
const STORE_SOURCE_REL: &str = "crates/spindle-vfs/src/store/mod.rs";

/// The six `Immediate` methods and three `Deferred` methods td-c7cd5a decided, in a stable
/// order so a failure report reads like the mapping.
const EXPECTED_MAPPING: &[(&str, Behavior)] = &[
    // Must be IMMEDIATE: each does a check (overlap scan / cap count / row read) and then a
    // write that depends on the check's result. DEFERRED would let two writers both pass the
    // check before either takes the write lock.
    ("add_share", Behavior::Immediate),
    ("add_share_exclude", Behavior::Immediate),
    ("record_upload", Behavior::Immediate),
    ("remove_uploads_under", Behavior::Immediate),
    ("remove_upload_row", Behavior::Immediate),
    ("reconcile_upload_counters", Behavior::Immediate),
    // Must stay DEFERRED: these rely on the snapshot a DEFERRED transaction holds across their
    // reads (or, for the revokes, on DEFERRED's existing write contract); IMMEDIATE would take a
    // RESERVED lock up front and needlessly serialize them against every writer.
    ("revoke_member_and_bump_epoch", Behavior::Deferred),
    ("revoke_device_and_bump_epoch", Behavior::Deferred),
    ("member_and_cap_epoch", Behavior::Deferred),
];

/// Other literal-context transaction call sites in the same file. They are not part of
/// td-c7cd5a's six/three split, but the guard accounts for every literal call site so a new one
/// cannot appear unregistered. `set_member_status` mirrors the revoke path's `Deferred` choice;
/// `burn_invite_nonce` goes through `with_mut_transaction`, whose body hardcodes `Deferred`.
const OTHER_LITERAL_SITES: &[(&str, Behavior)] = &[
    ("set_member_status", Behavior::Deferred),
    ("burn_invite_nonce", Behavior::Deferred),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behavior {
    Immediate,
    Deferred,
}

impl Behavior {
    fn as_str(self) -> &'static str {
        match self {
            Behavior::Immediate => "TransactionBehavior::Immediate",
            Behavior::Deferred => "TransactionBehavior::Deferred",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wrapper {
    WithTransaction,
    WithMutTransaction,
}

impl Wrapper {
    fn as_str(self) -> &'static str {
        match self {
            Wrapper::WithTransaction => "with_transaction",
            Wrapper::WithMutTransaction => "with_mut_transaction",
        }
    }
}

/// One scanned call site.
#[derive(Debug)]
struct Site {
    wrapper: Wrapper,
    /// `Some` when the first argument is a string literal; `None` for a one-line delegation.
    context: Option<String>,
    /// The explicit `TransactionBehavior::...` token in the argument list, if the call has one.
    behavior: Option<Behavior>,
    /// 1-based source line, for diagnostics only. Never matched on.
    line: usize,
}

impl Site {
    /// The behavior the call site actually opens. `with_mut_transaction` takes no behavior
    /// argument; its body hardcodes `Deferred`, and that body is pinned separately.
    fn effective_behavior(&self) -> Option<Behavior> {
        match self.wrapper {
            Wrapper::WithTransaction => self.behavior,
            Wrapper::WithMutTransaction => Some(Behavior::Deferred),
        }
    }
}

/// `<crate>/src/store/mod.rs`, derived from `CARGO_MANIFEST_DIR` so this test does not depend on
/// where `cargo test` was invoked from.
fn store_source_path() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("store")
        .join("mod.rs");
    assert!(
        path.is_file(),
        "expected {} to exist — a guard that finds no source to scan must fail loudly, not \
         silently pass",
        path.display()
    );
    path
}

fn scan_store_source() -> Vec<Site> {
    let source = fs::read_to_string(store_source_path())
        .unwrap_or_else(|e| panic!("failed to read {STORE_SOURCE_REL}: {e}"));
    scan_call_sites(&mask_comments(&source))
}

/// 1-based line number containing byte `offset` in `src`.
fn line_number_at(src: &str, offset: usize) -> usize {
    src.as_bytes()[..offset]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Blanks `//` line comments and nested `/* */` block comments, preserving every byte offset and
/// every newline. String and char literals are copied verbatim, so their contents — including
/// the context arguments this guard reads and any `//` or `)` inside them — reach the caller
/// unchanged.
fn mask_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let mut depth = 1usize;
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else {
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
            }
        } else if let Some(len) = literal_len(bytes, i) {
            out.extend_from_slice(&bytes[i..i + len]);
            i += len;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).expect("masking only replaces bytes with ASCII spaces or newlines")
}

/// Length of a string or char literal starting at `i`, if one starts there. Raw strings and
/// escaped characters are handled; a lifetime (`'a`) is not a char literal and returns `None`.
fn literal_len(bytes: &[u8], i: usize) -> Option<usize> {
    match bytes[i] {
        b'"' => quoted_len(bytes, i),
        b'\'' => char_literal_len(bytes, i),
        b'r' => raw_string_len(bytes, i),
        _ => None,
    }
}

fn quoted_len(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2,
            b'"' => return Some(j + 1 - i),
            _ => j += 1,
        }
    }
    None
}

fn raw_string_len(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'r') {
        return None;
    }
    let mut j = i + 1;
    let mut hashes = 0usize;
    while bytes.get(j) == Some(&b'#') {
        hashes += 1;
        j += 1;
    }
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < bytes.len() {
        if bytes[j] == b'"' {
            let closed = (0..hashes).all(|n| bytes.get(j + 1 + n) == Some(&b'#'));
            if closed {
                return Some(j + 1 + hashes - i);
            }
        }
        j += 1;
    }
    None
}

fn char_literal_len(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'\'') {
        return None;
    }
    if bytes.get(i + 1) == Some(&b'\\') {
        // Escaped char: `'\n'`, `'\''`, `'\u{1F600}'`, ...
        let mut j = i + 2;
        while j < bytes.len() {
            if bytes[j] == b'\'' {
                return Some(j + 1 - i);
            }
            j += 1;
        }
        return None;
    }
    if bytes.get(i + 2) == Some(&b'\'') {
        return Some(3);
    }
    // A lifetime or label (`'static`, `'a:`), not a char literal.
    None
}

/// Index of the `)` matching the `(` at `open`, using the same literal-skipping rules as
/// [`mask_comments`]. Comments are already blanked by the caller.
fn matching_close_paren(src: &str, open: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            _ => match literal_len(bytes, i) {
                Some(len) => i += len,
                None => i += 1,
            },
        }
    }
    None
}

/// If `text`'s first non-whitespace token is a plain string literal, returns its contents.
fn leading_string_literal(text: &str) -> Option<String> {
    let start = text.len() - text.trim_start().len();
    let tail = &text[start..];
    let bytes = tail.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let len = quoted_len(bytes, 0)
        .unwrap_or_else(|| panic!("{STORE_SOURCE_REL}: unterminated string literal in call args"));
    Some(tail[1..len - 1].to_string())
}

/// The explicit `TransactionBehavior` token in a call's argument list. `None` means the call
/// passes a variable (a delegation), not a decision; multiple tokens are a scan error, not a
/// guess.
fn explicit_behavior(args: &str) -> Option<Behavior> {
    let immediate = args.matches("TransactionBehavior::Immediate").count();
    let deferred = args.matches("TransactionBehavior::Deferred").count();
    match (immediate, deferred) {
        (0, 0) => None,
        (1, 0) => Some(Behavior::Immediate),
        (0, 1) => Some(Behavior::Deferred),
        _ => panic!(
            "{STORE_SOURCE_REL}: a single call's argument list names TransactionBehavior more \
             than once: {args}"
        ),
    }
}

const CALL_NEEDLES: &[(&str, Wrapper)] = &[
    (".with_transaction(", Wrapper::WithTransaction),
    (".with_mut_transaction(", Wrapper::WithMutTransaction),
];

fn scan_call_sites(masked: &str) -> Vec<Site> {
    let mut sites = Vec::new();
    for &(needle, wrapper) in CALL_NEEDLES {
        let mut search_from = 0;
        while let Some(relative) = masked[search_from..].find(needle) {
            let open = search_from + relative + needle.len() - 1;
            let close = matching_close_paren(masked, open).unwrap_or_else(|| {
                panic!(
                    "{STORE_SOURCE_REL}: could not find the closing `)` for the call site at \
                     line {}",
                    line_number_at(masked, open)
                )
            });
            let args = &masked[open + 1..close];
            sites.push(Site {
                wrapper,
                context: leading_string_literal(args),
                behavior: explicit_behavior(args),
                line: line_number_at(masked, open),
            });
            search_from = close + 1;
        }
    }
    sites
}

#[test]
fn the_decided_transaction_behavior_is_pinned_for_every_expected_method() {
    let sites = scan_store_source();
    let mut failures = Vec::new();

    for &(context, expected) in EXPECTED_MAPPING {
        let found: Vec<&Site> = sites
            .iter()
            .filter(|site| site.context.as_deref() == Some(context))
            .collect();
        match found.as_slice() {
            [] => failures.push(format!(
                "{STORE_SOURCE_REL}: no transaction call site with context `{context}` was \
                 found. Was the method renamed or removed, or did it stop using \
                 `with_transaction`? Expected {}.",
                expected.as_str()
            )),
            [site] => match site.effective_behavior() {
                Some(actual) if actual == expected => {}
                Some(actual) => failures.push(format!(
                    "{STORE_SOURCE_REL}:{}: `{context}` opens {} but must open {}",
                    site.line,
                    actual.as_str(),
                    expected.as_str()
                )),
                None => failures.push(format!(
                    "{STORE_SOURCE_REL}:{}: `{context}` has no TransactionBehavior argument",
                    site.line
                )),
            },
            many => failures.push(format!(
                "{STORE_SOURCE_REL}: context `{context}` appears at {} call sites (lines {:?}); \
                 expected exactly one",
                many.len(),
                many.iter().map(|site| site.line).collect::<Vec<_>>()
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "\n\ntransaction_behavior_guard found {} problem(s):\n\n{}\n",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_literal_context_call_site_is_registered_with_its_expected_behavior() {
    let sites = scan_store_source();
    let mut registered: BTreeMap<&str, Behavior> = BTreeMap::new();
    for &(context, behavior) in EXPECTED_MAPPING.iter().chain(OTHER_LITERAL_SITES) {
        assert!(
            registered.insert(context, behavior).is_none(),
            "transaction_behavior_guard's own registry lists `{context}` twice"
        );
    }

    let mut failures = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for site in &sites {
        let Some(context) = site.context.as_deref() else {
            continue;
        };
        if let Some(previous_line) = seen.insert(context, site.line) {
            failures.push(format!(
                "{STORE_SOURCE_REL}: context `{context}` appears twice (lines {previous_line} \
                 and {})",
                site.line
            ));
            continue;
        }
        let Some(&expected) = registered.get(context) else {
            failures.push(format!(
                "{STORE_SOURCE_REL}:{}: unregistered transaction call site `{context}` — add it \
                 and its decided behavior to EXPECTED_MAPPING (if it is part of the split) or \
                 OTHER_LITERAL_SITES, with a comment saying why",
                site.line
            ));
            continue;
        };
        match site.effective_behavior() {
            Some(actual) if actual == expected => {}
            Some(actual) => failures.push(format!(
                "{STORE_SOURCE_REL}:{}: `{context}` opens {} but the registry says {}",
                site.line,
                actual.as_str(),
                expected.as_str()
            )),
            None => failures.push(format!(
                "{STORE_SOURCE_REL}:{}: `{context}` has no TransactionBehavior argument",
                site.line
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "\n\ntransaction_behavior_guard found {} problem(s):\n\n{}\n",
        failures.len(),
        failures.join("\n")
    );
}

/// `with_mut_transaction` takes no behavior: it forwards to `with_transaction` with `Deferred`.
/// This pins that forwarding, which is what makes [`Site::effective_behavior`]'s inference for
/// `with_mut_transaction` callers sound. It also pins the shape of both test seams, so an extra
/// non-literal call site cannot hide from the mapping assertions above.
#[test]
fn the_wrapper_delegations_keep_their_shape() {
    let sites = scan_store_source();
    let mut wrapper_body = 0usize;
    let mut transaction_test_seam = 0usize;
    let mut mut_test_seam = 0usize;
    let mut failures = Vec::new();

    for site in &sites {
        if site.context.is_some() {
            continue;
        }
        match (site.wrapper, site.behavior) {
            (Wrapper::WithTransaction, Some(Behavior::Deferred)) => wrapper_body += 1,
            (Wrapper::WithTransaction, None) => transaction_test_seam += 1,
            (Wrapper::WithMutTransaction, None) => mut_test_seam += 1,
            (Wrapper::WithTransaction, Some(Behavior::Immediate)) => failures.push(format!(
                "{STORE_SOURCE_REL}:{}: `{}` delegates to `with_transaction` with {}, but every \
                 `with_mut_transaction` caller is guarded as Deferred — the forwarding must be \
                 Deferred",
                site.line,
                site.wrapper.as_str(),
                Behavior::Immediate.as_str()
            )),
            (Wrapper::WithMutTransaction, Some(behavior)) => failures.push(format!(
                "{STORE_SOURCE_REL}:{}: unexpected explicit {} on a `with_mut_transaction` call",
                site.line,
                behavior.as_str()
            )),
        }
    }

    if wrapper_body != 1 {
        failures.push(format!(
            "{STORE_SOURCE_REL}: expected exactly one non-literal `with_transaction` delegation \
             forwarded as Deferred (the body of `with_mut_transaction`), found {wrapper_body}"
        ));
    }
    if transaction_test_seam != 1 {
        failures.push(format!(
            "{STORE_SOURCE_REL}: expected exactly one non-literal `with_transaction` delegation \
             with a variable behavior (the `with_transaction_for_test` seam), found \
             {transaction_test_seam}"
        ));
    }
    if mut_test_seam != 1 {
        failures.push(format!(
            "{STORE_SOURCE_REL}: expected exactly one non-literal `with_mut_transaction` \
             delegation (the `with_mut_transaction_for_test` seam), found {mut_test_seam}"
        ));
    }

    assert!(
        failures.is_empty(),
        "\n\ntransaction_behavior_guard found {} problem(s):\n\n{}\n",
        failures.len(),
        failures.join("\n")
    );
}

/// The scan must survive the formatting this file actually uses: one-line calls, multi-line
/// argument lists, comments between arguments, comment-only mentions that are not call sites,
/// and context strings containing commas or parentheses.
#[test]
fn the_scan_reads_this_files_real_formatting() {
    let source = r#"
        // `self.with_transaction("ghost_in_a_line_comment", TransactionBehavior::Immediate, ...)`
        /* `self.with_mut_transaction("ghost_in_a_block_comment", ...)` */
        fn probe(&self) {
            self.with_transaction("one_line", TransactionBehavior::Immediate, |_tx| {});
            self.with_transaction(
                "multi_line", // a comment between arguments
                TransactionBehavior::Deferred,
                |_tx| { /* a block comment in the closure */ },
            );
            self.with_transaction(
                "weird // not a comment, with a ) paren",
                TransactionBehavior::Deferred,
                |_tx| {},
            );
            self.with_mut_transaction("mut_site", |_tx| {});
            self.with_transaction(context, behavior, f);
        }
    "#;

    let sites = scan_call_sites(&mask_comments(source));
    let summary: Vec<(Option<&str>, Wrapper, Option<Behavior>)> = sites
        .iter()
        .map(|site| (site.context.as_deref(), site.wrapper, site.behavior))
        .collect();

    assert_eq!(
        summary,
        vec![
            (
                Some("one_line"),
                Wrapper::WithTransaction,
                Some(Behavior::Immediate)
            ),
            (
                Some("multi_line"),
                Wrapper::WithTransaction,
                Some(Behavior::Deferred)
            ),
            (
                Some("weird // not a comment, with a ) paren"),
                Wrapper::WithTransaction,
                Some(Behavior::Deferred)
            ),
            (None, Wrapper::WithTransaction, None),
            (Some("mut_site"), Wrapper::WithMutTransaction, None),
        ],
        "comment-only mentions must not be scanned as call sites, and literals must not confuse \
         the argument scan: {sites:?}"
    );
}
