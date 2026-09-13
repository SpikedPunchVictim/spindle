//! Guards `docs/DESIGN.md`'s citations into the codebase.
//!
//! The review corpus has recorded the same defect nine times under the class `stale-line-citation`:
//! prose cites `some/file.rs:412`, the file is edited, and the offset silently comes to mean
//! something else. A line number in prose is a claim that no tool checks, so it rots in place —
//! and the near-miss case is the worst one, because a drifted offset usually still lands on real
//! code in the right file and reads as verified.
//!
//! v0.9.42 began replacing those offsets with **symbol anchors**: a cited file plus a literal
//! string that must appear in it, e.g. ``(`spindle-proto/src/artifacts.rs`, `HostOpKeyCert::ts`)``.
//! Unlike a line number, that form is mechanically checkable, and this guard checks it. What it
//! cannot check is whether the anchor supports the sentence around it; a human still owns that.
//!
//! Two scans run here:
//! 1. every symbol anchor resolves — the file exists and literally contains the anchor text;
//! 2. every surviving `path:line` citation is at least in range — the file exists and the line
//!    number is not past its end. This is deliberately weak (it cannot see a two-line drift), and
//!    it exists to stop the *silent* half: a citation into a file that was deleted or truncated.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/spindle-core is two levels below the repo root")
        .to_path_buf();
    assert!(
        root.join("docs/DESIGN.md").is_file(),
        "expected {} to exist — a guard that finds no document to scan must fail loudly, not \
         silently pass.",
        root.join("docs/DESIGN.md").display()
    );
    root
}

fn design_text() -> String {
    std::fs::read_to_string(repo_root().join("docs/DESIGN.md"))
        .expect("docs/DESIGN.md is readable; repo_root() already asserted it exists")
}

/// Resolves a cited path, which DESIGN.md writes either workspace-relative
/// (`crates/spindle-core/src/identity.rs`) or shortened (`spindle-proto/src/artifacts.rs`,
/// `helper.rs`). Returns `None` when no single tracked file matches, which the callers report as
/// a failure rather than skipping.
fn resolve_cited_path(root: &Path, cited: &str) -> Option<PathBuf> {
    let direct = root.join(cited);
    if direct.is_file() {
        return Some(direct);
    }
    let mut matches: Vec<PathBuf> = Vec::new();
    let suffix = format!("/{cited}");
    for entry in walk_files(root) {
        let rel = entry.strip_prefix(root).unwrap_or(&entry);
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if rel_str.ends_with(&suffix) {
            matches.push(entry.clone());
        }
    }
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

/// Every file under `crates/`, `packages/`, `apps/` and `spikes/`, skipping build output and
/// dependency directories so the walk stays fast and deterministic.
fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for top in ["crates", "packages", "apps", "spikes"] {
        collect(&root.join(top), &mut out);
    }
    out.sort();
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == "node_modules" || name == "dist" || name == ".git" {
                continue;
            }
            collect(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Pulls every ``(`path`, `anchor`)`` pair out of the document. The shape is deliberately narrow:
/// two adjacent backtick spans separated by `, `, where the first ends in a source extension.
fn symbol_anchors(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes: Vec<char> = text.chars().collect();
    let spans = backtick_spans(&bytes);
    for pair in spans.windows(2) {
        let (first, second) = (&pair[0], &pair[1]);
        if !(first.2.ends_with(".rs") || first.2.ends_with(".ts")) {
            continue;
        }
        // The two spans must be adjacent, separated by exactly `, ` — allowing a line break and
        // indentation, since DESIGN.md wraps at ~110 columns. `second.0` is the first character
        // INSIDE the second span, so the separator ends one before it, at its opening backtick.
        let between: String = bytes[first.1..second.0 - 1].iter().collect();
        if between.split_whitespace().collect::<Vec<_>>().join(" ") == "," {
            out.push((first.2.clone(), second.2.clone()));
        }
    }
    out
}

/// `(start_index_of_content, end_index_after_closing_backtick, content)` for each backtick span,
/// paired left to right across the whole document.
///
/// An earlier version special-cased ``...`` spans by skipping them wholesale. That desynchronised
/// the scan — DESIGN.md's ten `` occurrences are not all balanced pairs — and the extractor
/// silently returned zero anchors. It was caught by this guard's own floor assertion, which is the
/// argument for having one: a scanner that finds nothing must fail, because "nothing to check" and
/// "the scanner is broken" look identical from the outside.
fn backtick_spans(chars: &[char]) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '`' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < chars.len() && chars[j] != '`' {
            j += 1;
        }
        if j >= chars.len() {
            break;
        }
        out.push((start, j + 1, chars[start..j].iter().collect()));
        i = j + 1;
    }
    out
}

#[test]
fn every_design_symbol_anchor_resolves_in_the_file_it_names() {
    let root = repo_root();
    let text = design_text();
    let anchors = symbol_anchors(&text);

    assert!(
        anchors.len() >= 8,
        "expected DESIGN.md to carry at least the 8 symbol anchors v0.9.42 introduced, found {} — \
         a guard that finds nothing to check must fail loudly, not silently pass. Anchors: {anchors:?}",
        anchors.len()
    );

    let mut failures = Vec::new();
    for (cited, anchor) in &anchors {
        let Some(path) = resolve_cited_path(&root, cited) else {
            failures.push(format!(
                "{cited}: no single tracked file matches this path (anchor `{anchor}`)"
            ));
            continue;
        };
        let Ok(body) = std::fs::read_to_string(&path) else {
            failures.push(format!(
                "{cited}: not readable as UTF-8 (anchor `{anchor}`)"
            ));
            continue;
        };
        // Anchors are written the way a reader would search: `Type::member`. Rust declares those
        // apart (`pub struct Type {` ... `pub member:`), so accept either the joined spelling or
        // both halves appearing in the file.
        let found = body.contains(anchor.as_str())
            || match anchor.split_once("::") {
                Some((ty, member)) => body.contains(ty) && body.contains(member),
                None => false,
            };
        if !found {
            failures.push(format!(
                "{cited}: does not contain the cited anchor `{anchor}` — the citation has rotted, \
                 or the anchor was never in this file"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "design_citation_guard found {} unresolvable symbol anchor(s) in docs/DESIGN.md:\n{}\n\n\
         A symbol anchor is the checkable replacement for a line offset (v0.9.42). If a symbol was \
         renamed, update DESIGN.md in the same commit — that is the whole point of the form.",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn every_surviving_line_citation_is_in_range() {
    let root = repo_root();
    let text = design_text();

    let mut failures = Vec::new();
    let mut checked = 0usize;
    for raw in text.split('`') {
        let Some((path_part, line_part)) = raw.rsplit_once(':') else {
            continue;
        };
        if !(path_part.ends_with(".rs") || path_part.ends_with(".ts")) {
            continue;
        }
        let first_number = line_part.split('-').next().unwrap_or("");
        let Ok(line_no) = first_number.parse::<usize>() else {
            continue;
        };
        checked += 1;
        let Some(path) = resolve_cited_path(&root, path_part) else {
            failures.push(format!(
                "{path_part}:{line_part}: no single tracked file matches"
            ));
            continue;
        };
        let Ok(body) = std::fs::read_to_string(&path) else {
            failures.push(format!("{path_part}:{line_part}: not readable as UTF-8"));
            continue;
        };
        let total = body.lines().count();
        if line_no == 0 || line_no > total {
            failures.push(format!(
                "{path_part}:{line_part}: line {line_no} is past the end of the file ({total} lines)"
            ));
        }
    }

    assert!(
        checked >= 8,
        "expected to find the surviving `path:line` citations in DESIGN.md, found {checked} — a \
         guard that finds nothing to check must fail loudly, not silently pass."
    );
    assert!(
        failures.is_empty(),
        "design_citation_guard found {} out-of-range line citation(s) in docs/DESIGN.md:\n{}\n\n\
         This check is deliberately weak — it cannot see a citation that drifted onto the wrong \
         line, only one that points past the end of its file. Prefer a symbol anchor.",
        failures.len(),
        failures.join("\n")
    );
}
