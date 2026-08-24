//! Minimal precompiled glob matcher for share exclusions (DESIGN.md §A4b: `excludes: [glob…]`).
//!
//! **Why hand-rolled**: `Cargo.lock` has a `glob` crate entry, but it is pulled in only
//! transitively (as a build-dependency of `clang-sys`, itself several hops behind some other
//! workspace dependency's `bindgen` usage) — it is not a workspace dependency any crate here can
//! `use`, and adding it as a direct `spindle-vfs` dependency was out of this slice's stated
//! budget ("pick a glob crate ONLY if one is already in the workspace tree"). §A4b does not
//! specify a glob dialect beyond the single example "Photos except Photos/Private", so this
//! implements the minimum needed to express that: `*` and `?` wildcards within one path segment,
//! and `**` matching zero or more whole segments — no character classes (`[abc]`), brace
//! expansion, or extended globbing.
//!
//! **Ancestor-cascading exclusion (an assumption, not a §A4b-mandated resolution)**: §A4b's only
//! example, "Photos except Photos/Private", implies that excluding a directory hides everything
//! under it, not just a dirent literally named `Photos/Private`. Since §A4b does not otherwise
//! specify whether excludes cascade to descendants, [`CompiledGlob::matches_path_or_ancestor`]
//! treats a glob as matching path `P` if it matches `P` **or any ancestor of `P`** — the only
//! interpretation consistent with the stated example without inventing directory-vs-file
//! distinctions §A4b never mentions.
//!
//! **Fold-key matching**: every path component is compared via `crate::confine::fold_key`
//! (DESIGN.md §A4b case/Unicode folding), so an exclude glob written as `Private` also excludes
//! `PRIVATE` or a Unicode-normalization variant of the same name — consistent with the
//! collision-is-overwrite rule applied elsewhere in §A4b.

use crate::confine::fold_key;

/// A single path segment's compiled pattern: `**` (matches zero or more whole segments) or a
/// literal-with-wildcards segment (already fold-keyed at compile time).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    DoubleStar,
    Single(String),
}

/// A precompiled exclude glob. Compilation never fails — any string is a valid pattern (a
/// pattern with no `*`/`?`/`**` is just a fold-keyed literal path).
#[derive(Clone, Debug)]
pub struct CompiledGlob {
    original: String,
    segments: Vec<Segment>,
}

impl CompiledGlob {
    /// Compiles `pattern` (a `/`-separated glob) once, so repeated matching against many
    /// listing entries never re-parses the string.
    pub fn compile(pattern: &str) -> Self {
        let segments = pattern
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|segment| {
                if segment == "**" {
                    Segment::DoubleStar
                } else {
                    Segment::Single(fold_key(segment))
                }
            })
            .collect();
        CompiledGlob {
            original: pattern.to_string(),
            segments,
        }
    }

    pub fn pattern(&self) -> &str {
        &self.original
    }

    /// `true` if this glob matches `components` exactly (component-for-component; `**` may
    /// consume zero or more).
    pub fn matches(&self, components: &[String]) -> bool {
        matches_components(&self.segments, components)
    }

    /// `true` if this glob matches `components`, **or any ancestor (proper prefix) of
    /// `components`** — see the module doc comment for why exclusion cascades to descendants.
    pub fn matches_path_or_ancestor(&self, components: &[String]) -> bool {
        (0..=components.len()).any(|len| matches_components(&self.segments, &components[..len]))
    }
}

/// Classic `*`/`?` single-segment wildcard match, iterative two-pointer with backtracking on the
/// last-seen `*`. Both `pattern` and `text` are expected to already be fold-keyed (matching is
/// then a plain char-for-char comparison plus wildcard handling).
fn segment_matches(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_idx: Option<usize> = None;
    let mut star_match = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_idx = Some(pi);
            star_match = ti;
            pi += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            star_match += 1;
            ti = star_match;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Recursively matches compiled `segments` against fold-keyed path `components`.
/// `**` backtracks over every possible number of components it could consume (0..=remaining).
fn matches_components(segments: &[Segment], components: &[String]) -> bool {
    match segments.split_first() {
        None => components.is_empty(),
        Some((Segment::Single(pattern), rest_segments)) => match components.split_first() {
            Some((first, rest_components)) => {
                segment_matches(pattern, &fold_key(first))
                    && matches_components(rest_segments, rest_components)
            }
            None => false,
        },
        Some((Segment::DoubleStar, rest_segments)) => (0..=components.len())
            .any(|consumed| matches_components(rest_segments, &components[consumed..])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comps(s: &str) -> Vec<String> {
        s.split('/').map(str::to_string).collect()
    }

    #[test]
    fn literal_segment_matches_exactly() {
        let g = CompiledGlob::compile("Photos/Private");
        assert!(g.matches(&comps("Photos/Private")));
        assert!(!g.matches(&comps("Photos/Private/secret.txt")));
        assert!(!g.matches(&comps("Photos")));
        assert!(!g.matches(&comps("Other/Private")));
    }

    #[test]
    fn literal_segment_is_case_insensitive() {
        let g = CompiledGlob::compile("Photos/Private");
        assert!(g.matches(&comps("photos/PRIVATE")));
    }

    #[test]
    fn literal_segment_is_unicode_fold_insensitive() {
        // "café" glob (NFC é) must match an NFD-spelled ("e" + combining acute) component.
        let g = CompiledGlob::compile("Photos/caf\u{00E9}");
        assert!(g.matches(&["Photos".into(), "cafe\u{0301}".into()]));
    }

    #[test]
    fn star_wildcard_matches_within_one_segment() {
        let g = CompiledGlob::compile("*.tmp");
        assert!(g.matches(&comps("build.tmp")));
        assert!(g.matches(&comps(".tmp")));
        assert!(!g.matches(&comps("build.tmp/nested")));
    }

    #[test]
    fn question_wildcard_matches_exactly_one_char() {
        let g = CompiledGlob::compile("photo?.jpg");
        assert!(g.matches(&comps("photo1.jpg")));
        assert!(!g.matches(&comps("photo12.jpg")));
        assert!(!g.matches(&comps("photo.jpg")));
    }

    #[test]
    fn doublestar_matches_zero_or_more_segments() {
        let g = CompiledGlob::compile("Photos/**/secret.txt");
        assert!(g.matches(&comps("Photos/secret.txt")));
        assert!(g.matches(&comps("Photos/2024/secret.txt")));
        assert!(g.matches(&comps("Photos/2024/summer/secret.txt")));
        assert!(!g.matches(&comps("Other/secret.txt")));
    }

    #[test]
    fn matches_path_or_ancestor_cascades_to_descendants() {
        let g = CompiledGlob::compile("Photos/Private");
        assert!(g.matches_path_or_ancestor(&comps("Photos/Private")));
        assert!(g.matches_path_or_ancestor(&comps("Photos/Private/secret.txt")));
        assert!(g.matches_path_or_ancestor(&comps("Photos/Private/nested/deep.txt")));
        assert!(!g.matches_path_or_ancestor(&comps("Photos/Public")));
        assert!(!g.matches_path_or_ancestor(&comps("Photos")));
    }
}
