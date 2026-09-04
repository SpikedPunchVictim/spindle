//! Case/Unicode fold-key comparison and collision detection against existing dirents (DESIGN.md
//! §A4b: "cap-std does not canonicalize, case-fold, or normalize — Spindle does"). Closes A12
//! #20 (exclusion/permission bypass via case or Unicode variants) and, combined with
//! `crate::confine::upload`, A12 #31 (case/NFD upload collision overwrites without `delete`).
//!
//! The fold is real Unicode canonical decomposition (NFD) plus simple lowercasing, via the
//! `unicode-normalization` crate — not the hand-rolled 27-entry Latin-1 table this module used
//! to carry (td-47d24d, USER DECISION 2026-09-04). See [`fold_key`]'s doc comment for exactly
//! what does and does not fold together under the current rule.

use super::ConfineError;
use cap_std::fs::Dir;
use unicode_normalization::UnicodeNormalization;

/// Folds `name` to a comparison key stable across case variance and NFC/NFD spelling variance —
/// i.e. two spellings of the *same* sequence of base characters plus combining marks, however
/// those marks are composed. The fold is canonical decomposition (Unicode NFD) followed by
/// simple lowercasing: `"café"` (NFC, precomposed `é` = U+00E9) and `"cafe\u{0301}"` (NFD, `e` +
/// combining acute accent U+0301) fold to the same key and are therefore the same dirent
/// (DESIGN.md §A4b: a case-insensitive or Unicode-normalization collision with an existing
/// dirent **is** an overwrite, not a new entry).
///
/// Diacritics themselves are **preserved**, deliberately: `"café"` and `"cafe"` fold to
/// *different* keys and are different names. td-47d24d's predecessor implementation got this
/// backwards — its hand-rolled table didn't normalize, it *stripped* combining marks outright,
/// so `"café"`, `"cafe\u{0301}"`, and plain `"cafe"` all collided. That is broader than
/// DESIGN.md:370-371's "collides under Unicode normalization" rule actually promises (which is
/// about one name's NFC/NFD spellings, not about treating `é` and `e` as the same letter), and
/// it was a real hazard: an upload literally named `resume.pdf` could silently overwrite an
/// owner's `résumé.pdf`. The fix closes both directions at once — folding now covers every
/// Unicode block NFD does (Latin Extended, Greek, Cyrillic, Vietnamese, ...), not just 27
/// precomposed Latin-1 letters, while no longer erasing marks that make two names different.
///
/// This key is inherited by `crate::model::VirtualPath::descends_from_or_eq` and `crate::glob`
/// in addition to the collision scan below, so confinement, the entitlement algebra, and
/// exclusion matching all move together under any change to this function.
pub fn fold_key(name: &str) -> String {
    // Lowercase, then NFD. NFD runs last deliberately, so the output is canonically decomposed
    // by construction, not by a property of today's Unicode tables. No pre-normalization pass is
    // needed: lowercasing a single scalar value was verified to commute with decomposing it,
    // across all 1,114,112 scalar values, against `unicode-normalization` 0.1.25.
    name.to_lowercase().nfd().collect()
}

/// `true` when `a` and `b` fold to the same key and must therefore be treated as the same dirent.
pub fn names_collide(a: &str, b: &str) -> bool {
    fold_key(a) == fold_key(b)
}

/// A fold-colliding entry found by [`existing_entry_colliding_typed`]: its actual on-disk name,
/// plus whether it is a directory. The upload/mkdir overwrite gate
/// ([`super::upload::write_is_authorized`]) needs the kind to tell a same-type collision (an
/// overwrite) apart from a type mismatch (always refused, per DESIGN.md :370-371's collision rule
/// as narrowed by the user's 2026-09-04 decision on td-d5b098/td-789f11); plain name-only lookups
/// ([`resolve_folded_path`](super::resolve::resolve_folded_path), via
/// [`existing_entry_colliding`]) don't care about kind at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollidingEntry {
    pub name: std::ffi::OsString,
    pub is_dir: bool,
}

/// Scans `dir`'s top-level entries for one whose name fold-collides with `candidate_name`,
/// returning its on-disk name and whether it is a directory. This is the one fold-comparison scan
/// in this crate — [`existing_entry_colliding`] (name only) and [`existing_entry_colliding_typed`]
/// (name + kind) both call it rather than re-implementing the comparison, so there is no risk of
/// the two ever disagreeing on what counts as a collision. Works even on filesystems (e.g. Linux)
/// that keep case/Unicode variants as distinct, non-colliding dirents at the OS level, which is
/// exactly why Spindle must do this check itself rather than relying on the filesystem.
///
/// If the colliding entry's type cannot be determined (e.g. a race where it vanished between the
/// readdir syscall and this follow-up `file_type()` call), it is reported as *not* a directory —
/// matching this function's pre-existing behavior when kind wasn't tracked at all, and erring
/// toward the file/overwrite path rather than silently authorizing a directory no-op or refusing a
/// write that would otherwise have succeeded.
fn scan_for_collision(
    dir: &Dir,
    candidate_name: &str,
) -> Result<Option<CollidingEntry>, ConfineError> {
    let target_key = fold_key(candidate_name);
    for entry in dir.entries().map_err(|e| ConfineError::io(".", e))? {
        let entry = entry.map_err(|e| ConfineError::io(".", e))?;
        let name = entry.file_name();
        if let Some(name_str) = name.to_str() {
            if fold_key(name_str) == target_key {
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                return Ok(Some(CollidingEntry { name, is_dir }));
            }
        }
    }
    Ok(None)
}

/// Scans `dir`'s top-level entries for one whose name fold-collides with `candidate_name`.
/// Returns the colliding entry's actual on-disk name, if any. This is the identity-agnostic half
/// of collision detection — it works even on filesystems (e.g. Linux) that keep case/Unicode
/// variants as distinct, non-colliding dirents at the OS level, which is exactly why Spindle must
/// do this check itself rather than relying on the filesystem. Callers that need to know whether
/// the collision is a directory (the upload/mkdir overwrite gate) should use
/// [`existing_entry_colliding_typed`] instead — both share the same underlying scan.
pub fn existing_entry_colliding(
    dir: &Dir,
    candidate_name: &str,
) -> Result<Option<std::ffi::OsString>, ConfineError> {
    Ok(scan_for_collision(dir, candidate_name)?.map(|entry| entry.name))
}

/// Like [`existing_entry_colliding`], but also reports whether the colliding entry is a
/// directory — see [`CollidingEntry`].
pub fn existing_entry_colliding_typed(
    dir: &Dir,
    candidate_name: &str,
) -> Result<Option<CollidingEntry>, ConfineError> {
    scan_for_collision(dir, candidate_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confine::open_share_root;
    // Only used inside the `#[cfg(target_os = "macos")]` blocks below — cfg-gated here too so
    // this import isn't flagged unused on Linux/Windows (`clippy -D warnings`).
    #[cfg(target_os = "macos")]
    use crate::confine::resolve_identity;
    use tempfile::tempdir;

    #[test]
    fn case_fold_collision_detected() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");

        dir.write("Photo.JPG", b"original-bytes")
            .expect("write Photo.JPG");

        assert!(
            names_collide("Photo.JPG", "photo.jpg"),
            "our fold key must treat a case-only variant as the same name"
        );
        assert!(!names_collide("Photo.JPG", "Other.JPG"));

        let colliding = existing_entry_colliding(&dir, "photo.jpg")
            .expect("scan dir entries")
            .expect("a case-fold collision with Photo.JPG must be found");
        assert_eq!(colliding, std::ffi::OsString::from("Photo.JPG"));

        #[cfg(target_os = "macos")]
        {
            // APFS is case-insensitive by default: the OS itself must already treat these as the
            // same dirent, which our check must agree with.
            let id_original = resolve_identity(&dir, "Photo.JPG").expect("stat Photo.JPG");
            let id_variant = resolve_identity(&dir, "photo.jpg").expect("stat photo.jpg");
            assert_eq!(
                id_original, id_variant,
                "macOS APFS (default, case-insensitive) must fold these to the same file"
            );
        }
    }

    #[test]
    fn unicode_nfd_collision_detected() {
        let nfc = "caf\u{00E9}"; // "café", precomposed é (U+00E9)
        let nfd = "cafe\u{0301}"; // "café", e (U+0065) + combining acute accent (U+0301)
        assert_ne!(nfc, nfd, "sanity: the two byte-level spellings must differ");
        assert!(
            names_collide(nfc, nfd),
            "our fold key must treat the NFC and NFD spellings of \"café\" as the same name"
        );

        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");
        dir.write(nfc, b"cafe-content")
            .expect("write NFC-named file");

        #[cfg(target_os = "macos")]
        {
            let id_nfc = resolve_identity(&dir, nfc).expect("stat NFC name");
            let id_nfd = resolve_identity(&dir, nfd).expect("stat NFD name");
            assert_eq!(
                id_nfc, id_nfd,
                "macOS APFS must normalize the NFD lookup onto the NFC-created dirent"
            );
        }
    }

    /// td-47d24d's named gap, closed: the old hand-rolled `LATIN1_DECOMPOSITIONS` table only knew
    /// about 27 precomposed Latin-1 letters, so a Latin Extended-A letter like "ā" (U+0101) never
    /// matched the table and its combining-mark strip only ran on the *already-decomposed*
    /// spelling — the two forms folded to different keys ("ā" vs "a"). Real NFD has no such
    /// per-letter allowlist.
    #[test]
    fn latin_extended_a_macron_collides() {
        let precomposed = "\u{0101}"; // "ā", NFC
        let decomposed = "a\u{0304}"; // "a" + combining macron (U+0304), NFD
        assert_ne!(
            precomposed, decomposed,
            "sanity: byte-level spellings differ"
        );
        assert!(
            names_collide(precomposed, decomposed),
            "NFC and NFD spellings of \"ā\" must fold to the same key"
        );
    }

    /// Non-Latin coverage the old 27-entry Latin-1-only table could never have handled: Greek and
    /// Cyrillic precomposed/decomposed pairs both collide under real NFD.
    #[test]
    fn non_latin_scripts_collide_under_nfd() {
        let greek_precomposed = "\u{03AC}"; // "ά", GREEK SMALL LETTER ALPHA WITH TONOS
        let greek_decomposed = "\u{03B1}\u{0301}"; // alpha (U+03B1) + combining acute (U+0301)
        assert!(
            names_collide(greek_precomposed, greek_decomposed),
            "NFC and NFD spellings of Greek \"ά\" must fold to the same key"
        );

        let cyrillic_precomposed = "\u{0439}"; // "й", CYRILLIC SMALL LETTER SHORT I
        let cyrillic_decomposed = "\u{0438}\u{0306}"; // и (U+0438) + combining breve (U+0306)
        assert!(
            names_collide(cyrillic_precomposed, cyrillic_decomposed),
            "NFC and NFD spellings of Cyrillic \"й\" must fold to the same key"
        );
    }

    /// Vietnamese stacks two combining marks on one base letter (a tone mark plus a vowel
    /// modifier) — a case the old table's single-(base, mark) triples structurally could not
    /// represent even if it had been extended.
    #[test]
    fn vietnamese_double_diacritic_collides() {
        let precomposed = "\u{1EA7}"; // "ầ", LATIN SMALL LETTER A WITH CIRCUMFLEX AND GRAVE
        let decomposed = "a\u{0302}\u{0300}"; // a + combining circumflex (U+0302) + combining grave (U+0300)
        assert!(
            names_collide(precomposed, decomposed),
            "NFC and NFD spellings of Vietnamese \"ầ\" must fold to the same key"
        );
    }

    /// The deliberate behavior change (td-47d24d, USER DECISION 2026-09-04): diacritics are now
    /// preserved, not stripped, so a plain-ASCII name and its accented counterpart are DIFFERENT
    /// names. Do not "fix" this back — the old stripping behavior was the bug: an upload literally
    /// named `resume.pdf` could silently overwrite an owner's `résumé.pdf`.
    #[test]
    fn accented_and_unaccented_names_are_distinct() {
        assert!(
            !names_collide("café", "cafe"),
            "\"café\" and \"cafe\" must be distinct names — diacritics are preserved"
        );
        assert!(
            !names_collide("résumé.pdf", "resume.pdf"),
            "\"résumé.pdf\" and \"resume.pdf\" must be distinct names — diacritics are preserved"
        );
    }

    /// Case and normalization variance together: an NFC uppercase spelling and an NFD lowercase
    /// spelling of the same word must still collide.
    #[test]
    fn case_and_normalization_combine() {
        let nfc_upper = "CAF\u{00C9}"; // "CAFÉ", NFC uppercase (precomposed É, U+00C9)
        let nfd_lower = "cafe\u{0301}"; // "café", NFD lowercase
        assert!(
            names_collide(nfc_upper, nfd_lower),
            "uppercase NFC and lowercase NFD spellings of \"café\" must fold to the same key"
        );
    }

    /// `fold_key` must be idempotent — folding an already-folded key must be a no-op — because
    /// `fold_key(fold_key(x)) == fold_key(x)` is exactly what the trailing `.nfd()` in `fold_key`
    /// is there to guarantee (see that function's doc comment).
    #[test]
    fn fold_key_is_idempotent() {
        let inputs = [
            "café",
            "cafe\u{0301}",
            "CAFÉ",
            "résumé.pdf",
            "resume.pdf",
            "\u{0101}",          // ā, NFC
            "a\u{0304}",         // ā, NFD
            "\u{03AC}",          // ά, NFC
            "\u{03B1}\u{0301}",  // ά, NFD
            "\u{0439}",          // й, NFC
            "\u{0438}\u{0306}",  // й, NFD
            "\u{1EA7}",          // ầ, NFC
            "a\u{0302}\u{0300}", // ầ, NFD
            "Photo.JPG",
            "plain-ascii-name.txt",
        ];
        for input in inputs {
            let once = fold_key(input);
            let twice = fold_key(&once);
            assert_eq!(
                once, twice,
                "fold_key must be idempotent for input {input:?}"
            );
        }
    }
}
