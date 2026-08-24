//! Case/Unicode fold-key comparison and collision detection against existing dirents (DESIGN.md
//! §A4b: "cap-std does not canonicalize, case-fold, or normalize — Spindle does"). Closes A12
//! #20 (exclusion/permission bypass via case or Unicode variants) and, combined with
//! `crate::confine::upload`, A12 #31 (case/NFD upload collision overwrites without `delete`).

use super::ConfineError;
use cap_std::fs::Dir;

/// Precomposed Latin-1 Supplement letter -> (base letter, combining mark) decompositions.
///
/// **Scope limitation, carried over from the S11 spike verbatim**: this is *not* a general
/// Unicode NFC/NFD implementation — it covers exactly the common Latin accented letters (the set
/// needed to prove the "café" NFC/NFD case `docs/SPIKES.md` names, and the only Unicode folding
/// this slice's test suite exercises). A future slice should replace this with a real Unicode
/// normalization crate (e.g. `unicode-normalization`) rather than growing this table further;
/// it stays hand-rolled here only because this slice's dependency budget is `cap-std` + `thiserror`
/// (+ `spindle-core`), matching the spike's own no-extra-deps constraint.
const LATIN1_DECOMPOSITIONS: &[(char, char, char)] = &[
    ('à', 'a', '\u{0300}'),
    ('á', 'a', '\u{0301}'),
    ('â', 'a', '\u{0302}'),
    ('ã', 'a', '\u{0303}'),
    ('ä', 'a', '\u{0308}'),
    ('å', 'a', '\u{030A}'),
    ('ç', 'c', '\u{0327}'),
    ('è', 'e', '\u{0300}'),
    ('é', 'e', '\u{0301}'),
    ('ê', 'e', '\u{0302}'),
    ('ë', 'e', '\u{0308}'),
    ('ì', 'i', '\u{0300}'),
    ('í', 'i', '\u{0301}'),
    ('î', 'i', '\u{0302}'),
    ('ï', 'i', '\u{0308}'),
    ('ñ', 'n', '\u{0303}'),
    ('ò', 'o', '\u{0300}'),
    ('ó', 'o', '\u{0301}'),
    ('ô', 'o', '\u{0302}'),
    ('õ', 'o', '\u{0303}'),
    ('ö', 'o', '\u{0308}'),
    ('ù', 'u', '\u{0300}'),
    ('ú', 'u', '\u{0301}'),
    ('û', 'u', '\u{0302}'),
    ('ü', 'u', '\u{0308}'),
    ('ý', 'y', '\u{0301}'),
    ('ÿ', 'y', '\u{0308}'),
];

/// Folds `name` to a comparison key that is stable across simple case variance and NFC/NFD
/// spelling variance of the Latin letters in [`LATIN1_DECOMPOSITIONS`]. Two names with equal fold
/// keys must be treated as the same dirent (DESIGN.md §A4b: a case-insensitive or Unicode-
/// normalization collision with an existing dirent **is** an overwrite, not a new entry). Also
/// used by `crate::model::VirtualPath::descends_from_or_eq` and `crate::glob` for path-component
/// comparison, so the same folding rule applies uniformly across confinement, the entitlement
/// algebra, and exclusion matching.
pub fn fold_key(name: &str) -> String {
    let lowered = name.to_lowercase();
    let mut folded = String::with_capacity(lowered.len());
    for ch in lowered.chars() {
        if ('\u{0300}'..='\u{036F}').contains(&ch) {
            continue; // strip a standalone combining diacritical mark (already-NFD input)
        }
        if let Some(&(_, base, _mark)) = LATIN1_DECOMPOSITIONS.iter().find(|&&(c, _, _)| c == ch) {
            folded.push(base); // decompose, then drop the mark exactly as the branch above would
        } else {
            folded.push(ch);
        }
    }
    folded
}

/// `true` when `a` and `b` fold to the same key and must therefore be treated as the same dirent.
pub fn names_collide(a: &str, b: &str) -> bool {
    fold_key(a) == fold_key(b)
}

/// Scans `dir`'s top-level entries for one whose name fold-collides with `candidate_name`.
/// Returns the colliding entry's actual on-disk name, if any. This is the identity-agnostic half
/// of collision detection — it works even on filesystems (e.g. Linux) that keep case/Unicode
/// variants as distinct, non-colliding dirents at the OS level, which is exactly why Spindle must
/// do this check itself rather than relying on the filesystem.
pub fn existing_entry_colliding(
    dir: &Dir,
    candidate_name: &str,
) -> Result<Option<std::ffi::OsString>, ConfineError> {
    let target_key = fold_key(candidate_name);
    for entry in dir.entries().map_err(|e| ConfineError::io(".", e))? {
        let entry = entry.map_err(|e| ConfineError::io(".", e))?;
        let name = entry.file_name();
        if let Some(name_str) = name.to_str() {
            if fold_key(name_str) == target_key {
                return Ok(Some(name));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confine::{open_share_root, resolve_identity};
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
}
