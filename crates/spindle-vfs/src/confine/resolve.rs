//! Fold-aware path resolution (DESIGN.md §A4b, :370-371: a name colliding case-insensitively or
//! under Unicode normalization with an existing dirent **is** that dirent). `stat_through_dir`
//! (`crate::confine::identity`) is a literal `dir.open_with(virtual_path, ...)` — the OS resolves
//! it, so it folds names on case-insensitive filesystems (macOS, Windows) and does **not** on
//! Linux. A caller that needs to tell "this path is genuinely gone" apart from "this path exists
//! on disk under a differently-spelled name" cannot rely on a literal lookup alone, because both
//! present as `NotFound` on Linux. [`resolve_folded_path`] is that distinction, made explicit and
//! portable: it walks the virtual path component by component using this crate's own fold-key
//! identity ([`super::fold::existing_entry_colliding`]) rather than the host filesystem's
//! resolution behavior.

use super::fold::existing_entry_colliding;
use super::ConfineError;
use cap_std::fs::Dir;

/// Resolves `virtual_path` through `dir` using the VFS's own folded name identity rather than
/// whatever the host filesystem happens to do, returning the real on-disk spelling of the path
/// (`/`-joined, which may differ from `virtual_path` in any component), or `None` when no chain
/// of fold-matching dirents leads to it.
///
/// `virtual_path` is split on `/`, skipping empty components (so a leading, trailing, or doubled
/// slash is harmless). At each level this tries the **literal** name first — a plain existence
/// check through the current `Dir` — which is cheap and correct for the overwhelming common case
/// where nothing has drifted. Only when the literal lookup finds nothing does this fall back to
/// scanning that directory for a fold-colliding entry via the existing
/// [`super::fold::existing_entry_colliding`] (this function does not implement a second fold
/// comparison); if neither finds anything at some level, resolution fails outright and this
/// returns `Ok(None)` — the path genuinely does not resolve. This ordering is deliberate: the
/// directory scan is `O(entries in that directory)` where the literal check is one syscall, so
/// staying on the literal fast path whenever possible keeps a sweep over many ledger rows cheap.
///
/// Every lookup goes through the capability `Dir` — descending via `Dir::open_dir` on the real
/// name just resolved, exactly as [`super::upload::finalize_upload`] and
/// [`super::listing::create_dir_confined`] open a nested parent (`dir.open_dir(&parent)`) rather
/// than resolving a joined path directly. Nothing here ever passes `..` or an absolute path
/// onward, and no path is touched via `std::fs` — that is the whole point of `confine`.
///
/// The final component may name a file or a directory; every earlier component must be a
/// directory (it is opened with `open_dir`, which fails if it isn't).
pub fn resolve_folded_path(dir: &Dir, virtual_path: &str) -> Result<Option<String>, ConfineError> {
    let components: Vec<&str> = virtual_path.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        // The share root itself: nothing to resolve, and it always "exists" from the caller's
        // point of view (the `Dir` capability is already open on it).
        return Ok(Some(String::new()));
    }

    let mut current = dir
        .try_clone()
        .map_err(|e| ConfineError::io(virtual_path, e))?;
    let mut resolved: Vec<String> = Vec::with_capacity(components.len());
    let last_index = components.len() - 1;

    for (index, component) in components.iter().enumerate() {
        let real_name = if current.exists(component) {
            component.to_string()
        } else {
            match existing_entry_colliding(&current, component)? {
                // `existing_entry_colliding` only ever reports an entry whose name is valid
                // UTF-8 (it skips anything that fails `to_str` internally), so `to_string_lossy`
                // never actually loses information here.
                Some(existing) => existing.to_string_lossy().into_owned(),
                None => return Ok(None),
            }
        };

        if index == last_index {
            resolved.push(real_name);
        } else {
            current = current
                .open_dir(&real_name)
                .map_err(|e| ConfineError::io(virtual_path, e))?;
            resolved.push(real_name);
        }
    }

    Ok(Some(resolved.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confine::open_share_root;
    use tempfile::tempdir;

    #[test]
    fn literal_match_resolves_unchanged() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir_all(root.join("Vacation")).expect("mkdir nested");
        std::fs::write(root.join("Vacation/photo.jpg"), b"x").expect("write");
        let dir = open_share_root(&root).expect("open share root");

        assert_eq!(
            resolve_folded_path(&dir, "Vacation/photo.jpg").expect("resolve"),
            Some("Vacation/photo.jpg".to_string())
        );
    }

    // ---- Case-differing spelling ----
    //
    // **Platform note**: this machine's default macOS/APFS volume is case-insensitive
    // (`crate::confine::fold::tests::case_fold_collision_detected` documents and relies on this
    // same fact for the OS's own resolution). That means the *literal* existence check this
    // function tries first — a single `Dir::exists` — already succeeds for a case-only variant,
    // because the OS itself folds the lookup before `resolve_folded_path` ever gets a chance to
    // fall back to `existing_entry_colliding`. So a pure case-difference test on this machine
    // exercises only the literal fast path, not the fold-scan fallback this function exists to
    // add — it is not wrong, just insufficient proof of the fallback.
    //
    // **td-47d24d update (2026-09-04)**: the tests below used to force the fold-scan fallback
    // deterministically with an accented-vs-unaccented spelling (`fold_key` used to strip
    // diacritics entirely, a broader rule than any OS-level normalization, so "café" written to
    // disk and "cafe" requested would fail the literal check on every platform including this
    // one). That device no longer exists: `fold_key` now preserves diacritics (NFD + case only),
    // so "café" and "cafe" are different names to Spindle too, exactly like they are to the OS —
    // there is no longer any fold collision that this machine's default (case-insensitive,
    // NFD-normalizing) APFS volume does *not* already paper over at the literal-check step. The
    // tests below therefore use the same case-difference technique as the test above, and accept
    // *either* the requested or the real on-disk spelling as a passing outcome — deliberately,
    // because which one it is now depends on the filesystem:
    //   - on a case-folding filesystem (this machine's default APFS, or Windows): the literal
    //     `Dir::exists` check already succeeds, so `resolve_folded_path` returns the *requested*
    //     spelling and the fold-scan fallback never runs;
    //   - on a case-sensitive filesystem (Linux, or the `hdiutil`-created "Case-sensitive APFS"
    //     volume this ticket's verification runs against): the literal check genuinely fails and
    //     the fold-scan fallback is what makes the test pass, returning the real on-disk spelling.
    // Either outcome proves `resolve_folded_path` resolves the path correctly on its own
    // filesystem; only running on the case-sensitive volume proves the fallback branch itself
    // executes. Do not read a passing run on default macOS as proof the fold scan ran.

    #[test]
    fn case_differing_final_component_resolves() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        std::fs::write(root.join("Photo.JPG"), b"x").expect("write");
        let dir = open_share_root(&root).expect("open share root");

        // The exact spelling returned here is platform-dependent, not a defect: on a
        // case-insensitive volume (this machine's default) the literal `Dir::exists("photo.jpg")`
        // check itself already succeeds, so `resolve_folded_path` never needs the fold-scan
        // fallback and returns the *requested* spelling. On a case-sensitive volume the literal
        // check genuinely fails and the fallback runs, correctly returning the real on-disk
        // spelling "Photo.JPG" instead — verified by running this same test suite with `TMPDIR`
        // pointed at a `hdiutil`-created "Case-sensitive APFS" volume (see this ticket's neuter
        // proof). Either outcome is correct; what must hold on every platform is just that the
        // path resolves at all.
        let resolved = resolve_folded_path(&dir, "photo.jpg").expect("resolve");
        assert!(
            resolved == Some("photo.jpg".to_string()) || resolved == Some("Photo.JPG".to_string()),
            "expected the requested or real spelling, got {resolved:?}"
        );
    }

    #[test]
    fn genuinely_absent_path_resolves_to_none() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        let dir = open_share_root(&root).expect("open share root");

        assert_eq!(
            resolve_folded_path(&dir, "never-existed.txt").expect("resolve"),
            None
        );
        assert_eq!(
            resolve_folded_path(&dir, "no/such/nested/path.txt").expect("resolve"),
            None
        );
    }

    // ---- Fold-scan fallback, forced deterministically via an accent (not case) mismatch ----
    //
    // `fold_key` (`crate::confine::fold`) strips a Latin accent entirely when folding (e.g.
    // "café" and "cafe" fold to the same key, "cafe") — a broader rule than any OS-level Unicode
    // normalization, which only unifies *different representations of the same accented
    // character* (precomposed vs. combining-mark NFD), never an accented letter with its bare,
    // unaccented counterpart. So writing "café..." on disk and requesting "cafe..." (no accent)
    // makes the literal `Dir::exists` check genuinely fail on every platform, including this
    // case-insensitive macOS volume, forcing `resolve_folded_path` through
    // `existing_entry_colliding` — the exact branch these tests are meant to prove.

    #[test]
    fn final_component_resolves_across_a_case_difference() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        std::fs::write(root.join("REPORT.txt"), b"x").expect("write REPORT.txt");
        let dir = open_share_root(&root).expect("open share root");

        // Outcome-only assertion (see the module comment above for why): on this machine's
        // default case-folding APFS volume the literal fast path already resolves this, so the
        // fold-scan fallback is only actually exercised on a case-sensitive filesystem.
        let resolved = resolve_folded_path(&dir, "report.txt").expect("resolve");
        assert!(
            resolved == Some("report.txt".to_string())
                || resolved == Some("REPORT.txt".to_string()),
            "expected the requested or real spelling, got {resolved:?}"
        );
    }

    #[test]
    fn intermediate_directory_resolves_across_a_case_difference() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir_all(root.join("VACATION")).expect("mkdir dir");
        std::fs::write(root.join("VACATION/photo.jpg"), b"x").expect("write nested file");
        let dir = open_share_root(&root).expect("open share root");

        // Outcome-only assertion (see the module comment above for why): on this machine's
        // default case-folding APFS volume the literal fast path already descends through the
        // intermediate directory, so the fold-scan fallback is only actually exercised on a
        // case-sensitive filesystem.
        let resolved = resolve_folded_path(&dir, "vacation/photo.jpg").expect("resolve");
        assert!(
            resolved == Some("vacation/photo.jpg".to_string())
                || resolved == Some("VACATION/photo.jpg".to_string()),
            "expected the requested or real spelling for the intermediate directory, got {resolved:?}"
        );
    }

    #[test]
    fn one_component_literal_one_case_differs() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        // "Vacation" matches the requested spelling literally; "PHOTO.jpg" only matches by a
        // case fold on the final component.
        std::fs::create_dir_all(root.join("Vacation")).expect("mkdir nested");
        std::fs::write(root.join("Vacation/PHOTO.jpg"), b"x").expect("write");
        let dir = open_share_root(&root).expect("open share root");

        // Outcome-only assertion (see the module comment above for why): on this machine's
        // default case-folding APFS volume the literal fast path already resolves the final
        // component, so the fold-scan fallback is only actually exercised on a case-sensitive
        // filesystem.
        let resolved = resolve_folded_path(&dir, "Vacation/photo.jpg").expect("resolve");
        assert!(
            resolved == Some("Vacation/photo.jpg".to_string())
                || resolved == Some("Vacation/PHOTO.jpg".to_string()),
            "expected the requested or real spelling for the final component, got {resolved:?}"
        );
    }

    #[test]
    fn root_path_resolves_to_empty_string() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        let dir = open_share_root(&root).expect("open share root");

        assert_eq!(
            resolve_folded_path(&dir, "").expect("resolve"),
            Some(String::new())
        );
    }
}
