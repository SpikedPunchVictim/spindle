//! File identity (dev+ino / file-id), the hardlink-bypass `nlink` guard, and the TOCTOU/rename
//! -race per-chunk identity check (DESIGN.md §A4b; closes A12 #29, #30).

use super::ConfineError;
use cap_std::fs::Dir;

/// A cross-platform file-identity tuple: `(volume, file-id)`. On Unix this is `(dev, ino)`; on
/// Windows it is `(volume_serial_number, file_index)`. Two dirents with equal identity are the
/// same underlying file regardless of what name(s) reach them — the primitive every TOCTOU/
/// overlap check in this module builds on.
#[cfg(unix)]
pub fn file_identity(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(windows)]
pub fn file_identity(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::windows::fs::MetadataExt;
    (
        u64::from(meta.volume_serial_number().unwrap_or(0)),
        meta.file_index().unwrap_or(0),
    )
}

/// Fetches a real `std::fs::Metadata` for `virtual_path` through `dir`'s `cap-std` capability, by
/// opening it (capability-checked, confined, symlink-target-inside-root only) and delegating to
/// `std::fs::File::metadata`. This sidesteps `cap-std`'s own `Metadata` wrapper, whose
/// identity/link-count accessors require a nightly-only feature on Windows
/// (`cap_primitives`'s `windows_by_handle`) — going through the real `std` type keeps
/// [`file_identity`] and [`nlink_guard`] usable on stable Rust on every platform, without ever
/// leaving the `Dir`'s confinement to do it.
pub fn stat_through_dir(dir: &Dir, virtual_path: &str) -> Result<std::fs::Metadata, ConfineError> {
    dir.open(virtual_path)
        .and_then(|f| f.into_std().metadata())
        .map_err(|e| ConfineError::io(virtual_path, e))
}

/// Resolves `virtual_path` through `dir` (never leaving its `cap-std` capability, even when the
/// resolved entry is reached via a symlink whose target is inside the root) and returns its file
/// identity. This is the primitive both [`nlink_guard`]'s callers and
/// [`read_confined_with_identity_check`]'s TOCTOU check build on.
pub fn resolve_identity(dir: &Dir, virtual_path: &str) -> Result<(u64, u64), ConfineError> {
    Ok(file_identity(&stat_through_dir(dir, virtual_path)?))
}

#[cfg(unix)]
fn nlink_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(windows)]
fn nlink_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    u64::from(meta.number_of_links().unwrap_or(1))
}

/// DESIGN.md §A4b hardlink-bypass rule, verbatim: "when a share has exclusions, files with link
/// count > 1 are not served." Returns `true` when the file may be served, given whether the
/// share has any exclusion globs configured at all (`crate::model::Share::has_exclusions`).
/// Closes A12 #29 (overlapping share roots / hardlinks defeat exclusions).
pub fn nlink_guard(meta: &std::fs::Metadata, share_has_exclusions: bool) -> bool {
    !(share_has_exclusions && nlink_of(meta) > 1)
}

/// Reads `relative` through `dir` in `chunk_size` chunks, re-resolving the path's identity after
/// every chunk and aborting if it no longer matches the identity observed before the first byte
/// was read (DESIGN.md §A4b: "file identity is checked between stat and read/upload and on every
/// chunk boundary, aborting on change"). `after_chunk` is invoked with the zero-based chunk index
/// right after each chunk is appended to the output and right before the post-chunk identity
/// check — it exists so tests can deterministically inject a race at an exact point instead of
/// relying on timing (sleeps/threads), which would make the test flaky. Closes A12 #30 (TOCTOU/
/// rename race inside a share).
pub fn read_confined_with_identity_check<F: FnMut(usize)>(
    dir: &Dir,
    relative: &str,
    chunk_size: usize,
    mut after_chunk: F,
) -> Result<Vec<u8>, ConfineError> {
    use std::io::Read;

    let expected_identity = resolve_identity(dir, relative)?;
    let mut file = dir
        .open(relative)
        .map_err(|e| ConfineError::io(relative, e))?;
    let mut out = Vec::new();
    let mut chunk = vec![0u8; chunk_size];
    let mut chunk_index = 0usize;
    loop {
        let n = file
            .read(&mut chunk)
            .map_err(|e| ConfineError::io(relative, e))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        after_chunk(chunk_index);

        let current_identity = resolve_identity(dir, relative)?;
        if current_identity != expected_identity {
            return Err(ConfineError::IdentityChangedMidTransfer {
                path: relative.to_string(),
                chunk_index,
            });
        }
        chunk_index += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confine::open_share_root;
    use tempfile::tempdir;

    // ---- Hardlink bypass guard ----

    #[test]
    fn hardlink_nlink_guard() {
        // Attack: a hardlink (nlink > 1) into a share with exclusions is used to serve content
        // under a name the exclusion globs don't match.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");

        dir.write("original.txt", b"content")
            .expect("write original");
        dir.write("solo.txt", b"content").expect("write solo file");
        dir.hard_link("original.txt", &dir, "linked.txt")
            .expect("create hardlink (same filesystem, same dir)");

        let linked_meta = stat_through_dir(&dir, "linked.txt").expect("stat linked.txt");
        let solo_meta = stat_through_dir(&dir, "solo.txt").expect("stat solo.txt");

        assert!(
            nlink_of(&linked_meta) > 1,
            "sanity: hard_link must actually raise the link count"
        );
        assert_eq!(
            nlink_of(&solo_meta),
            1,
            "sanity: the non-hardlinked control file must have link count 1"
        );

        assert!(
            !nlink_guard(&linked_meta, true),
            "a file with link count > 1 must not be served when the share has exclusions"
        );
        assert!(
            nlink_guard(&solo_meta, true),
            "a file with link count 1 must still be served when the share has exclusions"
        );
        assert!(
            nlink_guard(&linked_meta, false),
            "the hardlink rule only applies when the share actually has exclusions configured"
        );
    }

    // ---- TOCTOU / rename races ----

    #[test]
    fn exclusion_bypass_via_rename() {
        // Attack (A4b TOCTOU rule): an entitlement/exclusion decision is made for "target.txt" at
        // check time (not excluded, ok to serve); before the bytes are actually served, an
        // attacker (or a benign concurrent rename) swaps a different file into that name. Must
        // prove: the identity captured at check time no longer matches at serve time, so a
        // stat-before/stat-after identity check catches the swap.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");

        dir.write("target.txt", b"checked-and-approved content")
            .expect("write target.txt");
        let checked_identity = resolve_identity(&dir, "target.txt").expect("stat at check time");

        dir.write("payload.txt", b"attacker-controlled content")
            .expect("write payload.txt");
        dir.rename("payload.txt", &dir, "target.txt")
            .expect("rename over target.txt");

        let serve_identity = resolve_identity(&dir, "target.txt").expect("stat at serve time");
        assert_ne!(
            checked_identity, serve_identity,
            "identity must differ after the swap so the VFS aborts instead of serving unchecked \
             content"
        );
    }

    #[test]
    fn rename_race_identity_check() {
        // Attack: the target file is renamed/replaced between two chunk reads of the same
        // transfer. Must prove: the per-chunk-boundary identity check detects this and the read
        // aborts instead of silently splicing old and new content together.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");

        dir.write("stream.bin", vec![0xABu8; 4096])
            .expect("write stream.bin");

        let bytes = read_confined_with_identity_check(&dir, "stream.bin", 1024, |_| {})
            .expect("uninterrupted read must succeed");
        assert_eq!(bytes.len(), 4096);
        assert!(bytes.iter().all(|&b| b == 0xAB));

        let result = read_confined_with_identity_check(&dir, "stream.bin", 1024, |chunk_index| {
            if chunk_index == 0 {
                dir.write("attacker.bin", vec![0xCDu8; 4096])
                    .expect("write attacker.bin");
                dir.rename("attacker.bin", &dir, "stream.bin")
                    .expect("rename attacker.bin over stream.bin");
            }
        });
        assert!(
            matches!(result, Err(ConfineError::IdentityChangedMidTransfer { .. })),
            "an identity change mid-transfer must abort the read with IdentityChangedMidTransfer, \
             got {result:?}"
        );
    }
}
