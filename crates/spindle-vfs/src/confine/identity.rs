//! File identity (dev+ino / file-id), the hardlink-bypass `nlink` guard, and the TOCTOU/rename
//! -race per-chunk identity check (DESIGN.md §A4b; closes A12 #29, #30).

use super::ConfineError;
use cap_std::fs::Dir;

/// A cross-platform file-identity value: two dirents with equal identity are the same underlying
/// file regardless of what name(s) reach them — the primitive every TOCTOU/overlap check in this
/// module builds on. On Unix this is the `(dev, ino)` pair. On Windows,
/// `std::os::windows::fs::MetadataExt`'s identity accessors (`volume_serial_number`,
/// `file_index`) are gated behind the nightly-only `windows_by_handle` feature
/// (rust-lang/rust#63010) and are unusable on stable Rust — going through `std`'s own `Metadata`
/// type (rather than `cap-std`'s wrapper) does not sidestep this; the feature gate is on the
/// accessor itself. Windows identity instead goes through the `same-file` crate's `Handle`, which
/// gets the equivalent `(volume serial, file index)` pair via `GetFileInformationByHandle` on
/// stable Rust.
#[cfg(unix)]
pub type FileIdentity = (u64, u64);
#[cfg(windows)]
pub type FileIdentity = same_file::Handle;

#[cfg(unix)]
fn identity_from_metadata(meta: &std::fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

/// Computes the [`FileIdentity`] of an already-open `file` (e.g. one obtained through a `Dir`
/// capability via [`resolve_identity`]).
pub fn file_identity(file: &std::fs::File) -> std::io::Result<FileIdentity> {
    #[cfg(unix)]
    {
        Ok(identity_from_metadata(&file.metadata()?))
    }
    #[cfg(windows)]
    {
        same_file::Handle::from_file(file.try_clone()?)
    }
}

/// Computes the [`FileIdentity`] of an ambient filesystem `path` that has not been opened yet —
/// used by [`super::overlap::overlap_check`], which compares share roots (which may be
/// directories) by real path before either is opened as a `Dir`. On Windows this goes through
/// `same_file::Handle::from_path`, which (unlike a plain `File::open`) opens directories
/// correctly via `FILE_FLAG_BACKUP_SEMANTICS`.
pub fn identity_of_ambient_path(path: &std::path::Path) -> std::io::Result<FileIdentity> {
    #[cfg(unix)]
    {
        Ok(identity_from_metadata(&std::fs::metadata(path)?))
    }
    #[cfg(windows)]
    {
        same_file::Handle::from_path(path)
    }
}

/// Fetches a real `std::fs::Metadata` for `virtual_path` through `dir`'s `cap-std` capability, by
/// opening it (capability-checked, confined, symlink-target-inside-root only) and delegating to
/// `std::fs::File::metadata`. This sidesteps `cap-std`'s own `Metadata` wrapper, which is
/// convenient for stable, cross-platform metadata fields (size, timestamps, permissions); it is
/// **not** used for identity or link-count, which need [`file_identity`] / [`nlink_guard`]
/// instead (see their doc comments for why `Metadata` alone cannot provide those on Windows).
pub fn stat_through_dir(dir: &Dir, virtual_path: &str) -> Result<std::fs::Metadata, ConfineError> {
    dir.open(virtual_path)
        .and_then(|f| f.into_std().metadata())
        .map_err(|e| ConfineError::io(virtual_path, e))
}

/// Resolves `virtual_path` through `dir` (never leaving its `cap-std` capability, even when the
/// resolved entry is reached via a symlink whose target is inside the root) and returns its file
/// identity. This is the primitive both [`nlink_guard`]'s callers and
/// [`read_confined_with_identity_check`]'s TOCTOU check build on.
pub fn resolve_identity(dir: &Dir, virtual_path: &str) -> Result<FileIdentity, ConfineError> {
    let file = dir
        .open(virtual_path)
        .map_err(|e| ConfineError::io(virtual_path, e))?
        .into_std();
    file_identity(&file).map_err(|e| ConfineError::io(virtual_path, e))
}

#[cfg(unix)]
fn nlink_of(file: &std::fs::File) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn nlink_of(file: &std::fs::File) -> std::io::Result<u64> {
    // `std::os::windows::fs::MetadataExt::number_of_links` is gated behind the same nightly-only
    // `windows_by_handle` feature as the identity accessors above (rust-lang/rust#63010) and is
    // unusable on stable Rust; `winapi-util` (the same crate `same-file` itself uses internally
    // for `GetFileInformationByHandle`) exposes the link count directly.
    Ok(winapi_util::file::information(file)?.number_of_links())
}

/// DESIGN.md §A4b hardlink-bypass rule, verbatim: "when a share has exclusions, files with link
/// count > 1 are not served." Returns `true` when the file may be served, given whether the
/// share has any exclusion globs configured at all (`crate::model::Share::has_exclusions`).
/// Closes A12 #29 (overlapping share roots / hardlinks defeat exclusions).
pub fn nlink_guard(file: &std::fs::File, share_has_exclusions: bool) -> std::io::Result<bool> {
    if !share_has_exclusions {
        return Ok(true);
    }
    Ok(nlink_of(file)? <= 1)
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

        let linked_file = dir.open("linked.txt").expect("open linked.txt").into_std();
        let solo_file = dir.open("solo.txt").expect("open solo.txt").into_std();

        assert!(
            nlink_of(&linked_file).expect("nlink linked.txt") > 1,
            "sanity: hard_link must actually raise the link count"
        );
        assert_eq!(
            nlink_of(&solo_file).expect("nlink solo.txt"),
            1,
            "sanity: the non-hardlinked control file must have link count 1"
        );

        assert!(
            !nlink_guard(&linked_file, true).expect("guard linked.txt, exclusions"),
            "a file with link count > 1 must not be served when the share has exclusions"
        );
        assert!(
            nlink_guard(&solo_file, true).expect("guard solo.txt, exclusions"),
            "a file with link count 1 must still be served when the share has exclusions"
        );
        assert!(
            nlink_guard(&linked_file, false).expect("guard linked.txt, no exclusions"),
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
