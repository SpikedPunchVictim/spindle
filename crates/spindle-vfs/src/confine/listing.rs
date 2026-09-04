//! Directory listing, `mkdir`, and `delete` primitives — added for the Stage 6 slice 3 VFS RPC
//! server. Slice 1/2 only needed identity/exclusion/upload-path-scoping helpers (nothing in
//! `spindle-vfs` yet enumerated a directory's real entries or created/removed filesystem
//! objects); the RPC server (`spindle-host-core`) needs all three, through the same `cap-std`
//! `Dir` capability so DESIGN.md §A4b's "every request re-resolves from the share `Dir` (no
//! long-lived subdirectory handles)" rule holds for these operations too, not just `read`.
//!
//! Every function here is unopinionated about permissions — filtering a listing down to what a
//! member may browse is [`crate::algebra::EffectiveGrants::filter_listing`]'s job, and the
//! upload/delete-requires-`delete` overwrite gate is [`super::upload::write_is_authorized`]'s;
//! this module only knows how to talk to the real filesystem safely through the capability.

use super::identity::stat_through_dir;
use super::upload::{is_staging_name, upload_target_path, WriteKind, WriteTarget};
use super::ConfineError;
use cap_std::fs::Dir;
use std::path::{Path, PathBuf};

/// The real filesystem kind of a directory entry (mirrors, but is independent of,
/// `spindle_proto::vfs_rpc::EntryKind` — this module has no wire-type dependency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealEntryKind {
    File,
    Dir,
}

/// One directory entry read straight off the real filesystem — no permission filtering applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealDirEntry {
    pub name: String,
    pub kind: RealEntryKind,
    pub size: u64,
    pub mtime: u64,
}

fn unix_seconds(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lists `relative`'s direct children through `dir` (re-resolved fresh — DESIGN.md §A4b "every
/// request re-resolves from the share `Dir`"; no handle from this call is retained). `relative`
/// empty means `dir`'s own root. An entry whose name is not valid UTF-8, or whose metadata cannot
/// be read (permission error, a race where the entry vanished between the readdir syscall and the
/// follow-up stat), is silently skipped rather than aborting the whole listing or reporting
/// *why* — consistent with this crate's no-existence-leak posture (the caller,
/// `EffectiveGrants::filter_listing`, independently decides visibility; a skipped entry here is
/// just absent from what it gets to filter, exactly like an entry the member isn't entitled to).
/// An entry matching [`super::upload::is_staging_name`] is likewise skipped unconditionally
/// (DESIGN.md §A8 transfer manager: an in-progress upload's hidden staging file is "never
/// listed") — this is independent of the share's `show_hidden` flag, which governs real dotfiles
/// a member placed, not host-internal bookkeeping files.
pub fn list_dir(dir: &Dir, relative: &str) -> Result<Vec<RealDirEntry>, ConfineError> {
    let read_dir = if relative.is_empty() {
        dir.entries()
    } else {
        dir.read_dir(relative)
    }
    .map_err(|e| ConfineError::io(relative, e))?;

    let mut out = Vec::new();
    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if is_staging_name(&name) {
            continue;
        }
        let child_relative = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        let Ok(meta) = stat_through_dir(dir, &child_relative) else {
            continue;
        };
        let kind = if meta.is_dir() {
            RealEntryKind::Dir
        } else {
            RealEntryKind::File
        };
        out.push(RealDirEntry {
            name,
            kind,
            size: meta.len(),
            mtime: unix_seconds(&meta),
        });
    }
    Ok(out)
}

/// Splits a validated upload-relative target path into `(parent_relative, file_name)` —
/// `parent_relative` is `""` for a top-level target. Used by both [`create_dir_confined`] and
/// [`remove_confined`] so both can check the *parent* directory's entries for a fold-key
/// collision on the target's own name (DESIGN.md §A4b overwrite/collision rules), not `dir`'s own
/// root entries when the target is nested.
pub(super) fn split_parent_and_name(target: &Path) -> (PathBuf, String) {
    let name = target
        .file_name()
        .expect("upload_target_path guarantees at least one component")
        .to_string_lossy()
        .to_string();
    let parent = target.parent().map(Path::to_path_buf).unwrap_or_default();
    (parent, name)
}

/// The outcome of [`create_dir_confined`]: three-way, because a fold-colliding name can mean two
/// very different things depending on what it collides *with* (see [`WriteTarget`]'s doc
/// comment). A caller must be able to tell "nothing needed doing" apart from "you may not" — a
/// plain `bool` collapsed both into the same `false`, which is exactly what td-789f11 was open
/// about (a directory collision and a file collision were indistinguishable, and on macOS/Windows
/// the directory case didn't even reach this far cleanly — it surfaced as an `EEXIST` `Err`
/// instead of either boolean).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MkdirOutcome {
    /// No existing entry collided; a new, empty directory was created at `relative`.
    Created,
    /// td-789f11: the name fold-collided with an existing **directory** — exactly the thing
    /// `mkdir` was asked to ensure exists. Nothing was created or touched; this is a success, not
    /// a denial.
    AlreadyExists,
    /// `can_upload` is false, or the name fold-collided with an existing **file** (td-789f11: a
    /// type mismatch is always refused, never overwritten — see [`WriteTarget::TypeMismatch`]).
    Refused,
}

/// Creates a directory at `relative` (DESIGN.md §A8 `mkdir`). `relative` is validated the same
/// way an upload target is ([`upload_target_path`]) — no `..`, no absolute/rooted component, not
/// empty — since `mkdir` is exactly as capable of a path-traversal attempt as `upload` is, and
/// DESIGN.md draws no distinction between the two for path-safety purposes.
///
/// **Design note (interpretation, not explicit in DESIGN.md)**: this crate treats `mkdir`'s
/// permission requirement identically to `upload`'s — creating a directory needs `upload`.
/// DESIGN.md §A8 lists `mkdir` as one of the six RPC calls but never states which permission bit
/// governs it; that part is this implementation's choice, flagged per the task brief rather than
/// resolved silently. The parent directory must already exist (this is `create_dir`, not
/// `create_dir_all` — DESIGN.md's virtual tree has no notion of implicitly creating intermediate
/// directories on `mkdir`).
///
/// **Collision semantics (resolved 2026-09-04, td-789f11)**: routed through the same
/// [`super::upload::write_is_authorized`] gate `upload` uses, with [`WriteKind::Directory`] so it
/// applies `mkdir`'s rule rather than `upload`'s: a fold-colliding **directory** is a no-op success
/// ([`MkdirOutcome::AlreadyExists`]) regardless of `can_delete` (creating a directory that already
/// exists destroys nothing, so there is nothing for `delete` to gate), while a fold-colliding
/// **file** is always refused ([`MkdirOutcome::Refused`]) regardless of `can_delete` too (there is
/// no atomic "overwrite a file with a directory" operation, and `remove` + `create_dir` would
/// destroy the file's contents for an operation nobody asked to be destructive). Keeping this
/// decision inside `write_is_authorized` — rather than re-deriving it here from `WriteTarget`'s
/// variants — is what keeps `upload` and `mkdir` from re-stating (and risking drift on) the same
/// type-mismatch-is-always-refused rule; see that function's doc comment.
pub fn create_dir_confined(
    dir: &Dir,
    relative: &str,
    can_upload: bool,
    can_delete: bool,
) -> Result<MkdirOutcome, ConfineError> {
    let target = upload_target_path(relative)?;
    let (parent, name) = split_parent_and_name(&target);
    let parent_dir;
    let parent_ref: &Dir = if parent.as_os_str().is_empty() {
        dir
    } else {
        parent_dir = dir
            .open_dir(&parent)
            .map_err(|e| ConfineError::io(relative, e))?;
        &parent_dir
    };
    match super::upload::write_is_authorized(
        parent_ref,
        &name,
        WriteKind::Directory,
        can_upload,
        can_delete,
    )? {
        WriteTarget::Fresh => {}
        WriteTarget::AlreadyExists => return Ok(MkdirOutcome::AlreadyExists),
        // `Denied`: no `can_upload`. `TypeMismatch`: collided with a file. `Overwrites(_)` never
        // occurs for `WriteKind::Directory` (it's `write_is_authorized`'s `WriteKind::File`-only
        // outcome), listed here only so this match stays exhaustive against future `WriteTarget`
        // variants; refusing is the safe fallback.
        WriteTarget::Denied | WriteTarget::TypeMismatch | WriteTarget::Overwrites(_) => {
            return Ok(MkdirOutcome::Refused)
        }
    }
    dir.create_dir(&target)
        .map_err(|e| ConfineError::io(relative, e))?;
    Ok(MkdirOutcome::Created)
}

/// Deletes the file or directory at `relative` (DESIGN.md §A8 `delete`). Path-validated the same
/// way as [`create_dir_confined`]. A directory is removed recursively
/// (`Dir::remove_dir_all`) — DESIGN.md does not specify recursive-vs-empty-only delete semantics
/// for a directory target; recursive is this implementation's choice (documented per the task
/// brief), matching the ordinary expectation of a "delete this folder" file-manager action rather
/// than requiring the caller to empty it first.
pub fn remove_confined(dir: &Dir, relative: &str) -> Result<(), ConfineError> {
    let target = upload_target_path(relative)?;
    let meta = stat_through_dir(dir, relative)?;
    if meta.is_dir() {
        dir.remove_dir_all(&target)
            .map_err(|e| ConfineError::io(relative, e))
    } else {
        dir.remove_file(&target)
            .map_err(|e| ConfineError::io(relative, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confine::open_share_root;
    use tempfile::tempdir;

    #[test]
    fn list_dir_lists_root_and_nested() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        std::fs::write(root.join("a.txt"), b"a").expect("write a");
        std::fs::create_dir(root.join("sub")).expect("mkdir sub");
        std::fs::write(root.join("sub/b.txt"), b"bb").expect("write b");

        let dir = open_share_root(&root).expect("open");

        let mut top = list_dir(&dir, "").expect("list root");
        top.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].name, "a.txt");
        assert_eq!(top[0].kind, RealEntryKind::File);
        assert_eq!(top[0].size, 1);
        assert_eq!(top[1].name, "sub");
        assert_eq!(top[1].kind, RealEntryKind::Dir);

        let nested = list_dir(&dir, "sub").expect("list sub");
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].name, "b.txt");
        assert_eq!(nested[0].size, 2);
    }

    #[test]
    fn list_dir_never_shows_staging_files() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        std::fs::write(root.join("a.txt"), b"a").expect("write a");
        let staging = super::super::upload::staging_name(&[0x01, 0x02, 0x03]);
        std::fs::write(root.join(&staging), b"partial-upload-bytes").expect("write staging file");

        let dir = open_share_root(&root).expect("open");
        let entries = list_dir(&dir, "").expect("list root");

        assert_eq!(entries.len(), 1, "the staging file must never be listed");
        assert_eq!(entries[0].name, "a.txt");
    }

    #[test]
    fn create_dir_confined_respects_upload_and_delete_gates() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        let dir = open_share_root(&root).expect("open");

        // No upload perm: refused, nothing created.
        assert_eq!(
            create_dir_confined(&dir, "NewAlbum", false, false).expect("check"),
            MkdirOutcome::Refused
        );
        assert!(!root.join("NewAlbum").exists());

        // Upload perm, new name: created.
        assert_eq!(
            create_dir_confined(&dir, "NewAlbum", true, false).expect("check"),
            MkdirOutcome::Created
        );
        assert!(root.join("NewAlbum").is_dir());

        // mkdir over an existing DIRECTORY (td-789f11): no-op success, no delete needed.
        assert_eq!(
            create_dir_confined(&dir, "NewAlbum", true, false).expect("check"),
            MkdirOutcome::AlreadyExists
        );

        // Traversal attempt rejected outright.
        let err = create_dir_confined(&dir, "../escape", true, true).unwrap_err();
        assert!(matches!(err, ConfineError::UnsafeUploadPath(_)));
    }

    /// td-789f11, NEW behavior 3: `mkdir` whose name fold-collides with an existing **directory**
    /// (via an accent/no-accent spelling difference `fold_key` folds but no OS-level case/Unicode
    /// normalization does — see `resolve.rs`'s test module for why this is the technique that
    /// actually proves the fold-scan path runs, rather than the OS's own folding papering over a
    /// pure case difference) succeeds as a no-op, and afterwards there is exactly one dirent,
    /// spelled as the pre-existing one.
    #[test]
    fn mkdir_onto_existing_directory_is_no_op_success_with_one_surviving_dirent() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        let nfc = "caf\u{00E9}"; // precomposed "café"
        let nfd = "cafe\u{0301}"; // decomposed "café": e + combining acute accent
        std::fs::create_dir(root.join(nfc)).expect("seed existing directory");
        let dir = open_share_root(&root).expect("open");

        assert_eq!(
            create_dir_confined(&dir, nfd, true, false).expect("check"),
            MkdirOutcome::AlreadyExists,
            "a fold-colliding mkdir must be a no-op success, not an error or a second dirent"
        );
        assert_eq!(
            create_dir_confined(&dir, nfd, true, true).expect("check"),
            MkdirOutcome::AlreadyExists,
            "can_delete must not change this outcome — nothing needs deleting"
        );

        let entries: Vec<_> = std::fs::read_dir(&root)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from(nfc)],
            "exactly one dirent must remain, spelled as the pre-existing one"
        );
    }

    /// td-789f11, NEW behavior 4: `mkdir` whose name fold-collides with an existing **file** is
    /// refused, and the file is left completely untouched.
    #[test]
    fn mkdir_onto_existing_file_is_refused_and_file_untouched() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        let nfc = "caf\u{00E9}.txt";
        let nfd = "cafe\u{0301}.txt";
        std::fs::write(root.join(nfc), b"original-contents").expect("seed existing file");
        let dir = open_share_root(&root).expect("open");

        assert_eq!(
            create_dir_confined(&dir, nfd, true, false).expect("check"),
            MkdirOutcome::Refused
        );
        assert_eq!(
            create_dir_confined(&dir, nfd, true, true).expect("check"),
            MkdirOutcome::Refused,
            "can_delete must not turn this into an overwrite — mkdir never replaces a file"
        );

        assert!(root.join(nfc).is_file(), "the existing file must survive");
        assert_eq!(
            std::fs::read(root.join(nfc)).expect("read"),
            b"original-contents",
            "the existing file's contents must be completely unchanged"
        );
    }

    #[test]
    fn remove_confined_deletes_file_and_dir_recursively() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        std::fs::write(root.join("f.txt"), b"x").expect("write f");
        std::fs::create_dir_all(root.join("d/nested")).expect("mkdir nested");
        std::fs::write(root.join("d/nested/g.txt"), b"y").expect("write g");

        let dir = open_share_root(&root).expect("open");

        remove_confined(&dir, "f.txt").expect("remove file");
        assert!(!root.join("f.txt").exists());

        remove_confined(&dir, "d").expect("remove dir recursively");
        assert!(!root.join("d").exists());

        let err = remove_confined(&dir, "../escape").unwrap_err();
        assert!(matches!(err, ConfineError::UnsafeUploadPath(_)));
    }
}
