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
use super::upload::{is_staging_name, upload_target_path};
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

/// Creates a directory at `relative` (DESIGN.md §A8 `mkdir`). `relative` is validated the same
/// way an upload target is ([`upload_target_path`]) — no `..`, no absolute/rooted component, not
/// empty — since `mkdir` is exactly as capable of a path-traversal attempt as `upload` is, and
/// DESIGN.md draws no distinction between the two for path-safety purposes.
///
/// **Design note (interpretation, not explicit in DESIGN.md)**: this crate treats `mkdir`'s
/// permission and overwrite requirements identically to `upload`'s — creating a directory needs
/// `upload`, and creating one whose name collides (including a case/Unicode fold collision) with
/// an existing entry needs `delete` too, via the same [`super::upload::write_is_authorized`] gate
/// a file upload uses. DESIGN.md §A8 lists `mkdir` as one of the six RPC calls but never states
/// which permission bit governs it or whether its overwrite behavior matches `upload`'s; treating
/// directory creation as "just another kind of write" is this implementation's choice, flagged
/// per the task brief rather than resolved silently. The parent directory must already exist
/// (this is `create_dir`, not `create_dir_all` — DESIGN.md's virtual tree has no notion of
/// implicitly creating intermediate directories on `mkdir`).
pub fn create_dir_confined(
    dir: &Dir,
    relative: &str,
    can_upload: bool,
    can_delete: bool,
) -> Result<bool, ConfineError> {
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
    if !super::upload::write_is_authorized(parent_ref, &name, can_upload, can_delete)? {
        return Ok(false);
    }
    dir.create_dir(&target)
        .map_err(|e| ConfineError::io(relative, e))?;
    Ok(true)
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
        assert!(!create_dir_confined(&dir, "NewAlbum", false, false).expect("check"));
        assert!(!root.join("NewAlbum").exists());

        // Upload perm, new name: created.
        assert!(create_dir_confined(&dir, "NewAlbum", true, false).expect("check"));
        assert!(root.join("NewAlbum").is_dir());

        // mkdir over an existing name without delete: refused (overwrite-requires-delete).
        assert!(!create_dir_confined(&dir, "NewAlbum", true, false).expect("check"));

        // Traversal attempt rejected outright.
        let err = create_dir_confined(&dir, "../escape", true, true).unwrap_err();
        assert!(matches!(err, ConfineError::UnsafeUploadPath(_)));
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
