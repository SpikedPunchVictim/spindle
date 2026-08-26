//! Upload-relative path scoping and overwrite-requires-`delete` gating (DESIGN.md §A4b: "uploads
//! land only under the granted subpath ... and never overwrite without `delete`"). Closes A12
//! #23 (upload outside granted subpath / overwrite) and, via [`write_is_authorized`]'s use of
//! `crate::confine::fold`, A12 #31 (case/NFD upload collision overwrites without `delete`).

use super::fold::existing_entry_colliding;
use super::listing::split_parent_and_name;
use super::ConfineError;
use cap_std::fs::Dir;
use std::path::{Path, PathBuf};

/// Resolves an upload-relative path to a path guaranteed to stay under the caller's granted
/// subdirectory: every component must be a plain (`Normal`) path segment — any `..`, absolute
/// root, Windows prefix, or even `.` component is rejected outright (fail closed rather than try
/// to prove a `..`-laden path nets to something safe).
pub fn upload_target_path(relative: &str) -> Result<PathBuf, ConfineError> {
    let mut resolved = PathBuf::new();
    for component in Path::new(relative).components() {
        match component {
            std::path::Component::Normal(part) => resolved.push(part),
            _ => return Err(ConfineError::UnsafeUploadPath(relative.to_string())),
        }
    }
    if resolved.as_os_str().is_empty() {
        Err(ConfineError::UnsafeUploadPath(relative.to_string()))
    } else {
        Ok(resolved)
    }
}

/// The fixed prefix every upload-session staging file's real (hidden) name starts with —
/// DESIGN.md §A8 "transfer manager": staging names are "hidden" and "never listed". A leading
/// `.` additionally matches this crate's existing `show_hidden`-independent posture that VFS RPC
/// listing never has a reason to expose host-internal bookkeeping files, regardless of a share's
/// `show_hidden` flag (staging files are not part of the *virtual* tree at all, so that flag,
/// which governs whether dotfiles a member actually placed are shown, does not apply to them).
const STAGING_NAME_PREFIX: &str = ".spindle-upload-";

/// The real (hidden) filename an in-progress upload session's staged bytes are written under,
/// inside the share's real root — DESIGN.md §A8: "staging files use a hidden name never listed
/// and counted against quota". Derived from the session id so two concurrent sessions never
/// collide and a session's staging file can be found again by id alone (no other session state
/// needs to be consulted to know where its bytes live).
pub fn staging_name(session_id: &[u8]) -> String {
    let mut hex = String::with_capacity(STAGING_NAME_PREFIX.len() + session_id.len() * 2);
    hex.push_str(STAGING_NAME_PREFIX);
    for b in session_id {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// True if `name` is a hidden upload-staging filename ([`staging_name`]'s output shape) that must
/// never appear in a `list` reply (DESIGN.md §A8: "never listed") regardless of which directory is
/// being listed or the share's `show_hidden` flag.
pub fn is_staging_name(name: &str) -> bool {
    name.starts_with(STAGING_NAME_PREFIX)
}

/// DESIGN.md §A4b entitlement rule: overwriting an existing entry (including one only reachable
/// via a case/Unicode-folding collision, per [`existing_entry_colliding`]) requires `delete`;
/// `upload` alone only ever creates a genuinely new dirent.
pub fn write_is_authorized(
    dir: &Dir,
    candidate_name: &str,
    can_upload: bool,
    can_delete: bool,
) -> Result<bool, ConfineError> {
    if !can_upload {
        return Ok(false);
    }
    Ok(match existing_entry_colliding(dir, candidate_name)? {
        Some(_) => can_delete,
        None => true,
    })
}

/// Moves a completed upload session's staged bytes (at `staging_name`, directly under `dir` —
/// DESIGN.md §A8 transfer manager: staging files live in the target share dir) into place at
/// `target_relative`, applying the same overwrite-requires-`delete` collision gate
/// [`write_is_authorized`] enforces for a fresh upload (DESIGN.md §A4b: "collision == overwrite").
/// The caller (`spindle-host-core`) is responsible for everything that must happen *before* this
/// is called: manifest-signature verification, whole-file hash check, quota/free-space checks,
/// and confirming `can_upload` — this function only re-derives the target path and performs the
/// final collision check + atomic same-filesystem rename, mirroring [`super::listing::create_dir_confined`]'s
/// parent/name-splitting so a nested target (`"Vacation/photo.jpg"`) is collision-checked against
/// its own parent directory's entries, not `dir`'s root. Returns `Ok(false)` (nothing moved) on a
/// collision without `delete`, exactly like [`super::listing::create_dir_confined`]'s `mkdir`
/// analogue.
pub fn finalize_upload(
    dir: &Dir,
    staging_name: &str,
    target_relative: &str,
    can_delete: bool,
) -> Result<bool, ConfineError> {
    let target = upload_target_path(target_relative)?;
    let (parent, name) = split_parent_and_name(&target);
    let parent_dir;
    let parent_ref: &Dir = if parent.as_os_str().is_empty() {
        dir
    } else {
        parent_dir = dir
            .open_dir(&parent)
            .map_err(|e| ConfineError::io(target_relative, e))?;
        &parent_dir
    };
    if !write_is_authorized(parent_ref, &name, true, can_delete)? {
        return Ok(false);
    }
    dir.rename(staging_name, parent_ref, &name)
        .map_err(|e| ConfineError::io(target_relative, e))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confine::open_share_root;
    use tempfile::tempdir;

    #[test]
    fn finalize_upload_moves_staged_file_into_place() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("mkdir root");
        let dir = open_share_root(&root).expect("open");
        let staging = staging_name(&[1, 2, 3]);
        dir.write(&staging, b"upload-bytes").expect("write staging");

        assert!(finalize_upload(&dir, &staging, "incoming.bin", false).expect("finalize"));
        assert!(!root.join(&staging).exists(), "staging file must be gone");
        assert_eq!(
            std::fs::read(root.join("incoming.bin")).expect("read final"),
            b"upload-bytes"
        );
    }

    #[test]
    fn finalize_upload_into_nested_target_checks_parent_dir_collisions() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir_all(root.join("Vacation")).expect("mkdir nested");
        std::fs::write(root.join("Vacation/photo.jpg"), b"existing").expect("seed existing");
        let dir = open_share_root(&root).expect("open");
        let staging = staging_name(&[9]);
        dir.write(&staging, b"new-bytes").expect("write staging");

        // Collision in the nested parent dir, no delete: refused, staging survives untouched.
        assert!(!finalize_upload(&dir, &staging, "Vacation/photo.jpg", false).expect("finalize"));
        assert!(root.join(&staging).exists());
        assert_eq!(
            std::fs::read(root.join("Vacation/photo.jpg")).expect("read"),
            b"existing"
        );

        // With delete: overwrite succeeds.
        assert!(finalize_upload(&dir, &staging, "Vacation/photo.jpg", true).expect("finalize"));
        assert_eq!(
            std::fs::read(root.join("Vacation/photo.jpg")).expect("read"),
            b"new-bytes"
        );
    }

    #[test]
    fn upload_outside_subpath_blocked() {
        assert_eq!(
            upload_target_path("photo.jpg").unwrap(),
            PathBuf::from("photo.jpg")
        );
        assert_eq!(
            upload_target_path("album/photo.jpg").unwrap(),
            PathBuf::from("album/photo.jpg")
        );

        for malicious in [
            "../escape.txt",
            "../../etc/passwd",
            "/etc/passwd",
            "album/../../escape.txt",
            "./photo.jpg",
            "",
        ] {
            assert!(
                matches!(
                    upload_target_path(malicious),
                    Err(ConfineError::UnsafeUploadPath(_))
                ),
                "upload_target_path must reject {malicious:?}"
            );
        }

        // End-to-end: the rejection happens before any filesystem write, and a legitimate path
        // really does land under the granted subdirectory via the Dir capability.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        let granted = root.join("granted-subdir");
        std::fs::create_dir_all(&granted).expect("create granted subdir");
        let dir = open_share_root(&granted).expect("open granted subdir as its own capability");

        let safe = upload_target_path("photo.jpg").expect("legitimate relative path");
        dir.write(&safe, b"upload-bytes").expect("write via Dir");
        assert!(granted.join("photo.jpg").exists());

        assert!(
            upload_target_path("../escape.txt").is_err(),
            "a malicious upload path must never be handed to Dir::write at all"
        );
    }

    #[test]
    fn staging_name_is_hidden_and_stable() {
        let id = [0x01u8, 0x02, 0xab, 0xff];
        let name = staging_name(&id);
        assert_eq!(name, ".spindle-upload-0102abff");
        assert!(is_staging_name(&name));
        assert!(!is_staging_name("photo.jpg"));
        assert!(!is_staging_name(".hidden-but-not-staging"));
        // Deterministic: same id always yields the same name (so a session's staging file can be
        // found again by id alone).
        assert_eq!(staging_name(&id), name);
        // Distinct ids never collide.
        assert_ne!(staging_name(&id), staging_name(&[0x01, 0x02, 0xab, 0xfe]));
    }

    #[test]
    fn overwrite_requires_delete() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");
        dir.write("Photo.JPG", b"existing")
            .expect("seed existing entry");

        assert!(!write_is_authorized(&dir, "Photo.JPG", true, false).expect("check"));
        assert!(write_is_authorized(&dir, "Photo.JPG", true, true).expect("check"));
        // Case-fold collision counts as an overwrite too — still needs delete.
        assert!(!write_is_authorized(&dir, "photo.jpg", true, false).expect("check"));
        // A genuinely new name needs only upload.
        assert!(write_is_authorized(&dir, "new-name.jpg", true, false).expect("check"));
        // No upload permission at all: always rejected, regardless of delete or collisions.
        assert!(!write_is_authorized(&dir, "new-name.jpg", false, true).expect("check"));
    }
}
