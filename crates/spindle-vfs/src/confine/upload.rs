//! Upload-relative path scoping and overwrite-requires-`delete` gating (DESIGN.md §A4b: "uploads
//! land only under the granted subpath ... and never overwrite without `delete`"). Closes A12
//! #23 (upload outside granted subpath / overwrite) and, via [`write_is_authorized`]'s use of
//! `crate::confine::fold`, A12 #31 (case/NFD upload collision overwrites without `delete`).

use super::fold::existing_entry_colliding;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confine::open_share_root;
    use tempfile::tempdir;

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
