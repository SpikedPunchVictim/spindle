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

/// The result of the overwrite-requires-`delete` collision gate ([`write_is_authorized`]) for a
/// candidate write target name. Distinguishes "authorized, nothing existing is touched" from
/// "authorized, but an existing dirent will be replaced" — and in the latter case carries that
/// dirent's *actual* on-disk name, because on a filesystem that does not fold case/Unicode
/// variants itself (Linux), that name can differ from `candidate_name`. A caller that authorizes
/// a write and then throws this name away (writing to `candidate_name` instead) reopens exactly
/// the collision this check exists to close: see [`finalize_upload`]'s doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteTarget {
    /// `can_upload` is false, or a colliding entry exists and `can_delete` is false.
    Denied,
    /// No existing entry collides (by fold key, [`crate::confine::fold::fold_key`]) with the
    /// candidate name: a write may proceed and should land under the requested spelling.
    Fresh,
    /// A colliding entry already exists under this on-disk name and `can_delete` is set: a write
    /// may proceed, but must land under *this* name — see [`finalize_upload`].
    Overwrites(std::ffi::OsString),
}

/// The outcome of [`finalize_upload`]: either the staged file landed on disk (carrying the name
/// it actually landed under), or the write was refused by the overwrite-requires-`delete` gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadOutcome {
    /// The staged file was renamed into place. Carries the name it actually landed under,
    /// which is the pre-existing dirent's spelling when the requested name fold-collided
    /// with one, and the requested spelling otherwise.
    Landed(std::ffi::OsString),
    /// Refused: the requested name fold-collides with an existing entry and the caller
    /// lacks `delete`. The staged file is left in place so the caller can retry.
    Refused,
}

/// DESIGN.md §A4b entitlement rule: overwriting an existing entry (including one only reachable
/// via a case/Unicode-folding collision, per [`existing_entry_colliding`]) requires `delete`;
/// `upload` alone only ever creates a genuinely new dirent.
pub fn write_is_authorized(
    dir: &Dir,
    candidate_name: &str,
    can_upload: bool,
    can_delete: bool,
) -> Result<WriteTarget, ConfineError> {
    if !can_upload {
        return Ok(WriteTarget::Denied);
    }
    Ok(match existing_entry_colliding(dir, candidate_name)? {
        Some(existing_name) => {
            if can_delete {
                WriteTarget::Overwrites(existing_name)
            } else {
                WriteTarget::Denied
            }
        }
        None => WriteTarget::Fresh,
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
/// its own parent directory's entries, not `dir`'s root. Returns [`UploadOutcome::Refused`]
/// (nothing moved) on a collision without `delete`, exactly like
/// [`super::listing::create_dir_confined`]'s `mkdir` analogue.
///
/// **The staged file lands on the *existing* entry's name, not the requested spelling, when this
/// is an overwrite** (DESIGN.md :370-371: a case/Unicode-fold collision with an existing dirent
/// **is** an overwrite of that dirent). `write_is_authorized` already returns that dirent's real
/// on-disk name ([`WriteTarget::Overwrites`]) precisely so this function does not have to guess
/// it, and renaming onto it — rather than removing the colliding entry and renaming to the
/// requested spelling — is deliberate for two reasons:
/// 1. **Atomicity.** `Dir::rename` onto an existing name is a single syscall that atomically
///    replaces the file's contents. Remove-then-rename has a window where neither the old nor the
///    new file exists; a crash there loses bytes the user still had a moment before.
/// 2. **It matches native behavior.** A case-insensitive filesystem (macOS, Windows) already
///    preserves the original dirent's spelling when a write comes in through a case variant.
///    Renaming onto the existing name makes Linux (which does not fold these names itself) behave
///    the same way, rather than inventing a third, platform-specific behavior.
///
/// The visible consequence is that the uploader's chosen spelling is silently not honored once it
/// collides — that is the intended reading of "collision is an overwrite", not a bug.
///
/// **The caller must record the name carried by [`UploadOutcome::Landed`], not the name it
/// requested, in anything that later resolves this file on disk.** Recording the requested
/// spelling instead is a bug: on a fold collision, this function renames onto the *existing*
/// dirent's name (see above), so a caller that persists the requested spelling stores a path that
/// does not exist on a case-sensitive filesystem — nothing will ever stat it back.
pub fn finalize_upload(
    dir: &Dir,
    staging_name: &str,
    target_relative: &str,
    can_delete: bool,
) -> Result<UploadOutcome, ConfineError> {
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
    let write_target_name: std::ffi::OsString =
        match write_is_authorized(parent_ref, &name, true, can_delete)? {
            WriteTarget::Denied => return Ok(UploadOutcome::Refused),
            WriteTarget::Fresh => std::ffi::OsString::from(name),
            WriteTarget::Overwrites(existing_name) => existing_name,
        };
    dir.rename(staging_name, parent_ref, &write_target_name)
        .map_err(|e| ConfineError::io(target_relative, e))?;
    Ok(UploadOutcome::Landed(write_target_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confine::fold::names_collide;
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

        assert_eq!(
            finalize_upload(&dir, &staging, "incoming.bin", false).expect("finalize"),
            UploadOutcome::Landed(std::ffi::OsString::from("incoming.bin"))
        );
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
        assert_eq!(
            finalize_upload(&dir, &staging, "Vacation/photo.jpg", false).expect("finalize"),
            UploadOutcome::Refused
        );
        assert!(root.join(&staging).exists());
        assert_eq!(
            std::fs::read(root.join("Vacation/photo.jpg")).expect("read"),
            b"existing"
        );

        // With delete: overwrite succeeds.
        assert_eq!(
            finalize_upload(&dir, &staging, "Vacation/photo.jpg", true).expect("finalize"),
            UploadOutcome::Landed(std::ffi::OsString::from("photo.jpg"))
        );
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

        assert_eq!(
            write_is_authorized(&dir, "Photo.JPG", true, false).expect("check"),
            WriteTarget::Denied
        );
        assert_eq!(
            write_is_authorized(&dir, "Photo.JPG", true, true).expect("check"),
            WriteTarget::Overwrites(std::ffi::OsString::from("Photo.JPG"))
        );
        // Case-fold collision counts as an overwrite too — still needs delete.
        assert_eq!(
            write_is_authorized(&dir, "photo.jpg", true, false).expect("check"),
            WriteTarget::Denied
        );
        // ...and when authorized, surfaces the *existing* dirent's spelling, not the candidate's.
        assert_eq!(
            write_is_authorized(&dir, "photo.jpg", true, true).expect("check"),
            WriteTarget::Overwrites(std::ffi::OsString::from("Photo.JPG"))
        );
        // A genuinely new name needs only upload.
        assert_eq!(
            write_is_authorized(&dir, "new-name.jpg", true, false).expect("check"),
            WriteTarget::Fresh
        );
        // No upload permission at all: always rejected, regardless of delete or collisions.
        assert_eq!(
            write_is_authorized(&dir, "new-name.jpg", false, true).expect("check"),
            WriteTarget::Denied
        );
    }

    /// The core fix for td-48fb1d: on a filesystem that does not fold case variants itself
    /// (Linux; macOS folds them natively so this assertion is what actually distinguishes the
    /// fixed behavior there too — see the dirent-count comment below), uploading `photo.jpg` when
    /// `Photo.JPG` already exists must replace that file, not create a second, distinctly-spelled
    /// one. Before the fix, `finalize_upload` authorized the write via the collision check but
    /// then renamed onto the *requested* spelling, so `rename` created a brand new dirent next to
    /// the untouched original — asserting only "`Photo.JPG` still exists" would not have caught
    /// that, hence asserting on the directory's total entry count here.
    #[test]
    fn finalize_upload_case_collision_overwrites_existing_dirent_not_requested_spelling() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");
        dir.write("Photo.JPG", b"original-bytes")
            .expect("seed existing entry");

        let staging = staging_name(&[0xaa]);
        dir.write(&staging, b"uploaded-bytes")
            .expect("write staging");

        assert_eq!(
            finalize_upload(&dir, &staging, "photo.jpg", true).expect("finalize"),
            UploadOutcome::Landed(std::ffi::OsString::from("Photo.JPG"))
        );

        let entries: Vec<_> = std::fs::read_dir(&root)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            entries,
            vec!["Photo.JPG".to_string()],
            "exactly one entry must remain, spelled as the pre-existing dirent was"
        );
        assert_eq!(
            std::fs::read(root.join("Photo.JPG")).expect("read final"),
            b"uploaded-bytes",
            "the surviving dirent's contents must be the newly uploaded bytes"
        );
    }

    /// The NFC/NFD equivalent of the case-collision fix above: a precomposed "café" (é as a
    /// single U+00E9 code point) and its decomposed spelling ("cafe" + combining U+0301) must
    /// fold equal and finalize onto the pre-existing dirent's spelling.
    ///
    /// **Platform caveat, confirmed by two independent reviewers**: the filesystem-level
    /// assertions below (`entries.len() == 1`, the surviving dirent keeping the NFC spelling)
    /// cannot fail on macOS. APFS is normalization-insensitive even on a volume created
    /// case-sensitive — the two byte sequences resolve to *one* dirent at the filesystem layer
    /// regardless of whether `finalize_upload`'s fold-key fix is present, verified empirically on
    /// a case-sensitive APFS image. So on macOS this test is intent-locking only: it documents
    /// the desired behavior but cannot distinguish "the fix works" from "the filesystem already
    /// made this a non-issue". Real evidence that the fix does something requires a filesystem
    /// that stores names as opaque bytes and would otherwise keep both spellings as separate
    /// dirents — ext4 / Linux CI. The `names_collide(nfc, nfd)` sanity assertion just below DOES
    /// prove the fold-key half of this fix on every platform; it is only the filesystem-plumbing
    /// half (finalize actually overwriting rather than creating a second dirent) that stays
    /// unproven here on macOS.
    ///
    /// Updated when `finalize_upload` grew [`UploadOutcome`]: the `assert_eq!` on the returned
    /// `Landed(nfc)` below IS platform-independent — it checks which name this function *chose*,
    /// which no filesystem can paper over — so that assertion is load-bearing on macOS too
    /// (verified by neutering: returning the requested name instead fails this test here). What
    /// remains macOS-unprovable is only the `entries.len() == 1` disk check further down.
    #[test]
    fn finalize_upload_nfd_collision_overwrites_existing_dirent_not_requested_spelling() {
        let nfc = "caf\u{00E9}.txt"; // precomposed é (U+00E9)
        let nfd = "cafe\u{0301}.txt"; // decomposed: e (U+0065) + combining acute accent (U+0301)
        assert_ne!(
            nfc, nfd,
            "sanity: the two byte-level spellings must actually differ"
        );
        assert!(
            names_collide(nfc, nfd),
            "sanity: our fold key must treat NFC and NFD \"café\" as the same name before we \
             rely on that below"
        );

        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");
        dir.write(nfc, b"original-bytes")
            .expect("seed existing NFC-named entry");

        let staging = staging_name(&[0xbb]);
        dir.write(&staging, b"uploaded-bytes")
            .expect("write staging");

        assert_eq!(
            finalize_upload(&dir, &staging, nfd, true).expect("finalize"),
            UploadOutcome::Landed(std::ffi::OsString::from(nfc))
        );

        let entries: Vec<_> = std::fs::read_dir(&root)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(entries.len(), 1, "exactly one entry must remain");
        assert_eq!(
            entries[0],
            std::ffi::OsString::from(nfc),
            "the surviving dirent must keep the pre-existing (NFC) spelling"
        );
        assert_eq!(
            std::fs::read(root.join(nfc)).expect("read final"),
            b"uploaded-bytes",
            "the surviving dirent's contents must be the newly uploaded bytes"
        );
    }

    /// No regression for the common path: a genuinely fresh name still lands under the spelling
    /// the uploader requested.
    #[test]
    fn finalize_upload_fresh_name_lands_under_requested_spelling() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");

        let staging = staging_name(&[0xcc]);
        dir.write(&staging, b"uploaded-bytes")
            .expect("write staging");

        assert_eq!(
            finalize_upload(&dir, &staging, "NewFile.txt", false).expect("finalize"),
            UploadOutcome::Landed(std::ffi::OsString::from("NewFile.txt"))
        );
        assert!(root.join("NewFile.txt").exists());
        assert_eq!(
            std::fs::read(root.join("NewFile.txt")).expect("read final"),
            b"uploaded-bytes"
        );
    }

    /// The permission gate must not weaken: a colliding entry without `can_delete` still refuses
    /// the write and leaves the existing file completely untouched.
    #[test]
    fn finalize_upload_case_collision_without_delete_is_refused_and_existing_file_untouched() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");
        dir.write("Photo.JPG", b"original-bytes")
            .expect("seed existing entry");

        let staging = staging_name(&[0xdd]);
        dir.write(&staging, b"uploaded-bytes")
            .expect("write staging");

        assert_eq!(
            finalize_upload(&dir, &staging, "photo.jpg", false).expect("finalize"),
            UploadOutcome::Refused
        );

        let entries: Vec<_> = std::fs::read_dir(&root)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        let mut sorted = entries.clone();
        sorted.sort();
        assert_eq!(
            sorted,
            vec![staging.clone(), "Photo.JPG".to_string()],
            "the existing entry and the still-pending staging file must both remain untouched"
        );
        assert_eq!(
            std::fs::read(root.join("Photo.JPG")).expect("read"),
            b"original-bytes",
            "the existing file's contents must be untouched"
        );
    }

    /// Proves the return value itself — not disk state — carries the pre-existing dirent's
    /// spelling on a fold-collision overwrite. This is the one assertion that can actually catch
    /// a caller-facing regression: this machine is macOS/APFS, which is case-insensitive and
    /// whose `rename(2)` preserves the pre-existing dirent's case regardless of what
    /// `finalize_upload` returns, so a disk-based assertion (reading back the directory entry's
    /// name, as other tests in this file do) would pass whether or not `finalize_upload` reports
    /// the landed name correctly — it would even pass if `finalize_upload` returned the
    /// *requested* spelling by mistake. The `UploadOutcome` value under test here is what the
    /// `spindle-host-core` caller actually consumes (to decide what to persist in the upload
    /// ledger, DESIGN.md's `uploaded_files.subpath`), and it is platform-independent: asserting on
    /// it is the only way this test can fail when the fix regresses.
    #[test]
    fn finalize_upload_returned_outcome_carries_existing_dirent_spelling_not_requested() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");
        dir.write("Photo.JPG", b"original-bytes")
            .expect("seed existing entry");

        let staging = staging_name(&[0xee]);
        dir.write(&staging, b"uploaded-bytes")
            .expect("write staging");

        let outcome =
            finalize_upload(&dir, &staging, "photo.jpg", true).expect("finalize should land");
        assert_eq!(
            outcome,
            UploadOutcome::Landed(std::ffi::OsString::from("Photo.JPG")),
            "the landed name must be the pre-existing dirent's spelling, not the requested one"
        );
    }
}
