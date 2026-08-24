//! Path confinement, graduated from spike S11 (`spikes/s11-vfs-confinement`) to production
//! quality (DESIGN.md §A4b "Path confinement"; ADR-006). Every share root is opened as a
//! `cap-std` `Dir`; all I/O goes through the returned capability, so `..` traversal, symlink
//! escape, and absolute-path tricks are excluded **by construction** — closes A12 #19 (VFS
//! escape). Everything else §A4b requires — the hardlink-bypass guard, overlapping-root
//! rejection, case/Unicode folding, upload-subpath scoping + overwrite gating, and TOCTOU/rename
//! -race identity checks — is **not** provided by `cap-std` and is implemented in this module
//! tree, exactly as prototyped and proven by S11's negative-test suite
//! (`spikes/s11-vfs-confinement/RESULTS.md`: 12/12 non-Windows cases passing on macOS, 4
//! Windows-only cases real-bodied but compile-gated). This slice preserves the spike's tested
//! semantics exactly; see each submodule's doc comments for the specific A12 red-team row(s) it
//! closes.
//!
//! # Module map
//! - [`identity`] — file identity (dev+ino / file-id), the hardlink-bypass `nlink` guard, and the
//!   TOCTOU/rename-race per-chunk identity check (A12 #29, #30).
//! - [`overlap`] — overlapping share-root rejection by resolved real path *and* identity (A12
//!   #29).
//! - [`fold`] — case/Unicode fold-key comparison and collision detection against existing dirents
//!   (A12 #20, #31).
//! - [`upload`] — upload-relative path scoping and overwrite-requires-`delete` gating (A12 #23,
//!   #31).
//! - [`windows`] — Windows-only attack surface (reserved device names, ADS, `\\?\` paths); real
//!   bodies, `#[cfg(windows)]`-gated items (A12 #19, Windows-specific S11 cases 11-14).

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use std::io;
use std::path::Path;
use thiserror::Error;

pub mod fold;
pub mod identity;
pub mod overlap;
pub mod upload;
pub mod windows;

pub use fold::{existing_entry_colliding, fold_key, names_collide};
pub use identity::{
    file_identity, identity_of_ambient_path, nlink_guard, read_confined_with_identity_check,
    resolve_identity, stat_through_dir, FileIdentity,
};
pub use overlap::overlap_check;
pub use upload::{upload_target_path, write_is_authorized};

/// Errors from the confinement layer. Each variant's doc comment on its emitting function names
/// the DESIGN.md §A4b rule and A12 red-team row it is part of closing.
#[derive(Debug, Error)]
pub enum ConfineError {
    /// An OS-level filesystem operation failed — missing path, permission denied, not a
    /// directory, or (per `cap-std`'s own confinement) a resolved target outside the share root.
    #[error("path operation failed for {path:?}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },

    /// A file's identity, re-checked at a chunk boundary, no longer matches the identity captured
    /// before the transfer began — DESIGN.md §A4b: "file identity is checked between `stat` and
    /// `read`/`upload` and on every chunk boundary, aborting on change." Closes A12 #30
    /// (TOCTOU/rename race inside a share).
    #[error(
        "file identity changed mid-transfer for {path:?} at chunk {chunk_index}; aborting \
         (TOCTOU/rename race guard — DESIGN.md §A4b, closes A12 #30)"
    )]
    IdentityChangedMidTransfer { path: String, chunk_index: usize },

    /// An upload-relative path contained a `..`, an absolute/rooted component, a Windows prefix,
    /// a bare `.`, or was empty — rejected before it ever reaches the filesystem. DESIGN.md
    /// §A4b: "uploads land only under the granted subpath." Closes A12 #23 (upload outside
    /// granted subpath).
    #[error(
        "upload path {0:?} is not a safe relative path: contains \"..\", is absolute/rooted, or \
         is empty (DESIGN.md §A4b upload scoping, closes A12 #23)"
    )]
    UnsafeUploadPath(String),
}

impl ConfineError {
    fn io(path: impl Into<String>, source: io::Error) -> Self {
        ConfineError::Io {
            path: path.into(),
            source,
        }
    }
}

/// Opens `path` as a `cap-std` `Dir` share-root capability. This is the one place ambient
/// filesystem authority is used to *establish* a share root; every other operation in this crate
/// goes through the returned `Dir`, never through ambient paths again (DESIGN.md §A4b "Path
/// confinement"; ADR-006; closes A12 #19, VFS escape).
pub fn open_share_root(path: &Path) -> Result<Dir, ConfineError> {
    Dir::open_ambient_dir(path, ambient_authority())
        .map_err(|e| ConfineError::io(path.display().to_string(), e))
}

/// `cap_std::fs::Dir` only exposes a unified `symlink` on Unix; Windows distinguishes file vs.
/// directory symlink targets (`symlink_file`/`symlink_dir`, `#[cfg(windows)]`-gated in `cap-std`
/// itself). Every symlink this test suite creates targets a file, so this helper is a thin,
/// platform-specific shim over whichever `cap-std` method exists on the current target.
#[cfg(test)]
#[cfg(unix)]
fn test_symlink(dir: &Dir, original: &str, link: &str) -> io::Result<()> {
    dir.symlink(original, link)
}

#[cfg(test)]
#[cfg(windows)]
fn test_symlink(dir: &Dir, original: &str, link: &str) -> io::Result<()> {
    dir.symlink_file(original, link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Scaffold check: the crate builds and the test harness runs.
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }

    // ---- Path escape (blocked by cap-std construction; closes A12 #19) ----

    #[test]
    fn dotdot_traversal_blocked() {
        // Attack: a virtual path containing ".." segments tries to reach outside the share root.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let secret = sandbox.path().join("secret.txt");
        std::fs::write(&secret, b"outside-the-share").expect("write secret outside root");

        let dir = open_share_root(&root).expect("open share root");

        let one_up = dir.open("../secret.txt");
        assert!(
            one_up.is_err(),
            "cap-std Dir must refuse a \"..\" path that would leave the share root, got {one_up:?}"
        );

        let deep = dir.open("a/b/../../../secret.txt");
        assert!(
            deep.is_err(),
            "cap-std Dir must refuse a multi-\"..\" path that nets outside the root, got {deep:?}"
        );
    }

    #[test]
    fn absolute_path_blocked() {
        // Attack: an absolute virtual path tries to address the real filesystem root instead of
        // being resolved relative to the share root.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");

        let outside_dir = tempdir().expect("outside tempdir");
        let outside = outside_dir.path().join("canary.txt");
        std::fs::write(&outside, b"real-secret-outside-the-share").expect("write canary");

        let dir = open_share_root(&root).expect("open share root");

        let absolute = outside.to_str().expect("utf8 path");
        let result = dir.open(absolute);
        match result {
            Err(_) => { /* refused outright: confinement holds */ }
            Ok(mut file) => {
                use std::io::Read;
                let mut contents = Vec::new();
                let _ = file.read_to_end(&mut contents);
                assert_ne!(
                    contents, b"real-secret-outside-the-share",
                    "an absolute-looking virtual path must never reach the real file outside the \
                     share root"
                );
            }
        }
    }

    #[test]
    fn symlink_escape_blocked() {
        // Attack: a symlink inside the share points outside the root; reading through it must not
        // follow the link out of the capability.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let outside = sandbox.path().join("outside.txt");
        std::fs::write(&outside, b"outside-content").expect("write outside file");

        let dir = open_share_root(&root).expect("open share root");
        test_symlink(&dir, "../outside.txt", "escape")
            .expect("create symlink pointing outside the root");

        let opened = dir.open("escape");
        assert!(
            opened.is_err(),
            "cap-std Dir must not follow a symlink whose target resolves outside the share root, \
             got {opened:?}"
        );

        let metadata = dir.metadata("escape");
        assert!(
            metadata.is_err(),
            "stat through the escaping symlink must also fail, got {metadata:?}"
        );
    }
}
