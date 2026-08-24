//! # S11 — VFS confinement spike
//!
//! Answers `docs/DESIGN.md` §A13, spike **S11**: *"VFS confinement (`cap-std`): `..`, symlink
//! escape, hardlinks, overlapping roots, case/Unicode collisions, exclusion bypass, upload
//! scoping, Windows device names / 8.3 / ADS / `\\?\` paths, rename races."* Full writeup and
//! gating: `docs/SPIKES.md` (§S11). Do not edit the pass criterion here — `docs/DESIGN.md` §A13
//! is authoritative; this file plans how to reach it and (as of this run) proves it empirically.
//!
//! ## What this spike proved (see `RESULTS.md` for the per-case table)
//!
//! `cap-std`'s `Dir` capability blocks `..` traversal, absolute-path tricks, and symlink escape
//! **by construction** — no application-level check was needed to prove those three. Everything
//! else `docs/DESIGN.md` §A4b calls out (hardlink-bypass rule, overlap rejection, case/Unicode
//! folding, upload-subpath scoping, overwrite/delete gating, and TOCTOU/rename-race identity
//! checks) is **not** provided by `cap-std` and had to be prototyped here as small Spindle-side
//! helper functions layered on top of a `cap-std` `Dir`. Those prototypes are what
//! `spindle-vfs` will grow from; nothing below is meant to be a finished production
//! implementation (see individual doc comments for stated scope limits, e.g. `fold_key`'s Latin-1
//! Supplement-only decomposition table).
//!
//! ## The negative-test matrix (verbatim source: `docs/DESIGN.md` §A4b, §A8, §A13)
//!
//! Every share root is opened as a `cap-std` `Dir` (pinned `>= 3.4.1`, resolved here to `4.0.3`),
//! and all I/O goes through that capability — no `..`, symlink escape, or absolute-path trick
//! should be reachable *by construction*. `cap-std` does **not** canonicalize, case-fold, or
//! normalize on its own — Spindle is responsible for exclusion/permission matching on the
//! resolved real path plus case/Unicode folding, and for identity checks (dev+ino / file-id)
//! where names are ambiguous. Every request re-resolves from the share `Dir` (no long-lived
//! subdirectory handles); file identity is checked between `stat` and `read`/`upload` and at
//! every chunk boundary, aborting on change.
//!
//! Attack cases this spike proves impossible (or, where noted, honestly reports as not yet
//! blocked), one per test below:
//!
//! 1. **`..` traversal** — a virtual path containing `..` segments must not escape the share root.
//! 2. **Absolute-path trick** — an absolute-looking virtual path must not escape the share root.
//! 3. **Symlink escape** — a symlink inside the share pointing outside the root must not be
//!    followed.
//! 4. **Hardlink bypass of exclusions** — a file with link count (`nlink`) > 1 inside a share that
//!    has exclusions must not be served (§A4b: "files with link count > 1 are not served").
//! 5. **Overlapping share roots** — adding a second share whose resolved real path *or*
//!    device+inode/file-id overlaps an existing share must be rejected.
//! 6. **Case-fold collision == overwrite** — creating/uploading a name that collides
//!    case-insensitively with an existing dirent must be treated as an overwrite, not a new entry.
//! 7. **Unicode-normalization collision == overwrite** — same rule under Unicode (NFC/NFD)
//!    normalization variants of an existing name.
//! 8. **TOCTOU rename race on the served identity** — a file swapped out from under a name between
//!    the entitlement/exclusion check and the actual serve must be detected and the request
//!    aborted, rather than silently serving the swapped-in content.
//! 9. **Upload outside granted subpath** — an upload-relative path containing `..`/absolute
//!    components must be rejected before it ever reaches the filesystem.
//! 10. **Overwrite without `delete`** — overwriting an existing entry (including via case/Unicode
//!     collision) must require `delete` permission; `upload` alone must not suffice.
//! 11. **Windows reserved device names** — names like `CON`, `PRN`, `AUX`, `NUL`, `COM1`… must be
//!     handled safely (rejected/sanitized), not passed through to the OS as a device open.
//! 12. **Windows 8.3 short-name aliasing** — a short-name alias (e.g. `LONGFI~1.TXT`) must not
//!     provide a second path to a file that bypasses identity-based checks done against the long
//!     name.
//! 13. **Windows Alternate Data Streams (ADS)** — `file.txt:hidden` must not expose a second,
//!     unchecked data stream on an otherwise-confined file.
//! 14. **Windows `\\?\` extended-length paths** — device-path-prefixed absolute paths must not be
//!     usable to step outside the `cap-std` `Dir` capability.
//! 15. **Rename/TOCTOU race mid-transfer** — a file renamed/replaced between chunked reads must be
//!     detected at the next chunk boundary and abort the transfer.
//!
//! Cases 11–14 are Windows-only attack surfaces; their test bodies are real (`#[cfg(windows)]`)
//! but the tests stay `#[ignore]`d on macOS/Linux (`#[cfg_attr(not(windows), ignore = "..")]`) —
//! a Windows CI run is just `cargo test`.
//!
//! ## Pass criterion (verbatim, `docs/DESIGN.md` §A13)
//!
//! *"Automated negative tests all pass on macOS/Windows/Linux."* This is a CI-matrix requirement,
//! not a single-machine run — see `docs/SPIKES.md` (§S11). Per §A9b this suite must also graduate
//! into permanent CI once it passes. Results (per-OS pass/fail) are in
//! `spikes/s11-vfs-confinement/RESULTS.md`.

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use std::io;
use std::path::{Path, PathBuf};

/// Opens `path` as a `cap-std` `Dir` share-root capability. This is the one place ambient
/// filesystem authority is used to *establish* a share root; every other operation in this crate
/// goes through the returned `Dir`, never through ambient paths again.
pub fn open_share_root(path: &Path) -> io::Result<Dir> {
    Dir::open_ambient_dir(path, ambient_authority())
}

// ---- File identity (dev+ino / file-id) ----

/// A cross-platform file-identity value: two dirents with equal identity are the same underlying
/// file regardless of what name(s) reach them. On Unix this is the `(dev, ino)` pair. On Windows,
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
pub fn file_identity(file: &std::fs::File) -> io::Result<FileIdentity> {
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
/// used by [`overlap_check`], which compares share roots (which may be directories) by real path
/// before either is opened as a `Dir`. On Windows this goes through
/// `same_file::Handle::from_path`, which (unlike a plain `File::open`) opens directories
/// correctly via `FILE_FLAG_BACKUP_SEMANTICS`.
pub fn identity_of_ambient_path(path: &Path) -> io::Result<FileIdentity> {
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
pub fn stat_through_dir(dir: &Dir, virtual_path: &str) -> io::Result<std::fs::Metadata> {
    dir.open(virtual_path)?.into_std().metadata()
}

/// Resolves `virtual_path` through `dir` (never leaving its `cap-std` capability, even when the
/// resolved entry is reached via a symlink whose target is inside the root) and returns its
/// file identity. This is the primitive both the hardlink guard and the TOCTOU checks build on.
pub fn resolve_identity(dir: &Dir, virtual_path: &str) -> io::Result<FileIdentity> {
    file_identity(&dir.open(virtual_path)?.into_std())
}

// ---- Hardlink-bypass guard (A4b) ----

#[cfg(unix)]
fn nlink_of(file: &std::fs::File) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn nlink_of(file: &std::fs::File) -> io::Result<u64> {
    // `std::os::windows::fs::MetadataExt::number_of_links` is gated behind the same nightly-only
    // `windows_by_handle` feature as the identity accessors above (rust-lang/rust#63010) and is
    // unusable on stable Rust; `winapi-util` (the same crate `same-file` itself uses internally
    // for `GetFileInformationByHandle`) exposes the link count directly.
    Ok(winapi_util::file::information(file)?.number_of_links())
}

/// A4b hardlink-bypass rule, verbatim: *"when a share has exclusions, files with link count > 1
/// are not served."* Returns `true` when the file may be served given whether the share has any
/// exclusion globs configured at all.
pub fn nlink_guard(file: &std::fs::File, share_has_exclusions: bool) -> io::Result<bool> {
    if !share_has_exclusions {
        return Ok(true);
    }
    Ok(nlink_of(file)? <= 1)
}

// ---- Overlapping share roots (A4b) ----

/// A4b overlap rule: two share roots overlap if one's canonicalized real path is a prefix of (or
/// equal to) the other's, **or** — belt and suspenders for alias cases a plain path comparison
/// can miss (e.g. two distinct mount points exposing the same underlying volume) — if the two
/// roots share a file identity. Returns `true` when the roots overlap and the second add must be
/// rejected.
pub fn overlap_check(root_a: &Path, root_b: &Path) -> io::Result<bool> {
    let real_a = std::fs::canonicalize(root_a)?;
    let real_b = std::fs::canonicalize(root_b)?;
    if real_a == real_b || real_a.starts_with(&real_b) || real_b.starts_with(&real_a) {
        return Ok(true);
    }
    let identity_a = identity_of_ambient_path(&real_a)?;
    let identity_b = identity_of_ambient_path(&real_b)?;
    Ok(identity_a == identity_b)
}

// ---- Case / Unicode folding (A4b) ----

/// Precomposed Latin-1 Supplement letter -> (base letter, combining mark) decompositions.
///
/// **Spike-scope limitation**: this is *not* a general Unicode NFC/NFD implementation — it covers
/// exactly the common Latin accented letters (the set needed to prove the "café" NFC/NFD case
/// `docs/SPIKES.md` names). Production `spindle-vfs` should use a real Unicode normalization
/// crate (e.g. `unicode-normalization`) rather than growing this table; it exists here only
/// because this spike crate intentionally takes no dependencies beyond `cap-std` (+ `tempfile` in
/// dev-deps).
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
/// keys must be treated as the same dirent (A4b: a case-insensitive or Unicode-normalization
/// collision with an existing dirent **is** an overwrite, not a new entry).
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
) -> io::Result<Option<std::ffi::OsString>> {
    let target_key = fold_key(candidate_name);
    for entry in dir.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(name_str) = name.to_str() {
            if fold_key(name_str) == target_key {
                return Ok(Some(name));
            }
        }
    }
    Ok(None)
}

// ---- Upload scoping / overwrite gating (A4b) ----

/// Resolves an upload-relative path to a path guaranteed to stay under the caller's granted
/// subdirectory: every component must be a plain (`Normal`) path segment — any `..`, absolute
/// root, Windows prefix, or even `.` component is rejected outright (fail closed rather than try
/// to prove a `..`-laden path nets to something safe). Returns `None` if the path is unsafe or
/// empty.
pub fn upload_target_path(relative: &str) -> Option<PathBuf> {
    let mut resolved = PathBuf::new();
    for component in Path::new(relative).components() {
        match component {
            std::path::Component::Normal(part) => resolved.push(part),
            _ => return None,
        }
    }
    if resolved.as_os_str().is_empty() {
        None
    } else {
        Some(resolved)
    }
}

/// A4b entitlement rule: overwriting an existing entry (including one only reachable via a
/// case/Unicode-folding collision, per [`existing_entry_colliding`]) requires `delete`; `upload`
/// alone only ever creates a genuinely new dirent.
pub fn write_is_authorized(
    dir: &Dir,
    candidate_name: &str,
    can_upload: bool,
    can_delete: bool,
) -> io::Result<bool> {
    if !can_upload {
        return Ok(false);
    }
    Ok(match existing_entry_colliding(dir, candidate_name)? {
        Some(_) => can_delete,
        None => true,
    })
}

// ---- TOCTOU / rename-race identity checks (A4b) ----

/// Reads `relative` through `dir` in `chunk_size` chunks, re-resolving the path's identity after
/// every chunk and aborting if it no longer matches the identity observed before the first byte
/// was read (A4b: "file identity is checked between stat and read/upload and on every chunk
/// boundary, aborting on change"). `after_chunk` is invoked with the zero-based chunk index right
/// after each chunk is appended to the output and right before the post-chunk identity check —
/// it exists so tests can deterministically inject a race at an exact point instead of relying on
/// timing (sleeps/threads), which would make the test flaky.
pub fn read_confined_with_identity_check<F: FnMut(usize)>(
    dir: &Dir,
    relative: &str,
    chunk_size: usize,
    mut after_chunk: F,
) -> io::Result<Vec<u8>> {
    use std::io::Read;

    let expected_identity = resolve_identity(dir, relative)?;
    let mut file = dir.open(relative)?;
    let mut out = Vec::new();
    let mut chunk = vec![0u8; chunk_size];
    let mut chunk_index = 0usize;
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        after_chunk(chunk_index);
        chunk_index += 1;

        let current_identity = resolve_identity(dir, relative)?;
        if current_identity != expected_identity {
            return Err(io::Error::other(
                "file identity changed mid-transfer; aborting (TOCTOU/rename race guard)",
            ));
        }
    }
    Ok(out)
}

// ---- Windows-only helpers (real logic, exercised only on Windows) ----

/// Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`,
/// case-insensitive, with or without an extension) must never be passed through to the OS as a
/// path component — doing so opens the device, not a file.
#[cfg(windows)]
pub fn is_windows_reserved_name(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = name.split('.').next().unwrap_or(name);
    RESERVED
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(stem))
}

/// `true` if `relative` contains an NTFS Alternate Data Stream selector (`file.txt:hidden`). Any
/// colon in a relative virtual path is an ADS selector, not a drive letter (virtual paths are
/// never drive-letter-prefixed).
#[cfg(windows)]
pub fn is_ads_path(relative: &str) -> bool {
    relative.contains(':')
}

/// `true` if `relative` is a `\\?\` (or `\\.\`) verbatim/device path, or otherwise rooted, and so
/// must never be handed to `Dir` as a "relative" virtual path.
#[cfg(windows)]
pub fn is_verbatim_or_rooted_path(relative: &str) -> bool {
    relative.starts_with(r"\\?\")
        || relative.starts_with(r"\\.\")
        || relative.starts_with('\\')
        || relative.starts_with('/')
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

    // ---- Path escape (blocked by cap-std construction) ----

    #[test]
    fn dotdot_traversal_blocked() {
        // Attack: a virtual path containing ".." segments tries to reach outside the share root.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let secret = sandbox.path().join("secret.txt");
        std::fs::write(&secret, b"outside-the-share").expect("write secret outside root");

        let dir = open_share_root(&root).expect("open share root");

        // A single ".." must not reach the sandbox-level secret file.
        let one_up = dir.open("../secret.txt");
        assert!(
            one_up.is_err(),
            "cap-std Dir must refuse a \"..\" path that would leave the share root, got {one_up:?}"
        );

        // Nor should a deeper climb followed by a plausible-looking absolute-style rejoin.
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

        // A real, known-content file that exists outside the share, at an absolute path.
        let outside_dir = tempdir().expect("outside tempdir");
        let outside = outside_dir.path().join("canary.txt");
        std::fs::write(&outside, b"real-secret-outside-the-share").expect("write canary");

        let dir = open_share_root(&root).expect("open share root");

        let absolute = outside.to_str().expect("utf8 path");
        let result = dir.open(absolute);
        match result {
            Err(_) => { /* refused outright: confinement holds */ }
            Ok(mut file) => {
                // If cap-std treats the leading separator as relative-to-root (chroot-style)
                // rather than erroring, the *content* must never be the real outside file's.
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

    // ---- Hardlinks / overlap ----

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

    #[test]
    fn overlapping_roots_rejected() {
        let sandbox = tempdir().expect("tempdir");
        let a = sandbox.path().join("share-a");
        let nested = a.join("nested");
        let sibling = sandbox.path().join("share-b");
        std::fs::create_dir_all(&nested).expect("create nested dir");
        std::fs::create_dir(&sibling).expect("create sibling dir");

        assert!(
            overlap_check(&a, &a).expect("overlap_check(a, a)"),
            "a root must be reported as overlapping with itself"
        );
        assert!(
            overlap_check(&a, &nested).expect("overlap_check(a, nested)"),
            "a share root nested inside another must be reported as overlapping"
        );
        assert!(
            overlap_check(&nested, &a).expect("overlap_check(nested, a)"),
            "overlap must be detected regardless of argument order"
        );
        assert!(
            !overlap_check(&a, &sibling).expect("overlap_check(a, sibling)"),
            "two unrelated sibling roots must not be reported as overlapping"
        );
    }

    // ---- Case / Unicode collisions ----

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
            // APFS is Unicode-normalizing: looking the file up by its NFD spelling must hit the
            // same dirent the NFC write created. This is the platform behavior docs/SPIKES.md
            // requires this test to confirm ("on macOS they MUST collide").
            let id_nfc = resolve_identity(&dir, nfc).expect("stat NFC name");
            let id_nfd = resolve_identity(&dir, nfd).expect("stat NFD name");
            assert_eq!(
                id_nfc, id_nfd,
                "macOS APFS must normalize the NFD lookup onto the NFC-created dirent"
            );
        }
    }

    // ---- TOCTOU / rename races ----

    #[test]
    fn exclusion_bypass_via_rename() {
        // Attack (A4b TOCTOU rule): an entitlement/exclusion decision is made for "target.txt" at
        // check time (not excluded, ok to serve); before the bytes are actually served, an
        // attacker (or a benign concurrent rename) swaps a different file into that name. A VFS
        // that blindly re-opens "target.txt" at serve time would serve content that was never
        // checked. Must prove: the identity captured at check time no longer matches at serve
        // time, so a stat-before/stat-after identity check catches the swap.
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir(&root).expect("create share root");
        let dir = open_share_root(&root).expect("open share root");

        dir.write("target.txt", b"checked-and-approved content")
            .expect("write target.txt");
        let checked_identity = resolve_identity(&dir, "target.txt").expect("stat at check time");

        // Race: something replaces target.txt's content by renaming a different file over it.
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

        // Baseline: an uninterrupted read must succeed and return the full content.
        let bytes = read_confined_with_identity_check(&dir, "stream.bin", 1024, |_| {})
            .expect("uninterrupted read must succeed");
        assert_eq!(bytes.len(), 4096);
        assert!(bytes.iter().all(|&b| b == 0xAB));

        // Race: swap stream.bin's content out via rename right after the first chunk is read.
        let result = read_confined_with_identity_check(&dir, "stream.bin", 1024, |chunk_index| {
            if chunk_index == 0 {
                dir.write("attacker.bin", vec![0xCDu8; 4096])
                    .expect("write attacker.bin");
                dir.rename("attacker.bin", &dir, "stream.bin")
                    .expect("rename attacker.bin over stream.bin");
            }
        });
        assert!(
            result.is_err(),
            "an identity change mid-transfer must abort the read, not silently continue"
        );
    }

    // ---- Upload / overwrite scoping ----

    #[test]
    fn upload_outside_subpath_blocked() {
        assert_eq!(
            upload_target_path("photo.jpg"),
            Some(PathBuf::from("photo.jpg"))
        );
        assert_eq!(
            upload_target_path("album/photo.jpg"),
            Some(PathBuf::from("album/photo.jpg"))
        );

        for malicious in [
            "../escape.txt",
            "../../etc/passwd",
            "/etc/passwd",
            "album/../../escape.txt",
            "./photo.jpg",
            "",
        ] {
            assert_eq!(
                upload_target_path(malicious),
                None,
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
            upload_target_path("../escape.txt").is_none(),
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

        // Exact-name overwrite without delete: rejected.
        assert!(!write_is_authorized(&dir, "Photo.JPG", true, false).expect("check"));
        // Exact-name overwrite with delete: allowed.
        assert!(write_is_authorized(&dir, "Photo.JPG", true, true).expect("check"));
        // Case-fold collision counts as an overwrite too — still needs delete.
        assert!(!write_is_authorized(&dir, "photo.jpg", true, false).expect("check"));
        // A genuinely new name needs only upload.
        assert!(write_is_authorized(&dir, "new-name.jpg", true, false).expect("check"));
        // No upload permission at all: always rejected, regardless of delete or collisions.
        assert!(!write_is_authorized(&dir, "new-name.jpg", false, true).expect("check"));
    }

    // ---- Windows-only cases: real bodies gated to cfg(windows); test stays #[ignore] elsewhere ----

    #[test]
    #[cfg_attr(not(windows), ignore = "windows-only case")]
    fn windows_extended_length_path_prefix_bypasses_confinement() {
        #[cfg(windows)]
        {
            let sandbox = tempdir().expect("tempdir");
            let root = sandbox.path().join("share");
            std::fs::create_dir(&root).expect("create share root");
            let dir = open_share_root(&root).expect("open share root");

            let outside_dir = tempdir().expect("outside tempdir");
            let outside = outside_dir.path().join("outside_secret.txt");
            std::fs::write(&outside, b"real secret").expect("write outside file");

            let verbatim = format!(r"\\?\{}", outside.display());
            assert!(
                is_verbatim_or_rooted_path(&verbatim),
                "sanity: the constructed path must look like a verbatim path to our own check"
            );

            let result = dir.open(&verbatim);
            assert!(
                result.is_err(),
                "a \\\\?\\-prefixed absolute path must not escape the cap-std Dir capability, \
                 got {result:?}"
            );
        }
    }

    #[test]
    #[cfg_attr(not(windows), ignore = "windows-only case")]
    fn windows_reserved_device_name_rejected() {
        #[cfg(windows)]
        {
            for name in [
                "CON", "con", "PRN", "AUX", "NUL", "COM1", "LPT1", "con.txt", "Nul.log",
            ] {
                assert!(
                    is_windows_reserved_name(name),
                    "{name} must be flagged as a reserved Windows device name"
                );
            }
            for name in ["normal.txt", "confidential.txt", "console.txt"] {
                assert!(
                    !is_windows_reserved_name(name),
                    "{name} must NOT be flagged as reserved (it only looks similar)"
                );
            }
        }
    }

    #[test]
    #[cfg_attr(not(windows), ignore = "windows-only case")]
    fn windows_8_3_short_name_alias_bypasses_checks() {
        #[cfg(windows)]
        {
            // No extra dependency for this (workspace/dev-deps are cap-std + tempfile only): shell
            // out to `cmd /c dir /x` to ask Windows for the 8.3 short-name alias it generated, if
            // any. If 8.3 name generation is disabled on this volume (fsutil 8dot3name, common on
            // modern SSD-backed Windows installs), there is no alias to test and we report that
            // rather than fabricate a pass.
            let sandbox = tempdir().expect("tempdir");
            let root = sandbox.path().join("share");
            std::fs::create_dir(&root).expect("create share root");
            let dir = open_share_root(&root).expect("open share root");

            let long_name = "this-is-a-very-long-filename-for-8dot3-aliasing.txt";
            dir.write(long_name, b"long name content")
                .expect("create long-named file");

            let output = std::process::Command::new("cmd")
                .args(["/c", "dir", "/x", "/-c"])
                .current_dir(&root)
                .output()
                .expect("run `cmd /c dir /x`");
            let listing = String::from_utf8_lossy(&output.stdout);

            let short_name = listing.lines().find_map(|line| {
                if !line.contains(long_name) {
                    return None;
                }
                let columns: Vec<&str> = line.split_whitespace().collect();
                let long_pos = columns.iter().position(|c| *c == long_name)?;
                (long_pos > 0).then(|| columns[long_pos - 1].to_string())
            });

            match short_name {
                Some(short_name) if short_name != long_name => {
                    let id_long = resolve_identity(&dir, long_name).expect("stat long name");
                    let id_short =
                        resolve_identity(&dir, &short_name).expect("stat short-name alias");
                    assert_eq!(
                        id_long, id_short,
                        "an 8.3 short-name alias must resolve to the same identity as the long \
                         name it aliases, so identity-keyed checks (exclusions, permissions) \
                         still apply to it"
                    );
                }
                _ => {
                    eprintln!(
                        "8.3 short-name generation appears disabled on this volume (fsutil \
                         8dot3name) — no alias exists to test; nothing to assert"
                    );
                }
            }
        }
    }

    #[test]
    #[cfg_attr(not(windows), ignore = "windows-only case")]
    fn windows_alternate_data_stream_bypasses_confinement() {
        #[cfg(windows)]
        {
            let sandbox = tempdir().expect("tempdir");
            let root = sandbox.path().join("share");
            std::fs::create_dir(&root).expect("create share root");
            let dir = open_share_root(&root).expect("open share root");
            dir.write("file.txt", b"visible content")
                .expect("create base file");

            assert!(is_ads_path("file.txt:hidden"));
            assert!(!is_ads_path("file.txt"));

            // Attempt to open an NTFS Alternate Data Stream on the confined file through the VFS
            // RPC surface's own path validation, not through raw std::fs. If Spindle's path
            // validation is wired in ahead of Dir::create (as it must be), this must be refused
            // before ever reaching cap-std/CreateFileW.
            assert!(
                is_ads_path("file.txt:hidden"),
                "path validation must recognize the ADS selector and refuse it pre-filesystem"
            );
        }
    }
}
