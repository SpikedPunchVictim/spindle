//! # S11 — VFS confinement spike
//!
//! Answers `docs/DESIGN.md` §A13, spike **S11**: *"VFS confinement (`cap-std`): `..`, symlink
//! escape, hardlinks, overlapping roots, case/Unicode collisions, exclusion bypass, upload
//! scoping, Windows device names / 8.3 / ADS / `\\?\` paths, rename races."* Full writeup and
//! gating: `docs/SPIKES.md` (§S11). Do not edit the pass criterion here — `docs/DESIGN.md` §A13
//! is authoritative; this file only plans how to reach it and stubs the test matrix.
//!
//! ## The negative-test matrix (verbatim source: `docs/DESIGN.md` §A4b, §A8, §A13)
//!
//! Every share root is opened as a `cap-std` `Dir` (pinned `>= 3.4.1`), and all I/O goes through
//! that capability — no `..`, symlink escape, or absolute-path trick should be reachable *by
//! construction*. `cap-std` does **not** canonicalize, case-fold, or normalize on its own —
//! Spindle is responsible for exclusion/permission matching on the resolved real path plus
//! case/Unicode folding, and for identity checks (dev+ino / file-id) where names are ambiguous.
//! Every request re-resolves from the share `Dir` (no long-lived subdirectory handles); file
//! identity is checked between `stat` and `read`/`upload` and at every chunk boundary, aborting on
//! change.
//!
//! Attack cases this spike must prove impossible, one per test below:
//!
//! 1. **`..` traversal** — a virtual path containing `..` segments must not escape the share root.
//! 2. **Symlink escape** — a symlink inside the share pointing outside the root must not be
//!    followed.
//! 3. **Hardlink bypass of exclusions** — a file with link count (`nlink`) > 1 inside a share that
//!    has exclusions must not be served (§A4b: "files with link count > 1 are not served").
//! 4. **Overlapping share roots** — adding a second share whose resolved real path *or*
//!    device+inode/file-id overlaps an existing share must be rejected at add-time, and re-checked
//!    at host start.
//! 5. **Case-fold collision == overwrite** — creating/uploading a name that collides
//!    case-insensitively with an existing dirent on a case-insensitive filesystem must be treated
//!    as an overwrite, not a new entry.
//! 6. **Unicode-normalization collision == overwrite** — same rule under Unicode (NFC/NFD)
//!    normalization variants of an existing name.
//! 7. **Exclusion bypass** — a globbed-out path must remain unreachable via any alternate
//!    (symlink/hardlink/case-variant) route into the same real file.
//! 8. **Upload outside granted subpath** — an upload targeting a virtual path outside the caller's
//!    granted subpath must be rejected before touching the filesystem.
//! 9. **Overwrite without `delete`** — overwriting an existing entry must require `delete`
//!    permission; `upload` alone must not suffice.
//! 10. **Windows reserved device names** — names like `CON`, `PRN`, `AUX`, `NUL`, `COM1`… must be
//!     handled safely (rejected/sanitized), not passed through to the OS as a device open.
//! 11. **Windows 8.3 short-name aliasing** — a short-name alias (e.g. `LONGFI~1.TXT`) must not
//!     provide a second path to a file that bypasses exclusion/permission checks done against the
//!     long name.
//! 12. **Windows Alternate Data Streams (ADS)** — `file.txt:hidden` must not expose a second,
//!     unchecked data stream on an otherwise-confined file.
//! 13. **Windows `\\?\` extended-length paths** — device-path-prefixed absolute paths must not be
//!     usable to step outside the `cap-std` `Dir` capability.
//! 14. **Rename / TOCTOU races** — a file renamed, replaced, or mutated between `stat` and
//!     `read`/`upload`, or across a chunk boundary mid-transfer, must cause the request to abort
//!     rather than serve/accept stale or mismatched content.
//!
//! ## Pass criterion (verbatim, `docs/DESIGN.md` §A13)
//!
//! *"Automated negative tests all pass on macOS/Windows/Linux."* This is a CI-matrix requirement,
//! not a single-machine run — see `docs/SPIKES.md` (§S11). Per §A9b this suite must also graduate
//! into permanent CI once it passes.
//!
//! Results (per-OS pass/fail) go in `spikes/s11-vfs-confinement/RESULTS.md`. This crate has no
//! dependencies yet — see the commented block in `Cargo.toml`.

#[cfg(test)]
mod tests {
    /// Scaffold check: the crate builds and the test harness runs. Not part of the negative-test
    /// matrix — remove or replace once real tests land.
    #[test]
    fn scaffold() {
        assert!(true);
    }

    // ---- Path escape ----

    #[test]
    #[ignore = "spike not yet run"]
    fn dotdot_traversal_escapes_share_root() {
        // Attack: a virtual path containing ".." segments reaches outside the share root.
        // Must prove: resolving through the cap-std Dir never yields a path outside the root.
    }

    #[test]
    #[ignore = "spike not yet run"]
    fn symlink_escape_out_of_root() {
        // Attack: a symlink inside the share points outside the root and is followed on read.
        // Must prove: symlinks that resolve outside the share root are never followed.
    }

    #[test]
    #[ignore = "spike not yet run"]
    fn windows_extended_length_path_prefix_bypasses_confinement() {
        // Attack: a \\?\-prefixed absolute/device path is used to step outside the share Dir.
        // Must prove: \\?\ paths cannot be used to escape the cap-std capability on Windows.
    }

    // ---- Hardlinks / overlap ----

    #[test]
    #[ignore = "spike not yet run"]
    fn hardlink_bypasses_exclusion() {
        // Attack: a hardlink (nlink > 1) into an excluded file is served via a non-excluded name.
        // Must prove: any dirent with link count > 1 in a share with exclusions is refused.
    }

    #[test]
    #[ignore = "spike not yet run"]
    fn overlapping_share_roots_rejected_at_add_time() {
        // Attack: a second share is added whose real root overlaps an existing share's root.
        // Must prove: overlap (by resolved path AND device+inode/file-id) is rejected at add-time
        // and re-checked at host start.
    }

    // ---- Case / Unicode collisions ----

    #[test]
    #[ignore = "spike not yet run"]
    fn case_fold_collision_treated_as_overwrite() {
        // Attack: uploading "Photo.JPG" when "photo.jpg" exists creates a second, unmanaged entry.
        // Must prove: the collision is detected and treated as an overwrite requiring `delete`.
    }

    #[test]
    #[ignore = "spike not yet run"]
    fn unicode_nfd_collision_treated_as_overwrite() {
        // Attack: an NFD-normalized name variant of an existing NFC name creates a second entry.
        // Must prove: Unicode-normalization collisions are folded and treated as an overwrite.
    }

    // ---- Exclusions ----

    #[test]
    #[ignore = "spike not yet run"]
    fn exclusion_bypass_via_alternate_path() {
        // Attack: an excluded file is reached via a symlink/hardlink/case-variant alternate route.
        // Must prove: exclusion matching is done on the resolved real path/identity, not the name.
    }

    // ---- Upload / overwrite scoping ----

    #[test]
    #[ignore = "spike not yet run"]
    fn upload_outside_granted_subpath_rejected() {
        // Attack: an upload targets a virtual path outside the caller's granted subpath.
        // Must prove: the request is rejected before any filesystem write occurs.
    }

    #[test]
    #[ignore = "spike not yet run"]
    fn overwrite_without_delete_permission_rejected() {
        // Attack: `upload` permission alone is used to silently overwrite an existing entry.
        // Must prove: overwriting an existing dirent requires `delete`, not just `upload`.
    }

    // ---- Windows-specific ----

    #[test]
    #[ignore = "spike not yet run"]
    fn windows_reserved_device_name_rejected() {
        // Attack: a name like "CON", "PRN", "AUX", "NUL", or "COM1" is passed through to the OS.
        // Must prove: reserved device names are sanitized/rejected, never opened as a device.
    }

    #[test]
    #[ignore = "spike not yet run"]
    fn windows_8_3_short_name_alias_bypasses_checks() {
        // Attack: an 8.3 short-name alias (e.g. LONGFI~1.TXT) reaches a file whose long name was
        // excluded or permission-checked differently.
        // Must prove: short-name aliases resolve to the same identity checks as the long name.
    }

    #[test]
    #[ignore = "spike not yet run"]
    fn windows_alternate_data_stream_bypasses_confinement() {
        // Attack: "file.txt:hidden" (an NTFS ADS) exposes a second unchecked data stream.
        // Must prove: alternate data streams are inaccessible through the VFS RPC surface.
    }

    // ---- Races ----

    #[test]
    #[ignore = "spike not yet run"]
    fn rename_toctou_race_aborts_request() {
        // Attack: the target file is renamed/replaced/mutated between stat and read/upload, or
        // across a chunk boundary mid-transfer.
        // Must prove: the request detects the identity change (dev+ino / file-id) and aborts
        // rather than serving or accepting stale/mismatched content.
    }
}
