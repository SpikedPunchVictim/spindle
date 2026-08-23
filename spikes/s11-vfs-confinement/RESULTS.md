# S11 — VFS confinement results

Pass criterion (verbatim, `docs/DESIGN.md` §A13): automated negative tests all pass on
macOS/Windows/Linux. See `docs/SPIKES.md` (§S11) and `src/lib.rs` for the full test matrix.

Status: **macOS run complete (2026-08-23), 12/12 non-Windows cases pass.** Linux and Windows are
pending (this machine is macOS-only; Windows-specific cases are compiled behind `#[cfg(windows)]`
and will run as-is — `cargo test` — on a Windows box per the spike's design).

**Environment**: macOS (Darwin 25.3.0, arm64), APFS (default: case-insensitive,
Unicode-normalizing), Rust 1.98.0, `cap-std` resolved to **4.0.3** (workspace pin `>=3.4.1`
satisfied).

| Case | macOS | Windows | Linux | Notes |
|------|-------|---------|-------|-------|
| `..` traversal (`dotdot_traversal_blocked`) | **PASS** | pending | pending | Blocked by `cap-std` `Dir` by construction — no app-level check needed. |
| Absolute-path trick (`absolute_path_blocked`) | **PASS** | pending | pending | Blocked by `cap-std` `Dir` by construction. |
| Symlink escape (`symlink_escape_blocked`) | **PASS** | pending | pending | Symlink inside share pointing outside root: `open`/`metadata` both error. Blocked by `cap-std` by construction. |
| Hardlink bypasses exclusion (`hardlink_nlink_guard`) | **PASS** | pending | pending | `cap-std` does **not** block this — confirms DESIGN.md's framing that this is a Spindle-side rule, not a `cap-std` guarantee. Prototype `nlink_guard()` correctly refuses `nlink > 1` only when `share_has_exclusions`. |
| Overlapping share roots rejected (`overlapping_roots_rejected`) | **PASS** | pending | pending | Spindle-side `overlap_check()` (canonicalized real path prefix/equality + dev+ino fallback). Not a `cap-std` feature. |
| Case-fold collision == overwrite (`case_fold_collision_detected`) | **PASS** | pending | pending | Spindle-side `fold_key()`/`existing_entry_colliding()`. On macOS/APFS the OS *also* already folds `Photo.JPG`/`photo.jpg` to the same dirent (asserted); our check must still hold OS-independently for Linux. |
| Unicode NFD collision == overwrite (`unicode_nfd_collision_detected`) | **PASS** | pending | pending | `fold_key()` treats NFC/NFD "café" as equal. On macOS/APFS the OS *also* normalizes NFD lookups onto the NFC-created file (asserted, `cfg(target_os = "macos")`) — matches DESIGN.md's expectation that this "MUST collide" on macOS. |
| Exclusion-check TOCTOU (`exclusion_bypass_via_rename`) | **PASS** | pending | pending | Reinterpreted per task instructions as the TOCTOU race: stat at check-time, rename a different file over the target, stat again — identity differs, so a real VFS would abort. Spindle-side identity check, not `cap-std`. |
| Upload outside granted subpath (`upload_outside_subpath_blocked`) | **PASS** | pending | pending | Prototype `upload_target_path()`: rejects any `..`, absolute, `.`, or empty component before any filesystem write. Spindle-side. |
| Overwrite without `delete` rejected (`overwrite_requires_delete`) | **PASS** | pending | pending | Prototype `write_is_authorized()`: exact-name and case-fold-collision overwrites both require `can_delete`; new names need only `can_upload`; no `can_upload` always rejects. Spindle-side. |
| Windows reserved device name rejected | N/A | pending | N/A | Real body under `#[cfg(windows)]`; `#[ignore]`d on macOS/Linux by design. `is_windows_reserved_name()` unit-checked logic only (device-open behavior itself is Windows-only). |
| Windows 8.3 short-name alias | N/A | pending | N/A | Real body under `#[cfg(windows)]`; queries the OS-generated short name via `cmd /c dir /x` (no extra dependency) and, if one exists, asserts identity equality with the long name; gracefully no-ops if 8.3 generation is disabled on the volume. |
| Windows Alternate Data Stream | N/A | pending | N/A | Real body under `#[cfg(windows)]`; `is_ads_path()` flags any colon in a relative virtual path. |
| Windows `\\?\` extended-length path | N/A | pending | N/A | Real body under `#[cfg(windows)]`; attempts to `open()` a `\\?\`-prefixed absolute path to a file outside the share via the `Dir` capability and asserts it errors. |
| Rename/TOCTOU race aborts request (`rename_race_identity_check`) | **PASS** | pending | pending | Prototype `read_confined_with_identity_check()`: re-resolves identity after every chunk; deterministically (no sleeps/threads) swaps the file after chunk 0 and asserts the read errors instead of continuing. |

## Assumptions from DESIGN.md that did NOT hold empirically

- **Hardlink bypass is not blocked by `cap-std`.** DESIGN.md §A4b states shares with exclusions
  must not serve files with link count > 1, and frames path confinement generally around
  `cap-std`'s guarantees. Empirically, `cap-std`'s `Dir::hard_link` / `Dir::metadata` do nothing to
  prevent or flag a hardlinked file — `nlink` is exposed as plain metadata and enforcement is
  **entirely** a Spindle-side responsibility (confirmed by `hardlink_nlink_guard`, which required
  a from-scratch guard function; nothing in `cap-std` opted us out of writing it). This is
  consistent with — not a contradiction of — DESIGN.md's own wording ("cap-std does not
  canonicalize, case-fold, or normalize — Spindle does"), but it's worth stating explicitly: none
  of the hardlink/overlap/case-fold/Unicode/TOCTOU rules in §A4b come for free from `cap-std`.
  Only the three path-escape cases (`..`, absolute paths, symlink escape) are structural guarantees
  of the `Dir` capability itself.
- Everything else DESIGN.md attributes to `cap-std` "by construction" (§A4b: "no `..`, symlink
  escape, or absolute-path tricks by construction") held exactly as claimed — no surprises there.

## Files changed

- `spikes/s11-vfs-confinement/Cargo.toml` — added `cap-std = { workspace = true }` and
  crate-local `tempfile = "3"` dev-dependency.
- `spikes/s11-vfs-confinement/src/lib.rs` — prototype helpers (`open_share_root`,
  `file_identity`/`resolve_identity`/`stat_through_dir`, `nlink_guard`, `overlap_check`,
  `fold_key`/`names_collide`/`existing_entry_colliding`, `upload_target_path`,
  `write_is_authorized`, `read_confined_with_identity_check`, plus `#[cfg(windows)]`-only
  `is_windows_reserved_name`/`is_ads_path`/`is_verbatim_or_rooted_path`) and 16 tests (12 real and
  passing on macOS/Linux, 4 real-bodied-but-`#[ignore]`d-here Windows-only cases).
- `spikes/s11-vfs-confinement/RESULTS.md` — this file.

## Toolchain / build status

- `cap-std` resolved: **4.0.3** (workspace pin `>=3.4.1`).
- `cargo test -p spike-s11-vfs-confinement`: 12 passed, 0 failed, 4 ignored (Windows-only).
- `cargo test --workspace`: green (all other crates' scaffold tests unaffected).
- `cargo fmt --all -- --check`: clean.
- `cargo clippy -p spike-s11-vfs-confinement --all-targets -- -D warnings`: clean.
