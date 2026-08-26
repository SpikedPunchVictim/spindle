//! Upload quota and free-space-floor configuration (DESIGN.md §A4b: "quotas per member and per
//! share"; §A8 "Owner live operations": "host-level free-space floor that pauses uploads before
//! the disk fills").
//!
//! # Free-space floor: real OS probe (user decision 2026-08-26)
//!
//! Checking *real* available disk space requires an OS-level call (`statvfs` on Unix,
//! `GetDiskFreeSpaceExW` on Windows) that has no stable API in `std`. Earlier slices flagged
//! choosing a dependency for this as an architecture decision this task brief did not authorize
//! unilaterally; the "whichever dependency is chosen" placeholder that used to sit here is now
//! resolved — the user decided (2026-08-26, DESIGN.md A9c manifest amended) on `rustix`
//! (`rustix::fs::statvfs` on Unix) and `windows-sys` (`GetDiskFreeSpaceExW` on Windows); see
//! [`OsFreeSpace`]. Both were already *transitive* dependencies of this crate via
//! `cap-std`/`cap-primitives` before this decision, so promoting them to direct, target-scoped
//! dependencies here adds no new crate version to the workspace's dependency graph (verified via
//! `cargo tree -i rustix` and `cargo tree --target all -i windows-sys`).
//!
//! [`OsFreeSpace`] **fails closed**: any probe error (nonexistent path, permission denied, a
//! Windows path that isn't representable in UTF-16, ...) reports `0` bytes available, which trips
//! `storage_full` rather than silently behaving as if space were unlimited. DESIGN.md §A4b's
//! free-space floor exists specifically to pause uploads "before the disk fills" — a probe that
//! fails *open* (reports plenty of space when it actually does not know) would defeat that
//! guarantee at exactly the moment it matters most.
//!
//! What *is* implemented, fully and testably: the [`FreeSpaceProbe`] seam
//! `crate::server::VfsRpcServer` calls before accepting every `upload_chunk` (task brief: "free
//! space floor check before accepting chunks"), and the `storage_full` error path it drives. The
//! default probe ([`UnlimitedFreeSpace`]) always reports "plenty of space", so tests never depend
//! on host-machine free space; a production host wires in [`OsFreeSpace`] via
//! [`crate::server::VfsRpcServer::with_limits`]. Tests in `crate::server` inject a fake probe that
//! reports a full disk, to exercise the `storage_full` path end to end.

use std::path::Path;

/// Per-member/per-share upload byte quotas, plus the free-space floor. Defaults are
/// generous-but-bounded placeholders — DESIGN.md specifies that these quotas/floor must exist,
/// not their numeric values — documented here exactly like `spindle_vfs::store::StoreLimits` so a
/// later slice can retune without hunting through `crate::server`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UploadLimits {
    /// Maximum cumulative bytes one member may have uploaded (DESIGN.md §A4b "quotas per
    /// member"). Default: 50 GiB. See `spindle_vfs::store::Store`'s upload-quota-counters module
    /// doc comment for exactly what this counts.
    pub max_member_upload_bytes: u64,
    /// Maximum cumulative bytes one share may have received via upload (DESIGN.md §A4b "quotas
    /// per share"). Default: 500 GiB.
    pub max_share_upload_bytes: u64,
    /// The free-space floor (DESIGN.md §A8 "Owner live operations"): an `upload_chunk` is refused
    /// with `storage_full` once [`FreeSpaceProbe::available_bytes`] reports fewer bytes than this
    /// remaining on the share's filesystem. Default: 1 GiB.
    pub min_free_bytes: u64,
}

impl Default for UploadLimits {
    fn default() -> Self {
        UploadLimits {
            max_member_upload_bytes: 50 * 1024 * 1024 * 1024,
            max_share_upload_bytes: 500 * 1024 * 1024 * 1024,
            min_free_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Reports how many bytes are available on the filesystem backing `real_root` — see the module
/// doc comment for why this is an injectable seam rather than a real OS call in this slice.
pub trait FreeSpaceProbe {
    fn available_bytes(&self, real_root: &Path) -> u64;
}

/// The default probe: always reports effectively unlimited free space, so this slice's
/// `storage_full` path never fires unless a caller explicitly opts into a real (or, in tests, a
/// fake) probe via [`crate::server::VfsRpcServer::with_limits`].
pub struct UnlimitedFreeSpace;

impl FreeSpaceProbe for UnlimitedFreeSpace {
    fn available_bytes(&self, _real_root: &Path) -> u64 {
        u64::MAX
    }
}

/// The real OS probe (user decision 2026-08-26 — see the module doc comment). Queries the
/// filesystem backing `real_root` directly: `rustix::fs::statvfs` on Unix, `GetDiskFreeSpaceExW`
/// on Windows.
///
/// **Fails closed**: any probe error reports `0` bytes available (never `u64::MAX`, never the
/// error propagated) so the free-space floor in `crate::server::VfsRpcServer` refuses uploads
/// (`storage_full`) rather than silently letting the disk fill — see the module doc comment for
/// why fail-open would defeat DESIGN.md §A4b's floor.
pub struct OsFreeSpace;

#[cfg(unix)]
impl FreeSpaceProbe for OsFreeSpace {
    fn available_bytes(&self, real_root: &Path) -> u64 {
        // `f_bavail` (blocks available to an unprivileged user) times `f_frsize` (fragment/block
        // size in bytes) is the standard statvfs "space I could actually use" computation —
        // `f_bfree` includes blocks reserved for root, which would overstate what a normal upload
        // path can claim. Saturating multiply: astronomically large disks should clamp to
        // `u64::MAX` rather than wrap.
        match rustix::fs::statvfs(real_root) {
            Ok(stat) => stat.f_bavail.saturating_mul(stat.f_frsize),
            Err(_) => 0,
        }
    }
}

#[cfg(windows)]
impl FreeSpaceProbe for OsFreeSpace {
    fn available_bytes(&self, real_root: &Path) -> u64 {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

        // GetDiskFreeSpaceExW wants a NUL-terminated, UTF-16 ("wide") path.
        let mut wide: Vec<u16> = real_root.as_os_str().encode_wide().collect();
        wide.push(0);

        let mut free_bytes_available_to_caller: u64 = 0;
        // SAFETY: `wide` is a valid, NUL-terminated UTF-16 buffer kept alive for the duration of
        // this call. `free_bytes_available_to_caller` is a live, uniquely-owned local `u64`; we
        // pass a valid pointer to it as the out-param this function actually reads. The other two
        // out-params (total bytes, total free bytes) are not needed here — the Win32 API accepts
        // `NULL` for any of the three pointer out-params, so passing null is well-defined per the
        // documented contract, not a safety violation.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free_bytes_available_to_caller,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if ok == 0 {
            // BOOL == 0 means the call failed (e.g. path does not exist) — fail closed.
            0
        } else {
            // FreeBytesAvailableToCaller (not the raw total-free) is the caller-quota-aware value:
            // it already accounts for any per-user disk quota, matching "available-to-unprivileged"
            // in spirit with the Unix `f_bavail` branch above.
            free_bytes_available_to_caller
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_free_space_reports_max() {
        let probe = UnlimitedFreeSpace;
        assert_eq!(probe.available_bytes(Path::new("/anything")), u64::MAX);
    }

    #[test]
    fn os_free_space_reports_a_real_bounded_value_for_a_real_directory() {
        // A real filesystem has *some* space, and is never reported as literally infinite —
        // distinguishes a working probe from a stub that just returns `u64::MAX`.
        let dir = tempfile::tempdir().expect("tempdir");
        let probe = OsFreeSpace;
        let bytes = probe.available_bytes(dir.path());
        assert!(bytes > 0);
        assert!(bytes < u64::MAX);
    }

    #[test]
    fn os_free_space_fails_closed_on_a_nonexistent_path() {
        let probe = OsFreeSpace;
        let missing = Path::new("/definitely/does/not/exist/spindle-limits-test");
        assert_eq!(probe.available_bytes(missing), 0);
    }

    #[test]
    fn default_limits_are_generous_but_bounded() {
        let limits = UploadLimits::default();
        assert!(limits.max_member_upload_bytes > 0);
        assert!(limits.max_share_upload_bytes > limits.max_member_upload_bytes);
        assert!(limits.min_free_bytes > 0);
    }
}
