//! Upload quota and free-space-floor configuration (DESIGN.md §A4b: "quotas per member and per
//! share"; §A8 "Owner live operations": "host-level free-space floor that pauses uploads before
//! the disk fills").
//!
//! # Free-space floor: a documented dependency gap, not silently resolved
//!
//! Checking *real* available disk space requires an OS-level call (`statvfs` on Unix,
//! `GetDiskFreeSpaceExW` on Windows) that has no stable API in `std` and is not provided by any
//! crate already in this workspace's dependency graph (`libc`, `fs4`/`fs2`, and `sysinfo` are the
//! usual choices; none is currently a dependency of any crate here). Adding one is an
//! architecture decision — a new third-party dependency — that this task brief did not authorize
//! unilaterally (per this repo's own "be cognizant about adding dependencies, ask clarifying
//! questions" standing instruction), so it is flagged here instead of silently added.
//!
//! What *is* implemented, fully and testably: the [`FreeSpaceProbe`] seam
//! `crate::server::VfsRpcServer` calls before accepting every `upload_chunk` (task brief: "free
//! space floor check before accepting chunks"), and the `storage_full` error path it drives. The
//! default probe ([`UnlimitedFreeSpace`]) always reports "plenty of space", so this slice does not
//! regress any existing behavior; a production host wires in a real probe (implementing
//! [`FreeSpaceProbe`] over whichever dependency is chosen) via [`crate::server::VfsRpcServer::with_limits`]
//! — a one-line change once that dependency decision is made. Tests in `crate::server` inject a
//! fake probe that reports a full disk, to exercise the `storage_full` path end to end.
//!
//! Options for the real probe, for whoever makes that call:
//! - `libc::statvfs`/`libc::GetDiskFreeSpaceExW` directly: zero extra dependency weight beyond
//!   `libc` itself (already ubiquitous, but not currently a dependency here), full control, but
//!   hand-rolled `unsafe` FFI and platform-specific code to maintain.
//! - `fs4` (maintained fork of the unmaintained `fs2`): small, focused, cross-platform
//!   `available_space(path)` function; adds one small dependency.
//! - `sysinfo`: much heavier (whole-system inventory: CPU, memory, processes, disks) for what is
//!   needed here; not recommended unless this workspace already wants that for other reasons.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_free_space_reports_max() {
        let probe = UnlimitedFreeSpace;
        assert_eq!(probe.available_bytes(Path::new("/anything")), u64::MAX);
    }

    #[test]
    fn default_limits_are_generous_but_bounded() {
        let limits = UploadLimits::default();
        assert!(limits.max_member_upload_bytes > 0);
        assert!(limits.max_share_upload_bytes > limits.max_member_upload_bytes);
        assert!(limits.min_free_bytes > 0);
    }
}
