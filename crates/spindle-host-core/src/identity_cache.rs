//! Per-`(member, share, subpath)` last-observed file-identity cache — carries DESIGN.md §A4b's
//! stat→read TOCTOU rule ("file identity is checked between `stat` and `read`") *across separate
//! RPC calls*.
//!
//! `spindle_vfs::confine::identity::read_confined_with_identity_check` already checks identity at
//! every chunk boundary, but it does so *within a single whole-file read call* — this slice's
//! `read` RPC serves one bounded chunk (≤ [`spindle_proto::vfs_rpc::MAX_READ_CHUNK`], 64 KiB) per
//! request, and `spindle-proto::vfs_rpc`'s module doc comment explains why there is no wire-level
//! identity token a client round-trips: the check has to live here instead, server-side, spanning
//! the gap between one `stat`/`read` call and the next. This is genuinely a per-*session* cache
//! (an identity observed for member A must never gate member B's read of the same path), keyed by
//! `MemberId` even though every request is already scoped to one member — see
//! `crate::server::SessionContext`.

use spindle_vfs::confine::identity::FileIdentity;
use spindle_vfs::model::{MemberId, ShareId, VirtualPath};
use std::cell::RefCell;
use std::collections::HashMap;

type Key = (MemberId, ShareId, VirtualPath);

pub(crate) struct IdentityCache {
    last_seen: RefCell<HashMap<Key, FileIdentity>>,
}

impl IdentityCache {
    pub(crate) fn new() -> Self {
        IdentityCache {
            last_seen: RefCell::new(HashMap::new()),
        }
    }

    /// Records `identity` as the most recently observed identity for this `(member, share, path)`
    /// — call after every successful `stat` and after every successful `read`.
    pub(crate) fn record(
        &self,
        member_id: MemberId,
        share_id: ShareId,
        path: &VirtualPath,
        identity: FileIdentity,
    ) {
        self.last_seen
            .borrow_mut()
            .insert((member_id, share_id, path.clone()), identity);
    }

    /// `true` only when a prior observation exists for this key *and* it differs from `current`.
    /// No prior observation is not a mismatch — the first `stat` or `read` of a path establishes
    /// the baseline (exactly as `read_confined_with_identity_check` establishes its baseline from
    /// the first stat of a single whole-file read; this cache extends that baseline across
    /// separate RPC calls instead of just across chunks of one call).
    pub(crate) fn mismatches(
        &self,
        member_id: MemberId,
        share_id: ShareId,
        path: &VirtualPath,
        current: &FileIdentity,
    ) -> bool {
        self.last_seen
            .borrow()
            .get(&(member_id, share_id, path.clone()))
            .is_some_and(|prev| prev != current)
    }

    /// Drops one entry — called after a `delete` removes the file (there is nothing left to
    /// compare against), and after a detected mismatch (don't keep comparing future calls against
    /// a baseline already known to be stale; the next `stat`/`read` establishes a fresh one).
    pub(crate) fn forget(&self, member_id: MemberId, share_id: ShareId, path: &VirtualPath) {
        self.last_seen
            .borrow_mut()
            .remove(&(member_id, share_id, path.clone()));
    }
}

// This module's tests build `FileIdentity` values from bare `(u64, u64)` tuples via the local
// `identity()` helper, which only typechecks when `FileIdentity` *is* `(u64, u64)` — i.e. on
// Unix (see `spindle_vfs::confine::identity::FileIdentity`'s doc comment: on Windows it's
// `same_file::Handle`, which cannot be constructed from raw integers). Gating the whole module
// on `unix` (rather than sprinkling `#[cfg(unix)]` on each item, which left `use super::*`
// unused when built on Windows — that unused import was a real Windows CI compile failure) is
// simpler than writing a parallel `Handle`-based Windows harness, and there is nothing
// platform-specific in `IdentityCache` itself left unexercised on Windows: it's a thin
// `HashMap` wrapper that is generic over `FileIdentity` and never branches on it, so these tests
// verify the same cache logic on both platforms even though they can only compile on one.
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn identity(a: u64, b: u64) -> FileIdentity {
        (a, b)
    }

    #[test]
    fn no_prior_observation_is_not_a_mismatch() {
        let cache = IdentityCache::new();
        let path = VirtualPath::parse("img.jpg").unwrap();
        assert!(!cache.mismatches(MemberId(1), ShareId(1), &path, &identity(1, 2)));
    }

    #[test]
    fn records_and_detects_a_mismatch_then_forgets() {
        let cache = IdentityCache::new();
        let path = VirtualPath::parse("img.jpg").unwrap();
        cache.record(MemberId(1), ShareId(1), &path, identity(1, 2));

        assert!(!cache.mismatches(MemberId(1), ShareId(1), &path, &identity(1, 2)));
        assert!(cache.mismatches(MemberId(1), ShareId(1), &path, &identity(9, 9)));

        cache.forget(MemberId(1), ShareId(1), &path);
        assert!(!cache.mismatches(MemberId(1), ShareId(1), &path, &identity(9, 9)));
    }

    #[test]
    fn distinct_members_do_not_share_a_baseline() {
        let cache = IdentityCache::new();
        let path = VirtualPath::parse("img.jpg").unwrap();
        cache.record(MemberId(1), ShareId(1), &path, identity(1, 2));
        assert!(!cache.mismatches(MemberId(2), ShareId(1), &path, &identity(9, 9)));
    }
}
