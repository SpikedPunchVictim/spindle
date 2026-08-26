//! The host-wide `shares`/`entitlements` cache — the "cached per member, invalidated by
//! `grants_version` + `cap_epoch`" half of the enforcement pipeline (DESIGN.md §A4, §A8; task
//! brief deliverable #2). Both tables are host-wide (not member-specific), so this cache stores
//! one shared snapshot rather than one copy per member; [`spindle_vfs::algebra::EffectiveGrants`]
//! is cheaply recomputed per request from that snapshot plus whichever member is asking (see
//! `crate::server`) — a `HashSet`/`Vec` filter over at most `StoreLimits::max_shares` (default
//! 256) entitlements, not worth caching per member on top of caching the snapshot itself.
//!
//! # What this cache deliberately does NOT hold: the member's own row
//!
//! [`spindle_vfs::store::Store::revoke_member`]/`set_member_status` do **not** bump
//! `grants_version` or `cap_epoch` (see `spindle_vfs::store` module doc comment, "two counters,
//! two rules" — a status transition is not an entitlement/group/share mutation). If this cache
//! keyed a member's `status`/`groups` snapshot by those two counters, a revoked member would keep
//! passing the "member active?" pipeline step until some *unrelated* entitlement edit happened to
//! bump `grants_version` — silently reopening exactly the revocation-liveness hole DESIGN.md
//! §A4b's audit/enforcement model exists to close. So `crate::server::VfsRpcServer` always fetches
//! `Store::get_member` fresh, every request, *before* ever consulting this cache — see this
//! crate's `lib.rs` module doc comment for the full pipeline order. This cache exists purely to
//! avoid re-querying the (potentially larger, but change-infrequent) shares/entitlements tables
//! on every request.

use spindle_vfs::model::{Entitlement, Share};
use spindle_vfs::store::{Store, StoreError};
use std::cell::RefCell;

struct CachedHostState {
    grants_version: u64,
    cap_epoch: u64,
    shares: Vec<Share>,
    entitlements: Vec<Entitlement>,
}

/// `RefCell`, not `Mutex`: `crate::server::VfsRpcServer` (like `spindle_vfs::store::Store` itself)
/// is a plain synchronous, single-caller-at-a-time type — session multiplexing/concurrency is a
/// transport-layer concern this slice defers to `spindle-net` (see this crate's `lib.rs` module
/// doc comment's scope section), so there is no cross-thread sharing requirement here to satisfy.
pub(crate) struct GrantsCache {
    state: RefCell<Option<CachedHostState>>,
}

impl GrantsCache {
    pub(crate) fn new() -> Self {
        GrantsCache {
            state: RefCell::new(None),
        }
    }

    /// Returns the current `(shares, entitlements)`, refreshing from `store` first if the cache is
    /// empty or either counter has moved since the last refresh.
    pub(crate) fn get(&self, store: &Store) -> Result<(Vec<Share>, Vec<Entitlement>), StoreError> {
        let grants_version = store.grants_version()?;
        let cap_epoch = store.cap_epoch()?;

        if let Some(cached) = self.state.borrow().as_ref() {
            if cached.grants_version == grants_version && cached.cap_epoch == cap_epoch {
                return Ok((cached.shares.clone(), cached.entitlements.clone()));
            }
        }

        let shares = store.list_shares()?;
        let entitlements = store.list_entitlements()?;
        *self.state.borrow_mut() = Some(CachedHostState {
            grants_version,
            cap_epoch,
            shares: shares.clone(),
            entitlements: entitlements.clone(),
        });
        Ok((shares, entitlements))
    }

    #[cfg(test)]
    pub(crate) fn cached_counters(&self) -> Option<(u64, u64)> {
        self.state
            .borrow()
            .as_ref()
            .map(|c| (c.grants_version, c.cap_epoch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_vfs::model::{Perms, ShareFlags, VirtualPath};
    use spindle_vfs::store::Store;

    #[test]
    fn cache_is_empty_until_first_get() {
        let store = Store::open_in_memory().expect("open store");
        let cache = GrantsCache::new();
        assert_eq!(cache.cached_counters(), None);
        cache.get(&store).expect("first get populates the cache");
        assert!(cache.cached_counters().is_some());
    }

    #[test]
    fn cache_reflects_new_entitlement_after_grants_version_bumps() {
        let store = Store::open_in_memory().expect("open store");
        let share_id = store
            .add_share(
                "Photos",
                "Photos",
                std::path::Path::new("/tmp/does-not-matter"),
                ShareFlags::default(),
                &[],
                0,
            )
            .expect("add share");
        let group_id = store.create_custom_group("Friends").expect("create group");

        let cache = GrantsCache::new();
        let (_, entitlements) = cache.get(&store).expect("first get");
        assert!(entitlements.is_empty(), "nothing granted yet");

        store
            .add_entitlement(group_id, share_id, &VirtualPath::root(), Perms::BROWSE)
            .expect("grant browse");

        let (_, entitlements) = cache.get(&store).expect("second get, after mutation");
        assert_eq!(
            entitlements.len(),
            1,
            "grants_version bump on add_entitlement must invalidate the cached snapshot"
        );
    }

    #[test]
    fn cache_also_invalidates_on_cap_epoch_bump_alone() {
        let store = Store::open_in_memory().expect("open store");
        let cache = GrantsCache::new();
        let (_, _) = cache.get(&store).expect("first get");
        let before = cache.cached_counters().expect("populated");

        store.bump_cap_epoch().expect("bump cap_epoch");
        let (_, _) = cache.get(&store).expect("second get, after cap_epoch bump");
        let after = cache.cached_counters().expect("still populated");

        assert_ne!(
            before, after,
            "a cap_epoch-only change must still refresh the cached counters, even though it does \
             not itself change any share/entitlement row"
        );
    }
}
