//! Per-share serialization between live upload commits and the disk reconcile sweep (td-042e4f).
//!
//! # The race this closes
//!
//! `UploadCommit` and `spindle_vfs::reconcile::reconcile_uploads_against_disk` both touch the same
//! two things — a share's real filesystem and its `uploaded_files` ledger — and neither the upload
//! path nor the sweep serializes the pair. A commit renames the staged file into place
//! (`confine::finalize_upload`) and only then calls `Store::record_upload`; nothing holds a lock
//! across those two steps. A sweep observing the filesystem between them can therefore:
//!
//! 1. resolve/stat a ledger row for `a.txt` while it is genuinely absent (it was deleted out of
//!    band, or a previous commit's row is about to be replaced);
//! 2. decide the row is gone and prepare to remove it by key;
//! 3. meanwhile a member's commit lands `a.txt` and inserts the replacement ledger row;
//! 4. remove the row it decided about — which is now the freshly-inserted one.
//!
//! The file then exists forever with no ledger row, the uploader's quota was refunded, and the
//! undercount is permanent (the sweep deliberately never discovers files). The resize arm has the
//! mirror image: a size stat'ed before a concurrent commit can overwrite the newer ledger size.
//!
//! `Delete` has the mirror ordering: it unlinks the file first and only then calls
//! `Store::remove_uploads_under`, which deletes ledger rows and refunds both counters. A commit
//! can land and `record_upload` the same path between those two steps, and the delete's
//! key/subtree remove then deletes the fresh row — leaving a file on disk with no ledger row and
//! permanently refunded quota, which the row-walking sweep can never heal.
//!
//! SQLite's write lock cannot close either ordering. The sweep's or delete's mutation is a
//! transaction and the rows it touches are committed and current by the time the lock is taken;
//! the missing serialization is between a *filesystem operation* and a *later database write*. The
//! lock therefore has to cover the whole filesystem-plus-database pair, and both an upload commit
//! (`finalize_upload` + `record_upload` + audit) and a `Delete` (`remove_confined` +
//! `remove_uploads_under` + audit) have to take the same lock.
//!
//! # Scope and shape
//!
//! One lock per share, shared in-process. The scheduled sweep runs inside the host process, so it
//! and every session task hold clones of the same registry. The one-shot `--reconcile-once` path
//! runs in a **separate process** and cannot share this lock; `spindle-hostd`'s `HELP` and
//! `reconcile_surface` module docs require the host to be stopped for it. SQLite still prevents
//! database corruption in that case; what remains possible is exactly the FS/DB interleaving
//! above, which only an in-process lock can close.
//!
//! The map allocates lazily per [`ShareId`]. Share ids are host-local and bounded by
//! [`spindle_vfs::store::StoreLimits::max_shares`], so it cannot grow without bound in normal
//! operation.
//!
//! # Where the lock is taken
//!
//! `VfsRpcServer::handle` is synchronous by design (all of its filesystem I/O is blocking on the
//! session's one task), so it cannot `.await` a lock. The production entry point,
//! [`crate::serve::serve_control_stream`], therefore decodes each frame, asks
//! [`crate::server::VfsRpcServer::ledger_share_for`] whether the request mutates the ledger (and
//! for which share), awaits that share's lock, and only then runs the synchronous pipeline with
//! the [`tokio::sync::OwnedMutexGuard`] held. The scheduled sweep runs inside
//! `tokio::task::spawn_blocking`, where [`UploadLedgerLocks::lock_blocking`] is the corresponding
//! synchronous acquisition. Both paths contend on the same `tokio::sync::Mutex`.
//!
//! There is deliberately no unlocked bytes-in/bytes-out entry point: the old
//! `VfsRpcServer::handle_bytes` wrapper was removed (td-042e4f) so no caller can reach a
//! ledger-mutating path around this lock. Unit tests drive [`VfsRpcServer::handle`] directly with
//! typed requests; every byte-level caller goes through [`crate::serve::serve_control_stream`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use spindle_vfs::model::ShareId;
use tokio::sync::{Mutex as TokioMutex, OwnedMutexGuard};

/// A cloneable registry of one asynchronous lock per share, shared by every VFS session's upload
/// commit and the in-process reconcile sweep. See the module doc comment for the race it closes.
#[derive(Clone, Default)]
pub struct UploadLedgerLocks {
    locks: Arc<Mutex<HashMap<ShareId, Arc<TokioMutex<()>>>>>,
}

impl UploadLedgerLocks {
    /// An empty registry. Locks are allocated on first use for each share.
    pub fn new() -> Self {
        Self::default()
    }

    /// The lock cell for `share_id`, allocating it on first use. Exposed separately from the
    /// acquire helpers so a caller that must hand the lock to a blocking closure (or hold two
    /// cells) can do so without acquiring it first.
    pub fn lock_for(&self, share_id: ShareId) -> Arc<TokioMutex<()>> {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(locks.entry(share_id).or_default())
    }

    /// Acquires `share_id`'s lock, waiting if a commit or another sweep holds it. The owned guard
    /// is `Send + 'static`, so it can be held across the synchronous commit pipeline.
    pub async fn lock(&self, share_id: ShareId) -> OwnedMutexGuard<()> {
        self.lock_for(share_id).lock_owned().await
    }

    /// The synchronous counterpart for a blocking caller. Must be called from a blocking context
    /// (the scheduled sweep's `spawn_blocking` tick); [`tokio::sync::Mutex::blocking_lock_owned`]
    /// panics inside an asynchronous execution context.
    pub fn lock_blocking(&self, share_id: ShareId) -> OwnedMutexGuard<()> {
        self.lock_for(share_id).blocking_lock_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[test]
    fn the_same_share_maps_to_the_same_lock_and_different_shares_do_not() {
        let locks = UploadLedgerLocks::new();
        let a = locks.lock_for(ShareId(1));
        let a_again = locks.lock_for(ShareId(1));
        let b = locks.lock_for(ShareId(2));

        assert!(Arc::ptr_eq(&a, &a_again), "a share must have one lock cell");
        assert!(!Arc::ptr_eq(&a, &b), "different shares must not serialize");
    }

    #[test]
    fn clones_of_the_registry_share_the_same_lock_cells() {
        let locks = UploadLedgerLocks::new();
        let clone = locks.clone();
        assert!(Arc::ptr_eq(
            &locks.lock_for(ShareId(7)),
            &clone.lock_for(ShareId(7))
        ));
    }

    /// A second acquirer of a held share waits until the first guard is dropped, while a
    /// different share stays immediately available. This is the serialization the race fix
    /// depends on.
    #[tokio::test]
    async fn a_held_share_lock_serializes_a_second_acquirer() {
        let locks = UploadLedgerLocks::new();
        let held = locks.lock(ShareId(1)).await;

        let (acquired_tx, mut acquired_rx) = oneshot::channel();
        let waiter = {
            let locks = locks.clone();
            tokio::spawn(async move {
                let _guard = locks.lock(ShareId(1)).await;
                let _ = acquired_tx.send(());
            })
        };

        // Give the waiter a chance to run: it must block behind the guard.
        tokio::task::yield_now().await;
        assert!(
            acquired_rx.try_recv().is_err(),
            "the second acquirer must not get the held share's lock"
        );

        // A different share is not blocked by ShareId(1)'s guard.
        let _other = locks.lock(ShareId(2)).await;

        drop(held);
        acquired_rx
            .await
            .expect("the waiter must acquire once the guard is dropped");
        waiter.await.expect("waiter task");
    }
}
