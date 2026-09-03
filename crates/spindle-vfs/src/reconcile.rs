//! Heals DB-vs-filesystem skew in the upload ledger (td-2db67d). `Store::reconcile_upload_counters`
//! (`crate::store`) only recomputes the two running quota counters *from* the `uploaded_files`
//! ledger — it never touches disk, so it cannot notice a crash between a filesystem op and its
//! ledger write, or an owner deleting/resizing an uploaded file directly on the real filesystem
//! (out of band, never through a VFS RPC call). That is the gap this module closes.
//!
//! # Why this is a composing function here, not a `Store` method
//!
//! Architecture confirmed by the user (td-2db67d session log, 2026-09-03): `Store` stays pure
//! DB — see the `store` module doc comment's own framing. Healing DB-vs-disk skew needs
//! `confine`'s real filesystem access (to open the share root and stat/resolve real paths) *and*
//! `store`'s ledger methods, and `spindle-vfs` is the one crate that owns both, so
//! [`reconcile_uploads_against_disk`] lives here rather than growing `Store` a filesystem
//! dependency it has never had.
//!
//! # Why this is not the rejected directory walk
//!
//! The rejected idea was walking a share's real filesystem to *discover* files: unbounded work,
//! and no way to attribute a discovered file to an uploader. This sweep is the inverse: it starts
//! from [`crate::store::Store::list_uploads`] — a bounded worklist with the uploader already
//! attached to every row — and stats each one. Cost is `O(ledger rows)`, with zero directory
//! discovery.
//!
//! # A file on disk with no ledger row is IGNORED — read this before "fixing" it
//!
//! **This sweep never discovers files. It only walks the ledger.** Owner-placed content living on
//! a share's real filesystem, uploaded through no VFS RPC call, has no `uploaded_files` row and is
//! deliberately excluded from upload-quota accounting (`crate::store::mod`'s upload-ledger module
//! comment; `schema::SCHEMA_V6`'s doc comment) — DESIGN.md's quota rules are about the upload path
//! specifically, not a share's total on-disk footprint. **Do not** add a branch here that walks a
//! share's real directory tree looking for untracked files "to be thorough" — that reintroduces
//! the unbounded, unattributable directory walk this ticket explicitly rejected, and it would
//! silently start overcounting an owner's own files against nobody's quota (there is no uploader
//! to attribute them to). If a file has no ledger row, this sweep must not move any counter for it,
//! full stop.
//!
//! # Fold-aware resolution, not a literal stat
//!
//! Every row is resolved via [`crate::confine::resolve_folded_path`], not a literal
//! [`crate::confine::stat_through_dir`] on `row.subpath` directly. `stat_through_dir` is a literal
//! `Dir::open_with` — the OS resolves it, so it folds names on case-insensitive filesystems
//! (macOS, Windows) and does not on Linux. A row whose ledger `subpath` spelling has drifted from
//! the real dirent (a pre-fix `finalize_upload` recording the requested spelling instead of the
//! landed one, or an out-of-band rename) would stat as `NotFound` on Linux and be indistinguishable
//! from a genuinely deleted file — this sweep would then delete the row and refund the uploader
//! for a file that is still sitting right there on disk. `resolve_folded_path` is what makes
//! "genuinely gone" and "present under a different spelling" distinguishable everywhere, not just
//! on the platforms whose filesystem happens to fold names for us.

use crate::confine::{self, ConfineError};
use crate::model::Share;
use crate::store::{Store, StoreError};
use thiserror::Error;

/// Errors from [`reconcile_uploads_against_disk`] itself (opening the share root, or a `Store`
/// failure). Per-row resolution/stat problems are *not* reported this way — they are recorded in
/// [`ReconcileReport::unresolved`] so one bad row cannot abort healing every other row in the same
/// sweep.
#[derive(Debug, Error)]
pub enum ReconcileError {
    /// The share's real root could not be opened as a `cap-std` capability at all — nothing in
    /// this share can be swept.
    #[error("could not open share root for reconciliation: {0}")]
    Confine(#[from] ConfineError),

    /// A `Store` operation (listing the ledger, removing rows, or recording a resize) failed.
    #[error("store error during reconciliation: {0}")]
    Store(#[from] StoreError),
}

/// What [`reconcile_uploads_against_disk`] did, so the caller can audit a sweep instead of trusting
/// a bare success. Every field is a plain count/total — no per-row detail beyond
/// [`ReconcileReport::unresolved`], which needs the offending subpath to be actionable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Ledger rows deleted because [`crate::confine::resolve_folded_path`] found no chain of
    /// fold-matching dirents leading to them — the file is genuinely gone. Each removal already
    /// refunded its uploader's counter and decremented the share's counter, via
    /// [`crate::store::Store::remove_uploads_under`]'s single transaction.
    pub rows_removed: usize,

    /// Total bytes released back to quota accounting by `rows_removed` rows — the sum of each
    /// removed row's *ledger* `bytes` value (how much headroom deleting them freed). This does
    /// not fold in `rows_resized`'s deltas, which can be negative (file shrank, bytes freed) or
    /// positive (file grew, bytes consumed) — see [`crate::store::Store::record_upload`]'s doc
    /// comment for exactly how a resize moves the two counters.
    pub bytes_reclaimed: u64,

    /// Ledger rows whose real on-disk size no longer matched the ledger's recorded `bytes` and
    /// were corrected via [`crate::store::Store::record_upload`], which applies the resulting
    /// delta to both the uploader's and the share's running counters in one transaction. Passing
    /// the *resolved* (real, fold-aware) path to `record_upload` — not the row's original,
    /// possibly-stale `subpath` — also repairs a stale literal `subpath` column as a side effect;
    /// this is deliberate, not incidental (see [`reconcile_uploads_against_disk`]'s doc comment).
    pub rows_resized: usize,

    /// Rows this sweep could not settle one way or the other: a filesystem error other than "not
    /// found" (permission denied, a race where the file vanished between resolution and the
    /// follow-up stat, or a directory now occupying a name the ledger records as an uploaded
    /// file), captured as `(row.subpath, error message)`. Left completely
    /// untouched — neither deleted nor resized — rather than guessed at, so a caller can decide
    /// whether to retry, investigate, or ignore.
    pub unresolved: Vec<(String, String)>,
}

/// Walks every `uploaded_files` row for `share` (via [`crate::store::Store::list_uploads`]) and
/// reconciles each one against the real filesystem, healing drift between the ledger and disk:
///
/// 1. **Resolve** the row's `subpath` through [`crate::confine::resolve_folded_path`] against
///    `share.real_root`. `None` means no fold-matching dirent chain reaches it — the file is
///    genuinely gone: remove the row via [`crate::store::Store::remove_uploads_under`] (refunds
///    the uploader and decrements the share counter in one transaction) and count it.
/// 2. **Otherwise**, `stat` the *resolved* real path with [`crate::confine::stat_through_dir`] and
///    compare its size to the row's recorded `bytes`:
///    - equal: no-op.
///    - different: call [`crate::store::Store::record_upload`] with the actual size (and the
///      resolved path, repairing any stale `subpath` spelling for free), which applies the
///      resulting delta to both counters — the same resize semantics an ordinary overwrite uses.
///
/// A resolved path that turns out to be a **directory** is recorded in
/// [`ReconcileReport::unresolved`] and left alone rather than resized: a ledger row always
/// describes an uploaded file, and a directory's `metadata.len()` is its inode size, not a byte
/// count that means anything to a quota (td-836b2a tracks whether that case should instead
/// refund the uploader outright).
///
/// A stat failure after a successful resolution (a race, a permission error) does not abort the
/// whole sweep — it is recorded in [`ReconcileReport::unresolved`] and the row is left untouched,
/// so one bad row can't stop every other row in the same share from being healed.
///
/// **This sweep never discovers files with no ledger row — see the module doc comment's loud
/// warning before changing that.**
pub fn reconcile_uploads_against_disk(
    store: &Store,
    share: &Share,
) -> Result<ReconcileReport, ReconcileError> {
    let dir = confine::open_share_root(&share.real_root)?;
    let rows = store.list_uploads(share.share_id)?;

    let mut report = ReconcileReport::default();

    for row in rows {
        let resolution = confine::resolve_folded_path(&dir, &row.subpath);
        let resolved_path = match resolution {
            Ok(Some(path)) => path,
            Ok(None) => {
                // Genuinely gone: heal by deleting the ledger row, which refunds the uploader and
                // decrements the share counter in one transaction.
                let removed = store.remove_uploads_under(share.share_id, &row.subpath)?;
                report.rows_removed += removed.len();
                report.bytes_reclaimed += removed.iter().map(|(_, bytes)| bytes).sum::<u64>();
                continue;
            }
            Err(e) => {
                report.unresolved.push((row.subpath.clone(), e.to_string()));
                continue;
            }
        };

        match confine::stat_through_dir(&dir, &resolved_path) {
            Ok(metadata) => {
                // A ledger row always describes an uploaded *file*. If a directory now occupies
                // that name — the owner deleted the file out of band and created a directory
                // spelled the same way — then `metadata.len()` is the directory inode's own size
                // (96 on APFS, 4096 on ext4, entirely filesystem-dependent), not any quantity of
                // uploaded bytes. Resizing the row to it would write a meaningless number straight
                // into both quota counters. Record it as unresolved and leave the row alone: the
                // uploaded file is arguably gone and its uploader arguably owed a refund, but that
                // is a semantic call this sweep should not make silently (td-836b2a).
                if metadata.is_dir() {
                    report.unresolved.push((
                        row.subpath.clone(),
                        format!(
                            "a directory now occupies {resolved_path:?}, which the ledger \
                             records as an uploaded file; refusing to resize the row to a \
                             directory's inode size"
                        ),
                    ));
                    continue;
                }
                let actual_size = metadata.len();
                if actual_size != row.bytes {
                    store.record_upload(
                        share.share_id,
                        row.member_id,
                        &resolved_path,
                        actual_size,
                    )?;
                    report.rows_resized += 1;
                }
            }
            Err(e) => {
                report.unresolved.push((row.subpath.clone(), e.to_string()));
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MemberId, ShareFlags};
    use spindle_core::Fingerprint;
    use tempfile::tempdir;

    /// Shared fixture: an on-disk share root plus a store with one upload-enabled share and two
    /// distinct members, mirroring `store::tests::upload_ledger_fixture` but returning the
    /// `Share` model value `reconcile_uploads_against_disk` needs, and the real root `PathBuf`
    /// tests write/delete/truncate files under directly.
    fn fixture() -> (tempfile::TempDir, Store, Share, MemberId, MemberId) {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        std::fs::create_dir_all(&root).expect("mkdir share root");
        let store = Store::open_in_memory().expect("open store");
        let share_id = store
            .add_share(
                "Drop",
                "Drop",
                &root,
                ShareFlags {
                    allow_upload: true,
                    ..ShareFlags::default()
                },
                &[],
                0,
            )
            .expect("add_share");
        let member_a = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
            .expect("add_member alex");
        let member_b = store
            .add_member(Fingerprint::of_parts(&[b"blair"]), "Blair", 0)
            .expect("add_member blair");
        let share = store
            .get_share(share_id)
            .expect("get_share")
            .expect("share must exist");
        (sandbox, store, share, member_a, member_b)
    }

    #[test]
    fn missing_file_drops_row_refunds_uploader_and_decrements_share() {
        let (sandbox, store, share, member_a, _member_b) = fixture();
        let real_path = sandbox.path().join("share/gone.bin");
        std::fs::write(&real_path, vec![0u8; 500]).expect("write file");
        store
            .record_upload(share.share_id, member_a, "gone.bin", 500)
            .expect("record_upload");
        assert_eq!(store.member_upload_bytes(member_a).unwrap(), 500);
        assert_eq!(store.share_upload_bytes(share.share_id).unwrap(), 500);

        // Delete the file out of band, directly on the real filesystem.
        std::fs::remove_file(&real_path).expect("delete file");

        let report = reconcile_uploads_against_disk(&store, &share).expect("reconcile");
        assert_eq!(report.rows_removed, 1);
        assert_eq!(report.bytes_reclaimed, 500);
        assert_eq!(report.rows_resized, 0);
        assert!(report.unresolved.is_empty());

        assert_eq!(
            store.member_upload_bytes(member_a).unwrap(),
            0,
            "the uploader must be refunded"
        );
        assert_eq!(
            store.share_upload_bytes(share.share_id).unwrap(),
            0,
            "the share counter must be decremented"
        );
        assert_eq!(
            store.list_uploads(share.share_id).unwrap(),
            Vec::new(),
            "the ledger row must be gone"
        );
    }

    #[test]
    fn size_grew_resizes_row_and_adjusts_both_counters_upward() {
        let (sandbox, store, share, member_a, _member_b) = fixture();
        let real_path = sandbox.path().join("share/grew.bin");
        std::fs::write(&real_path, vec![0u8; 100]).expect("write file");
        store
            .record_upload(share.share_id, member_a, "grew.bin", 100)
            .expect("record_upload");

        // The owner appends bytes directly on the real filesystem, out of band.
        std::fs::write(&real_path, vec![0u8; 900]).expect("grow file");

        let report = reconcile_uploads_against_disk(&store, &share).expect("reconcile");
        assert_eq!(report.rows_resized, 1);
        assert_eq!(report.rows_removed, 0);
        assert!(report.unresolved.is_empty());

        assert_eq!(store.member_upload_bytes(member_a).unwrap(), 900);
        assert_eq!(store.share_upload_bytes(share.share_id).unwrap(), 900);
        let rows = store.list_uploads(share.share_id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bytes, 900);
    }

    #[test]
    fn size_shrank_resizes_row_and_adjusts_both_counters_downward() {
        let (sandbox, store, share, member_a, _member_b) = fixture();
        let real_path = sandbox.path().join("share/shrank.bin");
        std::fs::write(&real_path, vec![0u8; 1000]).expect("write file");
        store
            .record_upload(share.share_id, member_a, "shrank.bin", 1000)
            .expect("record_upload");

        // The owner truncates the file directly on the real filesystem, out of band.
        std::fs::write(&real_path, vec![0u8; 40]).expect("truncate file");

        let report = reconcile_uploads_against_disk(&store, &share).expect("reconcile");
        assert_eq!(report.rows_resized, 1);
        assert_eq!(report.rows_removed, 0);

        assert_eq!(store.member_upload_bytes(member_a).unwrap(), 40);
        assert_eq!(store.share_upload_bytes(share.share_id).unwrap(), 40);
        let rows = store.list_uploads(share.share_id).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bytes, 40);
    }

    #[test]
    fn matching_size_is_a_no_op() {
        let (sandbox, store, share, member_a, _member_b) = fixture();
        let real_path = sandbox.path().join("share/steady.bin");
        std::fs::write(&real_path, vec![0u8; 250]).expect("write file");
        store
            .record_upload(share.share_id, member_a, "steady.bin", 250)
            .expect("record_upload");

        let report = reconcile_uploads_against_disk(&store, &share).expect("reconcile");
        assert_eq!(
            report,
            ReconcileReport {
                rows_removed: 0,
                bytes_reclaimed: 0,
                rows_resized: 0,
                unresolved: Vec::new(),
            },
            "nothing should move when the on-disk size already matches the ledger"
        );
        assert_eq!(store.member_upload_bytes(member_a).unwrap(), 250);
        assert_eq!(store.share_upload_bytes(share.share_id).unwrap(), 250);
    }

    /// An uploaded file replaced out of band by a *directory* of the same name must not be
    /// "resized" to that directory's inode size. `metadata.len()` on a directory is a
    /// filesystem-dependent artifact (96 on APFS, 4096 on ext4) with no relationship to any
    /// uploaded byte count, so writing it into the quota counters would be a meaningless number
    /// in exactly the place this sweep exists to keep honest. The row is left untouched and
    /// reported, rather than silently refunded — td-836b2a tracks that semantic decision.
    #[test]
    fn a_directory_occupying_a_ledger_rows_name_is_reported_not_resized() {
        let (sandbox, store, share, member_a, _member_b) = fixture();
        std::fs::create_dir(sandbox.path().join("share/report.txt")).expect("mkdir over the name");
        std::fs::write(sandbox.path().join("share/report.txt/inner"), b"junk").expect("write");
        store
            .record_upload(share.share_id, member_a, "report.txt", 400)
            .expect("record_upload");

        let report = reconcile_uploads_against_disk(&store, &share).expect("reconcile");
        assert_eq!(report.rows_removed, 0, "the row must not be removed");
        assert_eq!(report.rows_resized, 0, "the row must not be resized");
        assert_eq!(
            report.unresolved.len(),
            1,
            "the directory-over-a-file case must be reported to the caller"
        );
        assert_eq!(report.unresolved[0].0, "report.txt");

        // Neither counter moved: the ledger still says 400 bytes, not the directory's inode size.
        assert_eq!(store.member_upload_bytes(member_a).unwrap(), 400);
        assert_eq!(store.share_upload_bytes(share.share_id).unwrap(), 400);
    }

    #[test]
    fn file_with_no_ledger_row_is_provably_untouched() {
        let (sandbox, store, share, member_a, _member_b) = fixture();
        // A tracked file, so the ledger and counters aren't both trivially empty.
        let tracked = sandbox.path().join("share/tracked.bin");
        std::fs::write(&tracked, vec![0u8; 10]).expect("write tracked file");
        store
            .record_upload(share.share_id, member_a, "tracked.bin", 10)
            .expect("record_upload");

        // Owner-placed content: exists on disk, was never uploaded through this crate's upload
        // path, and therefore has no `uploaded_files` row at all.
        let untracked = sandbox.path().join("share/owner-placed.bin");
        std::fs::write(&untracked, vec![0u8; 999_999]).expect("write untracked file");

        let before_member = store.member_upload_bytes(member_a).unwrap();
        let before_share = store.share_upload_bytes(share.share_id).unwrap();

        let report = reconcile_uploads_against_disk(&store, &share).expect("reconcile");
        assert_eq!(
            report,
            ReconcileReport {
                rows_removed: 0,
                bytes_reclaimed: 0,
                rows_resized: 0,
                unresolved: Vec::new(),
            },
            "an untracked file must not move the sweep's own report at all"
        );

        assert_eq!(
            store.member_upload_bytes(member_a).unwrap(),
            before_member,
            "an untracked file must never move a quota counter"
        );
        assert_eq!(
            store.share_upload_bytes(share.share_id).unwrap(),
            before_share,
            "an untracked file must never move a quota counter"
        );
        assert!(
            untracked.exists(),
            "the sweep must never touch a file it has no ledger row for"
        );
        assert_eq!(
            store.list_uploads(share.share_id).unwrap().len(),
            1,
            "no ledger row must be invented for the untracked file"
        );
    }

    #[test]
    fn post_sweep_counters_agree_with_reconcile_upload_counters() {
        let (sandbox, store, share, member_a, member_b) = fixture();

        // A mix of every skew case at once, across both members.
        let gone = sandbox.path().join("share/gone.bin");
        std::fs::write(&gone, vec![0u8; 300]).expect("write");
        store
            .record_upload(share.share_id, member_a, "gone.bin", 300)
            .expect("record_upload");
        std::fs::remove_file(&gone).expect("delete");

        let resized = sandbox.path().join("share/resized.bin");
        std::fs::write(&resized, vec![0u8; 50]).expect("write");
        store
            .record_upload(share.share_id, member_b, "resized.bin", 50)
            .expect("record_upload");
        std::fs::write(&resized, vec![0u8; 700]).expect("grow");

        let steady = sandbox.path().join("share/steady.bin");
        std::fs::write(&steady, vec![0u8; 20]).expect("write");
        store
            .record_upload(share.share_id, member_a, "steady.bin", 20)
            .expect("record_upload");

        reconcile_uploads_against_disk(&store, &share).expect("reconcile");

        let member_a_before = store.member_upload_bytes(member_a).unwrap();
        let member_b_before = store.member_upload_bytes(member_b).unwrap();
        let share_before = store.share_upload_bytes(share.share_id).unwrap();

        store
            .reconcile_upload_counters()
            .expect("reconcile_upload_counters");

        assert_eq!(
            store.member_upload_bytes(member_a).unwrap(),
            member_a_before
        );
        assert_eq!(
            store.member_upload_bytes(member_b).unwrap(),
            member_b_before
        );
        assert_eq!(
            store.share_upload_bytes(share.share_id).unwrap(),
            share_before
        );
    }

    /// The case this whole module exists for: a ledger row whose stored spelling differs in case
    /// from the real dirent must be *resolved*, not deleted. A literal, non-fold-aware stat would
    /// see `NotFound` on a case-sensitive filesystem and destroy this row's accounting — refunding
    /// the uploader for a file that is still sitting right there on disk.
    #[test]
    fn case_differing_stored_spelling_is_resolved_not_deleted() {
        let (sandbox, store, share, member_a, _member_b) = fixture();
        let real_path = sandbox.path().join("share/Photo.JPG");
        std::fs::write(&real_path, vec![0u8; 777]).expect("write real file");
        // The ledger row is deliberately written with a different-case spelling than what's on
        // disk (e.g. a pre-fix `finalize_upload` recording the requested spelling, or an
        // out-of-band rename of the real dirent's case after the row was written).
        store
            .record_upload(share.share_id, member_a, "photo.jpg", 777)
            .expect("record_upload");

        let report = reconcile_uploads_against_disk(&store, &share).expect("reconcile");
        assert_eq!(
            report.rows_removed, 0,
            "a case-differing spelling must resolve to the real file, not read as missing"
        );
        assert!(report.unresolved.is_empty());

        assert_eq!(
            store.member_upload_bytes(member_a).unwrap(),
            777,
            "the uploader must not be refunded for a file that still exists"
        );
        assert_eq!(store.share_upload_bytes(share.share_id).unwrap(), 777);
        assert_eq!(
            store.list_uploads(share.share_id).unwrap().len(),
            1,
            "the ledger row must survive"
        );
    }
}
