//! Production callers for the two upload-ledger reconcile paths (td-042e4f).
//!
//! Both paths were correct and tested but had no caller in the shipped binary:
//! [`spindle_vfs::store::Store::reconcile_upload_counters`] (ledger -> counters) and
//! [`spindle_vfs::reconcile::reconcile_uploads_against_disk`] (disk -> ledger). They are not
//! interchangeable, and this module deliberately gives them different surfaces:
//!
//! - **The disk sweep is scheduled.** DB-vs-filesystem skew has genuine ongoing sources: a crash
//!   between a filesystem operation and its ledger write, or the owner deleting/resizing an
//!   uploaded file directly on the real filesystem, out of band. A configurable interval
//!   (`SPINDLE_HOST_RECONCILE_INTERVAL_SECS` / `--reconcile-interval-secs`) bounds how long that
//!   skew can last.
//! - **The counter reconcile is operator-only.** Ledger-vs-counter drift is impossible by
//!   construction — both counter rows move in the same `Immediate` transaction as the ledger write
//!   — so scheduling it would be maintenance for a bug that cannot happen, not for ongoing skew.
//!   It is a repair tool: run it once, deliberately, with `SPINDLE_HOST_RECONCILE_ONCE` /
//!   `--reconcile-once`.
//!
//! Both surfaces are in this library module rather than in `main.rs` so the wiring the binary runs
//! is the same code the tests here exercise. The binary keeps only config parsing and scheduling.
//!
//! # Not per client connect
//!
//! Nothing here is called per connect. `reconcile_upload_counters` is whole-database (neither
//! `UPDATE` has a `WHERE`) and a connect carries no signal that drift occurred; the disk sweep is
//! `O(ledger rows)` per share. A client connecting is not evidence that either should run.
//!
//! # Serialization with live uploads, and the one-shot's host-stopped rule
//!
//! SQLite's write lock is not enough on its own. The sweep observes the filesystem and repairs the
//! ledger *later* (`remove_upload_row` / `record_upload`), while an upload commit renames its file
//! into place and only then inserts the ledger row; nothing in SQLite serializes that pair. Without
//! an in-process lock, a sweep could decide an old row is gone, a commit could replace it, and the
//! sweep's key-only delete would then remove the *new* row — leaving a file on disk with no ledger
//! row and permanently refunded quota. The mirror case is a stale size overwriting a newer ledger
//! value.
//!
//! The **scheduled** sweep therefore takes [`UploadLedgerLocks`]'s per-share lock around each
//! share's sweep, and every session's `UploadCommit` takes the same lock across
//! `finalize_upload` + `record_upload` + the audit append (see
//! `spindle_host_core::upload_locks`). Both run in the same process, so they genuinely serialize.
//!
//! `--reconcile-once` runs in a **separate process** and cannot share that lock. An operator must
//! run it with the host stopped; SQLite still prevents database corruption, so the residual risk
//! is exactly the filesystem/ledger interleaving the in-process lock closes.
//!
//! # Exclusive-write-lock interaction
//!
//! The scheduled sweep opens its **own** [`Store`] connection each time, separate from the
//! connections `HostDaemon::run` serves sessions on. Every repair it makes — each row removal or
//! resize — takes an `Immediate` transaction (`Store::remove_upload_row` / `Store::record_upload`),
//! which takes SQLite's write lock up front. While that transaction is open, a session write on
//! another connection waits; the sweep therefore can briefly block session writes in proportion to
//! the number of ledger rows it has to repair, not to the share's total size. It never holds a
//! transaction across the whole sweep: one transaction per repaired row. `--reconcile-once` has
//! the same interaction, and an operator running it against a live host would see it even if the
//! in-process lock did not exist — which is one more reason its rule is "host stopped".
//!
//! # Redaction
//!
//! Log lines here carry counts and the share's host-local numeric `share_id`. They never carry the
//! share's real root, a ledger `subpath`, or a member identifier — `ReconcileReport::unresolved`
//! holds `(subpath, message)` pairs and is logged only as a count. A per-share failure logs a
//! static reason, never the error's `Display`: `ReconcileError` wraps `ConfineError`/`StoreError`,
//! whose text can embed the share root's path.

use std::path::{Path, PathBuf};
use std::time::Duration;

use spindle_host_core::UploadLedgerLocks;
use spindle_vfs::model::Share;
use spindle_vfs::reconcile::{reconcile_uploads_against_disk, ReconcileError, ReconcileReport};
use spindle_vfs::store::{Store, StoreError};
use tokio::sync::watch;

/// Shortest interval [`run_scheduled_disk_sweep`] will honor, in seconds.
///
/// The config surface (`SPINDLE_HOST_RECONCILE_INTERVAL_SECS`) validates against this same value;
/// the clamp inside the scheduler is the library-level backstop for a caller that bypasses the
/// parser. A sweep is `O(ledger rows)` per share and takes an exclusive write transaction per
/// repaired row on its own connection, so it can briefly block session writes. Its reason to run is
/// skew measured in "since the last crash or out-of-band edit", not sub-minute events; zero is not
/// "disabled" (unset is) and is clamped here rather than spinning ticks continuously.
pub const MIN_SWEEP_INTERVAL_SECS: u64 = 60;

/// Applies [`MIN_SWEEP_INTERVAL_SECS`] to a caller-supplied interval. Extracted so the clamp is
/// directly testable (a paused-clock scheduler test asserting "no tick yet" is inherently racy:
/// an unclamped tick may simply not have completed at the assertion point).
fn clamped_interval(interval: Duration) -> Duration {
    interval.max(Duration::from_secs(MIN_SWEEP_INTERVAL_SECS))
}

/// Totals from one disk sweep across every share in the store.
///
/// Every field is a count or byte total — deliberately no per-row detail. The one actionable
/// per-row value in [`ReconcileReport`], `unresolved`, is reduced to its count here for the same
/// reason the module doc comment gives: it carries subpaths.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskSweepTotals {
    /// Shares whose ledger was compared against disk without an error.
    pub shares_swept: usize,
    /// Shares whose sweep failed outright (e.g. the share root could not be opened). One failed
    /// share never aborts the remaining shares.
    pub shares_failed: usize,
    /// Ledger rows deleted because the uploaded file was genuinely gone (or a directory now
    /// occupied its name).
    pub rows_removed: usize,
    /// Sum of the removed rows' ledger `bytes` — the headroom returned to quota accounting.
    pub bytes_reclaimed: u64,
    /// Ledger rows corrected to the file's real on-disk size.
    pub rows_resized: usize,
    /// Rows this sweep could not resolve either way (a permission error, a race). Left untouched.
    pub unresolved: usize,
}

impl DiskSweepTotals {
    fn record(&mut self, report: &ReconcileReport) {
        self.shares_swept += 1;
        self.rows_removed += report.rows_removed;
        self.bytes_reclaimed += report.bytes_reclaimed;
        self.rows_resized += report.rows_resized;
        self.unresolved += report.unresolved.len();
    }
}

/// What one `--reconcile-once` run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OneShotReport {
    /// Totals from the disk sweep across every share.
    pub disk: DiskSweepTotals,
    /// `true` when `Store::reconcile_upload_counters` completed. `false` means the ledger repairs
    /// stand (they already committed transaction by transaction), but the two counter tables were
    /// not recomputed.
    pub counters_reconciled: bool,
}

impl OneShotReport {
    /// `true` when the run must exit `FAILURE`: a share could not be swept, or the counter
    /// reconcile failed. A single failed share does not stop the other shares from being healed,
    /// but it does make the operator action unsuccessful.
    pub fn failed(&self) -> bool {
        self.disk.shares_failed > 0 || !self.counters_reconciled
    }
}

/// Everything [`reconcile_once`] can reject.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileOnceError {
    /// The configured store path does not exist.
    ///
    /// [`Store::open`] **creates and migrates** a fresh database when the path is absent. For a
    /// serving host that is the intended first-start behavior, but for an operator repair tool it
    /// turns the worst possible mistake — a mistyped or unmounted `SPINDLE_HOST_STORE` — into the
    /// most reassuring possible output: a brand-new empty store, "0 shares swept", and a
    /// reconciled-counter success. The one-shot path therefore refuses before opening, and never
    /// creates the file.
    #[error("host store does not exist at the configured path: {0}")]
    StoreAbsent(PathBuf),

    /// Opening the existing store, or listing its shares, failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Opens the existing host store at `store_path` and runs one full operator repair pass: the disk
/// sweep for every share, then the ledger -> counters reconcile.
///
/// The two steps together are what `--reconcile-once` runs. The disk sweep is first because it
/// changes the ledger; recomputing the counters afterwards is what makes them agree with the
/// repaired ledger. (The sweep's own row removals/resizes already adjust both counters per row, so
/// the counter reconcile is normally a no-op — it is here as the deliberate repair step for the
/// separate, bug-only drift class, not because the sweep needs it.)
///
/// **The host must be stopped.** This path runs in its own process and cannot share the
/// in-process per-share upload lock (`spindle_host_core::upload_locks`) that the scheduled sweep
/// and every live `UploadCommit` use. SQLite still prevents database corruption, but a commit
/// interleaving with this sweep can be mis-reconciled (a fresh ledger row removed, or a newer size
/// overwritten) — exactly the race the in-process lock closes. That is why the operator action is
/// documented as "run with the host stopped", not merely as "needs no NATS or seed".
///
/// **The store must already exist.** An absent path is [`ReconcileOnceError::StoreAbsent`], never a
/// freshly migrated empty database — see that variant's doc comment. It is opened with
/// [`Store::open_for_reconcile`], which additionally refuses a zero-byte or foreign database and
/// skips the persisted-share overlap re-check that would otherwise make a deleted share root block
/// every share's repair. A serving host creates its store on first start; an operator repairing
/// one should be pointing at that file.
///
/// A per-share disk-sweep failure is logged and counted, never fatal to the other shares. Only
/// failing to open the store, or to list its shares, is returned as `Err`.
pub fn reconcile_once(store_path: &Path) -> Result<OneShotReport, ReconcileOnceError> {
    // Checked before opening, so an absent path gets this operator-facing error rather than a raw
    // SQLite "unable to open" message. `exists()` follows symlinks, matching what the store
    // constructors do; a directory, zero-byte file, or foreign database is refused by
    // `open_for_reconcile` below.
    if !store_path.exists() {
        return Err(ReconcileOnceError::StoreAbsent(store_path.to_path_buf()));
    }
    let store = Store::open_for_reconcile(store_path)?;
    let disk = sweep_uploads_against_disk(&store)?;
    let counters_reconciled = match store.reconcile_upload_counters() {
        Ok(()) => true,
        Err(_) => {
            // Deliberately not `%error`: StoreError's Display can carry a filesystem path.
            tracing::error!(
                "recomputing the upload counters from the ledger failed; the per-share ledger \
                 repairs above are already committed, but the two counter tables were not \
                 reconciled"
            );
            false
        }
    };

    tracing::info!(
        shares_swept = disk.shares_swept,
        shares_failed = disk.shares_failed,
        rows_removed = disk.rows_removed,
        bytes_reclaimed = disk.bytes_reclaimed,
        rows_resized = disk.rows_resized,
        unresolved = disk.unresolved,
        counters_reconciled = counters_reconciled,
        "one-shot upload-ledger reconciliation finished"
    );

    Ok(OneShotReport {
        disk,
        counters_reconciled,
    })
}

/// Sweeps every share's upload ledger in `store` against its real filesystem root.
///
/// This is the disk -> ledger half only; it never recomputes the two counter tables. The per-share
/// loop logs counts and continues past a failed share, so one unreadable share root cannot stop
/// the remaining shares from being healed.
///
/// This is the **one-shot** form: it takes no upload lock, because `--reconcile-once` runs in a
/// separate process from the host and cannot share one (see the module doc comment). The scheduled
/// sweep uses [`sweep_uploads_against_disk_locked`] instead.
pub fn sweep_uploads_against_disk(store: &Store) -> Result<DiskSweepTotals, StoreError> {
    let shares = store.list_shares()?;
    Ok(sweep_shares(store, &shares, None))
}

/// The scheduled sweep's form: as [`sweep_uploads_against_disk`], but each share's sweep runs
/// under [`UploadLedgerLocks`]'s lock for that share — the same lock every live `UploadCommit`
/// holds across `finalize_upload` + `record_upload`. That is what stops the sweep from deleting a
/// ledger row a commit inserted after the sweep's filesystem observation, and from overwriting a
/// newer size with a stale one.
///
/// **Must be called from a blocking context** (the scheduler's `spawn_blocking` tick):
/// [`UploadLedgerLocks::lock_blocking`] panics inside an asynchronous execution context.
fn sweep_uploads_against_disk_locked(
    store: &Store,
    locks: &UploadLedgerLocks,
) -> Result<DiskSweepTotals, StoreError> {
    let shares = store.list_shares()?;
    Ok(sweep_shares(store, &shares, Some(locks)))
}

fn sweep_shares(
    store: &Store,
    shares: &[Share],
    locks: Option<&UploadLedgerLocks>,
) -> DiskSweepTotals {
    let mut totals = DiskSweepTotals::default();
    for share in shares {
        // The guard covers the whole per-share observation+repair pair, exactly the window a
        // concurrent upload commit serializes against (see `spindle_host_core::upload_locks`).
        let _upload_guard = locks.map(|locks| locks.lock_blocking(share.share_id));
        match reconcile_uploads_against_disk(store, share) {
            Ok(report) => {
                totals.record(&report);
                tracing::info!(
                    share_id = share.share_id.0,
                    rows_removed = report.rows_removed,
                    bytes_reclaimed = report.bytes_reclaimed,
                    rows_resized = report.rows_resized,
                    unresolved = report.unresolved.len(),
                    "reconciled one share's upload ledger against the filesystem"
                );
            }
            Err(error) => {
                totals.shares_failed += 1;
                tracing::error!(
                    share_id = share.share_id.0,
                    reason = reconcile_failure_reason(&error),
                    "could not reconcile this share's upload ledger against the filesystem; \
                     continuing with the remaining shares"
                );
            }
        }
    }
    totals
}

/// A static description of a per-share failure. `ReconcileError`'s `Display` is never interpolated
/// into a log line here — see the module doc comment's redaction section.
fn reconcile_failure_reason(error: &ReconcileError) -> &'static str {
    match error {
        ReconcileError::Confine(_) => "the share root could not be opened",
        ReconcileError::Store(_) => "a store operation failed during the sweep",
    }
}

/// Runs the scheduled disk -> ledger sweep until `stop` says this host is shutting down.
///
/// Each tick opens a **fresh** [`Store`] connection with [`Store::open_for_reconcile`] (the repair
/// constructor: it refuses a foreign or empty database and skips the serving-path overlap
/// re-check), takes each share's [`UploadLedgerLocks`] lock, and sweeps that share's ledger
/// against disk. It deliberately does **not** call `reconcile_upload_counters`: that path is an
/// operator repair tool for a drift class that is impossible by construction, not routine
/// maintenance.
///
/// The open+sweep runs in [`tokio::task::spawn_blocking`], with its `JoinHandle` selected against
/// `stop.changed()`, so a dropped sender — the serving half of the binary returning — is observed
/// promptly even while a tick is running. If stop wins, this function returns immediately; a
/// blocking tick already in flight is detached and finishes on its own thread while the process
/// shuts down. Blocking filesystem work cannot be cancelled mid-share, and on shutdown there is
/// nothing left to serialize against.
///
/// `interval` is clamped up to [`MIN_SWEEP_INTERVAL_SECS`], so `Duration::ZERO` (or anything
/// shorter) does not spin ticks. The next tick starts one interval after the previous tick's
/// spawn, so a slow sweep delays the schedule rather than piling ticks up.
pub async fn run_scheduled_disk_sweep(
    store_path: PathBuf,
    interval: Duration,
    locks: UploadLedgerLocks,
    mut stop: watch::Receiver<bool>,
) {
    let interval = clamped_interval(interval);
    loop {
        tokio::select! {
            biased;
            changed = stop.changed() => {
                // `Err` is the sender having been dropped, which is how the serving half of the
                // binary reports shutdown. `true` is the explicit stop flag.
                if changed.is_err() || *stop.borrow() {
                    tracing::debug!("scheduled upload-ledger disk sweep stopping");
                    return;
                }
                continue;
            }
            _ = tokio::time::sleep(interval) => {}
        }

        let sweep = {
            let store_path = store_path.clone();
            let locks = locks.clone();
            tokio::task::spawn_blocking(move || sweep_tick(&store_path, &locks, interval))
        };

        tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    tracing::debug!(
                        "scheduled upload-ledger disk sweep stopping; an in-flight tick will \
                         finish on its blocking thread"
                    );
                    return;
                }
                continue;
            }
            result = sweep => {
                if let Err(error) = result {
                    // A `JoinError` here means the blocking tick panicked; the tick's own error
                    // paths log without content, so only the join failure kind is worth naming.
                    tracing::error!(
                        cancelled = error.is_cancelled(),
                        "scheduled upload-ledger disk sweep's blocking task failed; will retry on \
                         the next interval"
                    );
                }
            }
        }
    }
}

/// One scheduled tick: open the repair store, sweep every share under its upload lock, and log the
/// counts. Synchronous so the scheduler can run it in [`tokio::task::spawn_blocking`]; the
/// scheduler tests also call it directly to exercise exactly one tick.
fn sweep_tick(store_path: &Path, locks: &UploadLedgerLocks, interval: Duration) {
    match Store::open_for_reconcile(store_path) {
        Ok(store) => match sweep_uploads_against_disk_locked(&store, locks) {
            Ok(totals) => tracing::info!(
                shares_swept = totals.shares_swept,
                shares_failed = totals.shares_failed,
                rows_removed = totals.rows_removed,
                bytes_reclaimed = totals.bytes_reclaimed,
                rows_resized = totals.rows_resized,
                unresolved = totals.unresolved,
                interval_secs = interval.as_secs(),
                "scheduled upload-ledger disk sweep finished"
            ),
            // Listing shares failed; the per-share failures are already logged. Retry on the next
            // tick rather than stopping the schedule.
            Err(_) => tracing::error!(
                "scheduled upload-ledger disk sweep could not enumerate the store's shares; will \
                 retry on the next interval"
            ),
        },
        // A store connection held elsewhere can make this fail transiently; the schedule keeps
        // running and retries rather than killing the host.
        Err(_) => tracing::error!(
            "scheduled upload-ledger disk sweep could not open the host store; will retry on the \
             next interval"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use spindle_core::Fingerprint;
    use spindle_vfs::model::{MemberId, ShareFlags, ShareId};
    use tempfile::tempdir;

    use super::*;

    fn add_upload_share(store: &Store, root: &Path) -> ShareId {
        store
            .add_share(
                "Drop",
                "/drop",
                root,
                ShareFlags {
                    allow_upload: true,
                    ..ShareFlags::default()
                },
                &[],
                0,
            )
            .expect("add_share")
    }

    /// The one-shot flag path end to end, against a real temp store and a real temp share root:
    /// seed a share and a ledger row, delete the backing file out of band, then run the same
    /// `reconcile_once` the `--reconcile-once` flag calls. The row must be gone and **both**
    /// counter tables must agree with the repaired ledger.
    #[test]
    fn one_shot_sweep_removes_a_deleted_uploads_row_and_reconciles_both_counters() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        fs::create_dir_all(&root).expect("create share root");
        let store_path = sandbox.path().join("host.db");
        let real_path = root.join("gone.bin");

        let (share_id, member_id): (ShareId, MemberId) = {
            let store = Store::open(&store_path).expect("open store");
            let share_id = add_upload_share(&store, &root);
            let member_id = store
                .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
                .expect("add_member");
            fs::write(&real_path, vec![0u8; 500]).expect("write uploaded file");
            store
                .record_upload(share_id, member_id, "gone.bin", 500)
                .expect("record_upload");
            assert_eq!(store.member_upload_bytes(member_id).unwrap(), 500);
            assert_eq!(store.share_upload_bytes(share_id).unwrap(), 500);

            // Delete the file directly on disk, never through the VFS: the skew source this
            // sweep exists for.
            fs::remove_file(&real_path).expect("delete uploaded file");
            (share_id, member_id)
        };
        // The first `Store` is dropped here, so `reconcile_once` opens its own connection exactly
        // as the binary's one-shot path does.

        let report = reconcile_once(&store_path).expect("one-shot reconcile");

        assert_eq!(report.disk.shares_swept, 1);
        assert_eq!(report.disk.shares_failed, 0);
        assert_eq!(report.disk.rows_removed, 1);
        assert_eq!(report.disk.bytes_reclaimed, 500);
        assert_eq!(report.disk.rows_resized, 0);
        assert_eq!(report.disk.unresolved, 0);
        assert!(report.counters_reconciled);
        assert!(!report.failed());

        let store = Store::open(&store_path).expect("reopen store");
        assert!(
            store.list_uploads(share_id).unwrap().is_empty(),
            "the deleted file's ledger row must be gone"
        );
        assert_eq!(
            store.member_upload_bytes(member_id).unwrap(),
            0,
            "the uploader's counter must reflect the repaired ledger"
        );
        assert_eq!(
            store.share_upload_bytes(share_id).unwrap(),
            0,
            "the share's counter must reflect the repaired ledger"
        );
    }

    /// The one-shot repair must never create a store. `Store::open` would migrate a fresh empty
    /// database at an absent path, turning a mistyped or unmounted `SPINDLE_HOST_STORE` into the
    /// most reassuring possible output — "0 shares swept", counters reconciled, success.
    #[test]
    fn one_shot_refuses_a_missing_store_and_does_not_create_it() {
        let sandbox = tempdir().expect("tempdir");
        let store_path = sandbox.path().join("typo.db");

        match reconcile_once(&store_path) {
            Err(ReconcileOnceError::StoreAbsent(path)) => assert_eq!(path, store_path),
            other => panic!("expected StoreAbsent, got {other:?}"),
        }
        assert!(
            !store_path.exists(),
            "the one-shot repair must not create a fresh store at an absent path"
        );
    }

    /// A share that cannot be swept must be counted and must not stop the other shares from
    /// being healed; the run is still reported as failed so the exit code is `FAILURE`.
    #[test]
    fn one_failed_share_does_not_stop_the_remaining_shares() {
        let sandbox = tempdir().expect("tempdir");
        let good_root = sandbox.path().join("good");
        let broken_root = sandbox.path().join("broken");
        fs::create_dir_all(&good_root).expect("create good root");
        fs::create_dir_all(&broken_root).expect("create broken root");
        let store_path = sandbox.path().join("host.db");
        let gone = good_root.join("gone.bin");

        let (good_share, member_id) = {
            let store = Store::open(&store_path).expect("open store");
            let good_share = add_upload_share(&store, &good_root);
            store
                .add_share(
                    "Broken",
                    "/broken",
                    &broken_root,
                    ShareFlags {
                        allow_upload: true,
                        ..ShareFlags::default()
                    },
                    &[],
                    0,
                )
                .expect("add broken share");
            let member_id = store
                .add_member(Fingerprint::of_parts(&[b"blair"]), "Blair", 0)
                .expect("add_member");
            fs::write(&gone, vec![0u8; 40]).expect("write uploaded file");
            store
                .record_upload(good_share, member_id, "gone.bin", 40)
                .expect("record_upload");
            fs::remove_file(&gone).expect("delete uploaded file");
            (good_share, member_id)
        };
        // Delete the broken share's root out of band: the per-share sweep cannot open it, while
        // `Store::open_for_reconcile` still opens the store (it deliberately skips the
        // serving-path persisted-overlap re-check, which canonicalizes every root and would
        // otherwise make this — the exact skew the sweep exists to heal — unopenable).
        fs::remove_dir_all(&broken_root).expect("remove broken root");

        let report = reconcile_once(&store_path).expect("one-shot reconcile");

        assert_eq!(report.disk.shares_swept, 1);
        assert_eq!(report.disk.shares_failed, 1);
        assert_eq!(report.disk.rows_removed, 1);
        assert_eq!(report.disk.bytes_reclaimed, 40);
        assert!(report.counters_reconciled);
        assert!(
            report.failed(),
            "a failed share must make the operator action report failure"
        );

        // Reopen with the repair constructor: the serving constructor would (correctly) refuse this
        // store because the deliberately deleted share root fails its overlap re-check.
        let store = Store::open_for_reconcile(&store_path).expect("reopen store");
        assert!(store.list_uploads(good_share).unwrap().is_empty());
        assert_eq!(store.member_upload_bytes(member_id).unwrap(), 0);
    }

    /// One scheduled tick, run through the exact `sweep_tick` the scheduler calls: ledger-vs-disk
    /// skew is repaired (the stale size is corrected and both counters follow), while
    /// counter-table drift on a share with no ledger rows is left absolutely untouched — proof
    /// that the scheduled surface does **not** call `reconcile_upload_counters`.
    #[test]
    fn a_sweep_tick_repairs_ledger_drift_but_does_not_reconcile_counters() {
        let sandbox = tempdir().expect("tempdir");
        let root = sandbox.path().join("share");
        let other_root = sandbox.path().join("other");
        fs::create_dir_all(&root).expect("create share root");
        fs::create_dir_all(&other_root).expect("create other share root");
        let store_path = sandbox.path().join("host.db");
        let resized = root.join("resized.bin");

        let (share_id, member_id, other_share, other_member) = {
            let store = Store::open(&store_path).expect("open store");
            let share_id = add_upload_share(&store, &root);
            let member_id = store
                .add_member(Fingerprint::of_parts(&[b"alex"]), "Alex", 0)
                .expect("add_member");
            fs::write(&resized, vec![0u8; 100]).expect("write uploaded file");
            store
                .record_upload(share_id, member_id, "resized.bin", 100)
                .expect("record_upload");
            // The owner grows the file directly on disk: ledger says 100, disk says 250.
            fs::write(&resized, vec![0u8; 250]).expect("grow file out of band");

            // A second share/member with no ledger rows and deliberately drifted counters. A
            // counter reconcile would zero these; the disk sweep must not touch them.
            let other_share = store
                .add_share(
                    "Other",
                    "/other",
                    &other_root,
                    ShareFlags::default(),
                    &[],
                    0,
                )
                .expect("add other share");
            let other_member = store
                .add_member(Fingerprint::of_parts(&[b"blair"]), "Blair", 0)
                .expect("add_member");
            store
                .set_upload_counters_for_test(other_member, 999, other_share, 999)
                .expect("seed counter drift");
            (share_id, member_id, other_share, other_member)
        };

        sweep_tick(
            &store_path,
            &UploadLedgerLocks::new(),
            Duration::from_secs(MIN_SWEEP_INTERVAL_SECS),
        );

        let store = Store::open(&store_path).expect("reopen store");
        let rows = store.list_uploads(share_id).expect("list uploads");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].bytes, 250,
            "the disk sweep must repair the stale ledger size"
        );
        assert_eq!(
            store.member_upload_bytes(member_id).unwrap(),
            250,
            "the sweep's resize adjusts the uploader's counter by the same delta"
        );
        assert_eq!(store.share_upload_bytes(share_id).unwrap(), 250);
        assert_eq!(
            store.member_upload_bytes(other_member).unwrap(),
            999,
            "a scheduled tick must never reconcile the counter tables"
        );
        assert_eq!(
            store.share_upload_bytes(other_share).unwrap(),
            999,
            "a scheduled tick must never reconcile the share counter table"
        );
    }

    /// The serving half stops the sweep by dropping the `watch` sender it owns. The task must
    /// observe that promptly, without waiting for the next interval. Real time plus a timeout, so
    /// a failure is a bounded assertion rather than a hung test binary.
    #[tokio::test]
    async fn dropping_the_stop_sender_ends_the_scheduled_sweep() {
        let sandbox = tempdir().expect("tempdir");
        let store_path = sandbox.path().join("host.db");
        // The sweep's store-open path requires an existing Spindle store.
        drop(Store::open(&store_path).expect("create store"));

        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = tokio::spawn(run_scheduled_disk_sweep(
            store_path,
            Duration::from_secs(MIN_SWEEP_INTERVAL_SECS),
            UploadLedgerLocks::new(),
            stop_rx,
        ));

        tokio::task::yield_now().await;
        assert!(
            !handle.is_finished(),
            "the sweep must wait for its interval, not tick at startup"
        );

        drop(stop_tx);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("the scheduler must stop promptly after the sender is dropped")
            .expect("the scheduler task must not panic");
    }

    /// `Duration::ZERO` is clamped to [`MIN_SWEEP_INTERVAL_SECS`] inside the library, not treated
    /// as "tick continuously" or "disabled". Tested directly on the clamp itself: the earlier
    /// paused-clock version asserted "no tick after 59 s", which is racy — an unclamped tick may
    /// simply not have completed when the assertion ran.
    #[test]
    fn a_sub_minimum_interval_is_clamped_to_the_documented_floor() {
        let floor = Duration::from_secs(MIN_SWEEP_INTERVAL_SECS);
        assert_eq!(
            MIN_SWEEP_INTERVAL_SECS, 60,
            "the config parser uses this value"
        );
        assert_eq!(clamped_interval(Duration::ZERO), floor);
        assert_eq!(clamped_interval(Duration::from_secs(1)), floor);
        assert_eq!(clamped_interval(Duration::from_secs(59)), floor);
        assert_eq!(clamped_interval(floor), floor);
        assert_eq!(
            clamped_interval(Duration::from_secs(61)),
            Duration::from_secs(61),
            "an interval above the floor is left alone"
        );
    }
}
