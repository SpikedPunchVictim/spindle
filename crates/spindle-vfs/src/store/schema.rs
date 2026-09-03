//! Embedded schema migrations, applied via `PRAGMA user_version` (no external migration runner —
//! this crate must not gain a dependency beyond `rusqlite`). One numbered `&str` SQL constant per
//! schema version; [`migrate`] applies every version strictly greater than the connection's
//! current `user_version`, each inside its own transaction, and leaves `user_version` set to the
//! highest version applied. Versions are never edited after being shipped — a schema change is a
//! new numbered constant appended to [`MIGRATIONS`].

use super::StoreError;
use rusqlite::{Connection, TransactionBehavior};

/// Version 1 — the core host-authorization tables (DESIGN.md §A4b): members, devices, groups
/// (+ built-in `Owner`/`Members` seeded here so every fresh store has them from the first
/// connection, per "created at init"), member↔group assignment, shares, share-level exclusion
/// globs, entitlements, the idempotent invite-nonce CAS table (DESIGN.md §A4), and the single-row
/// `meta` table holding the two independent counters `cap_epoch`/`grants_version` (§A4's
/// two-counters rule — see `crate::store::Store::bump_cap_epoch` doc comment for the distinction).
const SCHEMA_V1: &str = r#"
CREATE TABLE meta (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    cap_epoch INTEGER NOT NULL DEFAULT 0,
    grants_version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO meta (id, cap_epoch, grants_version) VALUES (0, 0, 0);

CREATE TABLE members (
    member_id INTEGER PRIMARY KEY AUTOINCREMENT,
    root_fp BLOB NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('invited', 'active', 'revoked')),
    created INTEGER NOT NULL
);

CREATE TABLE devices (
    device_fp BLOB PRIMARY KEY,
    member_id INTEGER NOT NULL REFERENCES members(member_id),
    label TEXT NOT NULL,
    added INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

-- Built-in groups (DESIGN.md §A4b: "built-in Owner (implicit, all, not editable) and Members
-- (default, empty grants)"), seeded with fixed ids so `crate::store` can recognize them without a
-- lookup. Plain INTEGER PRIMARY KEY (not AUTOINCREMENT) so these explicit ids can be pre-seeded;
-- SQLite still assigns 3, 4, ... to subsequent auto (id-omitted) inserts of custom groups.
CREATE TABLE groups (
    group_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('owner', 'members', 'custom'))
);
INSERT INTO groups (group_id, name, kind) VALUES (1, 'Owner', 'owner');
INSERT INTO groups (group_id, name, kind) VALUES (2, 'Members', 'members');

CREATE TABLE member_groups (
    member_id INTEGER NOT NULL REFERENCES members(member_id),
    group_id INTEGER NOT NULL REFERENCES groups(group_id),
    PRIMARY KEY (member_id, group_id)
);

CREATE TABLE shares (
    share_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mount_path TEXT NOT NULL UNIQUE,
    real_root TEXT NOT NULL,
    read_only INTEGER NOT NULL DEFAULT 0,
    allow_upload INTEGER NOT NULL DEFAULT 0,
    show_hidden INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
);

CREATE TABLE share_excludes (
    share_id INTEGER NOT NULL REFERENCES shares(share_id),
    glob TEXT NOT NULL,
    PRIMARY KEY (share_id, glob)
);

CREATE TABLE entitlements (
    entitlement_id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES groups(group_id),
    share_id INTEGER NOT NULL REFERENCES shares(share_id),
    subpath TEXT NOT NULL,
    perms INTEGER NOT NULL,
    UNIQUE (group_id, share_id, subpath)
);

-- DESIGN.md §A4 idempotent invite redemption: `nonce` is the sole CAS key, mirroring
-- spindle-helper's `burned_admission_nonces` (`crates/spindle-helper/src/pg_store.rs`) shape —
-- `INSERT ... ON CONFLICT (nonce) DO NOTHING` then a read-back in the same transaction, done in
-- `crate::store::Store::burn_invite_nonce`.
CREATE TABLE invite_nonces (
    nonce BLOB PRIMARY KEY,
    member_id INTEGER NOT NULL,
    issued_cap BLOB NOT NULL,
    redeemed_at INTEGER NOT NULL
);
"#;

/// Version 2 — the tamper-evident audit chain (DESIGN.md §A4b "Audit log"). `audit_log.seq` is
/// `AUTOINCREMENT` so a deleted row's sequence number is never reused (SQLite tracks the
/// high-water mark in `sqlite_sequence` even across deletes), which is what lets
/// `crate::audit::Audit::verify_chain` distinguish "a row was deleted" from "the chain is merely
/// short" by watching for a gap rather than only a hash mismatch. `signed_heads.seq` is *not*
/// auto-generated — it is always set explicitly to the `audit_log.seq` value the signature covers.
const SCHEMA_V2: &str = r#"
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    member BLOB,
    device BLOB,
    action TEXT NOT NULL,
    virtual_path TEXT,
    bytes INTEGER,
    outcome TEXT NOT NULL,
    prev_hash BLOB NOT NULL,
    hash BLOB NOT NULL
);

-- No signer public key column, deliberately: DESIGN.md §A4b's audit-log signed-head tuple is
-- exactly `{seq, head_hash, ts, sig}` (`crate::audit`'s HeadSigner design brief). Persisting the
-- public key alongside the signature it verifies would let an attacker who can already edit this
-- row swap in their own keypair and a matching forged signature; `crate::audit::Audit::verify_head`
-- requires the caller to supply the expected public key from outside the database instead.
CREATE TABLE signed_heads (
    seq INTEGER PRIMARY KEY,
    head_hash BLOB NOT NULL,
    ts INTEGER NOT NULL,
    sig BLOB NOT NULL
);
"#;

/// Version 3 — Stage 6 slice 4 additions (DESIGN.md §A8 "transfer manager" / "received-file
/// policy"), flagged per the task brief as a real schema gap rather than resolved silently:
///
/// - `devices.sign_pk`: the device's Ed25519 signing public key, nullable (`ALTER TABLE ... ADD
///   COLUMN` requires a default for `NOT NULL`, and there is no sensible default for a key; a
///   `NULL` here means "no key on file", handled explicitly by `spindle-host-core` as "cannot
///   verify a manifest signed by this device", never as "skip verification"). See
///   `crate::model::Device::sign_pk`'s doc comment for why this was missing through slice 3 and
///   why slice 4 needs it (manifest-signature verification before an upload is moved into place).
/// - `member_upload_bytes` / `share_upload_bytes`: running byte counters backing DESIGN.md §A4b's
///   "quotas per member and per share". Deliberately scoped to bytes that moved through *this
///   crate's* upload path (an `upload_commit`), not a full recursive walk of on-disk usage — see
///   `crate::store::Store::adjust_member_upload_bytes`'s doc comment for the accounting model and
///   its documented limitation (a delete does not retroactively restore a *different* member's
///   counter, since no ownership ledger maps a real file back to whichever member uploaded it).
const SCHEMA_V3: &str = r#"
ALTER TABLE devices ADD COLUMN sign_pk BLOB;

CREATE TABLE member_upload_bytes (
    member_id INTEGER PRIMARY KEY REFERENCES members(member_id),
    bytes INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE share_upload_bytes (
    share_id INTEGER PRIMARY KEY REFERENCES shares(share_id),
    bytes INTEGER NOT NULL DEFAULT 0
);
"#;

/// Version 4 — connect-time authorization (DESIGN.md §A5 / `spindle-net`'s injected
/// `ConnectAuthorizer`): `devices.agree_pk`, the device's X25519 key-agreement public key,
/// alongside the `sign_pk` V3 already added. Nullable for the same reason `sign_pk` is (`ALTER
/// TABLE ... ADD COLUMN` requires a default for `NOT NULL`, and there is no sensible default for a
/// key) — rows written before this version have no value for it. A device row missing either key
/// half fails closed at authorization time: `spindle_core::identity::device_fp_of` shows
/// `device_fp` is the hash of exactly `(DEVICE_FP_DOMAIN, alg_id, sign_pk, agree_pk)`, so a
/// verifier needs *both* halves to recompute it and check the binding — the same check
/// `spindle_core::artifacts::verify_device_certificate` performs (DESIGN.md §A7b clarification 6).
/// A verifier cannot recompute that binding from half a preimage, and MUST NOT treat a missing key
/// as "skip the check" — see `crate::model::Device::agree_pk`'s doc comment.
const SCHEMA_V4: &str = r#"
ALTER TABLE devices ADD COLUMN agree_pk BLOB;
"#;

/// Version 5 (td-93cee6) — fixes a missing `REFERENCES` on `invite_nonces.member_id`. V1's
/// `invite_nonces` (DESIGN.md §A4 idempotent invite redemption: `nonce` is the sole CAS key,
/// mirroring spindle-helper's `burned_admission_nonces` (`crates/spindle-helper/src/pg_store.rs`)
/// shape — `INSERT ... ON CONFLICT (nonce) DO NOTHING` then a read-back in the same transaction,
/// done in `crate::store::Store::burn_invite_nonce`) declared `member_id INTEGER NOT NULL` with no
/// foreign key, unlike every other member-scoped table (`devices.member_id`,
/// `member_groups.member_id`, `member_upload_bytes.member_id`). Because the bundled SQLite is
/// built with `SQLITE_DEFAULT_FOREIGN_KEYS=1`, that omission was live, not decorative: burning an
/// invite nonce for a nonexistent member silently succeeded where the equivalent orphan insert
/// into `member_upload_bytes` already failed with a foreign-key violation (extended code 787).
///
/// SQLite has no `ALTER TABLE ... ADD CONSTRAINT`, so fixing an existing column's foreign key
/// requires the standard rebuild: create a replacement table with the constraint, copy rows
/// across, drop the old table, rename the replacement into place. `migrate()` runs each migration
/// inside its own transaction, and `PRAGMA foreign_keys` is a no-op inside a transaction (per
/// SQLite's docs), so unlike the "Making Other Kinds Of Table Schema Changes" recipe this rebuild
/// cannot toggle FK enforcement off around itself — it runs with foreign keys enforced the entire
/// time, which is why the copy below has to pre-filter rather than rely on disabling checks.
///
/// The copy filters out any row whose `member_id` no longer exists in `members`
/// (`WHERE member_id IN (SELECT member_id FROM members)`) rather than letting the migration abort
/// on an orphan row. This is intentionally close to vacuous: `burn_invite_nonce` has zero callers
/// anywhere in the workspace outside its own two tests, so no shipped database can contain any
/// `invite_nonces` row at all, let alone an orphaned one. But the filter is correct on its own
/// terms even if that ever changes: an orphan invite nonce is a row whose member no longer
/// exists, and such a row can never be matched by a legitimate redemption (there is no member left
/// to redeem it for), so dropping it during the rebuild discards nothing a caller could observe.
const SCHEMA_V5: &str = r#"
CREATE TABLE invite_nonces_new (
    nonce BLOB PRIMARY KEY,
    member_id INTEGER NOT NULL REFERENCES members(member_id),
    issued_cap BLOB NOT NULL,
    redeemed_at INTEGER NOT NULL
);

-- See this migration's doc comment (SCHEMA_V5) for why orphan rows (member_id no longer present
-- in `members`) are filtered out here instead of being allowed to abort the migration.
INSERT INTO invite_nonces_new (nonce, member_id, issued_cap, redeemed_at)
SELECT nonce, member_id, issued_cap, redeemed_at
FROM invite_nonces
WHERE member_id IN (SELECT member_id FROM members);

DROP TABLE invite_nonces;

ALTER TABLE invite_nonces_new RENAME TO invite_nonces;
"#;

/// Version 6 (td-b940b1) — `uploaded_files`, the missing source of truth behind the upload-quota
/// counters (`member_upload_bytes`/`share_upload_bytes`, added in `SCHEMA_V3`). Per that table's
/// doc comment and `crate::store::Store`'s upload-quota module comment, those running counters
/// have "no other durable source of truth once files sit anonymously on the real filesystem" —
/// there was no row anywhere mapping a real file back to whichever member's upload put it there.
/// Without one, `spindle-host-core`'s counter bumps (outside any transaction covering the
/// filesystem operation, with no reconciliation path) drift silently and permanently: an upload
/// undercounts on a swallowed error, and a delete by a member other than the uploader overcounts —
/// the direction that can lock a member out of their own quota.
///
/// `uploaded_files` holds the **current state of files that arrived via the upload path** — one
/// row per `(share_id, subpath)` still present on disk via that path, upserted on every commit and
/// deleted when the file is removed. It is explicitly **not** a history of upload events (no
/// per-event rows, no timestamps of past uploads — a later commit or delete simply updates or
/// removes the row), and **not a complete index of every file in the share**: content the owner
/// placed directly on the real filesystem, never seen by any VFS RPC call, has no row here and
/// never will. Reintroducing it would require the recursive directory walk that was already
/// rejected as the on-demand alternative to a running counter (see the module comment: "too slow
/// to check before every chunk write"). Do not build anything on this table that assumes it
/// enumerates a share's full contents.
///
/// The counter tables stay, as a maintained cache over this one: recomputing a `SUM` over
/// `uploaded_files` before every chunk write does not scale to a large share any better than a
/// directory walk did, so `member_upload_bytes`/`share_upload_bytes` remain the fast path for a
/// quota check, and `crate::store::Store::reconcile_upload_counters` recomputes them from this
/// table's rows when drift is suspected — making that drift healable instead of permanent.
///
/// **No backfill, by design**: existing databases carry `member_upload_bytes`/
/// `share_upload_bytes` counters with no corresponding rows here, and there is no source to
/// backfill them from — the entire premise of this migration is that no such record existed
/// before it (a real file on disk carries no metadata saying which member's upload put it there).
/// Pre-migration uploads are therefore forgotten by `uploaded_files`, which is a one-time quota
/// amnesty for bytes already counted in the running totals: those totals are left as-is (nothing
/// in this migration touches them), only future `record_upload`/`remove_uploads_under` calls and
/// any later `reconcile_upload_counters` run affect what `uploaded_files` itself knows about. This is
/// acceptable because device enrollment — the only path that can currently reach an upload commit
/// — has zero production callers; no real deployment exists yet to lose data from.
const SCHEMA_V6: &str = r#"
CREATE TABLE uploaded_files (
    share_id  INTEGER NOT NULL REFERENCES shares(share_id),
    member_id INTEGER NOT NULL REFERENCES members(member_id),
    subpath   TEXT    NOT NULL,
    bytes     INTEGER NOT NULL,
    PRIMARY KEY (share_id, subpath)
);
"#;

/// Every schema version in order, oldest first. Appending a new `(N, SQL)` pair is the only way
/// to evolve the schema — existing entries are never edited once shipped.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, SCHEMA_V1),
    (2, SCHEMA_V2),
    (3, SCHEMA_V3),
    (4, SCHEMA_V4),
    (5, SCHEMA_V5),
    (6, SCHEMA_V6),
];

/// Applies every migration strictly newer than the connection's current `user_version`, each in
/// its own transaction, advancing `user_version` as it goes. Safe to call on every [`super::Store`]
/// open (a fully up-to-date connection is a no-op).
///
/// Refuses to open a database whose `user_version` is newer than the newest migration this build
/// knows about ([`StoreError::SchemaTooNew`]) — an older build silently using a newer schema's
/// columns/constraints is worse than failing to open at all.
///
/// Each pending migration re-reads `user_version` under an `Immediate` (write-locked) transaction
/// before deciding whether to apply it, so two connections racing to open the same out-of-date
/// file cannot both apply the same migration (see the loop below for why a plain `Deferred`
/// transaction is not enough).
pub(super) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let latest = MIGRATIONS.last().map(|&(v, _)| v).unwrap_or(0);

    // Fast path: an up-to-date connection takes no write lock at all. Reading `user_version`
    // outside a transaction is safe *here* only because `current == latest` means there is
    // nothing left to apply — a concurrent migrator could only be advancing it to this same
    // `latest`. Any other value falls through to the locked path below, which re-reads.
    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if current > latest {
        return Err(StoreError::SchemaTooNew {
            found: current,
            supported: latest,
        });
    }
    if current == latest {
        return Ok(());
    }

    for &(version, sql) in MIGRATIONS {
        // `Immediate`, not the default `Deferred`: the write lock must be held BEFORE
        // `user_version` is read, or two openers both read the same stale version and both
        // apply the same migration. rusqlite's default `busy_timeout(5000)` makes the loser
        // of a deferred race wait out the winner and then proceed on its stale read rather
        // than failing, which is exactly the "duplicate column name" case this prevents.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if current > latest {
            return Err(StoreError::SchemaTooNew {
                found: current,
                supported: latest,
            });
        }
        if version <= current {
            // Already applied — possibly by the racing opener we just waited out for the write
            // lock. Dropping `tx` here rolls back (nothing was written under it), which is
            // correct and intended: this connection has nothing left to commit for this version.
            continue;
        }
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {version}"))?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_is_idempotent_and_sets_user_version() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn).expect("first migrate");
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("read user_version");
        assert_eq!(version, MIGRATIONS.last().unwrap().0);

        // Re-running must not error (no "table already exists") and must not change the version.
        migrate(&mut conn).expect("second migrate is a no-op");
        let version_again: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("read user_version again");
        assert_eq!(version_again, version);
    }

    #[test]
    fn migrate_seeds_builtin_groups() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn).expect("migrate");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM groups", [], |row| row.get(0))
            .expect("count groups");
        assert_eq!(count, 2, "Owner and Members must be seeded at init");
    }

    /// td-93cee6's upgrade-path check: build a database at the OLD (pre-V5) schema by hand,
    /// insert a valid `invite_nonces` row through the unconstrained V1 table shape, then run
    /// [`migrate`] and confirm the row survived the rebuild and the table now enforces the
    /// foreign key that V1 was missing.
    #[test]
    fn migrate_v5_rebuild_preserves_rows_and_adds_the_missing_foreign_key() {
        let mut conn = Connection::open_in_memory().expect("open");

        // Hand-roll a database at schema version 4 (pre-V5) by applying V1..V4 directly, the
        // same versions `MIGRATIONS` would have applied to any database created before this
        // migration existed.
        conn.execute_batch(SCHEMA_V1).expect("apply V1");
        conn.execute_batch(SCHEMA_V2).expect("apply V2");
        conn.execute_batch(SCHEMA_V3).expect("apply V3");
        conn.execute_batch(SCHEMA_V4).expect("apply V4");
        conn.execute_batch("PRAGMA user_version = 4")
            .expect("set user_version to 4");

        conn.execute(
            "INSERT INTO members (root_fp, display_name, status, created) \
             VALUES (?1, 'Alex', 'active', 0)",
            [vec![0x11u8; 32]],
        )
        .expect("insert member under old schema");
        let member_id = conn.last_insert_rowid();

        // Under the V1 table shape (no REFERENCES on member_id) this insert has nothing to
        // violate — it is the same row a real pre-V5 `burn_invite_nonce` call would have written.
        conn.execute(
            "INSERT INTO invite_nonces (nonce, member_id, issued_cap, redeemed_at) \
             VALUES (?1, ?2, ?3, 1000)",
            rusqlite::params![vec![0xAAu8; 16], member_id, vec![0x22u8; 8]],
        )
        .expect("insert invite_nonces row under old schema");

        migrate(&mut conn).expect("migrate old schema up to latest");

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("read user_version");
        assert_eq!(version, MIGRATIONS.last().unwrap().0);

        // The pre-existing row must have survived the create/copy/drop/rename rebuild intact.
        let (stored_member_id, stored_cap, stored_redeemed_at): (i64, Vec<u8>, i64) = conn
            .query_row(
                "SELECT member_id, issued_cap, redeemed_at FROM invite_nonces WHERE nonce = ?1",
                [vec![0xAAu8; 16]],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("row survived the V5 rebuild");
        assert_eq!(stored_member_id, member_id);
        assert_eq!(stored_cap, vec![0x22u8; 8]);
        assert_eq!(stored_redeemed_at, 1000);

        // And the table now enforces the foreign key V1 was missing: a fresh insert against a
        // nonexistent member must fail, where it previously would have succeeded.
        let no_such_member = member_id + 1000;
        let err = conn
            .execute(
                "INSERT INTO invite_nonces (nonce, member_id, issued_cap, redeemed_at) \
                 VALUES (?1, ?2, ?3, 2000)",
                rusqlite::params![vec![0xBBu8; 16], no_such_member, vec![0x33u8; 8]],
            )
            .expect_err("orphan insert must now fail the foreign key check");
        match err {
            rusqlite::Error::SqliteFailure(ffi_err, ref msg) => {
                assert_eq!(
                    ffi_err.extended_code, 787,
                    "expected SQLITE_CONSTRAINT_FOREIGNKEY (787), got {ffi_err:?}: {msg:?}"
                );
            }
            other => panic!("expected SqliteFailure, got {other:?}"),
        }
    }

    #[test]
    fn migrate_refuses_a_database_from_a_newer_build() {
        let mut conn = Connection::open_in_memory().expect("open");
        migrate(&mut conn).expect("migrate to latest");
        let supported = MIGRATIONS.last().unwrap().0;

        conn.execute_batch("PRAGMA user_version = 9")
            .expect("simulate a newer-build database");

        let err = migrate(&mut conn).expect_err("must refuse a newer schema version");
        match err {
            StoreError::SchemaTooNew {
                found,
                supported: s,
            } => {
                assert_eq!(found, 9);
                assert_eq!(s, supported);
            }
            other => panic!("expected StoreError::SchemaTooNew, got {other:?}"),
        }
        let message = err_to_string(&err);
        assert!(
            message.contains('9'),
            "message must mention found version: {message}"
        );
        assert!(
            message.contains(&supported.to_string()),
            "message must mention the newest known migration: {message}"
        );
    }

    /// Small helper so the test above can render the error message without fighting borrow
    /// checker gymnastics around `expect_err` + `to_string`.
    fn err_to_string(err: &StoreError) -> String {
        err.to_string()
    }

    /// Reproduces the Bug B race directly against the real [`super::super::Store::open`]: two
    /// threads opening the same out-of-date file concurrently must not both apply the same
    /// migration (which previously surfaced as "duplicate column name: agree_pk" from the loser,
    /// which had read a stale `user_version` under rusqlite's default busy-timeout-then-proceed
    /// behavior). Run 20 times in one test to make the race bite reliably.
    ///
    /// The out-of-date file is built by applying `SCHEMA_V1..V3` directly and setting
    /// `user_version = 3` (the same technique
    /// `migrate_v5_rebuild_preserves_rows_and_adds_the_missing_foreign_key` uses above), rather
    /// than fully migrating a store to latest and then trying to strip the later versions back
    /// off. An earlier revision of this test did the latter — open a fully-migrated store, then
    /// `ALTER TABLE ... DROP COLUMN agree_pk` to undo just `SCHEMA_V4` — which only ever happened
    /// to work because every migration added after V4 (V5's rebuild, in particular) is naturally
    /// safe to re-run against a database that already has its effect applied. `SCHEMA_V6`'s plain
    /// `CREATE TABLE uploaded_files` is not: re-running it against a file that was never actually
    /// downgraded past V6 fails with "table uploaded_files already exists". Building the v3 file
    /// from the real V1..V3 SQL sidesteps this category of fragility entirely and keeps working
    /// no matter what future migrations look like.
    #[test]
    fn concurrent_opens_on_an_out_of_date_file_do_not_both_apply_the_same_migration() {
        use std::sync::Barrier;
        use tempfile::tempdir;

        for iteration in 0..20 {
            let dir = tempdir().expect("tempdir");
            let path = dir.path().join("store.sqlite3");

            // Build a genuine v3 database directly, rather than fully migrating then trying to
            // undo later versions — see this test's doc comment for why.
            {
                let conn = Connection::open(&path).expect("create file");
                conn.execute_batch(SCHEMA_V1).expect("apply V1");
                conn.execute_batch(SCHEMA_V2).expect("apply V2");
                conn.execute_batch(SCHEMA_V3).expect("apply V3");
                conn.execute_batch("PRAGMA user_version = 3")
                    .expect("set user_version to 3");
            }

            let barrier = std::sync::Arc::new(Barrier::new(2));
            let path_a = path.clone();
            let barrier_a = barrier.clone();
            let handle_a = std::thread::spawn(move || {
                barrier_a.wait();
                super::super::Store::open(&path_a)
            });
            let path_b = path.clone();
            let barrier_b = barrier.clone();
            let handle_b = std::thread::spawn(move || {
                barrier_b.wait();
                super::super::Store::open(&path_b)
            });

            let result_a = handle_a.join().expect("thread a did not panic");
            let result_b = handle_b.join().expect("thread b did not panic");

            assert!(
                result_a.is_ok(),
                "iteration {iteration}: thread a must succeed, got {:?}",
                result_a.err()
            );
            assert!(
                result_b.is_ok(),
                "iteration {iteration}: thread b must succeed, got {:?}",
                result_b.err()
            );

            let conn = Connection::open(&path).expect("reopen to check version");
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .expect("read user_version");
            assert_eq!(
                version,
                MIGRATIONS.last().unwrap().0,
                "iteration {iteration}: user_version must land on the newest migration"
            );
        }
    }
}
