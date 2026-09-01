//! Embedded schema migrations, applied via `PRAGMA user_version` (no external migration runner —
//! this crate must not gain a dependency beyond `rusqlite`). One numbered `&str` SQL constant per
//! schema version; [`migrate`] applies every version strictly greater than the connection's
//! current `user_version`, each inside its own transaction, and leaves `user_version` set to the
//! highest version applied. Versions are never edited after being shipped — a schema change is a
//! new numbered constant appended to [`MIGRATIONS`].

use rusqlite::Connection;

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

/// Every schema version in order, oldest first. Appending a new `(N, SQL)` pair is the only way
/// to evolve the schema — existing entries are never edited once shipped.
const MIGRATIONS: &[(i64, &str)] = &[
    (1, SCHEMA_V1),
    (2, SCHEMA_V2),
    (3, SCHEMA_V3),
    (4, SCHEMA_V4),
];

/// Applies every migration strictly newer than the connection's current `user_version`, each in
/// its own transaction, advancing `user_version` as it goes. Safe to call on every [`super::Store`]
/// open (a fully up-to-date connection is a no-op).
pub(super) fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    for &(version, sql) in MIGRATIONS {
        if version <= current {
            continue;
        }
        let tx = conn.transaction()?;
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
}
