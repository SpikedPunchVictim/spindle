-- Adds device_fp to session_records (DESIGN.md §A5, amended v0.9.18): the kick relay (§A3, a
-- later slice) is keyed `device_fp -> (server_id, cid)`, but the schema this session record was
-- originally built against (0001_init.sql) had no device_fp column at all, so a device-scoped
-- revocation could never be resolved back to the live connection it names. Nullable -- a host
-- connection's session record (see session.rs's SessionRecord::device_fp doc comment) has no
-- client device fingerprint in the client sense, so NULL is the honest representation there, not
-- a placeholder -- and nullable is also what lets this migration apply cleanly against rows
-- already sitting in a running dev stack's database (a NOT NULL add would need a default/backfill
-- for those pre-existing session_records rows, which don't have a device_fp value to backfill).
ALTER TABLE session_records ADD COLUMN device_fp BYTEA;

-- Supports HelperView::sessions_for_subject's `WHERE (root_fp = $1 OR device_fp = $1) AND exp >
-- $2` lookup (DESIGN.md §A4: "a revocation names root_fp | device_fp") with index scans on both
-- sides of the OR instead of a full table scan. Two single-column indexes (rather than one
-- composite) because Postgres can combine them with a BitmapOr for this query, and each also
-- stays useful on its own if a future caller ever needs to look up sessions by just one side.
CREATE INDEX session_records_root_fp_idx ON session_records (root_fp);
CREATE INDEX session_records_device_fp_idx ON session_records (device_fp);
