-- spindle-helper durable store (Stage 4 slice 3, DESIGN.md §A9b/§A10.23).
--
-- Every fingerprint (`host_fp`, `subject_fp`, `root_fp`, `nats_fp`) is stored as its 32 raw bytes
-- (BYTEA), matching spindle-core's `Fingerprint::as_bytes()`/`from_slice` wire convention rather
-- than the base32 *display* form — no string round-tripping, no collation surprises.

-- Revocation epochs: max-wins, never decreases (DESIGN.md §A7b). One row per host.
CREATE TABLE revocation_epochs (
    host_fp BYTEA PRIMARY KEY,
    epoch   BIGINT NOT NULL
);

-- Revoked-subject sets alongside the epoch above (DESIGN.md §A9b). `subject_fp` is either a
-- root_fp or a device_fp (HelperView::is_revoked takes either, per its own doc comment).
CREATE TABLE revoked_subjects (
    host_fp    BYTEA NOT NULL,
    subject_fp BYTEA NOT NULL,
    PRIMARY KEY (host_fp, subject_fp)
);

-- Admission records: {host_fp, label, admitted_at, quota_profile} (DESIGN.md §A3b/§A4).
CREATE TABLE admission_records (
    host_fp       BYTEA PRIMARY KEY,
    label         TEXT NOT NULL,
    admitted_at   BIGINT NOT NULL,
    quota_profile TEXT NOT NULL
);

-- Burned admission-token nonces: single-use, CAS via INSERT ... ON CONFLICT DO NOTHING, keyed by
-- nonce ALONE (not (host_fp, nonce)) -- this is what makes cross-host reuse of the same nonce
-- detectable at all. See memory_store.rs's doc comment for the bug this exact keying choice fixes
-- (the S1 spike's own store keyed by (host_fp, nonce), silently defeating single-use).
CREATE TABLE burned_admission_nonces (
    nonce         BYTEA PRIMARY KEY,
    host_fp       BYTEA NOT NULL,
    label         TEXT NOT NULL,
    admitted_at   BIGINT NOT NULL,
    quota_profile TEXT NOT NULL
);

-- Session records: nats_fp -> {root_fp, host_fps, quota_profile, exp} (DESIGN.md §A5). host_fps is
-- stored as a Postgres BYTEA array (order-preserving, exactly matching Vec<Fingerprint>) rather
-- than a join table -- it is never queried by individual host_fp, only round-tripped whole.
CREATE TABLE session_records (
    nats_fp       BYTEA PRIMARY KEY,
    root_fp       BYTEA NOT NULL,
    host_fps      BYTEA[] NOT NULL,
    quota_profile TEXT NOT NULL,
    exp           BIGINT NOT NULL
);

-- Expiry-aware reads filter on `exp` directly; this index makes the periodic sweep
-- (`DELETE FROM session_records WHERE exp <= $1`) an index scan instead of a full table scan.
CREATE INDEX session_records_exp_idx ON session_records (exp);

-- TURN usage counters keyed by root_fp with a rolling window (DESIGN.md §A8/§A9b). `period` is a
-- fixed 30-day bucket index (`unix_seconds / (30*86400)`), not a calendar month -- see
-- HelperView::record_turn_issuance's doc comment for why (no calendar dependency in this crate's
-- A9c manifest).
CREATE TABLE turn_usage (
    root_fp BYTEA NOT NULL,
    period  BIGINT NOT NULL,
    count   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (root_fp, period)
);
