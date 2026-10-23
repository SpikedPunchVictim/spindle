-- Stage: self-revocation store (DESIGN.md §A4/§A7b, amended v0.9.47).
--
-- (1) session_records gains the identity root public key the caller presented in its auth bundle.
-- `helper.revoke.<nfp>` must check that a self-revocation's signer is the session's `root_fp`, and
-- a fingerprint cannot verify a signature. Nullable: a host connection has no member root, and
-- rows written before this migration have no value to backfill.
ALTER TABLE session_records ADD COLUMN root_pk BYTEA;

-- (2) Self-revocation epoch high-water mark per identity root. Max-wins, never decreases; it
-- gates acceptance of a `spindle-self-rev-v1` record elsewhere and is never derived from the
-- subject set below.
CREATE TABLE self_revocation_epochs (
    root_fp BYTEA PRIMARY KEY,
    epoch   BIGINT NOT NULL
);

-- (3) The accepted self-revoked subject set. The set is the monotone union of every accepted
-- record's entries: `INSERT ... ON CONFLICT DO NOTHING` makes re-adds (and replays of older
-- records) idempotent, and nothing here ever deletes a row, so a winning record with an empty
-- `revoked` list revokes nothing and un-revokes nothing.
CREATE TABLE self_revocations (
    root_fp   BYTEA NOT NULL,
    device_fp BYTEA NOT NULL,
    PRIMARY KEY (root_fp, device_fp)
);
