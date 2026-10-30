-- Stage: HostDeviceCert distribution cache (DESIGN.md §A5/§A5b, decision A10.37).
--
-- The helper's durable copy of each host's `HostDeviceCert`, published by the host itself on
-- `registry.devcert.<hfp>` on every registry connect. The helper is an untrusted carrier by
-- construction (§A10.37): it stores and serves the bytes, and the consuming client verifies the
-- root -> op -> device chain to a pinned root. Nothing here is derived from or verified against
-- the certificate's own signature.
--
-- `host_fp` is the subject token of the publish (the cert's own `host_fp` is checked to equal it
-- before this write; see `spindle-helper/src/devcert.rs`). Last write wins: the host republishes
-- on every connect and its `device_fp` changes every restart (A10.37), so an upsert replaces
-- `cert`/`updated_at` rather than preserving history. `updated_at` is unix seconds.
CREATE TABLE host_device_certs (
    host_fp    BYTEA PRIMARY KEY,
    cert       BYTEA NOT NULL,
    updated_at BIGINT NOT NULL
);
