-- Stage: host suspension/eviction (DESIGN.md §A3b operator capabilities, td-efea19).
--
-- Both flags refuse new host connections in the callout. `evicted` is terminal; `suspended` is the
-- reversible deny. Absence of a row means `Active`. Kicking already-live sessions is the admin
-- command's concern, not this table's.
CREATE TABLE host_states (
    host_fp    BYTEA PRIMARY KEY,
    suspended  BOOLEAN NOT NULL DEFAULT FALSE,
    evicted    BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at BIGINT NOT NULL
);
