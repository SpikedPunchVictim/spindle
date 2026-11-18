-- Stage: durable registry admission mode (DESIGN.md §A3b, td-efea19).
--
-- `set_mode` is an admin command, so the mode must outlive the process that accepted it and be
-- visible to the callout connection. The row is seeded from ADMISSION_MODE on first start
-- (`ON CONFLICT DO NOTHING`), then only the admin plane changes it. `id = 1` is a single-row
-- table, not a key.
CREATE TABLE registry_state (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    admission_mode TEXT NOT NULL CHECK (admission_mode IN ('open', 'invite', 'closed'))
);
