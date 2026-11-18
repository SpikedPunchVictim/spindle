-- Stage: admin plane durable state (DESIGN.md §A3b, td-efea19).
--
-- `admin_replay` is the per-signer anti-replay guard: a command's `seq` must be strictly greater
-- than every previously accepted seq for its signer, and its 16-byte nonce is single-use. The
-- primary key makes the seq check atomic; the unique constraint is the nonce check.
--
-- `admin_audit` is the hash-chained record of every command the helper accepted (A3b: "every
-- command, signer, result"). `hash = SHA-256(prev_hash || ts || signer_fp || seq || cmd ||
-- result_code)`, with `prev_hash` the previous row's hash (32 zero bytes for the first). The
-- chain is appended under a transaction-scoped advisory lock so concurrent writers cannot fork
-- it. Result codes are the fixed strings from `spindle_helper::admin::AdminRefusal::code`.
CREATE TABLE admin_replay (
    signer_fp BYTEA NOT NULL,
    seq       BIGINT NOT NULL,
    nonce     BYTEA NOT NULL,
    ts        BIGINT NOT NULL,
    PRIMARY KEY (signer_fp, seq),
    UNIQUE (signer_fp, nonce)
);

CREATE TABLE admin_audit (
    id          BIGSERIAL PRIMARY KEY,
    ts          BIGINT NOT NULL,
    signer_fp   BYTEA NOT NULL,
    seq         BIGINT NOT NULL,
    cmd         TEXT NOT NULL,
    result_code TEXT NOT NULL,
    prev_hash   BYTEA NOT NULL,
    hash        BYTEA NOT NULL
);
