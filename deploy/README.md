# deploy/

The **reference deployment** described in `docs/DESIGN.md` §A9b: a single-box `docker-compose`
stack (NATS + broker helper + Postgres + coturn) that is both the demo path and the substrate the
spikes (`spikes/`) run against.

## Status (Stage 4 slice 3)

**`nats`, `helper`, `postgres`, and `coturn` are all real, runnable services.**
`docker compose -f deploy/docker-compose.yml up --build` (or `just dev`) brings up:

- `nats` — `nats:2.10-alpine`, configured for NATS Auth Callout per `nats/nats-server.conf`
  (adapted from `spikes/s1-callout/server.conf`, the config S1 proved passes 19/19 automated
  checks against a live server — `spikes/s1-callout/RESULTS.md`).
- `postgres` — `postgres:16-alpine`, a named volume, and a `pg_isready` healthcheck the `helper`
  service's `depends_on` waits on. Dev-only default credentials (`spindle`/`spindle-dev-only`);
  override via `POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB` env vars (or a `.env` file — see
  "Files" below) for anything beyond a throwaway local stack.
- `coturn` — `coturn/coturn`, `--use-auth-secret` with `--static-auth-secret` set from
  `TURN_SECRET` (must match the helper's own `TURN_SECRET` env var below — coturn validates
  credentials the helper mints using the same shared secret, DESIGN.md §A8). Relay port range is
  kept small for dev (`49160-49200`); widen it for real NAT-traversal testing.
- `helper` — `crates/spindle-helper`'s graduated Auth Callout responder + TURN credential minter
  (`src/bin/helper.rs`), built via `deploy/Dockerfile`. Runs in **`open` admission mode**
  (docs/DESIGN.md §A3b) against `spindle_helper::pg_store::PgStore` — the durable, `sqlx`-backed
  `HelperView` (embedded migrations run automatically at startup; the container fails fast with a
  descriptive error if Postgres is unreachable or a migration fails). Holds the two NATS
  connections DESIGN.md §A5 / ADR-002 describe (callout/system + application); the application
  connection now actively answers `helper.turn.get.<nfp>` (TURN credential minting, quota-limited
  per `root_fp` via `TURN_MONTHLY_QUOTA`; `<nfp>` is the caller's session-nkey fingerprint, taken
  from the subject the callout granted rather than the request body — DESIGN.md §A5 v0.9.7,
  A12 #45).

**No-postgres dev flow**: unset `DATABASE_URL` in the `helper` service's environment block (or run
`spindle-helper` directly, outside compose, without `DATABASE_URL`) to fall back to
`spindle_helper::memory_store::InMemoryHelperView` — ephemeral, every revocation/admission/
session/TURN-usage fact lost on restart, but requires no Postgres container at all. The helper
logs a loud warning on startup either way, naming which store it picked.

**Still stubbed / not running:**

- **TLS / local dev CA** — docs/DESIGN.md §A9b's dev-mode sentence is "helper in `open` admission
  **with a local CA**"; only the `open`-admission half is real today. `nats-server.conf`'s
  listeners are plaintext TCP/WebSocket, dev/local only, matching the S1 spike's own config (see
  that file's dev-only notes). No dev-CA generation script exists yet.
- **Presence, admin-command verifier** — not implemented (`crates/spindle-helper`'s own module
  docs list what's still out of scope).
- **Calendar-month TURN quota windows** — `TURN_MONTHLY_QUOTA` is enforced over a fixed 30-day
  rolling bucket, not a calendar month (see `HelperView::record_turn_issuance`'s doc comment for
  why — no calendar/date dependency in this crate's A9c manifest).

## Dev mode

```sh
just dev
```

runs `docker compose -f deploy/docker-compose.yml up --build` — NATS + Postgres + coturn + the
helper, in `open` admission mode, so a host or client can connect without a pre-provisioned
admission invite (once `spindle-net`/`spindle-host-core`/`spindle-client-core` exist to actually
make such a connection — Stage 5+). Until then, the stack's own automated verification is
`spikes/s1-callout/src/bin/s1-tests.rs`'s 19-check suite, pointed at this compose stack's NATS
port via `NATS_URL=nats://127.0.0.1:4222` (and `CALLOUT_USER_SEED` unset, which skips the one
bridging check that needs the spike's own responder process rather than this compose stack's
containerized one — see that test's own gating comment). This has been re-run against the
Postgres-backed helper (`DATABASE_URL` set, as the compose file now sets it) with the same
18/18-checks-run result as against the in-memory store — the store swap does not change callout
behavior, which is the whole point of the `HelperView` trait boundary.

To additionally exercise `crates/spindle-helper`'s Postgres-gated store-contract tests against
this stack's own database:

```sh
docker compose -f deploy/docker-compose.yml up -d
TEST_DATABASE_URL="postgres://spindle:spindle-dev-only@127.0.0.1:5434/spindle" \
  cargo test -p spindle-helper
docker compose -f deploy/docker-compose.yml down
```

(Host-side Postgres port is `5434`, not the default `5432` — dev boxes commonly already have a
Postgres bound to `5432`; see `docker-compose.yml`'s port mapping comment. Only host-side tools need
this — the `helper` container itself addresses `postgres:5432` over the compose network, unaffected.)

## Files

- `docker-compose.yml` — `nats`, `postgres`, `coturn`, `helper` (all real, runnable services as of
  Stage 4 slice 3).
- `Dockerfile` — multi-stage build for the `spindle-helper` binary (plain `rust:1-slim-bookworm`
  builder for now; ADR-010 notes `Dockerfile.toolchain`, repo root, as the base for this image
  "later" — not a blocker for this slice, see the Dockerfile's own header comment).
- `nats/nats-server.conf` — `max_control_line: 32768` (A10.10), TCP (4222) + WebSocket (8080
  in-container, published to the host as 8090 — see `docker-compose.yml`'s port mapping comment —
  dev-only no-TLS) + HTTP monitor (8222) listeners, and the Auth Callout account topology
  (`AUTH`/`APP`/`SYS`) adapted from the S1 spike's proven config — see that file's own comments
  for the full account-topology rationale and the throwaway-nkey provenance/regeneration note.
- `.env` (not checked in) — optional overrides for `POSTGRES_USER`/`POSTGRES_PASSWORD`/
  `POSTGRES_DB`/`TURN_SECRET`; every one of these has a dev-only default baked into
  `docker-compose.yml` so the stack runs with zero setup, but never reuse those defaults outside a
  throwaway local stack.
