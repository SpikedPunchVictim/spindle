# deploy/

The **reference deployment** described in `docs/DESIGN.md` §A9b: a single-box `docker-compose`
stack (NATS + broker helper + Postgres + coturn) that is both the demo path and the substrate the
spikes (`spikes/`) run against.

## Status (Stage 4 slice 2)

**`nats` + `helper` are real, runnable services.** `docker compose -f deploy/docker-compose.yml up
--build` (or `just dev`) brings up:

- `nats` — `nats:2.10-alpine`, configured for NATS Auth Callout per `nats/nats-server.conf`
  (adapted from `spikes/s1-callout/server.conf`, the config S1 proved passes 19/19 automated
  checks against a live server — `spikes/s1-callout/RESULTS.md`).
- `helper` — `crates/spindle-helper`'s graduated Auth Callout responder
  (`src/bin/helper.rs`), built via `deploy/Dockerfile`. Runs in **`open` admission mode**
  (docs/DESIGN.md §A3b) with `spindle_helper::memory_store::InMemoryHelperView` — an in-memory,
  **not durable** `HelperView` (every revocation/admission/session fact is lost on restart).
  Holds the two NATS connections DESIGN.md §A5 / ADR-002 describe (callout/system + application —
  see `src/bin/helper.rs`'s module docs); the application connection is established but otherwise
  idle in this slice.

**Still stubbed / not running:**

- **Postgres** — commented placeholder block in `docker-compose.yml`. The helper's durable,
  sqlx-backed `HelperView` is Stage 4 slice 3 work; until it lands there is nothing for a Postgres
  container to back.
- **coturn** — commented placeholder block. `helper.turn.get` (TURN credential minting) isn't
  implemented yet.
- **TLS / local dev CA** — docs/DESIGN.md §A9b's dev-mode sentence is "helper in `open` admission
  **with a local CA**"; only the `open`-admission half is real today. `nats-server.conf`'s
  listeners are plaintext TCP/WebSocket, dev/local only, matching the S1 spike's own config (see
  that file's dev-only notes). No dev-CA generation script exists yet.
- **Presence, admin-command verifier** — not implemented (`crates/spindle-helper`'s own module
  docs list what's still out of scope).

## Dev mode

```sh
just dev
```

runs `docker compose -f deploy/docker-compose.yml up --build` — NATS + the helper, in `open`
admission mode, so a host or client can connect without a pre-provisioned admission invite (once
`spindle-net`/`spindle-host-core`/`spindle-client-core` exist to actually make such a connection —
Stage 5+). Until then, the stack's own automated verification is
`spikes/s1-callout/src/bin/s1-tests.rs`'s 19-check suite, pointed at this compose stack's NATS
port via `NATS_URL=nats://127.0.0.1:4222` (and `CALLOUT_USER_SEED` unset, which skips the one
bridging check that needs the spike's own responder process rather than this compose stack's
containerized one — see that test's own gating comment).

## Files

- `docker-compose.yml` — `nats` + `helper` (real); `postgres`/`coturn` (commented placeholders,
  Stage 4 slice 3+).
- `Dockerfile` — multi-stage build for the `spindle-helper` binary (plain `rust:1-slim-bookworm`
  builder for now; ADR-010 notes `Dockerfile.toolchain`, repo root, as the base for this image
  "later" — not a blocker for this slice, see the Dockerfile's own header comment).
- `nats/nats-server.conf` — `max_control_line: 32768` (A10.10), TCP (4222) + WebSocket (8080
  in-container, published to the host as 8090 — see `docker-compose.yml`'s port mapping comment —
  dev-only no-TLS) + HTTP monitor (8222) listeners, and the Auth Callout account topology
  (`AUTH`/`APP`/`SYS`) adapted from the S1 spike's proven config — see that file's own comments
  for the full account-topology rationale and the throwaway-nkey provenance/regeneration note.
- `.env` (not checked in, not currently read by anything in this stack — reserved for the
  Postgres credentials and coturn `TURN_SECRET` once those services are uncommented).
