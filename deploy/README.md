# deploy/

The **reference deployment** described in `docs/DESIGN.md` §A9b: a single-box `docker-compose`
stack (NATS + broker helper + Postgres + coturn) that is both the demo path and the substrate
the spikes (`spikes/`) run against.

**Status: this is a skeleton, not yet runnable end to end.** `helper` in `docker-compose.yml`
points at `../crates/spindle-helper`, which is currently an unimplemented stub binary (see
`IMPLEMENTATION_PLAN.md` Stage 4 — helper + NATS callout + deploy compose). Until that stage
lands, `docker compose up` here will start NATS, Postgres, and coturn, but the helper will not
do anything useful (no callout responder, no presence, no TURN credential minting).

## Dev mode

`just dev` (also not implemented yet — see the `justfile`) is meant to bring up this stack with
the helper running in **`open` admission mode** (docs/DESIGN.md §A3b) against a **local
development CA**, so a host or client can connect without a pre-provisioned admission invite.
The dev-CA generation script referenced by that flow does not exist yet; it is a placeholder for
now (see Stage 4 in `IMPLEMENTATION_PLAN.md`).

## Files

- `docker-compose.yml` — the four services above.
- `nats/nats-server.conf` — `max_control_line: 32768` (A10.10), a WebSocket listener for
  browsers, and comments pointing at the Auth Callout / account-topology decisions in ADR-002
  (once written) — this file intentionally has no static `authorization {}`/`accounts {}` block,
  since permissions are granted dynamically by the broker helper's callout responder.
- `.env` (not checked in) — Postgres credentials and the coturn `TURN_SECRET`; see the
  `environment`/`env_file` entries in `docker-compose.yml` for the variables expected.
