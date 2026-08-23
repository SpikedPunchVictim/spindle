# Spindle

Spindle is peer-to-peer file sharing: you run a **host** on your own machine, share chosen
files and directories through a virtual file system, and let approved people browse, download,
and upload according to group entitlements — from a native app or a browser — directly,
peer-to-peer, over WebRTC.

The registry (an operator-run NATS deployment plus a small "broker helper" service) is a
**connection broker and nothing more**. It never holds accounts, never introduces keys, cannot
read file contents or signaling payloads, and cannot alter session setup without detection. All
accounts, shares, groups, and entitlements live only on each host. See
[`docs/DESIGN.md`](docs/DESIGN.md) (the source of truth for this repository) for the full
threat model, protocol, and rationale, and [`docs/adr/`](docs/adr/) for the individual
Architecture Decision Records as they land.

## Shape: one wire contract, two engines, one UI layer

- **One wire contract** — canonical CBOR schemas and signed-artifact formats (`spindle-proto` /
  `@spindle/proto`) are defined once and verified byte-identical across Rust and TypeScript via
  golden test vectors in CI (see `vectors/`).
- **Two engines** — a Rust engine (`spindle-client-core`, `spindle-host-core`) does everything
  security-relevant (crypto, keys, NATS, WebRTC, VFS) for the native Tauri apps; a pure-TypeScript
  engine (`@spindle/engine-web`) implements the same contract for the browser client. Both are
  reached through one interface, `@spindle/engine-api`, so UI code cannot tell which engine it's
  running on.
- **One UI layer** — React components shared via `@spindle/ui` drive the host admin UI, the
  native client UI, and the web client UI identically.

## Repository tour

```
crates/          Rust workspace: proto, core, net, vfs, host-core, client-core, helper
apps/            host (Tauri tray app), client (Tauri app), web (browser client, no Rust)
packages/        TypeScript workspace: proto, crypto, engine-api, engine-web, engine-tauri,
                 ui, admin, admin-cli
vectors/         golden CBOR/signature test vectors shared by Rust and TypeScript
spikes/          evidence-before-code experiments (DESIGN.md A13); deletable after graduation
deploy/          reference docker-compose deployment (NATS + helper + Postgres + coturn)
docs/            DESIGN.md (authoritative) and docs/adr/ (Architecture Decision Records)
```

This layout follows `docs/DESIGN.md` §A9c exactly; see `docs/adr/ADR-009-repo-layout-toolchain.md`
(once written) for the enumerated boundary rules, including that Tauri frontends receive only
fingerprints and display state over IPC — never keys, seeds, or capabilities.

## Prerequisites

- **Rust** (stable channel, pinned in `rust-toolchain.toml`):
  `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **just** (task runner, the single front door over cargo + pnpm):
  `cargo install just` (or `brew install just`)
- **pnpm**: `corepack enable && corepack prepare pnpm@latest --activate`
- **Node 22 LTS** (pinned in `.nvmrc`): `nvm install` (or any Node 22.x install)

Once installed, `just build` builds everything; `just --list` shows all targets.

## Scaffold status

**This scaffold has not been compile-verified.** It was generated on a machine with no Rust
toolchain (`cargo`) and no `just` installed, so no Rust crate here has been built, tested, or even
`cargo check`ed, and no `justfile` target has been executed end to end. All JSON/YAML/TOML files
were validated syntactically (JSON via `node`, YAML/TOML by careful hand construction) but not
functionally exercised. Treat every crate and package as a structural skeleton — filenames,
dependency lists, and comments matching `docs/DESIGN.md` §A9c — until the first real
implementation stage (see `IMPLEMENTATION_PLAN.md`) builds and tests it for real.

## Where to go next

- [`docs/DESIGN.md`](docs/DESIGN.md) — the authoritative design document (read this first).
- [`docs/adr/`](docs/adr/) — Architecture Decision Records, one per major design area.
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — the staged execution plan for this repo.
