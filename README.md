<p align="center"><img src="assets/icon.svg" width="128" alt="Spindle icon"/></p>
<h1 align="center">Spindle</h1>
<p align="center">Peer-to-peer file sharing — direct, end-to-end encrypted, no cloud storage in the middle.</p>

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

## How it works

```mermaid
flowchart LR
    subgraph deviceGroup["Your device"]
        client["Client app<br/>native or browser"]
    end

    subgraph registryGroup["Registry (untrusted for contents & keys — brokers connections only)"]
        registry["NATS + broker helper"]
    end

    subgraph hostGroup["Your friend's host"]
        host["Host daemon + virtual file system"]
    end

    turn(["TURN relay — only if direct connection fails; still end-to-end encrypted"])
    turn -.-> client
    turn -.-> host

    client -->|"1 · E2E-encrypted signaling (SDP/ICE)"| registry
    registry -->|"1 · routes, cannot read or alter"| host
    client ==>|"2 · direct WebRTC DataChannel (DTLS) — files never touch the registry"| host
```

1. The host owner shares folders into a virtual tree and sends an invite (QR code or link) —
   the invite itself carries the host's keys, so the registry never introduces them.
2. The invitee redeems it and gets a host-signed capability. Accounts live on the host; the
   registry stores none.
3. Opening the host, the two apps exchange encrypted signaling through the registry, which can
   route the exchange but cannot read or tamper with it.
4. The file transfer runs directly between the two machines, end-to-end encrypted, with
   entitlements enforced by the host on every request.

## Actors and terminology

Three actors, but the names in the code are more specific than "server, host, client" — this is
the vocabulary used throughout `docs/DESIGN.md`, the crate names, and the logs.

**Registry** — the operator-run brokering side, and a connection broker only (DESIGN.md §A3). It is
not one process but three:

- **NATS cluster** — the signaling substrate, nothing more. A TCP listener for daemons, a
  WebSocket listener for browsers.
- **Broker helper** (usually just *the helper*) — the whole "backend": the auth-callout responder
  that verifies host-signed capabilities, the presence service, the TURN credential issuer, the
  kick relay, and the revocation store. Crate `spindle-helper`.
- **TURN (coturn)** — relay, used only when hole-punching fails. Still end-to-end encrypted.

**Host** — the daemon that holds the files, the accounts, and the authority. Crate
`spindle-host-core`, app `apps/host`. It signs capabilities; the registry only ever *verifies*
them. Accounts, shares, groups, and entitlements live only here.

**Client** — the app that connects to a host to browse and transfer files. Crate
`spindle-client-core`, with `apps/client` (native) and `apps/web` (browser).

"Client" splits into two identities that are not interchangeable, and the distinction is
load-bearing:

- **Member** — the *person* holding an account on a host, identified by their identity root
  fingerprint `root_fp`.
- **Device** — one *installation* belonging to a member (a laptop, a phone, a browser profile),
  identified by `device_fp` and carrying its own keypair.

This is why the authorization entry points are `decide_device_connect` and `decide_host_connect`:
what actually connects is a device, never an abstract "client". It is also why revoking a member
(names their `root_fp`, cuts off every device they own) and revoking a device (names one
`device_fp`, leaves their other devices alone) are separate operations.

A third fingerprint appears in every helper log line: **`nats_fp`** identifies a single
*connection*, not a person and not a device. One device with the native app and a browser tab
open holds two of them.

| Informally | In this repo | Identified by |
|---|---|---|
| main server | registry (NATS + broker helper + TURN) | — |
| the backend | broker helper / the helper | — |
| host | host, host daemon | `host_fp` |
| client | client app | — |
| the person | member | `root_fp` |
| their laptop/phone | device | `device_fp` |
| one live connection | session | `nats_fp` |

One clarification the diagram above can hide: a client does not read files *through* the registry.
The registry brokers only the introduction. Once signaling completes, the transfer is direct —
QUIC between two native peers, a WebRTC DataChannel for browsers — and end-to-end encrypted. The
registry never sees file bytes and by design cannot: it holds no session keys and can neither read
nor forge them (DESIGN.md §A7).

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

## Prerequisites & getting started

**Primary path: mise + `just bootstrap`** (ADR-010). [mise](https://mise.jdx.dev) is
the single toolchain front door on all three OSes — it provisions Rust, Node, pnpm,
and `just` from the versions declared once in `mise.toml` (which mirrors
`rust-toolchain.toml`, `.nvmrc`, and the `packageManager` pin, so there's one place to
look). Install it, then bootstrap:

```
brew install mise                    # macOS
curl https://mise.run | sh           # Linux/macOS
winget install jdx.mise              # Windows

just bootstrap
```

`just bootstrap` provisions the pinned tool versions (`mise install`), runs per-OS
native dependency checks (warnings, never a hard fail), and installs JS dependencies
(`pnpm install`). Until `just` itself is installed, run the same script directly — it's
exactly what `just bootstrap` calls, and it installs `just` for you as part of the
pinned toolchain:

```
bash scripts/bootstrap.sh
```

Once bootstrapped, `just build` builds everything; `just --list` shows all targets.

**Alternative: devcontainer / GitHub Codespaces — Linux slice only.**
`.devcontainer/devcontainer.json` builds `Dockerfile.toolchain` (the same image used
for Linux CI toolchain validation) and gives a ready-to-use Linux environment for
`spindle-helper`, the TypeScript packages, and docs. **It cannot build the Tauri apps
or run the native spikes** — Tauri, `keyring`, and other native-OS work need a real
macOS/Windows/Linux host (ADR-010); use the mise path above for that.

**Per-OS native requirements** (checked, non-fatally, by `scripts/bootstrap.sh`):

| OS | Requirement | Check / install |
|----|-------------|------------------|
| macOS | Xcode Command Line Tools | `xcode-select -p` / `xcode-select --install` |
| Windows | MSVC C++ Build Tools (for Tauri) | https://visualstudio.microsoft.com/visual-cpp-build-tools/ |
| Linux | webkit2gtk (for Tauri) | `sudo apt install libwebkit2gtk-4.1-dev build-essential libssl-dev pkg-config` |

## Build status

The workspace builds, tests, and lints on Linux, macOS, and Windows; CI (`.github/workflows/`) runs
`cargo fmt --check`, `cargo clippy -D warnings`, and `cargo test --workspace` on all three. As of
2026-09-01 the Rust suite is **574 passing, 0 failing, 11 ignored**. The ignored tests are the ones
`cargo test` cannot run unaided: three need a live stack (`docker compose -f
deploy/docker-compose.yml up -d`), and the rest are Windows-only path-confinement tests that compile
everywhere but only execute on Windows.

Not every stage is implemented, and a directory existing does not mean the code inside it works.
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) is the authoritative record of what is done, what
is in progress, and what has been proven only in a test rather than against live infrastructure —
read it before assuming a subsystem exists. The implemented work lives in the Rust crates under
`crates/`; `apps/host/`, `apps/client/`, and `apps/web/` are still scaffolding.

## Where to go next

- [`docs/DESIGN.md`](docs/DESIGN.md) — the authoritative design document (read this first).
- [`docs/adr/`](docs/adr/) — Architecture Decision Records, one per major design area.
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — the staged execution plan for this repo.
