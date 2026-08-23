# ADR-010: Developer Environment & Toolchain Provisioning

## Status

Accepted

## Context

ADR-009 fixed the repository's *shape* (crates, packages, apps, the `justfile` front door). It did not answer a
narrower but equally load-bearing question: **how do the tools that shape depends on — Rust, Node, pnpm, `just`
itself — actually get onto a developer's machine, and onto CI, in a way that is uniform across all three target
OSes?** Two requirements drove this decision:

1. **A new developer opens the repo and has tools ready.** Cloning `spindle` and running one or two commands should
   produce a working `cargo`, `pnpm`, `just`, and the pinned Rust toolchain — no tribal knowledge, no "install these
   eleven things in this order" wiki page.
2. **The solution must be easily accessible to scripts and the build pipeline.** CI (`.github/workflows/`, per
   ADR-009) and any local automation need to provision the same toolchain non-interactively, without a human at a
   keyboard clicking through an installer.

The repo already pins exact tool versions declaratively: `rust-toolchain.toml` (pinned stable, MSRV = pinned − 2)
and `.nvmrc` (Node 22 LTS) exist per ADR-009's directory layout, and `packageManager` will pin the pnpm version in
`package.json`. **This ADR is not about *which* versions** — that's already decided — **it is about *how* those
pins get turned into installed binaries** on a developer's machine and in CI.

**The native-cross-platform constraint.** Spindle is not a server-side product that can standardize on a single
Linux container image for development. Per DESIGN.md §A9c, native apps are Tauri 2 shells that must produce
real, signed, notarized bundles for macOS, Windows, and Linux, and per §A9 the UX bar (connect latency, transfer
throughput) is measured on real OS network stacks. Concretely, several already-decided pieces of the design make
a container-first (or container-only) developer environment unworkable:

- **Tauri bundles build on their target OS.** A macOS `.app`/`.dmg` cannot be produced from a Linux container; the
  same is true of Windows MSIX/NSIS bundles requiring MSVC. `just package` (ADR-009 §Versioning & release) has to
  run natively per OS.
- **S11's negative-test matrix needs real filesystems.** DESIGN.md §A13 spike S11 (VFS confinement) enumerates
  Windows-specific escape classes — device names, 8.3 short names, alternate data streams, `\\?\` paths — that only
  exist on a real Windows filesystem; a Linux container cannot exercise them. macOS case-folding/Unicode-NFD
  behavior is likewise host-OS-specific (DESIGN.md §A4b).
- **`keyring` needs real OS keystores.** ADR-003 §A4 stores the identity root's OS-keystore-backed key material via
  the `keyring` crate against Keychain (macOS), Credential Manager (Windows), and Secret Service (Linux) — none of
  which are meaningfully testable from inside a generic Linux dev container.
- **S3 and S7 need host network/GUI stacks.** Spike S3 (DataChannel throughput) and S7 (browser large-file
  sink/tab-throttling/sleep-resume, DESIGN.md §A13) measure real OS networking and a real browser's tab-lifecycle
  behavior — both degrade or become unmeasurable inside a container's virtualized network and headless environment.

Given that, a devcontainer or Docker image cannot be the *primary* development environment for the two native apps
(`apps/host`, `apps/client`). It remains useful, however, for the slice of the repo that genuinely is
platform-agnostic: docs, the TypeScript packages, and the `apps/web` browser client, plus CI's own Linux jobs and
the helper's Linux-only release image (`spindle-helper` never runs on a desktop OS at all).

**Supply-chain note (ADR-001 §A12, security-relevant only here as a build input, not a runtime asset).** The
toolchain image (`Dockerfile.toolchain`) is not part of Spindle's runtime attack surface — it never ships to an end
user and holds no key material — but it *is* a build input for CI and for the helper's release image, so it
inherits ADR-001's general "supply chain of daemon/web bundle... tracked separately" scoping note (§A2, "explicitly
out of scope" list) rather than any specific A12 row: it is pinned to a specific `mise.toml` version declaration and
built from a Dockerfile checked into this repo (not pulled from a third-party registry unpinned), keeping its
provenance reviewable the same way any other repo-versioned build artifact is.

## Decision

Adopt a **hybrid** provisioning model: mise as the native front door for all three OSes, backed by one
Dockerfile-based toolchain image consumed by three separate things that need a Linux-slice build environment.
Made 2026-08-23, after a walkthrough of five options (see Alternatives Considered).

### 1. mise is the front door for native development

A repo-root `mise.toml` pins `node`, `pnpm`, `just`, and `rust` as mise-managed tools — **one version
declaration** other than the exceptions below. The `rust-toolchain.toml` file mandated by ADR-009 remains
**authoritative for the exact Rust channel**: mise's `rust` backend defers to it rather than duplicating the pin,
so there is exactly one place that says which Rust toolchain is in use.

New-developer flow on any of the three OSes:
1. Install mise (one line — the officially documented curl/PowerShell installer for the platform).
2. Run `just bootstrap`.

`just bootstrap` wraps `mise install` (installs everything `mise.toml` declares) with per-OS native prerequisite
checks that mise itself cannot install:
- **macOS**: verifies Xcode Command Line Tools are present (required for linking Rust binaries and for Tauri's
  macOS bundler).
- **Windows**: prints a note pointing at the MSVC Build Tools requirement (Tauri's Windows target needs the MSVC
  linker; this is not something a version-pinning tool can silently install).
- **Linux**: checks for `webkit2gtk` and `pkg-config` (Tauri's Linux runtime/build dependencies).

After `just bootstrap` completes, `cargo`, `pnpm`, `just`, and the pinned Rust toolchain are all on `PATH` and
ready.

### 2. One `Dockerfile.toolchain`, three consumers

A single `Dockerfile.toolchain` installs mise and runs `mise install` against the **same** `mise.toml` used for
native development — one version declaration serves both native and containerized environments. This image is
consumed by:

(a) **`.devcontainer/`** — so VS Code/Codespaces onboarding works out of the box for docs, TypeScript package, and
    helper (Linux-slice) contributions.
(b) **Linux CI** — the Linux leg of the 3-OS CI matrix (ADR-009 §`.github/workflows/`) builds/tests from this same
    image, so CI and the devcontainer cannot silently drift from each other.
(c) **The helper's release image build** (later) — `spindle-helper` (ADR-007) is a Linux server binary; its
    release container reuses the same toolchain image as its build stage rather than maintaining a fourth,
    parallel toolchain declaration.

### 3. Containers are explicitly NOT the primary dev environment

Stated plainly, so it isn't rediscovered by accident later: because Spindle is native cross-platform, the
devcontainer/Dockerfile path **only covers the Linux slice** — docs, TypeScript packages, and helper development.
It does not and cannot cover:
- Tauri bundle builds for `apps/host` / `apps/client` on macOS or Windows (must build on their target OS).
- Spike S11's negative-test matrix on real macOS/Windows filesystems.
- `keyring`-backed OS keystore integration on macOS/Windows.
- Spikes S3/S7, which need a host network stack and a real browser/GUI, not a container's virtualized network and
  headless environment.

A developer working on `apps/host`, `apps/client`, or any of the S3/S7/S11 spikes uses the native mise path (§1),
not the container.

### 4. CI provisioning

All three OS jobs in the CI matrix (ADR-009) provision their toolchain via mise, using `jdx/mise-action`, reading
the same `mise.toml`. A separate CI job builds `Dockerfile.toolchain` itself, path-filtered to trigger only on
changes to `Dockerfile.toolchain` or `mise.toml`, so the image is validated as green without rebuilding it on
every unrelated commit.

### 5. Known caveat, recorded

mise's Windows support is newer and less mature than its Unix (macOS/Linux) support. This is a recorded risk, not
a blocker: if mise disappoints in practice on Windows during Stage 0 (verification below), the fallback is a
**bootstrap script for Windows** (an imperative PowerShell script installing the pinned tools directly) while
`mise.toml` remains the single version-declaration source of truth that the script reads from or is kept in sync
with. This fallback is scoped to Windows only; macOS and Linux stay on mise regardless.

### File inventory this decision mandates

- `mise.toml` — pins `node`, `pnpm`, `just`, `rust` (rust backend defers to `rust-toolchain.toml`).
- `Dockerfile.toolchain` — installs mise, runs `mise install` against `mise.toml`.
- `.devcontainer/devcontainer.json` — builds from `Dockerfile.toolchain`; Linux-slice contributions only.
- `scripts/bootstrap.sh` — the cross-platform bootstrap logic invoked by `just bootstrap`, with per-OS branches
  (Xcode CLT check on macOS, MSVC note on Windows, webkit2gtk/pkg-config check on Linux); a Windows-specific
  fallback bootstrap script is added only if the Stage 0 mise-on-Windows verification (§5) requires it.
- `just bootstrap` target in the top-level `justfile` (ADR-009), wrapping `mise install` + the per-OS checks in
  `scripts/bootstrap.sh`.
- CI provisioning step in `.github/workflows/` using `jdx/mise-action` on all three OS jobs, plus a path-filtered
  `Dockerfile.toolchain` build job.

(A parallel effort is authoring the actual content of `mise.toml`, `Dockerfile.toolchain`, `.devcontainer/`, the
`justfile` target, and the CI workflow changes; this ADR records the decision those files implement.)

## Consequences

### Positive

- A new developer's path to a working toolchain is two steps (install mise; `just bootstrap`) on any of the three
  target OSes, satisfying the "tools ready" requirement without per-OS documentation drift.
- Exactly one version-declaration file (`mise.toml`, deferring to `rust-toolchain.toml` for the Rust channel) feeds
  native dev, the devcontainer, Linux CI, and the future helper release image — eliminating the class of bug where
  CI's Node/pnpm/`just` versions quietly diverge from a developer's machine.
- Native Tauri builds, spike S11's filesystem-dependent negative tests, `keyring` OS-keystore integration, and
  S3/S7's network/GUI-dependent measurements all run on the real target OS, matching what DESIGN.md's spikes and
  release process actually require — no container-induced measurement or behavior distortion.
- The devcontainer still gives docs/TS/helper contributors (and anyone bootstrapping via Codespaces) a working
  environment with zero native prerequisites, for exactly the slice of the repo where that's sufficient.
- The toolchain image doubling as CI's Linux base and the helper's release-image build stage means that image is
  exercised (and kept correct) by every Linux CI run, not just by devcontainer users — it can't silently rot.

### Negative

- Two provisioning mechanisms exist (mise natively, mise-inside-Docker for the Linux slice) rather than one; a
  contributor working across both a native OS and the devcontainer needs to understand which one applies where.
- mise's Windows support is the least mature of the three OS paths (§5); Windows contributors carry more risk of
  hitting rough edges before Stage 0's verification is complete, and may need to fall back to an imperative script
  if that risk materializes.
- `just bootstrap`'s per-OS native-prerequisite checks (Xcode CLT, MSVC note, webkit2gtk/pkg-config) are itself
  code that has to be written and maintained per OS — mise does not abstract this part away.

### Neutral

- `Dockerfile.toolchain` is deliberately narrow in scope: a toolchain-provisioning image, not a full reference
  deployment. It is unrelated to `deploy/`'s docker-compose reference stack (DESIGN.md §A9c), which packages the
  *runtime* (NATS + helper + Postgres + coturn), not the *build* toolchain.
- The helper's release-image consumption of `Dockerfile.toolchain` (§2c) is recorded as a decision now but deferred
  in implementation — `spindle-helper`'s release packaging happens later in the execution plan (IMPLEMENTATION_PLAN
  Stage 10 covers packaging/signing broadly; the toolchain-image reuse itself is realized whenever the helper's
  release image is actually built).

## Alternatives Considered

| Alternative | Verdict | Why |
|-------------|---------|-----|
| **Devcontainer-primary** (all development happens inside `.devcontainer/`, native installs are secondary) | Rejected | Linux-only container builds cannot produce macOS/Windows Tauri bundles; on macOS, Docker's Linux VM imposes real cargo build I/O overhead (bind-mount/virtiofs filesystem performance) painful enough to hurt daily iteration; GUI-heavy Tauri development (webview debugging, tray interaction) inside a container is awkward at best |
| **Docker-primary** (Dockerfile-based image is the dev environment, not just a CI/devcontainer artifact) | Rejected as dev env; retained as CI/reproducibility artifact | No native editor integration (rust-analyzer inside a container requires remote-attach gymnastics that degrade the day-to-day edit/build/debug loop); the same native-cross-platform blockers as devcontainer-primary apply. Retained in scope as `Dockerfile.toolchain`, used only for CI and the Linux slice |
| **Nix flakes** | Rejected for v1 | Windows support exists only via WSL; Tauri's Windows build needs MSVC, which is outside WSL's Linux userspace — the same native-target problem recurs. Also carries a steeper learning curve for contributors than mise's simple TOML + CLI |
| **asdf** | Rejected | Dominated by mise (mise is a compatible, faster, better-UX successor covering the same plugin ecosystem) and has no Windows support at all, which is a hard requirement given v1's three-OS target (DESIGN.md §A10.9) |
| **Bootstrap-script-only** (an imperative install script per OS, no version-pinning tool) | Rejected as the primary mechanism; retained as the named Windows fallback (§5) | This is the imperative approach mise replaces declaratively — a script has to hand-encode per-OS install logic for every tool and re-implement version pinning that mise already provides out of the box. Kept in reserve specifically for the one OS (Windows) where mise's maturity is the open question |

Note on scope: the repo already pins the exact versions (`rust-toolchain.toml`, `.nvmrc`, `packageManager`); none
of the five options above were answering "which Rust/Node/pnpm version" — only "how do rustup/node/just get onto
the machine uniformly," which is what this ADR decides.

## Open items

- **mise-on-Windows maturity**: mise's Windows support is newer/less mature than its Unix support (§5). This is
  verified during **Stage 0** (IMPLEMENTATION_PLAN.md) rather than assumed; if it disappoints in practice, the
  fallback is a bootstrap script for Windows, with `mise.toml` remaining the single version-declaration source of
  truth. Not blocking this ADR's acceptance — recorded so the fallback isn't rediscovered from scratch if needed.
- **Pinning exact tool versions**: this ADR decides the *mechanism* (mise + `Dockerfile.toolchain` + devcontainer +
  `just bootstrap`); the exact version numbers written into `mise.toml` (node, pnpm, `just`, and the Rust channel
  already governed by `rust-toolchain.toml`) are an implementation detail resolved when `mise.toml` is authored,
  not a decision this ADR needs to make.

## References

- `../DESIGN.md` §A9c (repository layout & toolchain — `rust-toolchain.toml`, `.nvmrc`, `justfile` front door that
  this ADR provisions the tools for), §A10 row 28 (this decision), §A13 (spikes S3, S7, S11 — the native-OS
  requirements cited in Context)
- [ADR-009: Repository Layout & Toolchain](./ADR-009-repo-layout-toolchain.md) — the repository shape and
  `justfile`/workspace structure this ADR's tooling provisions; `just bootstrap` is a new top-level target
  alongside ADR-009's `build | test | vectors | dev | lint | package`
- [ADR-001: Threat Model](./ADR-001-threat-model.md) — §A2 "explicitly out of scope" (supply chain of daemon/web
  bundle, tracked separately) — the scoping note this ADR's toolchain-image provenance discussion falls under
- [ADR-003: Identity, Capabilities, Enrollment](./ADR-003-identity-capabilities-enrollment.md) — §A4 `keyring`/OS
  keystore usage, cited in Context as a reason native OS environments are required for `apps/host`/`apps/client`
  development
- [ADR-007: Registry Control Plane](./ADR-007-registry-control-plane.md) — `spindle-helper` as the Linux-only
  service whose release image is the third consumer of `Dockerfile.toolchain`
- `../SPIKES.md` S3, S7, S11 (native OS/network/GUI/filesystem requirements cited in Context)
- `../IMPLEMENTATION_PLAN.md` Stage 0 (verifies the mise-on-Windows open item)
