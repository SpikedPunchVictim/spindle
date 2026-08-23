# ADR-009: Repository Layout & Toolchain

## Status

Accepted

## Context

Spindle ships three frontends — a Tauri host app, a Tauri client app, and a browser client — that must all speak the
same wire contract (ADR-002 subjects, ADR-004 envelope, ADR-006 VFS RPC) and present the same UX (DESIGN.md §A9).
Two of those frontends carry private key material on the same device as their UI (ADR-003 §A4: root keys, device
keys, NATS connect keys); the third runs entirely inside a browser sandbox with no Rust at all (ADR-008). Getting
the repository shape wrong — letting UI code touch keys directly, letting the two engines drift, or letting a
security-relevant crate depend on a UI framework — would reopen exactly the kind of confused-boundary problems the
rest of the design (ADR-001 through ADR-008) closes at the protocol level. This ADR codifies the shape that keeps
those boundaries enforced by the build, not by convention.

**The shape in one sentence** (DESIGN.md §A9c): *one wire contract, two engines, one UI layer.* Native apps are
**Tauri 2** shells where a **Rust engine does everything security-relevant** (crypto, keys, NATS, WebRTC, VFS) and
the React frontend is display-only over Tauri IPC; the browser client is a **pure-TS engine** implementing the same
wire contract; the contract itself is defined once and enforced by golden test vectors on both sides (DESIGN.md
§A9b).

## Decision

### Decisions A10.25–27 (2026-08-23)

- **UI framework (A10.25)**: **React** for all three frontends — the Tauri client, the host admin UI, and the web
  client — sharing components via `@spindle/ui`.
- **Host app shape (A10.26)**: **one Tauri 2 tray app** — the daemon runs in-process, the tray is always on, the
  admin window opens on demand, and there is **no localhost admin port**; a headless/NAS mode is deferred.
- **Monorepo tooling (A10.27)**: a **cargo workspace** plus **pnpm workspaces**, fronted by a single top-level
  **`justfile`** as the sole build/test/dev entry point; CI runs the same `just` targets as local development.

### Directory layout (verbatim, DESIGN.md §A9c)

```
spindle/
├── justfile                    # front door: just build | test | vectors | dev | lint | package
├── Cargo.toml                  # [workspace] → crates/*, apps/*/src-tauri, spikes/*
├── pnpm-workspace.yaml         # packages/*, apps/*/ui, apps/web
├── rust-toolchain.toml         # pinned stable (MSRV = pinned − 2); .nvmrc pins Node 22 LTS
├── .github/workflows/          # CI: 3-OS matrix, Rust + TS suites, vector cross-check, S1/S11/S16/S18 negatives
│
├── crates/                     # Rust — dependency law: proto ← core ← {net, vfs} ← {host-core, client-core}
│   ├── spindle-proto/          #   wire types, canonical CBOR (RFC 8949 §4.2.1), A7b artifact tags;
│   │                           #   `gen-vectors` bin writes /vectors
│   ├── spindle-core/           #   identity (roots, device certs), caps, envelope (A7), signed artifacts (A7b)
│   ├── spindle-net/            #   NATS client + callout presentation, WebRTC (webrtc ≥0.20), trickle ICE,
│   │                           #   transfer manager (A8)
│   ├── spindle-vfs/            #   shares/groups/entitlements engine, cap-std confinement, audit chain (A4b); SQLite
│   ├── spindle-host-core/      #   host library: members, invites, revocation, VFS RPC server, live-ops
│   ├── spindle-client-core/    #   client library: sessions, pinning store, transfer queue, key custody
│   └── spindle-helper/         #   broker-helper service bin: callout responder, presence, TURN, revocation
│                               #   store, admin verifier; Postgres (sqlx)
│
├── apps/
│   ├── host/                   # Tauri 2 tray app — spindle-host-core in-process
│   │   ├── src-tauri/          #   tray, autostart, updater, IPC commands → host-core (typed, minimal)
│   │   └── ui/                 #   React admin UI: Shares · People · Groups · Preview-as · Sessions · Audit
│   ├── client/                 # Tauri 2 client app
│   │   ├── src-tauri/          #   thin shell over spindle-client-core; exposes the engine API over IPC
│   │   └── ui/                 #   React client UI: host list, browse, transfers, invites, device mgmt
│   └── web/                    # browser client (no Rust): React UI + @spindle/engine-web;
│                               #   hardened-delivery build pipeline (ADR-008): reproducible, manifest, SRI
│
├── packages/                   # TypeScript
│   ├── proto/                  # @spindle/proto — TS twin of spindle-proto: types + canonical CBOR
│   │                           #   (own ~small encoder; third-party CBOR libs are not canonical)
│   ├── crypto/                 # @spindle/crypto — WebCrypto Ed25519/X25519 + @noble/curves fallback (A7)
│   ├── engine-api/             # @spindle/engine-api — THE client-engine interface: sessions, VFS ops,
│   │                           #   transfers, presence, security events (walls)
│   ├── engine-web/             # @spindle/engine-web — engine-api implemented in TS: nats.ws + browser WebRTC
│   ├── engine-tauri/           # @spindle/engine-tauri — engine-api implemented as a Tauri IPC adapter
│   ├── ui/                     # @spindle/ui — shared React components: file tree, transfer list, permission
│   │                           #   grid, QR flows, key-change wall, "registry degraded" banner
│   ├── admin/                  # @spindle/admin — operator command signing, pluggable Signer, NATS conn (A3b)
│   └── admin-cli/              # spindle-admin — CLI over @spindle/admin
│
├── vectors/                    # golden vectors: canonical bytes + signatures for every A7b artifact;
│                               #   generated by Rust, byte-verified by TS in CI (divergence fails the build)
├── spikes/                     # s3-throughput, s11-vfs-confinement, … (workspace members; deletable)
├── deploy/                     # docker-compose reference (NATS+helper+Postgres+coturn), dev-CA scripts,
│                               #   `just dev` target = helper in `open` admission with local CA
└── docs/                       # DESIGN.md, adr/ADR-001…009, SPIKES.md
```

### Boundary rules (enforced, not aspirational — verbatim, DESIGN.md §A9c)

1. **Key custody**: private key material exists only in Rust (`keyring`/OS keystore) or non-extractable WebCrypto.
   Tauri frontends receive fingerprints and display state over IPC — never keys, seeds, or caps. The IPC command
   list is enumerated in ADR-009 and is the host/client attack surface review target.
2. **Engine substitution**: `apps/client/ui` and `apps/web` import **only** `@spindle/engine-api` (lint-enforced);
   the Tauri build wires in `engine-tauri`, the web build wires in `engine-web`. UI code cannot tell which engine
   it is on — this is what keeps browser and native UX identical (A9).
3. **Crate layering**: nothing below `apps/*/src-tauri` depends on `tauri`; `spindle-helper` depends only on
   `proto` + `core` (the helper must never grow host/client logic); `spindle-proto` has no crypto dependency.
4. **Tauri capability config is minimal**: no shell, no frontend fs access, no remote content; custom IPC
   commands only; single-instance + autostart + updater plugins (signed releases per A9b).

Rule 1 is the rule this ADR's IPC command list exists to make auditable: every command below carries fingerprints,
display state, or opaque handles across the Tauri IPC boundary — never a private key, seed, or capability blob
(ADR-003 §A4, ADR-001 §A12 #3, #25).

### Dependency manifest (verbatim, DESIGN.md §A9c — v1 baseline; spikes may amend with justification in the ADR)

| Concern | Rust | TypeScript |
|---------|------|------------|
| Runtime | tokio, tracing, thiserror (libs) / anyhow (bins) | Node 22 LTS (CLI/admin), evergreen browsers per A7 |
| NATS | async-nats | nats.ws |
| WebRTC | webrtc ≥0.20 (datachannel-rs = S3 fallback) | browser RTCPeerConnection |
| Crypto | ed25519-dalek 2, x25519-dalek 2, sha2, hkdf, aes-gcm, rand (OsRng), subtle, zeroize | WebCrypto + @noble/curves fallback |
| Encoding | minicbor (hand-driven canonical encode; no serde-derive ambiguity) | own canonical encoder in @spindle/proto |
| Storage | rusqlite (bundled) host-side; sqlx/Postgres helper-side | IndexedDB (caps, resume manifests) |
| Confinement | cap-std ≥3.4.1 | — (browser sandbox) |
| OS / shell | keyring, tauri 2 + plugins (tray, autostart, single-instance, updater), qrcode | @tauri-apps/api |
| UI | — | React, Vite, @spindle/ui |
| CLI | — | commander |
| Test/lint | cargo test + clippy + rustfmt; S-suite negatives in CI | vitest, ESLint + Prettier, TS strict |

### Versioning & release (DESIGN.md §A9c)

Lockstep versions across the repo in v1 (one release train; the A9b compat matrix is about *wire* versions, not
package versions). `just package` produces: signed/notarized Tauri bundles (host, client) per A9b, the hardened web
bundle + manifest (ADR-008), the helper container image, and the `spindle-admin` npm tarball.

### Initial Tauri IPC command list

This list is **initial — reviewed at implementation, per A9c rule 1**. It is derived strictly from features named
elsewhere in DESIGN.md (client: A9 UX table, A8 transport/VFS RPC, A4 identity/enrollment; host: A4b host
authorization). Every row obeys boundary rule 1: the payload column names only fingerprints, display state, virtual
paths, or opaque handles — never a private key, seed, or capability blob. "Command" = frontend invokes the Rust
engine over `invoke`; "event" = the Rust engine pushes to the frontend over `emit`/`listen`.

#### Client app (`apps/client`, over `@spindle/engine-tauri`)

| Command | Direction | Payload summary | Security note |
|---------|-----------|------------------|----------------|
| `hosts.list` | command | none → `[{host_fp, label, state}]` | Fingerprints/labels only; host roots never cross IPC (rule 1) |
| `presence.updated` | event | `{host_fp, state, last_seen}` | Presence deltas sourced from the helper (A6); display-state only |
| `host.connect` | command | `{host_fp}` → session state | Engine performs signaling/envelope handling internally (ADR-004); IPC carries only the target fingerprint |
| `vfs.list` | command | `{host_fp, path, cursor}` → `entries[{name, kind, size, mtime, perms_here}]` | Server-side permission check is authoritative; unauthorized paths return not-found, not a distinguishable error (ADR-006, ADR-001 §A12 #21) |
| `vfs.stat` | command | `{host_fp, path}` → `{kind, size, mtime}` | Same not-found semantics as `vfs.list` (ADR-001 §A12 #21) |
| `transfer.download.start` | command | `{host_fp, path, destPath}` → `{transferId}` | File bytes flow host→Rust engine→disk inside the engine process; IPC never carries raw chunk data |
| `transfer.upload.start` | command | `{host_fp, path, localPath}` → `{transferId}` | Received-file policy (sanitized names, quarantine, no overwrite without `delete`) enforced by the engine/host, not the frontend (ADR-005, ADR-001 §A12 #18, #23) |
| `transfer.control` | command | `{transferId, action: pause\|resume\|cancel}` | Idempotent; resumable via locally persisted manifests (A8 transfer manager) |
| `transfer.progress` | event | `{transferId, bytes, speed, path: direct\|relayed}` | Display-only; no key or session material |
| `invite.redeem` | command | `{inviteToken}` → `{host_fp, memberState}` | Registry endpoint + TLS pin policy travel inside the invite itself, not as a separate IPC input (ADR-003 §A4) |
| `identity.show` | command | none → `{root_fp, device_fp, deviceLabel}` | Returns fingerprints and label only; the root/device private keys never leave OS keystore/Rust (rule 1) |
| `identity.rotateRoot` | command | none → `{newRootFp}` | Signing of `sig_old_root(new_root_pk)` happens entirely inside the Rust engine (ADR-003 §A4, ADR-001 §A12 #26) |
| `device.add.issueQr` | command | none (primary device only) → `{qrPayload}` | QR carries a signed state bundle `{registry endpoint, [{host_fp, host_pk, member_cap}…]}`, not the root key itself (ADR-003 §A4) |
| `device.add.scan` | command | `{qrPayload}` → `{deviceState}` | New device becomes primary only if enrolled via recovery phrase, never via QR (ADR-003 §A4) |
| `device.revoke` | command | `{device_fp}` → ack | Root-signed revocation; propagated to hosts and deposited at the helper even if a host is offline (ADR-003 §A4, ADR-001 §A12 #5, #27) |
| `security.wallEvent` | event | `{kind: key_change\|sig_failure\|fingerprint_mismatch, host_fp}` | Drives a non-dismissable UI wall; transfer blocked until resolved (DESIGN.md §A9) |
| `registry.degraded` | event | `{degraded: bool}` | Distinct from "host offline"; a dead helper must not be symptomless for up to an hour (DESIGN.md §A6, §A9) |

#### Host app (`apps/host`, over `spindle-host-core`)

| Command | Direction | Payload summary | Security note |
|---------|-----------|------------------|----------------|
| `shares.list` | command | none → `[{share_id, name, mount_path, flags, excludes}]` | Owner-only admin surface; no remote admin exists in v1 (DESIGN.md §A10.11) |
| `shares.add` | command | `{name, mount_path, real_root, flags{read_only, allow_upload, show_hidden}, excludes[]}` | Rejects overlapping roots by resolved real path *and* device+inode/file-id at add time and again at host start (ADR-006, ADR-001 §A12 #29) |
| `shares.update` / `shares.remove` | command | `{share_id, ...}` | Exclusion globs re-precompiled; existing sessions re-checked against the new grant table on next request (ADR-006, ADR-001 §A12 #22) |
| `members.list` | command | none → `[{member_id, root_fp, display_name, status, devices[], groups[]}]` | Host-local only; never sent to the registry (ADR-001 §A2 zero-knowledge definition) |
| `members.revokeDevice` / `members.revokePerson` | command | `{member_id, device_fp?}` | Bumps `cap_epoch`; publishes a host-signed revocation record to `registry.revoke`; target cut-off < 5 s (ADR-006, ADR-001 §A12 #5, #22) |
| `groups.list` / `groups.add` / `groups.remove` | command | `{group_id?, name?}` | `Owner` and `Members` are built-in and not editable (ADR-006) |
| `entitlements.set` | command | `{group_id, share_id, subpath, perms: [browse\|download\|upload\|delete]}` | Positive-only union algebra; `upload`/`delete` grantable only on `allow_upload` shares (ADR-006, ADR-001 §A12 #23) |
| `invite.mint` | command | `{initialGroup?, expHours?}` → `{inviteLink, qrPayload}` | Single-use, host-side nonce burn on redemption, hours-scale `exp`, per-nonce rate limit (ADR-003 §A4, ADR-001 §A12 #33) |
| `previewAs.get` | command | `{member_id}` → tree as that member would see it | Read-only projection through the same effective-grant table used for real requests (DESIGN.md §A4b) |
| `sessions.list` | command/event | none → `[{member, device, host_fp?, currentTransfer, bytes}]` | Live connection state only; pushed as an event on change |
| `sessions.softDisconnect` | command | `{session_id}` | Disconnects a live session **without** revoking the member — distinct from `members.revokeDevice` (DESIGN.md §A4b) |
| `audit.read` | command | `{cursor, pageSize}` → `entries[{ts, member, device, action, virtual_path, bytes, outcome}]` | Cursor-paged with a max page size; hash-chained, tamper-evident (ADR-006, ADR-001 §A12 not applicable — integrity property, not an attack row) |
| `host.backup.export` / `host.backup.restore` | command | opaque backup blob | Restoring from backup keeps the same host identity; members are unaffected; no wall triggered (ADR-003 §A4, ADR-001 §A12 #35) |
| `quotas.setEgressCap` | command | `{bytesPerSec}` | Owner bandwidth throttle, distinct from the security-driven per-peer rate limits (DESIGN.md §A4b) |
| `quotas.setFreeSpaceFloor` | command | `{minFreeBytes}` | Pauses uploads before the disk fills (DESIGN.md §A4b) |

## Consequences

### Positive

- Boundary rule 1 (key custody) is directly auditable: every command in both tables above is enumerable, and none
  of them carries key, seed, or cap material — the IPC surface *is* the host/client attack-surface review target
  (ADR-001 §A12 #3, #25).
- Engine substitution (rule 2) means the client and web UIs are built from the same component library
  (`@spindle/ui`) against the same interface (`@spindle/engine-api`), so UX parity between native and browser
  clients (DESIGN.md §A9) is enforced by the import graph, not by manual review.
- Crate layering (rule 3) keeps `spindle-helper` from ever growing host- or client-specific logic, preserving the
  registry's zero-knowledge posture at the code-structure level, not just the protocol level (ADR-001 §A2).
- A single `justfile` front door means CI and local development run identical targets, removing an entire class of
  "works on my machine" / CI-only failures.
- Golden vectors generated by Rust and byte-verified by TypeScript in CI catch canonical-encoding divergence between
  the two engines before it becomes a silent signature-verification failure in production (ADR-004, DESIGN.md §A9b).

### Negative

- Lockstep versioning across the whole repo means a change to any one app or package forces a release train for
  all of them, even when only one frontend actually changed.
- The minimal Tauri capability config (rule 4: no shell, no frontend fs access, no remote content) constrains what
  the host and client UIs can do directly; any new capability needed later requires a boundary-rule review, not
  just a UI change.
- The IPC command list above is explicitly initial; DESIGN.md does not enumerate exact Tauri command signatures, so
  this list is this ADR's own derivation from named features (A9, A8, A4, A4b) and must be reconciled against the
  real implementation before it can be treated as a frozen contract.

### Neutral

- `spikes/` are workspace members but deletable — spikes are expected to graduate into `crates/`/`packages/` code
  or be removed, not to persist indefinitely as parallel implementations.
- The `deploy/` reference docker-compose stack and `just dev` (helper in `open` admission with a local CA) exist
  purely for development/demo purposes; `open` admission mode is a deliberate contrast with the `invite`-default
  production posture (ADR-007).

## Alternatives Considered

DESIGN.md §A11 does not list a rejected alternative repository shape distinct from the one adopted in §A9c; the
directory tree, boundary rules, and dependency manifest above represent the only layout codified for v1. The
alternatives explicitly weighed and rejected elsewhere in DESIGN.md that bear on this ADR's scope:

| Alternative | Verdict | Why |
|-------------|---------|-----|
| WASM Rust core for the browser engine (would collapse "two engines" into one) | Rejected | WebCrypto + `@noble/curves` sufficient for browser crypto; a pure-TS engine avoids a second toolchain in `apps/web` (DESIGN.md §A11, ADR-008) |
| Server-side archive generation for folder download (would add a data path bypassing the client-side transfer manager) | Rejected (v0.8) | Memory/CPU cost on hosts and resume complexity; client-side queue over `list`+`read` instead (DESIGN.md §A11, §A8) |

## Open items

DESIGN.md flags the following as a `[USER DECISION]` still open; it is recorded here as such and is not resolved
by this ADR:

- **A10.24 — License & repo [USER DECISION]**: license is **TBD**; the monorepo shape itself (Rust workspace + TS
  packages) is decided per A9c and is not part of the open item — only the license text/SPDX identifier remains
  unresolved.

## References

- `../DESIGN.md` §A9c (repository layout & toolchain, in full), §A9b (wire schemas, CI matrix, compat policy,
  `just package` release artifacts), §A10 rows 24–27, §A11 (alternatives)
- [ADR-001: Threat Model](./ADR-001-threat-model.md) — §A12 rows #3, #5, #18, #21–23, #25–27, #29, #33, #35 (rows
  closed by mechanisms this ADR's IPC boundary must not bypass)
- [ADR-003: Identity, Capabilities, Enrollment](./ADR-003-identity-capabilities-enrollment.md) — key custody
  location that IPC boundary rule 1 protects
- [ADR-004: End-to-End Signaling Envelope](./ADR-004-e2e-signaling-envelope.md) — canonical CBOR/golden-vector
  cross-check referenced under Consequences
- [ADR-006: Host Authorization — Members, Shares, Entitlements](./ADR-006-host-authorization-members-shares-entitlements.md)
  — shares/members/groups/entitlements/audit-log semantics behind the host IPC table
- [ADR-007: Registry Control Plane](./ADR-007-registry-control-plane.md) — `just dev`'s `open`-admission contrast
  with production `invite` default
- [ADR-008: Browser Client Delivery](./ADR-008-browser-client-delivery.md) — `apps/web` hardened-delivery pipeline
  referenced in the directory tree and release artifacts
- `../SPIKES.md` S1, S11, S16, S18 (negative-test suites named in the CI workflow entry of the directory tree)
