# Spindle — Implementation Plan

> `docs/DESIGN.md` is authoritative for all design decisions; this file tracks staged execution
> only. Per this repo's global development conventions, **this file is deleted once every stage
> below is Complete**.

## Stage 0: Developer environment (ADR-010)
**Goal**: mise-based toolchain provisioning + toolchain image + devcontainer, per ADR-010.
**Success Criteria**: fresh-machine path (install mise → `just bootstrap`) yields working cargo/just/pnpm/node;
`cargo check` passes on the scaffold; Dockerfile.toolchain builds; CI provisions via mise on all 3 OSes.
**Tests**: `just bootstrap && just build && just test` locally; image build job green.
**Status**: Complete
**Note**: verified 2026-08-23 — bootstrap, build/test/lint green locally; toolchain image builds with identical versions; CI green on main after first push.

## Stage 1: Spikes — S3 throughput + S11 VFS confinement
**Goal**: Answer the two highest-risk open questions before any production transport or VFS code
is written: DataChannel throughput under realistic RTT, and `cap-std`-based path confinement
against every known escape/collision class.
**Success Criteria**: S3 is **complete** — resolved via decisions A10.31/A10.32 (transport split:
QUIC for native↔native, WebRTC only for browser peers) rather than by `webrtc-rs`/`datachannel-rs`
clearing the original ≥ 50 MB/s LAN / ≥ 15 MB/s @ 50 ms bar, which the full evidence chain in
`spikes/s3-throughput/RESULTS.md` proved unreachable for WebRTC data channels as shipped, against
any measured peer. That throughput bar now applies to the QUIC native↔native path, verified by
spike S19 (Stage 5), not by S3. S11's negative-test suite (`..`, symlink escape, hardlinks,
overlapping roots, case/Unicode collisions, exclusion bypass, upload scoping, Windows device
names/8.3/ADS/`\\?\` paths, rename races) still needs to pass on macOS, Windows, and Linux.
**Tests**: `spikes/s3-throughput` benchmark harness at 0/20/50/100 ms RTT (done); `spikes/s11-vfs-confinement`
automated negative-test suite (all three OSes in CI).
**Status**: In Progress
**Note**: S3 is **done** (2026-08-24): `webrtc-rs` and `datachannel-rs` both fail the 50 ms bar;
containerized matrix vs. real headless Chromium 151 shows a `webrtc-rs` sender collapse (0.885
MB/s @ 50 ms) and a frozen-cwnd Chrome-dcSCTP→webrtc-rs freeze (0.083 MB/s @ 50 ms, diagnosed via
`rtc_sctp` tracing); the decisive Chromium↔Chromium control (dcSCTP both ends, no Rust code)
plateaus at 0.845 MB/s @ 50 ms too — proving the shortfall is a property of WebRTC data channels
as shipped, not a Rust-crate defect (TCP does 60.7 MB/s on the identical shaped path). Full data:
`spikes/s3-throughput/RESULTS.md`. Resolved by decisions A10.31/A10.32: native↔native moves to
QUIC (`quinn` + standalone ICE); browser peers keep WebRTC with a stated ~1–2 MB/s @ 50 ms
ceiling. ADR-005's Accepted gate moves from S3 to the new spike **S19**
(quinn-over-punched-ICE native↔native), tracked under Stage 5. Stage 1 itself is **In Progress on
S11 alone now** — S11 macOS complete (12/12; Linux/Windows runs pending) is the only remaining
work item for this stage; S3 is fully closed out and no longer blocks Stage 1's own completion.

## Stage 2: spindle-proto + @spindle/proto + golden vectors
**Goal**: Define the wire contract once — canonical CBOR (RFC 8949 §4.2.1) types and the A7b
signed-artifact catalog — in Rust, with a byte-identical TypeScript twin.
**Success Criteria**: `cargo run -p spindle-proto --bin gen-vectors` produces golden vectors for
every A7b artifact type; `@spindle/proto`'s canonical encoder reproduces them byte-for-byte in
CI; any divergence fails the build.
**Tests**: Rust unit tests for each artifact type's canonical encoding; TS vector-comparison
tests in `@spindle/proto`; the `vectors` CI job wired to actually compare (no longer a
placeholder).
**Status**: Complete
**Note**: spindle-proto + golden vectors (25 Rust tests, byte-stable regeneration) and the
@spindle/proto TS twin (171 tests, zero byte mismatches against every vector) both done;
`just vectors` runs the full gate locally (regenerate → git diff --exit-code → TS conformance)
and the CI vectors job runs the same commands. CI cross-check on 3 OSes confirms on next push.

## Stage 3: spindle-core identity/caps/envelope + @spindle/crypto
**Goal**: Implement identity roots, device certs, capabilities, and the A7 end-to-end envelope in
`spindle-core`, with `@spindle/crypto` providing the browser-side primitives.
**Success Criteria**: S6 (browser crypto + `alg_id` interop) passes envelope round-trips
Rust↔browser across 3 browsers; every A7 MUST-check has an automated negative test (signature,
`to_fp`, revocation, `sid`/`seq`, `ts` skew, `kind`, version floor).
**Tests**: `spindle-core` unit tests for each MUST-check; `@spindle/crypto` WebCrypto/`@noble/curves`
parity tests; S6 cross-browser interop harness.
**Status**: In Progress
**Note**: Rust half done: `spindle-core` implements identity (`RootKey` pre-committed rotation,
`DeviceKey`), issue/verify for all six non-`Envelope` A7b signed artifacts, and the A7 envelope
(`seal`/`open`) with a distinct `EnvelopeError` variant and negative test per MUST-check plus
round-trip/bidirectional-session tests (55 unit tests total). `src/bin/gen-crypto-vectors` adds
real-Ed25519-signature/real-AEAD golden vectors under `vectors/signed/*.json` (deterministic,
TEST-ONLY seeds, byte-stable across reruns, wired into `just vectors`/CI); `tests/vectors.rs`
independently reloads and re-verifies them (7 tests). TypeScript half done: `@spindle/crypto`
implements the browser-side twin on top of `@spindle/proto`'s canonical CBOR — dual-backend
Ed25519/X25519 (WebCrypto with `@noble/curves` fallback; HKDF-SHA256/AES-256-GCM/SHA-256 are
WebCrypto-only per A7), fingerprints (`rootFpOf`/`deviceFpOf`/RFC 4648 base32), `verify*` for all
six non-`Envelope` A7b signed artifacts, and `seal`/`open` with the same distinct-error-per-
MUST-check behavior as the Rust `open` — verified byte-for-byte against the real-signature
golden vectors in `vectors/signed/*.json` plus MUST-check negatives and WebCrypto/`@noble/curves`
backend-parity tests (88 tests total). Still pending: the S6 cross-browser interop harness
(tracked separately).

## Stage 4: Helper + NATS callout + deploy compose
**Goal**: Implement the broker helper (`spindle-helper`): Auth Callout responder, presence,
TURN credential minting, durable revocation store, admission verifier — and make
`deploy/docker-compose.yml` actually runnable end to end in `open` admission / dev-CA mode.
**Success Criteria**: S1 (callout negative-test suite) all green; S12 (32 caps + device cert
under `max_control_line` 32 KiB; p99 callout < 250 ms at 5k connects/min) met; S8 (HA, 5k clients
re-auth in a minute, no failed auths) met; S16 (control-plane admit/evict/mode-switch negative
tests) all fail closed.
**Tests**: S1/S8/S12/S16 automated suites graduated into CI; `just dev` brings up a working local
stack.
**Status**: In Progress
**Note**: slice 1 — pure callout-verification core (authz decisions, §A5 permission sets, session
records) done with S1-at-logic-level negative suite; NATS wiring, Postgres store, compose stack
pending. S1 spike: **PASS** (2026-08-24, 19/19 automated checks against a live nats-server;
`spikes/s1-callout/RESULTS.md`) — real Auth Callout loop proven against the unmodified decision
core; flags a pre-existing host_fp derivation mismatch between `decide_device_connect` (op-key)
and `decide_host_connect` (root-key) that needs resolving before this stage's real NATS wiring.
A10.30 cap-chain schema executed on the Rust side; TS twins + docs in flight.
slice 2 — responder graduated into spindle-helper bin (two-connection bridging), deploy compose
dev stack up, S1 suite re-run against it: 18/18 applicable checks passed (1 skipped by design —
`bridging_callout_account_cannot_reach_app_subjects` needs the spike's own standalone responder
process, not the containerized one); Postgres store + coturn pending.

## Stage 5: spindle-net WebRTC + QUIC transport signaling E2E
**Goal**: Implement NATS-mediated WebRTC signaling (offer/answer/trickle ICE) and presence in
`spindle-net`, connecting a real Rust host to a real Rust client end to end. Per ADR-005's
2026-08-24 transport-split amendment (A10.31/A10.32), also implement the native↔native QUIC path:
`quinn` running over a `webrtc-rs`-`ice`-punched UDP socket, with a per-session self-signed cert
pinned via the connect envelope (mirrors the DTLS fingerprint rule) and transport negotiated
inside that envelope (`quic` when both peers are native, WebRTC otherwise).
**Success Criteria**: S2 (median connect < 2 s LAN, < 5 s across NATs) met; S5 (presence ≤ 5 s
clean / ≤ 60 s dead) met; S9 (revoke→kick→reject < 5 s) met; S14 (revoke while host offline;
callout refuses before host returns) met; S18 (cap lifecycle: expiry→connect-only→re-issue;
device bootstrap; no lockout in any path) met; S19 (quinn-over-punched-ICE native↔native: ≥ 15
MB/s @ 50 ms, NAT-combination punch/relay success) met for the QUIC path.
**Tests**: S2/S5/S9/S14/S18/S19 automated suites graduated into CI.
**Status**: Not Started
**Note**: S5 spike: **PASS** (2026-08-25/26, 15/15 automated checks against the composed
`deploy/docker-compose.yml` stack; `spikes/s5-presence/RESULTS.md`) — presence's bar met live
(0.01 s clean / 42.36 s dead vs. the 5 s/60 s bar); two live-only bugs found and fixed (SYS-account
connection wiring for `$SYS.ACCOUNT.*.CONNECT|DISCONNECT`, CONNZ's real `authorized_user` field
name). This validates only the presence slice of this stage's success criteria — S2/S9/S14/S18/S19
and the WebRTC/QUIC signaling work itself remain not started, so this stage's own Status is
unchanged.

## Stage 6: spindle-vfs + host-core
**Goal**: Implement the shares/groups/entitlements engine and the VFS RPC server in
`spindle-vfs`/`spindle-host-core`, enforcing A4b's permission algebra per request.
**Success Criteria**: S11's full negative-test suite runs in CI against the real implementation
(not just the Stage 1 spike); A4b semantics tests pass (positive-only union, traversal implied
by browse, upload-without-listing, delete-required-to-overwrite, case/Unicode collision ==
overwrite, not-found for unauthorized paths).
**Tests**: `spindle-vfs`/`spindle-host-core` unit + integration tests; S11 suite in CI.
**Status**: In Progress
**Note**: slice 1 — `spindle-vfs`'s two foundation modules, both pure/in-memory (no SQLite, no
VFS RPC, no `spindle-host-core` yet). `confine` graduates S11's prototype helpers to production
quality (real `thiserror` error types, doc comments citing the A12 rows each closes): share-root
`cap-std` capabilities, dev+ino/file-id identity checks, the hardlink-`nlink` exclusion-bypass
guard, overlapping-root rejection, case/Unicode fold-key collision detection, and upload-path
scoping + overwrite-requires-delete gating — S11's tested semantics preserved exactly, spike left
untouched. `algebra` implements the positive-only union entitlement algebra over new `model`
structs (`Share`/`Group`/`Member`/`Entitlement`), with every §A4b edge rule unit-tested
individually (browse-implies-ancestor-traversal, upload-implies-resolve-without-listing,
delete-does-not-imply-download, overwrite-requires-delete, fold-collision-is-overwrite,
not-found-is-indistinguishable-from-nonexistent) plus the negative suite (new share/member →
nothing visible, no sibling/ancestor leakage, excluded paths invisible even to broad grants).
`glob` is a minimal hand-rolled exclude-glob matcher (no workspace-available glob crate to reuse).
40 tests total (36 passing, 4 real-bodied Windows-only cases compile-gated); `cargo fmt`/`clippy
-D warnings` clean. Pending: SQLite persistence, the VFS RPC server, the tamper-evident audit
chain, `spindle-host-core`, and the mount-path-to-share virtual-tree resolution step (flagged as
an open ambiguity — §A4b does not specify how a raw client-facing virtual path resolves to
`(share_id, subpath)` across multiple mounted shares).

## Stage 7: client-core + Tauri apps init + engine-api/engine-tauri/ui
**Goal**: Implement `spindle-client-core`; initialize `apps/host` and `apps/client` as real Tauri
2 apps (`pnpm create tauri-app`); implement `@spindle/engine-api`, `@spindle/engine-tauri`, and
the shared `@spindle/ui` components.
**Success Criteria**: S13 (host operating-key rotation/reinstall — members see no wall, sessions
resume) met; S15 (recovery-phrase + primary-device comprehension test — tester backs up phrase,
adds a second device, recovers unaided) met; S10 (invite/redeem + "Preview as" + permission grid
usability test — non-technical tester completes unaided) met.
**Tests**: S10/S13/S15 usability/automated suites; Tauri IPC command allowlist matches ADR-009's
enumerated list (lint-enforced engine-api-only imports).
**Status**: Not Started

## Stage 8: engine-web + apps/web + hardened delivery
**Goal**: Implement `@spindle/engine-web` (nats.ws + browser WebRTC) and the `apps/web` browser
client, including the ADR-008 hardened-delivery pipeline (reproducible build, signed manifest,
SRI, verification extension).
**Success Criteria**: S7 (5 GB receive in Chromium; fallback ceiling measured; resume works) met;
S17 (tampered bundle flagged in all 3 browsers; honest bundle passes) met.
**Tests**: S7/S17 automated suites; reproducible-build verification in CI.
**Status**: Not Started

## Stage 9: Admin library + CLI
**Goal**: Implement `@spindle/admin` (command signing, pluggable `Signer`, NATS connection logic)
and the `spindle-admin` CLI over it.
**Success Criteria**: S16's admin-specific negative tests pass (reused admission token rejected,
forged admin command rejected, evicted host reconnect refused, admin connection without mTLS
refused).
**Tests**: S16 admin negative-test subset in CI; CLI integration tests against a running helper.
**Status**: Not Started

## Stage 10: Packaging/signing + release train
**Goal**: Produce real release artifacts per A9b: signed/notarized Tauri bundles (host, client),
the hardened web bundle + manifest, the helper container image, and the `spindle-admin` npm
tarball, with a compat matrix and staged-rollout updater.
**Success Criteria**: `just package` produces all four artifact classes; macOS notarization and
Windows code signing are acquired and wired in; the N−1 wire-format compat policy is documented
and tested; staged rollout works end to end on a test channel.
**Tests**: packaging pipeline smoke test on all 3 OSes in CI; compat-matrix tests against the
previous release's wire formats.
**Status**: Not Started
