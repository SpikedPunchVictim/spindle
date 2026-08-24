# Spindle — Spikes

> Source of truth for spike scope and pass/fail is `docs/DESIGN.md` §A13. This file does not
> restate or reinterpret those pass criteria — it quotes them verbatim and adds the "how to run
> it" detail A13's table doesn't have room for. If this file and DESIGN.md ever disagree,
> DESIGN.md wins; fix this file.

## Why spikes, and how to read this file

Spindle's design (`docs/DESIGN.md`) makes several claims that no amount of additional design
review can settle — DataChannel throughput under real RTT, whether `cap-std` actually closes
every VFS escape, whether a non-technical person can use the permission model unaided. Spikes are
small, throwaway programs that answer one such question each, with a **measured pass/fail
criterion**, before the ADR or implementation stage that depends on the answer is accepted.

- **Order**: the eighteen spikes below are listed in `docs/DESIGN.md` §A13's risk order — highest
  risk first (S3, S7), then the next tier (S1, S11), then the rest. Run them in this order unless
  a dependency forces otherwise.
- **Gates**: each spike's "Gates" line cross-references the `IMPLEMENTATION_PLAN.md` stage(s) that
  cannot start (or cannot be marked Complete) until the spike passes, and the ADR(s) whose design
  claims the spike validates. Per DESIGN.md's Part B verification note: *"S3 before any transport
  ADR is Accepted"*; S1 and S11 negative tests are automated as a hard requirement, not a nice-to-have.
- **Pass criteria are authoritative in DESIGN.md §A13** — nothing below invents a new one. Where a
  criterion looks incomplete on its own (e.g. "knobs documented"), that is because A13's table cell
  is intentionally terse; the method sketch explains what satisfying it looks like without changing
  what "passing" means.
- **CI graduation (§A9b)**: S1, S11, S16, and S18 are not just one-time spikes — their negative-test
  suites are required to graduate into the permanent CI matrix (3-OS) per `docs/DESIGN.md` §A9b:
  *"CI matrix: 3 OSes; S1/S11/S16/S18 negative suites graduate into permanent CI."* Passing the
  spike once is necessary but not sufficient; the suite has to keep passing on every future commit.
- **Status**: all spikes are **Not run** as of this writing, except **S3** and **S11**, which have
  runnable (but empty-result) skeletons under `spikes/` — see `spikes/s3-throughput/` and
  `spikes/s11-vfs-confinement/`. A skeleton existing does not mean the spike has been run.

---

## S3 — DataChannel throughput at 0/20/50/100 ms RTT

**Question** (A13): DataChannel throughput at 0/20/50/100 ms RTT; SCTP tuning.

**Method sketch**:
- Two peers using the `webrtc` crate (workspace pin `>=0.20`, sans-I/O core per A8); fall back to
  `datachannel-rs` only if `webrtc` cannot hit the pass bar (A8: *"evaluate `datachannel-rs` if S3
  fails"*).
- Run the pair over a controlled-latency link: `tc netem` (Linux) or Network Link Conditioner
  (macOS) / an equivalent WAN emulator on Windows, set to 0, 20, 50, and 100 ms RTT.
- One reliable-ordered control channel + one unordered-reliable data channel, sharing a single
  SCTP association (A8: *"more channels don't add throughput"*) — do not spike a multi-channel
  variant.
- Transfer a large synthetic payload in 64 KiB chunks (A8's chosen chunk size) with backpressure
  via `bufferedAmountLow`; vary SCTP send/receive buffer sizes at each RTT point.
- Record MB/s per (RTT, buffer-config) cell in `RESULTS.md`; note which buffer settings were needed
  to clear the bar at 50 ms.

**Pass criterion (verbatim, A13)**: *"≥ 50 MB/s LAN; ≥ 15 MB/s @ 50 ms; knobs documented."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 1 (cannot be marked Complete without this) and — per
DESIGN.md Part B's verification note — **ADR-005** (transport, VFS RPC, file safety) cannot move
to Accepted until S3 passes. Also sets the v1 numbers referenced in DESIGN.md §A9's UX bar
("goals ≥ 50 MB/s LAN native and ≥ 15 MB/s at 50 ms RTT (**S3 sets the v1 numbers**)").

**Status**: Run 2026-08-23 — webrtc-rs FAILS the 50 ms bar (2.2 MB/s vs ≥15 MB/s); loopback
passes (125+ MB/s); datachannel-rs evaluation in progress per §A8 fallback.
- Loopback (macOS arm64, 0 ms RTT): 125–128 MB/s — clears the ≥ 50 MB/s LAN bar.
- RTT matrix (Linux container, `tc netem`): ~95 MB/s @ 0 ms, ~5 MB/s @ 20 ms, ~2.2 MB/s @ 50 ms,
  ~1.3 MB/s @ 100 ms — misses the ≥ 15 MB/s @ 50 ms bar by ~85%.
- Buffer/window tuning does not help: the smallest buffer was consistently fastest across the
  matrix, pointing to a congestion-control/ACK-clocking ceiling in the crate's SCTP stack rather
  than a bandwidth-delay-product/window-size problem. See `spikes/s3-throughput/RESULTS.md`.
- **Follow-up (2026-08-23)**: TCP through the same netem path does 60 MB/s @ 50 ms with zero drops
  — the environment is not the bottleneck. Parallel SCTP associations scale sub-linearly (1.9/3.7/
  6.8/7.7 MB/s at N=1/2/4/8), plateauing below the ≥ 15 MB/s bar.
- **Decision A10.29 (2026-08-23)**: investigate deeper first — measure against a real Chrome peer
  (dcSCTP) and profile webrtc-rs cwnd before revising the A9 bar or reopening the transport choice;
  ADR-005 stays Proposed; Stages 2–4 proceed meanwhile.

---

## S7 — Browser large-file sink; tab throttling; sleep/resume

**Question** (A13): Browser large-file sink; tab throttling; sleep/resume.

**Method sketch**:
- Drive a real Chromium instance receiving a large synthetic transfer (target 5 GB) over the
  browser receive path described in A8: File System Access API where available, streaming-download
  fallback with a stated ceiling (A10.6).
- Exercise the resumable-transfer machinery from A8: resume manifest + offsets + per-chunk hashes,
  persisted to IndexedDB, so a resume can actually be triggered and checked.
- Force background-tab throttling and OS sleep/resume mid-transfer (DevTools throttling, or
  literally backgrounding the tab / suspending the machine) and confirm the transfer resumes rather
  than silently stalling or corrupting.
- Where FSA is unavailable, measure the actual ceiling the streaming-download fallback holds up to
  (A10.6 flags this as a still-open default, e.g. "2 GB" — S7 is what turns that into a number).
- Record results per browser/OS combination in `RESULTS.md`.

**Pass criterion (verbatim, A13)**: *"5 GB receive in Chromium; fallback ceiling measured; resume
works."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 8 (`@spindle/engine-web` + `apps/web` + hardened
delivery) — Stage 8's own success criteria repeat this pass bar verbatim. Validates **ADR-005**
(file-safety / transfer-manager resume semantics, A8) and the browser receive-ceiling default in
**ADR-009**'s dependency manifest / DESIGN.md §A10.6.

**Status**: Not run.

---

## S1 — Callout verifying self-signed caps; scoped perms; no-cap refusal

**Question** (A13): Callout verifying self-signed caps; per-device inbox; scoped perms; no-cap
refusal.

**Method sketch**:
- Stand up a NATS instance with Auth Callout wired to a broker-helper callout responder (A3, A5)
  and a handful of simulated devices/hosts, some holding valid host-signed caps, some not.
- Automated negative-test harness attempting each of the specific attacks A13 names:
  - another device's `_INBOX_<dfp>.>` prefix — assert unreadable;
  - connect to a host for which the device holds no cap — assert unreachable;
  - subscribe/publish into another client's `sess.<cfp>.<sid>` — assert unreachable;
  - trigger `allow_responses` with a forged/foreign reply-subject prefix — assert rejected;
  - connect with a freshly generated device key presenting no cap at all — assert refused
    outright (A5: *"A connection presenting no valid cap is refused"*).
- Each case should be a single automated test that fails loudly (not just logs a warning) if the
  attack succeeds.

**Pass criterion (verbatim, A13)**: *"Automated negative tests: other inbox unreadable; un-capped
host unreachable; other client's session unreachable; reply-prefix bypass rejected; fresh key with
no cap refused."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 4 (Helper + NATS callout + deploy compose) — Stage 4's
own success criteria require "S1 (callout negative-test suite) all green." Validates **ADR-002**
(NATS signaling, §A5 subject/permission model) and **ADR-003** (identity, capabilities,
enrollment). Per §A9b, this suite graduates into permanent CI.

**Status**: **PASS — run 2026-08-24.** 19/19 automated checks green against a live
`nats-server:2.10-alpine` (v2.10.29), covering all five A13 attacks plus positive-permission and
`$SYS`/`$JS` denial checks. `spindle-helper`'s decision core
(`crates/spindle-helper/src/{authz,permissions,session}.rs`) wired unmodified to the real Auth
Callout loop. Also answers ADR-002's "to be finalized in S1" broker-connection-topology row: two
separate NATS connections (one per account) are required — account boundaries, not permission
lists, enforce the isolation. One significant pre-existing design ambiguity found and **not**
patched here (out of this spike's scope): `decide_device_connect` scopes host subjects by the
host's *operating*-key-derived `host_fp`, while `decide_host_connect` scopes the host's own
connection permissions by its *root*-key-derived `host_fp` — these diverge whenever a host's root
and op keys differ, which needs a DESIGN.md/ADR-002 decision before Stage 4 wires this up for
real. Full detail, JWT claim structures, and a harness bug found/fixed (double subscription
delivery silently burning the `allow_responses` budget) in `spikes/s1-callout/RESULTS.md`.

---

## S11 — VFS confinement (`cap-std`)

**Question** (A13): VFS confinement (`cap-std`): `..`, symlink escape, hardlinks, overlapping
roots, case/Unicode collisions, exclusion bypass, upload scoping, Windows device names / 8.3 / ADS
/ `\\?\` paths, rename races.

**Method sketch**:
- Build the negative-test matrix across macOS, Windows, and Linux, exercising every attack case
  DESIGN.md §A4b/§A8 name explicitly:
  - `..` traversal and absolute-path tricks against a share root opened as a `cap-std` `Dir`;
  - symlink escape (a symlink inside the share pointing outside the root — must not be followed);
  - hardlinks: a file with link count > 1 inside a share that has exclusions (A4b: such files
    "are not served — hardlink bypass");
  - overlapping share roots — rejected at add-time by resolved real path *and* device+inode/file-id,
    re-checked at host start;
  - case-insensitive / Unicode-normalization collisions with an existing dirent — must be treated
    as an overwrite (A4b), not a silent new entry;
  - exclusion bypass via any of the above;
  - upload landing outside the granted subpath;
  - overwrite of an existing entry without `delete` permission;
  - Windows-specific cases: reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`…), 8.3
    short-name aliasing, Alternate Data Streams (`file.txt:hidden`), and `\\?\`-prefixed
    long/UNC paths;
  - rename/TOCTOU races — mutate the file between `stat` and `read`/`upload` or across a chunk
    boundary and confirm the request aborts (A4b: "every request re-resolves from the share `Dir`
    ... aborting on change").
- Run identically on all three target OSes (macOS + Windows + Linux, per DESIGN.md §A10.9); this
  is a CI-matrix job, not a single-machine run.
- Pin `cap-std >= 3.4.1` (A4b explicitly calls out RUSTSEC-2024-0445 and Windows DOS/UNC
  device-path handling as covered here).

**Pass criterion (verbatim, A13)**: *"Automated negative tests all pass on macOS/Windows/Linux."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 1 (skeleton, this crate) and Stage 6 (`spindle-vfs` +
`spindle-host-core` — Stage 6's success criteria require "S11's full negative-test suite runs in
CI against the real implementation, not just the Stage 1 spike"). Validates **ADR-005**
(transport, VFS RPC, file safety) and **ADR-006** (host authorization: members, shares,
entitlements — the confinement rules live in §A4b). Per §A9b, this suite graduates into permanent
CI.

**Status**: Run 2026-08-23 on macOS — 12/12 blocked; Linux/Windows pending.
- Empirical finding: `cap-std` structurally guarantees only `..`-traversal, absolute-path, and
  symlink-escape blocking; the hardlink `nlink` rule, overlapping-root rejection, case/Unicode-
  collision detection, and TOCTOU identity checks are entirely Spindle-side (prototype helpers
  written in the spike, to graduate into `spindle-vfs`). See `spikes/s11-vfs-confinement/RESULTS.md`.

---

## S2 — `webrtc-rs` ↔ browser trickle ICE over NATS

**Question** (A13): `webrtc-rs` ↔ browser trickle ICE over NATS.

**Method sketch**:
- Wire up the real signaling flow from DESIGN.md §A6: `host.<h>.connect` request/reply, then
  trickle ICE over `sess.<c>.<sid>.c2h` / `.h2c`, between a real `webrtc-rs` host and a real
  browser client (or, at minimum, a second `webrtc-rs` instance standing in for browser ICE
  behavior if a browser harness isn't ready yet).
- Exercise both LAN (no NAT) and cross-NAT paths (two networks, or a NAT-simulating test rig) so
  both halves of the pass bar are measured, not just the easy one.
- Time from `connect` request to DataChannel open (post-DTLS-handshake), per §A6's flow diagram.
- Confirm the loss-tolerant/retry behavior A6 requires ("`connect` timeout covers the answer only
  (5 s, one retry); ICE streams independently; losses tolerated/retried") under induced packet
  loss.

**Pass criterion (verbatim, A13)**: *"Median connect < 2 s LAN, < 5 s across NATs."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 5 (`spindle-net` WebRTC signaling E2E) — Stage 5's
success criteria require this bar met. Validates **ADR-002** (NATS signaling, §A6 flows) and
**ADR-005** (transport).

**Status**: Not run.

---

## S8 — Helper HA; 5k clients re-auth in a minute

**Question** (A13): Helper HA; 5k clients re-auth in a minute.

**Method sketch**:
- Stand up the broker-helper as designed: ≥2 replicas in a queue group, single-writer leader over
  Postgres (§A9b consistency model), fronted by NATS with `max_control_line` and per-IP limits per
  §A10.10.
- Load-test harness that forces 5,000 simulated client connections to re-authenticate (fresh
  Auth Callout round-trip) within a one-minute window — e.g. simulating the JWT-expiry-driven
  reconnect storm A9b's "jittered exp in [45, 75] min" is meant to avoid, or a coordinated restart.
- Measure: count of failed auths (must be zero) and p99 callout latency across the whole run.
- Kill a replica mid-run to confirm HA behavior (no auth failures attributable to the replica
  loss), consistent with the single-writer-leader model.

**Pass criterion (verbatim, A13)**: *"No failed auths; p99 callout < 250 ms."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 4 (Helper + NATS callout + deploy compose) — Stage 4's
success criteria require this bar met alongside S1/S12/S16. Validates **ADR-007** (registry
control plane) and the helper HA/consistency claims in **ADR-002**/§A9b.

**Status**: Not run.

---

## S4 — NAT traversal with/without coturn; cost model

**Question** (A13): NAT traversal with/without coturn; cost model.

**Method sketch**:
- Exercise real connection attempts across a range of NAT types (full-cone, restricted, symmetric)
  with STUN only, and again with coturn TURN relay available as fallback (A8: "relay only if
  hole-punch fails" per the architecture diagram; `iceTransportPolicy: relay` as the privacy
  option).
- coturn configured per §A8/§A9b: `use-auth-secret`, `username = expiry:device_fp`, short TTLs,
  per-`root_fp` quota (not per device — A8 explicitly moved this off `device_fp` to prevent quota
  bypass via fresh device keys, A12 #28).
- Measure the fraction of connections that require relay vs. successful direct hole-punch across
  the NAT-type matrix.
- From measured relay bandwidth and coturn's real hosting cost, compute a cost/GB figure — this is
  the number §A10.8 ("[USER DECISION] self-host coturn; per-device monthly relay quota; S4 →
  cost/GB") is waiting on.

**Pass criterion (verbatim, A13)**: *"Relay %; cost/GB."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 4/Stage 5 (TURN credential minting is a Stage-4 helper
responsibility; NAT traversal is exercised end-to-end in Stage 5). Validates **ADR-005**
(transport) and resolves the open TURN cost/quota policy in DESIGN.md §A10.8.

**Status**: Not run.

---

## S5 — Presence via `$SYS` events; ping tuning

**Question** (A13): Presence via `$SYS` events; ping tuning.

**Method sketch**:
- Build the presence pipeline from §A6: helper reconstructs a live connection map from
  `$SYS.REQ.SERVER.PING.CONNZ` on start plus `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` deltas, answers
  `helper.presence.get`, and pushes deltas on `host.<hfp>.presence`.
- Subscribe a test client and force two disconnect scenarios: a clean disconnect (normal
  DISCONNECT event) and a dead socket (network partition with no FIN, so only ping timeout
  detects it).
- Tune `ping_interval` (~20 s) / `ping_max` (2) per §A6 and measure actual detection latency for
  each scenario against those settings.
- Also verify the one-to-many / overlap semantics §A6 calls out: multiple connections per
  `device_fp` (native app + browser tab) don't flip presence, and reconnect-before-stale-disconnect
  never flips a live host to offline.

**Pass criterion (verbatim, A13)**: *"≤ 5 s clean / ≤ 60 s dead."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 5 (`spindle-net` WebRTC signaling E2E) — Stage 5's
success criteria require this bar met. Validates **ADR-002** (§A6 signaling flows) and the "Open
app" / host-list row of the DESIGN.md §A9 UX bar.

**Status**: Not run.

---

## S6 — Browser crypto + `alg_id` interop

**Question** (A13): Browser crypto + `alg_id` interop.

**Method sketch**:
- Build an envelope round-trip harness (§A7): one side is `spindle-core` in Rust producing a
  signed/encrypted envelope; the other is `@spindle/crypto` in a real browser, and vice versa.
- Use the real primitive set from §A7/§A9c: WebCrypto Ed25519/X25519 with `@noble/curves` as
  fallback, AES-256-GCM with deterministic direction+seq nonces, HKDF-SHA256 session-key
  derivation.
- Run the same round-trip across the three named target browsers (§A7: "Firefox 129+, Safari 17+,
  Chrome 137+") to catch WebCrypto availability/behavior gaps per engine.
- Confirm the receiver-side MUST-checks from §A7 (signature under pinned key, `to_fp`, `seq`
  monotonic, `ts` skew, `kind`, version floor) are exercised, not just the happy path.

**Pass criterion (verbatim, A13)**: *"Envelope round-trip Rust↔browser, 3 browsers."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 3 (`spindle-core` identity/caps/envelope +
`@spindle/crypto`) — Stage 3's success criteria require this pass explicitly. Validates
**ADR-004** (E2E signaling envelope).

**Status**: Not run.

---

## S9 — Revoke → kick → host rejects

**Question** (A13): Revoke → kick → host rejects.

**Method sketch**:
- Trigger a real revocation per §A4: host publishes a host-signed revocation record to
  `registry.revoke`, the helper stores it durably and issues a kick
  (`$SYS.REQ.SERVER.<id>.KICK`) from its connection map.
- With a live VFS session open against the revoked device/member, measure wall-clock time from
  the revocation call to: (a) the live NATS connection being kicked, and (b) the host itself
  rejecting the now-live-but-unauthorized VFS request (the authoritative check, per §A4b — the
  kick is defense in depth, not the only mechanism).
- Confirm both paths independently — a kick that succeeds but a host that still serves stale
  in-flight requests would be a false pass.

**Pass criterion (verbatim, A13)**: *"< 5 s end to end."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 5 (`spindle-net` WebRTC signaling E2E) — Stage 5's
success criteria require this bar met. Validates **ADR-003** (identity, capabilities, enrollment —
§A4 revocation) and the "Lost device" row of DESIGN.md §A9's UX bar.

**Status**: Not run.

---

## S10 — Invite/redeem + "Preview as" + permission grid usability

**Question** (A13): Invite/redeem + "Preview as" + permission grid with a non-technical tester.

**Method sketch**:
- Recruit a non-technical tester (§A9b/§A9 target audience) and hand them a real build with a
  working invite/redeem flow, the "Preview as …" feature, and the Groups × Shares permission grid
  described in §A4b's Operator UX.
- Task: "invite someone to a group," "see what they'd see" via Preview-as, and interpret the
  resulting permission grid — with no coaching once the task starts.
- Observe whether they complete each step unaided (note every point they got stuck or asked for
  help); afterward, ask them to explain in their own words *why* a given member can see what they
  see, and check it against the actual union-of-groups algebra (§A4b).
- This is a usability test, not an automated suite — the pass criterion is about the tester's
  behavior and comprehension, and needs a written observation log per session in `RESULTS.md`.

**Pass criterion (verbatim, A13)**: *"Completes unaided; can explain why a member sees what they
see."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 7 (client-core + Tauri apps init + engine-api/ui) —
Stage 7's success criteria require S10 met alongside S13/S15. Validates **ADR-006** (host
authorization: members, shares, entitlements) and the "Invite someone" / "Share a folder" rows of
DESIGN.md §A9's UX bar.

**Status**: Not run.

---

## S12 — CONNECT size (32 caps under `max_control_line`); callout cost at scale

**Question** (A13): CONNECT size: 32 caps + device cert under `max_control_line` 32 KiB; callout
cost at 5k connects/min.

**Method sketch**:
- Construct a real CONNECT payload holding the maximum allowed 32 host caps (§A10.5) plus a device
  certificate, using the actual compact-CBOR cap encoding (~200 B each per §A4) and confirm the
  serialized size fits under the 32 KiB `max_control_line` set in §A10.10.
- Load-test the Auth Callout responder at a sustained 5,000 connects/minute and record p99 latency
  for the callout step alone.
- Separately verify the per-IP connection/rate limiter in front of NATS actually blocks a flood
  attempt (§A3: "the callout is the DoS surface" — this is the mitigation being validated).

**Pass criterion (verbatim, A13)**: *"Fits; p99 callout < 250 ms; per-IP limiter blocks flood."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 4 (Helper + NATS callout + deploy compose) — Stage 4's
success criteria require this bar met alongside S1/S8/S16. Validates **ADR-002** (§A5 subject and
permission model, including the §A10.5/§A10.10 defaults it verifies) and **ADR-003** (cap
presentation, §A4).

**Status**: Not run.

---

## S13 — Host operating-key rotation / reinstall from backup

**Question** (A13): Host operating-key rotation / reinstall from backup.

**Method sketch**:
- Rotate a running host's operating key (host root re-signs a new operating key per §A4) with
  members actively connected, and confirm no key-change wall is shown — §A4 states rotating or
  reinstalling the operating key from backup "does **not** trigger the key-change wall," since
  members pin the host *root*, not the operating key.
- Separately, simulate a full host reinstall from a backed-up host root (per §A9 "Host reinstall"
  row) and confirm the restored host presents the same identity and existing members are
  unaffected.
- Confirm any in-flight or freshly-opened sessions resume/connect normally in both scenarios.

**Pass criterion (verbatim, A13)**: *"Members see no wall; sessions resume."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 7 (client-core + Tauri apps init) — Stage 7's success
criteria require this bar met. Validates **ADR-003** (identity, capabilities, enrollment — §A4
host identity, §A10.13).

**Status**: Not run.

---

## S14 — Revoke a device while its host is offline

**Question** (A13): Revoke a device while its host is offline.

**Method sketch**:
- Take a host offline (stop the daemon / cut its NATS connection) while it still has an active
  member/device relationship.
- From a client, issue a root-signed device revocation (§A4: "delivered to each host on next
  contact *and* deposited at the helper so the callout refuses it even while hosts are offline").
- Attempt to reconnect as the revoked device *before* the host comes back — confirm the callout
  refuses it using the helper's durable revocation store.
- Bring the host back online and confirm it also rejects the revoked device on contact
  (authoritative per-request check, §A4b), independent of what the callout already did.

**Pass criterion (verbatim, A13)**: *"Callout refuses before host comes back; host rejects on
return."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 5 (`spindle-net` WebRTC signaling E2E) — Stage 5's
success criteria require this bar met alongside S2/S5/S9/S18. Validates **ADR-003** (§A4
revocation, A12 #27).

**Status**: Not run.

---

## S15 — Recovery-phrase + primary-device comprehension

**Question** (A13): Recovery-phrase + primary-device comprehension with the S10 tester.

**Method sketch**:
- Reuse the S10 tester pool (§A13 explicitly ties these together) for continuity of baseline
  technical comfort.
- Task 1: have them go through enrollment and back up their recovery phrase unaided, per the
  in-product messaging described in §A9b ("no one, including the operator, can recover this for
  you").
- Task 2: have them add a second device via the real flow (§A4/§A9: scan QR from the primary
  device, or enter the recovery phrase).
- Task 3 (the real test): without the original primary device, have them recover the root onto a
  fresh device using only the recovery phrase they backed up in Task 1, unaided.
- Log where they hesitated or needed help at each step in `RESULTS.md`.

**Pass criterion (verbatim, A13)**: *"Backs up phrase; adds a second device; recovers on a fresh
device unaided."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 7 (client-core + Tauri apps init) — Stage 7's success
criteria require this bar met alongside S10/S13. Validates **ADR-003** (§A4 recovery, §A10.4).

**Status**: Not run.

---

## S16 — Control plane: admit, evict, mode switch; negative tests

**Question** (A13): Control plane: admit (token + pre-reg), evict, mode switch; negative tests
(reused token, forged command, evicted host reconnect, admin without mTLS).

**Method sketch**:
- Exercise both admission mechanisms from §A3b: a single-use admission-invite token redeemed by a
  prospective host, and fingerprint pre-registration by the operator.
- Exercise eviction (`suspend/evict` per §A3b operator capabilities) and mode switching
  (`invite`/`open`/`closed`) as signed admin commands via `@spindle/admin`.
- Automated negative-test cases, each asserting fail-closed:
  - replay an already-burned admission token — rejected;
  - submit an admin command with a forged/invalid operator signature — rejected;
  - reconnect attempt from a host that was just evicted — refused;
  - attempt an admin connection over the TCP listener without the mandatory mTLS profile
    (§A3b: "Admin NATS connections MUST use the mTLS profile") — refused.
- Time the happy path separately: admission token redemption to that host's first successful
  client-facing connect.

**Pass criterion (verbatim, A13)**: *"All negative tests fail closed; admit→first-connect < 10 s."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 4 (Helper + NATS callout + deploy compose, for the core
admit/evict/mode-switch suite) and Stage 9 (Admin library + CLI, for the admin-specific negative
subset — "reused admission token rejected, forged admin command rejected, evicted host reconnect
refused, admin connection without mTLS refused"). Validates **ADR-007** (registry control plane).
Per §A9b, this suite graduates into permanent CI.

**Status**: Not run.

---

## S17 — Hardened web delivery: tamper detection

**Question** (A13): Hardened web delivery: reproducible build → signed manifest → verification
extension detects a tampered bundle.

**Method sketch**:
- Produce a reproducible build of the web client bundle and a release-key-signed manifest
  (§A2/§A10.20; release key is distinct from the operator key).
- Serve an honestly-unmodified copy of the bundle and confirm the companion verification extension
  (Code-Verify pattern) validates it against the published manifest cleanly.
- Serve a deliberately tampered copy (modify a served asset post-build, simulating a malicious or
  compromised operator per adversary A2) and confirm the extension flags the mismatch.
- Run both cases in all three target browsers named for S6 (Chrome, Firefox, Safari), since the
  extension mechanism differs by browser platform.

**Pass criterion (verbatim, A13)**: *"Tampered bundle flagged in all 3 browsers; honest bundle
passes."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 8 (`@spindle/engine-web` + `apps/web` + hardened
delivery) — Stage 8's success criteria require this bar met alongside S7. Validates **ADR-008**
(browser client delivery).

**Status**: Not run.

---

## S18 — Cap lifecycle: expiry, offline renewal, device bootstrap

**Question** (A13): Cap lifecycle: expiry while offline → connect-only → E2E re-issue; device
bootstrap QR state bundle; refetch on second device.

**Method sketch**:
- Exercise the no-lockout renewal path from §A4: let a member's cap go stale/expired while the
  client was offline, reconnect, confirm the callout still grants connect-only NATS permissions
  (signature-valid, not revoked), and confirm the host verifies the device over the E2E channel
  and re-issues a fresh cap in its reply.
- Exercise device bootstrap: scan a QR from the primary device and confirm the new device receives
  the full state bundle (§A4: `{registry endpoint, [{host_fp, host_pk, member_cap}…]}` — "the QR
  transfers state, not just a signature") and that every pinned host accepts it automatically.
- Exercise the standalone refetch path: an already-root-certified device re-fetching its cap
  directly from a host (connect-only → E2E re-issue), independent of the bootstrap flow.
- Confirm none of these paths ever produces a dead end — the pass bar is explicitly "no lockout in
  any path," so the test matrix should include edge orderings (e.g. cap expired *and* epoch bumped
  while offline) as well as the straightforward cases.

**Pass criterion (verbatim, A13)**: *"No lockout in any path; second device reaches all hosts
unaided."*

**Gates**: `IMPLEMENTATION_PLAN.md` Stage 5 (`spindle-net` WebRTC signaling E2E) — Stage 5's
success criteria require this bar met alongside S2/S5/S9/S14. Validates **ADR-003** (identity,
capabilities, enrollment — §A4 cap lifecycle, §A10.3). Per §A9b, this suite graduates into
permanent CI.

**Status**: Not run.
