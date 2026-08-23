# ADR-002: NATS Core for Peer Discovery, Authentication, and WebRTC Signaling

## Status

Proposed — revises the original `SPINDLE_ADR.pdf` ADR-002 ("NATS Core over mTLS for Peer Discovery, Authentication,
and WebRTC Signaling"). Remains **Proposed** until spikes **S1** (callout negative-test suite) and **S12** (CONNECT
size / callout cost at scale) pass; see `docs/SPIKES.md`.

## Context

The original ADR-002 assumed NATS static `verify_and_map` authorization and registry-held accounts. DESIGN.md v0.5
removed registry accounts entirely (user decision, 2026-08-23: "accounts live only on each server; the registry only
facilitates connections") and replaced static account mapping with a self-verifying, host-signed capability model
enforced through NATS **Auth Callout**. This ADR captures the resulting signaling architecture: the registry is a
connection broker only — it holds no accounts, introduces no keys, and cannot read file contents or signaling
payloads (ADR-001 §A2).

## Decision

### Architecture overview (DESIGN.md §A3, verbatim)

```
                 ┌──────────────────────────────────────────────────────────────┐
                 │                Registry (operator-run) — connection broker   │
                 │  ┌───────────────┐  $SYS.REQ.USER.AUTH    ┌────────────────┐ │
                 │  │ NATS cluster  │◄──────────────────────►│ Broker helper  │ │
                 │  │ TLS (server   │  $SYS.ACCOUNT.*.       │ (≥2 replicas)  │ │
                 │  │ cert) on TCP  │  CONNECT/DISCONNECT    │ - callout:     │ │
                 │  │ and WebSocket │◄──────────────────────►│   verify caps  │ │
                 │  │ listeners     │  registry.revoke        │ - presence     │ │
                 │  │ [opt: mTLS on │◄───────────────────────│ - TURN creds   │ │
                 │  │  TCP listener]│                        │ - kick relay   │ │
                 │  └──▲─────────▲──┘                        │ - revoc. store │ │
                 │     │         │                           └────────────────┘ │
                 │     │         │                  ┌───────────────┐           │
                 │     │         │                  │ TURN (coturn) │           │
                 └─────┼─────────┼──────────────────┴───────▲───────┴───────────┘
           TLS (TCP)   │         │ TLS (WSS)                 │ relay only if
                       │         │                           │ hole-punch fails
        ┌──────────────┴──────┐ ┌┴─────────────────────┐     │
        │ Host daemon (Rust)  │ │ Client               │     │
        │ - host key          │ │ native (Rust) /      │─────┘
        │ - members, groups,  │ │ browser (TS)         │
        │   shares, grants    │ │ - identity root +    │
        │ - signs capabilities│ │   device key         │
        │ - VFS (cap-std)     │ │ - pinned host keys   │
        └──────────┬──────────┘ └──────────┬───────────┘
                   └─ WebRTC DataChannel (DTLS/SCTP), E2E: VFS RPC ─┘
```

**Components**

- **NATS cluster** — signaling substrate only (core NATS; no JetStream in v1, see Alternatives). TCP listener for
  daemons, WebSocket for browsers; both server-cert TLS; every connection authorized via Auth Callout. mTLS with
  short-lived certs from the private CA = optional hardened profile on the TCP listener (decided, A10.1). Minimum
  nats-server **2.10**.
- **Broker helper** (the whole "backend"): small, replicated (≥2, queue group), holds no membership data. Roles:
  callout responder verifying **host-signed capabilities**; presence service (live connection map rebuilt from
  `$SYS.REQ.SERVER.PING.CONNZ` on start + `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` deltas; answers
  `helper.presence.get`); kick relay (`device_fp → (server_id, cid)` from the same map); TURN credential minting with
  quotas per `root_fp`; durable store of host-signed revocation/epoch records (opaque, host-signed, keyed by
  `host_fp`) + TURN counters + connection-metadata retention. NATS in front must set `max_control_line` and sit
  behind per-IP connection/rate limits (the callout is the DoS surface; ADR-001 §A12 #24). HA + load test (S8, S12).
- **Host daemon** (Rust): host identity root + operating key (ADR-003); owns members, groups, shares, entitlements
  (ADR-006); signs capabilities; pins member identity roots; VFS server over the DataChannel; rate-limits per peer;
  received-file policy; audit log.
- **Clients**: native (Rust, shared core crate with host) and browser (TypeScript; WebCrypto + `@noble/curves`
  fallback). Hold a root-signed device key (primary device also holds the root, ADR-003); pin host roots.
- **TURN**: coturn with REST-style time-limited credentials.

### Subject and permission model (DESIGN.md §A5, verbatim)

| Subject | Publisher | Subscriber | Notes |
|---------|-----------|------------|-------|
| `host.<hfp>.connect` | devices holding a cap for `hfp` | host | request/reply; envelope (ADR-004) with client's inbox inside |
| `host.<hfp>.sess.<cfp>.<sid>.c2h` | client `cfp` only | host | trickle ICE + session control |
| `host.<hfp>.sess.<cfp>.<sid>.h2c` | host | client `cfp` only | trickle ICE + session control |
| `host.<hfp>.presence` | broker helper (from `$SYS` events) | devices holding a cap for `hfp` | push deltas `{host_fp, state, last_seen}` only |
| `helper.presence.get` | devices | broker helper | request/reply snapshot for the caller's hosts (core NATS has no retained messages) |
| `registry.revoke.<hfp>` | host `hfp` only | broker helper | host-signed revocation/epoch records (durable; helper asserts subject token == record `host_fp`; per-host token bucket) |
| `helper.turn.get` | authenticated devices | broker helper | request/reply TURN credentials (helper authorizes via the session record, below) |
| `registry.admin.>` | operator (mTLS + operator cert) | broker helper | signed admin commands (ADR-007); replies via `allow_responses` |
| `_INBOX_<dfp>.>` | host via `allow_responses` after prefix check | owning device | private inbox prefix |

**Permissions issued by callout**

- Host: `sub host.<own>.>`, `pub host.<own>.sess.*.*.h2c`, `pub registry.revoke`, `allow_responses {max:1,
  expires:"2m"}`; explicit deny of `_INBOX.>`, `$SYS.>`, `$JS.>`.
- Client, for each host `h` in its verified caps: `pub host.<h>.connect`, `pub host.<h>.sess.<own>.*.c2h`,
  `sub host.<h>.sess.<own>.*.h2c`, `sub host.<h>.presence`; plus `sub _INBOX_<own>.>`, `pub helper.presence.get`,
  `pub helper.turn.get`. Invite-only and stale-cap connections get just `pub host.<h>.connect` + inbox. Max 32 hosts
  per connection (see Open items, A10.5). **Session record**: on each successful auth the callout writes
  `nats_fp → {root_fp, host_fps, quota_profile, exp}` to the helper store, so the helper can authorize non-callout
  requests (`helper.presence.get`, `helper.turn.get`) — cleaned up on DISCONNECT/expiry.
- **Host MUST validate** on every `connect`: reply subject starts with `_INBOX_<from_fp>.`; sender is an active member
  device (cheap check **before** crypto) or holds a valid unused invite; per-`from_fp` token bucket and
  max-concurrent-sessions; `sid` not bound to a different `from_fp`. All rejections are **uniform silent drops** (no
  distinguishable not-member / rate-limited / bad-envelope responses, timing included) — this closes ADR-001 §A12
  #4 and #24 (flood/enumerate, Sybil flood) and prevents the confused-deputy case in ADR-001 §A12 #9.
- Consequences: an A1 attacker cannot reach/enumerate/flood hosts it has no cap for, cannot see/inject into other
  clients' sessions (ADR-001 §A12 #10), cannot read other inboxes (ADR-001 §A12 #2), cannot proxy through a host; an
  A5 attacker with fresh keys gets no connection at all (ADR-001 §A12 #24).

### NATS authentication: Auth Callout for every connection

1. Device connects signing the server nonce with its session nkey and presents: device certificate (root-signed),
   session-nkey attestation, and the capabilities for this session (`member` caps, or one `invite` cap).
2. Callout verifies (cheap checks first: sizes, counts, `exp`): nkey signature; device cert → `root_fp`; each cap's
   `sig_host`, `exp`, `subject` matches `root_fp`; **best-effort** revocation/epoch check against the helper's durable
   store of host-signed records — *the authoritative check is the host's per-request enforcement* (ADR-003 §A4b;
   ADR-001 §A12 #13). Returns a user JWT with permissions (above), limits (`payload` 64 KiB, `subs` ≤ 4N+8, `data`
   cap), `allowed_connection_types` (`WEBSOCKET` browser / `STANDARD` daemon; closes ADR-001 §A12 #3), `exp` jittered
   in [45, 75] min.
3. A host connection presents `sig_host_root(host_op_pk, nats_fp, ts)` (+ an admission invite on first connect);
   callout checks `host_fp == hash(host_root_pk)` **and** the admission record / mode policy (ADR-007) → host
   permissions for `host.<own_fp>.>`. A connection presenting **no** valid cap is refused (ADR-001 §A12 #24, Sybil/
   flood defense) — the `invite` cap is the only bootstrap path; per-IP limits in front of NATS bound callout cost.
4. Why not `verify_and_map`/registry accounts: cannot express per-host scoping, revocation, browsers, or "no accounts
   at the registry" (see Alternatives Considered). mTLS optional.

### Signaling flows (DESIGN.md §A6)

**Presence**: broker helper keeps a live connection map (CONNZ on start + `$SYS.ACCOUNT.<acct>.CONNECT|DISCONNECT`
deltas), answers `helper.presence.get` on client start, and pushes deltas on `host.<hfp>.presence`; `ping_interval`
~20 s / `ping_max` 2 so a dead socket flips ≤ ~60 s; UI shows online / offline / unresponsive (last seen). **Multiple
connections per identity are normal** (native app + browser tab): the connection map and kick relay are one-to-many
per `device_fp`; presence is by connection count, not a boolean, and reconnect overlap (CONNECT before stale
DISCONNECT) never flips a live host to offline. **Two daemons with the same restored host key** = split-brain:
newest connection wins, the older is kicked, and both machines show a loud warning. No-responders on `connect` →
**instant** "host is offline". Clients also expose a **"registry degraded"** state (helper unreachable) distinct from
"host offline" — without it a dead helper is symptomless for up to an hour (DESIGN.md §A14).

**Connect + offer/answer + trickle ICE** (verbatim):

```
Client                          NATS                            Host
  │ sub host.<h>.sess.<c>.<sid>.h2c                               │
  │ request host.<h>.connect ──────► (route) ────────────────────►│ member/invite? rate-limit? → verify envelope,
  │  env{eph_pk_c, offer, inbox,    (reply=_INBOX_<c>.x)          │ derive session key, setRemote(offer)
  │      [device cert+chain if invite]}                           │
  │ ◄──────────────────── reply (prefix validated) ◄──────────────│ env{eph_pk_h, answer, [member cap if invite]}
  │ verify sig, setRemote(answer)                                 │
  │ pub …c2h env{ice} ───────────────────────────────────────────►│ addIceCandidate
  │ ◄──────────────────────────────────────────────── …h2c env{ice}│
  │      DTLS handshake; compare remote DTLS fingerprint with a=fingerprint from the *verified* envelope
  │ ◄═══════════ DataChannel (DTLS/SCTP) → VFS RPC session bound to device_fp ═══════════► │
```

- `connect` timeout covers the answer only (5 s, one retry); ICE streams independently; losses tolerated/retried.
- ICE servers + TURN creds per session from the broker helper; `iceTransportPolicy: relay` privacy option (mitigates
  ADR-001 §A12 #17, local IP disclosure).

### NATS account topology (DESIGN.md §A10.15 / §A5 requirement)

DESIGN.md pins the shape (one application account + one system account, explicit denies on `$SYS.>`/`$JS.>`/
`_INBOX.>`) but does not fully specify export/import wiring for every cross-boundary subject. The table below is
derived faithfully from §A3 (components) and §A5 (subject table); rows not directly pinned by DESIGN.md are marked
**"to be finalized in S1."**

| Subject | Home account | Consumer account | Direction | Purpose | Status |
|---------|--------------|-------------------|-----------|---------|--------|
| `$SYS.REQ.USER.AUTH` | SYS (built-in NATS auth callout hook) | Broker helper, connected in the SYS account | Service (request/reply) | Auth Callout: authorizes every device/host connection (§A4 step 1–3) | Pinned by §A3 diagram |
| `$SYS.ACCOUNT.*.CONNECT` / `$SYS.ACCOUNT.*.DISCONNECT` | SYS (built-in) | Broker helper, SYS account | System event stream (subscribe) | Feeds the live connection map for presence + kick relay (§A3, §A6) | Pinned by §A3 diagram |
| `$SYS.REQ.SERVER.PING.CONNZ` | SYS (built-in) | Broker helper, SYS account | Service (request) | Rebuild connection map on helper start/restart (§A3) | Pinned by §A3 |
| `$SYS.REQ.SERVER.<id>.KICK` | SYS (built-in) | Broker helper, SYS account | Service (request) | Kick relay: force-disconnect `(server_id, cid)` on revocation (§A3, §A4 Revocation) | Pinned by §A3 |
| `helper.presence.get` | APP account, exported by the broker helper's app-account identity | APP account, imported by all authenticated devices | Service (request/reply) | Presence snapshot for the caller's hosts (§A5) | Pinned by §A5 |
| `helper.turn.get` | APP account (broker helper) | APP account, imported by all authenticated devices | Service (request/reply) | TURN credential vending, authorized via session record (§A5, §A8) | Pinned by §A5 |
| `registry.revoke.<hfp>` | APP account (host publishes) | APP account, imported by broker helper only | Service (request, per-host scoped) | Host-signed revocation/epoch records (§A5); helper asserts subject token == record `host_fp` | Pinned by §A5 |
| `registry.admin.>` | APP account (operator, mTLS + operator cert) | APP account, imported by broker helper only | Service (request/reply via `allow_responses`) | Signed admin commands (ADR-007, §A3b) | Pinned by §A5 |
| `host.<hfp>.>` (`connect`, `sess.<cfp>.<sid>.c2h`/`h2c`, `presence`) | APP account | APP account, scoped per-connection by callout-issued permissions (no wildcard subs) | Pub/sub, request/reply | Signaling subjects (§A5) | Pinned by §A5 |
| `_INBOX_<dfp>.>` | APP account (private per-device prefix) | APP account; only the owning device subscribes; host publishes into it via `allow_responses` after prefix validation | Reply-only | Private reply inbox (§A5; closes ADR-001 §A12 #2) | Pinned by §A5 |
| **Broker helper's own connection(s)**: whether the helper holds one dual-privileged connection (SYS + APP) or two separate connections (one per account) bridging `$SYS` events into APP-account publishes (`host.<hfp>.presence`, replies on `helper.*`) | — | — | — | DESIGN.md's diagram shows the helper touching both `$SYS.*` and `registry.*`/`helper.*` subjects but does not specify single- vs. dual-connection wiring | **To be finalized in S1** |
| Explicit deny: `$SYS.>` (all other system subjects) | — | Denied for every APP-account connection (device, host) | n/a | Prevents devices/hosts from reading arbitrary system events (A10.15) | Pinned by §A5 permissions list |
| Explicit deny: `$JS.>` | — | Denied for every APP-account connection | n/a | No JetStream in v1 (§A3, Alternatives Considered) | Pinned by §A3/§A11 |
| Explicit deny: `_INBOX.>` (broad wildcard) | — | Denied for every APP-account connection; only the caller's own `_INBOX_<dfp>.>` is permitted | n/a | Prevents reading other devices' inboxes (ADR-001 §A12 #2) | Pinned by §A5 |

### Configuration requirements

- nats-server **≥ 2.10** (§A3 Components).
- `max_control_line` = **32 KiB** (default is 4 KiB; raised so a CONNECT can carry up to 32 compact-CBOR capabilities
  plus device certificate — §A4 presentation, A10.10; verified by S12).
- `allowed_connection_types` set per callout-issued JWT: `WEBSOCKET` for browsers, `STANDARD` for native daemons
  (§A4 step 2; closes ADR-001 §A12 #3).
- `ping_interval` ~20 s / `ping_max` 2 so a dead socket is detected within ≤ ~60 s (§A6 Presence).
- Per-IP connection/rate limits **in front of** NATS — the Auth Callout is the DoS surface (§A3; closes ADR-001
  §A12 #24). Enforced at the load balancer / reverse proxy layer, not by nats-server config alone.

## Consequences

### Positive

- Replaces static `verify_and_map` with dynamic, self-verifying, host-signed capability checks — no registry-held
  account or key directory exists to compromise (ADR-001 §A12 #11, #12, #13).
- Per-device private inboxes and session-scoped subjects (`sess.<cfp>.<sid>`) prevent cross-client eavesdropping and
  injection without requiring per-pair ACLs to be provisioned out of band (ADR-001 §A12 #2, #10).
- Uniform silent drops on all pre-auth rejections deny an attacker any oracle for enumerating hosts, members, or rate
  limits (ADR-001 §A12 #4, #32).
- The registry never needs writable state about hosts or members to authorize a connection — every fact it checks
  (cap signature, host identity, revocation epoch) is either self-verifying or a best-effort cache backed by the
  host's authoritative per-request enforcement (ADR-001 §A12 #13).

### Negative

- The Auth Callout is a mandatory per-connection cost center and the primary DoS surface; it depends on per-IP
  limiting living *outside* NATS itself, which is an operational dependency this ADR cannot fully verify until S8/S12
  land (ADR-001 §A12 #24).
- `max_control_line` at 32 KiB (8× the nats-server default) enlarges the connection handshake's memory footprint per
  in-flight CONNECT; this is an accepted trade-off pending S12's measurement.
- The broker helper's dual-account wiring (SYS + APP) is not fully pinned by DESIGN.md (see Open items) — any
  implementation choice here is a de facto architectural decision that this ADR cannot yet ratify.

### Neutral

- No JetStream in v1 means no durable message log; presence and revocation state are instead helper-side derived
  state (connection map, revocation store) rather than NATS-native durability. This trades NATS-native durability
  for the flexibility described in Alternatives Considered.
- The registry retains visibility into which device connects to which host at which time — an accepted, explicitly
  stated limitation of the zero-knowledge definition, not a defect of this signaling design (ADR-001 §A2, §A12 #7,
  #34).

## Alternatives Considered

| Alternative | Verdict | Why |
|-------------|---------|-----|
| Custom WebSocket relay | Rejected | NATS gives routing, req/reply, reconnect, and permissions for free; reimplementing these is unjustified custom infrastructure |
| NATS static `verify_and_map` (original ADR-002 as written) | Rejected | Cannot express per-host scoping, revocation, browser connection types, or "no accounts at the registry" — Auth Callout can |
| JetStream (durability / KV presence) | Rejected for v1 | Not needed for presence (rebuilt from `$SYS` events + request/reply); KV permissions cannot express the per-host scoping this design needs |
| Ungated host registration (any valid host cert admitted, no admission control) | Rejected | Enables Sybil hosts and TURN abuse; closed by the admission-mode control plane in ADR-007 (A3b) |

## References

- `../DESIGN.md` §A3 (Architecture overview), §A3b (Registry control plane, forward reference), §A5 (Subject and
  permission model), §A6 (Signaling flows), §A9b (Helper consistency, observability), §A10.1, §A10.5, §A10.10,
  §A10.15, §A11 (Alternatives considered)
- ADR-001 (Threat model — §A12 rows cited throughout this document)
- ADR-003 (Identity, capabilities, enrollment — capability structure and Auth Callout presentation this ADR consumes)
- ADR-004 (E2E signaling envelope — the `env{...}` payloads carried over the subjects in this ADR)
- ADR-007 (Registry control plane — host admission modes, admin surface, `registry.admin.>`)
- `docs/SPIKES.md`: S1 (callout negative-test suite — gates this ADR's Proposed → Accepted transition), S2
  (webrtc-rs ↔ browser trickle ICE), S5 (presence tuning), S8 (helper HA at 5k clients), S12 (CONNECT size / callout
  cost at scale — gates this ADR's Proposed → Accepted transition)
