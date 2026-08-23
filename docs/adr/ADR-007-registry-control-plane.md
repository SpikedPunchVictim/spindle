# ADR-007: Registry Control Plane — Host Admission & Administration

## Status

Accepted

## Context

Through v0.6 a host was purely self-certifying: anyone able to mint a host root key could present it and be treated
as a host. Clients are gated by capabilities they must obtain from a host or the operator (no capability → refused,
ADR-001 §A12 #24), so the host was the one ungated principal in the system. This ADR closes that gap with a registry
**control plane**: an admission gate in front of the NATS callout, plus a signed-command administration surface for
the operator, both explicitly scoped so that neither can touch member data, share data, or file contents — only
whether a given host root key is allowed to hold a live connection at all.

This directly answers adversary **A7** (thief of the operator admission key) from the threat model (ADR-001 §A2):
someone who starts with control of the registry's admission mechanism and wants to admit rogue hosts or evict real
ones. The design constraint carried into every decision below is that **admission ≠ identity**: members connect only
to hosts whose root keys they pinned via invites (ADR-003 §A4), so a rogue admitted host with no invited members is
an empty host nobody has joined. The control plane can therefore only ever be an *availability* lever, never a
confidentiality or impersonation one (ADR-001 §A12 #36).

This ADR also codifies the **helper consistency model** (how the broker helper's durable state is written and read
under replication), the **secrets inventory** (every long-lived credential the control plane depends on), and the
**observability contract** the control plane must expose — all promised as appendices of this ADR by DESIGN.md §A9b.

## Decision

### Admission modes

Registry-wide admission mode is configuration, switchable at runtime; every mode change is itself a signed admin
command, so "downgrade to open" is authenticated and logged like any other admin action. Verbatim from DESIGN.md
§A3b:

| Mode | Behavior |
|------|----------|
| `invite` (**default**, decided A10.17) | New hosts must redeem a single-use operator **admission invite** |
| `open` | Any valid host cert admitted; per-IP and total-host quotas apply |
| `closed` | No new hosts; existing admitted hosts unaffected (incident response / capacity freeze) |

`invite` as the default mode bounds rogue-host admission at scale even under an otherwise-idle registry
(ADR-001 §A12 #39); `open` mode's per-IP and total-host quotas bound the same attack when admission is intentionally
relaxed; `closed` mode gives operators a capacity-freeze / incident-response lever that does not disturb hosts
already admitted.

### Admission mechanisms (decided A10.18: both)

Same invite/capability pattern used for host→member enrollment (ADR-003 §A4), one level up:

- **Admission invite token**: `{nonce, exp (days), label, quota_profile, sig_operator}` — a bearer token minted by
  the operator and pasted or scanned into the host daemon's setup flow. On first connect the host presents it with
  its host cert; the helper **burns the nonce** in its durable store and writes an **admission record**
  `{host_fp, label, admitted_at, quota_profile}`. Thereafter the host connects on its cert alone; the callout checks
  the admission record instead of the token. Single-use nonce burn at the helper, a days-scale `exp`, and the
  per-token `quota_profile` together close leaked-token abuse (ADR-001 §A12 #37).
- **Fingerprint pre-registration**: the prospective host shows its `host_fp` out of band; the operator signs it
  directly (`sig_operator(host_fp, label, quota_profile)`) — no bearer token is ever in flight. Intended for
  high-assurance admissions where even a short-lived bearer token is an unacceptable leak surface.

### Operator admission key & blast radius

The operator admission key is separate from every other key in the system (host roots, user roots, release signing
key, TLS/CA material). It is held in the admin library's pluggable `Signer` — file-encrypted, OS keychain, or
hardware token — with the same **pre-committed rotation** pattern used for user identity roots (ADR-003 §A4).

**Blast radius is a stated design property, not an incidental one**: a stolen admission key can admit rogue hosts
and evict real ones — an *availability* attack only. It can never impersonate an existing host, read payloads, or
reach any member's files, because admission is checked once at connect time while identity and per-request
authorization are enforced independently and continuously by each host (ADR-006). A rogue admitted host is, by
construction, an empty host nobody has joined (ADR-001 §A12 #36).

### Admin surface (decided A10.19)

A **TypeScript library**, `@spindle/admin`, owns the entire admin protocol: command signing under the same envelope
discipline used for live signaling (nonce, timestamp, canonical CBOR — ADR-004 §A7b, artifact tag
`spindle-adm-cmd-v1`), admission-invite minting, the pluggable `Signer` interface (file key / OS keychain / hardware
token / WebCrypto), and the NATS connection logic itself. The v1 client is a CLI, `spindle-admin`, built on the
library; any future interface (web console, chat-ops bot, …) builds on the same library and owns its own transport
security rather than the helper trusting a new surface.

The helper verifies operator signatures on `registry.admin.>` — **the admin plane is a verifier, not a login**:
there are no passwords, sessions, or CSRF surface to attack (ADR-001 §A12 #44, closed by per-signer monotonic `seq`
+ nonce and idempotent execution). Admin NATS connections **MUST** use the mTLS profile on the TCP listener — the
private CA is mandatory here even though it is optional for ordinary users (DESIGN.md §A10.1). Two-person co-sign
for destructive operations is noted as an optional future hardening, not a v1 requirement.

### Operator capabilities

The signed admin command set covers exactly: switch admission mode · mint or revoke admission invites · pre-register
a `host_fp` · list admitted hosts (fingerprint, label, first/last seen, connection count — **metadata only**; shares
and members remain invisible to the operator per the zero-knowledge definition, ADR-001 §A2) · **suspend/evict** a
host (kick its live connections and refuse re-auth; members simply see it offline) · set quota profiles (max
concurrent member connections, TURN budget) · rotate the admission key · read the hash-chained admin **audit log**
(every command, its signer, and its result). Eviction plus durable admission records closes evicted-host
resurrection and mode-downgrade abuse (ADR-001 §A12 #38): an evicted host cannot simply reconnect, and a mode
downgrade back to `open` is itself a logged, signed command.

### Helper consistency model

The broker helper runs as a **single-writer leader over Postgres**: replicas serve reads and callout verification,
but every write path — nonce burns (compare-and-swap), revocation epochs (max-wins, never decreasing), session
records, admission records, the audit chain, and TURN counters — goes through the leader, and presence deltas are
published by the leader only (DESIGN.md §A9b, decision A10.23). Max-wins epochs mean an old revocation record,
whether replayed or restored from a stale backup, can never roll a host's epoch backward (ADR-001 §A12 #42); hosts
fetch the epoch high-water mark from the helper at startup rather than trusting only their own local state. A stated
staleness bound of **≤ 2 s** applies to callout-time views of admission and revocation records under replication,
verified by spikes S8 and S16.

### Secrets inventory

DESIGN.md §A9b enumerates the control plane's secrets compactly and promises the full table here. Every column below
is drawn only from facts stated in DESIGN.md; a cell reading "not specified" means DESIGN.md does not state that
fact and this ADR does not invent one.

| Secret | Holder | Lifetime | Rotation | Blast radius |
|--------|--------|----------|----------|---------------|
| Operator admission key | Admin library `Signer` — file-encrypted key, OS keychain, or hardware token (§A3b) | No fixed expiry stated; governed by pre-committed rotation, same pattern as user identity roots (§A3b, §A4) | Pre-committed rotation: the next key's commitment is published ahead of use (§A3b, §A9b) | **Availability-only**: admits rogue hosts, evicts real hosts; cannot impersonate an existing host, read payloads, or reach any member's files — admission ≠ identity (§A3b, ADR-001 §A12 #36) |
| Release signing key | Held offline (§A9b); distinct from the operator key — "release key ≠ operator key" (§A2) | Offline; pre-committed next-key hash [DEFAULT] | Rotated only on compromise or planned succession [DEFAULT] | Controls the signed manifest for hardened browser delivery (§A2, ADR-008); a compromise could sign a malicious manifest, mitigated at the client by the companion verification extension (§A2, ADR-001 §A12 #40) |
| TURN `use-auth-secret` | coturn (§A8, §A9b) | Rotated monthly [DEFAULT] | **Dual-secret overlap window**, so rotating it does not kill live TURN allocations (§A9b) | Mediates minting of time-limited TURN credentials (`username = expiry:device_fp`, §A8); credential issuance itself is quota-bound per `root_fp` by the helper (§A8, ADR-001 §A12 #8, #28) |
| NATS server TLS certs | Registry's NATS cluster (TCP + WebSocket listeners, §A3) | 90-day [DEFAULT] | Auto-renewed [DEFAULT] | Transport-layer trust anchor; clients trust the private CA root shipped in the invite's pin policy (§A9b). Session-setup confidentiality and integrity do **not** depend solely on this layer — they are additionally guaranteed end-to-end by the A7 envelope (ADR-004), independent of NATS/TLS (ADR-001 §A12 #1) |
| Private CA | Registry (closed system; private CA available per §A0) | **Short lifetimes in lieu of revocation** (§A9b) | Reissuance via short-lived certs rather than a revocation mechanism (§A9b) | Backs the optional hardened mTLS profile on the NATS TCP listener (§A10.1) and the **mandatory** mTLS profile for admin connections (§A3b) |
| Helper DB credentials | Broker helper / Postgres (§A9b, §A9c) | 90-day [DEFAULT] | Leader-managed [DEFAULT] | Gates access to the helper's operational store: revocation/epoch records, connection map, TURN counters, admission records, and the audit chain — explicitly **not** member, group, or share data, which never leaves the host (§A3, §A10.14) |
| Host root / operating key / user roots & device keys | OS keystore on the owning device (§A4); "covered in A4" per §A9b | Host operating key `exp` 90 d (ADR-004 §A7b); device certs `exp` 1 y, re-signed on contact (ADR-004 §A7b) | Pre-committed rotation for identity roots (§A4, ADR-001 §A12 #26) | Out of scope for this ADR's admission blast-radius analysis — full treatment in ADR-003 |

### Observability contract

The helper exports: callout latency and decision counts, revocation propagation delay, presence-map size and
replica divergence, nonce-burn conflicts, and TURN quota consumption. Hosts export: failed-envelope-verification
rate, rate-limit hits, session/transfer counts, and audit-chain head. Clients surface a "registry degraded" state
distinct from "host offline" (DESIGN.md §A6, §A9). The SLOs proven by spikes S8, S9, and S12 — p99 callout latency
< 250 ms, revoke-to-refusal cut-off < 5 s — become **production alerts**, not merely spike pass criteria
(DESIGN.md §A9b).

## Consequences

### Positive

- Hosts are no longer an ungated principal: every host must pass through `invite`, `open` (quota-bounded), or
  `closed` admission before it can hold a live connection at all (ADR-001 §A12 #39).
- The admission key's blast radius is bounded to availability by construction — theft cannot escalate to
  impersonation or data access, because admission and identity are enforced by entirely separate mechanisms
  (ADR-001 §A12 #36).
- The admin plane has no login surface to attack (no passwords, sessions, or CSRF) because every command is a
  self-verifying signed artifact (ADR-001 §A12 #44).
- Durable admission and revocation records under a single-writer, max-wins consistency model close both
  evicted-host resurrection and revocation rollback via replay or stale backup (ADR-001 §A12 #38, #42).
- Operator visibility is metadata-only (fingerprint, label, connection count) — shares, members, and groups remain
  invisible to the operator, preserving the zero-knowledge definition (ADR-001 §A2).

### Negative

- A stolen admission key can still evict every legitimate host — a real, if bounded, denial-of-service exposure
  that this ADR accepts rather than eliminates (ADR-001 §A12 #36).
- The helper's single-writer-leader design introduces a write bottleneck and a stated staleness window (≤ 2 s) for
  replica reads of admission/revocation state; a host or client observing a stale replica during that window could
  briefly act on out-of-date admission data before the authoritative host-side enforcement catches it.
- Several secrets in the inventory (release signing key lifetime/rotation, TURN secret lifetime, NATS/CA cert
  lifetimes, helper DB credential lifetime/rotation) carry **[DEFAULT]** values recorded in DESIGN.md §A9b
  (v0.9.1), adopted pending operator confirmation rather than a policy this ADR itself specifies.
- `open` admission mode, even quota-bounded, still allows any valid host cert to register — an operational choice
  that trades admission friction for onboarding speed, and shifts the abuse ceiling to whatever quotas are
  configured.

### Neutral

- The admin surface is deliberately a thin, replaceable shell (`spindle-admin` CLI) over a protocol library
  (`@spindle/admin`); future interfaces (web, chat-ops) inherit the verifier model but must independently secure
  their own transport, which this ADR does not prescribe.
- Two-person co-sign for destructive admin operations is left as an explicit future option rather than a v1
  requirement — a deliberate scope cut, not an oversight.

## Alternatives Considered

From DESIGN.md §A11:

| Alternative | Verdict | Why |
|-------------|---------|-----|
| Ungated host registration (status quo through v0.6) | Rejected (v0.7) | Sybil hosts and TURN-budget abuse with no gate at all; admission modes close this (§A3b) |
| Web admin panel with login sessions | Rejected (v0.7) | The largest attack surface on the most sensitive service in the system; a signed-command verifier has no login surface to attack instead |
| Stateless helper with cached epochs | Rejected (v0.6) | Fails open on restart; durable host-signed records (the basis of this ADR's consistency model) were adopted instead |

## Open items

DESIGN.md flags the following as `[DEFAULT]` choices rather than explicit user decisions; they are recorded here as
such and are not resolved by this ADR:

- **A10.14 — Helper state [DEFAULT]**: a small, replicated store holding host-signed revocation/epoch records, the
  connection map, TURN counters, and metadata retention — explicitly **no membership data**.
- **A10.23 — Helper store [DEFAULT]**: single-writer leader over Postgres; nonce burns via CAS; epochs via max-wins;
  presence deltas and the audit chain are leader-only.

## References

- `../DESIGN.md` §A3b (registry control plane), §A9b (helper consistency, secrets inventory, observability
  contract), §A10 rows 14, 17–19, 23, §A12 rows #36–39, #42–44
- [ADR-001: Threat Model](./ADR-001-threat-model.md) — adversary A7, §A12 rows #1, #8, #24, #26, #28, #36–39, #42–44
- [ADR-003: Identity, Capabilities, Enrollment](./ADR-003-identity-capabilities-enrollment.md) — root keys, device
  certificates, pre-committed rotation pattern shared by the admission key
- [ADR-004: End-to-End Signaling Envelope](./ADR-004-e2e-signaling-envelope.md) — A7b signed-artifact profile used
  by admission tokens and admin commands
- [ADR-006: Host Authorization — Members, Shares, Entitlements](./ADR-006-host-authorization-members-shares-entitlements.md)
  — per-request enforcement that keeps admission separate from identity/access
- [ADR-008: Browser Client Delivery](./ADR-008-browser-client-delivery.md) — release signing key referenced in the
  secrets inventory above
- `../SPIKES.md` S8 (helper HA, callout latency), S12 (CONNECT size / callout cost), S16 (control-plane negative
  tests: admit, evict, mode switch)
