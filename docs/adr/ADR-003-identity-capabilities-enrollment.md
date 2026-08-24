# ADR-003: Identity, Capabilities, and Enrollment

## Status

Accepted

## Context

DESIGN.md v0.5 removed registry-held accounts entirely (user decision, 2026-08-23): "accounts live only on each
host server — the registry's sole responsibility is facilitating client↔server connections." This forced identity to
become fully cryptographic and per-host: there is no global directory, no passkey-at-registry model, and no key
introduction service. This ADR is the source of truth for how people, devices, and hosts are identified; how
host-signed capabilities work; how the NATS Auth Callout consumes them (see ADR-002 for the callout's role inside the
signaling protocol); and how enrollment, key introduction, revocation, root rotation, and recovery work end to end.

## Decision

### Principals (DESIGN.md §A4)

**There are no global accounts.** Identity is cryptographic and is *recognized* per host.

- *Person* = an **identity root key** (Ed25519). Generated on the person's **primary device**, where it lives in the
  OS keystore (biometric/passcode-gated) and is backed up as the recovery phrase (decided A10.4). At enrollment the
  root also commits `hash(next_root_pk)` (pre-committed rotation). `root_fp = hash(root_pk)`.
- *Device* = keypair generated on-device: Ed25519 (sign) + X25519 (agree); `alg_id` is a **suite version byte**
  (`1` = Ed25519/X25519/AES-256-GCM; no P-256 fallback — all target browsers ship Ed25519/X25519);
  `device_fp = base32(SHA-256("spindle-dev-v1" || alg_id || sign_pk || agree_pk))`. Carries a **device certificate
  signed only by the root**: `sig_root(device_fp, nats_fp, ts, label)`. **Secondary devices cannot mint devices**
  (a compromised secondary cannot amplify — ADR-001 §A12 #25); browsers are never root holders. Adding a device =
  scan QR from the primary device (or enter the recovery phrase on the new device, which then becomes primary).
- *Host* = has a **host identity root** (`host_fp = hash(host_root_pk)`, backed up with the share config / recovery
  phrase) that signs its **operating key** (`sig_host_root(host_op_pk, nats_fp, ts)`). Members pin `host_fp`; rotating
  or reinstalling the operating key from backup does **not** trigger the key-change wall; losing the host root = new
  host (re-invite everyone) — stated in the host UI at setup, with backup nagging.
- *Member* = a host-local record binding a `root_fp` (and its accepted device chain) to host-local state (ADR-006).

### Two credentials per device

1. *Device identity key* — envelopes (ADR-004), capability redemption, VFS session binding. Browser: non-extractable
   WebCrypto (limits persistence of an XSS compromise; does not prevent use while the page is compromised —
   ADR-001 §A12 #3).
2. *NATS connect key* — a separate nkey, **rotated per session** (native: seed in OS keychain; browser: IndexedDB —
   low value by design). Stolen → scoped broker access only, never E2E impersonation. `nats_fp = hash(nats_pk)`; the
   device certificate binds `nats_fp` to `device_fp`; a per-session nkey is attested by `sig_device(nats_fp, ts)`.
   This split means a stolen NATS key alone cannot decrypt or forge signaling (ADR-001 §A12 #3, #5).

### Capabilities (host-signed, self-verifying)

```
cap = { v, host_fp, host_root_pk, op_cert, kind: invite|member, subject: root_fp | device_fp, cap_epoch, exp, nonce,
        sig }
```

`op_cert` is the existing Host op-key cert (`spindle-host-cert-v1`) embedded as its complete canonical encoding;
`sig` is the operating key's signature over the capability.

- **`cap_epoch` vs `grants_version`** (two jobs, two counters): `cap_epoch` bumps only on security events (member/
  device revocation) and invalidates caps; `grants_version` is host-internal (entitlement edits, cache invalidation)
  and **never leaves the host**. Revoking one member does not invalidate other members' caps unless the host chooses
  a full rotation.
- Self-verifying, in three steps: (1) `host_fp == hash(host_root_pk)`; (2) `op_cert` valid under `host_root_pk`
  (including its own `exp`); (3) `sig` valid under the op key certified by `op_cert` — the callout needs **no
  registry of hosts or members** (ADR-001 §A12 #11, #12, #13). **[amended v0.9.5, A10.30]** The cap now embeds the
  root→op-key chain instead of being signed directly by the host root, so `host_fp` is always root-derived even
  though the day-to-day signer is the operating key — the root stays cold and op-key rotation never re-walls
  members.
- `invite`: **bearer** token — single-use enforced by the **host** (nonce burned on redemption; the helper cannot
  enforce single-use), `exp` in **hours** (default 24 h, owner-adjustable), scope = `connect` only, rate-limited per
  nonce at the host, may embed an initial group (ADR-006). Shared as QR/link; the payload also carries the
  **registry endpoint + TLS pin policy** (so clients need no baked-in registry address; admission tokens likewise).
  **Redemption is idempotent**: the host stores `nonce → {member_id, issued_cap}` atomically; re-presentation of the
  same nonce within `exp` replays the stored cap (a crash or lost reply between burn and delivery cannot strand the
  invitee). The same rule applies to admission invites at the helper (ADR-007). **It also carries the host's public
  keys → the registry never introduces a key** (closes ADR-001 §A12 #11).
- `member`: issued by the host after redemption, scope = full signaling with that host; `subject = root_fp` so every
  root-certified device of the person may use it. `exp` in **weeks** (default 6; refreshed opportunistically on every
  successful session). Stored per platform: native → OS keychain; browser → IndexedDB (a cap is host-signed and
  useless without the device key). **Renewal path (no lockout)**: a cap that is expired or stale-epoch but
  signature-valid still earns **connect-only** NATS permissions (same as an invite); the host verifies the device
  over the E2E channel and re-issues the current cap in the reply. Only *revoked* subjects are refused outright.
- **Presentation**: caps travel in the CONNECT `auth_token` as compact CBOR (~330 B each, chain-carrying, v0.9.5,
  base64url). nats-server's default `max_control_line` is 4 KiB, so the registry sets it to **32 KiB** (see Open
  items, A10.10 — full config detail in ADR-002) and clients present **only the caps for hosts they will use this
  session** (pinned/open hosts), max **32** per connection (see Open items, A10.5). S12 measures.

### NATS authentication = Auth Callout for every connection

(Full signaling-side detail — permission grants, subjects, rejection semantics — lives in ADR-002. Reproduced here
for the identity-verification steps this ADR is authoritative for.)

1. Device connects signing the server nonce with its session nkey and presents: device certificate (root-signed),
   session-nkey attestation, and the capabilities for this session (`member` caps, or one `invite` cap).
2. Callout verifies (cheap checks first: sizes, counts, `exp`): nkey signature; device cert → `root_fp`; each cap's
   `sig_host`, `exp`, `subject` matches `root_fp`; **best-effort** revocation/epoch check against the helper's durable
   store of host-signed records (see Revocation, below) — *the authoritative check is the host's per-request
   enforcement* (ADR-006). Returns a user JWT with permissions, limits, `allowed_connection_types`
   (`WEBSOCKET` browser / `STANDARD` daemon), `exp` jittered in [45, 75] min.
3. A host connection presents `sig_host_root(host_op_pk, nats_fp, ts)` (+ an admission invite on first connect);
   callout checks `host_fp == hash(host_root_pk)` **and** the admission record / mode policy (ADR-007) → host
   permissions for `host.<own_fp>.>`. A connection presenting **no** valid cap is refused (ADR-001 §A12 #24) — the
   `invite` cap is the only bootstrap path; per-IP limits in front of NATS bound callout cost.
4. Why not `verify_and_map`/registry accounts: cannot express per-host scoping, revocation, browsers, or "no accounts
   at the registry." mTLS optional. (Full alternative-analysis detail lives in ADR-002.)

### Enrollment / first run (primary device)

Generate root (show recovery phrase; commit next-root hash) + device key; native: optional short-lived cert from the
private CA (hardened profile). Redeem an invite → member of that host.

**Adding a device (device bootstrap)**: new device shows QR; the **primary** device signs its certificate **and
returns a state bundle** `{registry endpoint, [{host_fp, host_pk, member_cap}…]}` — the QR transfers state, not just
a signature. All hosts accept the new device automatically (they pinned `root_fp`) and notify the owner ("Alex added
*iPhone*"). Any root-certified device can also **re-fetch its cap** from a host directly (connect-only → E2E
re-issue, above). A browser is enrolled the same way and is never primary.

**Recovery without the primary device**: the recovery phrase restores the root but *not* the host list — the person
re-learns hosts from saved invite links or by re-invite; the signup UI says this. Device certificates carry `exp`
(1 year, re-signed by the primary on contact); device **labels are host-local display state**, renameable by the
person and the host owner — never baked into certificates.

### Key introduction (decided A10.3)

Invite carries host keys; the client's first envelope carries its device certificate + chain encrypted to the
host's agree key and HMAC'd with the invite nonce; both sides **pin**; later key change = hard, non-dismissable wall
(closes ADR-001 §A12 #11). Safety numbers optional.

### Revocation

Host revokes a member (root) or a device → bumps epoch and publishes a **host-signed revocation record**
`{host_fp, epoch, revoked: [root_fp|device_fp], ts, sig_host_op}` to `registry.revoke` (ADR-002 §A5); the helper
stores it durably, kicks live connections (`$SYS.REQ.SERVER.<id>.KICK {id: cid}` via its connection map), and refuses
the cap on re-auth; the host rejects envelopes/VFS requests from revoked keys **per request** (authoritative); live
VFS sessions are dropped. Cut-off target < 5 s (S9; closes ADR-001 §A12 #5). A person revokes a lost device with a
**root-signed** revocation, delivered to each host on next contact *and* deposited at the helper so the callout
refuses it even while hosts are offline (S14; closes ADR-001 §A12 #27).

### Root rotation

`sig_old_root(new_root_pk)` where `hash(new_root_pk)` matches the pre-committed value; hosts accept without the wall;
owner can also revoke a root out-of-band from the host UI. Pre-committed rotation closes ADR-001 §A12 #26 (root key
compromise).

### Recovery

Recovery phrase restores the root onto a new primary device (decided A10.4); if the root is lost, the documented
fallback is per-host owner **re-invite** (member record migrates to the new root) — not a disaster, a normal flow.

### Signed-artifact profile rows relevant to identity (DESIGN.md §A7b subset)

Every signed artifact in Spindle shares: version byte `v`, a **distinct domain-separation tag**, canonical CBOR
(RFC 8949 §4.2.1), a stated time rule, and a stated replay rule. Unknown `v` ⇒ reject. The rows below are the subset
of the full A7b catalog relevant to capabilities, device certificates, and revocation (the full catalog, including
envelope and admin-command rows, belongs to the signaling and control-plane ADRs):

| Artifact | Tag | Signer | Time rule | Replay rule |
|----------|-----|--------|-----------|-------------|
| Member/invite cap | `spindle-cap-v1` | host op key (chained: embedded root-signed HostOpKeyCert) [amended v0.9.5] | `exp`; `nbf` = issue ts [amended v0.9.4: the schema-of-record Capability carries no `nbf`; `exp` is the sole time bound] | invite: nonce burn (idempotent replay of result); member: n/a |
| Device certificate | `spindle-dev-cert-v1` | identity root | `exp` 1 y; re-sign on contact | n/a (revocable) |
| Revocation record | `spindle-rev-v1` | host op key / identity root | none (permanent) | **max-wins, never decreases**; old records cannot roll back |
| Host op-key cert | `spindle-host-cert-v1` | host root | `exp` 90 d | n/a (rotation) |

Root keys sign two artifact types (device certs, self-revocations) — the distinct tags prevent cross-artifact
signature confusion (closes ADR-001 §A12 #41). Host and helper both use helper server time for `exp`/`nbf` checks
(single authority; ±2 min).

## Consequences

### Positive

- Eliminating registry accounts removes an entire class of attack (key-directory substitution, registry-added
  devices) by construction — there is no directory to compromise (ADR-001 §A12 #11, #12).
- The two-credential split (device identity key vs. per-session NATS nkey) means a stolen NATS credential yields only
  scoped broker access, never E2E impersonation (ADR-001 §A12 #3, #5).
- Root-only device certification bounds compromise blast radius: a stolen secondary device cannot mint further
  devices (ADR-001 §A12 #25).
- The cap-renewal path (expired/stale-epoch caps still earn connect-only access for re-issue) eliminates lockout as a
  failure mode without weakening revocation — only explicitly revoked subjects are refused.
- Pre-committed root rotation and root-signed self-revocation give a person a way to recover from device loss or
  suspected root compromise without any registry involvement (ADR-001 §A12 #26).

### Negative

- Losing the recovery phrase *and* all devices is unrecoverable for that identity root — the documented fallback is
  per-host re-invite under a new root, which loses continuity of the old identity (an accepted trade-off, not a bug).
- Losing a host's root key invalidates that host's identity entirely (new host, re-invite everyone) — there is no
  registry-side recovery path, by design, since the registry holds nothing about the host.
- Revocation is only best-effort at the callout (helper's durable store may lag); the host's per-request enforcement
  is authoritative, which means a compromised device can still reach the host directly until the host itself
  processes the revocation — mitigated but not eliminated by S14's offline-revocation deposit.

### Neutral

- `cap_epoch` and `grants_version` are deliberately two separate counters — merging them (as in the v0.7 design) was
  found to conflate security invalidation with cache invalidation and was rejected (see Alternatives Considered).
- The 32-cap-per-connection ceiling and 32 KiB `max_control_line` are current defaults pending S12 measurement, not
  permanent limits — see Open items below.

## Alternatives Considered

| Alternative | Verdict | Why |
|-------------|---------|-----|
| Registry-held user accounts (passkeys) + key directory (v0.2–0.4 design) | **Rejected (user decision)** | Registry must only broker connections; accounts live per host; removes the identity provider / key directory from the trust surface entirely |
| Per-device members, no chain | Rejected | Poor multi-device UX; would require re-invite at every host on recovery |
| Host-local passwords for members | Rejected | Breaks the E2E key model and the one-identity-many-hosts UX |
| Device-signs-device chains | Rejected (v0.6) | Unbounded compromise amplifier — a compromised secondary device could mint further devices; root-only certification instead |
| P-256 fallback suite | Rejected (v0.6) | All target browsers ship Ed25519/X25519; a second curve suite is itself a downgrade attack surface |
| Stateless helper with cached epochs | Rejected (v0.6) | Fails open on helper restart; durable host-signed revocation records instead |
| Host-wide single epoch (merging `cap_epoch`/`grants_version`) | Rejected (v0.8) | Conflated security invalidation with cache invalidation; split into two counters |

## Open items

Per DESIGN.md's provenance note, remaining `[USER DECISION]` and `[DEFAULT]` rows relevant to this ADR are recorded
here, not resolved by this document:

| A10 # | Decision | Status | Detail |
|-------|----------|--------|--------|
| 5 | Max hosts per client connection (CONNECT + JWT size) | **[DEFAULT]** | 32 (S12 verifies) |
| 12 | Device certification | **[DEFAULT]** | Root-signed only; root on primary device (OS keystore) + recovery phrase; browsers never primary |

The following related A10 rows are **already decided** (not open) and are folded into the Decision section above for
context: A10.1 (private CA/mTLS optional profile), A10.2 (no registry accounts), A10.3 (invite-carried keys + pinning
+ key-change wall), A10.4 (recovery phrase), A10.4b (host authorization model — full detail in ADR-006).

## References

- `../DESIGN.md` §A4 (Identity, capabilities, enrollment), §A7b (Signed-artifact profile — subset reproduced above),
  §A10.1–5, §A10.12
- ADR-001 (Threat model — §A12 rows cited throughout this document)
- ADR-002 (NATS signaling — full Auth Callout permission grants and subject scoping that consume the capabilities
  defined here)
- ADR-004 (E2E signaling envelope — the envelope format that carries device certificates and caps during connect)
- ADR-006 (Host authorization: members, shares, entitlements — host-side per-request enforcement, the authoritative
  revocation check)
- ADR-007 (Registry control plane — admission tokens, which reuse this ADR's invite/capability pattern one level up)
- `docs/SPIKES.md`: S9 (revoke → kick → host rejects, < 5 s), S12 (CONNECT size / cap presentation at scale), S14
  (revoke a device while its host is offline), S15 (recovery-phrase comprehension test), S18 (cap lifecycle: expiry,
  device bootstrap QR state bundle, refetch)
