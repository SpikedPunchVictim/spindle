# Spindle — System Design Document (draft v0.9.4) + Execution Plan

> **How to read this file.** Part A is the codified design (what will become `docs/DESIGN.md` and ADR-001…006 in the
> project). Part B is the execution plan. Part C records the Opus review disposition. Part D is the change log.
> v0.5: **registry is a connection broker only — all accounts live on hosts** (user decision 2026-08-23); adds the
> host authorization model (members, shares, entitlements). v0.6: second Opus review integrated (Part C2): CONNECT
> size, helper state, root-only device certs, root/host key rotation, honest ZK wording, VFS hardening. v0.7: adds
> the registry control plane (A3b — host admission, operator admin via signed commands, TypeScript admin library;
> user decisions 2026-08-23). v0.8: dual gap-hunt (Opus + Fable) integrated — capability lifecycle & device
> bootstrap, signed-artifact profile (A7b), helper consistency model, transfer manager, operations (A14), delivery
> (A15), hardened browser delivery, LAN non-goal, abuse posture (user decisions 2026-08-23). v0.9: repository
> layout & toolchain codified (A9c) — React UIs, host = single Tauri tray app, `just` + pnpm + cargo front door
> (user decisions 2026-08-23).
> Remaining **[USER DECISION]** items: A10.6–9, A10.24 (license), and the **[DEFAULT]**-flagged rows in A10.

---

# Part A — Design Document

## A0. Status & provenance

- Supersedes/amends: `SPINDLE_ADR.pdf` (ADR-002 "NATS Core over mTLS for Peer Discovery, Authentication, and WebRTC Signaling").
- Inputs from the user (2026-08-23): a **browser client is planned**; **ADR-001 (threat model) did not exist**; closed
  system with its own **private CA available**; **accounts live only on each host server — the registry's sole
  responsibility is facilitating client↔server connections**; priorities are user integrity and a superior UX.
- Method: architecture review → red-team pass → codified v0.2 → independent Opus review → v0.3/0.4 → host-auth
  model discussion → v0.5 → second Opus review → v0.6.

## A1. Goals and non-goals

**Goals**
1. Users run a *host* (Rust daemon, system tray) on their own machine, expose chosen files/directories in a **virtual
   file system**, and let approved people browse/download/upload according to **group entitlements** — from a native
   app **or a browser** — peer-to-peer.
2. The registry is a **connection broker and nothing more**: it holds no accounts, introduces no keys, cannot read
   file contents or signaling payloads, and cannot alter session setup without detection. It never learns what a host
   shares, member names, groups, or entitlements; it does observe, as connection metadata, which devices hold
   capabilities for which hosts (stated honestly in A2).
3. Connection setup feels instant; presence is accurate; failures are explained, not silent; transfers are fast enough
   that users don't reach for a USB stick; permissions are predictable and explainable in one sentence.
4. Custom infrastructure is **small**: NATS for signaling, WebRTC for transport, one small replicated broker-helper
   service (callout verifier, presence, TURN credentials, kick relay, durable store of host-signed revocations) that
   holds **no membership data**.

**Non-goals (v1)**
- Hiding *metadata* (which device connected to which host, when, from which IP) from the registry operator.
- Protecting a member from a malicious *host owner* they chose to join, or anyone from a compromised endpoint/OS.
- Federation / multiple registries; delegated host administration (owner-only in v1).
- **LAN-only operation** (decided A10.21): two devices without internet cannot connect in v1 — signaling requires the
  registry; the transfer itself is direct. The UI says so plainly; mDNS-assisted local signaling is a tracked v2
  candidate.

## A2. Threat model (→ ADR-001)

**Assets**: (1) file contents in transit (confidentiality + integrity); (2) identity (no impersonation of a person or
device); (3) host availability and non-exposure to unauthorized parties; (4) session-setup integrity (keys, SDP/ICE,
DTLS fingerprint); (5) the host owner's filesystem — confinement to what was deliberately shared, and safety of what
is received.

**Adversaries**

| ID | Adversary | Starts with | Wants |
|----|-----------|-------------|-------|
| A1 | Malicious *authenticated* device/member | A valid device key; membership on some hosts | Reach hosts/paths they weren't granted; escape the VFS; eavesdrop/hijack/inject into others' sessions; enumerate/flood hosts; plant hostile files |
| A2 | Compromised or malicious registry (NATS node, broker-helper service, or operator) | Full view of broker traffic & config; can mint NATS permissions | MITM session setup by substituting keys/SDP; impersonate; grant itself access |
| A3 | Device/credential thief | A user's laptop/phone, or extracted keys/tokens | Act as that device/person until revoked |
| A4 | Browser-side attacker (XSS, malicious extension) | Code execution in the web client page | Use/steal device key or NATS token; exfiltrate files mid-transfer |
| A5 | Resource abuser | Any number of freshly generated device keys | Flood NATS/hosts; run up TURN bills |
| A6 | Passive/active network attacker | On-path | Read/alter traffic (defeated by TLS/DTLS) |
| A7 | Thief of the **operator admission key** | The registry control plane | Admit rogue hosts; evict real hosts (availability). **Cannot** impersonate existing hosts or reach any member's files — admission ≠ identity (A3b) |

**Definition of "zero-knowledge" for Spindle**: *The registry can route messages and observe connection metadata, but
(a) cannot read file contents, (b) cannot read signaling payloads, (c) cannot alter session setup — including which
public keys peers trust — without detection, and (d) holds no account, member, group, or share data; the only
membership signal it has is connection metadata (device ↔ host capability presentation).* (c) follows from keys being
introduced only via **invites** and **root-signed device certificates** (A4) plus E2E-authenticated signaling (A7);
(d) follows from the registry verifying host-signed capabilities it does not issue (A4). Mitigations for the
metadata in (d): present only the caps needed this session; rotate the NATS connect key per session.

**Trust boundaries**: device ↔ registry (TLS; authorization via host-signed capabilities); device ↔ host (pinned
identity roots + E2E envelope + DTLS); host ↔ its own filesystem (capability-confined share roots, A4b/A8). Registry
operator is **untrusted for payloads, keys, and membership**, trusted for availability and metadata retention (A10.7).
**Browser client code**: the web bundle would otherwise be served by the operator — the party this model distrusts —
so v1 uses **hardened delivery** (decided A10.20): reproducible builds, a release-key-signed manifest (release key ≠
operator key), immutable versioned bundles with SRI pinning, and a companion **verification extension** (Code-Verify
pattern) that checks the served bundle against the published manifest. Residual risk, stated: a browser session
without the extension trusts the operator for code integrity on first load; native apps never do.

**Explicitly out of scope**: malicious host owner, endpoint compromise, supply chain of daemon/web bundle (tracked
separately), legal compulsion of connection metadata.

## A3. Architecture overview

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
- **NATS cluster** — signaling substrate only (core NATS; no JetStream in v1). TCP listener for daemons, WebSocket for
  browsers; both server-cert TLS; every connection authorized via Auth Callout. mTLS with short-lived certs from the
  private CA = optional hardened profile on the TCP listener (decided, A10.1). Minimum nats-server **2.10**.
- **Broker helper** (the whole "backend"): **small, replicated (≥2, queue group), holds no membership data**. Roles:
  callout responder verifying **host-signed capabilities**; presence service (live connection map rebuilt from
  `$SYS.REQ.SERVER.PING.CONNZ` on start + `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` deltas; answers
  `helper.presence.get`); kick relay (`device_fp → (server_id, cid)` from the same map); TURN credential minting with
  quotas per `root_fp`; **durable store of host-signed revocation/epoch records** (opaque, host-signed, keyed by
  `host_fp`) + TURN counters + connection-metadata retention (A10.7). NATS in front must set `max_control_line`
  (A10.10) and sit behind per-IP connection/rate limits (the callout is the DoS surface). HA + load test (S8, S12).
- **Host daemon** (Rust): host identity root + operating key (A4); owns **members, groups, shares, entitlements**
  (A4b); signs capabilities; pins member identity roots; VFS server over the DataChannel; rate-limits per peer;
  received-file policy; audit log.
- **Clients**: native (Rust, shared core crate with host) and browser (TypeScript; WebCrypto + `@noble/curves`
  fallback). Hold a root-signed device key (primary device also holds the root, A4); pin host roots.
- **TURN**: coturn with REST-style time-limited credentials.

## A3b. Registry control plane: host admission & administration (→ ADR-007)

In v0.6 a host was purely self-certifying — anyone could mint a key and become a host. Clients are already gated
(no capability → refused), so hosts were the one ungated principal. The control plane closes that.

**Admission modes** (registry config, switchable at runtime; mode changes are signed admin commands, so a
"downgrade to open" is itself authenticated and logged):

| Mode | Behavior |
|------|----------|
| `invite` (**default**, decided A10.17) | New hosts must redeem a single-use operator **admission invite** |
| `open` | Any valid host cert admitted; per-IP and total-host quotas apply |
| `closed` | No new hosts; existing admitted hosts unaffected (incident response / capacity freeze) |

**Admission mechanisms (decided A10.18: both)** — same invite/capability pattern as host→member, one level up:
- *Admission invite token*: `{nonce, exp (days), label, quota_profile, sig_operator}` — bearer token minted by the
  operator, pasted/scanned into the host daemon's setup. On first connect the host presents it with its host cert;
  the helper **burns the nonce** (durable store) and writes an **admission record**
  `{host_fp, label, admitted_at, quota_profile}`. Thereafter the host connects on its cert alone; the callout checks
  the admission record.
- *Fingerprint pre-registration*: the prospective host shows its `host_fp`; the operator signs it directly
  (`sig_operator(host_fp, label, quota_profile)`) — no bearer token in flight; for high-assurance admissions.

**Operator admission key**: separate from all other keys; held in the admin library's `Signer` (file-encrypted, OS
keychain, or hardware token); pre-committed rotation (same pattern as user roots). **Blast radius (by design)**: a
stolen admission key can admit rogue hosts and evict real ones — an *availability* attack only. It can never
impersonate an existing host, read payloads, or reach members' files, because admission ≠ identity: members connect
only to hosts whose root keys they pinned via invites. A rogue admitted host is an empty host nobody has joined.

**Admin surface (decided A10.19)**: a **TypeScript library** (`@spindle/admin`) owns the protocol — command signing
(same envelope discipline as A7: nonce, ts, canonical CBOR), admission-invite minting, pluggable `Signer` interface
(file key / OS keychain / hardware token / WebCrypto), and the NATS connection logic. The v1 client is a CLI
(`spindle-admin`) built on it; any future interface (web, Telegram, …) builds on the library and owns its own
transport security. The helper verifies operator signatures on `registry.admin.>` — the admin plane is **a verifier,
not a login**: no passwords, sessions, or CSRF surface. Admin NATS connections MUST use the mTLS profile on the TCP
listener (the private CA is mandatory here even though optional for users). Optional later: two-person co-sign for
destructive ops.

**Operator capabilities**: switch mode · mint/revoke admission invites · pre-register a host_fp · list admitted
hosts (fp, label, first/last seen, connection count — metadata only; shares/members remain invisible per A2) ·
**suspend/evict** a host (kick + refuse re-auth; members see it offline) · set quota profiles (max concurrent member
connections, TURN budget) · rotate the admission key · read the hash-chained admin **audit log** (every command,
signer, result).

## A4. Identity, capabilities, enrollment (→ ADR-003)

**There are no global accounts.** Identity is cryptographic and is *recognized* per host.

**Principals**
- *Person* = an **identity root key** (Ed25519). Generated on the person's **primary device**, where it lives in the
  OS keystore (biometric/passcode-gated) and is backed up as the recovery phrase (decided A10.4). At enrollment the
  root also commits `hash(next_root_pk)` (pre-committed rotation). `root_fp = hash(root_pk)`.
- *Device* = keypair generated on-device: Ed25519 (sign) + X25519 (agree); `alg_id` is a **suite version byte**
  (`1` = Ed25519/X25519/AES-256-GCM; no P-256 fallback — all target browsers ship Ed25519/X25519);
  `device_fp = base32(SHA-256("spindle-dev-v1" || alg_id || sign_pk || agree_pk))`. Carries a **device certificate
  signed only by the root**: `sig_root(device_fp, nats_fp, ts, label)`. **Secondary devices cannot mint devices**
  (a compromised secondary cannot amplify); browsers are never root holders. Adding a device = scan QR from the
  primary device (or enter the recovery phrase on the new device, which then becomes primary).
- *Host* = has a **host identity root** (`host_fp = hash(host_root_pk)`, backed up with the share config / recovery
  phrase) that signs its **operating key** (`sig_host_root(host_op_pk, nats_fp, ts)`). Members pin `host_fp`; rotating
  or reinstalling the operating key from backup does **not** trigger the key-change wall; losing the host root = new
  host (re-invite everyone) — stated in the host UI at setup, with backup nagging.
- *Member* = a host-local record binding a `root_fp` (and its accepted device chain) to host-local state (A4b).

**Two credentials per device**
1. *Device identity key* — envelopes (A7), capability redemption, VFS session binding. Browser: non-extractable
   WebCrypto (limits persistence of an XSS compromise; does not prevent use while the page is compromised).
2. *NATS connect key* — a separate nkey, **rotated per session** (native: seed in OS keychain; browser: IndexedDB —
   low value by design). Stolen → scoped broker access only, never E2E impersonation. `nats_fp = hash(nats_pk)`; the
   device certificate binds `nats_fp` to `device_fp`; a per-session nkey is attested by `sig_device(nats_fp, ts)`.

**Capabilities (host-signed, self-verifying)**
```
cap = { v, host_fp, host_pk, kind: invite|member, subject: root_fp | device_fp, cap_epoch, exp, nonce, sig_host }
```
- **`cap_epoch` vs `grants_version`** (two jobs, two counters): `cap_epoch` bumps only on security events (member/
  device revocation) and invalidates caps; `grants_version` is host-internal (entitlement edits, cache invalidation)
  and **never leaves the host**. Revoking one member does not invalidate other members' caps unless the host chooses
  a full rotation.
- Self-verifying: `host_fp == hash(host_pk)` and `sig_host` checks under `host_pk` — the callout needs **no registry
  of hosts or members**.
- `invite`: **bearer** token — single-use enforced by the **host** (nonce burned on redemption; the helper cannot
  enforce single-use), `exp` in **hours** (default 24 h, owner-adjustable), scope = `connect` only, rate-limited per
  nonce at the host, may embed an initial group (A4b). Shared as QR/link; the payload also carries the **registry
  endpoint + TLS pin policy** (so clients need no baked-in registry address; admission tokens likewise).
  **Redemption is idempotent**: the host stores `nonce → {member_id, issued_cap}` atomically; re-presentation of the
  same nonce within `exp` replays the stored cap (a crash or lost reply between burn and delivery cannot strand the
  invitee). The same rule applies to admission invites at the helper. **It also carries the host's public keys →
  the registry never introduces a key.**
- `member`: issued by the host after redemption, scope = full signaling with that host; `subject = root_fp` so every
  root-certified device of the person may use it. `exp` in **weeks** (default 6; refreshed opportunistically on every
  successful session). Stored per platform: native → OS keychain; browser → IndexedDB (a cap is host-signed and
  useless without the device key). **Renewal path (no lockout)**: a cap that is expired or stale-epoch but
  signature-valid still earns **connect-only** NATS permissions (same as an invite); the host verifies the device
  over the E2E channel and re-issues the current cap in the reply. Only *revoked* subjects are refused outright.
- **Presentation**: caps travel in the CONNECT `auth_token` as compact CBOR (~200 B each, base64url). nats-server's
  default `max_control_line` is 4 KiB, so the registry sets it to **32 KiB** (A10.10) and clients present **only the
  caps for hosts they will use this session** (pinned/open hosts), max **32** per connection (A10.5). S12 measures.

**NATS authentication = Auth Callout for every connection**
1. Device connects signing the server nonce with its session nkey and presents: device certificate (root-signed),
   session-nkey attestation, and the capabilities for this session (`member` caps, or one `invite` cap).
2. Callout verifies (cheap checks first: sizes, counts, `exp`): nkey signature; device cert → `root_fp`; each cap's
   `sig_host`, `exp`, `subject` matches `root_fp`; **best-effort** revocation/epoch check against the helper's durable
   store of host-signed records (A4 Revocation) — *the authoritative check is the host's per-request enforcement
   (A4b)*. Returns a user JWT with permissions (A5), limits (`payload` 64 KiB, `subs` ≤ 4N+8, `data` cap),
   `allowed_connection_types` (`WEBSOCKET` browser / `STANDARD` daemon), `exp` jittered in [45, 75] min.
3. A host connection presents `sig_host_root(host_op_pk, nats_fp, ts)` (+ an admission invite on first connect);
   callout checks `host_fp == hash(host_root_pk)` **and the admission record / mode policy (A3b)**
   → host permissions for `host.<own_fp>.>`. A connection presenting **no** valid cap is refused (A5 Sybil/flood
   defense) — the `invite` cap is the only bootstrap path; per-IP limits in front of NATS bound callout cost.
4. Why not `verify_and_map`/registry accounts: cannot express per-host scoping, revocation, browsers, or "no accounts
   at the registry." mTLS optional.

**Enrollment / first run (primary device)**: generate root (show recovery phrase; commit next-root hash) + device key;
native: optional short-lived cert from the private CA (hardened profile). Redeem an invite → member of that host.
**Adding a device (device bootstrap)**: new device shows QR; the **primary** device signs its certificate **and
returns a state bundle** `{registry endpoint, [{host_fp, host_pk, member_cap}…]}` — the QR transfers state, not just
a signature. All hosts accept the new device automatically (they pinned `root_fp`) and notify the owner ("Alex added
*iPhone*"). Any root-certified device can also **re-fetch its cap** from a host directly (connect-only → E2E
re-issue, above). A browser is enrolled the same way and is never primary. **Recovery without the primary device**:
the recovery phrase restores the root but *not* the host list — the person re-learns hosts from saved invite links
or by re-invite; the signup UI says this. Device certificates carry `exp` (1 year, re-signed by the primary on
contact); device **labels are host-local display state**, renameable by the person and the host owner — never baked
into certificates.

**Key introduction** (decided A10.3): invite carries host keys; the client's first envelope carries its device
certificate + chain encrypted to the host's agree key and HMAC'd with the invite nonce; both sides **pin**; later key
change = hard, non-dismissable wall. Safety numbers optional.

**Revocation**: host revokes a member (root) or a device → bumps epoch and publishes a **host-signed revocation
record** `{host_fp, epoch, revoked: [root_fp|device_fp], ts, sig_host_op}` to `registry.revoke`; the helper stores it
durably, kicks live connections (`$SYS.REQ.SERVER.<id>.KICK {id: cid}` via its connection map), and refuses the
cap on re-auth; the host rejects envelopes/VFS requests from revoked keys **per request** (authoritative); live VFS
sessions are dropped. Cut-off target < 5 s (S9). A person revokes a lost device with a **root-signed** revocation,
delivered to each host on next contact *and* deposited at the helper so the callout refuses it even while hosts are
offline (S14). **Root rotation**: `sig_old_root(new_root_pk)` where `hash(new_root_pk)` matches the pre-committed
value; hosts accept without the wall; owner can also revoke a root out-of-band from the host UI. **Recovery**:
recovery phrase restores the root onto a new primary device (decided A10.4); if the root is lost, the documented
fallback is per-host owner **re-invite** (member record migrates to the new root) — not a disaster, a normal flow.

## A4b. Host authorization: members, shares, entitlements (→ ADR-006)

Everything here lives **only on the host** (SQLite) and is enforced **only by the host**. The registry never sees it.

**Members** — `{member_id, root_fp, display_name, status: invited|active|revoked, devices[{device_fp, label, added,
revoked?}], groups[], created}`. "Creating an account" == issuing an invite; redemption creates the member.
Owner = implicit member with all rights; **owner-only administration in v1** (decided), performed **only in the
host's local UI** (tray/desktop) — no remote admin surface in v1 (A10.11).

**Shares (the VFS)** — the owner adds a file or directory → `{share_id, name, mount_path, real_root, flags:
{read_only, allow_upload, show_hidden}, excludes: [glob…]}`. Shares are mounted into **one virtual tree per host**;
clients only ever see/speak virtual paths. Exclusions are share-level (apply to everyone) and are how "Photos except
Photos/Private" is expressed — keeping the permission algebra monotonic. Rules: **no overlapping roots** (rejected at
add-time by resolved real path *and* device+inode/file-id; re-checked at host start); warn when rooting at a home or
volume root; caps on shares per host, globs per share; when a share has exclusions, files with link count > 1 are
not served (hardlink bypass); **archives are never auto-expanded**.

**Groups** — built-in `Owner` (implicit, all, not editable) and `Members` (default, empty grants); custom groups.
Members ↔ groups many-to-many. Invites may name an initial group ("Invite Alex to *Family*").

**Entitlements** — `{group_id, share_id, subpath, perms ⊆ {browse, download, upload, delete}}`.
- **Algebra (decided)**: positive-only; effective perms of a member on virtual path P = **union** of all grants from
  all their groups whose `(share, subpath)` is a prefix of P; inherited down. No denies in v1; exclusions live on shares.
  Explainable as: "you can do whatever any of your groups can do, anywhere under the folder it was granted on."
- `upload`/`delete` grantable only on shares flagged `allow_upload` (decided: uploads in v1, opt-in per share).
- **Edge rules**: `browse` on P implies *traversal* of P's ancestors (ancestors list only the path toward P);
  `upload` on P implies resolution of P without listing it (drop-box); `delete` does **not** imply `download`;
  overwrite of an existing entry requires `delete`; creating a name that collides case-insensitively or under
  Unicode normalization with an existing dirent **is** an overwrite.
- **Secure by default**: new share → no grants; new member → `Members` group with no grants. Nothing is visible until
  granted.

**Enforcement** — every VFS request (A8) is checked against a cached effective-grant table for the member,
invalidated by the host `epoch`, **per request** (revoking Family takes effect immediately, not at reconnect).
Listings show only entries the member can `browse`; non-browsable paths return **not found** (no existence leak).
Client UI hides what isn't permitted — courtesy, not security.

**Path confinement** — share roots opened as `cap-std` `Dir`s (pinned ≥ 3.4.1 / 4.x; RUSTSEC-2024-0445 and
Windows DOS/UNC device-path cases covered in S11); all I/O via the capability (no `..`, symlink escape, or
absolute-path tricks by construction); symlinks out of the root not followed; no device files. cap-std does **not**
canonicalize, case-fold, or normalize — Spindle does: exclusion/permission matching uses the resolved real path plus
case/Unicode folding on case-insensitive filesystems, and identity checks (dev+ino / file-id) where names are
ambiguous. Every request re-resolves from the share `Dir` (no long-lived subdirectory handles); file identity is
checked between `stat` and `read`/`upload` and on every chunk boundary, aborting on change (TOCTOU/rename races).
Uploads land only under the granted subpath, obey A8's received-file policy, per-member and per-share quotas, and
never overwrite without `delete`.

**Audit log** — `{ts, member, device, action, virtual_path, bytes, outcome}` for every VFS op and every admin change;
hash-chained append-only with a periodically signed head (tamper-evident). `list` is cursor-paged with a max page;
exclusion globs are precompiled; `whoami` returns only the caller's own effective paths (no group names).

**Owner live operations** — *Sessions* view (who is connected now, per device, current transfer, bytes); **soft
disconnect** of a live session (not a revocation); host-level **free-space floor** that pauses uploads before the
disk fills; optional per-host **egress cap** (owner bandwidth throttle, distinct from the security rate limits).

**Operator UX** — *Shares* (add folder → name → appears in tree), *People* (members, their devices, groups; revoke a
device or the person), *Groups* (grid Groups × Shares with perm chips; click to refine a subpath),
**"Preview as …"** (see the tree exactly as a member sees it), plain-language explanations ("Alex can download from
Photos because they're in Family") derived directly from the union model.

## A5. Subject and permission model (→ ADR-002 rev)

| Subject | Publisher | Subscriber | Notes |
|---------|-----------|------------|-------|
| `host.<hfp>.connect` | devices holding a cap for `hfp` | host | request/reply; envelope (A7) with client's inbox inside |
| `host.<hfp>.sess.<cfp>.<sid>.c2h` | client `cfp` only | host | trickle ICE + session control |
| `host.<hfp>.sess.<cfp>.<sid>.h2c` | host | client `cfp` only | trickle ICE + session control |
| `host.<hfp>.presence` | broker helper (from `$SYS` events) | devices holding a cap for `hfp` | push deltas `{host_fp, state, last_seen}` only |
| `helper.presence.get` | devices | broker helper | request/reply snapshot for the caller's hosts (core NATS has no retained messages) |
| `registry.revoke.<hfp>` | host `hfp` only | broker helper | host-signed revocation/epoch records (durable; helper asserts subject token == record `host_fp`; per-host token bucket) |
| `helper.turn.get` | authenticated devices | broker helper | request/reply TURN credentials (helper authorizes via the session record, below) |
| `registry.admin.>` | operator (mTLS + operator cert) | broker helper | signed admin commands (A3b); replies via `allow_responses` |
| `_INBOX_<dfp>.>` | host via `allow_responses` after prefix check | owning device | private inbox prefix |

**Permissions issued by callout**
- Host: `sub host.<own>.>`, `pub host.<own>.sess.*.*.h2c`, `pub registry.revoke`,
  `allow_responses {max:1, expires:"2m"}`; explicit deny of `_INBOX.>`, `$SYS.>`, `$JS.>`.
- Client, for each host `h` in its verified caps: `pub host.<h>.connect`, `pub host.<h>.sess.<own>.*.c2h`,
  `sub host.<h>.sess.<own>.*.h2c`, `sub host.<h>.presence`; plus `sub _INBOX_<own>.>`, `pub helper.presence.get`,
  `pub helper.turn.get`. Invite-only and stale-cap connections get just `pub host.<h>.connect` + inbox. Max 32 hosts
  per connection (A10.5). **Session record**: on each successful auth the callout writes
  `nats_fp → {root_fp, host_fps, quota_profile, exp}` to the helper store, so the helper can authorize non-callout
  requests (`helper.presence.get`, `helper.turn.get`) — cleaned up on DISCONNECT/expiry.
  **Account topology (A10.15)**: one application account + system account; every cross-boundary subject
  (`$SYS.REQ.USER.AUTH`, `$SYS` events, `helper.*`, `registry.*`) gets an explicit export/import row in ADR-002's
  topology table — no implicit sharing.
- **Helper account bridging [DEFAULT]**: the broker helper holds **two separate NATS connections** — one on the
  system account (callout responder, `$SYS` events, CONNZ, KICK) and one on the application account
  (`helper.*` request/reply, `host.<hfp>.presence` publishing, `registry.*` subscriptions) — rather than one
  dual-privileged connection; finalized in S1 and recorded in ADR-002's topology table.
- **Host MUST validate** on every `connect`: reply subject starts with `_INBOX_<from_fp>.`; sender is an active member
  device (cheap check **before** crypto) or holds a valid unused invite; per-`from_fp` token bucket and
  max-concurrent-sessions; `sid` not bound to a different `from_fp`. All rejections are **uniform silent drops**
  (no distinguishable not-member / rate-limited / bad-envelope responses, timing included).
- Consequences: an A1 attacker cannot reach/enumerate/flood hosts it has no cap for, cannot see/inject into other
  clients' sessions, cannot read other inboxes, cannot proxy through a host; an A5 attacker with fresh keys gets no
  connection at all.

## A6. Signaling flows

**Presence**: broker helper keeps a live connection map (CONNZ on start + `$SYS.ACCOUNT.<acct>.CONNECT|DISCONNECT`
deltas), answers `helper.presence.get` on client start, and pushes deltas on `host.<hfp>.presence`;
`ping_interval` ~20 s / `ping_max` 2 so a dead socket flips ≤ ~60 s; UI shows online / offline / unresponsive
(last seen). **Multiple connections per identity are normal** (native app + browser tab): the connection map and
kick relay are one-to-many per `device_fp`; presence is by connection count, not a boolean, and reconnect overlap
(CONNECT before stale DISCONNECT) never flips a live host to offline. **Two daemons with the same restored host
key** = split-brain: newest connection wins, the older is kicked, and both machines show a loud warning.
No-responders on `connect` → **instant** "host is offline". Clients also expose a **"registry degraded"** state
(helper unreachable) distinct from "host offline" — without it a dead helper is symptomless for up to an hour (A14).

**Connect + offer/answer + trickle ICE**
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
- ICE servers + TURN creds per session from the broker helper; `iceTransportPolicy: relay` privacy option.

## A7. End-to-end signaling envelope (→ ADR-004)

```
Envelope { v:1, alg_id, from_fp, to_fp, sid, kind, seq, ts, eph_pk?, ciphertext, sig }
Session key:  k = HKDF-SHA256(X25519(eph_self, eph_peer) || X25519(dev_self, dev_agree_peer),
                              info = "spindle-sess-v1" || sid || from_fp || to_fp)   (ephemeral-static hybrid)
AEAD:         AES-256-GCM, nonce = direction(1) || seq(11) — deterministic, never reused; AAD = canonical header
sig:          Ed25519(dev_sign_from, "spindle-env-v1" || canonical(header) || ciphertext)
canonical():  deterministic CBOR per RFC 8949 §4.2.1 (same profile for VFS RPC)
```
**Receiver MUST**: verify `sig` under the **pinned** key for `from_fp` (or, for an invite redemption, under the key
carried in the device certificate, which must chain to a root and be HMAC-bound to the invite nonce); `to_fp == self`;
sender active/not revoked; `sid` matches subject and is bound to `from_fp`; `seq` strictly increasing per
(sid, direction); `|ts − now| ≤ 2 min`; `kind` matches subject; `v`/`alg_id` not below the peer's pinned minimum.
Failure ⇒ drop, count, alert on threshold.
**Browser crypto**: WebCrypto Ed25519/X25519 (Firefox 129+, Safari 17+, Chrome 137+) with `@noble/curves` fallback;
AES-GCM/HKDF native. **Clock skew**: the helper returns server time in the callout reply; clients compute an offset
for `ts`/`exp` checks and the UI warns on large skew.
**Properties**: registry cannot read or forge SDP/ICE; device-key compromise does not retroactively decrypt captured
signaling; replay/splicing/downgrade rejected.

## A7b. Signed-artifact profile (applies A7's discipline to every signed thing)

Every signed artifact shares: version byte `v`, **distinct domain-separation tag**, canonical CBOR (RFC 8949
§4.2.1), a stated time rule, and a stated replay rule. Unknown `v` ⇒ reject. Catalog:

| Artifact | Tag | Signer | Time rule | Replay rule |
|----------|-----|--------|-----------|-------------|
| Envelope | `spindle-env-v1` | device key | `ts` ±2 min (helper server-time offset) | (sid, direction, seq) monotonic |
| Member/invite cap | `spindle-cap-v1` | host root (via op key) | `exp` (no `nbf`; schema-of-record carries none [amended v0.9.4]) | invite: nonce burn (idempotent replay of result); member: n/a |
| Admission token | `spindle-adm-v1` | operator key | `exp` days | nonce burn at helper (CAS, idempotent) |
| Device certificate | `spindle-dev-cert-v1` | identity root | `exp` 1 y; re-sign on contact | n/a (revocable) |
| Revocation record | `spindle-rev-v1` | host op key / identity root | none (permanent) | **max-wins, never decreases**; old records cannot roll back |
| Admin command | `spindle-adm-cmd-v1` | operator key | `ts` ±2 min | per-signer monotonic `seq` + nonce; idempotent execution |
| Host op-key cert | `spindle-host-cert-v1` | host root | `exp` 90 d | n/a (rotation) |

Root keys sign two artifact types (device certs, self-revocations) — the distinct tags prevent cross-artifact
signature confusion. Host and helper both use helper server time for `exp`/`nbf` checks (single authority; ±2 min).

**Schema-of-record**: the canonical CBOR field-level schema for every artifact above now lives in
`crates/spindle-proto/src/lib.rs` (Stage 2 implementation), superseding this table for field-level detail. Two
clarifications resolved during implementation: (1) **Device certificate carries no `label` field** — A4's "labels
never baked into certificates" rule supersedes the older inline notation that listed `label`; (2) only **Envelope**,
**Member/invite cap** (Capability), and **Admin command** carry an explicit `v` field — for the other four artifacts
(Admission token, Device certificate, Revocation record, Host op-key cert) the A7b domain tag above is itself the
version discriminant; (3) the Capability artifact carries no `nbf` field — `exp` is the sole time bound; (4) the
pre-committed root-rotation record (`sig_old_root(new_root_pk)`, §A4) is not one of the seven cataloged wire
artifacts — v1 implements it crate-locally in spindle-core with its own domain tag; promoting it to a spindle-proto
wire type (with golden vectors) is flagged for when rotation records first cross the wire (device↔host sync).

## A8. Transport, VFS RPC, and file safety (→ ADR-005)

- Rust: `webrtc-rs` (≥ 0.20, sans-I/O core); evaluate `datachannel-rs` if S3 fails. **Throughput is RTT-bound by SCTP
  windows** — window/buffer tuning is a required S3 outcome.
- **S3 result (2026-08:)** loopback/LAN passes; single-association SCTP fails the 50 ms bar in both Rust stacks
  (~1–2 MB/s) while TCP on the same path does 60 MB/s; parallel associations reach ~7.7 MB/s at N=8. Decision
  A10.29: investigate deeper (Chrome dcSCTP peer measurement + cwnd profiling) before revising the A9 bar or
  reopening the transport alternative; ADR-005 remains Proposed.
- Channels: one reliable-ordered control channel (VFS RPC) + **one** unordered-reliable data channel (all channels
  share one SCTP association/cwnd; more channels don't add throughput); 64 KiB chunks; backpressure via
  `bufferedAmountLow`; resumable transfers (manifest + offsets + per-chunk hashes); UI shows direct/relayed and speed.
- **VFS RPC** (control channel, CBOR): `list(path, cursor) → entries[{name, kind, size, mtime, perms_here}]`,
  `stat(path)`, `read(path, offset, len) → chunk stream on data channel`, `upload(path, size, hash) → resumable
  session`, `mkdir(path)`, `delete(path)`, `whoami → {member_display, effective_paths}`. All paths virtual; every
  call permission-checked (A4b); unauthorized == not found. RPC carries a protocol version; peers negotiate the
  highest common version with no downgrade below each side's minimum.
- File integrity: per-chunk hash + whole-file hash in a manifest signed by the sender's device key.
- **Received-file policy**: attacker-supplied names → flat sanitized basename; reject separators/`..`/reserved names;
  land under the granted upload subpath (or per-member quarantine dir for owner-received files); no overwrite
  without `delete`; size caps per transfer/member/share; OS quarantine attribute; never auto-open; audit log.
- TURN: coturn `use-auth-secret`, `username = expiry:device_fp`; quota enforced by the helper per **`root_fp`**
  (device keys are free to mint); short TTLs; allocation caps.
- Browser receive path: File System Access API where available; streaming-download fallback with a stated ceiling
  (A10.6); background-tab/sleep → resume (S7).
- **Transfer manager**: client-side queue (folder download = sequential queue over `list` + `read`; **no server-side
  archive generation**); directory upload mirrors it; per-session concurrency limit (default 3); resume manifests
  persisted locally (native: app data; browser: IndexedDB/FSA) so progress survives restart; on resume-conflict
  ("file changed") the transfer aborts with a clear choice (re-download / keep partial). **Upload sessions** are
  explicit host-side objects: `{id, member, path, size, hash, offset, expires}`; partials live under a hidden
  staging name (never listed, counted against quota), GC'd at TTL (48 h); an entitlement change mid-transfer aborts
  the session and GCs the partial; the signed manifest is verified **before** the file is moved into place.
- **VFS error model** (post-DTLS, inside the authenticated session — the silent-drop rule applies only pre-auth):
  typed error codes (`not_found`, `quota_exceeded`, `grants_changed`, `resume_expired`, `upload_rejected`,
  `storage_full`, `throttled`) with UI copy per code. Pre-auth failures remain uniform on the wire; the client
  derives honest composite states ("host offline — or your access changed; it will retry"). One narrow exception:
  invite-redemption results are returned inside the verified reply envelope (accepted / expired / already-used).

## A9. UX requirements (the bar the spikes must meet)

| Moment | Requirement |
|--------|-------------|
| Open app | Host list with online/offline/unresponsive ≤ 5 s after clean disconnect, ≤ 60 s after dead socket |
| Click a host | Offline → instant, specific message; online → connected < 2 s LAN, < 5 s WAN (STUN); tree appears immediately |
| Browse | Only what you may see; actions you can't do aren't there (upload targets discoverable) |
| Transfer | Progress, speed, direct/relayed; goals ≥ 50 MB/s LAN native and ≥ 15 MB/s at 50 ms RTT (**S3 sets the v1 numbers**); survives blips; resumes |
| Invite someone | "Invite Alex to Family" → QR/link; Alex redeems; sees Family tree at once; owner sees Alex + devices |
| Share a folder | Add folder → name → choose groups/perms in one grid; "Preview as Alex" |
| New device | Scan QR from the **primary** device (or enter recovery phrase) → every host accepts it; owners notified, no action |
| Lost device | Revoke from the primary device → cut off < 5 s on all hosts even if a host is offline; recovery phrase restores root |
| Host reinstall | Restore host backup → same identity, members unaffected; no backup → clear "new host, re-invite" path |
| Browser | Same flows as native; receive ceiling stated; no client-cert prompts |
| Security events | Key change / signature failure / fingerprint mismatch → clear wall; transfer blocked |
| Received files | Land where granted/quarantined; owner sees sender, size, hash-verified badge; audit viewable |
| Access lost | Revoked/expired member sees an honest state ("host offline — or your access changed"), never an eternal spinner |
| Registry down | Distinct "registry degraded" indicator; existing transfers continue (P2P), new connections queue |

## A9b. Operations & delivery (→ ADR-002/007 appendices, IMPLEMENTATION_PLAN)

**Helper consistency (A10.23)**: single-writer leader over Postgres; replicas serve reads + callout verification;
writes (nonce burns = CAS, revocation epochs = max-wins/never-decrease, session records, admission records, audit
chain, TURN counters) go through the leader; presence deltas published by the leader only; stated staleness bound
for callout views of admission/revocation records (≤ 2 s) verified in S8/S16.

**Secrets inventory** (each: holder · lifetime · rotation · blast radius — full table in ADR-007):
operator admission key (hardware/keychain; pre-committed rotation; availability-only) · release signing key (offline;
web-bundle integrity) · TURN `use-auth-secret` (**dual-secret overlap window** so rotation doesn't kill live
allocations) · NATS server TLS certs (clients trust the private CA root shipped in the invite pin policy) · private
CA (hardened profile + admin certs; short lifetimes in lieu of revocation) · helper DB credentials · host root /
op key / user roots & device keys (covered in A4). **[DEFAULT] lifetimes where not stated elsewhere**: release signing key — offline, pre-committed next-key hash,
rotated only on compromise or planned succession; TURN `use-auth-secret` — rotated monthly via the dual-secret
overlap; NATS server TLS certs — 90-day, auto-renewed; helper DB credentials — 90-day rotation, leader-managed.

**Observability contract**: helper exports callout latency + decision counts, revocation propagation delay,
presence-map size and replica divergence, nonce-burn conflicts, TURN quota consumption; hosts export
failed-envelope-verification rate, rate-limit hits, session/transfer counts, audit-chain head; clients surface
"registry degraded" vs "host offline". S8/S9/S12 SLOs (p99 callout < 250 ms, revoke cut-off < 5 s) become
production alerts, not just spike criteria.

**Delivery**: monorepo — Rust workspace + TS packages (authoritative layout & dependency manifest: **A9c**).
**Wire schemas defined once**:
canonical CBOR schemas live in a schema package with **golden test vectors** consumed by both Rust and TS in CI
(divergence fails the build). CI matrix: 3 OSes; S1/S11/S16/S18 negative suites graduate into permanent CI.
Packaging: macOS notarization + Windows code signing acquired as an explicit pre-implementation task (lead time +
cost); auto-start at login; updater with staged rollout and signed releases. **Compat policy**: helper upgrades
first; every versioned format supports N−1 for one release window; a compat matrix ships with each release.
**Reference deployment**: docker-compose single box (NATS + helper + Postgres + coturn) with sample config = the
demo path and the spike substrate; dev mode runs helper in `open` admission with a local CA. **Support posture**:
in-product messaging at recovery-phrase creation — "no one, including the operator, can recover this for you";
operator abuse-report channel documented; remedy = suspension/eviction (A10.22). **i18n/a11y**: v1 English-only
behind a string table; timestamps stored UTC, displayed local; tray + web target keyboard navigation and
screen-reader basics from the start.

## A9c. Repository layout & toolchain (→ ADR-009)

**The shape in one sentence**: *one wire contract, two engines, one UI layer.* Native apps are **Tauri 2** shells
where a **Rust engine does everything security-relevant** (crypto, keys, NATS, WebRTC, VFS) and the React frontend
is display-only over Tauri IPC; the browser client is a **pure-TS engine** implementing the same wire contract;
the contract itself is defined once and enforced by golden test vectors on both sides (A9b).

**Decisions (A10.25–27, 2026-08-23)**: UI framework = **React** for all three frontends; host = **one Tauri tray
app** (daemon in-process, tray always on, admin window on demand — no localhost admin port); task running =
**`just`** as the single front door over the cargo workspace + pnpm workspace (CI calls the same `just` targets
as local dev).

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

**Boundary rules (enforced, not aspirational)**
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

**Dependency manifest (v1 baseline — spikes may amend with justification in the ADR)**

| Concern | Rust | TypeScript |
|---------|------|------------|
| Runtime | tokio, tracing, thiserror (libs) / anyhow (bins) | Node 22 LTS (CLI/admin), evergreen browsers per A7 |
| NATS | async-nats | nats.ws |
| WebRTC | webrtc ≥0.20 (datachannel-rs = S3 fallback) | browser RTCPeerConnection |
| Crypto | ed25519-dalek 2, x25519-dalek 2, sha2, hkdf, aes-gcm, rand (OsRng), subtle, zeroize | WebCrypto + @noble/curves fallback |
| Encoding | hand-rolled zero-dep canonical codec in spindle-proto (strict non-canonical rejection; minicbor rejected — decoder abstracts the raw bytes) | own canonical encoder in @spindle/proto |
| Storage | rusqlite (bundled) host-side; sqlx/Postgres helper-side | IndexedDB (caps, resume manifests) |
| Confinement | cap-std ≥3.4.1 | — (browser sandbox) |
| OS / shell | keyring, tauri 2 + plugins (tray, autostart, single-instance, updater), qrcode | @tauri-apps/api |
| UI | — | React, Vite, @spindle/ui |
| CLI | — | commander |
| Test/lint | cargo test + clippy + rustfmt; S-suite negatives in CI | vitest, ESLint + Prettier, TS strict |

**Versioning & release**: lockstep versions across the repo in v1 (one release train; the A9b compat matrix is
about *wire* versions, not package versions). `just package` produces: signed/notarized Tauri bundles (host,
client) per A9b, the hardened web bundle + manifest (ADR-008), helper container image, and `spindle-admin` npm
tarball.

**Developer environment (A10.28 → ADR-010)**: hybrid provisioning — **mise** is the native front door on all three
OSes (`mise.toml` pins node/pnpm/`just`/rust; `rust-toolchain.toml` stays authoritative for the exact Rust
channel), with `just bootstrap` wrapping `mise install` plus per-OS native checks (Xcode CLT, MSVC note,
webkit2gtk/pkg-config). One `Dockerfile.toolchain` is consumed by three things: `.devcontainer/`, Linux CI, and
(later) the helper's release image. Containers cover **only the Linux slice** — Tauri bundles, spike S11's
filesystem matrix, `keyring` OS-keystore integration, and spikes S3/S7 all need real native OSes, so devcontainer/
Docker is explicitly not the primary dev environment.

## A10. Decisions

| # | Decision | Status |
|---|----------|--------|
| 1 | Private CA / mTLS | **DECIDED 2026-08-23:** optional hardened profile on TCP listener; not baseline |
| 2 | Account model | **DECIDED 2026-08-23 (supersedes "passkey accounts at registry"):** **no registry accounts**; identity = root key + device chain; members live per host |
| 3 | Key introduction & invite UX | **DECIDED 2026-08-23:** invite-carried keys + pinning + key-change wall (mandatory) |
| 4 | Recovery when all devices lost | **DECIDED 2026-08-23:** root key = recovery phrase shown once; it signs a new device |
| 4b | Host authorization | **DECIDED 2026-08-23:** positive-only union + share exclusions; uploads on opt-in shares; owner-only admin |
| 5 | Max hosts per client connection (CONNECT + JWT size) | **[DEFAULT]** 32 (S12 verifies) |
| 6 | Browser receive ceiling | **[USER DECISION]** FSA API where available; else stated cap (e.g. 2 GB) |
| 7 | Metadata retention at registry | **[USER DECISION]** connection logs 30 days; no payload logging |
| 8 | TURN hosting & cost policy | **[USER DECISION]** self-host coturn; per-device monthly relay quota; S4 → cost/GB |
| 9 | v1 native platforms | **[USER DECISION]** macOS + Windows + Linux; mobile later |
| 10 | `max_control_line` + cap presentation | **[DEFAULT]** 32 KiB; compact CBOR caps; present only this session's hosts; max 32 |
| 11 | Admin surface | **[DEFAULT]** local host UI only in v1; remote admin deferred |
| 12 | Device certification | **[DEFAULT]** root-signed only; root on primary device (OS keystore) + recovery phrase; browsers never primary |
| 13 | Host identity | **[DEFAULT]** host root (backed up) signs operating key; reinstall from backup keeps identity |
| 14 | Helper state | **[DEFAULT]** small replicated store: host-signed revocation/epoch records, connection map, TURN counters, metadata retention; no membership data |
| 15 | NATS account topology | **[DEFAULT]** one application account for all devices + system account for helper; explicit denies on `$SYS.>`, `$JS.>`, `_INBOX.>` |
| 16 | Canonical encoding | **[DEFAULT]** deterministic CBOR (RFC 8949 §4.2.1) for envelopes, caps, VFS RPC; versioned, no downgrade |
| 17 | Host admission default mode | **DECIDED 2026-08-23:** `invite` |
| 18 | Admission mechanisms | **DECIDED 2026-08-23:** invite tokens **and** fingerprint pre-registration |
| 19 | Admin surface | **DECIDED 2026-08-23:** TypeScript library (`@spindle/admin`) owning signing/connection logic; CLI as v1 client; future interfaces build on the library and own their security |
| 20 | Browser client integrity | **DECIDED 2026-08-23:** hardened delivery in v1 — reproducible build, release-key-signed manifest, SRI-pinned immutable bundles, companion verification extension (ADR-008) |
| 21 | LAN without internet | **DECIDED 2026-08-23:** declared v1 non-goal, stated in UI; mDNS local signaling = v2 candidate |
| 22 | Abuse posture | **DECIDED 2026-08-23:** report channel + host suspension/eviction as the remedy; no content inspection exists; documented operator policy + in-product "cannot recover / cannot inspect" messaging |
| 23 | Helper store | **[DEFAULT]** single-writer leader over Postgres; burns = CAS, epochs = max-wins, presence deltas + audit chain leader-only |
| 24 | License & repo | **[USER DECISION]** license TBD; monorepo (Rust workspace + TS packages) per A9c |
| 25 | UI framework | **DECIDED 2026-08-23:** React for all three frontends (Tauri client, host admin UI, web), shared via `@spindle/ui` |
| 26 | Host app shape | **DECIDED 2026-08-23:** one Tauri 2 tray app — daemon in-process, admin window on demand, IPC-only admin surface (no localhost port); headless/NAS mode deferred |
| 27 | Monorepo tooling | **DECIDED 2026-08-23:** cargo workspace + pnpm workspaces with a top-level `justfile` as the single build/test/dev entry point; CI runs the same `just` targets |
| 28 | Developer environment | **DECIDED 2026-08-23:** hybrid — mise (`mise.toml`) as the native front door on all 3 OSes; single `Dockerfile.toolchain` consumed by devcontainer, Linux CI, and the helper image; devcontainer = Linux slice only; `just bootstrap` wrapper (ADR-010) |
| 29 | S3 throughput shortfall | **DECIDED 2026-08-23:** investigate deeper first — browser-peer (dcSCTP) measurement + webrtc-rs cwnd profiling before revising the A9 WAN bar or reopening the transport choice; Stages 2–4 proceed; parallel associations (~7.7 MB/s @ N=8) recorded as the current mitigation ceiling |

## A11. Alternatives considered

| Alternative | Verdict | Why |
|-------------|---------|-----|
| Custom WebSocket relay | Rejected | NATS gives routing, req/reply, reconnect, permissions |
| NATS static `verify_and_map` (ADR-002 as written) | Rejected | No scale, per-host scoping, revocation, or browser |
| Registry-held user accounts (passkeys) + key directory (v0.2–0.4) | **Rejected (user)** | Registry must only broker connections; accounts per host; removes IdP/key-dir from trust surface |
| Per-device members, no chain | Rejected | Poor multi-device UX; re-invite everywhere on recovery |
| Deny rules in entitlements | Deferred | Predictability; exclusions on shares cover the common case |
| Host-local passwords for members | Rejected | Breaks E2E key model and one-identity-many-hosts UX |
| iroh / QUIC instead of WebRTC | Rejected for v1 | Browser client required |
| JetStream (durability / KV presence) | Rejected for v1 | Not needed; KV perms break scoping |
| WASM Rust core for browser crypto | Rejected | WebCrypto + `@noble/curves` suffices |
| String-sanitization path confinement | Rejected | `cap-std` capability confinement by construction (+ Spindle-side folding/identity checks) |
| Device-signs-device chains | Rejected (v0.6) | Unbounded compromise amplifier; root-only certification |
| P-256 fallback suite | Rejected (v0.6) | All target browsers ship Ed25519/X25519; second suite = downgrade surface |
| N data channels for throughput | Rejected (v0.6) | One SCTP association; no gain |
| Stateless helper with cached epochs | Rejected (v0.6) | Fail-open on restart; durable host-signed records instead |
| Web admin panel with login sessions (v1) | Rejected (v0.7) | Largest attack surface on the most sensitive service; signed-command verifier instead |
| Ungated host registration | Rejected (v0.7) | Sybil hosts / TURN abuse; admission modes (A3b) |
| Operator-served web bundle (plain) | Rejected (v0.8) | Operator could ship key-leaking JS; hardened delivery (A10.20) |
| Server-side archive generation for folder download | Rejected (v0.8) | Memory/CPU on hosts, resume complexity; client-side queue instead |
| Host-wide single epoch | Rejected (v0.8) | Conflated security + cache invalidation; cap_epoch / grants_version split |

## A12. Red-team traceability

| # | Attack (adversary) | Closed by |
|---|--------------------|-----------|
| 1 | Broker MITMs DTLS via SDP tamper (A2) | A7 signature + fingerprint check |
| 2 | Read/spoof others' replies via `_INBOX.>` (A1) | A5 private inbox; A7 encryption |
| 3 | Browser can't use client certs; token theft (A4) | A4 two-key split; `allowed_connection_types` |
| 4 | Flood/enumerate hosts (A1/A5) | A5 cap-scoped perms; no-cap connections refused; host pre-crypto checks + rate limits |
| 5 | Stolen device stays valid (A3) | A4 short JWTs; revocation + kick relay; pinned-key removal; self-revocation by root |
| 6 | Host-ID squat/fan-out eavesdrop (A1) | A5 `host_fp` from key; no wildcard subs |
| 7 | Metadata at broker (A2) | Accepted; A10.7 |
| 8 | TURN denial-of-wallet (A5) | A8 quota per `device_fp` |
| 9 | `allow_responses` confused deputy (A1) | A5 reply-prefix validation |
| 10 | Cross-client session eavesdrop/inject (A1) | A5 `sess.<cfp>.<sid>` |
| 11 | Registry substitutes keys (A2) | A4 invite-carried keys, pinning |
| 12 | Registry adds a device to a person (A2) | A4 device chain rooted at the person's root key; registry has no directory at all |
| 13 | Registry grants itself access / stale perms (A2/A1) | A4 self-verifying host-signed caps; **host per-request enforcement is authoritative**; helper revocation store + kick as defense in depth |
| 14 | Host DoS by approved peer (A1/A5) | A5 pre-crypto checks, token bucket, concurrency cap |
| 15 | No forward secrecy (A2/A3) | A7 ephemeral-static hybrid |
| 16 | Envelope splicing/replay/downgrade | A7 MUST-checks |
| 17 | Local IP disclosure to peers (A1) | A6 relay option |
| 18 | Hostile received files / path traversal (A1) | A8 received-file policy |
| 19 | **VFS escape: `..`, symlinks, absolute paths (A1)** | A4b `cap-std` confinement |
| 20 | **Exclusion/permission bypass via case or Unicode variants (A1)** | A4b matching on canonicalized real path |
| 21 | **Existence leak of non-browsable paths (A1)** | A4b/A8 not-found semantics, filtered listings |
| 22 | **Stale grants in live sessions after revocation (A1)** | A4b per-request checks (authoritative), epoch invalidation |
| 23 | **Upload outside granted subpath / overwrite (A1)** | A4b upload scoping, `delete` required to overwrite, quotas |
| 24 | **Sybil device keys flooding NATS (A5)** | A4 no-cap connections refused; per-IP limits in front of NATS; cheap pre-checks in callout |
| 25 | Compromised secondary device mints devices (A3) | A4 root-only device certs |
| 26 | Root key compromise (A3) | A4 pre-committed root rotation; owner out-of-band root revoke |
| 27 | Revocation while host offline (A3) | A4 root-signed revocation deposited at helper; host checks on contact (S14) |
| 28 | TURN quota bypass via fresh device keys (A5) | A8 quota per `root_fp` |
| 29 | Overlapping share roots / hardlinks defeat exclusions (A1) | A4b overlap rejection by path+identity; nlink rule |
| 30 | TOCTOU/rename inside share (A1) | A4b per-request re-resolve + identity checks |
| 31 | Case/NFD upload collision overwrites without `delete` (A1) | A4b collision == overwrite rule |
| 32 | Member enumeration via presence / `whoami` / timing (A1) | A5 minimal presence payload; trimmed `whoami`; uniform drops |
| 33 | Invite link leak (A1) | A4 host-side nonce burn, hours-scale exp, per-nonce rate limit |
| 34 | Membership graph visible to registry (A2) | Accepted & stated (A2); present-only-needed caps; per-session nkeys |
| 35 | Host key loss → wall for every member (availability) | A4 host root + operating key; backup |
| 36 | Stolen operator admission key (A7) | A3b blast-radius design (availability only); hardware-token Signer; pre-committed rotation; audit log |
| 37 | Admission invite token leak (A5) | A3b single-use nonce burn at helper; days-scale exp; quota profile |
| 38 | Evicted host resurrection / mode-downgrade (A2/A7) | A3b admission records durable; mode changes are signed + logged commands |
| 39 | Rogue admitted hosts at scale (A5) | A3b `invite` default mode; quotas in `open` mode |
| 40 | Operator ships malicious web-client JS (A2) | A2/ADR-008 hardened delivery: signed manifest, SRI, verification extension |
| 41 | Cross-artifact signature confusion (A1/A2) | A7b distinct domain tags per artifact type |
| 42 | Revocation rollback via replayed old record / restored backup (A1/A3) | A7b max-wins epochs; host fetches epoch high-water from helper at startup |
| 43 | Cross-host forgery/flood on shared revoke subject (A1) | A5 `registry.revoke.<hfp>` scoping + per-host bucket |
| 44 | Admin command replay / race / audit fork (A7) | A7b per-signer seq + idempotence; single-writer audit chain (A14) |

## A13. Spikes (evidence before code) — ordered by risk

| Spike | Question | Pass criterion |
|-------|----------|----------------|
| **S3** | DataChannel throughput at 0/20/50/100 ms RTT; SCTP tuning | ≥ 50 MB/s LAN; ≥ 15 MB/s @ 50 ms; knobs documented |
| **S7** | Browser large-file sink; tab throttling; sleep/resume | 5 GB receive in Chromium; fallback ceiling measured; resume works |
| S1 | Callout verifying self-signed caps; per-device inbox; scoped perms; no-cap refusal | Automated negative tests: other inbox unreadable; un-capped host unreachable; other client's session unreachable; reply-prefix bypass rejected; fresh key with no cap refused |
| **S11** | VFS confinement (`cap-std`): `..`, symlink escape, hardlinks, overlapping roots, case/Unicode collisions, exclusion bypass, upload scoping, Windows device names / 8.3 / ADS / `\\?\` paths, rename races | Automated negative tests all pass on macOS/Windows/Linux |
| S2 | webrtc-rs ↔ browser trickle ICE over NATS | Median connect < 2 s LAN, < 5 s across NATs |
| S8 | Helper HA; 5k clients re-auth in a minute | No failed auths; p99 callout < 250 ms |
| S4 | NAT traversal with/without coturn; cost model | Relay %; **cost/GB** |
| S5 | Presence via `$SYS` events; ping tuning | ≤ 5 s clean / ≤ 60 s dead |
| S6 | Browser crypto + alg_id interop | Envelope round-trip Rust↔browser, 3 browsers |
| S9 | Revoke → kick → host rejects | < 5 s end to end |
| S10 | Invite/redeem + "Preview as" + permission grid with a non-technical tester | Completes unaided; can explain why a member sees what they see |
| S12 | CONNECT size: 32 caps + device cert under `max_control_line` 32 KiB; callout cost at 5k connects/min | Fits; p99 callout < 250 ms; per-IP limiter blocks flood |
| S13 | Host operating-key rotation / reinstall from backup | Members see no wall; sessions resume |
| S14 | Revoke a device while its host is offline | Callout refuses before host comes back; host rejects on return |
| S15 | Recovery-phrase + primary-device comprehension with the S10 tester | Backs up phrase; adds a second device; recovers on a fresh device unaided |
| S16 | Control plane: admit (token + pre-reg), evict, mode switch; negative tests (reused token, forged command, evicted host reconnect, admin without mTLS) | All negative tests fail closed; admit→first-connect < 10 s |
| S17 | Hardened web delivery: reproducible build → signed manifest → verification extension detects a tampered bundle | Tampered bundle flagged in all 3 browsers; honest bundle passes |
| S18 | Cap lifecycle: expiry while offline → connect-only → E2E re-issue; device bootstrap QR state bundle; refetch on second device | No lockout in any path; second device reaches all hosts unaided |

---

# Part B — Execution plan (after approval)

| Stage | Output | Source |
|-------|--------|--------|
| 1 | `docs/DESIGN.md` | Part A (kept in sync) |
| 2 | `docs/adr/ADR-001-threat-model.md` | A1–A2, A12 |
| 3 | `docs/adr/ADR-002-nats-signaling.md` (revised; Proposed) | A3, A5, A6, A11 |
| 4 | `docs/adr/ADR-003-identity-capabilities-enrollment.md` | A4, A10.1–5 |
| 5 | `docs/adr/ADR-004-e2e-signaling-envelope.md` | A7 |
| 6 | `docs/adr/ADR-005-transport-vfs-rpc-file-safety.md` | A8, A10.6–8 |
| 7 | `docs/adr/ADR-006-host-authorization-members-shares-entitlements.md` | A4b |
| 8 | `docs/adr/ADR-007-registry-control-plane.md` | A3b, A10.17–19, A9b (ops/secrets) |
| 9 | `docs/adr/ADR-008-browser-client-delivery.md` | A2, A10.20 |
| 10 | `docs/adr/ADR-009-repo-layout-toolchain.md` (incl. the enumerated Tauri IPC command list) | A9c, A10.25–27 |
| 11 | `docs/SPIKES.md` + skeletons (`spikes/s3-throughput` first, then `s11-vfs-confinement`) | A13 |
| 12 | `IMPLEMENTATION_PLAN.md` (per global CLAUDE.md) + repo scaffold per A9c | — |
| 13 | `docs/adr/ADR-010-dev-environment-toolchain.md` + mise.toml, Dockerfile.toolchain, .devcontainer/, `just bootstrap`, CI provisioning | A9c, A10.28 |

**Verification**: each ADR cites ADR-001 for every security claim; A12 reproduced in ADR-001; S1 and S11 negative
tests automated; user reviews each ADR before the next; S3 before any transport ADR is Accepted.

---

# Part C — Opus review disposition (v0.2 → v0.3) — see Part D for what v0.5 changed on top

| Finding | Disposition |
|---------|-------------|
| XChaCha20 not in WebCrypto | Accepted → AES-256-GCM, deterministic nonces (A7) |
| Non-extractable key overstated | Accepted → wording fixed (A4) |
| nats.ws nkey needs seed | Accepted → two-key split (A4) |
| Ed25519 availability; `@noble/curves` not WASM; alg id | Accepted (A7, A11) |
| `device_fp` ambiguous | Accepted → explicit derivation (A4) |
| S3 must test RTT; datachannel-rs alternative | Accepted (A8, A13) |
| KV presence problems | Accepted → dropped; `$SYS` events (A6) |
| 10 s vs 20 s inconsistency | Accepted (A9) |
| JWT expiry stampede | Accepted → jittered exp (A4), S8 |
| "Minimal infra" dishonest; SPOF | Accepted → reworded; HA + S8 |
| `allow_responses` confused deputy | Accepted (kept with prefix validation) (A5) |
| Session wildcards leak | Accepted → `sess.<cfp>.<sid>` (A5) |
| Key-directory substitution | Accepted by user → invite-carried keys; in v0.5 the directory no longer exists |
| Directory adds device | Accepted → device chain rooted at person's root key |
| Approvals drift | Accepted → self-verifying caps + epoch + kick |
| Host DoS | Accepted (A5) |
| Browser token from native | Accepted → `allowed_connection_types` |
| TURN quota bypass | Accepted (A8) |
| No forward secrecy | Accepted (A7) |
| Missing MUST-checks / canonical encoding | Accepted (A7) |
| Local IP disclosure | Accepted (A6) |
| Received-file safety | Accepted (A8, A4b) |
| Browser large-file / throttling | Accepted → S7 |
| Relay economics | Accepted → S4 cost/GB |
| Drop private CA/mTLS | Accepted by user → optional profile |
| Drop KV, WASM; replace allow_responses; approvals mirror → capabilities | Accepted (allow_responses retained with validation; mirror removed entirely in v0.5) |

# Part C2 — Opus review disposition (v0.5 → v0.6)

| Finding | Disposition |
|---------|-------------|
| CONNECT size (4 KiB default control line; 64 caps impossible) | Accepted → A4 presentation, A10.10, max 32, S12 |
| No retained messages in core NATS (presence/epoch) | Accepted → helper request/reply + deltas (A5, A6) |
| Host self-certification incoherent | Accepted → host root + operating key cert (A4) |
| Callout epoch check fail-open / needs state | Accepted → demoted to best-effort; host authoritative; durable host-signed records (A4, A12 #13/#22) |
| Kick needs (server, cid) map | Accepted → helper connection map (A3) |
| No per-IP limits in NATS; callout is DoS surface | Accepted → per-IP limits in front; cheap pre-checks (A3, A12 #24) |
| Invite bearer / single-use needs host state | Accepted → host nonce burn, hours exp, per-nonce limit (A4, A12 #33) |
| cap-std doesn't canonicalize; Windows cases | Accepted → A4b wording, S11 expanded |
| N data channels don't add throughput | Accepted → one data channel (A8) |
| Registry sees membership graph | Accepted → honest A1/A2 wording; present-only-needed; per-session nkeys (A12 #34); per-host pseudonymous subjects deferred |
| Device-signs-device amplifier | Accepted → root-only certs; root on primary device (A4, A10.12) |
| Root compromise / rotation | Accepted → pre-committed rotation (A4, A12 #26) |
| Revocation with host offline | Accepted → helper durable revocation store (A4, S14) |
| TURN quota per device_fp bypass | Accepted → per root_fp (A8) |
| Overlapping roots / hardlinks / TOCTOU / case-NFD collisions | Accepted (A4b, A12 #29–31, S11) |
| Algebra edge cases | Accepted → edge rules (A4b) |
| `whoami` / presence / timing leaks | Accepted (A4b, A5, A12 #32) |
| Audit log tamper; archive expansion; resource limits | Accepted (A4b) |
| Recovery-phrase UX | Accepted → primary-device keystore + phrase + per-host re-invite fallback (A4, S15) |
| Host key loss/reinstall undesigned | Accepted → host identity root (A4, A10.13, S13) |
| Browser never root holder; admin surface | Accepted (A4, A10.11) |
| A9 throughput as goals | Accepted (A9) |
| Drop P-256; trim whoami; stop calling helper stateless | Accepted |
| Missing decisions | Folded into A10.10–16, A7 (clock skew, canonical CBOR), A8 (RPC versioning) |

# Part C3 — Dual gap-hunt disposition (v0.7 → v0.8)

Opus (protocol/state/security-lifecycle) and Fable (product/ops/delivery) gap-hunts: 32 findings, 27 distinct.
All accepted and integrated except where noted. Highlights: cap lifecycle + device bootstrap (both agents' #1) →
A4 + S18; signed-artifact profile → A7b; helper consistency + secrets + observability + delivery → A9b; transfer
manager + VFS error model → A8; duplicate-connection semantics → A6; `registry.revoke.<hfp>` scoping → A5;
hardened web delivery → A2/ADR-008/S17 (user decision); LAN non-goal + abuse posture (user decisions) → A1/A10.
Deferred: mDNS local signaling (v2); member-level operator remedies (would break ZK); license choice (A10.24 open).

# Part D — Change log

- **v0.9.4 (2026-08-24)** — Stage 3 (spindle-core) clarifications: Capability has no `nbf` (schema-of-record wins;
  A7b row amended); root-rotation record is crate-local in v1, promotion to a proto wire artifact flagged for when
  it first crosses the wire. Stage 3 Rust half + real-signature vectors (vectors/signed/) landed.
- **v0.9.3 (2026-08-24)** — S3 follow-up recorded (TCP baseline exonerates the environment; parallel-association
  ceiling; A10.29 investigate-deeper decision). Stage 2: spindle-proto schema-of-record (zero-dep canonical CBOR —
  A9c manifest amended), device-cert label + version-field clarifications.
- **v0.9.2 (2026-08-23)** — Developer environment decided (A10.28 → ADR-010): hybrid mise front door + single
  toolchain image (devcontainer / Linux CI / helper image), containers scoped to the Linux slice; Part B stage 13.
- **v0.9.1 (2026-08-23)** — Post-ADR-writing reconciliation: A10.24 added to the front-matter open list; helper
  NATS account bridging made explicit (two connections, A5 [DEFAULT], finalize in S1); [DEFAULT] lifetimes for the
  four secrets A9b left unspecified. Found by the ADR-writing agents; ADR-002/ADR-007 already reflect the gaps.
- **v0.9 (2026-08-23)** — Repository layout & toolchain codified (A9c → ADR-009): one-wire-contract/two-engines/
  one-UI-layer shape; crate + package tree; boundary rules (key custody in Rust or non-extractable WebCrypto,
  engine-api substitution, crate layering, minimal Tauri capabilities); dependency manifest; lockstep versioning.
  User decisions A10.25 (React), A10.26 (host = single Tauri tray app), A10.27 (`just` + pnpm + cargo).
- **v0.8 (2026-08-23)** — Dual gap-hunt integrated (Part C3): cap_epoch/grants_version split, no-lockout cap
  renewal, device bootstrap state bundle, idempotent redemptions, A7b signed-artifact profile, helper consistency
  model, session records, one-to-many kick/presence, split-brain policy, transfer manager + VFS error taxonomy,
  owner live-ops, A9b operations & delivery, hardened browser delivery (ADR-008), LAN non-goal, abuse posture,
  registry endpoint in invites, A12 #40–44, S17–S18, A10.20–24.
- **v0.7 (2026-08-23)** — Registry control plane (A3b): host admission modes (`invite` default), admission via
  single-use operator tokens + fingerprint pre-registration, operator admission key with availability-only blast
  radius, signed-command admin plane with TypeScript library `@spindle/admin` + CLI (user decisions A10.17–19),
  adversary A7, A12 #36–39, S16, ADR-007.
- **v0.6 (2026-08-23)** — Second Opus review integrated (Part C2). CONNECT-size-aware cap presentation; helper is
  small/replicated with durable host-signed revocation records (not stateless); host root + operating key; root-only
  device certs with root on primary device; root rotation; honest ZK wording on membership metadata; VFS hardening
  (overlap, hardlinks, TOCTOU, case/NFD, edge rules, limits, tamper-evident audit); one data channel; no P-256;
  A10.10–16 defaults; A12 #25–35; S12–S15.

- **v0.5 (2026-08-23)** — User: "accounts live only on each server; the registry only facilitates connections."
  Removed registry accounts/IdP/key directory; broker helper is a pure capability verifier; identity = root key +
  device chain (A4); caps self-verifying; invite = bootstrap cap; kick relay. Added A4b host authorization (members,
  shares, entitlements; positive-only union; uploads opt-in; owner-only admin), VFS RPC (A8), ADR-006, S11, A12
  #19–24. A10.2 superseded. Opus finding "key directory substitution" now moot by construction.
- **v0.4** — decisions A10.1–4 confirmed.
- **v0.3** — Opus review integrated (Part C).
- **v0.2** — first codified design after review + red-team.
