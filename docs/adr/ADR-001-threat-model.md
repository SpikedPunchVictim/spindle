# ADR-001: Threat Model

## Status

Accepted

## Context

Spindle lets a person run a *host* (a Rust daemon with a system tray) on their own machine, expose chosen files and
directories through a virtual file system, and let approved people browse, download, and upload according to group
entitlements — from a native app or a browser — peer-to-peer. A small operator-run *registry* (NATS cluster + broker
helper) exists only to broker connections between clients and hosts.

This ADR is the single source of truth for what Spindle defends against, what it deliberately does not defend
against, and how "zero-knowledge" is defined for this system. Every other ADR must cite a specific row of the A12
red-team traceability table (reproduced in the Appendix below) for each security claim it makes.

**Goals** (from DESIGN.md §A1):

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

**Non-goals (v1)** (from DESIGN.md §A1):

- Hiding *metadata* (which device connected to which host, when, from which IP) from the registry operator.
- Protecting a member from a malicious *host owner* they chose to join, or anyone from a compromised endpoint/OS.
- Federation / multiple registries; delegated host administration (owner-only in v1).
- **LAN-only operation** (decided A10.21): two devices without internet cannot connect in v1 — signaling requires the
  registry; the transfer itself is direct. The UI says so plainly; mDNS-assisted local signaling is a tracked v2
  candidate.

## Decision

Adopt the following threat model as the authoritative definition of Spindle's security posture.

### Assets

(1) file contents in transit (confidentiality + integrity); (2) identity (no impersonation of a person or device);
(3) host availability and non-exposure to unauthorized parties; (4) session-setup integrity (keys, SDP/ICE, DTLS
fingerprint); (5) the host owner's filesystem — confinement to what was deliberately shared, and safety of what is
received.

### Adversaries

| ID | Adversary | Starts with | Wants |
|----|-----------|-------------|-------|
| A1 | Malicious *authenticated* device/member | A valid device key; membership on some hosts | Reach hosts/paths they weren't granted; escape the VFS; eavesdrop/hijack/inject into others' sessions; enumerate/flood hosts; plant hostile files |
| A2 | Compromised or malicious registry (NATS node, broker-helper service, or operator) | Full view of broker traffic & config; can mint NATS permissions | MITM session setup by substituting keys/SDP; impersonate; grant itself access |
| A3 | Device/credential thief | A user's laptop/phone, or extracted keys/tokens | Act as that device/person until revoked |
| A4 | Browser-side attacker (XSS, malicious extension) | Code execution in the web client page | Use/steal device key or NATS token; exfiltrate files mid-transfer |
| A5 | Resource abuser | Any number of freshly generated device keys | Flood NATS/hosts; run up TURN bills |
| A6 | Passive/active network attacker | On-path | Read/alter traffic (defeated by TLS/DTLS) |
| A7 | Thief of the **operator admission key** | The registry control plane | Admit rogue hosts; evict real hosts (availability). **Cannot** impersonate existing hosts or reach any member's files — admission ≠ identity (A3b) |

### Definition of "zero-knowledge" for Spindle

*The registry can route messages and observe connection metadata, but (a) cannot read file contents, (b) cannot read
signaling payloads, (c) cannot alter session setup — including which public keys peers trust — without detection, and
(d) holds no account, member, group, or share data; the only membership signal it has is connection metadata (device
↔ host capability presentation).* (c) follows from keys being introduced only via **invites** and **root-signed device
certificates** (ADR-003) plus E2E-authenticated signaling (ADR-004); (d) follows from the registry verifying
host-signed capabilities it does not issue (ADR-003). Mitigations for the metadata in (d): present only the caps
needed this session; rotate the NATS connect key per session.

### Trust boundaries

- **Device ↔ registry**: TLS; authorization via host-signed capabilities.
- **Device ↔ host**: pinned identity roots + E2E envelope + DTLS.
- **Host ↔ its own filesystem**: capability-confined share roots (ADR-003 §A4b, ADR-006).

The registry operator is **untrusted for payloads, keys, and membership**, and **trusted for availability and
metadata retention** (see A10.7 in ADR-003's open items).

**Browser client code**: the web bundle would otherwise be served by the operator — the party this model distrusts —
so v1 uses **hardened delivery** (decided A10.20): reproducible builds, a release-key-signed manifest (release key ≠
operator key), immutable versioned bundles with SRI pinning, and a companion **verification extension** (Code-Verify
pattern) that checks the served bundle against the published manifest. Residual risk, stated: a browser session
without the extension trusts the operator for code integrity on first load; native apps never do.

### Explicitly out of scope

Malicious host owner, endpoint compromise, supply chain of daemon/web bundle (tracked separately), legal compulsion
of connection metadata.

## Consequences

### Positive

- A single, explicit adversary table (A1–A7) gives every other ADR a stable vocabulary for security claims, and the
  A12 traceability table (Appendix) gives every claim a numbered citation target.
- The zero-knowledge definition is falsifiable (four explicit clauses), not a marketing phrase — each clause maps to
  a concrete mechanism owned by another ADR (invite-carried keys, E2E envelope, self-verifying capabilities).
- Declaring metadata visibility, malicious-host-owner protection, and LAN-only operation as non-goals up front
  prevents scope creep into problems Spindle does not solve, and lets the UI state honest limits instead of implying
  guarantees that don't hold.

### Negative

- The registry operator retains a permanent, accepted view of connection metadata (who connects to whom, when, from
  which IP) — this is a real privacy limitation for any deployment where that graph itself is sensitive (A12 #7, #34).
- A member has no protection from a host owner they chose to join, nor from their own compromised endpoint — Spindle
  cannot help users who trust the wrong host or run compromised software.
- No federation and no LAN-only fallback in v1 means total dependence on the operator-run registry for connection
  setup, even between two devices on the same network segment (A10.21).

### Neutral

- The threat model explicitly separates *identity theft* (A3, mitigated by revocation and short-lived credentials)
  from *permanent compromise* (root key loss, mitigated by pre-committed rotation and recovery phrases) — later ADRs
  must preserve this distinction rather than collapsing it.
- The operator admission key (A7) is scoped to an *availability-only* blast radius by construction (admission ≠
  identity); this is a design constraint each future control-plane change must preserve, not merely an incidental
  property of the current implementation.

## Alternatives Considered

| Considered | Verdict | Why |
|------------|---------|-----|
| Hide connection metadata from the registry operator | Rejected for v1 (non-goal) | Would require onion-routing-class infrastructure disproportionate to the threat; explicitly accepted and stated instead (A12 #7, #34) |
| Protect members from a malicious host owner they joined | Rejected (non-goal) | A member's trust decision to join a host is out of Spindle's control; no technical control substitutes for that judgment |
| Federation / multiple registries in v1 | Deferred | Adds cross-registry trust and routing complexity with no v1 requirement driving it |
| Delegated host administration in v1 | Deferred (owner-only in v1) | Smaller attack surface; no remote admin surface at all (A10.11) |
| LAN-only operation without the registry | Deferred to v2 (mDNS-assisted local signaling candidate) | Signaling still requires the registry in v1; the transfer itself is already direct/P2P |

## References

- `../DESIGN.md` §A1 (Goals and non-goals), §A2 (Threat model), §A12 (Red-team traceability)
- ADR-002 (NATS signaling — closes many A1/A2/A5 rows via subject scoping and Auth Callout)
- ADR-003 (Identity, capabilities, enrollment — closes most impersonation/revocation rows)
- ADR-004 (E2E signaling envelope — closes MITM/replay/forward-secrecy rows)
- ADR-005 (Transport, VFS RPC, file safety — closes received-file and transport rows)
- ADR-006 (Host authorization: members, shares, entitlements — closes VFS confinement/permission rows)
- ADR-007 (Registry control plane — closes host-admission rows A12 #36–39)
- ADR-008 (Browser client delivery — closes A12 #40)
- `docs/SPIKES.md`: S1, S9, S11, S12, S14, S16, S17 (negative-test verification of the rows below)

## Appendix: A12 Red-team traceability (verbatim, all 44 rows)

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
