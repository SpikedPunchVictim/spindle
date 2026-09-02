# DRAFT — A5b. Subject registry (canonical) + A10.37 HostDeviceCert residency

> **Status: DRAFT, not yet merged into `docs/DESIGN.md`.** Drafted 2026-09-01 for review. On approval this becomes
> section **A5b**, inserted after A5, plus one new row in the A10 decisions table. Requires a version bump, a Part D
> change-log entry, and a matching update to the mirror at `~/.claude/plans/piped-launching-pony.md` so the two stay
> byte-identical — verify with a WORD-LEVEL diff, not by eye.

## Why this section exists

Subject information is currently spread across A5's subject table, A5's permission bullets, A5's "Helper account
bridging" prose, ADR-002, and the spike results — and the `$SYS.*` subjects the helper depends on appear in **none**
of the tables, only in prose. Building this list against the actual source found four divergences between DESIGN and
the implementation (marked ⚠️ below). This section is the single canonical list; where it disagrees with prose
elsewhere in the document, this section is authoritative.

**Status column**: ✅ implemented and exercised · ❌ specified but not implemented · ⚠️ implemented but DESIGN
describes it incorrectly.

## Application plane (APP account)

| Subject | Publisher | Subscriber | Purpose | Status |
|---------|-----------|------------|---------|--------|
| `host.<hfp>.connect` | devices holding a cap for `hfp` | host `hfp` | request/reply; A7 envelope carrying the client's inbox, bound to the reply subject (A10.36) | ✅ |
| `host.<hfp>.sess.<cfp>.<sid>.c2h` | client `cfp` only | host `hfp` | trickle ICE + session control, client→host | ✅ |
| `host.<hfp>.sess.<cfp>.<sid>.h2c` | host `hfp` | client `cfp` only | trickle ICE + session control, host→client | ✅ |
| `host.<hfp>.presence` | broker helper | devices holding a cap for `hfp` | push deltas `{host_fp, state, last_seen}` only | ✅ |
| `host.<hfp>.revoke-resync` | broker helper | host `hfp` | asks the host to republish its full revoked set; no reply | ❌ proposed in the A4c draft |
| `_INBOX_<dfp>.>` | host, via `allow_responses` after a prefix check | owning device `dfp` | private reply inbox prefix | ✅ |

## Helper request/reply (APP account)

Every subject here is parametrized by the caller's **session nkey** `<nfp>`. Caller identity is always the
callout-granted subject token, never anything in the payload — the helper authorizes from the session record keyed by
that `nfp`.

| Subject | Publisher | Subscriber | Purpose | Status |
|---------|-----------|------------|---------|--------|
| `helper.presence.get.<nfp>` | device whose session nkey is `nfp` | broker helper | request/reply presence snapshot for the caller's hosts | ✅ |
| `helper.turn.get.<nfp>` | device whose session nkey is `nfp` | broker helper | request/reply TURN credentials; per-root monthly quota | ✅ |
| `helper.devcert.get.<nfp>` | device whose session nkey is `nfp` | broker helper | request/reply fetch of a host device certificate; payload names the target `host_fp`, served only if that host is in the caller's session record, so it cannot enumerate hosts the caller holds no cap for | ❌ no handler exists |
| `helper.revoke.<nfp>` | device whose session nkey is `nfp` | broker helper | request/reply deposit of a **root-signed** `spindle-self-rev-v1` self-revocation (S14); accepted only if the signer is the `root_fp` in the caller's session record | ❌ no handler exists |

## Registry ingest (APP account)

| Subject | Publisher | Subscriber | Purpose | Status |
|---------|-----------|------------|---------|--------|
| `registry.revoke.<hfp>` | host `hfp` only | broker helper | host-signed revocation/epoch records; durable; helper asserts subject token == record `host_fp`; per-host token bucket | ✅ |
| `registry.devcert.<hfp>` | host `hfp` only | broker helper | host-signed device certificate; durable; republished on **every** host connect (A10.37); helper asserts subject token == the cert's `host_fp`; per-host token bucket | ❌ no handler exists |
| `registry.admin.>` | operator (mTLS + operator cert) | broker helper | signed admin commands (A3b); replies via `allow_responses` | ❌ no handler exists |

## System plane (`$SYS`) — absent from A5's tables until now

These are the subjects the broker helper uses against nats-server itself. They were previously documented only in
prose and in the spike results, which is how the CONNZ divergence below went unnoticed.

| Subject | Publisher | Subscriber | Purpose | Status |
|---------|-----------|------------|---------|--------|
| `$SYS.REQ.USER.AUTH` | nats-server | helper **callout** connection (AUTH account) | the auth callout request/reply — every connection in the system is authorized here | ✅ |
| `$SYS.REQ.SERVER.PING.CONNZ` | helper **SYS** connection | nats-server | connection listing; seeds both the presence map and the kick map at startup, and backs the on-demand kick fallback | ⚠️ see below |
| `$SYS.REQ.SERVER.<server_id>.KICK` | helper **SYS** connection | nats-server | disconnects one client; payload field is **`cid`**, not `id`; there is **no** `PING.KICK` broadcast form, so a concrete `server_id` is always required; **a reply is not proof of a kick** — a failed kick still replies, with an `error` key | ✅ |
| `$SYS.ACCOUNT.*.CONNECT` | nats-server | helper **SYS** connection | connection advisory; feeds the presence map and the kick map | ✅ |
| `$SYS.ACCOUNT.*.DISCONNECT` | nats-server | helper **SYS** connection | disconnect advisory; feeds presence, the kick map, and the session-record cleanup | ✅ |
| `$SYS.>` | — | — | explicitly **denied** to every client and host connection by the callout | ✅ |

**⚠️ CONNZ connection divergence.** A5's "Helper account bridging" paragraph states that the **callout** connection
makes the startup `$SYS.REQ.SERVER.PING.CONNZ` request. The implementation issues it on the **SYS** connection
(`connz_request(sys_client)`; `seed_maps(sys_ref, …)`). Both work — nats-server special-cases
`$SYS.REQ.USER.AUTH` and `$SYS.REQ.SERVER.PING.CONNZ` to answer across accounts — so this is a documentation error,
not a defect. DESIGN should be corrected to match the code.

## Known DESIGN divergences this list exposes

1. **⚠️ A5:416 grants a bare `pub registry.revoke`** with no `.<hfp>` suffix, contradicting the subject table nine
   lines above it. The implementation correctly grants `registry.revoke.<own_host_fp>`. Tracked as **td-40a2d0**.
2. **⚠️ A5:416 omits `registry.devcert` entirely** from the host permission bullet, although the subject table names
   hosts as its publisher. Also tracked as **td-40a2d0**.
3. **⚠️ CONNZ is issued on the SYS connection**, not the callout connection A5 describes (above).
4. **❌ Four specified subjects have no implementation**: `helper.devcert.get.<nfp>`, `registry.devcert.<hfp>`,
   `registry.admin.>`, and `helper.revoke.<nfp>`. The first two are addressed by A10.37 below; `helper.revoke.<nfp>`
   is S14, tracked as **td-b5d50c**; `registry.admin.>` is the A3b admin plane and needs its own task.

## A10.37 — Where the `HostDeviceCert` lives

**DECIDED 2026-09-01: one authority, two caches.** The certificate is minted and owned by the host, cached durably at
the registry for distribution, and pinned by the client.

- **Authoritative — the host.** The host mints the cert (its **operating** key signs it, per A10.35) and persists it
  in its own store. The host is its only writer.
- **Distribution cache — the broker helper.** The host publishes on `registry.devcert.<hfp>` **on every connect to
  the registry** (see Open items); the helper stores it durably and serves it on demand via
  `helper.devcert.get.<nfp>`. The helper is an **untrusted carrier by construction**: A10.34 requires the cert to
  reach the peer over a self-verifying root→op→device signature chain, "never by trusting the carrier", so caching
  it at the registry adds no trust and grants the registry nothing.
- **Pinned copy — the client.** The invite carries the host's keys at first contact (A10.3); the client pins the
  **root** and verifies every subsequent certificate's chain up to it.

**Why the registry must serve it, and the invite alone cannot.** A client's first message on `host.<hfp>.connect` is
an A7 envelope **sealed to the host's agreement key**. The client therefore needs the host device certificate
*before* it can address the host at all — so the cert can never be fetched from the host in band, and an offline host
can supply nothing. The invite covers first contact only; it cannot cover (a) a host that has **rotated** its device
key — and A7's stated mitigation for the offer's forward-secrecy gap depends on that rotation being practical — or
(b) a member enrolled long ago whose invite is gone.

**Rotation must not trigger the pinning wall [normative].** A4's "later key change = hard, non-dismissable wall"
applies to the **root**. A device-key change presented under a valid root→op→device chain is accepted **silently**;
only a changed root, or an op key that does not chain to the pinned root, raises the wall. A10.35's stated benefit is
that rotating a dedicated device key "touches nothing else" — that benefit is lost entirely if every rotation walls
every member.

**Crate residency (A9c).** Schema in `spindle-proto`; issue/verify in `spindle-core`; host-side persistence in
`spindle-vfs`; registry-side cache and serving in `spindle-helper`; fetch, pin, and chain verification in
`spindle-client-core`. The first two already exist; the rest do not.

**Rejected alternatives.**

- *Invite-only distribution.* Cannot deliver a rotated certificate to existing members, which makes A7's rotation
  mitigation unusable in practice.
- *Host serves it in band.* Structurally impossible — the client needs the agreement key to construct its first
  message, and an offline host serves nothing.
- *Helper mints or re-signs it.* Rejected for exactly the reason A10.34 rejected registry-minted agreement keys: it
  places the registry inside the trust chain, destroying A7's "registry cannot read or forge" property.

## Open items

- **DECIDED 2026-09-01 (user): publish on every host connect.** The host republishes its device certificate to
  `registry.devcert.<hfp>` each time it connects to the registry, not only after a rotation. Every-connect covers
  every scenario through one code path: it needs no rotation-detection state on the host, it is idempotent at the
  helper (an identical cert overwrites itself harmlessly), and it self-heals a helper that lost its cached copy —
  whereas rotation-only leaves a host permanently unreachable by new clients if the single publish that mattered was
  dropped. The cost is one small publish per host connect, already bounded by the per-host token bucket.
- **Not settled by the above.** A4c's two `[USER DECISION]` items — periodic revocation reconciliation versus
  trigger-driven only, and whether the digest earns its keep — remain open. This decision is consistent with A4c's
  existing host-connect trigger but does not answer either question.
- **No owner yet.** `apps/host/` is still a README, so nothing exists to publish the certificate or answer a resync.
  Specify now, implement with the host daemon.
