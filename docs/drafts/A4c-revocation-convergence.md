# DRAFT — A4c. Revocation convergence: making the helper's store self-healing

> **Status: DRAFT, not yet merged into `docs/DESIGN.md`.** Drafted 2026-09-01 for review. On approval this becomes
> section **A4c**, inserted after A4b, with a version bump to v0.9.19 and a Part D change-log entry — and the mirror
> at `~/.claude/plans/piped-launching-pony.md` must be updated in the same change so the two stay byte-identical.

## The gap this closes

A4 states that the helper's durable revocation store is "part of the cut-off path, not a backstop": a kicked client
reconnects on its own, so KICK alone cuts nobody off, and the cut-off holds only because the callout refuses the
reconnect. A4 specifies the publish — host bumps epoch, signs a `RevocationRecord`, publishes to
`registry.revoke.<hfp>` — but says nothing about what happens when that publish never lands.

The full operation is three steps and only the first is durable:

1. the host's store transaction commits (revoked status **and** the `cap_epoch` bump, atomically);
2. the `RevocationRecord` is minted in memory;
3. the record is published over NATS.

A process death, a partition, a dropped message, or a helper replica restart between (1) and (3) loses the record
permanently. Locally the subject is revoked and the host's per-request enforcement — authoritative, per A4 — still
denies them, so **no file contents are exposed**. What is lost is the registry-side cut-off: no KICK is issued, and
the callout keeps admitting the revoked device's capability. The `< 5 s` cut-off target (S9) is violated silently.

## Why a lost record does not repair itself

The helper's ingest is deliberately a **one-way lattice**: it unions the record's `revoked` subjects into its set,
applies max-wins to the stored epoch, never removes a subject, and never rejects a stale epoch (replay is explicitly
safe, so that a redelivered or operator-replayed record cannot roll anything back).

Union is what makes a lost record permanent: a *later* revocation record carries only its own subjects, so it never
re-adds the one that was lost. The max-wins epoch does bound the damage — any later record raises
`revocation_epoch(host_fp)`, which stales the lost victim's capability and downgrades them from full member
permissions to connect-only — but that is degradation, not repair. The subject remains absent from the helper's
revoked set until something republishes it.

The same lattice is also what makes repair cheap: **republishing is idempotent and order-independent**, so a
reconciliation pass cannot corrupt state no matter how often it runs or in what order records arrive.

## Decision 1 — convergence by state reconciliation, not a delivery queue **[DEFAULT]**

The host **republishes its complete current revoked set** rather than guaranteeing delivery of each individual
record. The revoked set is small, monotone, and derivable at any time from the host's own store (members with
`status = revoked`, devices with `revoked = 1`), which is exactly the shape where state reconciliation beats a queue.

This heals strictly more than a delivery guarantee does: the sender's crash window, but also a helper that lost its
store, a replica that was down, a dropped message, and a partition. It needs no new table, no migration, no drain
loop, and no retry policy.

**Rejected: a transactional outbox.** Writing the minted record into an `outbox` table inside the same transaction
and draining it with a background publisher fixes only the sender's crash window, and costs a schema migration plus a
publisher task with its own retry and table-growth policy. Held in reserve: if measurement later shows the
reconciliation payload is too large or too frequent to republish, an outbox becomes the fallback, not the first move.

## Decision 2 — what is republished: the revoked set only, never the roster **[normative]**

The reconciliation payload is exactly the existing A4/A7b `RevocationRecord` — `{host_fp, epoch, revoked: [...], ts,
sig_host_op}` — where `revoked` carries the host's complete current revoked set rather than a single revocation's
subjects. No new artifact type is introduced.

It **MUST NOT** carry non-revoked members. A1 and A2 state that accounts live only on hosts and that the registry
holds none; the helper today holds only revoked fingerprints, an epoch, and admission records. Sending the member
table would hand the registry the membership roster A2 says it must never have. That is a change to the threat model,
not an optimization, and it is rejected on those grounds.

## Decision 3 — three triggers

| Trigger | Detects | Cost |
|---------|---------|------|
| host connect | restart after a crash; helper restart; anything missed while the host was offline | one publish per host connect |
| `cap_epoch` divergence | the helper is provably behind — it missed at least one record | free; already on the wire |
| digest mismatch | epochs agree but the sets diverged | one digest field per host connect |

**(a) On host connect.** After each successful registry connection the host publishes one reconciliation record on
its existing `registry.revoke.<hfp>` subject. No new permission is required — the callout already grants a host
`pub registry.revoke`.

**(b) On proven divergence, detected from `cap_epoch` — the free detector.** A capability is host-signed and carries
the `cap_epoch` at which it was issued, so a cap naming epoch *N* is proof the host reached epoch *N*. If a connecting
device presents a verified cap whose `cap_epoch` is **greater** than the helper's stored `revocation_epoch(host_fp)`,
the helper has proof it missed at least one revocation record. This needs no hash, no extra round-trip, and no
protocol change — the value is already presented at every connect and today is used only for the freshness comparison
and then discarded.

**(c) On digest mismatch.** The `cap_epoch` detector catches "the helper is behind"; it structurally cannot catch
"the epochs agree but the set diverged" — a partial write, a restore from a stale backup, a replica that drifted. The
host therefore includes a digest of its revoked state on connect, and the helper compares it against its own.
Digest = `H(DOMAIN_REVOKE_DIGEST, host_fp, epoch, sorted(revoked))`, domain-separated per A7b and sorted for
determinism.

## Decision 4 — reconciliation is never on the connect critical path **[normative]**

The callout **MUST** decide every connection from the helper's local durable state alone. It must never block on a
round-trip to the host.

S14 requires the callout to refuse a revoked device *while hosts are offline*, and the helper's durable store exists
precisely so that question can be answered without the host. Making the decision depend on a host round-trip forces a
choice between failing open (a revoked device is admitted because its host is asleep) and failing closed (nobody
reaches a host that is merely offline). Both are worse than the current behaviour.

Reconciliation is therefore **asynchronous repair**, never a synchronous lookup. On detecting divergence the helper:

1. decides the current connection conservatively from local state — the existing stale-cap downgrade path;
2. publishes a resync request, rate-limited (below);
3. applies the host's reconciliation record whenever it arrives.

## Subject: `host.<hfp>.revoke-resync`

The helper needs a way to *ask*. Hosts are already granted `sub host.<own>.>` by the callout, and the helper already
publishes to `host.<hfp>.presence` under that grant, so the resync request fits the existing pattern with **no new
permission and no new grant**:

| Subject | Publisher | Subscriber | Notes |
|---------|-----------|------------|-------|
| `host.<hfp>.revoke-resync` | broker helper | host `hfp` | asks the host to republish its full revoked set on `registry.revoke.<hfp>`; no reply (the answer arrives on the existing revoke subject); per-host token bucket |

**Rate limiting is required, not optional.** A capability is host-signed and therefore unforgeable, but a genuine
old capability carrying a high `cap_epoch` can be replayed by a client at will, and each replay would otherwise
trigger a resync request. The subject takes a **per-host token bucket**, matching the buckets `registry.revoke.<hfp>`
and `registry.devcert.<hfp>` already carry.

## Open items

- **[USER DECISION]** Periodic reconciliation in addition to the three triggers, or trigger-driven only? Connect-time
  alone leaves a long-lived host that never reconnects out of sync if a single publish is dropped and no client with
  a newer cap happens to connect.
- **[USER DECISION]** Is the digest (trigger c) worth its extra field, given that `cap_epoch` (trigger b) covers the
  common case at zero cost? It defends only against helper-side data loss.
- **Unmeasured:** the reconciliation payload size ceiling. `deploy/nats/nats-server.conf` sets
  `max_control_line: 32768` (A10.10), but that governs the CONNECT control line where capabilities ride — **not**
  published payloads, which fall under `max_payload`, currently unset and therefore nats-server's 1 MB default. That
  is roughly 30,000 fingerprints, but the number must be measured before it is relied on, not derived on paper.
- **No owner yet.** `apps/host/` is still a README; nothing exists to run the connect hook or answer a resync
  request. This section should be specified now and implemented with the host daemon.
