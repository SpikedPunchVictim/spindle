# ADR-005: Transport, VFS RPC, and File Safety

## Status

Proposed

This ADR stays **Proposed** until spike **S3** (DataChannel throughput at 0/20/50/100 ms RTT; SCTP tuning) sets the
v1 throughput numbers. DESIGN.md's verification rule is explicit: *"S3 before any transport ADR is Accepted"*
(DESIGN.md Part B, Verification). Do not move this ADR to Accepted before S3 has run and its pass criterion (≥ 50
MB/s LAN; ≥ 15 MB/s @ 50 ms; knobs documented) has been met and recorded in ../SPIKES.md.

## Context

Once a WebRTC DataChannel is established (ADR-004 envelope negotiates the session; ADR-002 carries offer/answer),
all file browsing and transfer happens directly between client and host, peer-to-peer, with the registry out of the
data path entirely (DESIGN.md A3, A8). The host's filesystem is one of the five protected assets in the threat
model (ADR-001 §A2 asset 5: "the host owner's filesystem — confinement to what was deliberately shared, and safety
of what is received"), and adversary A1 ("malicious authenticated device/member") explicitly wants to "plant
hostile files" and escape confinement (ADR-001 §A2). Adversary A5 wants to run up TURN bills via denial-of-wallet
(ADR-001 §A2). The transport layer therefore has two coupled jobs: move bytes fast enough that users don't reach
for a USB stick (DESIGN.md A1 goal 3), and never let a peer plant a hostile or path-escaping file, or exhaust
host/relay resources, while doing so.

Because SCTP throughput inside a single DataChannel association is fundamentally RTT-bound by congestion windows,
the achievable numbers are an empirical question, not a design one — hence S3 gates this ADR's Accepted status.

## Decision

### webrtc-rs and channel layout

Rust uses `webrtc-rs` (≥ 0.20, sans-I/O core), with `datachannel-rs` evaluated as a fallback if S3 fails. Because
throughput is RTT-bound by SCTP windows, window/buffer tuning is a required S3 outcome, not an implementation
afterthought (DESIGN.md A8).

Channel layout: **one** reliable-ordered control channel (VFS RPC) plus **one** unordered-reliable data channel.
All channels share a single SCTP association and congestion window, so adding more channels does not add
throughput — this was evaluated and rejected (see Alternatives). Transfers use 64 KiB chunks, backpressure via
`bufferedAmountLow`, and are resumable via a manifest of offsets and per-chunk hashes. The UI shows direct/relayed
status and speed (DESIGN.md A8).

### VFS RPC surface

The control channel carries CBOR-encoded RPCs (canonical CBOR per ADR-004's A7b profile):

- `list(path, cursor) → entries[{name, kind, size, mtime, perms_here}]`
- `stat(path)`
- `read(path, offset, len) → chunk stream on data channel`
- `upload(path, size, hash) → resumable session`
- `mkdir(path)`
- `delete(path)`
- `whoami → {member_display, effective_paths}`

All paths are **virtual**; every call is permission-checked against the host authorization model (ADR-006), and an
unauthorized call returns the same result as a nonexistent path — **not found** — so authorization state can never
be inferred from a distinguishable error (ADR-001 §A12 #21, existence-leak closure defined in ADR-006). The RPC
carries a protocol version; peers negotiate the highest common version with **no downgrade below either side's
minimum** (DESIGN.md A8).

### File integrity

Every transfer carries a per-chunk hash plus a whole-file hash, delivered in a manifest signed by the sender's
device key (DESIGN.md A8) — the same device-key signing discipline as the envelope (ADR-004).

### Received-file policy

Attacker-supplied filenames are reduced to a flat, sanitized basename; path separators, `..`, and reserved OS names
are rejected outright (ADR-001 §A12 #18, hostile received files / path traversal). Files land under the granted
upload subpath, or in a per-member quarantine directory for owner-received files; nothing overwrites an existing
entry without `delete` permission; size caps apply per transfer, per member, and per share; received files carry an
OS quarantine attribute and are never auto-opened; every receipt is written to the audit log (DESIGN.md A8;
audit log itself specified in ADR-006).

### TURN

coturn is run with `use-auth-secret`, `username = expiry:device_fp`. Quota is enforced by the broker helper **per
`root_fp`**, not per device key, because device keys are free to mint and a per-device quota would be trivially
bypassed by generating fresh keys (ADR-001 §A12 #28, TURN quota bypass via fresh device keys; also §A12 #8, TURN
denial-of-wallet by adversary A5). Credentials use short TTLs with allocation caps.

### Browser receive path

The File System Access API is used where available; a streaming-download fallback applies with a stated ceiling
(open item A10.6, below). Background-tab/sleep behavior must resume correctly, verified by spike S7 (DESIGN.md A8).

### Transfer manager

Client-side: a folder download is a sequential queue over `list` + `read` — **there is no server-side archive
generation** (rejected alternative, see below), and directory upload mirrors the same queue structure. Concurrency
is limited per session (default 3). Resume manifests are persisted locally — native: app data directory; browser:
IndexedDB / File System Access — so progress survives a restart. On a resume conflict ("file changed"), the
transfer aborts and presents a clear choice: re-download or keep the partial (DESIGN.md A8).

**Upload sessions** are explicit host-side objects: `{id, member, path, size, hash, offset, expires}`. Partial
uploads live under a hidden staging name — never listed, but counted against quota — and are garbage-collected at a
48-hour TTL. An entitlement change mid-transfer aborts the session and garbage-collects the partial. The signed
manifest is verified **before** the file is moved into place (DESIGN.md A8).

### VFS error model

Inside an authenticated session (post-DTLS), the pre-auth uniform-silent-drop rule no longer applies; instead, the
VFS surfaces typed error codes with UI copy per code: `not_found`, `quota_exceeded`, `grants_changed`,
`resume_expired`, `upload_rejected`, `storage_full`, `throttled`. Pre-auth failures remain uniform on the wire, and
the client derives honest composite states such as "host offline — or your access changed; it will retry." One
narrow exception: invite-redemption results are returned inside the verified reply envelope as
accepted/expired/already-used (DESIGN.md A8).

### Acceptance criteria (DESIGN.md §A9 — the UX bar the spikes must meet)

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

## Consequences

### Positive

- P2P transfer keeps file contents entirely out of the registry's path, consistent with the zero-knowledge
  definition (ADR-001 §A2) — the registry never sees payloads even at scale.
- Uniform `not_found` for unauthorized VFS calls closes the existence-leak attack (ADR-001 §A12 #21) at the
  transport-adjacent layer, complementing ADR-006's listing-level filtering.
- Per-`root_fp` TURN quotas close both the denial-of-wallet attack (ADR-001 §A12 #8) and the fresh-key bypass
  variant of it (ADR-001 §A12 #28).
- Signed manifests verified before move-into-place, plus filename sanitization and quarantine attributes, directly
  close the hostile-received-file attack (ADR-001 §A12 #18).
- Client-side transfer queues avoid a large new attack/resource surface on the host (no server-side archive
  generation to exploit or exhaust).

### Negative

- Real-world throughput is unknown until S3 completes; the ADR cannot be Accepted, and any code built against it
  carries the risk of a later SCTP-tuning change invalidating assumptions.
- A single SCTP association/congestion window for both control and data traffic means large transfers can compete
  with VFS control-plane responsiveness (e.g., a `list` call queued behind saturated `read` chunk delivery).
- The browser receive path has a stated ceiling rather than unbounded capacity — large-file scenarios degrade to a
  fallback path whose UX is weaker than native (File System Access API unsupported browsers).
- 48-hour partial-upload TTL is a fixed constant; very large or very slow uploads near that boundary have no stated
  extension mechanism in DESIGN.md.

### Neutral

- The VFS RPC protocol version negotiation (no downgrade below either side's minimum) trades a small amount of
  compatibility flexibility for a firm security floor; this is consistent with ADR-004's `v`/`alg_id` floor rule.
- TURN relay percentage and cost/GB are empirical unknowns pending spike S4, independent of the throughput question
  S3 answers.

## Alternatives Considered

From DESIGN.md §A11:
- **iroh / QUIC instead of WebRTC** — Rejected for v1; a browser client is required, and WebRTC has the mature
  browser-native DataChannel story that QUIC-based alternatives lack.
- **JetStream (durability / KV presence)** — Rejected for v1; not needed for transport, and KV permissions would
  break the per-host subject scoping used elsewhere in the system.
- **N data channels for throughput** — Rejected (v0.6); all channels share one SCTP association and congestion
  window, so multiple channels provide no throughput gain, only added complexity.
- **Server-side archive generation for folder download** — Rejected (v0.8); this would add memory/CPU load on
  hosts and resume complexity; a client-side sequential queue over `list`/`read` was chosen instead.

## Open items

DESIGN.md marks the following as unresolved; they are recorded here, not decided by this ADR:

- **A10.6 — Browser receive ceiling [USER DECISION]**: File System Access API where available; otherwise a stated
  cap (e.g. 2 GB). The exact fallback ceiling value is not yet fixed.
- **A10.7 — Metadata retention at registry [USER DECISION]**: connection logs retained 30 days; no payload logging.
  This bounds what the helper's connection-metadata store (used by TURN quota and presence) may retain.
- **A10.8 — TURN hosting & cost policy [USER DECISION]**: self-host coturn; per-device monthly relay quota; spike
  S4 produces the cost/GB figure that should inform the final quota numbers.

## References

- ../DESIGN.md §A2 (threat model, asset 5, adversaries A1/A5), §A3 (architecture overview, TURN component), §A8
  (transport, VFS RPC, file safety), §A9 (UX requirements table), §A10 rows 6–8, §A11 (alternatives), §A12 (red-team
  traceability, rows #8, #18, #21, #28), §A13 (spikes S3, S4, S7)
- [ADR-001: Threat Model](./ADR-001-threat-model.md) — adversaries A1/A5, §A12 rows #8, #18, #21, #28
- [ADR-002: NATS Signaling](./ADR-002-nats-signaling.md) — session establishment that precedes the DataChannel
- [ADR-004: End-to-End Signaling Envelope](./ADR-004-e2e-signaling-envelope.md) — device-key manifest signing,
  canonical CBOR used by the VFS RPC
- [ADR-006: Host Authorization](./ADR-006-host-authorization-members-shares-entitlements.md) — per-request
  permission checks that gate every VFS RPC call
- ../SPIKES.md S3 (throughput — gates this ADR's Accepted status), S4 (NAT traversal / TURN cost), S7 (browser
  large-file sink)
