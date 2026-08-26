# ADR-005: Transport, VFS RPC, and File Safety

## Status

Proposed

This ADR stays **Proposed** until spike **S3** (DataChannel throughput at 0/20/50/100 ms RTT; SCTP tuning) sets the
v1 throughput numbers. DESIGN.md's verification rule is explicit: *"S3 before any transport ADR is Accepted"*
(DESIGN.md Part B, Verification). Do not move this ADR to Accepted before S3 has run and its pass criterion (≥ 50
MB/s LAN; ≥ 15 MB/s @ 50 ms; knobs documented) has been met and recorded in ../SPIKES.md. **S3 is now complete**
(see the 2026-08-24 update below); the gate for Accepted has moved to spike **S19** (below).

**2026-08-23 update**: TCP through the same netem path does 60 MB/s @ 50 ms with zero drops, exonerating the test
environment; single-association SCTP still fails the 50 ms bar in both Rust stacks (~1–2 MB/s), and parallel SCTP
associations scale sub-linearly, plateauing around ~7.7 MB/s at N=8 — short of the ≥ 15 MB/s bar. Per decision
A10.29, this stays **Proposed** pending deeper investigation (a real browser-peer/dcSCTP throughput measurement plus
webrtc-rs cwnd profiling) before the A9 bar is revised or the transport choice is reopened.

**2026-08-24 update — S3 chain complete; transport split decided (A10.31, A10.32)**: The deeper investigation
A10.29 called for is done (`spikes/s3-throughput/RESULTS.md`, commits 7f76c70, 9d248b5), and **S3 is marked
complete**. Full chain, all on identical `tc netem`-shaped paths, zero loss, TCP baseline 60.7 MB/s @ 50 ms:

| Pairing | 0 ms | 20 ms | 50 ms | 100 ms |
|---|---|---|---|---|
| webrtc-rs ↔ webrtc-rs / datachannel-rs (earlier host matrix) | — | — | ~1–2 MB/s | — |
| webrtc-rs sender (containerized) → real headless Chromium 151 | 9.776 | 2.076 | 0.885 | 0.484 |
| Chrome dcSCTP sender → webrtc-rs receiver | 90.360 | 0.179 | 0.083 | 0.044 |
| Chromium ↔ Chromium control (dcSCTP both ends, no Rust) | 73.219 | 1.892 | 0.845 | — |

The Chrome→webrtc-rs collapse (90.360 → 0.179 MB/s at 20 ms) was traced via `rtc_sctp` tracing to a frozen RFC 4960
initial congestion window (~4380 B): receiver SACKs are clean (1 per RTT, ~4.2 MB healthy `a_rwnd`, `dupTsn=[]`
across all 1,494 SACKs), so the freeze is dcSCTP-internal growth gating, not a network or receiver-side defect. The
Chromium↔Chromium control run — no Rust stack on either end — still shows a flat ~38–41.5 KB RTT-independent window
and fails the ≥ 15 MB/s @ 50 ms bar. **Conclusion**: WebRTC data channels as shipped cannot meet the bar against any
measured peer, Rust-stack or browser-native; the Rust stacks are additionally worse than the browser baseline.
Caveat: this matrix is netem-on-loopback in one container — real-WAN validation is folded into new spike **S19**
(below). The findings (webrtc-rs sender-side collapse; the dcSCTP interop freeze) are to be filed upstream against
`webrtc-rs`.

**Decisions (user, 2026-08-24)**:
- **A10.31 — transport split**: native↔native transfers use **QUIC**; WebRTC data channels are used only where a
  browser peer is involved. The browser WAN ceiling (~1–2 MB/s @ 50 ms, per the matrix above) is stated explicitly
  in DESIGN.md §A9 and surfaced in the UI, rather than presented as a general throughput bar.
- **A10.32 — QUIC stack**: `quinn`, paired with a **standalone ICE** implementation — reusing `webrtc-rs`'s `ice`
  crate for hole-punching — which hands the punched UDP socket to `quinn`. coturn/TURN and NATS signaling are
  **unchanged** (TURN relays UDP, and QUIC is UDP, so the existing relay covers it). Identity binding mirrors the
  DTLS rule: a per-session self-signed QUIC certificate, its fingerprint carried in the A7-verified envelope, and
  the TLS handshake verified against that pin. `iroh` was evaluated and **rejected**: a large dependency, its own
  relay network duplicating coturn, and its own identity layer that would need reconciling with ADR-003 (DESIGN.md
  §A4).

This amendment **supersedes the transport-selection paragraph above** (the ADR's original "webrtc-rs and channel
layout" section, which specified `webrtc-rs` as the single Rust transport for every peer) — see the Decision
section's new **Transport split** subsection below for the resulting design.

This ADR remains **Proposed**. Acceptance is now gated on spike **S19** (quinn-over-punched-ICE native↔native: ≥ 15
MB/s @ 50 ms, punch/relay success across the NAT-combination matrix, and real-two-host confirmation of the netem
numbers above) rather than S3, which is complete.

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

### Transport split: QUIC for native↔native, WebRTC only with a browser peer [amendment 2026-08-24, A10.31, A10.32]

**This subsection supersedes the transport-selection paragraph above** (the "webrtc-rs and channel layout" section,
which specified `webrtc-rs` as the Rust transport for every peer pairing). It does not change the VFS RPC surface,
chunk/manifest/resume format, or received-file policy below — those remain transport-agnostic, unchanged by this
amendment.

Per the evidence in the Status section above (S3 chain, `spikes/s3-throughput/RESULTS.md`, commits 7f76c70,
9d248b5), WebRTC data channels as shipped cannot meet the ≥ 15 MB/s @ 50 ms bar (DESIGN.md §A9) against any measured
peer. Decision A10.31 splits the transport by peer type:

- **Native↔native transfers use QUIC.** `spindle-net` gains a QUIC transport path (`quinn`), used whenever both
  peers are native (Tauri host/client). ICE is standalone: `webrtc-rs`'s `ice` crate performs hole-punching (reusing
  the existing NATS-mediated trickle-ICE signaling and coturn TURN fallback from ADR-002), and the resulting punched
  UDP socket is handed to `quinn` to run the QUIC handshake and streams over it. coturn/TURN and NATS signaling are
  otherwise **unchanged** — TURN relays UDP, and QUIC is UDP, so no new relay component is needed (A10.32).
- **Identity binding mirrors the DTLS rule (ADR-004).** Each QUIC session uses a per-session self-signed
  certificate; its fingerprint is carried inside the A7-verified connect envelope (the same place the DTLS
  `a=fingerprint` travels today), and the TLS handshake is verified against that pin. No CA, no TOFU — the envelope
  is the trust anchor, exactly as for the DataChannel/DTLS path.
- **Transport is negotiated inside the verified connect envelope**: peers advertise their transport capability and
  agree on `quic` when both are native, falling back to the existing WebRTC/DataChannel path whenever a browser peer
  is involved (browsers have no QUIC-transport API equivalent to DataChannels).
- **Browser path is unchanged**: one reliable-ordered control channel + one unordered-reliable data channel, 64 KiB
  chunks, `bufferedAmountLow` backpressure — the same layout as the "webrtc-rs and channel layout" section above —
  but now carries the **stated WAN ceiling** (~1–2 MB/s @ 50 ms) rather than the ≥ 15 MB/s bar, per A10.31. Parallel
  SCTP associations (~7.7 MB/s @ N=8, A10.29's mitigation) remain the recorded mitigation ceiling for this path, not
  a fix.
- **`iroh` was evaluated and rejected** (A10.32): a large dependency; it brings its own relay network alongside
  coturn (duplicated infrastructure, not a replacement); and its own identity layer would need reconciling with the
  root/device-cert model in ADR-003 (DESIGN.md §A4) — reconciliation the self-signed-cert-plus-envelope-pin approach
  avoids entirely.
- **Upstream**: the webrtc-rs sender-side collapse and the dcSCTP interop freeze (Status section above) are to be
  filed as upstream issues against `webrtc-rs`; that is tracking work, not a blocker for this ADR.

VFS RPC, the chunk/manifest/resume format, and received-file policy (below) are transport-agnostic and unaffected by
this split — they run unchanged over either the QUIC stream pair or the WebRTC channel pair.

**[amended 2026-08-26, DESIGN.md v0.9.12]** The QUIC control stream's wire format is now implemented and codified
(`spindle-net`, `spindle-host-core`; end-to-end tested): VFS RPC frames on the control stream use a 4-byte
big-endian length prefix followed by a canonical-CBOR payload, capped at 256 KiB (comfortably above the 64 KiB
chunk size plus CBOR overhead); the ALPN token is `spindle-vfs/1`; the certificate fingerprint is SHA-256 of the
certificate's DER encoding; pinning is **mutual** — each side pins the other's per-session certificate fingerprint,
sourced from the A7-verified envelope per the identity-binding bullet above. A framing or decode violation
(oversized length prefix, truncated frame, a request that doesn't decode) closes the connection rather than
producing a typed VFS error — typed `VfsErrorCode` replies (VFS error model, below) apply only to well-formed,
already-authenticated requests.

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
`resume_expired`, `upload_rejected`, `storage_full`, `throttled`, `unsupported_version`, `already_exists`,
`file_changed`. Pre-auth failures remain uniform on the wire, and the client derives honest composite states such as
"host offline — or your access changed; it will retry." One narrow exception: invite-redemption results are returned
inside the verified reply envelope as accepted/expired/already-used (DESIGN.md A8). `unsupported_version` fires
pre-dispatch on the protocol version gate above; `already_exists` is the overwrite-requires-delete refusal for name
collisions (Received-file policy, above); `file_changed` is the resume-conflict abort described above under Transfer
manager. **[amended 2026-08-26, DESIGN.md v0.9.10]**

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

**[amended 2026-08-24, A10.31]** The ≥ 15 MB/s @ 50 ms bar in the Transfer row above now applies to the
native↔native QUIC path (spike **S19** sets the pass bar, superseding S3 for this purpose). The browser row's
ceiling is stated separately, and explicitly, as ~1–2 MB/s @ 50 ms; parallel SCTP associations (~7.7 MB/s @ N=8,
A10.29) remain the recorded mitigation ceiling for that path, not a pass condition.

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
  browser-native DataChannel story that QUIC-based alternatives lack. **[amended 2026-08-24, A10.31/A10.32]**
  Partially superseded: QUIC (via `quinn` + a standalone `ice` implementation, not `iroh`) is now adopted for
  native↔native transfers — see the Decision section's "Transport split" subsection. `iroh` itself remains rejected
  (large dependency; its own relay network duplicating coturn; its own identity layer to reconcile with ADR-003).
  WebRTC remains mandatory wherever a browser peer is involved, since no browser ships a QUIC-transport API
  equivalent to DataChannels.
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
  (transport, VFS RPC, file safety), §A9 (UX requirements table), §A10 rows 6–8, 31–32, §A11 (alternatives), §A12
  (red-team traceability, rows #8, #18, #21, #28), §A13 (spikes S3, S4, S7, S19)
- [ADR-001: Threat Model](./ADR-001-threat-model.md) — adversaries A1/A5, §A12 rows #8, #18, #21, #28
- [ADR-002: NATS Signaling](./ADR-002-nats-signaling.md) — session establishment that precedes the DataChannel
- [ADR-004: End-to-End Signaling Envelope](./ADR-004-e2e-signaling-envelope.md) — device-key manifest signing,
  canonical CBOR used by the VFS RPC
- [ADR-006: Host Authorization](./ADR-006-host-authorization-members-shares-entitlements.md) — per-request
  permission checks that gate every VFS RPC call
- ../SPIKES.md S3 (throughput — **complete**, see the 2026-08-24 update above), S19 (quinn-over-punched-ICE
  native↔native throughput — gates this ADR's Accepted status), S4 (NAT traversal / TURN cost), S7 (browser
  large-file sink)
