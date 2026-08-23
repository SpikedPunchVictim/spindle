# ADR-004: End-to-End Signaling Envelope

## Status

Accepted

## Context

The registry (NATS cluster + broker helper) routes every signaling message between a client device and a host, but
it is explicitly untrusted for payloads, keys, and membership (ADR-001 §A2 trust boundaries). Adversary A2
("Compromised or malicious registry") starts with a full view of broker traffic and the ability to mint NATS
permissions, and wants to MITM session setup by substituting keys or SDP, impersonate a party, or grant itself
access (ADR-001 §A2). Because the registry carries the offer/answer/ICE exchange on `host.<hfp>.sess.<cfp>.<sid>.*`
subjects (DESIGN.md A5, A6), every signaling message must be end-to-end authenticated and encrypted independently
of NATS-layer TLS, must resist replay/splicing/downgrade, and must give forward secrecy so that a later device-key
compromise cannot retroactively decrypt captured signaling.

Spindle also signs many other artifact types outside the live signaling path — capabilities, admission tokens,
device certificates, revocation records, admin commands, host operating-key certificates (DESIGN.md A4, A3b, A4b).
All of these need the same discipline (versioning, canonical encoding, a stated time rule, a stated replay rule) so
that a signature over one artifact type can never be replayed as a valid signature over another (ADR-001 §A12 #41).
A7 defines the envelope used for live signaling; A7b generalizes that discipline into a single profile that every
signed artifact in the system follows.

## Decision

### A7 — envelope structure and session key

Every signaling message between a client device and a host is wrapped in the following envelope, verbatim from
DESIGN.md §A7:

```
Envelope { v:1, alg_id, from_fp, to_fp, sid, kind, seq, ts, eph_pk?, ciphertext, sig }
Session key:  k = HKDF-SHA256(X25519(eph_self, eph_peer) || X25519(dev_self, dev_agree_peer),
                              info = "spindle-sess-v1" || sid || from_fp || to_fp)   (ephemeral-static hybrid)
AEAD:         AES-256-GCM, nonce = direction(1) || seq(11) — deterministic, never reused; AAD = canonical header
sig:          Ed25519(dev_sign_from, "spindle-env-v1" || canonical(header) || ciphertext)
canonical():  deterministic CBOR per RFC 8949 §4.2.1 (same profile for VFS RPC)
```

The session key is an **ephemeral-static hybrid**: it combines a per-session ephemeral X25519 exchange with a
static device-to-device X25519 agreement, giving forward secrecy against a later device-key compromise
(ADR-001 §A12 #15) while still binding the session to the two devices' long-term identities. The AEAD nonce is
constructed deterministically from a direction bit and a strictly increasing sequence number rather than randomly
generated, which makes nonce reuse structurally impossible as long as `seq` is enforced monotonic per direction.
The signature covers the canonical header **and** the ciphertext, so header fields cannot be detached or swapped
without invalidating `sig`.

### Receiver MUST-checks

On every envelope, the receiver **MUST**:
- verify `sig` under the **pinned** key for `from_fp` — or, for an invite redemption, under the key carried in the
  device certificate, which must itself chain to a root and be HMAC-bound to the invite nonce;
- confirm `to_fp == self`;
- confirm the sender is active and not revoked;
- confirm `sid` matches the subject it arrived on and is bound to `from_fp`;
- confirm `seq` is strictly increasing per `(sid, direction)`;
- confirm `|ts − now| ≤ 2 min`;
- confirm `kind` matches the subject;
- confirm `v`/`alg_id` are not below the peer's pinned minimum.

Failure of any check causes the envelope to be dropped, counted, and alerted on threshold — never a distinguishable
error reply (DESIGN.md A7; consistent with the uniform-silent-drop rule of A5).

### Browser crypto and clock skew

Browsers use WebCrypto Ed25519/X25519 (supported from Firefox 129+, Safari 17+, Chrome 137+) with a `@noble/curves`
fallback; AES-GCM and HKDF are used natively via WebCrypto. Because clients have no reliable wall clock relative to
the registry, the broker helper returns server time in the callout reply; clients compute a local offset and apply
it to `ts`/`exp` checks, and the UI warns the user on large observed skew (DESIGN.md A7).

### A7b — signed-artifact profile

A7's discipline is generalized to every signed artifact in the system. Each artifact shares a version byte `v`, a
**distinct domain-separation tag**, canonical CBOR encoding (RFC 8949 §4.2.1), a stated time rule, and a stated
replay rule; an unknown `v` is always rejected. The full catalog, verbatim from DESIGN.md §A7b:

| Artifact | Tag | Signer | Time rule | Replay rule |
|----------|-----|--------|-----------|-------------|
| Envelope | `spindle-env-v1` | device key | `ts` ±2 min (helper server-time offset) | (sid, direction, seq) monotonic |
| Member/invite cap | `spindle-cap-v1` | host root (via op key) | `exp`; `nbf` = issue ts | invite: nonce burn (idempotent replay of result); member: n/a |
| Admission token | `spindle-adm-v1` | operator key | `exp` days | nonce burn at helper (CAS, idempotent) |
| Device certificate | `spindle-dev-cert-v1` | identity root | `exp` 1 y; re-sign on contact | n/a (revocable) |
| Revocation record | `spindle-rev-v1` | host op key / identity root | none (permanent) | **max-wins, never decreases**; old records cannot roll back |
| Admin command | `spindle-adm-cmd-v1` | operator key | `ts` ±2 min | per-signer monotonic `seq` + nonce; idempotent execution |
| Host op-key cert | `spindle-host-cert-v1` | host root | `exp` 90 d | n/a (rotation) |

**Domain-tag rationale**: root keys sign two artifact types — device certificates and self-revocations — so the
distinct tags per artifact type exist specifically to prevent cross-artifact signature confusion, i.e. a signature
that validates for one artifact kind cannot be replayed as a valid signature for another kind signed by the same
key (ADR-001 §A12 #41). Host and helper both resolve `exp`/`nbf` checks against helper server time as the single
time authority, with the same ±2 min tolerance used for envelopes.

### Decision A10.16

DESIGN.md §A10 row 16 — canonical encoding — governs the `canonical()` function referenced above and in every A7b
artifact.

## Consequences

### Positive

- The registry cannot read or forge SDP/ICE content, because signaling payloads are E2E-encrypted and authenticated
  independently of NATS/TLS (ADR-001 §A12 #1, addressing adversary A2's ability to MITM DTLS setup via SDP
  tampering).
- Forward secrecy: compromise of a device's long-term key does not retroactively decrypt previously captured
  signaling, because the session key mixes an ephemeral exchange (ADR-001 §A12 #15).
- Replay, splicing, and downgrade are all rejected by the MUST-checks (`seq` monotonicity, `sid` binding, `ts`
  window, `v`/`alg_id` floor) (ADR-001 §A12 #16).
- Domain-separated signing tags prevent a signature over one artifact type being reinterpreted as valid over
  another, even when the same key signs multiple artifact kinds (ADR-001 §A12 #41).
- Revocation records are explicitly max-wins/never-decreasing, closing rollback via a replayed old record or a
  restored backup (ADR-001 §A12 #42); hosts fetch the epoch high-water mark from the helper at startup.
- `registry.revoke.<hfp>` scoping plus a per-host token bucket prevents cross-host forgery/flood on the shared
  revocation subject (ADR-001 §A12 #43).

### Negative

- Two independent canonical-CBOR encoders (Rust `minicbor`-based, hand-driven; TypeScript own encoder in
  `@spindle/proto`) must byte-for-byte agree, or signature verification silently diverges between platforms;
  mitigated by golden test vectors in CI (DESIGN.md A9b, A9c), but this is an ongoing maintenance burden with every
  wire-format change.
- No P-256 fallback suite exists — if a target browser ever drops Ed25519/X25519 support, there is no automatic
  degradation path; a second suite was deliberately rejected as downgrade surface (DESIGN.md A11).
- The `±2 min` clock-skew tolerance is a single global constant; environments with unusually large clock drift
  (e.g. a laptop that has been asleep for days) rely entirely on the helper-offset correction working correctly
  before the user's first envelope.

### Neutral

- Browser cryptography has two code paths (native WebCrypto vs. `@noble/curves` fallback) that must be kept
  interoperable and are validated by S6 (Rust ↔ browser round-trip, three browsers).
- The envelope's AEAD nonce scheme is deterministic rather than random, which is a correctness requirement (never
  reuse) rather than a security trade-off, but it depends on `seq` state being correctly persisted per session.

## Alternatives Considered

From DESIGN.md §A11:
- **WASM Rust core for browser crypto** — Rejected; WebCrypto + `@noble/curves` was judged sufficient, avoiding a
  second toolchain and WASM-specific supply-chain surface in the browser client.
- **P-256 fallback suite** — Rejected (v0.6); all target browsers ship Ed25519/X25519, and a second cipher suite
  was assessed as downgrade attack surface rather than a safety net.
- **Device-signs-device certificate chains** — Rejected (v0.6) in favor of root-only device certification; while
  primarily an identity-model decision (ADR-003), it also bears on this ADR because it bounds who may hold a
  `spindle-dev-cert-v1` signing key.

## Open items

- **A10.16 — Canonical encoding [DEFAULT]**: deterministic CBOR (RFC 8949 §4.2.1) for envelopes, capabilities, and
  VFS RPC; versioned, no downgrade. DESIGN.md flags this as a `[DEFAULT]` choice, not an explicit user decision; it
  is recorded here as such and is not resolved by this ADR.

## References

- ../DESIGN.md §A2 (threat model, trust boundaries), §A5 (subject/permission model, uniform silent drops), §A7
  (end-to-end signaling envelope), §A7b (signed-artifact profile), §A10 row 16 (canonical encoding), §A11
  (alternatives), §A12 (red-team traceability, rows #1, #15, #16, #34, #41, #42, #43)
- [ADR-001: Threat Model](./ADR-001-threat-model.md) — adversary A2, §A12 rows #1, #15, #16, #34, #41, #42, #43
- [ADR-002: NATS Signaling](./ADR-002-nats-signaling.md) — subjects that carry the envelope
- [ADR-003: Identity, Capabilities, Enrollment](./ADR-003-identity-capabilities-enrollment.md) — device keys used
  for envelope signing and session-key derivation
- ../SPIKES.md S6 (browser crypto + `alg_id` interop)
