---
review_id: d6e5ec7162b00dc0371b926a96f3d743d4dc5a2c
date: 2026-08-31
ticket: null
scope_commits: [d6e5ec7162b00dc0371b926a96f3d743d4dc5a2c, 6bf12c76a3f8511fcc476e42bead5af69c02af07]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: "Commit says 'Deciding it exposed a latent defect' — the defect surfaced while making an unrelated design decision (A10.36), not from a test failure or a named review pass."
findings:
  - id: F1
    severity: reject
    class: missing-guard
    file: crates/spindle-net/src/signaling/client.rs
    line: null
    claim: "the comment above the inbox field asserted the signed value and the client's actual NATS reply subject were \"the same value\""
    reality: "SignalingClient set inbox from one new_inbox() call while Client::request minted its own reply subject internally (async-nats 0.35.1 send_request's no-inbox branch: let respond = self.new_inbox()), so the signed value never matched the subject the client actually listened on. The comment above the field asserted they were \"the same value\" -- they never were. Nothing host-side read the field, so no test could catch it: the same shape as the start_connectivity_checks omission found by the live run in c7528af."
    detection: trace
    evidence: null
    introduced_by: 6bf12c76a3f8511fcc476e42bead5af69c02af07
    introduced_by_kind: original
    implementer_could_have_caught_by: "assert host-side that the signed inbox field equals the actual reply subject the transport reported, rather than trusting a client-side comment claiming they matched"
    td_ref: null
---

## What the commit says

> Deciding it exposed a latent defect this commit fixes. `SignalingClient`
> set `inbox` from one `new_inbox()` call while `Client::request` minted its
> own reply subject internally (async-nats 0.35.1 `send_request`'s no-inbox
> branch: `let respond = self.new_inbox()`), so the signed value never
> matched the subject the client actually listened on. The comment above the
> field asserted they were "the same value" -- they never were. Nothing
> host-side read the field, so no test could catch it: the same shape as the
> `start_connectivity_checks` omission found by the live run in c7528af.

## Reading

A code comment in the signaling client flatly asserted that the signed `inbox` field and the client's real NATS reply subject were "the same value" — a claim that was never true, because `async-nats`'s `request()` helper mints its own internal reply subject independent of whatever the caller signs into the payload. Because nothing on the host side ever read or checked the `inbox` field, there was no way for any existing test to notice the mismatch; it surfaced only because the implementer was working through what A10.36 (binding the offer's inbox to the real reply subject) should actually mean, and in doing so re-examined a claim that had shipped unchallenged since 6bf12c76 (Stage 5 slice 3). The fix makes `inbox` a real security binding (host now rejects any offer whose decrypted `inbox` differs from the reported reply subject) rather than the decorative field it had silently been.
