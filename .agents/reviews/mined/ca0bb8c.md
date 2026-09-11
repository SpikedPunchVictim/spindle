---
review_id: ca0bb8c473336759ad799b98dbb235792582f65c
date: 2026-09-08
ticket: td-fc5a30
scope_commits: [ca0bb8c473336759ad799b98dbb235792582f65c]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: The commit describes an "S1" measurement stage (the implementer's own empirical audit) that disproved a DESIGN.md expectation the connect authorizer's cost-charging logic relied on. The separate "adversarial review found no defect" sentence refers to review of this commit's own fix, not to discovery of the original bug — this record is about the original bug.
findings:
  - id: F1
    severity: reject
    class: missing-guard
    file: null
    line: null
    claim: "DESIGN.md §A5's expectation: nats-server refuses a publish that names another device's inbox as its reply subject, so from_fp reaching the connect authorizer can be trusted before signature verification."
    reality: "nats-server 2.10 evaluates publish permissions against the publish subject only; the reply is checked solely by isReservedReply, a structural check for NATS-internal prefixes. Any peer with a valid device credential can publish to host.<h>.connect naming a victim's from_fp with a matching _INBOX_<victim_fp>. reply, so an attacker-chosen, unverified from_fp reaches the connect authorizer. Every per-identity cost charged there (per-from_fp token bucket, bounded tracking map, member-capability mint) was chargeable to a victim by an attacker who could never produce the victim's signature."
    detection: empirical
    evidence: "S1: seven permission shapes measured against nats-server 2.10 with zero effect; the only shape that blocked the spoof did so by denying host.<h>.connect outright. \"The broker cannot be made to enforce the rule at any price.\""
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "run the S1-style measurement against a real nats-server 2.10 broker (not just read its docs) before relying on a stated permission-model expectation for a security-relevant authorization decision"
    td_ref: td-fc5a30
---

## What the commit says

> S1 measured that DESIGN.md §A5's expectation does not hold. nats-server
> 2.10 does NOT refuse a publish naming another device's inbox as its reply
> subject: publish permissions are evaluated against the publish subject
> only, and the reply is tested solely by `isReservedReply`, a structural
> check for NATS-internal prefixes. The `Permissions Violation for Publish
> with Reply` error is not a permission decision despite its name.
>
> So any peer with a valid device credential can publish to
> `host.<h>.connect` naming a VICTIM's `from_fp` with a matching
> `_INBOX_<victim_fp>.` reply. `reply_prefix_ok` passes, and the offer
> reaches the connect authorizer with an attacker-chosen, unverified
> `from_fp`. Every per-identity cost charged there was charged to the
> victim by someone who could never produce the victim's signature:
>
>   1. the per-`from_fp` token bucket -> a remote, targeted lockout of an
>      arbitrary device, invisible to the global bucket
>   2. the bounded per-fp tracking map -> exhaustible with fabricated names
>   3. the member-capability mint -> a free Ed25519 signature per packet,
>      plus an Allow/Deny timing oracle (~16.7us mint vs ~3.3us equalization)
>
> The broker cannot be made to enforce the rule at any price: seven
> permission shapes were measured with zero effect, and the only shape that
> blocked the spoof did so by denying `host.<h>.connect` outright. NATS
> wildcards are full-token, so no narrower rule is writable.

## Reading

This is a case of a normative design expectation — that the broker itself would refuse a spoofed reply-to address — being taken as true in the shipped `ConnectAuthorizer` and never checked against the real broker's actual permission semantics. The gap was live: any device credential could target another device for lockout, map exhaustion, or a free-signature/timing-oracle abuse, entirely because per-identity cost was charged before the identity in question (`from_fp`) had been cryptographically verified. The implementer's own S1 measurement stage — testing seven permission shapes against a real nats-server 2.10 instance rather than trusting the design doc's stated behavior — is what surfaced this, and the fix (splitting `ConnectAuthorizer` at the signature-verification boundary) exists because no broker-side permission rule could substitute for it. This is a strong example of why the "matches the design doc" bar failed: the design doc itself was wrong about the dependency's behavior.
