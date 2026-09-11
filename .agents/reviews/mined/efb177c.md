---
review_id: efb177c9c6e4c32acdf85c01db00a2ecd3276ad1
date: 2026-08-30
ticket: null
scope_commits: [efb177c9c6e4c32acdf85c01db00a2ecd3276ad1, 404b52f2696c6636a2d236fd26cef2356cd61845]
verdict: PARTIAL
provenance: mined-from-commit
fidelity: second-hand
source_note: "The spike commit itself is an empirical audit ('First empirical test of DESIGN.md §A6's signaling flow') that lists 'FOUR DESIGN GAPS FOUND'; the resolving docs commit (404b52f2) states two of them as outright false/unimplementable claims in already-published design sections."
findings:
  - id: F1
    severity: reject
    class: spec-cannot-execute
    file: null
    line: null
    claim: "A7's session-key formula presumes both ephemeral public keys are known when k is derived."
    reality: "A6's flow has the client send the offer before it has ever seen the host's ephemeral key. [...] §A7's single session key `k` was unimplementable for the offer: it requires `eph_peer`, and the client cannot know the host's ephemeral before the host has replied."
    detection: trace
    evidence: null
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "walk the A6 offer step against the A7 key-derivation formula's required inputs (eph_peer) and confirm they are all available at that point in the flow, before publishing the formula as a single-key schedule"
    td_ref: null
  - id: F2
    severity: reject
    class: scope-mismatch
    file: null
    line: null
    claim: "device-key compromise does not retroactively decrypt captured signaling"
    reality: "§A7's blanket property [...] is false for the offer, and is withdrawn and re-scoped. Compromise of the host's static agreement key retroactively decrypts captured offers, including the client's SDP."
    detection: trace
    evidence: null
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "check the forward-secrecy property separately for each message type (offer vs. answer) against the specific key each one is sealed under, rather than stating it as one blanket property"
    td_ref: null
---

## What the commit says

From efb177c9 (the spike):

> FOUR DESIGN GAPS FOUND, none resolved here (all need decisions + amendments):
>
> 1. A7's session-key formula presumes both ephemeral public keys are known
> when k is derived, but A6's flow has the client send the offer before it has
> ever seen the host's ephemeral key. Worked around locally by sealing the
> offer under ephemeral-static and everything after under
> ephemeral-ephemeral, so one sid carries two different derived keys. An
> improvisation, not a design.

From 404b52f2 (the resolving docs commit):

> §A7's single session key `k` was unimplementable for the offer: it requires
> `eph_peer`, and the client cannot know the host's ephemeral before the host
> has replied. Replaced with a two-key schedule [...]
>
> The cost is stated rather than buried: §A7's blanket property "device-key
> compromise does not retroactively decrypt captured signaling" is false for
> the offer, and is withdrawn and re-scoped. Compromise of the host's static
> agreement key retroactively decrypts captured offers, including the
> client's SDP.

## Reading

An already-published design section (§A7) specified a single session-key derivation formula and a blanket forward-secrecy property, and neither one survived contact with the actual message flow it was meant to describe: the formula needed an input (the host's ephemeral key) that literally does not exist yet at the point the client must use it, and the forward-secrecy claim was false for exactly the message (the offer) where an attacker would care most, since it is sealed under a static-static term instead of an ephemeral one. The spike (efb177c9) surfaced this empirically by trying to actually implement the offer step against real infrastructure; the docs commit (404b52f2) is where the implementer states plainly that the formula "was unimplementable" and the property "is false" and "withdrawn." I've filed this as one record spanning both commits since the spike is the discovery and the docs commit is the verdict on it. Two other gaps the spike found (seq-reordering ambiguity, missing wire artifact for device public keys) are left out of this record — they read as ordinary unfinished design surface found during exploratory work, not a claim that shipped and was later shown false.
