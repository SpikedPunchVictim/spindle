---
review_id: d8c9ccced61a32ded26c62fa3fb9fab5bd2ab9e8
date: 2026-09-08
ticket: td-ac9a88
scope_commits: [d8c9ccced61a32ded26c62fa3fb9fab5bd2ab9e8]
verdict: PARTIAL
provenance: mined-from-commit
fidelity: second-hand
source_note: The commit merges a previously-committed draft doc (docs/drafts/A4c-revocation-convergence.md) into canonical DESIGN.md; the commit says two of the draft's factual claims about existing code "were WRONG and are corrected rather than merged" — it does not say whether this was found by a separate reviewer or by the implementer re-verifying the draft against the code before merge, so it is filed as the implementer's own audit.
findings:
  - id: F1
    severity: minor
    class: unverified-code-claim
    file: spindle-helper/src/permissions.rs
    line: 87
    claim: "the draft cited a bare `pub registry.revoke` grant"
    reality: "the code grants the scoped `registry.revoke.<own>` (spindle-helper/src/permissions.rs:87). The conclusion survives -- no new permission is needed -- and the scoping is what makes it safe."
    detection: reread
    evidence: null
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "grep the actual permission grant string in permissions.rs before citing it in the merged DESIGN prose"
    td_ref: td-ac9a88
  - id: F2
    severity: minor
    class: unverified-existence-claim
    file: revoke.rs
    line: 66
    claim: "the draft said the resync subject's per-host token bucket matches buckets that registry.revoke/registry.devcert 'already carry'"
    reality: "They do not exist. revoke.rs:66-77: \"This crate has no rate limiter of any kind today.\" All three are now recorded as an outstanding obligation."
    detection: reread
    evidence: "revoke.rs:66-77 doc comment quoted verbatim: \"This crate has no rate limiter of any kind today.\""
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "search the named crate for an actual rate-limiter implementation before asserting one 'already' exists, rather than assuming parity with a sibling subject"
    td_ref: td-ac9a88
---

## What the commit says

> Two draft claims were WRONG and are corrected rather than merged:
> - the draft cited a bare `pub registry.revoke` grant; the code grants the
>   scoped `registry.revoke.<own>` (spindle-helper/src/permissions.rs:87).
>   The conclusion survives -- no new permission is needed -- and the
>   scoping is what makes it safe.
> - the draft said the resync subject's per-host token bucket matches
>   buckets that registry.revoke/registry.devcert "already carry". They do
>   not exist. revoke.rs:66-77: "This crate has no rate limiter of any kind
>   today." All three are now recorded as an outstanding obligation.

## Reading

The draft document had already been committed to the repository (`docs/drafts/A4c-revocation-convergence.md`) before this merge commit finalized it into canonical DESIGN.md, so these two false claims about the existing codebase existed in a real, checked-in file rather than being caught before anything shipped. Both errors are the same shape — describing existing permission/rate-limiting infrastructure more generously than the code actually provides — and both were caught by checking the draft's claims against the cited source files rather than trusting the draft's prose. Neither changed the substantive decision (no new permission needed; the resync subject would need new rate limiting), but had they merged unchecked, DESIGN.md would have asserted the existence of a safety mechanism (a rate limiter) that the code does not have.
