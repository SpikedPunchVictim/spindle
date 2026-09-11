---
review_id: deefb421bb52d4384b7561ab0b1786f5b84c17ff
date: 2026-09-08
ticket: td-684764
scope_commits: [deefb421bb52d4384b7561ab0b1786f5b84c17ff]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: "Commit states plainly: 'Adversarial review of 524087a. No runtime defect — every line here is a comment. But all three were claims that would mislead the next reader, and two of them were mine.'"
findings:
  - id: F1
    severity: minor
    class: scope-mismatch
    file: null
    line: null
    claim: "The fail-open section of 524087a argued as a blanket principle that nothing running after the committed mutation may return `Err`."
    reality: "Three lines below that claim, `revoke_member_and_mint`'s `get_member(member_id)?` fetch of `root_fp` does exactly that. The code is right and the doc was wrong: `root_fp` is payload (it goes into `issue_revocation_record(.., vec![root_fp], ..)` as the thing being signed), not observability, so without it there is no publication to return and `Err` is the only truthful answer. The blanket principle as stated contradicted the code three lines below it."
    detection: reread
    evidence: null
    introduced_by: 524087a095a5c7079cb4f4a0a59026eac9b36d8f
    introduced_by_kind: original
    implementer_could_have_caught_by: "After stating a blanket rule in a doc comment, re-read the rest of the same function for a counter-example before committing the comment."
    td_ref: td-684764
  - id: F2
    severity: minor
    class: false-absence-claim
    file: null
    line: null
    claim: "The device revocation path's `member: None` fallback was justified with 'e.g. it was already removed'."
    reality: "That scenario cannot happen. There is no device-delete primitive, revocation only flips `revoked = 1`, and `revoke_device_and_bump_epoch` having succeeded proves the row exists, so the `devices.member_id` foreign key guarantees the member does too. The branch is legitimate future-proofing, but the justification given for it described a scenario that does not exist in this codebase."
    detection: reread
    evidence: null
    introduced_by: 524087a095a5c7079cb4f4a0a59026eac9b36d8f
    introduced_by_kind: original
    implementer_could_have_caught_by: "Before writing 'e.g. <scenario>' to justify a defensive branch, check whether that scenario is actually reachable given the schema's foreign keys and the primitives that exist today."
    td_ref: td-684764
  - id: F3
    severity: minor
    class: missing-guard
    file: null
    line: null
    claim: "`error = %e` logging the full `StoreError` at this call site is safe."
    reality: "That enum is not uniformly redaction-safe: `DeviceNotFound(Fingerprint)` renders the full untruncated base32, and `Confine` carries raw filesystem paths. It is safe here only because `member_for_device_fp` -> `get_member` can reach nothing but `Sqlite` and `CorruptFingerprint` — a reachability argument, not a type guarantee, and the same class of half-applied check that shipped a leak in e8480af. A sibling call site (authorize.rs) had already reasoned this out and carried a warning comment; this new site did not, until this correction."
    detection: reread
    evidence: null
    introduced_by: 524087a095a5c7079cb4f4a0a59026eac9b36d8f
    introduced_by_kind: original
    implementer_could_have_caught_by: "When logging an error enum's Display, check whether every reachable variant (not just the ones currently reachable through the call site in front of you) is redaction-safe, and add a comment naming the leaky variants so future widening of the call chain is flagged."
    td_ref: td-0bc380
---

## What the commit says

> Adversarial review of 524087a. No runtime defect — every line here is a
> comment. But all three were claims that would mislead the next reader, and
> two of them were mine.
>
> 1. The fail-open section overclaimed its scope. It argued as a blanket
>    principle that nothing running after the committed mutation may return
>    `Err`, while three lines below it `revoke_member_and_mint`'s
>    `get_member(member_id)?` fetch of `root_fp` does exactly that. The code is
>    right and the doc was wrong...
>
> 2. The device path justified its `member: None` fallback with "e.g. it was
>    already removed" — which cannot happen...
>
> 3. `error = %e` logs a whole `StoreError`, and that enum is not uniformly
>    redaction-safe... That is a reachability argument, not a type guarantee,
>    and it is the same class that shipped in e8480af.

## Reading

An adversarial review of 524087a (the commit that added the missing audit trail for revocations) found no runtime defect but three doc-comment claims that would mislead a future reader, two of which the author attributes to themselves. Two of the three are internal contradictions — a blanket rule stated in one place that the very next lines of code violate for a good reason, and a defensive branch justified by a scenario the schema makes impossible — and are low severity precisely because the code was already correct. The third (F3) is more substantive: it flags that a redaction-safety argument based on "what is reachable today" rather than "what the type guarantees" is the exact same reasoning shape that had already let a real leak ship in e8480af, and it corrects the new call site to carry the same warning comment a sibling call site (authorize.rs) had already worked out for itself. This is a comment-only correction, verified in the commit as mechanical (no added or removed line is anything but a comment or blank).
