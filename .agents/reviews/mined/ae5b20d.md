---
review_id: ae5b20de34ce7a1b2c63e45471561bb45f3bd055
date: 2026-09-09
ticket: td-c9b9bd
scope_commits: [ae5b20de34ce7a1b2c63e45471561bb45f3bd055]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: "Explicit: \"Both found by the independent review of td-c9b9bd.\""
findings:
  - id: F1
    severity: nit
    class: wrong-mechanism
    file: null
    line: null
    claim: "with_transaction's panic = \"abort\" doc clause said an abort happens \"instead of reaching catch_unwind at all\"."
    reality: "The closure does run -- what never happens is the catching, because the process aborts before unwinding starts and there is nothing for catch_unwind to intercept."
    detection: reread
    evidence: null
    introduced_by: 32118b37c19add466ab410ff59695005007c3b2b
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "re-read the doc clause against what actually happens under panic=\"abort\" (the closure body runs to the panic point; only unwinding/catching is skipped) rather than describing the closure itself as skipped"
    td_ref: td-c9b9bd
  - id: F2
    severity: nit
    class: wrong-mechanism
    file: null
    line: null
    claim: "The clause named the hazard under panic=\"abort\" a \"mis-poisoned Store\"."
    reality: "That is the opposite failure. The mechanism exists to prevent an un-poisoned, stranded Store that reports success on writes which never become durable; a false poison (over-poisoning a recoverable store) is the other direction, and a_panic_inside_a_store_transaction_with_a_working_rollback_leaves_it_unpoisoned pins that other direction."
    detection: reread
    evidence: null
    introduced_by: 32118b37c19add466ab410ff59695005007c3b2b
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "check which specific failure direction (false-poison vs. false-not-poisoned) the doc clause under discussion is actually about before naming it, cross-referencing the test that pins the opposite direction"
    td_ref: td-c9b9bd
---

## What the commit says

> The clause said an abort happens "instead of reaching `catch_unwind` at all".
> The closure does run — what never happens is the catching, because the process
> aborts before unwinding starts and there is nothing for `catch_unwind` to
> intercept.
>
> It also named the hazard a "mis-poisoned Store". That is the opposite failure.
> The one this mechanism exists to prevent is an un-poisoned, stranded Store that
> reports success on writes which never become durable; a false poison is the
> other direction, and `a_panic_inside_a_store_transaction_with_a_working_
> rollback_leaves_it_unpoisoned` pins that.
>
> Both found by the independent review of td-c9b9bd. The substance erred
> conservative either way, but this ticket spent four rounds on prose that claimed
> more than the code did, so the clause should not add a fifth instance of it.

## Reading

Both findings are doc-comment-only errors in a clause written the previous round (32118b3), and both are the kind of small mechanistic misstatement that, if repeated, compounds: describing the closure as never running under `panic = "abort"` (when it runs up to the panic point) and naming the wrong direction of poisoning hazard (calling out over-poisoning when the mechanism exists to prevent under-poisoning) are exactly the sort of imprecision that this same ticket (td-c9b9bd) had already produced four rounds of corrections over. The commit itself frames this as a pattern: "this ticket spent four rounds on prose that claimed more than the code did."
