---
review_id: 5f0fa3a3e2c32f461c89fd1b60d8168628141eeb
date: 2026-09-07
ticket: td-6c9d95
scope_commits: [5f0fa3a3e2c32f461c89fd1b60d8168628141eeb]
verdict: PARTIAL
provenance: mined-from-commit
fidelity: second-hand
source_note: "Found while systematically instrumenting the crate's 'genuinely silent failures' as step 2 of td-6c9d95 — the implementer's own audit of existing failure-handling code, not an external review request."
findings:
  - id: F1
    severity: minor
    class: missing-guard
    file: null
    line: null
    claim: "A failed rollback in the audit log's append path is a benign edge case."
    reality: "The most serious site was an unguarded `let _ = self.conn.execute_batch(\"ROLLBACK\")` in the audit log's own append path. Audit and Store share one connection, so a failed rollback strands it mid-transaction: later writes execute inside that stranded transaction rather than autocommitting, can appear to succeed while being undurable, and are lost silently on a crash before some later commit. That is the precise inconsistency a tamper-evident hash-chained audit log exists to surface, and it was invisible."
    detection: reread
    evidence: null
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "Audit every `let _ = ...` swallowing a Result on a shared database connection, and ask specifically what state the connection is left in if that particular call fails, not just whether the immediate caller can tolerate the failure."
    td_ref: td-6c9d95
  - id: F2
    severity: minor
    class: missing-guard
    file: null
    line: null
    claim: "list_dir's handling of unreadable or unnameable directory entries is acceptable because such entries are rare."
    reality: "list_dir silently dropped directory entries it could not read or name. Users saw an incomplete listing with nothing indicating anything was hidden — the same shape as the Windows bug that once dropped every directory."
    detection: reread
    evidence: null
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "For any loop that silently `continue`s past an unreadable item, add a counter and log a summary, since a silently incomplete listing is indistinguishable from a correct empty one to the caller."
    td_ref: td-6c9d95
---

## What the commit says

> The most serious site was an unguarded `let _ = self.conn.execute_batch("ROLLBACK")`
> in the audit log's own append path. Audit and Store share one connection, so
> a failed rollback strands it mid-transaction: later writes execute inside
> that stranded transaction rather than autocommitting, can appear to succeed
> while being undurable, and are lost silently on a crash before some later
> commit. That is the precise inconsistency a tamper-evident chain exists to
> surface, and it was invisible. Now `error!`, carrying both the rollback error
> and the append error that provoked it.
>
> `list_dir` silently dropped directory entries it could not read or name.
> Users saw an incomplete listing with nothing indicating anything was hidden —
> the same shape as the Windows bug that once dropped every directory.

## Reading

While systematically instrumenting the crate's silent failure points (an explicit, deliberate pass — "eight call sites, chosen rather than sprinkled" — rather than incidental discovery), the implementer found that a failed rollback in the audit log's own append path could strand the shared Store connection mid-transaction, making later writes silently non-durable in exactly the scenario a tamper-evident, hash-chained audit log exists to detect. The commit frames this as the single most serious of the audit's findings. A second, lower-severity finding is that `list_dir` had been silently dropping unreadable directory entries with no signal to the caller — the commit explicitly compares its shape to "the Windows bug that once dropped every directory" (fixed earlier in this repo's history), i.e. a previously-fixed defect class recurring in a milder, still-silent form. Both are existing, already-shipped behaviors surfaced by a systematic audit of failure paths rather than defects introduced by this commit itself.
