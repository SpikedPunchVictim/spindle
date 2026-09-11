---
review_id: d539bbff33629a34f87e536a63283db3be3da5f8
date: 2026-09-11
ticket: td-ef5744
scope_commits: [d539bbff33629a34f87e536a63283db3be3da5f8]
verdict: PARTIAL
provenance: mined-from-commit
fidelity: second-hand
source_note: "Explicit: \"Two corrections independent review raised against v0.9.36.\" The review approved the custody decision itself; these two findings are about the document's presentation of it."
findings:
  - id: F1
    severity: minor
    class: false-absence-claim
    file: null
    line: null
    claim: "DESIGN.md's running per-version summary block accurately reflected which version was current, through v0.9.35."
    reality: "The block carried an entry for every release through v0.9.35 -- including both prior no-figure-change ones -- but none for v0.9.36. A reader trusting that block would have concluded v0.9.35 was current."
    detection: reread
    evidence: null
    introduced_by: 94ebe19fa2e4d96cd72d1b8574337b624c8b911d
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "check that the running summary block gained an entry for every version bump, including no-figure-change ones, as part of finishing that version's amendment -- the two prior no-figure-change releases had entries, so the omission was inconsistent with the document's own established pattern"
    td_ref: td-ef5744
  - id: F2
    severity: minor
    class: unverified-code-claim
    file: crates/spindle-helper/src/authz.rs
    line: 630
    claim: "The custody argument's load-bearing claim -- host_fp *is* root_fp -- was authoritatively established by a workspace test fixture."
    reality: "The claim is true, but this workspace's recorded lesson is that a test reproducing a rule proves only that the test matches the rule -- a normative claim must trace to the production code that makes it true. It now cites the live helper authorization path (crates/spindle-helper/src/authz.rs:630), with the fixture demoted to an illustration."
    detection: trace
    evidence: null
    introduced_by: 94ebe19fa2e4d96cd72d1b8574337b624c8b911d
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "when citing authority for a normative design claim, trace to the production code path that enforces it, not to a test fixture that merely reproduces the rule -- a fixture proves the test agrees with the rule, not that production code implements it"
    td_ref: td-ef5744
---

## What the commit says

> The running per-version summary block carried an entry for every release
> through v0.9.35 — including both prior no-figure-change ones — but none
> for v0.9.36. A reader trusting that block would have concluded v0.9.35
> was current. Entries for v0.9.36 and v0.9.37 added.
>
> The custody argument's load-bearing claim, `host_fp` *is* `root_fp`,
> cited a TEST FIXTURE as its authority. The claim is true, but this
> workspace's recorded lesson is that a test reproducing a rule proves only
> that the test matches the rule — a normative claim must trace to the
> production code that makes it true. It now cites the live helper
> authorization path (`crates/spindle-helper/src/authz.rs:630`), with the
> fixture demoted to an illustration.

## Reading

Neither finding touches the substance of the custody decision the review approved; both are about how the document supports and presents that decision. The changelog omission is a small but real defect — a reader trusting the document's own running-summary convention would have been misled about which version was current, an omission inconsistent with how the two previous no-figure-change releases had been recorded. The citation-authority correction is more consequential in kind: it is the second appearance in this range of a recorded workspace lesson (a test reproducing a rule proves only that the test matches the rule, not that production code enforces it) being violated and then caught — here, a load-bearing normative claim in DESIGN.md cited a test fixture as its authority when it should have cited the actual production code path (`spindle-helper/src/authz.rs:630`) that makes the claim true.
