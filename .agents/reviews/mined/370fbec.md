---
review_id: 370fbec8120e710e58510ca6b25289a94036029b
date: 2026-09-02
ticket: td-2454b3
scope_commits: [370fbec8120e710e58510ca6b25289a94036029b]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: "Fix for a real concurrency defect surfaced by the 2026-09-02 bug hunt (td-2454b3, tracked in 288b608); the commit also corrects its own earlier probe's methodology."
findings:
  - id: F1
    severity: reject
    class: missing-guard
    file: null
    line: null
    claim: null
    reality: "add_share ran four read-based checks ... and then issued INSERT INTO shares with no transaction spanning them. Every statement autocommitted, nothing held a lock across the gap, and two concurrent callers both scanned, both saw no conflict, and both committed."
    detection: empirical
    evidence: "A scan sees [] ; B scan sees [] -> both find no conflict / A insert -> OK / B insert -> OK *** BOTH COMMITTED *** / final rows: [(1,'/pub','/srv/data'), (2,'/pub/sub','/srv/data/inner')]"
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "race two concurrent add_share calls against one Store file with overlapping-but-not-identical mount paths and confirm exactly one wins, rather than relying on the UNIQUE index on mount_path, which only catches exact-equality collisions"
    td_ref: td-2454b3
  - id: F2
    severity: minor
    class: unsound-search-receipt
    file: null
    line: null
    claim: "this finding's original probe claimed to mirror Store::open \"exactly\" while passing timeout=0"
    reality: "rusqlite sets a 5 s busy timeout on open. Re-run at timeout=5.0, both inserts still commit, so the finding survives on corrected evidence. The busy timeout is irrelevant here: the two inserts never contend, each taking and releasing its own write lock, so nothing ever blocks."
    detection: empirical
    evidence: null
    introduced_by: 288b608eefeb4357608bc673224fa034d42a58ed
    introduced_by_kind: original
    implementer_could_have_caught_by: "match every parameter of the real Store::open call, including its busy_timeout, before describing a probe as mirroring that call exactly"
    td_ref: null
---

## What the commit says

> `add_share` ran four read-based checks -- share-count limit, exclude-count
> limit, real_root overlap via a full list_shares() scan, and mount_path
> collision via that same scan -- and then issued INSERT INTO shares with no
> transaction spanning them. Every statement autocommitted, nothing held a
> lock across the gap, and two concurrent callers both scanned, both saw no
> conflict, and both committed.
>
> Reproduced with a python sqlite3 probe using the same 5000 ms busy timeout
> and true autocommit rusqlite uses:
>
>     A scan sees [] ; B scan sees []  -> both find no conflict
>     A insert -> OK
>     B insert -> OK  *** BOTH COMMITTED ***
>     final rows: [(1,'/pub','/srv/data'), (2,'/pub/sub','/srv/data/inner')]
>
> ...
>
> Note on provenance: this finding's original probe claimed to mirror
> Store::open "exactly" while passing timeout=0, which was wrong -- rusqlite
> sets a 5 s busy timeout on open. Re-run at timeout=5.0, both inserts still
> commit, so the finding survives on corrected evidence. The busy timeout is
> irrelevant here: the two inserts never contend, each taking and releasing
> its own write lock, so nothing ever blocks. The defect is the unlocked gap
> between scan and insert. The related td-f65637 "no busy_timeout" finding was
> false and has been retracted; this one is not it.

## Reading

The bug-hunt found a genuine check-then-act race in `Store::add_share`:
four read-based validation checks and the eventual insert ran as separate
autocommit statements with no transaction spanning them, so two concurrent
callers could both pass validation against stale reads and both commit,
producing overlapping shares the checks existed to prevent — a clean
`missing-guard` case, confirmed with a reproducing probe and a real
concurrency regression test (8/10 failing runs without the fix, 20/20
passing with it). The commit separately corrects its own earlier probe,
which had claimed to mirror the real `Store::open` call "exactly" while
actually passing a different busy-timeout value than production uses; the
underlying finding survives re-verification at the correct value, but the
receipt supporting it was initially unsound.
