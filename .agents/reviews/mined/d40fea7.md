---
review_id: d40fea7eae794009336336d846e5ab3d49b05f6f
date: 2026-09-09
ticket: td-c9b9bd
scope_commits: [d40fea7eae794009336336d846e5ab3d49b05f6f]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: "The commit does not attribute this to an external reviewer; it reads as the implementer's own follow-up audit of 618318a, measured with an authorizer-denial harness. Filed as the implementer's own audit."
findings:
  - id: F1
    severity: reject
    class: unverified-coverage-claim
    file: null
    line: null
    claim: "618318a's verification -- checking that all 26 Store write methods call check_not_poisoned() -- established that a stranded connection could no longer report a durable-looking success."
    reality: "That verification only proved which paths *read* the poison flag; it never asked which paths could *set* it. The flag was set from exactly one site (Audit::recover_from_non_autocommit, reachable only from Audit::append). Ten Store methods open their own transaction and end with tx.commit()?, and rusqlite 0.32.1's Transaction::drop retries ROLLBACK under #[allow(unused_must_use)] and discards the error, so a failed commit or an early `?` inside the body left is_autocommit() == false with the flag unset. Measured: with an authorizer denying `UPDATE members` and `ROLLBACK`, revoke_member_and_bump_epoch returns Err and leaves is_poisoned() == false; the next bump_cap_epoch() returns Ok(1); the reopened file still reads cap_epoch = 0."
    detection: empirical
    evidence: "authorizer-denial harness: revoke_member_and_bump_epoch -> Err, is_poisoned() == false; bump_cap_epoch() -> Ok(1); reopened file cap_epoch = 0"
    introduced_by: 618318a951c9fe631bb9ab4bb7bf0f80ad52c585
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "enumerate every site that CAN set is_autocommit() to false (every transaction-opening method), not only the sites that read the poison flag, before declaring the flag's coverage complete"
    td_ref: td-c9b9bd
---

## What the commit says

> 618318a (td-c9b9bd) added a poison flag so a connection stranded inside an
> un-ended SQLite transaction refuses every subsequent write instead of running
> it inside that transaction and reporting a success that is never durable. It
> guarded the entry of all 26 write paths, but set the flag from exactly one
> site — `Audit::recover_from_non_autocommit`, reachable only from
> `Audit::append`.
>
> Ten `Store` methods open their own transaction and end with `tx.commit()?`.
> rusqlite 0.32.1's `Transaction::drop` retries `ROLLBACK` under
> `#[allow(unused_must_use)]` and discards the error, so a failed commit or an
> early `?` inside the body leaves `is_autocommit() == false` with the flag
> unset. Measured, with an authorizer denying `UPDATE members` and `ROLLBACK`:
> `revoke_member_and_bump_epoch` returns `Err` and leaves `is_poisoned() ==
> false`; the next `bump_cap_epoch()` returns `Ok(1)`; the reopened file still
> reads `cap_epoch = 0`. That is the exact defect the ticket exists to close,
> on a path the fix never touched, and none of that commit's four tests reach it.
>
> The flaw in the original verification is worth naming: checking that all 26
> write methods call `check_not_poisoned` only proved which paths *read* the
> flag. It never asked which paths can *set* it.

## Reading

This is a clean case of a coverage claim ("all 26 write paths" guarded) being true on one axis and silently false on the orthogonal one: 618318a verified that every write path *checked* the poison flag before proceeding, but never verified that every path capable of stranding the connection could actually *set* that flag. The result reproduced the exact defect the original ticket existed to close — a write reporting success while its effect was rolled back on reopen — on a code path the original fix never touched, and none of that commit's own tests exercised it. The self-critique in the commit ("only proved which paths *read* the flag... never asked which paths can *set* it") is a precise statement of the coverage-claim failure and is why this record uses `unverified-coverage-claim` rather than a plain `missing-guard`: the guard existed everywhere it needed to be checked, but not everywhere it needed to be armed.
