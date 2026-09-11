---
review_id: e0ff2d6bc6eb226e3d9d33e164ade91e7ea4c3d8
date: 2026-09-03
ticket: td-2db67d
scope_commits: [e0ff2d6bc6eb226e3d9d33e164ade91e7ea4c3d8]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: "Commit does not use the word 'review'; it names the earlier commit (b0c2f3f) and describes the defect in its own account. Ambiguous whether this was caught by review or found by the implementer while building the next dependent feature (the disk-reconciliation sweep)."
findings:
  - id: F1
    severity: reject
    class: missing-guard
    file: null
    line: null
    claim: "b0c2f3f made `finalize_upload` rename the staged file onto the EXISTING dirent's name when the requested name fold-collides with one, correctly landing the fold-collision fix at the filesystem level."
    reality: "`finalize_upload` still returned a bare `bool`, so the caller never learned where the file actually landed; `server.rs` recorded `session.subpath` (the requested spelling) into the upload ledger. Uploading `photo.jpg` over an existing `Photo.JPG` on a case-sensitive filesystem left `uploaded_files.subpath` naming a path that does not exist on disk."
    detection: reread
    evidence: null
    introduced_by: b0c2f3f39472ae151189106b48b2e844e1cefe34
    introduced_by_kind: original
    implementer_could_have_caught_by: "After changing a function's return value to carry more information (bool -> enum with the landed name), grep every call site that previously used the bool to confirm none of them still records a value the new information should have replaced."
    td_ref: td-2db67d
---

## What the commit says

> `b0c2f3f` made `finalize_upload` rename the staged file onto the EXISTING
> dirent's name when the requested name fold-collides with one — but it still
> returned a bare `bool`, so the caller never learned where the file went.
> `server.rs` then recorded `session.subpath`, the requested spelling, into the
> upload ledger. Upload `photo.jpg` over an existing `Photo.JPG` on a
> case-sensitive filesystem and `uploaded_files.subpath` names a path that does
> not exist on disk.
>
> `finalize_upload` now returns `UploadOutcome::{Landed(OsString), Refused}`,
> where `Landed` carries the name it actually renamed onto, and the caller
> rebuilds the full virtual path with that final component before calling
> `record_upload`.
>
> This is a precondition for the disk-reconciliation sweep, not a fix for a live
> bug. Grepping every query against `uploaded_files` shows nothing reads the
> literal `subpath` column today — only `member_id`, `bytes` and `fold_subpath`
> are ever selected.

## Reading

b0c2f3f fixed the filesystem-level behavior of a fold-collision upload (rename onto the existing dirent) but left the ledger-recording half of the same operation reading the pre-fix value (the requested spelling) instead of the post-fix reality (the name it actually landed under). The commit is explicit that this had already shipped in a named prior commit and describes precisely how the two halves of one operation diverged — the write side was fixed, the record-keeping side was not. Notably the author frames it as "not a fix for a live bug" because nothing currently reads the stale column, but flags it as a landmine for the disk-reconciliation sweep being built next, which would otherwise stat a stale path, get ENOENT, and incorrectly delete-and-refund a file that is actually present under a different spelling. This is exactly the "fix one half of an invariant and miss the sibling" pattern this repo's commit history repeats several times (fold-key keying bugs across multiple layers).
