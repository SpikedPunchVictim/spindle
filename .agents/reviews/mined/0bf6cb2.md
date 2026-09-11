---
review_id: 0bf6cb2395b153ee0318245407ebb7583f491edb
date: 2026-09-04
ticket: td-9bf38d
scope_commits: [0bf6cb2395b153ee0318245407ebb7583f491edb]
verdict: REJECT
provenance: mined-from-commit
fidelity: second-hand
source_note: "Commit explicitly says 'open_or_resume, which the ticket does not mention and an audit found' — the audit is named as the source of this specific finding, separate from the ticket's original scope."
findings:
  - id: F1
    severity: reject
    class: missing-guard
    file: null
    line: null
    claim: "The identity cache correctly tracks a dirent's baseline across a stat/read followed by an upload to a fold-colliding spelling of the same name."
    reality: "A member stats or reads Photo.JPG, then uploads to photo.jpg, which (since b0c2f3f) overwrites that dirent and produces a new inode. forget(\"photo.jpg\") never cleared the \"Photo.JPG\" baseline, so the member's next read was refused denied:identity_changed / FileChanged for a change it had just made itself."
    detection: reread
    evidence: "Reverting the cache key fails the unit test and the end-to-end regression with `got Error { code: FileChanged }`, the exact signature from the ticket."
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "After a fix makes two spellings resolve to one dirent/inode, grep every cache or session map keyed on VirtualPath and confirm each uses a folded key rather than the literal one."
    td_ref: td-9bf38d
  - id: F2
    severity: reject
    class: missing-guard
    file: null
    line: null
    claim: "open_or_resume correctly resumes an in-progress upload session when a client re-opens the same target under a different but fold-colliding spelling."
    reality: "open_or_resume matched an existing session on `s.subpath == *subpath` (the literal spelling), so re-opening Photo.JPG as photo.jpg with the same size and hash opened a SECOND session instead of resuming — two sessions staging bytes for one dirent, the second's commit overwriting the first's, and aborting either leaving the other's staged bytes behind."
    detection: reread
    evidence: "Reverting the resume comparison opens a second session with a different id."
    introduced_by: null
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "Same check as F1: any subpath-keyed match/lookup for upload sessions needs to compare on the folded path, not `==` on the literal VirtualPath."
    td_ref: td-9bf38d
---

## What the commit says

> The identity cache: a member stats or reads Photo.JPG, then uploads to
> photo.jpg, which since b0c2f3f overwrites that dirent and produces a new
> inode. forget("photo.jpg") never cleared the "Photo.JPG" baseline, so the
> member's next read was refused denied:identity_changed / FileChanged for a
> change it had just made itself.
>
> open_or_resume, which the ticket does not mention and an audit found: it
> matched an existing session on `s.subpath == *subpath`, so re-opening
> Photo.JPG as photo.jpg with the same size and hash opened a SECOND session
> instead of resuming -- two sessions staging bytes for one dirent, the
> second's commit overwriting the first's, and aborting either leaving the
> other's staged bytes behind.
>
> Both now key through a new FoldedPath newtype and VirtualPath::folded().

## Reading

The ticket (td-9bf38d) named one shipped bug — the identity cache keying on the literal spelling — but an audit conducted while fixing it turned up a second, unticketed instance of the exact same root cause in `open_or_resume`: two spellings of one name could open two independent upload sessions for what is, since an earlier fix (b0c2f3f), a single dirent. The consequence is data loss (one session's commit silently overwrites the other, and aborting either strands the other's staged bytes). This is explicitly the audit-finds-a-second-unticketed-instance pattern the task's filing criteria call out, and it is the fifth instance in this range of the same "keyed on the literal path where evaluation folds" defect class (after SCHEMA_V7, SCHEMA_V8/11437a2e, and the two sites fixed here).
