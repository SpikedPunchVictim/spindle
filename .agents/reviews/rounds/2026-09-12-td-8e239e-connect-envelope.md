---
review_id: 2026-09-12-td-8e239e-connect-envelope
date: 2026-09-12
ticket: td-8e239e
scope_commits: [c0b97d74bb7205c74d1e50dadb08c798c7c58cb5]
verdict: CLEAN
provenance: first-hand-report
fidelity: first-hand
source_note: "Written from the reviewer's own verbatim report at the time of the review. An independent adversarial sub-agent reviewed c0b97d7 (fix(td-8e239e): the 18,820 B figure was measured from an encoder nothing connects with) by attacking nine claims from the commit message. All nine survived, several by direct demonstration: CBOR key-order being a non-issue, the device encoders being byte-identical, the admission_token neuter reproduced, both session_attest negative tests discriminating, the canonical-bytes comparison, no pinned host-arm figure, no missed encoder copies, no dependency-cycle or layering violation, and the gate numbers reproduced at 899/0/17. Reviewer's verdict, verbatim: \"Nothing at reject. Nothing at minor. Every attackable claim in that message survived, several by direct demonstration.\" Two nits followed, both fixed in 2d0b7a9681f40a8198a9c1bdc49f1d9e8329f582. The nine surviving attacks are logged in the record body because a corpus of only-defects would overstate how often review finds one."
findings:
  - id: N1
    severity: nit
    class: stale-doc-row
    file: crates/spindle-test-fixtures/Cargo.toml
    line: 1
    claim: "the crate's own header says it \"exists solely to be a `[dev-dependencies]` entry of other crates' integration tests\" and enumerates them: \"(`spindle-net`'s `tests/live_signaling.rs`, and `spindle-hostd`'s own live test)\". The same text is in `src/lib.rs:1-3`."
    reality: "The commit added a third consumer -- and it is a unit test in `src/`, not an integration test. The commit updated `spindle-helper`'s Cargo.toml and module doc in both directions but left the fixtures crate's own self-description one consumer behind."
    detection: reread
    evidence: "The third consumer is `crates/spindle-helper/src/auth_token.rs`, whose tests live in `#[cfg(test)] mod tests` inside `src/`, not in `tests/`. When scoping the fix the implementer found a further error in their own first count: `pg_store.rs` also matches `spindle_test_fixtures`, but only as a database-name string in test data (`parse_database_name(\"postgres://.../spindle_test_fixtures\")`), so it is not a consumer. Verified by `git grep`: three consumers, not four -- `crates/spindle-net/tests/live_signaling.rs` and `crates/spindle-hostd/tests/live_hostd.rs` (integration, live stack) and `crates/spindle-helper/src/auth_token.rs` (unit tests in `src/`)."
    introduced_by: c0b97d74bb7205c74d1e50dadb08c798c7c58cb5
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "when a commit adds a consumer to a shared crate, re-read that crate's own self-description in the same commit -- the doc most likely to rot is the one in the file the change does not touch"
    td_ref: td-8e239e
  - id: N2
    severity: nit
    class: stale-line-citation
    file: crates/spindle-helper/src/auth_token.rs
    line: 87
    claim: "\":87\" reads \"Caps are embedded as CBOR byte strings (see `fixtures::device_auth_token` above)\"."
    reality: "It is not above; it is `spindle_test_fixtures::fixtures::device_auth_token`. Harmless (not an intra-doc link, so nothing breaks), but the spatial word was carried over from the deleted local function."
    detection: reread
    evidence: "c0b97d7 deleted the local `encode_device_token`, which the word \"above\" had correctly pointed at. A sibling reference at `:70` had the same unqualified path. Both now spell the full cross-crate path."
    introduced_by: c0b97d74bb7205c74d1e50dadb08c798c7c58cb5
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "grep the deleted symbol's own doc neighbourhood for spatial words -- above, below, in this module -- whenever a definition moves to another crate; the compiler cannot see them because they are prose, not intra-doc links"
    td_ref: td-8e239e
---

## What the reviewer reported

The review set out to attack nine specific claims made by c0b97d7's commit message
and could not land a single one. Each survived by direct demonstration rather than by
absence of an attempt: CBOR key-order was shown to be a non-issue, the device encoders
were confirmed byte-identical, the `admission_token` neuter was reproduced, both
`session_attest` negative tests were shown to discriminate, the canonical-bytes
comparison held, no pinned host-arm figure was found lurking anywhere in the tree, no
encoder copy was missed, no dependency-cycle or layering violation was introduced, and
the gate numbers reproduced exactly at 899/0/17. The reviewer's own summary was blunt:
"Nothing at reject. Nothing at minor. Every attackable claim in that message survived,
several by direct demonstration."

What the review did find were two nits, both about prose rot rather than code. N1 is a
self-description one release behind: the fixtures crate's own header still enumerated
two integration-test consumers when the commit had just added a third, and that third
consumer isn't even the same shape as the other two -- it's a unit test living in `src/`,
not `tests/`. The implementer's own re-count while fixing it turned up a further wrinkle
in the same direction: a string literal in `pg_store.rs` matches the crate's name but is
just test data, not a consumer, and would have inflated the count to four if taken at
face value. N2 is smaller still -- a doc comment's "above" survived the deletion of the
local function it used to point at, now pointing across a crate boundary at nothing in
particular, but semantically compatible enough (not an intra-doc link) that nothing
actually breaks.

## Reading

This record exists specifically to hold the nine surviving attacks alongside the two
nits, because a corpus built only from commits that failed review would make failure
look like the norm. Here the heavier claims -- the ones with numbers and byte-identity
checks behind them -- were exactly the ones the implementer had already verified
carefully. What rotted were the two kinds of prose that don't get re-read once the
diff that would invalidate them lands somewhere else: a crate's self-description, and
a spatial word ("above") in a doc comment whose target moved. Both nits were fixed in
2d0b7a9681f40a8198a9c1bdc49f1d9e8329f582.
