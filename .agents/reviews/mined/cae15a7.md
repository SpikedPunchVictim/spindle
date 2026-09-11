---
review_id: cae15a7edb4caf9282b62dfd2fa956f36078c7df
date: 2026-09-02
ticket: td-ad1ca1
scope_commits: [cae15a7edb4caf9282b62dfd2fa956f36078c7df]
verdict: PARTIAL
provenance: mined-from-commit
fidelity: second-hand
source_note: "Gap identified during the review of 0280788/73d39b91 (73d39b91 records: 'One further gap it found is filed as td-ad1ca1 rather than folded in here: canonical_encode/encodeInto recurse with no depth guard of their own.'). Fixed here as a separate, deliberately-not-folded-in ticket."
findings:
  - id: F1
    severity: minor
    class: missing-guard
    file: null
    line: null
    claim: null
    reality: "Commit 0280788 bounded decode_one/decodeOne at MAX_NESTING_DEPTH = 32 because unbounded recursion on attacker-controlled CBOR overflows the stack, and a stack overflow aborts the process uncatchably. The encoders recursed on Array/Map with no guard at all. Not reachable today ... But CborValue and its array()/map() constructors are pub and re-exported, so the protection is incidental rather than defense in depth."
    detection: reread
    evidence: "with the encoder guard neutered, encode_panics_one_past_the_limit fails"
    introduced_by: 02807883421c5c984d1463ba1cb9b66f9a9654e8
    introduced_by_kind: unknown
    implementer_could_have_caught_by: "when bounding one side of a decode/encode pair against untrusted-input risk, check whether the paired direction (encode) shares the same unbounded recursion before closing the ticket"
    td_ref: td-ad1ca1
---

## What the commit says

> Commit 0280788 bounded `decode_one`/`decodeOne` at MAX_NESTING_DEPTH = 32
> because unbounded recursion on attacker-controlled CBOR overflows the stack,
> and a stack overflow aborts the process uncatchably (SIGABRT, exit 134;
> catch_unwind never fires). The encoders recursed on Array/Map with no guard
> at all.
>
> Not reachable today: every CborValue reaching an encoder either came from the
> now-bounded decoder or was built by this crate's flat struct-encoding code.
> But CborValue and its array()/map() constructors are pub and re-exported, so
> the protection is incidental rather than defense in depth — any future code
> that builds a tree from some other recursive input and encodes it hits the
> same uncatchable abort.

## Reading

While reviewing the decoder-side nesting-depth fix (0280788, corrected further
in 73d39b91), the reviewer noticed the encoders (`canonical_encode`,
`encodeInto`) recursed on the same Array/Map structure with no depth guard at
all — the fix had only closed the decode direction of a decode/encode pair
that shares the same recursive-abort risk. The commit is careful to note this
was not reachable through any code path that exists today, since every value
currently reaching the encoder is already depth-bounded by construction, but
`CborValue`'s constructors are public and re-exported, so the protection was
incidental rather than deliberate. This is filed as its own ticket
(td-ad1ca1) rather than folded into the earlier fix, and matches
`missing-guard`: the same invariant (a nesting ceiling) enforced on one side
of a symmetric pair and not the other.
