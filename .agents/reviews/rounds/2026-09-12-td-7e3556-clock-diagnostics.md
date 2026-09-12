---
review_id: 2026-09-12-td-7e3556-clock-diagnostics
date: 2026-09-12
ticket: td-7e3556
scope_commits: [67d89b68b78bf3241157e22e12b4ab13e931332d, 390d1fbec673c6479a745f32e85ee34bc5df1435, 9d7cb6a513f6585938938d75e2f8ca365b8c454e]
verdict: REJECT
provenance: first-hand-report
fidelity: first-hand
source_note: "Written from the reviewer's verbatim report. An independent adversarial sub-agent reviewed the three A10.42 cold-clock-diagnostics commits and rejected the third: 2 HIGH, 1 MEDIUM, 1 LOW, 4 nits. Its verdict line: 'Two of the three commits are solid. 9d7cb6a's guard relaxation is not -- it opened two holes in the security guards it claims to have proven safe.' Both HIGH findings were reproduced first-hand by the implementer, in both directions (planted probe GREEN under the relaxed guard, RED under the pre-relaxation guard at 390d1fb), before anything was changed. Fixed in 9c55fee. The reviewer also listed TEN claims it attacked that SURVIVED, each with evidence, including a 20,477-input cross-language differential with 0 disagreements and 0 panics, an exhaustive containment audit of ClockOffset in both languages, and independent reproduction of every gate figure in all three commit messages. Its own closing caveat, quoted because it is the right one: 'finding 1 is an agreement result against a sibling implementation written from the same brief. A rule both parsers get wrong identically is invisible to it by construction.'"
findings:
  - id: F1
    severity: reject
    class: false-green
    file: crates/spindle-core/tests/clock_source_guard.rs
    line: 174
    claim: "9d7cb6a's message: 'Relaxing a security guard demands proof it opened no hole, so both guards gained two tests: one asserting EVERY real forbidden form is still caught, one per pattern so a pattern that stops matching fails by name.'"
    reality: "The identifier-boundary check applied BOTH halves of the boundary unconditionally, so any forbidden pattern that is a PREFIX of a longer real name stopped matching. `FORBIDDEN_PATTERNS` contains `\"OffsetDateTime::now\"`, and the `time` crate's only two real ambient reads are `now_utc()` and `now_local()` -- both continue the identifier past `now`, so `after_ok` is false and the guard reports nothing. The test written to prove otherwise used the fixture `OffsetDateTime::now()`, which is not a `time` crate API: it is the one form for that pattern the bug did NOT blind, so the test stayed green while both real forms went dark. A correct, discriminating assertion over a fixture that could not fail -- inside the test added specifically to rule that out."
    detection: empirical
    evidence: "Planting `OffsetDateTime::now_utc()` and `now_local()` as live code in crates/spindle-core/src/artifacts/mod.rs: guard at 9d7cb6a -> 'test result: ok. 4 passed; 0 failed'. Pre-relaxation guard at 390d1fb, byte-identical source -> 'artifacts_never_read_an_ambient_clock ... FAILED', naming `OffsetDateTime::now` at the planted line. Reproduced first-hand in a throwaway git worktree, removed after."
    introduced_by: 9d7cb6a513f6585938938d75e2f8ca365b8c454e
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "build a guard's positive fixture from the REAL API names the pattern is meant to cover, looked up rather than recalled -- and when a pattern is a prefix of the names it targets, that is the case the fixture must contain, because it is the only one the boundary rule can break"
    td_ref: td-7e3556
  - id: F2
    severity: reject
    class: false-green
    file: crates/spindle-core/tests/clock_source_guard.rs
    line: 298
    claim: "clock_source_guard.rs's doc: 'Proves that no artifact validity path in spindle-core NAMES one of A10.42's diagnostic-only clock symbols as real code -- the structural half of \"the offset is diagnostic only\".'"
    reality: "`DIAGNOSTIC_ONLY_SYMBOLS` received the identical relaxation with ZERO positive coverage -- both new tests scanned `FORBIDDEN_PATTERNS` only. The list contains the stem `\"diagnose_clock\"` but not `diagnose_clock_from_capabilities`, leg (1)'s bundle entry point and the single most likely symbol for someone to fold into an `exp` check; before the relaxation the stem caught it as a substring, after it the trailing `_` killed the match. Same for `\"HttpsDateSource\"` vs `HttpsDateSourceError`. So 9d7cb6a's claim that 'both guards gained two tests ... EVERY real forbidden form is still caught' was true of one list and silently false of the other."
    detection: empirical
    evidence: "TypeScript, end to end: the reviewer appended a real `verifyCapabilityWithClockHelp` to packages/crypto/src/artifacts.ts, folding a diagnostic offset straight into `verifyCapability`'s `now` -- exactly what A10.42 forbids, with no forbidden symbol spelled anywhere, since TS is structurally typed and `ClockOffset`/`ClockDiagnosis` never need naming. Guard reported '4 passed'. Reproduced first-hand in Rust too (planted `diagnose_clock_from_capabilities` and `HttpsDateSourceError`: 4 passed at 9d7cb6a, 2 FAILED at 390d1fb), and the TS case re-run after the fix reddens naming artifacts.ts:626."
    introduced_by: 9d7cb6a513f6585938938d75e2f8ca365b8c454e
    introduced_by_kind: correction-commit
    implementer_could_have_caught_by: "when one change is applied to two lists, the proof must cover both lists -- an aggregate claim of 'both guards gained tests' is not the same as each list having a positive half, and the unproved one is where the hole will be"
    td_ref: td-7e3556
  - id: F3
    severity: minor
    class: unverified-code-claim
    file: docs/DESIGN.md
    line: 1628
    claim: "A10 row 42, normative and present-tense: 'before minting a SessionAttestation, a client ALWAYS RUNS a local bound check against the signed ts lower bound every HostOpKeyCert in its bundle already carries'. crates/spindle-core/src/lib.rs:20 calls it 'the always-on local clock bound check'."
    reality: "Nothing calls it, in either language. Excluding the defining modules and their tests, the only two hits are re-export lines (crates/spindle-core/src/lib.rs:56 and packages/crypto/src/index.ts:73). No SessionAttestation minting path consults it -- not artifacts/session_attest.rs, not host_session_attest.rs, not spindle-helper/src/authz.rs. The DESIGN text is AHEAD of the implementation rather than contradicted by it, which is the honest framing: both legs and both twins are implemented, tested and gated, and the client WIRING is absent. Consequence: td-7e3556's acceptance item 4 (a hostile time source must cause a REFUSAL, never an ACCEPTANCE) is not constructible, because there is no path on which a hostile source could cause either outcome. The two guard scans were standing in for that proof -- and F1/F2 show they could be walked past."
    detection: search
    evidence: "git grep -n 'diagnose_clock_from_capabilities|diagnoseClockFromCapabilities|diagnose_clock(|diagnoseClock(' -- crates packages apps spikes, minus the defining modules and their tests, returns exactly two re-export lines. Re-run first-hand at 036beed. Filed as td-f3d7fa; td-7e3556 is blocked on it."
    introduced_by: null
    introduced_by_kind: original
    implementer_could_have_caught_by: "a DESIGN sentence in the present tense ('a client always runs X') is a claim about shipped code; grep for a CALLER of X, not for X, before treating the sentence as satisfied by a library function existing"
    td_ref: td-f3d7fa
  - id: F4
    severity: nit
    class: unverified-coverage-claim
    file: crates/spindle-core/src/lib.rs
    line: 55
    claim: "The two implementations are presented throughout the commit messages as twins of one API."
    reality: "spindle-core's crate root re-exported leg (2) -- diagnose_clock_from_https, offset_from_date_header and the error types -- but NEITHER leg (1) entry point, while @spindle/crypto's index.ts exported both diagnoseClock and diagnoseClockFromCapabilities. A downstream Rust crate had to reach through spindle_core::clock_diagnostics:: for the 'always-on' check while leg (2) sat at the crate root. Nothing in the commit messages disclosed the asymmetry. Fixed in 9c55fee."
    detection: reread
    evidence: "Compared crates/spindle-core/src/lib.rs:55-58 against packages/crypto/src/index.ts:68-80 directly; the TS side also exports ClockDiagnosis and HttpsDateSource as types, so the surfaces now match."
    introduced_by: 390d1fbec673c6479a745f32e85ee34bc5df1435
    introduced_by_kind: original
    implementer_could_have_caught_by: "when two implementations are claimed to be twins, diff their EXPORT surfaces as a list, not their behaviour -- parity of behaviour was tested exhaustively here while parity of API was never looked at"
    td_ref: td-7e3556
  - id: N1
    severity: nit
    class: unverified-coverage-claim
    file: packages/crypto/src/clock-diagnostics.ts
    line: 232
    claim: "9d7cb6a's message: 'the Rust test ... has no analogue and was not invented.'"
    reality: "Above i64::MAX the two languages report different numbers for the same input: Rust saturates (9223372036854775807), TypeScript's unbounded bigint reports the exact value (18446744073709551615). Over a 7,500-case differential, 1,069 cases disagreed, ALL in exactly this class -- same kind, same bound_ts, only the offset differing. The divergence IS disclosed in the source and the property that matters (the offset never flips sign) holds. But no TypeScript test pins it, so declining to invent an analogue left the divergence unguarded rather than accepted-and-pinned. Second instance in the same finding: offset_from_date_header's Rust doc says a 4-digit year keeps both server_unix and local_now inside i64 -- true of server_unix, which the parser bounds, and not of caller-supplied local_now, where u64::MAX saturates to a fixed -9223372036070664030."
    detection: empirical
    evidence: "Reviewer's 7,500-case cross-language differential. Filed as td-fc3b88."
    introduced_by: 9d7cb6a513f6585938938d75e2f8ca365b8c454e
    introduced_by_kind: original
    implementer_could_have_caught_by: "'this test has no analogue in the other language' is a statement that a property is unpinned there; either pin it or say in the source that it is deliberately unpinned and why"
    td_ref: td-fc3b88
  - id: N2
    severity: nit
    class: missing-guard
    file: packages/crypto/src/clock-diagnostics.ts
    line: null
    claim: "The TypeScript twin mirrors the Rust API."
    reality: "Rust takes u64, so negative inputs are unrepresentable at the type level. The TS twin takes bigint and does not check: diagnoseClock(-1n, [0n], []) returns ProvablyBehind with behindBy = 1, and diagnoseClock(0n, [], [-5n]) returns Ambiguous. Unchecked and untested -- a guarantee the Rust side gets from its types has no counterpart on the side that does not."
    detection: empirical
    evidence: "Reviewer ran both calls directly. Filed as td-fc3b88."
    introduced_by: 9d7cb6a513f6585938938d75e2f8ca365b8c454e
    introduced_by_kind: original
    implementer_could_have_caught_by: "when porting an API from a language with a narrower type to one with a wider type, enumerate what the narrower type was ENFORCING and re-enforce it explicitly -- the port silently drops every guarantee that lived in the signature"
    td_ref: td-fc3b88
  - id: N3
    severity: nit
    class: spec-cannot-execute
    file: crates/spindle-core/src/clock_diagnostics.rs
    line: null
    claim: "HttpsDateSource::fetch_date_header asks an implementer for 'the raw Date response-header value'."
    reality: "The parser rejects any optional whitespace -- ' Sun, 06 Nov 1994 08:49:37 GMT' returns Err(InvalidLength { len: 30 }) -- and nothing in the trait contract tells an implementer to trim, though HTTP header values may carry leading or trailing OWS. The failure is SAFE (no offset, and an offset is diagnostic only), so the worst outcome is silently no diagnostic rather than a wrong one. Labelled ARGUED. Filed as td-2601e5."
    detection: empirical
    evidence: "Reviewer ran the leading-space input against the parser."
    introduced_by: 390d1fbec673c6479a745f32e85ee34bc5df1435
    introduced_by_kind: original
    implementer_could_have_caught_by: "a trait that asks a caller for a value from an external protocol must say which normalisations the caller owns; 'raw' names the source, not the required shape"
    td_ref: td-2601e5
  - id: N4
    severity: nit
    class: stale-line-citation
    file: docs/DESIGN.md
    line: 1235
    claim: "DESIGN cites spindle-proto/src/artifacts.rs:412 for Capability's op_cert (at :1235 and :2006) and :949 for HostOpKeyCert's ts (at :1628 and :2004)."
    reality: "op_cert is at :421 (struct Capability at :417); ts is at :958 (struct HostOpKeyCert at :956). Introduced in v0.9.32, untouched by these commits. Worth recording: the REVIEWER's own replacement for the first citation was itself wrong -- it said 419, which is `pub host_fp: Vec<u8>,`, a real field of the right struct. A near-miss line citation is worse than an absent one for exactly that reason, and the error class reproduced itself inside the report that found it."
    detection: reread
    evidence: "grep -n '^pub struct' crates/spindle-proto/src/artifacts.rs | awk -F: '$1<=421' | tail -1 -> 417:pub struct Capability {; sed -n '421p' -> '    pub op_cert: Vec<u8>,'. Same method for 956/958. Verified first-hand at 036beed, which is how the reviewer's 419 was caught. Filed as td-7080c2."
    introduced_by: null
    introduced_by_kind: original
    implementer_could_have_caught_by: "cite a field name and struct, not a line offset; the corpus now has nine instances of this class and every one rotted the same way"
    td_ref: td-7080c2
---

## What the reviewer reported

Two of the three commits under review survived intact. The third, `9d7cb6a`, was rejected
on two HIGH findings that are the same defect in two lists, and it is the most instructive
entry in this corpus so far because of what the commit was *for*.

`9d7cb6a` existed to fix a guard bug. The guards scanned masked source with a raw
substring search, so `chrono` matched inside `synchronous` and `new Date` matched inside
`new DateHeaderError` -- which had forced production TypeScript to route all ten of its
`DateHeaderError` constructions through a `private static make(...)` indirection purely to
avoid spelling a forbidden substring. The right call was made: fix the guard, not the code
it was distorting. The fix added an identifier-boundary check.

It applied both halves of that boundary unconditionally, and the two halves are not equally
safe. Requiring the byte BEFORE a match to be a non-identifier byte only ever removes false
positives. Requiring the byte AFTER is the half that can make a guard blind -- and it did,
to every forbidden pattern that is a *prefix* of a longer real name. `OffsetDateTime::now`
stopped matching `now_utc()` and `now_local()`, the `time` crate's only real ambient reads.
`diagnose_clock` stopped matching `diagnose_clock_from_capabilities`, leg (1)'s bundle entry
point. `HttpsDateSource` stopped matching `HttpsDateSourceError`.

The commit message anticipated exactly this risk -- "Relaxing a security guard demands proof
it opened no hole" -- and shipped tests for it. The Rust positive test's fixture said
`OffsetDateTime::now()`, which is not a `time` crate API: it was the one form for that
pattern the bug did not blind, so the test passed while both real forms went dark. That is
this repo's own "a correct assertion can have an unfailable fixture" class, occurring inside
the test written specifically to rule it out. And `DIAGNOSTIC_ONLY_SYMBOLS` received the
identical relaxation with no positive coverage at all -- so "both guards gained two tests
... EVERY real forbidden form is still caught" was true of one list and silently false of
the other, which is where the worse hole was.

The TypeScript demonstration is the one to remember. The reviewer appended a real
`verifyCapabilityWithClockHelp` to `src/artifacts.ts` that folds a diagnostic clock offset
straight into `verifyCapability`'s `now` -- precisely the acceptance-instead-of-refusal that
A10.42 exists to forbid -- and the guard reported 4 passed. TypeScript is structurally
typed, so neither `ClockOffset` nor `ClockDiagnosis` ever needs to be named; the only thing
standing between that code and the repo was a symbol scan that had just gone blind to the
function's name.

F3 is the finding with the longest tail. A10.42 says a client "always runs" the local bound
check before minting a `SessionAttestation`, and `lib.rs:20` calls it "the always-on local
clock bound check" -- but nothing calls it in either language; the only two grep hits are
re-export lines. Both legs, both twins, all the tests and both guards are real work that
landed; the client wiring is not. That makes `td-7e3556`'s acceptance item 4 -- a hostile
time source must cause a refusal and never an acceptance -- impossible to write, because no
path exists on which a hostile source could cause either. The guards were the stand-in for
that proof, which is why F1 and F2 mattered as much as they did.

Ten claims were attacked and survived, reported with evidence rather than asserted: a
20,477-input cross-language differential over the full IMF-fixdate grammar plus every
single-character substitution at every position (0 disagreements, 0 Rust panics under
`catch_unwind`, 0 non-`DateHeaderError` throws in TS, error *variants* agreeing too); the
byte-vs-code-unit hazard closed by the ASCII gate running before the length check; leg (1)'s
precedence and boundaries over 7,500 cases; an exhaustive containment audit of `ClockOffset`
in both languages (`JSON.stringify`, `String()`, `Number()`, spread, `structuredClone`,
`Reflect.ownKeys`, subclassing -- `#seconds` genuinely unreachable); the masker x matcher
interaction; every gate figure in all three commit messages reproduced independently; both
line citations in `9d7cb6a` confirmed as correct post-commit offsets; every counted figure
re-counted; and the three self-reported parser defects confirmed fixed and pinned.

## Reading

The lesson is not "boundary checks are hard." It is that a relaxation of a *detector* has an
asymmetric failure mode, and the test proving it safe must be built from the inputs the
relaxation can newly miss -- which are, by construction, the ones the author was not thinking
about when writing the relaxation. Both halves of this failure are things the corpus already
names: an unfailable fixture (F1), and a claim whose scope did not match the change's scope
(F2, one list proved, two lists changed). The fix inverts the default so the unsafe direction
is the loud one: `Prefix` unless a real collision is named at the opt-in site, because
over-firing is immediate and fixable while under-firing is silent and indefinite.

N4 deserves its own note. The reviewer found four stale line citations and gave a replacement
for one of them that was itself wrong -- 419 rather than 421, landing on `host_fp`, a real
field of the right struct. Verifying the reviewer's correction is what caught it. That is the
second time in two days this corpus has recorded a reviewer's assertion being adopted or
nearly adopted without tracing; the first (the v0.9.39 nkey parenthetical) shipped into the
normative document. A reviewer's number is evidence of where to look, not evidence of what is
there.
