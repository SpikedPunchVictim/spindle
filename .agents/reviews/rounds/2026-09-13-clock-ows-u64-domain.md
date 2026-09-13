---
review_id: 2026-09-13-clock-ows-u64-domain
date: 2026-09-13
ticket: td-fc3b88
scope_commits: [45673e35f1379bef22c46c0d5da7d79407044e4a, 5969fc2a56d74b75c90184f2b7e2da65515cf2e1]
verdict: ACCEPT WITH NITS
provenance: first-hand-report
fidelity: first-hand
source_note: "Written from the reviewer's verbatim report. An independent adversarial sub-agent reviewed the two clock-diagnostics fixes: the RFC 9110 OWS trim (td-2601e5) and the TypeScript u64 domain check (td-fc3b88). Its verdict line: 'Both fixes are behaviorally correct and genuinely pinned. I could not find a behavioral defect in either. Everything below is a comment/doc defect or a fixture-scope nit.' Six findings, all doc or test. Every one was verified first-hand by the implementer before being fixed; all six were confirmed, none was overturned. Fixed in 9b69ac5. The reviewer's heaviest attacks came up empty and it said so explicitly: an EXHAUSTIVE differential over the entire valid IMF-fixdate date space (every year 1970-9999 x 12 months x days 1-31 x three time patterns including the leap-second clamp = 8,961,480 cases, 162,789 of them error cases, byte-comparing error variants AND their fields) found ZERO mismatches; a 3,346-row malformed/padding differential found 86 disagreeing rows, all saturation at >= 2**63; an exhaustive sweep of all 128 ASCII code points as leading and trailing pad accepted exactly 0x09 and 0x20, which is RFC 9110's OWS production checked directly rather than twin-against-twin; and it independently reproduced all eight claimed neuter axes plus one unclaimed axis of its own. It also reported killing its own false alarm: a BOM-prefixed header appeared to diverge until it found `new TextDecoder(\"utf-8\")` strips a leading BOM without `ignoreBOM: true` -- its words, 'reporting it because it is exactly the artifact a differential invents.'"
findings:
  - id: F1
    severity: minor
    class: stale-doc-row
    file: crates/spindle-core/src/clock_diagnostics.rs
    line: 1011
    claim: "5969fc2's gate line: 'fmt clean, both clippy legs clean, tsc -b clean.'"
    reality: "True, and a 190-character line carrying the same doc comment written twice shipped anyway. The implementer's insert script computed `add = <new text> + anchor` and then called `s.replace(anchor, add + anchor)`, so the anchor line was emitted twice, concatenated onto one physical line because the first copy had no trailing newline. The file's next-longest line is 101. Neither `cargo fmt --all -- --check` nor clippy can see it: rustfmt does not reflow doc comments and there is no line-length lint in this workspace. A green gate is not a claim about anything a gate does not measure."
    detection: empirical
    evidence: "`awk '{print length($0)\"\\t\"NR}' crates/spindle-core/src/clock_diagnostics.rs | sort -rn | head -3` -> `190 1011`, `101 994`, `101 40`. `git grep -c \"/// .*    /// \" -- 'crates/**/*.rs'` matches this file only, once. `cargo fmt --all -- --check` rc=0 and clippy clean with the line present."
    introduced_by: 5969fc2a56d74b75c90184f2b7e2da65515cf2e1
    introduced_by_kind: fix-commit
    implementer_could_have_caught_by: "diff-read the file after a scripted insert, or run the max-line-length check that already exists for DESIGN.md prose against source files after any programmatic edit"
    td_ref: td-fc3b88
  - id: F2
    severity: minor
    class: unverified-code-claim
    file: crates/spindle-core/src/clock_diagnostics.rs
    line: 1031
    claim: "`non_ows_whitespace_is_not_trimmed`'s doc: '`\\u{a0}` is two bytes, so the 31-byte input is also proof the length check still runs on raw bytes after the trim.'"
    reality: "That input never reaches the length check. `if !bytes.is_ascii() { return Err(DateHeaderError::NonAscii) }` runs at :441, before `if bytes.len() != 29` at :476, so the U+00A0 case returns NonAscii and the byte-length path is never exercised by it. The test asserted only `is_err()`, so it could not tell the two rejection paths apart and could not have contradicted the sentence. A correct assertion whose fixture proves something other than what its comment says it proves -- the inverse of an unfailable fixture, and just as invisible."
    detection: empirical
    evidence: "Reviewer's scratch crate, path-dep on spindle-core: `\"\\u{a0}Sun, 06 Nov 1994 08:49:37 GMT\"` -> `Err(NonAscii)`; `\"\\nSun, 06 Nov 1994 08:49:37 GMT\"` -> `Err(InvalidLength { len: 30 })`. Reproduced first-hand by reading :438-444 and :474-478."
    introduced_by: 45673e35f1379bef22c46c0d5da7d79407044e4a
    introduced_by_kind: fix-commit
    implementer_could_have_caught_by: "assert the exact error variant rather than is_err(): a test that names which check rejected an input cannot carry a comment naming a different one"
    td_ref: td-2601e5
  - id: F3
    severity: minor
    class: wrong-mechanism
    file: packages/crypto/src/clock-diagnostics.ts
    line: 215
    claim: "`assertU64`'s doc: 'What this does NOT equalize is saturation: `[i64::MAX, 2**64)` is legal `u64` on both sides, and there Rust clamps while `bigint` stays exact.'"
    reality: "At exactly `i64::MAX`, `i64::try_from(i64::MAX)` succeeds and Rust does not clamp: both twins return -9223372036070664030. The divergence starts one above, at 2**63. The interval is `[2**63, 2**64)`, which the SAME COMMIT states correctly 56 lines later at :271 -- two doc blocks in one file contradicting each other, both written in the same sitting."
    detection: empirical
    evidence: "TS probe: `offsetFromDateHeader(2n**63n - 1n, hdr)` -> -9223372036070664030n; `offsetFromDateHeader(2n**63n, hdr)` -> -9223372036070664031n. Rust: 784111777 - (2**63-1) = -9223372036070664030 for both, since local saturates at i64::MAX. Reviewer's 3,346-row differential independently: the only disagreeing localNow values are 2**63, 2**63+1, and 2**64-1."
    introduced_by: 5969fc2a56d74b75c90184f2b7e2da65515cf2e1
    introduced_by_kind: fix-commit
    implementer_could_have_caught_by: "evaluate the boundary rather than name it: `i64::MAX` is the last value that FITS, so it is the last value that agrees, not the first that diverges -- an off-by-one available to anyone who runs the two numbers"
    td_ref: td-fc3b88
  - id: F4
    severity: nit
    class: unverified-coverage-claim
    file: packages/crypto/src/clock-diagnostics.ts
    line: 269
    claim: "'Saturation is the ONLY surviving divergence.'"
    reality: "A second divergence is documented 200 lines earlier in the same file. `ClockOffset.internalFromSeconds` is a public static on an exported class; Rust's `ClockOffset(i64)` has a module-private tuple field and cannot be constructed outside its module. So a TypeScript caller can build an offset no Rust `ClockOffset` can hold. Pre-existing and disclosed -- only the new blanket sentence was wrong, and it was wrong because it generalised from the one axis the commit had just measured to every axis."
    detection: empirical
    evidence: "`ClockOffset.internalFromSeconds(2n ** 200n).diagnosticSeconds()` -> 1606938044258990275541962092341162602522202993782792835301376, reached through `packages/crypto/src/index.ts`'s public `ClockOffset` export."
    introduced_by: 5969fc2a56d74b75c90184f2b7e2da65515cf2e1
    introduced_by_kind: fix-commit
    implementer_could_have_caught_by: "scope a uniqueness claim to the dimension actually measured -- 'the only divergence in what the shared u64 domain computes' was the true statement, and the file already held the counterexample to the broader one"
    td_ref: td-fc3b88
  - id: F5
    severity: nit
    class: missing-guard
    file: packages/crypto/src/clock-diagnostics.ts
    line: 334
    claim: "5969fc2's message: 'assertU64 now rejects anything outside [0, 2**64) at every entry point -- diagnoseClock, diagnoseClockFromCapabilities (via it), offsetFromDateHeader, and diagnoseClockFromHttps.'"
    reality: "'via it' is doing real work. `diagnoseClockFromCapabilities` had no check of its own and inherited one only by delegating on its last line, so its CBOR decode loop ran first: with a malformed capability in the bundle, `ClockDiagnosticError(MalformedOpCert)` is thrown and the caller bug never surfaces. The commit's own rationale for checking `diagnoseClockFromHttps` before awaiting -- 'a caller bug should not cost a request' -- applies here as 'a caller bug should not cost a full decode of every held capability', and was not applied."
    detection: empirical
    evidence: "Reviewer: `fromCapabilities(-1n, [garbageCap], [])` -> `ClockDiagnosticError: capability at index 0 has an op_cert that does not decode`, where `fromCapabilities(-1n, [], [])` -> `RangeError`. The test at clock-diagnostics.test.ts:503 used the empty-list fixture, the only one that reaches the delegate."
    introduced_by: 5969fc2a56d74b75c90184f2b7e2da65515cf2e1
    introduced_by_kind: fix-commit
    implementer_could_have_caught_by: "treat 'guarded by delegation' as unguarded until the delegating function's own prologue is shown to be side-effect-free -- and pick the fixture that reaches the delegate LAST, not first"
    td_ref: td-fc3b88
  - id: F6
    severity: nit
    class: unverified-coverage-claim
    file: crates/spindle-core/src/clock_diagnostics.rs
    line: 570
    claim: "45673e3 changed no behavior for inputs that were already rejected."
    reality: "Never stated outright, but implied by a commit message that describes only the accept-path change. Trimming before the fixed-length check moves which check a padded malformed input fails: `\" Sun, 06 Nov 1994 08:49:37 GM\"` is 29 bytes, so it used to pass the length check and fail the layout check (InvalidFormat); it is now 28 bytes and fails the length check (InvalidLength{28}). Padded obsolete forms likewise now reach ObsoleteFormat instead of InvalidLength. Every input stays rejected and both twins still agree, so this is a variant change on the reject path, not a hole -- and nothing pinned it on either side."
    detection: traced
    evidence: "TS probe: `\" Sun, 06 Nov 1994 08:49:37 GM\"` (length 29) -> `DateHeaderError` kind InvalidLength, len 28. `\"Sun, 06 Nov 1994 08:49:37 GMX\"` -> InvalidFormat, so the branch it used to reach is still reachable."
    introduced_by: 45673e35f1379bef22c46c0d5da7d79407044e4a
    introduced_by_kind: fix-commit
    implementer_could_have_caught_by: "ask, of any change that reorders checks, which REJECTED inputs change their rejection reason -- the accept path is where attention goes and the reject path is where parsers actually break"
    td_ref: td-2601e5
---

# Two clock fixes: no behavioral defect, six things the prose got wrong

The reviewer attacked these two commits harder than any round in this corpus so far and came back
with nothing behavioral. Its exhaustive differential covered the **entire valid IMF-fixdate date
space** — 8,961,480 cases, error variants and their fields compared byte for byte — with zero
mismatches. Its OWS check went to RFC 9110 §5.6.3 directly rather than twin-against-twin, sweeping
all 128 ASCII code points as leading and trailing pad and finding exactly `0x09` and `0x20`
accepted. It reproduced all eight claimed neuter axes independently, and added one the commits had
not claimed.

So all six findings are prose and fixtures. That is the interesting result, not a disappointing one:
**the code was right and the writing about it was wrong six times**, which is the same ratio this
corpus keeps producing and the reason correction commits carry the risk they do.

## What the fixes share

Five of the six are a claim that was true of the thing just measured and was written as though it
were true generally:

- F3 named `i64::MAX` as the start of the divergence. `i64::MAX` is the last value that *fits* —
  it is where the twins last **agree**. The commit had the right interval 56 lines away.
- F4 measured one divergence axis and wrote "the ONLY surviving divergence", with the
  counterexample sitting 200 lines up in the same file.
- F5's "at every entry point" was true of three entry points and true-by-delegation of the fourth,
  where delegation happens after a CBOR decode loop that can throw first.
- F2 described the U+00A0 fixture as proving the byte-length check. It proves the ASCII gate.
- F6 is the reject path going undescribed because the accept path was what changed on purpose.

F1 is different in kind and worth keeping separate: a scripted edit emitted a doc line twice onto
one 190-character physical line, and **the full gate is blind to it**. `cargo fmt --all -- --check`
does not reflow doc comments and this workspace has no line-length lint. The gate line in that
commit was honest and the defect shipped under it. Any programmatic edit to source deserves the
max-line-length check this repo already runs against DESIGN.md prose.

## The self-catch: a fixture that could not fail, again

Fixing F5 produced the round's most useful moment. The first replacement fixture passed a
**well-formed** capability:

```
fromCapabilities(-1n, [goodCap], [])  ->  RangeError        with the new check
fromCapabilities(-1n, [goodCap], [])  ->  RangeError        WITHOUT it
```

A well-formed capability decodes and reaches the `diagnoseClock` delegation, which throws
`RangeError` either way — so the assertion was correct, the test was green, and it could not see the
check it was written to pin. The neuter axis came back **GREEN**, which is the only reason this was
caught. An undecodable `op_cert` reddens it.

This is the third time in this corpus that a correct assertion over an unfailable fixture has
appeared inside the very test added to rule the defect out (see
`2026-09-12-td-7e3556-clock-diagnostics.md` F1). Running the axis is what finds it. Reading the
assertion never does.

## The reviewer's own false alarm

Recorded because it is the honest half of the report. A BOM-prefixed header first appeared to be
accepted by TypeScript and rejected as `NonAscii` by Rust — a genuine-looking cross-language
divergence. It was the harness: `new TextDecoder("utf-8")` strips a leading BOM unless
`ignoreBOM: true` is set. The reviewer found it, fixed the harness, watched the divergence vanish,
and reported it anyway with the note that it is "exactly the artifact a differential invents."

A differential's disagreements need the same scrutiny as its agreements. The agreements are blind
to shared gaps; the disagreements are where the harness's own bugs show up wearing a finding's
clothes.
