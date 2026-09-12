// Guards the invariant DESIGN.md A10.42 (td-e8b79f) decided: a client may compute a clock offset
// from a local bound check against a `HostOpKeyCert.ts` lower bound, and optionally from a
// configured HTTPS `Date` header — but both are diagnostic only. Neither may be fed into signing
// time, `exp` checks, or revocation checks, because a time source is not an authenticated
// channel; folding one into a validity check would turn a safe refusal (wrong or compromised
// clock) into an acceptance of an expired or revoked artifact.
//
// That property rests on every `.ts` file under `packages/crypto/src` taking every notion of
// "now" from an explicit caller-supplied `now: bigint` parameter, never from an ambient clock read
// inside this package. This guard scans the whole `src` tree recursively, not a fixed list of
// files, because there is no legitimate reason for any file in this package to read a clock
// itself — the clock is supplied at the edge, by callers outside this package. `envelope.ts` is
// singled out below because it performs the same kind of check on the same kind of ground: its
// `open` function's `if (absDiff(params.now, env.ts) > CLOCK_SKEW_SECS)` at :338 is a live
// clock-skew validity check, exactly the shape this guard exists to hold ambient-clock-free.
// `artifacts.ts`'s own module doc already states the rule in prose ("This module never reads a
// system clock: every time check takes a caller-supplied `now: bigint`"); this test is the
// enforcement that prose lacked.
//
// `packages/crypto` (like its Rust twin, `spindle-core`) reads no ambient clock anywhere; the
// pure verification library takes every "now" as a caller-supplied parameter, and the edge
// supplies it. On the Rust side, `crates/spindle-net/src/signaling/wire.rs:44`'s
// `SystemTime::now()` read is exactly this kind of legitimate edge caller, not a violation of the
// rule this guard enforces — TypeScript has no direct twin of that call site today, but the same
// layering applies if and when one is added: an edge caller outside this package may read a
// clock and pass the result in; this package itself may not. What does not exist yet is A10.42's
// *computed clock offset* — a configured time source derived from the diagnostic bound checks
// named in this file's opening paragraph — and this guard's job is to hold the ambient-clock-free
// ground in this package's own sources before and after that diagnostic lands, not to detect a
// violation after the fact.
//
// This is the TypeScript twin of `crates/spindle-core/tests/clock_source_guard.rs` — same
// invariant, same text-scan approach, same precedent (`redaction_guard.rs`'s comment/string
// masking), adapted to TypeScript's comment and string-literal syntax.
//
// # This is a heuristic, not a proof
//
// It cannot see through indirection: a helper two calls away that reads the clock and hands the
// result down as a plain `number`/`bigint` parameter looks identical, at this scan's boundary, to
// a legitimately caller-supplied `now`. Nor can it see a clock read inside an imported dependency
// (e.g. `@noble/curves`) that this file merely calls into. This guard only proves that the
// specific ambient-clock APIs it knows about — `Date.now`, `new Date`, and `performance.now` —
// are not spelled out, as real code, anywhere under `packages/crypto/src`. Treat a passing run as
// "no *obvious* new ambient clock read", not as a proof that every `now` value traces back to a
// caller argument.
//
// ## Comments and string literals
//
// Matches inside `//` line comments, `/* */` block comments, and `"..."`/`'...'`/`` `...` ``
// string and template literals are deliberately excluded from failing the test: a doc comment
// that *describes* the forbidden rule (this file's own header, or `artifacts.ts`'s module doc)
// would otherwise trip the guard it exists to justify. Template-literal interpolations
// (`` `${...}` ``) are masked along with the rest of the template's text, since this scan does not
// parse `${}` back into code — a `Date.now()` call written inside a template interpolation would
// therefore be invisible to this guard. That shape does not appear anywhere in any scanned file
// today; a heuristic guard test doesn't need a full TypeScript tokenizer to know that.
//
// Matching is plain substring search, so it can over-match: a local binding literally named
// `myDate` followed by `.now()` would contain the substring `Date.now` and be flagged even though
// it has nothing to do with `globalThis.Date`. No such binding exists in any scanned file.
//
// It can also under-match, in the opposite direction: `const { now: destructuredNow } = Date;
// destructuredNow();` is **not caught**, because the scan looks for the literal substring
// `Date.now`, and destructuring `now` off `Date` before calling it never spells that substring out
// anywhere in the source. No such destructuring exists in any scanned file today; it is
// disclosed because a heuristic that only lists its over-matches and not its under-matches invites
// more trust than it has earned.
//
// # Neuter-verification
//
// Demonstrated on 2026-09-11, not assumed. Appending `const probeNow = Date.now();` to
// `src/artifacts.ts` turned this test RED with ``artifacts.ts:625: found `Date.now` (`const
// probeNow = Date.now();`)``, and removing it turned the test green again with the file
// byte-identical to its original (`cmp` clean, `git diff --quiet` clean).
//
// The masking was neutered separately in the same run: a line comment containing `Date.now`, a
// block comment containing `new Date` and `performance.now`, a double-quoted string containing
// `Date.now` and `new Date`, a single-quoted string containing `performance.now`, and a template
// literal containing `Date.now` were all appended to the same file at once, and the test stayed
// green. That is the evidence for the masking claim above — without it, "matches in comments and
// strings are excluded" would itself be an untested assertion about what this test catches.
//
// The `envelope.ts` addition was neutered separately on the same day: appending `const probeEnvNow
// = Date.now();` to `src/envelope.ts` turned this test RED naming `envelope.ts:353`, and reverting
// it left the file byte-identical to its original (`cmp` clean, `git diff --quiet` clean). That
// file is scanned because it performs the envelope clock-skew validity check at `:338`, and an
// earlier version of this guard claimed in its own header that the property rested on
// `artifacts.ts` and `bootstrap.ts` alone — which `envelope.ts:338` made false. The broadened
// recursive scan was neutered on the same day: appending `const probeRecursion =
// Date.now();` to `src/primitives.ts` turned this test RED naming `primitives.ts:78`, and reverting
// it left the file byte-identical to its original (`cmp` clean, `git diff --quiet` clean). That
// file was chosen because it is outside the three names the old `SCANNED_FILES` list held, so
// reddening on it demonstrates the walk reaches files that list never named.
//
// # A second, structural guard: validity paths must never NAME a diagnostic clock symbol
//
// `src/clock-diagnostics.ts` (DESIGN.md §A10.42, td-7e3556) landed a *type-level* speed bump —
// `ClockOffset` has exactly one accessor and no conversion into a timestamp — but that type's own
// doc comment admits it is "a speed bump, not a proof": nothing stops a caller from reading
// `.diagnosticSeconds()` and folding the raw `bigint` into a validity check by hand. The second
// `it` block below is the structural layer underneath that type-level one, mirroring
// `crates/spindle-core/tests/clock_source_guard.rs`'s
// `validity_paths_never_consult_a_diagnostic_clock_offset`: it scans this package's artifact
// validity paths (`artifacts.ts` and `envelope.ts` — the two files that actually run an `exp` or
// clock-skew comparison; `bootstrap.ts` is in `MUST_BE_PRESENT` above because it states/relies on
// the no-ambient-clock rule while forwarding `now` into `verifyCapability`, not because it runs a
// comparison of its own) for the literal names of leg (1)/leg (2)'s diagnostic-only symbols. Two
// defences layered on purpose, neither sufficient alone — same rationale as the Rust twin's.

import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");
const srcDir = path.join(packageRoot, "src");

/** Files that must be present among the scanned set — these three hold the A10.42 clock-skew
 * validity checks (or state the no-ambient-clock rule) this guard exists to protect. Checked by
 * name, in addition to the minimum-count floor below, so a rename or removal of any one of them
 * fails loudly by name, not just as a number going down. */
const MUST_BE_PRESENT = ["artifacts.ts", "bootstrap.ts", "envelope.ts"];

/** Conservative floor on how many `.ts` files this scan should find under `packages/crypto/src`.
 * There are 9 files directly under `src` today (artifacts.ts, backend.ts, bootstrap.ts, bytes.ts,
 * clock-diagnostics.ts, envelope.ts, fingerprint.ts, index.ts, primitives.ts), confirmed by
 * listing the directory on 2026-09-12 (clock-diagnostics.ts added, DESIGN.md §A10.42 leg (2)
 * twin). Pinned at that exact count (not "just under" it) because this guard's whole purpose is to
 * catch a silently-shrinking scan set — an off-by-a-few floor would let a dropped file slip
 * through unnoticed. Adding a new file under `src` raises the true count above this floor and
 * stays green; only a *drop* below 9 (a move, rename, or scan-logic regression) turns this red. */
const MIN_TS_FILE_COUNT = 9;

/** Ambient clock APIs this guard looks for, as plain substrings of masked source text. */
const FORBIDDEN_PATTERNS = ["Date.now", "new Date", "performance.now"];

/** A10.42's diagnostic-only symbols (TypeScript names), mirroring
 * `clock_source_guard.rs`'s `DIAGNOSTIC_ONLY_SYMBOLS`. A clock offset computed by
 * `src/clock-diagnostics.ts` — leg (1)'s local bound check, or leg (2)'s optional configured
 * HTTPS `Date` source — is diagnostic only: it may be displayed, and it may never be folded into
 * signing time, an `exp` check, or a revocation check. If any of `clock-diagnostics.ts`'s exported
 * names change, update this list in the same commit. */
const DIAGNOSTIC_ONLY_SYMBOLS = [
  "ClockOffset",
  "ClockDiagnosis",
  "diagnoseClock",
  "HttpsDateSource",
  "offsetFromDateHeader",
  "diagnoseClockFromHttps",
];

/** The A10.42 artifact validity paths in this package: the two files that actually run an `exp`
 * or clock-skew comparison (`verifyCapability` and friends in `artifacts.ts`; `open`'s clock-skew
 * check in `envelope.ts`). Deliberately narrower than {@link tsFilesUnderRecursive}'s whole-`src`
 * walk above — widening this to the whole tree would fail this test on `clock-diagnostics.ts`
 * itself, which names these symbols entirely legitimately (it defines them), and on `index.ts`,
 * which re-exports them just as legitimately. */
const VALIDITY_PATH_FILE_NAMES = ["artifacts.ts", "envelope.ts"];

/** Floor on how many validity-path files the second guard below should find — both entries of
 * {@link VALIDITY_PATH_FILE_NAMES}. Same rationale as {@link MIN_TS_FILE_COUNT}: a scan that
 * silently finds nothing must not pass for the wrong reason. */
const MIN_VALIDITY_PATH_FILE_COUNT = 2;

interface Violation {
  file: string;
  line: number;
  pattern: string;
  text: string;
}

/** Recursively collects every `.ts` file under `dir`, sorted for deterministic reporting. */
function tsFilesUnderRecursive(dir: string): string[] {
  const out: string[] = [];
  collectTsFiles(dir, out);
  out.sort();
  return out;
}

/** Recursive helper for {@link tsFilesUnderRecursive}: walks `dir`, pushing every `.ts` file it
 * finds into `out` and recursing into every subdirectory. */
function collectTsFiles(dir: string, out: string[]): void {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectTsFiles(entryPath, out);
    } else if (entry.isFile() && entryPath.endsWith(".ts")) {
      out.push(entryPath);
    }
  }
}

/** Replaces `//` line comments, `/* *​/` block comments, and `"..."`/`'...'`/`` `...` `` string
 * and template literals with ASCII spaces, code-unit-for-code-unit (newlines preserved), so
 * scanning the result cannot mistake comment/string text for real code. This iterates UTF-16 code
 * units (JavaScript string indexing), not bytes, so it is character-based rather than byte-based;
 * every code-unit offset in the output lines up with the same offset (and line number) in the
 * original source.
 *
 * Deliberately simple, mirroring `redaction_guard.rs`'s `mask_non_code`: no special handling of
 * regex literals (`/.../`). `backend.ts:79` and `:83` each have two (`.replace(/\+/g, "-")` and
 * friends, for base64url's `+`/`-` and `/`/`_` swaps) — the only regex literals in any scanned
 * file — and measurement found no desync at those lines: none of `FORBIDDEN_PATTERNS` appears
 * inside a regex literal there, so this scanner's blindness to that shape happens not to matter
 * today, not because the shape is absent. Template-literal `${...}` interpolations are masked
 * along with the rest of the template rather than being recursively re-parsed as code (see this
 * file's header comment on that limitation). */
type Mode = "code" | "line-comment" | "block-comment" | "single" | "double" | "template";

function maskNonCode(src: string): string {
  let mode: Mode = "code";
  let out = "";
  let i = 0;
  let escaped = false;

  while (i < src.length) {
    const c = src[i];
    const next = i + 1 < src.length ? src[i + 1] : "";

    if (mode === "code") {
      if (c === "/" && next === "/") {
        mode = "line-comment";
        out += "  ";
        i += 2;
        continue;
      }
      if (c === "/" && next === "*") {
        mode = "block-comment";
        out += "  ";
        i += 2;
        continue;
      }
      if (c === "'") {
        mode = "single";
        out += " ";
        i += 1;
        continue;
      }
      if (c === '"') {
        mode = "double";
        out += " ";
        i += 1;
        continue;
      }
      if (c === "`") {
        mode = "template";
        out += " ";
        i += 1;
        continue;
      }
      out += c;
      i += 1;
      continue;
    }

    if (mode === "line-comment") {
      if (c === "\n") {
        mode = "code";
        out += "\n";
      } else {
        out += " ";
      }
      i += 1;
      continue;
    }

    if (mode === "block-comment") {
      if (c === "*" && next === "/") {
        mode = "code";
        out += "  ";
        i += 2;
        continue;
      }
      out += c === "\n" ? "\n" : " ";
      i += 1;
      continue;
    }

    // "single" | "double" | "template": identical escape handling, different terminators.
    const terminator = mode === "single" ? "'" : mode === "double" ? '"' : "`";
    if (escaped) {
      escaped = false;
      out += c === "\n" ? "\n" : " ";
      i += 1;
      continue;
    }
    if (c === "\\") {
      escaped = true;
      out += " ";
      i += 1;
      continue;
    }
    if (c === terminator) {
      mode = "code";
      out += " ";
      i += 1;
      continue;
    }
    out += c === "\n" ? "\n" : " ";
    i += 1;
  }

  return out;
}

/** 1-based line number containing `offset` in `src`. */
function lineNumberAt(src: string, offset: number): number {
  let count = 1;
  for (let i = 0; i < offset; i++) {
    if (src[i] === "\n") count += 1;
  }
  return count;
}

/** True for characters that can appear inside a TypeScript identifier: ASCII letters, digits,
 * `_`, and `$` (valid in identifiers, e.g. `$1`, `foo$bar`). */
function isIdentifierChar(ch: string): boolean {
  if (ch === "") return false;
  return /[A-Za-z0-9_$]/.test(ch);
}

/** A raw substring search has no identifier boundary, so a pattern like `"new Date"` matches not
 * only real code but also any identifier that merely *contains* it — `new DateHeaderError(...)`
 * is the concrete case that motivated this: `clock-diagnostics.ts` had to route all ten of that
 * class's error constructions through a `private static make(...)` indirection purely to avoid
 * spelling `new DateHeaderError(` at a call site, because that text contains the literal
 * substring `new Date`. A match at `masked[idx..idx + pattern.length]` counts only when the
 * character immediately before it (if any) and the character immediately after it (if any) are
 * both NOT identifier characters — i.e. the pattern isn't embedded inside a larger name. */
function isIdentifierBoundaryMatch(masked: string, idx: number, pattern: string): boolean {
  const before = idx > 0 ? masked[idx - 1] : "";
  const after = idx + pattern.length < masked.length ? masked[idx + pattern.length] : "";
  return !isIdentifierChar(before) && !isIdentifierChar(after);
}

/** One identifier-boundary match of a pattern in masked source, with enough context to report or
 * assert on it. */
interface PatternHit {
  line: number;
  pattern: string;
  text: string;
}

/** Pure scan of `original` for identifier-boundary matches of any of `patterns`. Masks comments
 * and string/template literals first (via {@link maskNonCode}) so a match inside prose doesn't
 * count, then searches the masked text but reports line numbers and text against `original`.
 *
 * Extracted as a standalone function, independent of any file path, so both the two real scans
 * below and this file's own tests can feed it synthetic source strings directly. */
function findPatternHits(original: string, patterns: readonly string[]): PatternHit[] {
  const masked = maskNonCode(original);
  const hits: PatternHit[] = [];

  for (const pattern of patterns) {
    let searchFrom = 0;
    for (;;) {
      const idx = masked.indexOf(pattern, searchFrom);
      if (idx === -1) break;
      searchFrom = idx + pattern.length;
      if (!isIdentifierBoundaryMatch(masked, idx, pattern)) continue;
      const line = lineNumberAt(original, idx);
      const text = (original.split("\n")[line - 1] ?? "").trim();
      hits.push({ line, pattern, text });
    }
  }

  return hits;
}

describe("clock-source-guard", () => {
  it("every .ts file under src never reads an ambient clock", () => {
    const files = tsFilesUnderRecursive(srcDir);

    // Pinned to a minimum count derived from what's on disk (see MIN_TS_FILE_COUNT above), not
    // just checked non-empty, so that a shrinking scan (e.g. an edit that silently drops a file
    // from the walk) fails loudly instead of quietly — a shrunk file set would otherwise still
    // pass this test by scanning less.
    expect(files.length).toBeGreaterThanOrEqual(MIN_TS_FILE_COUNT);

    for (const name of MUST_BE_PRESENT) {
      const present = files.some((f) => path.basename(f) === name);
      if (!present) {
        throw new Error(
          `expected ${name} to be found under ${srcDir} — did it get moved or renamed? It holds ` +
            "an A10.42 clock-skew validity check (or states the no-ambient-clock rule) this " +
            "guard exists to protect.",
        );
      }
    }

    const violations: Violation[] = [];
    let totalBytesRead = 0;

    for (const filePath of files) {
      const original = fs.readFileSync(filePath, "utf8");
      if (original.length === 0) {
        throw new Error(`${filePath} was read as empty — refusing to treat that as a clean scan`);
      }
      totalBytesRead += original.length;

      for (const hit of findPatternHits(original, FORBIDDEN_PATTERNS)) {
        violations.push({ file: filePath, ...hit });
      }
    }

    // A guard that silently scanned zero (or empty) files would pass for the wrong reason —
    // assert real content was actually read before trusting an empty violations list.
    expect(totalBytesRead).toBeGreaterThan(0);

    if (violations.length > 0) {
      const report = violations
        .map(
          (v) =>
            `${v.file}:${v.line}: found \`${v.pattern}\` (\`${v.text}\`) — A10.42 requires ` +
            "every artifact validity check to take a caller-supplied `now`, so that a wrong or " +
            "compromised time source can only cause a refusal, never an acceptance. Reading an " +
            "ambient clock here bypasses that.",
        )
        .join("\n");
      throw new Error(
        `clock-source-guard found ${violations.length} ambient clock read(s):\n${report}`,
      );
    }
  });

  // Mirrors `crates/spindle-core/tests/clock_source_guard.rs`'s
  // `validity_paths_never_consult_a_diagnostic_clock_offset` — the structural layer underneath
  // `ClockOffset`'s type-level speed bump (see this file's header comment). A passing run means
  // "no validity path spells one of these names", not "no diagnostic value can reach a validity
  // check" — it is a text scan, nothing more, and cannot see a diagnostic value laundered through
  // an intermediate `bigint` variable or a helper that takes a plain `bigint` and hands it on.
  // That is exactly why `ClockOffset` carries no conversion into a timestamp in the first place:
  // neither defence is sufficient alone, and the two are layered on purpose.
  it("validity paths never consult a diagnostic clock offset", () => {
    const files = VALIDITY_PATH_FILE_NAMES.map((name) => path.join(srcDir, name));

    // A floor on how many files this scan should find, so a scan that silently finds nothing (a
    // rename, a moved file, a typo in VALIDITY_PATH_FILE_NAMES) fails loudly rather than passing
    // for having scanned nothing.
    expect(files.length).toBeGreaterThanOrEqual(MIN_VALIDITY_PATH_FILE_COUNT);

    for (const filePath of files) {
      if (!fs.existsSync(filePath)) {
        throw new Error(
          `expected ${filePath} to exist — did it get moved or renamed? It holds an A10.42 ` +
            "validity check that must never consult a diagnostic clock offset.",
        );
      }
    }

    const violations: Violation[] = [];
    let totalBytesRead = 0;

    for (const filePath of files) {
      const original = fs.readFileSync(filePath, "utf8");
      if (original.length === 0) {
        throw new Error(`${filePath} was read as empty — refusing to treat that as a clean scan`);
      }
      totalBytesRead += original.length;

      for (const hit of findPatternHits(original, DIAGNOSTIC_ONLY_SYMBOLS)) {
        violations.push({ file: filePath, ...hit });
      }
    }

    // Same defence as the sibling test above: a guard that silently scanned zero (or empty)
    // files would pass for the wrong reason.
    expect(totalBytesRead).toBeGreaterThan(0);

    if (violations.length > 0) {
      const report = violations
        .map(
          (v) =>
            `${v.file}:${v.line}: found \`${v.pattern}\` (\`${v.text}\`) — A10.42 makes every ` +
            "clock offset diagnostic only: it may be displayed, never fed into signing time, an " +
            "`exp` check, or a revocation check. A time source is not an authenticated channel, " +
            "so folding one in here would turn a safe refusal into an acceptance of an expired " +
            "or revoked artifact.",
        )
        .join("\n");
      throw new Error(
        `clock-source-guard found ${violations.length} diagnostic-clock symbol(s) named in an ` +
          `artifact validity path:\n${report}`,
      );
    }
  });

  // Proof that the identifier-boundary fix ({@link isIdentifierBoundaryMatch}) does not open a
  // hole: every real ambient-clock form must still be caught (positive), and an occurrence merely
  // embedded in a larger identifier must not be (negative).
  it("still catches every real ambient-clock form after the identifier-boundary fix", () => {
    const source = ["const a = new Date();", "const b = Date.now();", "const c = performance.now();"].join("\n");

    const hits = findPatternHits(source, FORBIDDEN_PATTERNS);
    for (const pattern of FORBIDDEN_PATTERNS) {
      expect(
        hits.some((h) => h.pattern === pattern),
        `expected pattern \`${pattern}\` to still be caught by the identifier-boundary scan; got hits: ${JSON.stringify(hits)}`,
      ).toBe(true);
    }
  });

  it("does not flag an occurrence merely embedded in a larger identifier", () => {
    // `new DateHeaderError(...)` is the concrete case that motivated the fix (see
    // `clock-diagnostics.ts`). `someDate.now()` and `myPerformance.nowish` are the same shape for
    // the other two forbidden patterns.
    const source = [
      "class DateHeaderError extends Error {}",
      "new DateHeaderError();",
      "someDate.now();",
      "myPerformance.nowish;",
    ].join("\n");

    const hits = findPatternHits(source, FORBIDDEN_PATTERNS);
    expect(hits, `expected no hits for identifier-embedded occurrences, got: ${JSON.stringify(hits)}`).toEqual([]);
  });
});
