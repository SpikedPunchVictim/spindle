// Guards the invariant DESIGN.md A10.42 (td-e8b79f) decided: a client may compute a clock offset
// from a local bound check against a `HostOpKeyCert.ts` lower bound, and optionally from a
// configured HTTPS `Date` header — but both are diagnostic only. Neither may be fed into signing
// time, `exp` checks, or revocation checks, because a time source is not an authenticated
// channel; folding one into a validity check would turn a safe refusal (wrong or compromised
// clock) into an acceptance of an expired or revoked artifact.
//
// That property rests on `artifacts.ts` and `bootstrap.ts` taking every notion of "now" from an
// explicit caller-supplied `now: bigint` parameter, never from an ambient clock read inside this
// package. `artifacts.ts`'s own module doc already states the rule in prose ("This module never
// reads a system clock: every time check takes a caller-supplied `now: bigint`"); this test is
// the enforcement that prose lacked. As of writing, no clock source is wired into Spindle at all
// (A10.42's cold-clock diagnostic is not yet implemented), so this guard's job is to hold this
// ground *before* one gets wired in, not to detect a violation after the fact.
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
// are not spelled out, as real code, inside these two files. Treat a passing run as "no *obvious*
// new ambient clock read", not as a proof that every `now` value traces back to a caller argument.
//
// ## Comments and string literals
//
// Matches inside `//` line comments, `/* */` block comments, and `"..."`/`'...'`/`` `...` ``
// string and template literals are deliberately excluded from failing the test: a doc comment
// that *describes* the forbidden rule (this file's own header, or `artifacts.ts`'s module doc)
// would otherwise trip the guard it exists to justify. Template-literal interpolations
// (`` `${...}` ``) are masked along with the rest of the template's text, since this scan does not
// parse `${}` back into code — a `Date.now()` call written inside a template interpolation would
// therefore be invisible to this guard. That shape does not appear anywhere in either scanned file
// today; a heuristic guard test doesn't need a full TypeScript tokenizer to know that.
//
// Matching is plain substring search, so it can over-match: a local binding literally named
// `myDate` followed by `.now()` would contain the substring `Date.now` and be flagged even though
// it has nothing to do with `globalThis.Date`. No such binding exists in either scanned file.
//
// # Neuter-verification
//
// Demonstrated on 2026-09-11, not assumed. Appending `const probeNow = Date.now();` to
// `src/artifacts.ts` turned this test RED with ``artifacts.ts:620: found `Date.now` (`const
// probeNow = Date.now();`)``, and removing it turned the test green again with the file
// byte-identical to its original (`cmp` clean, `git diff --quiet` clean).
//
// The masking was neutered separately in the same run: a line comment containing `Date.now`, a
// block comment containing `new Date` and `performance.now`, a double-quoted string containing
// `Date.now` and `new Date`, a single-quoted string containing `performance.now`, and a template
// literal containing `Date.now` were all appended to the same file at once, and the test stayed
// green. That is the evidence for the masking claim above — without it, "matches in comments and
// strings are excluded" would itself be an untested assertion about what this test catches.

import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");
const srcDir = path.join(packageRoot, "src");

/** Files this guard scans, relative to `src/`. Both take a caller-supplied `now: bigint`. */
const SCANNED_FILES = ["artifacts.ts", "bootstrap.ts"];

/** Ambient clock APIs this guard looks for, as plain substrings of masked source text. */
const FORBIDDEN_PATTERNS = ["Date.now", "new Date", "performance.now"];

interface Violation {
  file: string;
  line: number;
  pattern: string;
  text: string;
}

/** Replaces `//` line comments, `/* *​/` block comments, and `"..."`/`'...'`/`` `...` `` string
 * and template literals with ASCII spaces, byte-for-byte (newlines preserved), so scanning the
 * result cannot mistake comment/string text for real code. Every character offset in the output
 * lines up with the same offset (and line number) in the original source.
 *
 * Deliberately simple, mirroring `redaction_guard.rs`'s `mask_non_code`: no special handling of
 * regex literals (`/.../`) — none appear in either scanned file — and template-literal
 * `${...}` interpolations are masked along with the rest of the template rather than being
 * recursively re-parsed as code (see this file's header comment on that limitation). */
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

describe("clock-source-guard", () => {
  it("artifacts.ts and bootstrap.ts never read an ambient clock", () => {
    const violations: Violation[] = [];
    let totalBytesRead = 0;

    for (const name of SCANNED_FILES) {
      const filePath = path.join(srcDir, name);
      if (!fs.existsSync(filePath)) {
        throw new Error(`expected ${filePath} to exist — did it get moved or renamed?`);
      }

      const original = fs.readFileSync(filePath, "utf8");
      if (original.length === 0) {
        throw new Error(`${filePath} was read as empty — refusing to treat that as a clean scan`);
      }
      totalBytesRead += original.length;

      const masked = maskNonCode(original);

      for (const pattern of FORBIDDEN_PATTERNS) {
        let searchFrom = 0;
        for (;;) {
          const idx = masked.indexOf(pattern, searchFrom);
          if (idx === -1) break;
          const line = lineNumberAt(original, idx);
          const text = (original.split("\n")[line - 1] ?? "").trim();
          violations.push({ file: filePath, line, pattern, text });
          searchFrom = idx + pattern.length;
        }
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
});
