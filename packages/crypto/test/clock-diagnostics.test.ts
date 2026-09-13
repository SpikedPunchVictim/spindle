// Tests for `../src/clock-diagnostics.ts` (DESIGN.md §A10.42 "Cold-clock diagnostics") — the
// TypeScript twin of `crates/spindle-core/src/clock_diagnostics.rs`. Mirrors that file's own
// `mod tests`, case for case, adapted to this package's vitest conventions (see
// `session-attestation.test.ts` and `key-validity.test.ts`).
//
// `diagnoseClock`, `diagnoseClockFromCapabilities`, and `offsetFromDateHeader` verify NOTHING —
// they read `ts`/`exp` fields out of already-decoded structs and never touch a signature — so,
// unlike `artifacts.ts`'s tests, none of the `Capability`/`HostOpKeyCert` fixtures built below
// carry real Ed25519 signatures: `sig`/`sig_host_root` are filled with arbitrary bytes. The one
// exception is `op_cert`, which must be REAL canonical CBOR (built with
// `HostOpKeyCert.toCanonicalBytes`) because `diagnoseClockFromCapabilities` actually decodes it.

import { CapKind, HostOpKeyCert, type Capability } from "@spindle/proto";
import { describe, expect, it } from "vitest";

import {
  ClockDiagnosticError,
  type ClockDiagnosis,
  DateHeaderError,
  type DateHeaderErrorKind,
  HttpsDateError,
  type HttpsDateSource,
  HttpsDateSourceError,
  diagnoseClock,
  diagnoseClockFromCapabilities,
  diagnoseClockFromHttps,
  offsetFromDateHeader,
} from "../src/clock-diagnostics.js";

// ---- fixtures ---------------------------------------------------------------------------------

function fakeHostOpKeyCert(ts: bigint, exp: bigint): HostOpKeyCert {
  return {
    host_op_pk: new Uint8Array(32).fill(0x22),
    ts,
    exp,
    sig_host_root: new Uint8Array(64).fill(0x99),
  };
}

/** Builds a `Capability` with a REAL, canonically-encoded embedded `op_cert` whose `ts` is
 * `opCertTs` — the same shape `diagnose_clock_from_capabilities`'s Rust twin's `real_capability`
 * test helper builds — so the extraction path under test decodes production bytes, not a
 * hand-assembled struct. No signature is real (`sig`/the op_cert's own `sig_host_root` are
 * arbitrary bytes): these functions never check one. */
function fakeCapability(opCertTs: bigint, capExp: bigint): Capability {
  const opCert = fakeHostOpKeyCert(opCertTs, 0xffff_ffff_ffff_ffffn);
  return {
    v: 1,
    host_fp: new Uint8Array(32).fill(0x11),
    host_root_pk: new Uint8Array(32).fill(0x21),
    op_cert: HostOpKeyCert.toCanonicalBytes(opCert),
    kind: CapKind.Member,
    subject: new Uint8Array(32).fill(0xaa),
    cap_epoch: 1n,
    exp: capExp,
    nonce: new Uint8Array(12).fill(0x33),
    sig: new Uint8Array(64).fill(0x44),
  };
}

function expectProvablyBehind(diagnosis: ClockDiagnosis, behindBy: bigint, boundTs: bigint): void {
  if (diagnosis.kind !== "ProvablyBehind") {
    throw new Error(`expected ProvablyBehind, got ${JSON.stringify(diagnosis)}`);
  }
  expect(diagnosis.behindBy.diagnosticSeconds()).toBe(behindBy);
  expect(diagnosis.boundTs).toBe(boundTs);
}

function expectAmbiguous(diagnosis: ClockDiagnosis, latestCapExp: bigint): void {
  expect(diagnosis).toEqual({ kind: "Ambiguous", latestCapExp });
}

function expectNoEvidence(diagnosis: ClockDiagnosis): void {
  expect(diagnosis).toEqual({ kind: "NoEvidenceOfSkew" });
}

/** Asserts `fn` throws a `DateHeaderError` of ANY kind, without asserting which. Deliberately not
 * `expect(fn).toThrow(DateHeaderError)`: `DateHeaderError`'s constructor is private (mirroring
 * `ArtifactError`'s), and vitest's `toThrow` overload that takes a constructor requires a public
 * one — the same reason this package's other test files (e.g. `session-attestation.test.ts`'s
 * `expectArtifactError`) always assert via `toBeInstanceOf` in a try/catch rather than
 * `toThrow(ErrorClass)`. */
function expectThrowsDateHeaderError(fn: () => unknown): void {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(DateHeaderError);
    return;
  }
  throw new Error("expected a DateHeaderError, but nothing threw");
}

function expectDateHeaderError(fn: () => unknown, kind: DateHeaderErrorKind): DateHeaderError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(DateHeaderError);
    expect((e as DateHeaderError).kind).toBe(kind);
    return e as DateHeaderError;
  }
  throw new Error(`expected a DateHeaderError(${kind}), but nothing threw`);
}

// ---- leg (1): diagnoseClock ---------------------------------------------------------------

describe("diagnoseClock", () => {
  it("local time before the signed bound is provably behind", () => {
    expectProvablyBehind(diagnoseClock(1_000n, [5_000n], []), 4_000n, 5_000n);
  });

  // The bound is max(op_cert.ts) per A10.42. The max sits in the MIDDLE position, so a `[0]` or a
  // `Math.min` implementation would pick a different value and this test would fail.
  it("the bound is the max op_cert ts, not the first or the min", () => {
    expectProvablyBehind(diagnoseClock(1_000n, [2_000n, 9_000n, 3_000n], []), 8_000n, 9_000n);
  });

  // Boundary: "earlier than" is strict. A clock exactly at the bound is consistent with a
  // certificate signed at that instant, so nothing is proven.
  it("local time exactly at the bound is not provably behind", () => {
    expectNoEvidence(diagnoseClock(5_000n, [5_000n], []));
  });

  it("local time one second past the bound is not provably behind", () => {
    expectNoEvidence(diagnoseClock(5_001n, [5_000n], []));
  });

  it("every capability expired is ambiguous with the latest exp", () => {
    expectAmbiguous(diagnoseClock(9_000n, [1_000n], [4_000n, 8_000n, 6_000n]), 8_000n);
  });

  // Order is normative (A10.42): the provable direction wins over the ambiguous one when both
  // conditions hold at once.
  it("provably behind wins over ambiguous when both hold", () => {
    expectProvablyBehind(diagnoseClock(500n, [5_000n], [100n, 200n]), 4_500n, 5_000n);
  });

  // `every`, not `some`: one unexpired capability means expiry explains nothing about the clock.
  it("one still-valid capability yields no evidence, not ambiguous", () => {
    expectNoEvidence(diagnoseClock(5_000n, [1_000n], [100n, 200n, 9_999n]));
  });

  // An empty op-cert array is the absence of a lower bound, not a good clock — but it does not
  // suppress the ambiguous case, which rests on `exp` alone.
  it("empty op-cert array with expired caps is ambiguous", () => {
    expectAmbiguous(diagnoseClock(9_000n, [], [4_000n, 8_000n]), 8_000n);
  });

  it("empty everything proves nothing", () => {
    expectNoEvidence(diagnoseClock(9_000n, [], []));
  });
});

// ---- leg (1): diagnoseClockFromCapabilities ------------------------------------------------

describe("diagnoseClockFromCapabilities", () => {
  it("extracts ts from a real embedded op_cert", () => {
    const cap = fakeCapability(7_000n, 8_000n);
    const diagnosis = diagnoseClockFromCapabilities(1_000n, [cap], []);
    expect(diagnosis).toEqual(diagnoseClock(1_000n, [7_000n], [8_000n]));
    expectProvablyBehind(diagnosis, 6_000n, 7_000n);
  });

  it("garbage op_cert bytes report the offending index", () => {
    const caps = [fakeCapability(7_000n, 8_000n), fakeCapability(7_000n, 8_000n)];
    caps[1] = { ...caps[1], op_cert: new Uint8Array([0xff, 0xff, 0xff]) };
    try {
      diagnoseClockFromCapabilities(1_000n, caps, []);
      throw new Error("expected a ClockDiagnosticError, but nothing threw");
    } catch (e) {
      expect(e).toBeInstanceOf(ClockDiagnosticError);
      expect((e as ClockDiagnosticError).kind).toBe("MalformedOpCert");
      expect((e as ClockDiagnosticError).index).toBe(1);
    }
  });

  // The host path (td-583db5 scope widening): a host holds its own HostOpKeyCert and may hold no
  // capabilities at all, and must still get the check.
  it("extra op certs alone drive the host path", () => {
    const cert = fakeHostOpKeyCert(7_000n, 0xffff_ffff_ffff_ffffn);
    const diagnosis = diagnoseClockFromCapabilities(1_000n, [], [cert]);
    expectProvablyBehind(diagnosis, 6_000n, 7_000n);
  });
});

// ---- leg (2): offsetFromDateHeader ---------------------------------------------------------

describe("offsetFromDateHeader", () => {
  // Ground truth from Python's `email.utils.parsedate_to_datetime` (an independent
  // implementation). The Rust twin (`clock_diagnostics.rs`'s
  // `ground_truth_vectors_from_an_independent_parser`) pins this EXACT same set of six vectors —
  // pinning them here too makes the two languages provably agree on the calendar computation
  // itself, rather than merely each being internally self-consistent. `localNow = 0n` so the
  // offset equals the parsed timestamp directly.
  it("ground truth vectors from an independent parser (same six as the Rust twin)", () => {
    const vectors: Array<[string, bigint]> = [
      ["Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777n], // RFC 9110's own example
      ["Thu, 01 Jan 1970 00:00:00 GMT", 0n],
      ["Sat, 29 Feb 2020 12:00:00 GMT", 1_582_977_600n],
      ["Tue, 29 Feb 2000 00:00:00 GMT", 951_782_400n], // 2000 IS a leap year
      ["Fri, 31 Dec 2038 23:59:59 GMT", 2_177_452_799n], // past the 32-bit cliff
      ["Wed, 01 Jan 2025 00:00:00 GMT", 1_735_689_600n],
    ];
    for (const [header, expected] of vectors) {
      const offset = offsetFromDateHeader(0n, header);
      expect(offset.diagnosticSeconds(), `header: ${header}`).toBe(expected);
    }
  });

  it("local clock behind the https source yields a positive offset", () => {
    const offset = offsetFromDateHeader(700_000_000n, "Sun, 06 Nov 1994 08:49:37 GMT");
    expect(offset.diagnosticSeconds()).toBe(784_111_777n - 700_000_000n);
    expect(offset.diagnosticSeconds() > 0n).toBe(true);
  });

  // Unlike leg (1), leg (2) CAN prove this direction — the whole reason §A10.42 offers it.
  it("local clock ahead of the https source yields a negative offset", () => {
    const offset = offsetFromDateHeader(800_000_000n, "Sun, 06 Nov 1994 08:49:37 GMT");
    expect(offset.diagnosticSeconds()).toBe(784_111_777n - 800_000_000n);
    expect(offset.diagnosticSeconds() < 0n).toBe(true);
  });

  it("local clock exactly matching the https source yields zero", () => {
    const offset = offsetFromDateHeader(784_111_777n, "Sun, 06 Nov 1994 08:49:37 GMT");
    expect(offset.diagnosticSeconds()).toBe(0n);
  });

  it("Feb 29 in a non-leap year is rejected", () => {
    expectDateHeaderError(() => offsetFromDateHeader(0n, "Sun, 29 Feb 2021 12:00:00 GMT"), "InvalidDayOfMonth");
  });

  // The %100 rule: 2100 is divisible by 4 but also by 100 and not by 400, so it is NOT a leap year.
  it("Feb 29 in a century non-leap year (2100) is rejected", () => {
    expectDateHeaderError(() => offsetFromDateHeader(0n, "Mon, 29 Feb 2100 00:00:00 GMT"), "InvalidDayOfMonth");
  });

  it("April 31st is rejected — April has thirty days", () => {
    expectDateHeaderError(() => offsetFromDateHeader(0n, "Thu, 31 Apr 2025 00:00:00 GMT"), "InvalidDayOfMonth");
  });

  // A leap second is accepted and clamped to :59's value rather than refused outright — POSIX
  // time has no leap second, and a one-second error in a diagnostic is immaterial.
  it("leap second 60 is accepted and clamped to 59", () => {
    const clamped = offsetFromDateHeader(0n, "Thu, 01 Jan 1970 00:00:60 GMT");
    const fiftyNine = offsetFromDateHeader(0n, "Thu, 01 Jan 1970 00:00:59 GMT");
    expect(clamped.diagnosticSeconds()).toBe(fiftyNine.diagnosticSeconds());
  });

  it("RFC 850 obsolete form is rejected by name", () => {
    const err = expectDateHeaderError(
      () => offsetFromDateHeader(0n, "Sunday, 06-Nov-94 08:49:37 GMT"),
      "ObsoleteFormat",
    );
    expect(err.form).toContain("RFC 850");
  });

  // The full-day-name check is not hard-coded to "Sunday": any of the seven full English day
  // names must trigger the same RFC 850 attribution.
  it("RFC 850 full day name check is not hard-coded to one name", () => {
    const err = expectDateHeaderError(
      () => offsetFromDateHeader(0n, "Wednesday, 06-Nov-94 08:49:37 GMT"),
      "ObsoleteFormat",
    );
    expect(err.form).toContain("RFC 850");
  });

  // A comma anywhere other than the IMF-fixdate position must not be blamed on RFC 850 unless a
  // FULL day name actually precedes it — "garbage,x" has a misplaced comma but no full day name
  // before it, so it must fall through to an ordinary error instead of a false RFC 850
  // attribution.
  it("a misplaced comma without a full day name is not blamed on RFC 850", () => {
    let thrown: unknown;
    try {
      offsetFromDateHeader(0n, "garbage,x");
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(DateHeaderError);
    expect((thrown as DateHeaderError).kind).not.toBe("ObsoleteFormat");
  });

  it("asctime obsolete form is rejected by name", () => {
    const err = expectDateHeaderError(() => offsetFromDateHeader(0n, "Sun Nov  6 08:49:37 1994"), "ObsoleteFormat");
    expect(err.form).toContain("asctime");
  });

  it("+0000 offset instead of GMT is rejected", () => {
    expectThrowsDateHeaderError(() => offsetFromDateHeader(0n, "Sun, 06 Nov 1994 08:49:37 +0000"));
  });

  it("unknown month name is rejected", () => {
    expectDateHeaderError(() => offsetFromDateHeader(0n, "Sun, 06 Xxx 1994 08:49:37 GMT"), "UnknownMonth");
  });

  it("unknown day name is rejected", () => {
    expectDateHeaderError(() => offsetFromDateHeader(0n, "Xxx, 06 Nov 1994 08:49:37 GMT"), "UnknownDayName");
  });

  // RFC 9110 makes the day-of-week redundant with the computed date; this parser deliberately
  // does NOT cross-check the two, so a disagreeing (but well-formed) day name is ACCEPTED.
  // 1994-11-06 was actually a Sunday — "Mon" here is wrong and accepted anyway.
  it("a day name that disagrees with the date is accepted", () => {
    const offset = offsetFromDateHeader(0n, "Mon, 06 Nov 1994 08:49:37 GMT");
    expect(offset.diagnosticSeconds()).toBe(784_111_777n);
  });

  // RFC 9110's `OWS = *( SP / HTAB )` may survive into the value an HTTP client hands over.
  // Trimming it is what keeps an untrimmed header from failing the fixed-length check and
  // silently producing no diagnostic at all.
  it("surrounding OWS is trimmed before the length check", () => {
    for (const header of [
      " Sun, 06 Nov 1994 08:49:37 GMT",
      "Sun, 06 Nov 1994 08:49:37 GMT ",
      "\t Sun, 06 Nov 1994 08:49:37 GMT \t",
      "   Sun, 06 Nov 1994 08:49:37 GMT   ",
    ]) {
      expect(offsetFromDateHeader(0n, header).diagnosticSeconds(), header).toBe(784_111_777n);
    }
  });

  // Only SP and HTAB are OWS. `String.prototype.trim` would also strip \n, \r, and U+00A0;
  // accepting those would widen what counts as a well-formed Date header past RFC 9110.
  it("non-OWS whitespace is not trimmed", () => {
    for (const header of [
      "\nSun, 06 Nov 1994 08:49:37 GMT",
      "Sun, 06 Nov 1994 08:49:37 GMT\r",
      "\u00a0Sun, 06 Nov 1994 08:49:37 GMT",
    ]) {
      expectThrowsDateHeaderError(() => offsetFromDateHeader(0n, header));
    }
  });

  it("year before Unix epoch is rejected", () => {
    const err = expectDateHeaderError(() => offsetFromDateHeader(0n, "Wed, 01 Jan 1969 00:00:00 GMT"), "BeforeUnixEpoch");
    expect(err.year).toBe(1969);
  });

  it("header one byte too short is rejected", () => {
    const short = "Sun, 06 Nov 1994 08:49:37 GM"; // 28 chars
    expect(short.length).toBe(28);
    const err = expectDateHeaderError(() => offsetFromDateHeader(0n, short), "InvalidLength");
    expect(err.len).toBe(28);
  });

  it("header one byte too long is rejected", () => {
    const long = "Sun, 06 Nov 1994 08:49:37 GMTT"; // 30 chars
    expect(long.length).toBe(30);
    const err = expectDateHeaderError(() => offsetFromDateHeader(0n, long), "InvalidLength");
    expect(err.len).toBe(30);
  });

  // A multi-code-unit input must be rejected, never throw an unexpected error.
  it("non-ASCII multi-byte input is rejected without an unexpected throw", () => {
    expectThrowsDateHeaderError(() => offsetFromDateHeader(0n, "Sün, 06 Nov 1994 08:49:37 GMT"));
  });

  // This input's comma sits where a viewer might expect RFC 850's misattribution logic to trip
  // (Rust's byte-indexed version saw the comma at byte 4, not 3, because 'ü' is a two-byte UTF-8
  // sequence there — see `clock-diagnostics.ts`'s `parseImfFixdate` doc comment for why
  // TypeScript's UTF-16 code-unit view does not reproduce that particular byte/char offset, and
  // why it does not need to: the ASCII gate fires first regardless). It must be reported as
  // non-ASCII, not as an obsolete format.
  it("non-ASCII input is reported as non-ASCII, not as an obsolete format", () => {
    const err = expectDateHeaderError(() => offsetFromDateHeader(0n, "Sün, 06 Nov 1994 08:49:37 GMT"), "NonAscii");
    expect(err.kind).not.toBe("ObsoleteFormat");
  });

  // Regression pin (mirrors the Rust twin's DEFECT 1 regression test): the asctime pre-check must
  // guard on `length >= 8` before reading index 7, not `length >= 7`. This exact 7-character input
  // is the one that panicked in Rust before that fix; pinned by name so the regression can never
  // silently come back.
  it("a seven-character header is rejected without an unexpected throw", () => {
    expectThrowsDateHeaderError(() => offsetFromDateHeader(0n, "Sun Nov"));
  });

  // Every truncation of a valid header, enumerated rather than sampled — mirrors the Rust twin's
  // `every_truncation_of_a_valid_header_is_rejected_without_panicking`. Two fixtures are
  // truncated, not one: the Rust twin's own neuter run proved a single comma-bearing fixture is
  // not enough, because every prefix of length >= 4 of that fixture already has its comma at
  // index 3, so control always takes the RFC-850 branch and never reaches the comma-less asctime
  // arm that indexes position 7 — the only arm the length-8 guard protects. Truncating the
  // genuine comma-less asctime form alongside it drives every prefix length through that arm
  // instead.
  it("every truncation of a valid header is rejected without an unexpected throw", () => {
    const fixtures = [
      "Sun, 06 Nov 1994 08:49:37 GMT", // comma-bearing: exercises the `Some(3)`-equivalent branch
      "Sun Nov  6 08:49:37 1994", // comma-less: exercises the asctime arm, index 7
    ];
    for (const valid of fixtures) {
      for (let len = 0; len < valid.length; len++) {
        const prefix = valid.slice(0, len);
        try {
          expectThrowsDateHeaderError(() => offsetFromDateHeader(0n, prefix));
        } catch (e) {
          throw new Error(`prefix of length ${len} of ${JSON.stringify(valid)}: ${(e as Error).message}`);
        }
      }
    }
  });

  it("non-digit in a numeric field is rejected", () => {
    expectDateHeaderError(() => offsetFromDateHeader(0n, "Sun, 0X Nov 1994 08:49:37 GMT"), "NonDigit");
  });
});

// ---- leg (2): HttpsDateSource ---------------------------------------------------------------

class FakeGoodSource implements HttpsDateSource {
  constructor(private readonly header: string) {}
  async fetchDateHeader(): Promise<string> {
    return this.header;
  }
}

class FakeFailingSource implements HttpsDateSource {
  async fetchDateHeader(): Promise<string> {
    throw new HttpsDateSourceError("connection reset by peer");
  }
}

describe("diagnoseClockFromHttps", () => {
  it("a good header yields a computed offset", async () => {
    const source = new FakeGoodSource("Sun, 06 Nov 1994 08:49:37 GMT");
    const offset = await diagnoseClockFromHttps(700_000_000n, source);
    expect(offset.diagnosticSeconds()).toBe(784_111_777n - 700_000_000n);
  });

  // A transport failure must propagate as an error, not be swallowed into some default offset.
  it("a transport error propagates, not swallowed", async () => {
    const source = new FakeFailingSource();
    try {
      await diagnoseClockFromHttps(0n, source);
      throw new Error("expected diagnoseClockFromHttps to reject");
    } catch (e) {
      expect(e).toBeInstanceOf(HttpsDateError);
      expect((e as HttpsDateError).kind).toBe("Source");
      expect((e as HttpsDateError).source?.message).toBe("connection reset by peer");
    }
  });
});

// ---- the u64 domain, and the one divergence it does not close (td-fc3b88) --------------------
//
// Rust's twins take `u64`. Two things follow that TypeScript does not get for free:
//
//   1. Out-of-domain inputs are not writable in Rust at all. `bigint` is unbounded and signed, so
//      they ARE writable here, and until td-fc3b88 they got an answer — `diagnoseClock(-1n, [0n],
//      [])` returned a confident `ProvablyBehind`. `assertU64` now rejects them at every entry
//      point, so both twins take the same domain.
//   2. Inside that shared domain, `[2**63, 2**64)` is legal on both sides and the two do NOT
//      agree: Rust narrows with `i64::try_from(..).unwrap_or(i64::MAX)` and clamps, `bigint` has
//      no width and stays exact. That is the only surviving divergence, and these tests are what
//      make it an asserted property rather than an undocumented accident. Each cites the Rust
//      test it diverges from, so neither side can drift without the other's number being wrong.

const U64_MAX = 2n ** 64n - 1n;

describe("the u64 domain", () => {
  // Rust: `an_absurd_bound_saturates_instead_of_wrapping` asserts
  // `behind_by.diagnostic_seconds() == i64::MAX` for the same input. This asserts the exact value
  // instead. Both refuse to flip sign, which is the property A10.42 actually requires.
  it("leg (1) is EXACT where the Rust twin saturates at i64::MAX", () => {
    const diagnosis = diagnoseClock(0n, [U64_MAX], []);
    expect(diagnosis.kind).toBe("ProvablyBehind");
    if (diagnosis.kind !== "ProvablyBehind") throw new Error("unreachable");
    expect(diagnosis.behindBy.diagnosticSeconds()).toBe(U64_MAX);
    expect(diagnosis.behindBy.diagnosticSeconds()).toBeGreaterThan(2n ** 63n - 1n); // Rust clamps here
    expect(diagnosis.boundTs).toBe(U64_MAX);
  });

  // Rust: `leg_two_local_now_above_i64_max_saturates` asserts -9223372036070664030 for this input
  // (784111777 - i64::MAX). Exact here, and still negative — locally-ahead, the correct direction.
  it("leg (2) is EXACT where the Rust twin saturates at i64::MAX", () => {
    const offset = offsetFromDateHeader(U64_MAX, "Sun, 06 Nov 1994 08:49:37 GMT");
    expect(offset.diagnosticSeconds()).toBe(784_111_777n - U64_MAX);
    expect(offset.diagnosticSeconds()).toBeLessThan(0n);
  });

  // The boundary itself: the largest legal u64 is accepted, one more is not. A test written
  // against `U64_MAX` alone would leave the actual number free (see the symbolic-constant trap).
  it("2**64 - 1 is accepted and 2**64 is rejected", () => {
    expect(() => diagnoseClock(18_446_744_073_709_551_615n, [], [])).not.toThrow();
    expect(() => diagnoseClock(18_446_744_073_709_551_616n, [], [])).toThrow(RangeError);
  });

  // The silent case td-fc3b88 was filed for: this used to return ProvablyBehind { behindBy: 1n }.
  it("a negative localNow is rejected, not answered", () => {
    expect(() => diagnoseClock(-1n, [0n], [])).toThrow(RangeError);
  });

  it("a negative capability exp is rejected, not answered", () => {
    expect(() => diagnoseClock(0n, [], [-5n])).toThrow(RangeError);
  });

  it("a negative op-cert timestamp is rejected", () => {
    expect(() => diagnoseClock(0n, [-1n], [])).toThrow(RangeError);
  });

  // Every entry point, not just the one the finding named — the check is worth nothing if a
  // caller can reach the arithmetic around it.
  it("every entry point rejects an out-of-domain localNow", async () => {
    expect(() => diagnoseClock(-1n, [], [])).toThrow(RangeError);
    expect(() => diagnoseClockFromCapabilities(-1n, [], [])).toThrow(RangeError);
    expect(() => offsetFromDateHeader(-1n, "Sun, 06 Nov 1994 08:49:37 GMT")).toThrow(RangeError);
    await expect(diagnoseClockFromHttps(-1n, new FakeGoodSource("Sun, 06 Nov 1994 08:49:37 GMT"))).rejects.toThrow(
      RangeError,
    );
  });

  // diagnoseClockFromHttps checks before awaiting: a caller bug must not cost a network request.
  it("diagnoseClockFromHttps rejects before it calls the source", async () => {
    let called = false;
    const source: HttpsDateSource = {
      async fetchDateHeader(): Promise<string> {
        called = true;
        return "Sun, 06 Nov 1994 08:49:37 GMT";
      },
    };
    await expect(diagnoseClockFromHttps(-1n, source)).rejects.toThrow(RangeError);
    expect(called).toBe(false);
  });
});
