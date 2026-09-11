// Pins the *value* 120 of the four A10.42 clock-skew constants. DESIGN.md's §A7 changelog for
// v0.9.30 states the decision this test enforces: "The ±2 min window itself is deliberately left
// at 120s (td-e8b79f)" — later folded into A10.42's cold-clock diagnostic (v0.9.32, closing
// td-e8b79f). That is one decision, applied to four constants across two languages:
// `envelope.ts`'s `CLOCK_SKEW_SECS` and `artifacts.ts`'s `ADMIN_COMMAND_CLOCK_SKEW_SECS`,
// `SESSION_ATTESTATION_CLOCK_SKEW_SECS`, and `HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS`, plus
// their Rust twins pinned by `crates/spindle-core/tests/clock_skew_value_guard.rs`.
//
// That Rust guard already covers cross-language parity (it reads these two `.ts` files as text
// and checks their literals against the same value). This test exists in addition so that a
// TypeScript-only run (`pnpm --filter @spindle/crypto test`) also reddens on a TS-side drift,
// without needing the Rust suite to catch it.
//
// This does not repeat the boundary-semantics tests already covering these constants (accept
// exactly at the window edge, reject one second past it, exercised via the symbolic constant in
// `envelope.test.ts` / `session-attestation.test.ts` / `host-session-attestation.test.ts`) — only
// the value 120 itself, which none of those tests pin.
//
// This test exists because it was demonstrated that widening
// `SESSION_ATTESTATION_CLOCK_SKEW_SECS` from 120 to 3600 left the entire Rust workspace suite
// and the whole crypto suite green — zero failures in either language. A device is refused when
// its clock is off by more than this window; silently widening one language's copy of it loosens
// a security bound in that language alone.
//
// # Neuter-verification
//
// Demonstrated on 2026-09-11, not assumed. Changing `HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS`
// in `src/artifacts.ts` from `120n` to `3600n` turned this test RED ("expected 3600n to be 120n"),
// and reverting it turned the file byte-identical to its original (`cmp` clean, `git diff
// --quiet` clean). The Rust twin, `clock_skew_value_guard.rs`, reddened on the same edit — that is
// the cross-language half. This test exists so a TypeScript-only run reddens on it too.

import { describe, expect, it } from "vitest";

import {
  ADMIN_COMMAND_CLOCK_SKEW_SECS,
  HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS,
  SESSION_ATTESTATION_CLOCK_SKEW_SECS,
} from "../src/artifacts.js";
import { CLOCK_SKEW_SECS } from "../src/envelope.js";

const DECIDED_SKEW_SECS = 120n;

// Shared tail for every assertion failure below: states *why* the value matters, not just that it
// changed.
function whyItMatters(constantName: string): string {
  return (
    `${constantName} no longer equals ${DECIDED_SKEW_SECS} -- the four A10.42 clock-skew ` +
    "windows are one decision (DESIGN.md §A7 changelog v0.9.30, td-e8b79f: \"The ±2 min window " +
    `itself is deliberately left at 120s\") and must stay equal to each other and to ` +
    `${DECIDED_SKEW_SECS} across both Rust and TypeScript. A device is refused when its clock ` +
    "is off by more than this window, so a silent widening loosens a security bound -- and if " +
    "only one language's copy moved, it loosens that bound in one language only, splitting " +
    "what both sides of a CONNECT are supposed to enforce identically."
  );
}

describe("clock-skew-value", () => {
  it("envelope.ts CLOCK_SKEW_SECS is 120", () => {
    expect(CLOCK_SKEW_SECS, whyItMatters("envelope.ts CLOCK_SKEW_SECS")).toBe(DECIDED_SKEW_SECS);
  });

  it("artifacts.ts ADMIN_COMMAND_CLOCK_SKEW_SECS is 120", () => {
    expect(
      ADMIN_COMMAND_CLOCK_SKEW_SECS,
      whyItMatters("artifacts.ts ADMIN_COMMAND_CLOCK_SKEW_SECS"),
    ).toBe(DECIDED_SKEW_SECS);
  });

  it("artifacts.ts SESSION_ATTESTATION_CLOCK_SKEW_SECS is 120", () => {
    expect(
      SESSION_ATTESTATION_CLOCK_SKEW_SECS,
      whyItMatters("artifacts.ts SESSION_ATTESTATION_CLOCK_SKEW_SECS"),
    ).toBe(DECIDED_SKEW_SECS);
  });

  it("artifacts.ts HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS is 120", () => {
    expect(
      HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS,
      whyItMatters("artifacts.ts HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS"),
    ).toBe(DECIDED_SKEW_SECS);
  });
});
