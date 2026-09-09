// Unit tests for `ProtoError.redacted()` — the TS twin of `crates/spindle-proto/src/artifacts.rs`'s
// `redacted_display_withholds_an_unknown_field_name_and_nothing_else` test. There is no
// `artifacts.test.ts` predating this file (`ProtoError` itself is otherwise exercised indirectly,
// through every other wire type's own test file), so this file exists solely for the redaction
// affordance added by td-37ff42.

import { describe, expect, it } from "vitest";

import { ProtoError } from "../src/artifacts.js";

describe("ProtoError.redacted()", () => {
  it("withholds an unknown field name and nothing else", () => {
    const leaky = ProtoError.unknownField("secret-peer-key-name");
    expect(leaky.message).toContain("secret-peer-key-name");

    const redacted = leaky.redacted();
    expect(redacted).not.toContain("secret-peer-key-name");
    // "secret-peer-key-name" is 20 bytes, all ASCII, so UTF-8 byte count equals string length.
    expect(redacted).toContain("20 bytes");
  });

  it("counts UTF-8 bytes, not UTF-16 code units, for the withheld field name", () => {
    // "café" is 4 UTF-16 code units but 5 UTF-8 bytes (é is 2 bytes) — proves the redacted count
    // matches Rust's `name.len()` (UTF-8 bytes), not JS's `string.length` (UTF-16 code units).
    const leaky = ProtoError.unknownField("café");
    expect(leaky.field?.length).toBe(4);
    expect(leaky.redacted()).toContain("5 bytes");
    expect(leaky.redacted()).not.toContain("4 bytes");
  });

  it("leaves every other kind's rendering unchanged", () => {
    const safeCases: ProtoError[] = [
      ProtoError.notAMap(),
      ProtoError.missingField("registry"),
      ProtoError.keyNotText(),
      ProtoError.wrongType("cert_fp"),
      ProtoError.intOutOfRange("kind"),
      ProtoError.invalidEnumValue("kind", 9n),
    ];
    for (const safe of safeCases) {
      expect(safe.redacted()).toBe(safe.message);
    }
  });
});
