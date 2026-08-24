// Primitive canonical CBOR conformance (vectors/canonical-cbor.json) plus hand-rolled negative
// tests mirroring the inline unit tests in crates/spindle-proto/src/canonical.rs — every rejection
// rule the strict decoder must enforce, exercised independently of any Spindle artifact type.

import { describe, expect, it } from "vitest";
import { CborError, CborValue, canonicalDecode, canonicalEncode } from "../src/canonical.js";
import { hexToBytes, bytesToHex } from "../src/hex.js";
import { loadVectorFile, normalize, parseCborTree } from "./helpers.js";

describe("canonical-cbor.json (primitive vectors)", () => {
  const doc = loadVectorFile("canonical-cbor.json");

  for (const c of doc.cases as Array<{
    name: string;
    description: string;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    value: any;
    canonical_cbor_hex: string;
  }>) {
    it(`${c.name}: encodes to canonical_cbor_hex`, () => {
      const value = parseCborTree(c.value);
      const encoded = canonicalEncode(value);
      expect(bytesToHex(encoded)).toBe(c.canonical_cbor_hex);
    });

    it(`${c.name}: decodes canonical_cbor_hex back to the same value`, () => {
      const expected = parseCborTree(c.value);
      const decoded = canonicalDecode(hexToBytes(c.canonical_cbor_hex));
      expect(normalize(decoded)).toEqual(normalize(expected));
    });

    it(`${c.name}: re-encoding the decoded value reproduces the original bytes`, () => {
      const decoded = canonicalDecode(hexToBytes(c.canonical_cbor_hex));
      expect(bytesToHex(canonicalEncode(decoded))).toBe(c.canonical_cbor_hex);
    });
  }
});

describe("canonical decode: rejection rules", () => {
  it("rejects a non-shortest-form integer (0x18 0x05 instead of 0x05)", () => {
    const err = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0x18, 0x05])));
    expect(err.kind).toBe("NonShortestForm");
    expect(err.offset).toBe(0);
  });

  it("rejects a non-shortest-form 2-byte length (byte string len=4 via 25 instead of inline)", () => {
    // 0x59 0x00 0x04 <4 bytes> — byte string, additional-info 25 (2-byte length) encoding the
    // value 4, which fits in the inline/1-byte forms.
    const err = expectThrowsCborError(() =>
      canonicalDecode(Uint8Array.from([0x59, 0x00, 0x04, 1, 2, 3, 4])),
    );
    expect(err.kind).toBe("NonShortestForm");
  });

  it("rejects an indefinite-length array (0x9f ... 0xff)", () => {
    const err = expectThrowsCborError(() =>
      canonicalDecode(Uint8Array.from([0x9f, 0x01, 0xff])),
    );
    expect(err.kind).toBe("IndefiniteLength");
    expect(err.offset).toBe(0);
  });

  it("rejects an indefinite-length map (0xbf ... 0xff)", () => {
    const err = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0xbf, 0xff])));
    expect(err.kind).toBe("IndefiniteLength");
  });

  it("rejects an indefinite-length byte string (0x5f ... 0xff)", () => {
    const err = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0x5f, 0xff])));
    expect(err.kind).toBe("IndefiniteLength");
  });

  it("rejects out-of-order map keys", () => {
    // map(2) { "aa": 1, "z": 2 } on the wire, in that (non-canonical) order — canonical order
    // requires the shorter key "z" (1-byte header) before the longer key "aa" (2-byte header).
    const bytes = Uint8Array.from([0xa2, 0x62, 0x61, 0x61, 0x01, 0x61, 0x7a, 0x02]);
    const err = expectThrowsCborError(() => canonicalDecode(bytes));
    expect(err.kind).toBe("MapKeyOrder");
  });

  it("rejects duplicate map keys", () => {
    const bytes = Uint8Array.from([0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]);
    const err = expectThrowsCborError(() => canonicalDecode(bytes));
    expect(err.kind).toBe("MapKeyOrder");
  });

  it("rejects floats (major 7, additional info 25/26/27)", () => {
    const f16 = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0xf9, 0, 0])));
    expect(f16.kind).toBe("FloatNotAllowed");
    const f32 = expectThrowsCborError(() =>
      canonicalDecode(Uint8Array.from([0xfa, 0, 0, 0, 0])),
    );
    expect(f32.kind).toBe("FloatNotAllowed");
    const f64 = expectThrowsCborError(() =>
      canonicalDecode(Uint8Array.from([0xfb, 0, 0, 0, 0, 0, 0, 0, 0])),
    );
    expect(f64.kind).toBe("FloatNotAllowed");
  });

  it("rejects tags (major type 6)", () => {
    const err = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0xc0, 0x00])));
    expect(err.kind).toBe("TagNotAllowed");
  });

  it("rejects simple values other than false/true/null (undefined, one-byte form)", () => {
    const undef = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0xf7])));
    expect(undef.kind).toBe("SimpleNotAllowed");
    const oneByte = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0xf8, 0x20])));
    expect(oneByte.kind).toBe("SimpleNotAllowed");
  });

  it("rejects reserved additional-info values (28-30)", () => {
    const err = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0x1c])));
    expect(err.kind).toBe("ReservedAdditionalInfo");
  });

  it("rejects invalid UTF-8 in a text string", () => {
    // major 3 (text), length 1, followed by 0xff (never valid as a UTF-8 lead byte).
    const err = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0x61, 0xff])));
    expect(err.kind).toBe("InvalidUtf8");
  });

  it("rejects trailing bytes after a complete top-level item", () => {
    const err = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([0x00, 0x00])));
    expect(err.kind).toBe("TrailingBytes");
    expect(err.offset).toBe(1);
  });

  it("rejects truncated input (unexpected EOF)", () => {
    // byte string header claims length 4 but only 2 bytes follow.
    const err = expectThrowsCborError(() =>
      canonicalDecode(Uint8Array.from([0x44, 0x01, 0x02])),
    );
    expect(err.kind).toBe("UnexpectedEof");
  });

  it("rejects an empty input", () => {
    const err = expectThrowsCborError(() => canonicalDecode(Uint8Array.from([])));
    expect(err.kind).toBe("UnexpectedEof");
  });
});

describe("canonical encode: map key sorting", () => {
  it("sorts shorter keys before longer keys regardless of content", () => {
    // "z" (1 byte, header 0x61) sorts before "aa" (2 bytes, header 0x62), even though "aa" < "z"
    // lexicographically — canonical CBOR sorts by encoded bytes, which puts shorter keys first.
    const value = CborValue.map([
      ["aa", CborValue.uint(1)],
      ["z", CborValue.uint(2)],
    ]);
    const encoded = canonicalEncode(value);
    expect(bytesToHex(encoded)).toBe("a2617a0262616101");
  });
});

function expectThrowsCborError(fn: () => unknown): CborError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(CborError);
    return e as CborError;
  }
  throw new Error("expected function to throw a CborError, but it did not throw");
}
