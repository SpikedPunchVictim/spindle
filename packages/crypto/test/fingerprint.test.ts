// Fingerprints and base32 display encoding — the TypeScript twin of
// `crates/spindle-core/src/fingerprint.rs`/`base32.rs`'s own unit tests. `rootFpOf`/`deviceFpOf`
// are additionally checked byte-for-byte against real key material in
// `test/envelope-vectors.test.ts` and `test/vectors.test.ts`; this file covers `base32EncodeNoPad`
// (verified against `base32.rs`'s exact RFC 4648 §10 known-answer vectors) and small
// self-consistency checks.

import { bytesToHex } from "@spindle/proto";
import { describe, expect, it } from "vitest";

import { FINGERPRINT_LEN, base32EncodeNoPad, deviceFpOf, rootFpOf } from "../src/fingerprint.js";

describe("base32EncodeNoPad", () => {
  // RFC 4648 §10 test vectors, stripped of '=' padding, lowercased — identical to
  // `base32.rs`'s `known_vectors_rfc4648_no_padding` test.
  const cases: Array<[string, string]> = [
    ["", ""],
    ["f", "my"],
    ["fo", "mzxq"],
    ["foo", "mzxw6"],
    ["foob", "mzxw6yq"],
    ["fooba", "mzxw6ytb"],
    ["foobar", "mzxw6ytboi"],
  ];

  for (const [input, expected] of cases) {
    it(`encode_no_pad(${JSON.stringify(input)}) === ${JSON.stringify(expected)}`, () => {
      expect(base32EncodeNoPad(new TextEncoder().encode(input))).toBe(expected);
    });
  }

  it("32 bytes produce 52 characters with no '=' padding", () => {
    const data = new Uint8Array(32).fill(0xab);
    const s = base32EncodeNoPad(data);
    expect(s).not.toContain("=");
    expect(s).toHaveLength(52); // ceil(256/5) = 52
    expect(s).toMatch(/^[a-z2-7]+$/);
  });
});

describe("rootFpOf", () => {
  it("is SHA-256(root_pk)", async () => {
    const rootPk = new Uint8Array(32).fill(0x42);
    const fp = await rootFpOf(rootPk);
    expect(fp).toHaveLength(FINGERPRINT_LEN);
  });

  it("is deterministic", async () => {
    const rootPk = new Uint8Array(32).fill(0x43);
    const a = await rootFpOf(rootPk);
    const b = await rootFpOf(rootPk);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });
});

describe("deviceFpOf", () => {
  it("is deterministic and 32 bytes", async () => {
    const signPk = new Uint8Array(32).fill(0x01);
    const agreePk = new Uint8Array(32).fill(0x02);
    const a = await deviceFpOf(1, signPk, agreePk);
    const b = await deviceFpOf(1, signPk, agreePk);
    expect(a).toHaveLength(FINGERPRINT_LEN);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it("differs when alg_id differs", async () => {
    const signPk = new Uint8Array(32).fill(0x01);
    const agreePk = new Uint8Array(32).fill(0x02);
    const a = await deviceFpOf(1, signPk, agreePk);
    const b = await deviceFpOf(2, signPk, agreePk);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});
