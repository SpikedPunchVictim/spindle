// SHA-256, HKDF-SHA256, and AES-256-GCM — WebCrypto-only (see `src/primitives.ts`'s module docs
// for why there is no `@noble/curves` backend to test parity against here). SHA-256 is checked
// against a standard known-answer vector; HKDF-SHA256's zero-salt convention and AES-256-GCM are
// exercised end-to-end by the envelope golden vector (`test/envelope-vectors.test.ts`) against
// real `spindle-core` output, so this file covers self-consistency and failure modes instead of
// duplicating that byte-for-byte check.

import { bytesToHex } from "@spindle/proto";
import { describe, expect, it } from "vitest";

import { aesGcmOpen, aesGcmSeal, hkdfSha256, sha256 } from "../src/primitives.js";

describe("sha256", () => {
  it("matches the standard known-answer vector for \"abc\"", async () => {
    const digest = await sha256(new TextEncoder().encode("abc"));
    expect(bytesToHex(digest)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("matches the known-answer vector for the empty string", async () => {
    const digest = await sha256(new Uint8Array(0));
    expect(bytesToHex(digest)).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});

describe("hkdfSha256", () => {
  it("is deterministic for the same inputs", async () => {
    const ikm = new Uint8Array(32).fill(0xab);
    const info = new TextEncoder().encode("spindle test info");
    const a = await hkdfSha256(ikm, info, 32);
    const b = await hkdfSha256(ikm, info, 32);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
    expect(a).toHaveLength(32);
  });

  it("different info strings produce different output", async () => {
    const ikm = new Uint8Array(32).fill(0xab);
    const a = await hkdfSha256(ikm, new TextEncoder().encode("info-a"), 32);
    const b = await hkdfSha256(ikm, new TextEncoder().encode("info-b"), 32);
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });

  it("supports non-default output lengths", async () => {
    const ikm = new Uint8Array(32).fill(0xcd);
    const info = new TextEncoder().encode("length test");
    const out = await hkdfSha256(ikm, info, 16);
    expect(out).toHaveLength(16);
  });
});

describe("aesGcmSeal/aesGcmOpen", () => {
  const key = new Uint8Array(32).fill(0x01);
  const nonce = new Uint8Array(12).fill(0x02);
  const aad = new TextEncoder().encode("associated data");
  const plaintext = new TextEncoder().encode("spindle plaintext");

  it("round-trips", async () => {
    const ciphertext = await aesGcmSeal(key, nonce, aad, plaintext);
    // 16-byte GCM tag appended, matching the Rust `aes-gcm` crate's default tag length.
    expect(ciphertext).toHaveLength(plaintext.length + 16);
    const opened = await aesGcmOpen(key, nonce, aad, ciphertext);
    expect(bytesToHex(opened)).toBe(bytesToHex(plaintext));
  });

  it("rejects a tampered ciphertext", async () => {
    const ciphertext = await aesGcmSeal(key, nonce, aad, plaintext);
    const tampered = ciphertext.slice();
    tampered[0] ^= 0xff;
    await expect(aesGcmOpen(key, nonce, aad, tampered)).rejects.toThrow();
  });

  it("rejects a tampered AAD", async () => {
    const ciphertext = await aesGcmSeal(key, nonce, aad, plaintext);
    const wrongAad = new TextEncoder().encode("wrong associated data");
    await expect(aesGcmOpen(key, nonce, wrongAad, ciphertext)).rejects.toThrow();
  });

  it("rejects the wrong key", async () => {
    const ciphertext = await aesGcmSeal(key, nonce, aad, plaintext);
    const wrongKey = new Uint8Array(32).fill(0xff);
    await expect(aesGcmOpen(wrongKey, nonce, aad, ciphertext)).rejects.toThrow();
  });
});
