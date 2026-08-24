// Backend parity: Ed25519 and X25519 are the two primitives with a real dual-backend split
// (WebCrypto vs. `@noble/curves` — see `src/backend.ts`'s module docs for why HKDF/AES-GCM/SHA-256
// don't need this suite: they are WebCrypto-only, per DESIGN.md §A7). Every case here runs against
// both backends explicitly (`{ backend: "webcrypto" }` / `{ backend: "noble" }`, no auto-fallback)
// and cross-checks that they agree byte-for-byte. Node 22 is expected to support both natively
// (DESIGN.md §A7's browser-support note); a runtime that genuinely lacks WebCrypto Ed25519/X25519
// skips those specific cases with an explicit message via `probeWebCryptoSupport`, rather than
// failing.

import { bytesToHex } from "@spindle/proto";
import { describe, expect, it } from "vitest";

import {
  type AsymmetricBackend,
  ed25519PublicKeyFromSeed,
  ed25519Sign,
  ed25519Verify,
  probeWebCryptoSupport,
  x25519PublicKeyFromSeed,
  x25519SharedSecret,
} from "../src/backend.js";

const BACKENDS: AsymmetricBackend[] = ["webcrypto", "noble"];

// Top-level await: Vitest collects `describe`/`it` blocks only after a test file's module-level
// code (including any top-level awaits) finishes running, so `support` is already populated by
// the time the `itOrSkip` calls below decide whether to register a real test or a skip.
const support = await probeWebCryptoSupport();

function itOrSkip(backend: AsymmetricBackend, algorithm: "ed25519" | "x25519") {
  const supported = backend === "noble" || support[algorithm];
  if (supported) return it;
  const skipMessage = `[skipped: this runtime's WebCrypto does not support ${algorithm}]`;
  return (name: string, fn: () => unknown) => it.skip(`${skipMessage} ${name}`, fn);
}

describe("Ed25519: public key from seed matches across backends", () => {
  for (const backend of BACKENDS) {
    itOrSkip(backend, "ed25519")(`backend=${backend}`, async () => {
      const seed = new Uint8Array(32).fill(0x77);
      const pk = await ed25519PublicKeyFromSeed(seed, { backend });
      expect(pk).toHaveLength(32);
    });
  }

  it("webcrypto and noble derive the identical public key for the same seed", async () => {
    if (!support.ed25519) return; // graceful skip: assertion body only, see itOrSkip cases above
    const seed = new Uint8Array(32).fill(0x77);
    const fromWebCrypto = await ed25519PublicKeyFromSeed(seed, { backend: "webcrypto" });
    const fromNoble = await ed25519PublicKeyFromSeed(seed, { backend: "noble" });
    expect(bytesToHex(fromWebCrypto)).toBe(bytesToHex(fromNoble));
  });
});

describe("Ed25519: sign/verify parity", () => {
  const seed = new Uint8Array(32).fill(0x88);
  const message = new TextEncoder().encode("spindle backend parity");

  for (const signBackend of BACKENDS) {
    for (const verifyBackend of BACKENDS) {
      itOrSkip(signBackend, "ed25519")(
        `sign(${signBackend}) verifies under verify(${verifyBackend})`,
        async () => {
          if (verifyBackend === "webcrypto" && !support.ed25519) return;
          const sig = await ed25519Sign(seed, message, { backend: signBackend });
          const pk = await ed25519PublicKeyFromSeed(seed, { backend: signBackend });
          const ok = await ed25519Verify(pk, message, sig, { backend: verifyBackend });
          expect(ok).toBe(true);
        },
      );
    }
  }

  it("webcrypto and noble produce byte-identical signatures for the same seed/message (Ed25519 is deterministic — RFC 8032)", async () => {
    if (!support.ed25519) return;
    const sigWebCrypto = await ed25519Sign(seed, message, { backend: "webcrypto" });
    const sigNoble = await ed25519Sign(seed, message, { backend: "noble" });
    expect(bytesToHex(sigWebCrypto)).toBe(bytesToHex(sigNoble));
  });

  for (const backend of BACKENDS) {
    itOrSkip(backend, "ed25519")(`backend=${backend} rejects a tampered signature`, async () => {
      const sig = await ed25519Sign(seed, message, { backend });
      const tampered = sig.slice();
      tampered[0] ^= 0xff;
      const pk = await ed25519PublicKeyFromSeed(seed, { backend });
      const ok = await ed25519Verify(pk, message, tampered, { backend });
      expect(ok).toBe(false);
    });
  }
});

describe("X25519: public key from seed matches across backends", () => {
  for (const backend of BACKENDS) {
    itOrSkip(backend, "x25519")(`backend=${backend}`, async () => {
      const seed = new Uint8Array(32).fill(0x66);
      const pk = await x25519PublicKeyFromSeed(seed, { backend });
      expect(pk).toHaveLength(32);
    });
  }

  it("webcrypto and noble derive the identical public key for the same seed", async () => {
    if (!support.x25519) return;
    const seed = new Uint8Array(32).fill(0x66);
    const fromWebCrypto = await x25519PublicKeyFromSeed(seed, { backend: "webcrypto" });
    const fromNoble = await x25519PublicKeyFromSeed(seed, { backend: "noble" });
    expect(bytesToHex(fromWebCrypto)).toBe(bytesToHex(fromNoble));
  });
});

describe("X25519: ECDH shared-secret parity", () => {
  for (const backend of BACKENDS) {
    itOrSkip(backend, "x25519")(`backend=${backend}: both sides derive the same shared secret`, async () => {
      const seedA = new Uint8Array(32).fill(0x21);
      const seedB = new Uint8Array(32).fill(0x22);
      const pkA = await x25519PublicKeyFromSeed(seedA, { backend });
      const pkB = await x25519PublicKeyFromSeed(seedB, { backend });
      const sharedFromA = await x25519SharedSecret(seedA, pkB, { backend });
      const sharedFromB = await x25519SharedSecret(seedB, pkA, { backend });
      expect(bytesToHex(sharedFromA)).toBe(bytesToHex(sharedFromB));
    });
  }

  it("webcrypto and noble derive the identical shared secret for the same seeds", async () => {
    if (!support.x25519) return;
    const seedA = new Uint8Array(32).fill(0x21);
    const seedB = new Uint8Array(32).fill(0x22);
    const pkBWebCrypto = await x25519PublicKeyFromSeed(seedB, { backend: "webcrypto" });
    const sharedWebCrypto = await x25519SharedSecret(seedA, pkBWebCrypto, { backend: "webcrypto" });
    const pkBNoble = await x25519PublicKeyFromSeed(seedB, { backend: "noble" });
    const sharedNoble = await x25519SharedSecret(seedA, pkBNoble, { backend: "noble" });
    expect(bytesToHex(sharedWebCrypto)).toBe(bytesToHex(sharedNoble));
  });
});

describe("auto backend selection (no explicit `backend` option)", () => {
  it("Ed25519 sign/verify works with no backend specified", async () => {
    const seed = new Uint8Array(32).fill(0x99);
    const message = new TextEncoder().encode("auto backend");
    const pk = await ed25519PublicKeyFromSeed(seed);
    const sig = await ed25519Sign(seed, message);
    await expect(ed25519Verify(pk, message, sig)).resolves.toBe(true);
  });

  it("X25519 shared secret works with no backend specified", async () => {
    const seedA = new Uint8Array(32).fill(0x23);
    const seedB = new Uint8Array(32).fill(0x24);
    const pkB = await x25519PublicKeyFromSeed(seedB);
    const shared = await x25519SharedSecret(seedA, pkB);
    expect(shared).toHaveLength(32);
  });
});
