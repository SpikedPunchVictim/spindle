// MUST-check negative tests for `seal`/`open` (DESIGN.md §A7), one per `EnvelopeError` kind —
// the TypeScript twin of `crates/spindle-core/src/envelope.rs`'s `#[cfg(test)] mod tests`. Uses
// the same TEST-ONLY fixture seeds as the Rust suite (not the golden-vector seeds — this suite
// exercises this package's own `seal`/`open` round-trip logic, not vector conformance; see
// `test/envelope-vectors.test.ts` for that) so the two suites are easy to cross-reference.

import { describe, expect, it } from "vitest";

import { ed25519PublicKeyFromSeed, x25519PublicKeyFromSeed, x25519SharedSecret } from "../src/backend.js";
import {
  CLOCK_SKEW_SECS,
  type OpenParams,
  type SealParams,
  deriveBootstrapKey,
  deriveSessionKey,
  directionByte,
  open,
  seal,
} from "../src/envelope.js";
import { deviceFpOf } from "../src/fingerprint.js";

async function buildDevice(signSeedByte: number, agreeSeedByte: number) {
  const signSeed = new Uint8Array(32).fill(signSeedByte);
  const agreeSeed = new Uint8Array(32).fill(agreeSeedByte);
  const signPk = await ed25519PublicKeyFromSeed(signSeed);
  const agreePk = await x25519PublicKeyFromSeed(agreeSeed);
  const fp = await deviceFpOf(1, signPk, agreePk);
  return { signSeed, signPk, agreeSeed, agreePk, fp };
}

async function buildFixture() {
  const devA = await buildDevice(0x10, 0x11); // client role: from_fp in session-key info
  const devB = await buildDevice(0x20, 0x21); // host role: to_fp in session-key info

  const ephASeed = new Uint8Array(32).fill(0x30);
  const ephBSeed = new Uint8Array(32).fill(0x40);
  const ephBPk = await x25519PublicKeyFromSeed(ephBSeed);
  const ephDh = await x25519SharedSecret(ephASeed, ephBPk);

  const devDh = await x25519SharedSecret(devA.agreeSeed, devB.agreePk);

  const sid = new Uint8Array(16).fill(0x99);
  const sessionKey = await deriveSessionKey(ephDh, devDh, sid, devA.fp, devB.fp);

  return { devA, devB, sid, sessionKey };
}

type Fixture = Awaited<ReturnType<typeof buildFixture>>;

async function sealAToB(fx: Fixture, seq: bigint, ts: bigint) {
  const params: SealParams = {
    sessionKey: fx.sessionKey,
    signSeed: fx.devA.signSeed,
    v: 1,
    algId: 1,
    fromFp: fx.devA.fp,
    toFp: fx.devB.fp,
    sid: fx.sid,
    kind: 7,
    seq,
    ts,
    plaintext: new TextEncoder().encode("hello host"),
  };
  return seal(params);
}

function baseOpenParams(fx: Fixture, now: bigint): OpenParams {
  return {
    sessionKey: fx.sessionKey,
    pinnedSenderKey: fx.devA.signPk,
    selfFp: fx.devB.fp,
    expectedSid: fx.sid,
    now,
    minV: 1,
    minAlgId: 1,
    expectedKind: 7,
    senderRevoked: false,
  };
}

describe("seal/open round-trip", () => {
  it("round_trip_seal_then_open", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const opened = await open(baseOpenParams(fx, 1000n), env);
    expect(new TextDecoder().decode(opened)).toBe("hello host");
  });

  it("bidirectional_session_nonces_never_collide", async () => {
    const fx = await buildFixture();

    const envAb = await sealAToB(fx, 0n, 1000n);
    const plaintextAb = await open(baseOpenParams(fx, 1000n), envAb);
    expect(new TextDecoder().decode(plaintextAb)).toBe("hello host");

    const envBa = await seal({
      sessionKey: fx.sessionKey,
      signSeed: fx.devB.signSeed,
      v: 1,
      algId: 1,
      fromFp: fx.devB.fp,
      toFp: fx.devA.fp,
      sid: fx.sid,
      kind: 8,
      seq: 0n,
      ts: 1001n,
      plaintext: new TextEncoder().encode("hello client"),
    });
    expect(directionByte(fx.devA.fp, fx.devB.fp)).not.toBe(directionByte(fx.devB.fp, fx.devA.fp));

    const openParamsBa: OpenParams = {
      sessionKey: fx.sessionKey,
      pinnedSenderKey: fx.devB.signPk,
      selfFp: fx.devA.fp,
      expectedSid: fx.sid,
      now: 1001n,
      minV: 1,
      minAlgId: 1,
      expectedKind: 8,
      senderRevoked: false,
    };
    const plaintextBa = await open(openParamsBa, envBa);
    expect(new TextDecoder().decode(plaintextBa)).toBe("hello client");

    // A second A->B message at seq=1 must still decrypt correctly.
    const envAb2 = await sealAToB(fx, 1n, 1002n);
    const p = { ...baseOpenParams(fx, 1002n), minSeqExclusive: 0n };
    const opened2 = await open(p, envAb2);
    expect(new TextDecoder().decode(opened2)).toBe("hello host");
  });

  it("first_message_of_session_has_no_seq_floor", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    await expect(open(baseOpenParams(fx, 1000n), env)).resolves.toBeDefined();
  });
});

describe("MUST-check negatives (one per EnvelopeError kind)", () => {
  it("rejects_bad_signature", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    env.sig = env.sig.slice();
    env.sig[0] ^= 0xff;
    await expect(open(baseOpenParams(fx, 1000n), env)).rejects.toMatchObject({ kind: "BadSignature" });
  });

  it("rejects_version_below_pinned_minimum", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const params = { ...baseOpenParams(fx, 1000n), minV: 2 };
    await expect(open(params, env)).rejects.toMatchObject({ kind: "VersionTooLow", actual: 1, minimum: 2 });
  });

  it("rejects_alg_id_below_pinned_minimum", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const params = { ...baseOpenParams(fx, 1000n), minAlgId: 2 };
    await expect(open(params, env)).rejects.toMatchObject({ kind: "AlgIdTooLow", actual: 1, minimum: 2 });
  });

  it("rejects_wrong_recipient", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const other = await buildDevice(0x50, 0x51);
    const params = { ...baseOpenParams(fx, 1000n), selfFp: other.fp };
    await expect(open(params, env)).rejects.toMatchObject({ kind: "WrongRecipient" });
  });

  it("rejects_revoked_sender", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const params = { ...baseOpenParams(fx, 1000n), senderRevoked: true };
    await expect(open(params, env)).rejects.toMatchObject({ kind: "SenderRevoked" });
  });

  it("rejects_sid_mismatch", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const params = { ...baseOpenParams(fx, 1000n), expectedSid: new Uint8Array(16).fill(0xee) };
    await expect(open(params, env)).rejects.toMatchObject({ kind: "SidMismatch" });
  });

  it("rejects_sid_bound_to_different_sender", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const impostor = await buildDevice(0x60, 0x61);
    const params = { ...baseOpenParams(fx, 1000n), boundFromFp: impostor.fp };
    await expect(open(params, env)).rejects.toMatchObject({ kind: "SidBoundToDifferentSender" });
  });

  it("rejects_non_monotonic_seq", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 5n, 1000n);
    const params = { ...baseOpenParams(fx, 1000n), minSeqExclusive: 5n }; // seq must be > 5, envelope carries 5
    await expect(open(params, env)).rejects.toMatchObject({ kind: "ReplaySeq" });
  });

  it("rejects_clock_skew", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const params = baseOpenParams(fx, 1000n + CLOCK_SKEW_SECS + 1n);
    await expect(open(params, env)).rejects.toMatchObject({ kind: "ClockSkew" });
  });

  it("rejects_kind_mismatch", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const params = { ...baseOpenParams(fx, 1000n), expectedKind: 9 };
    await expect(open(params, env)).rejects.toMatchObject({ kind: "KindMismatch" });
  });

  it("rejects_tampered_ciphertext_as_decrypt_failure (via a wrong session key)", async () => {
    // A tampered ciphertext byte breaks the AEAD tag but the signature covers the ciphertext too
    // (A7), so tampering the ciphertext is actually caught as BadSignature first (see the next
    // test). To exercise the AEAD-failure path directly, tamper the *session key* on the receive
    // side instead (e.g. a stale/incorrect key) — the signature check doesn't depend on it.
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    const wrongKey = new Uint8Array(32).fill(0xaa);
    const params = { ...baseOpenParams(fx, 1000n), sessionKey: wrongKey };
    await expect(open(params, env)).rejects.toMatchObject({ kind: "DecryptFailed" });
  });

  it("tampering_ciphertext_after_signing_breaks_signature_check", async () => {
    const fx = await buildFixture();
    const env = await sealAToB(fx, 0n, 1000n);
    env.ciphertext = env.ciphertext.slice();
    env.ciphertext[0] ^= 0xff;
    await expect(open(baseOpenParams(fx, 1000n), env)).rejects.toMatchObject({ kind: "BadSignature" });
  });
});

describe("k0/k1 two-key schedule (DESIGN.md §A7, amended v0.9.14)", () => {
  it("bootstrap_and_session_keys_differ_for_identical_inputs", async () => {
    // The load-bearing domain-separation guarantee: if someone later makes BOOT_KEY_INFO_DOMAIN
    // equal to SESSION_KEY_INFO_DOMAIN, or drops the domain parameter, this must fail.
    const devA = await buildDevice(0x10, 0x11);
    const devB = await buildDevice(0x20, 0x21);
    const ephASeed = new Uint8Array(32).fill(0x30);
    const ephBSeed = new Uint8Array(32).fill(0x40);
    const ephBPk = await x25519PublicKeyFromSeed(ephBSeed);
    const ephDh = await x25519SharedSecret(ephASeed, ephBPk);
    const devDh = await x25519SharedSecret(devA.agreeSeed, devB.agreePk);
    const sid = new Uint8Array(16).fill(0x99);

    const k1 = await deriveSessionKey(ephDh, devDh, sid, devA.fp, devB.fp);
    const k0 = await deriveBootstrapKey(ephDh, devDh, sid, devA.fp, devB.fp);
    expect(Array.from(k0)).not.toEqual(Array.from(k1));
  });

  it("k0_sealed_envelope_does_not_open_under_k1_and_vice_versa", async () => {
    const fx = await buildFixture();
    const ephASeed = new Uint8Array(32).fill(0x30);
    const ephBSeed = new Uint8Array(32).fill(0x40);
    const ephBPk = await x25519PublicKeyFromSeed(ephBSeed);
    const ephDh = await x25519SharedSecret(ephASeed, ephBPk);
    const devDh = await x25519SharedSecret(fx.devA.agreeSeed, fx.devB.agreePk);

    const k1 = await deriveSessionKey(ephDh, devDh, fx.sid, fx.devA.fp, fx.devB.fp);
    const k0 = await deriveBootstrapKey(ephDh, devDh, fx.sid, fx.devA.fp, fx.devB.fp);

    const envK0 = await seal({
      sessionKey: k0,
      signSeed: fx.devA.signSeed,
      v: 1,
      algId: 1,
      fromFp: fx.devA.fp,
      toFp: fx.devB.fp,
      sid: fx.sid,
      kind: 0,
      seq: 0n,
      ts: 1000n,
      plaintext: new TextEncoder().encode("offer"),
    });
    const envK1 = await seal({
      sessionKey: k1,
      signSeed: fx.devA.signSeed,
      v: 1,
      algId: 1,
      fromFp: fx.devA.fp,
      toFp: fx.devB.fp,
      sid: fx.sid,
      kind: 0,
      seq: 0n,
      ts: 1000n,
      plaintext: new TextEncoder().encode("answer-or-later"),
    });

    const baseParamsForKind0 = {
      pinnedSenderKey: fx.devA.signPk,
      selfFp: fx.devB.fp,
      expectedSid: fx.sid,
      now: 1000n,
      minV: 1,
      minAlgId: 1,
      expectedKind: 0,
      senderRevoked: false,
    };

    // k0-sealed envelope: fails under k1, succeeds under k0.
    await expect(open({ ...baseParamsForKind0, sessionKey: k1 }, envK0)).rejects.toMatchObject({
      kind: "DecryptFailed",
    });
    const openedK0 = await open({ ...baseParamsForKind0, sessionKey: k0 }, envK0);
    expect(new TextDecoder().decode(openedK0)).toBe("offer");

    // k1-sealed envelope: fails under k0, succeeds under k1.
    await expect(open({ ...baseParamsForKind0, sessionKey: k0 }, envK1)).rejects.toMatchObject({
      kind: "DecryptFailed",
    });
    const openedK1 = await open({ ...baseParamsForKind0, sessionKey: k1 }, envK1);
    expect(new TextDecoder().decode(openedK1)).toBe("answer-or-later");
  });
});
