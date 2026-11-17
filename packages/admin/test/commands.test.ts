// Golden-vector conformance and producer-side invariant tests for `buildAdminCommand`.
//
// The byte-identity cases read `vectors/admin-command.json` from disk — the same file
// `packages/proto/test/vectors.test.ts` drives the pure encoder with. Here the bytes come out of
// this package's builder, so a mismatch means the admin library diverged from the Rust encoder,
// not merely that the proto package did.

import { describe, expect, it } from "vitest";

import { AdminCommand, ADMIN_COMMAND_CURRENT_V, bytesToHex, hexToBytes } from "@spindle/proto";
import { ed25519Sign } from "@spindle/crypto";

import { buildAdminCommand } from "../src/commands.js";
import { AdminError } from "../src/errors.js";
import { fixedSigner, loadVectorFile, parseCborTree } from "./helpers.js";

interface VectorCase {
  name: string;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  decoded: any;
  canonical_cbor_hex: string;
  signing_input_hex: string;
}

interface VectorDoc {
  artifact: string;
  domain_tag: string;
  cases: VectorCase[];
}

const doc = loadVectorFile("admin-command.json") as VectorDoc;

const NONCE = new Uint8Array(16).fill(0xaa);
const SIGNER_FP = new Uint8Array(32).fill(0xbb);
const SIG = new Uint8Array(64).fill(0xcc);

function signerFor(fp: Uint8Array = SIGNER_FP, sig: Uint8Array = SIG) {
  return fixedSigner({ fingerprint: fp, signature: sig });
}

describe("buildAdminCommand: golden vectors", () => {
  for (const c of doc.cases) {
    it(`${c.name}: toCanonicalBytes is byte-identical to vectors/admin-command.json`, async () => {
      const signer = signerFor(hexToBytes(c.decoded.signer_fp), hexToBytes(c.decoded.sig));
      const command = await buildAdminCommand({
        cmd: c.decoded.cmd,
        args: parseCborTree(c.decoded.args),
        signerFp: hexToBytes(c.decoded.signer_fp),
        seq: BigInt(c.decoded.seq),
        nonce: hexToBytes(c.decoded.nonce),
        ts: BigInt(c.decoded.ts),
        v: c.decoded.v,
        signer,
      });
      expect(bytesToHex(AdminCommand.toCanonicalBytes(command))).toBe(c.canonical_cbor_hex);
    });

    it(`${c.name}: signingInput is byte-identical to vectors/admin-command.json`, async () => {
      const signer = signerFor(hexToBytes(c.decoded.signer_fp), hexToBytes(c.decoded.sig));
      const command = await buildAdminCommand({
        cmd: c.decoded.cmd,
        args: parseCborTree(c.decoded.args),
        signerFp: hexToBytes(c.decoded.signer_fp),
        seq: BigInt(c.decoded.seq),
        nonce: hexToBytes(c.decoded.nonce),
        ts: BigInt(c.decoded.ts),
        v: c.decoded.v,
        signer,
      });
      expect(bytesToHex(AdminCommand.signingInput(command))).toBe(c.signing_input_hex);
    });
  }

  it("signs exactly the signingInput preimage", async () => {
    const signer = signerFor();
    const command = await buildAdminCommand({
      cmd: "evict_host",
      args: parseCborTree(doc.cases[0].decoded.args),
      signerFp: SIGNER_FP,
      seq: 12n,
      nonce: NONCE,
      ts: 1_755_907_200n,
      signer,
    });
    expect(signer.signedMessages).toHaveLength(1);
    expect(bytesToHex(signer.signedMessages[0])).toBe(
      bytesToHex(AdminCommand.signingInput(command)),
    );
  });

  it("defaults v to ADMIN_COMMAND_CURRENT_V", async () => {
    const command = await buildAdminCommand({
      cmd: "evict_host",
      args: parseCborTree(doc.cases[0].decoded.args),
      signerFp: SIGNER_FP,
      seq: 1n,
      nonce: NONCE,
      ts: 1_755_907_200n,
      signer: signerFor(),
    });
    expect(command.v).toBe(ADMIN_COMMAND_CURRENT_V);
  });

  it("produces a signature verifiable by the operator key over the canonical preimage", async () => {
    const seed = new Uint8Array(32).fill(0x07);
    const publicKey = hexToBytes(
      "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    );
    const signer = fixedSigner({
      fingerprint: new Uint8Array(32).fill(0x11),
      signature: new Uint8Array(64),
      publicKey,
    });
    // Replace the fake signature with a real deterministic Ed25519 one over the same preimage.
    signer.sign = async (message: Uint8Array) => ed25519Sign(seed, message);
    const command = await buildAdminCommand({
      cmd: "set_mode",
      args: parseCborTree(doc.cases[1].decoded.args),
      signerFp: new Uint8Array(32).fill(0x11),
      seq: 13n,
      nonce: NONCE,
      ts: 1_755_907_260n,
      signer,
    });
    expect(bytesToHex(command.sig)).toBe(
      bytesToHex(await ed25519Sign(seed, AdminCommand.signingInput(command))),
    );
  });
});

describe("buildAdminCommand: producer invariants", () => {
  const base = {
    cmd: "evict_host",
    args: parseCborTree(doc.cases[0].decoded.args),
    signerFp: SIGNER_FP,
    seq: 1n,
    nonce: NONCE,
    ts: 1_755_907_200n,
  };

  it("rejects an empty command", async () => {
    await expect(
      buildAdminCommand({ ...base, cmd: "", signer: signerFor() }),
    ).rejects.toMatchObject({ kind: "EmptyCommand" });
  });

  it("rejects a whitespace-only command", async () => {
    await expect(
      buildAdminCommand({ ...base, cmd: "   ", signer: signerFor() }),
    ).rejects.toMatchObject({ kind: "EmptyCommand" });
  });

  it("rejects a 31-byte signer_fp", async () => {
    await expect(
      buildAdminCommand({ ...base, signerFp: new Uint8Array(31), signer: signerFor() }),
    ).rejects.toMatchObject({ kind: "WrongLength", field: "signer_fp", expected: 32, actual: 31 });
  });

  it("rejects a 15-byte nonce", async () => {
    await expect(
      buildAdminCommand({ ...base, nonce: new Uint8Array(15), signer: signerFor() }),
    ).rejects.toMatchObject({ kind: "WrongLength", field: "nonce", expected: 16, actual: 15 });
  });

  it("rejects a signer whose public key is not 32 bytes", async () => {
    const signer = signerFor();
    signer.publicKey = async () => new Uint8Array(31);
    await expect(buildAdminCommand({ ...base, signer })).rejects.toMatchObject({
      kind: "WrongLength",
      field: "public_key",
    });
  });

  it("rejects a signer whose fingerprint is not 32 bytes", async () => {
    const signer = signerFor();
    signer.fingerprint = async () => new Uint8Array(31);
    await expect(buildAdminCommand({ ...base, signer })).rejects.toMatchObject({
      kind: "WrongLength",
      field: "signer_fingerprint",
    });
  });

  it("rejects a signer that returns a 63-byte signature", async () => {
    await expect(
      buildAdminCommand({ ...base, signer: signerFor(SIGNER_FP, new Uint8Array(63)) }),
    ).rejects.toMatchObject({ kind: "WrongLength", field: "sig", expected: 64, actual: 63 });
  });

  it("rejects a signer_fp that does not name the signer's own identity", async () => {
    const signer = signerFor(new Uint8Array(32).fill(0xdd));
    await expect(buildAdminCommand({ ...base, signer })).rejects.toMatchObject({
      kind: "SignerFingerprintMismatch",
    });
    expect((signer as { signedMessages: Uint8Array[] }).signedMessages).toHaveLength(0);
  });

  it("rejects v below ADMIN_COMMAND_MIN_V", async () => {
    await expect(
      buildAdminCommand({ ...base, v: 0, signer: signerFor() }),
    ).rejects.toMatchObject({ kind: "VersionTooLow", found: 0, minimum: 1 });
  });

  it("rejects v above ADMIN_COMMAND_CURRENT_V", async () => {
    await expect(
      buildAdminCommand({ ...base, v: 2, signer: signerFor() }),
    ).rejects.toMatchObject({ kind: "VersionTooHigh", found: 2, maximum: 1 });
  });

  it("rejects a negative or out-of-range seq", async () => {
    await expect(
      buildAdminCommand({ ...base, seq: -1n, signer: signerFor() }),
    ).rejects.toMatchObject({ kind: "InvalidValue", field: "seq" });
    await expect(
      buildAdminCommand({ ...base, seq: 0x1_0000_0000_0000_0000n, signer: signerFor() }),
    ).rejects.toMatchObject({ kind: "InvalidValue", field: "seq" });
  });

  it("never includes key material or nonce bytes in its error messages", async () => {
    const nonce = new Uint8Array(16).fill(0x5a);
    const secretish = new Uint8Array(32).fill(0x5a);
    const forbidden = [bytesToHex(nonce), bytesToHex(secretish), "5a5a5a5a"];

    // Drive several distinct rejection paths, not just the cheapest one: an empty command, a
    // wrong nonce length, an out-of-range version, and a signer_fp/identity mismatch.
    const scenarios = [
      () => buildAdminCommand({ ...base, cmd: "", nonce, signerFp: secretish, signer: signerFor(secretish) }),
      () => buildAdminCommand({ ...base, nonce: nonce.slice(0, 15), signer: signerFor(secretish) }),
      () => buildAdminCommand({ ...base, v: 2, nonce, signer: signerFor(secretish) }),
      () => buildAdminCommand({ ...base, nonce, signer: signerFor(new Uint8Array(32).fill(0x5a)) }),
    ];

    for (const scenario of scenarios) {
      try {
        await scenario();
        throw new Error("expected buildAdminCommand to reject");
      } catch (err) {
        expect(err).toBeInstanceOf(AdminError);
        const message = (err as AdminError).message;
        for (const needle of forbidden) expect(message).not.toContain(needle);
      }
    }
  });
});
