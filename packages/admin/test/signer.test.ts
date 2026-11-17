// File-custody signer tests: key loading rules, no seed exposure, deterministic Ed25519
// signatures, and a real sign -> Rust-derived-verifier round trip.

import { mkdtemp, rm, writeFile, chmod, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { bytesToHex, hexToBytes, CborValue } from "@spindle/proto";
import {
  ed25519PublicKeyFromSeed,
  ed25519Sign,
  rootFpOf,
  verifyAdminCommand,
} from "@spindle/crypto";

import { buildAdminCommand } from "../src/commands.js";
import { AdminCommand } from "@spindle/proto";
import { FileKeySigner } from "../src/signer.js";
import { loadVectorFile, parseCborTree } from "./helpers.js";

const SEED = new Uint8Array(32).fill(0x07);
const NONCE = new Uint8Array(16).fill(0x93);
const SIGNER_FP = new Uint8Array(32).fill(0xab);

const tempDirs: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "spindle-admin-"));
  tempDirs.push(dir);
  return dir;
}

async function seedFile(seed: Uint8Array, mode = 0o600): Promise<string> {
  const dir = await tempDir();
  const file = path.join(dir, "operator.seed");
  await writeFile(file, seed, { mode });
  await chmod(file, mode);
  return file;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("FileKeySigner", () => {
  it("loads a 0600 seed, derives the public key, and defaults signer_fp to SHA-256(public_key)", async () => {
    const file = await seedFile(SEED);
    const signer = await FileKeySigner.open(file);

    const expectedPk = await ed25519PublicKeyFromSeed(SEED);
    expect(bytesToHex(await signer.publicKey())).toBe(bytesToHex(expectedPk));
    expect(bytesToHex(await signer.fingerprint())).toBe(bytesToHex(await rootFpOf(expectedPk)));
  });

  it("accepts an explicit operator fingerprint", async () => {
    const file = await seedFile(SEED);
    const signer = await FileKeySigner.open(file, { signerFp: SIGNER_FP });
    expect(bytesToHex(await signer.fingerprint())).toBe(bytesToHex(SIGNER_FP));
  });

  it("signs deterministically with the loaded key", async () => {
    const file = await seedFile(SEED);
    const signer = await FileKeySigner.open(file);
    const message = new Uint8Array(48).fill(0x42);
    expect(bytesToHex(await signer.sign(message))).toBe(
      bytesToHex(await ed25519Sign(SEED, message)),
    );
  });

  it("builds a command that @spindle/crypto's Rust-derived verifier accepts", async () => {
    const file = await seedFile(SEED);
    const signer = await FileKeySigner.open(file);
    const publicKey = await signer.publicKey();

    const command = await buildAdminCommand({
      cmd: "evict_host",
      args: CborValue.map([["host_fp", CborValue.bytes(new Uint8Array(32).fill(0xcc))]]),
      signerFp: await signer.fingerprint(),
      seq: 5n,
      nonce: NONCE,
      ts: 1_000n,
      signer,
    });

    await expect(
      verifyAdminCommand(command, publicKey, command.signer_fp, 1_000n),
    ).resolves.toBeUndefined();
    expect(bytesToHex(command.sig)).toBe(
      bytesToHex(await ed25519Sign(SEED, AdminCommand.signingInput(command))),
    );
  });

  it("reproduces the Rust-generated real signature in vectors/signed/admin-command.json", async () => {
    // The strongest cross-implementation check available here: Ed25519 is deterministic, so a
    // byte-identical signature proves this signing path agrees with `spindle-core`'s
    // `issue_admin_command`, not merely with `@spindle/crypto`'s own signer.
    const doc = loadVectorFile("signed/admin-command.json");
    const valid = doc.cases.find((c: { name: string }) => c.name === "valid");
    expect(valid).toBeDefined();

    const seed = hexToBytes(doc.signer.seed.seed_hex);
    const file = await seedFile(seed);
    const signer = await FileKeySigner.open(file, {
      signerFp: hexToBytes(valid.decoded.signer_fp),
    });

    const command = await buildAdminCommand({
      cmd: valid.decoded.cmd,
      args: parseCborTree(valid.decoded.args),
      signerFp: hexToBytes(valid.decoded.signer_fp),
      seq: BigInt(valid.decoded.seq),
      nonce: hexToBytes(valid.decoded.nonce),
      ts: BigInt(valid.decoded.ts),
      v: valid.decoded.v,
      signer,
    });

    expect(bytesToHex(AdminCommand.toCanonicalBytes(command))).toBe(valid.canonical_cbor_hex);
    expect(bytesToHex(command.sig)).toBe(valid.signature_hex);
  });

  it("rejects a signer_fp that is not the configured operator identity", async () => {
    const file = await seedFile(SEED);
    const signer = await FileKeySigner.open(file);
    await expect(
      buildAdminCommand({
        cmd: "evict_host",
        args: CborValue.null(),
        signerFp: SIGNER_FP,
        seq: 1n,
        nonce: NONCE,
        ts: 1n,
        signer,
      }),
    ).rejects.toMatchObject({ kind: "SignerFingerprintMismatch" });
  });

  it.skipIf(process.platform === "win32")(
    "refuses a symlink to an otherwise valid seed",
    async () => {
      const file = await seedFile(SEED);
      const dir = await tempDir();
      const link = path.join(dir, "operator.seed");
      await symlink(file, link);
      await expect(FileKeySigner.open(link)).rejects.toThrow(/not a regular file|ELOOP/);
    },
  );

  it("copies a caller-supplied fingerprint instead of retaining it", async () => {
    const file = await seedFile(SEED);
    const fp = new Uint8Array(32).fill(0x11);
    const signer = await FileKeySigner.open(file, { signerFp: fp });
    fp.fill(0);
    expect(bytesToHex(await signer.fingerprint())).toBe(
      bytesToHex(new Uint8Array(32).fill(0x11)),
    );
  });

  it("refuses a file with group/other access (POSIX)", async () => {
    if (process.platform === "win32") return;
    const file = await seedFile(SEED, 0o644);
    await expect(FileKeySigner.open(file)).rejects.toThrow(/0600/);
  });

  it("refuses a seed file that is not exactly 32 bytes", async () => {
    const file = await seedFile(new Uint8Array(31).fill(0x01));
    await expect(FileKeySigner.open(file)).rejects.toThrow(/32-byte seed/);
  });

  it("does not expose the seed through enumeration or stringification", async () => {
    const file = await seedFile(SEED);
    const signer = await FileKeySigner.open(file);
    const seedHex = bytesToHex(SEED);

    expect(Object.keys(signer)).toEqual([]);
    expect(JSON.stringify(signer)).toBe("{}");
    expect(String(signer)).not.toContain(seedHex);

    // The public key is deliberately exposed; the seed is not.
    expect(bytesToHex(await signer.publicKey())).not.toBe(seedHex);
  });

  it("returns defensive copies from publicKey/fingerprint", async () => {
    const file = await seedFile(SEED);
    const signer = await FileKeySigner.open(file);
    const pk = await signer.publicKey();
    pk.fill(0);
    expect(bytesToHex(await signer.publicKey())).not.toBe(bytesToHex(pk));
    expect(bytesToHex(await signer.publicKey())).toBe(
      bytesToHex(hexToBytes(bytesToHex(await ed25519PublicKeyFromSeed(SEED)))),
    );
  });
});
