// Golden-vector conformance against `vectors/signed/*.json` (real Ed25519 signatures, TEST-ONLY
// seeds — see `crates/spindle-core/src/bin/gen_crypto_vectors.rs`) for the six non-Envelope A7b
// signed-artifact types. The Envelope vector (session key, nonce, AAD, ciphertext, seal/open) has
// its own suite: `test/envelope-vectors.test.ts`.
//
// Each artifact case asserts:
// 1. the `@spindle/proto` struct's `signingInput()` reproduces `signing_input_hex` byte-for-byte
//    (proves this package feeds the right bytes — canonical encoding + domain tag — to the
//    signature check, not just that some signature happens to verify);
// 2. the real signature verifies under the vector's public key via this package's `verify*`;
// 3. the `tampered_signature_last_byte` case is rejected with `ArtifactError.kind === "BadSignature"`.
//
// Any mismatch here means either `@spindle/proto`'s TypeScript encoder or this package's
// `verify*`/backend wiring disagrees with `spindle-core`'s real Ed25519 output.

import { bytesToHex, hexToBytes } from "@spindle/proto";
import {
  AdminCommand,
  AdmissionToken,
  Capability,
  CapKind,
  DeviceCertificate,
  HostOpKeyCert,
  RevocationRecord,
} from "@spindle/proto";
import { describe, expect, it } from "vitest";

import { ArtifactError } from "../src/artifacts.js";
import {
  verifyAdminCommand,
  verifyAdmissionToken,
  verifyCapability,
  verifyDeviceCertificate,
  verifyHostOpKeyCert,
  verifyRevocationRecord,
} from "../src/artifacts.js";
import { ed25519PublicKeyFromSeed, ed25519Sign } from "../src/backend.js";
import { rootFpOf } from "../src/fingerprint.js";
import {
  argsFromCanonicalCbor,
  loadSignedVectorFile,
  parseAdminCommand,
  parseAdmissionToken,
  parseCapability,
  parseDeviceCertificate,
  parseHostOpKeyCert,
  parseRevocationRecord,
} from "./helpers.js";

async function expectArtifactError(fn: () => Promise<void>, kind: string): Promise<void> {
  try {
    await fn();
  } catch (e) {
    expect(e).toBeInstanceOf(ArtifactError);
    expect((e as ArtifactError).kind).toBe(kind);
    return;
  }
  throw new Error(`expected an ArtifactError(${kind}), but nothing threw`);
}

describe("device-certificate.json", () => {
  const doc = loadSignedVectorFile("device-certificate.json");
  const rootPk = hexToBytes(doc.signer.public_key_hex);
  const rootFpHex = doc.signer.root_fp_hex as string;

  it("signer's root_fp_hex matches SHA-256(root_pk)", async () => {
    expect(bytesToHex(await rootFpOf(rootPk))).toBe(rootFpHex);
  });

  for (const c of doc.cases) {
    it(`${c.name}: signing input matches`, () => {
      const cert = parseDeviceCertificate(c.decoded);
      expect(bytesToHex(DeviceCertificate.signingInput(cert))).toBe(c.signing_input_hex);
    });

    it(`${c.name}: verifyDeviceCertificate(now=ts) is ${c.signature_valid ? "ok" : "BadSignature"}`, async () => {
      const cert = parseDeviceCertificate(c.decoded);
      const rootFp = hexToBytes(rootFpHex);
      if (c.signature_valid) {
        await expect(verifyDeviceCertificate(cert, rootPk, rootFp, cert.ts)).resolves.toBeUndefined();
      } else {
        await expectArtifactError(
          () => verifyDeviceCertificate(cert, rootPk, rootFp, cert.ts),
          "BadSignature",
        );
      }
    });
  }
});

describe("capability.json", () => {
  const doc = loadSignedVectorFile("capability.json");

  for (const c of doc.cases) {
    it(`${c.name}: signing input matches`, () => {
      const cap = parseCapability(c.decoded);
      expect(bytesToHex(Capability.signingInput(cap))).toBe(c.signing_input_hex);
    });

    it(`${c.name}: verifyCapability(now=exp) is ${c.signature_valid ? "ok" : "BadSignature"}`, async () => {
      const cap = parseCapability(c.decoded);
      if (c.signature_valid) {
        await expect(verifyCapability(cap, cap.exp)).resolves.toBeUndefined();
      } else {
        await expectArtifactError(() => verifyCapability(cap, cap.exp), "BadSignature");
      }
    });
  }

  it("rejects a capability whose host_fp does not match SHA-256(host_root_pk)", async () => {
    const cap = parseCapability(doc.cases[0].decoded);
    cap.host_fp = cap.host_fp.slice();
    cap.host_fp[0] ^= 0xff;
    await expectArtifactError(() => verifyCapability(cap, cap.exp), "HostFingerprintMismatch");
  });

  it("rejects an expired capability", async () => {
    const cap = parseCapability(doc.cases[0].decoded);
    await expectArtifactError(() => verifyCapability(cap, cap.exp + 1n), "Expired");
  });

  // ---- Locally-generated fixtures for the rest of spindle-core's negative suite (A10.30) ----
  // These aren't golden-vector conformance checks (no fixed expected bytes) — they only need
  // internally self-consistent real Ed25519 signatures, built with this package's own primitives,
  // mirroring `crates/spindle-core/src/artifacts/capability.rs`'s own `test_host`/`issue` helpers.

  interface TestHost {
    rootSeed: Uint8Array;
    rootPk: Uint8Array;
    opSeed: Uint8Array;
    opPk: Uint8Array;
    opCert: HostOpKeyCert;
  }

  async function makeTestHost(rootSeedFill: number, opSeedFill: number, opCertExp: bigint): Promise<TestHost> {
    const rootSeed = new Uint8Array(32).fill(rootSeedFill);
    const opSeed = new Uint8Array(32).fill(opSeedFill);
    const rootPk = await ed25519PublicKeyFromSeed(rootSeed);
    const opPk = await ed25519PublicKeyFromSeed(opSeed);
    const unsigned: HostOpKeyCert = {
      host_op_pk: opPk,
      nats_fp: new Uint8Array(32).fill(0xee),
      ts: 0n,
      exp: opCertExp,
      sig_host_root: new Uint8Array(64),
    };
    const sig = await ed25519Sign(rootSeed, HostOpKeyCert.signingInput(unsigned));
    return { rootSeed, rootPk, opSeed, opPk, opCert: { ...unsigned, sig_host_root: sig } };
  }

  async function issueTestCapability(params: {
    hostRootPk: Uint8Array;
    opCert: HostOpKeyCert;
    opSignerSeed: Uint8Array;
    capEpoch: bigint;
    exp: bigint;
  }): Promise<Capability> {
    const hostFp = await rootFpOf(params.hostRootPk);
    const unsigned: Capability = {
      v: 1,
      host_fp: hostFp,
      host_root_pk: params.hostRootPk,
      op_cert: HostOpKeyCert.toCanonicalBytes(params.opCert),
      kind: CapKind.Member,
      subject: new Uint8Array(32).fill(0xaa),
      cap_epoch: params.capEpoch,
      exp: params.exp,
      nonce: new Uint8Array(16).fill(0xaa),
      sig: new Uint8Array(64),
    };
    const sig = await ed25519Sign(params.opSignerSeed, Capability.signingInput(unsigned));
    return { ...unsigned, sig };
  }

  it("rejects a capability whose host_root_pk is swapped for a different (validly-encoded) root — SHA-256(host_root_pk) no longer matches host_fp", async () => {
    const host = await makeTestHost(0x11, 0x12, 10_000n);
    const cap = await issueTestCapability({
      hostRootPk: host.rootPk,
      opCert: host.opCert,
      opSignerSeed: host.opSeed,
      capEpoch: 0n,
      exp: 2_000n,
    });
    const otherRootPk = await ed25519PublicKeyFromSeed(new Uint8Array(32).fill(0x99));
    cap.host_root_pk = otherRootPk; // host_fp is left as-is, computed from the original root
    await expectArtifactError(() => verifyCapability(cap, 1_500n), "HostFingerprintMismatch");
  });

  it("rejects when the embedded op cert has itself expired, even though the capability's own exp has not", async () => {
    const host = await makeTestHost(0x21, 0x22, 1_000n); // op cert expires at 1_000
    const cap = await issueTestCapability({
      hostRootPk: host.rootPk,
      opCert: host.opCert,
      opSignerSeed: host.opSeed,
      capEpoch: 0n,
      exp: 2_000n, // capability's own exp is still well in the future
    });
    await expectArtifactError(() => verifyCapability(cap, 1_500n), "Expired");
  });

  it("rejects an op cert that was actually signed by a different root than the capability declares", async () => {
    const realHost = await makeTestHost(0x31, 0x32, 10_000n);
    const impostorRootPk = await ed25519PublicKeyFromSeed(new Uint8Array(32).fill(0x77));
    const cap = await issueTestCapability({
      hostRootPk: impostorRootPk, // host_fp/host_root_pk declare the impostor root...
      opCert: realHost.opCert, // ...but op_cert was actually signed by realHost's root
      opSignerSeed: realHost.opSeed,
      capEpoch: 0n,
      exp: 2_000n,
    });
    await expectArtifactError(() => verifyCapability(cap, 1_500n), "BadSignature");
  });

  it("rejects a capability signed by a key other than the one the op cert certifies", async () => {
    const host = await makeTestHost(0x41, 0x42, 10_000n);
    const impostorSignerSeed = new Uint8Array(32).fill(0x66);
    const cap = await issueTestCapability({
      hostRootPk: host.rootPk,
      opCert: host.opCert,
      opSignerSeed: impostorSignerSeed, // not the key op_cert.host_op_pk names
      capEpoch: 0n,
      exp: 2_000n,
    });
    await expectArtifactError(() => verifyCapability(cap, 1_500n), "BadSignature");
  });
});

describe("host-op-key-cert.json", () => {
  const doc = loadSignedVectorFile("host-op-key-cert.json");
  const rootPk = hexToBytes(doc.signer.public_key_hex);
  const rootFpHex = doc.signer.root_fp_hex as string;

  it("signer's root_fp_hex matches SHA-256(root_pk)", async () => {
    expect(bytesToHex(await rootFpOf(rootPk))).toBe(rootFpHex);
  });

  for (const c of doc.cases) {
    it(`${c.name}: signing input matches`, () => {
      const cert = parseHostOpKeyCert(c.decoded);
      expect(bytesToHex(HostOpKeyCert.signingInput(cert))).toBe(c.signing_input_hex);
    });

    it(`${c.name}: verifyHostOpKeyCert(now=ts) is ${c.signature_valid ? "ok" : "BadSignature"}`, async () => {
      const cert = parseHostOpKeyCert(c.decoded);
      const rootFp = hexToBytes(rootFpHex);
      if (c.signature_valid) {
        await expect(verifyHostOpKeyCert(cert, rootPk, rootFp, cert.ts)).resolves.toBeUndefined();
      } else {
        await expectArtifactError(
          () => verifyHostOpKeyCert(cert, rootPk, rootFp, cert.ts),
          "BadSignature",
        );
      }
    });
  }
});

describe("revocation-record.json", () => {
  const doc = loadSignedVectorFile("revocation-record.json");
  const signerPk = hexToBytes(doc.signer.public_key_hex);

  for (const c of doc.cases) {
    it(`${c.name}: signing input matches`, () => {
      const rec = parseRevocationRecord(c.decoded);
      expect(bytesToHex(RevocationRecord.signingInput(rec))).toBe(c.signing_input_hex);
    });

    it(`${c.name}: verifyRevocationRecord is ${c.signature_valid ? "ok" : "BadSignature"}`, async () => {
      const rec = parseRevocationRecord(c.decoded);
      if (c.signature_valid) {
        await expect(verifyRevocationRecord(rec, signerPk)).resolves.toBeUndefined();
      } else {
        await expectArtifactError(() => verifyRevocationRecord(rec, signerPk), "BadSignature");
      }
    });
  }
});

describe("admission-token.json", () => {
  const doc = loadSignedVectorFile("admission-token.json");
  const operatorPk = hexToBytes(doc.signer.public_key_hex);

  for (const c of doc.cases) {
    it(`${c.name}: signing input matches`, () => {
      const tok = parseAdmissionToken(c.decoded);
      expect(bytesToHex(AdmissionToken.signingInput(tok))).toBe(c.signing_input_hex);
    });

    it(`${c.name}: verifyAdmissionToken(now=exp) is ${c.signature_valid ? "ok" : "BadSignature"}`, async () => {
      const tok = parseAdmissionToken(c.decoded);
      if (c.signature_valid) {
        await expect(verifyAdmissionToken(tok, operatorPk, tok.exp)).resolves.toBeUndefined();
      } else {
        await expectArtifactError(() => verifyAdmissionToken(tok, operatorPk, tok.exp), "BadSignature");
      }
    });
  }

  it("rejects an expired admission token", async () => {
    const tok = parseAdmissionToken(doc.cases[0].decoded);
    await expectArtifactError(() => verifyAdmissionToken(tok, operatorPk, tok.exp + 1n), "Expired");
  });
});

describe("admin-command.json", () => {
  const doc = loadSignedVectorFile("admin-command.json");
  const operatorPk = hexToBytes(doc.signer.public_key_hex);

  for (const c of doc.cases) {
    it(`${c.name}: signing input matches`, () => {
      const args = argsFromCanonicalCbor(c.canonical_cbor_hex);
      const cmd = parseAdminCommand(c.decoded, args);
      expect(bytesToHex(AdminCommand.signingInput(cmd))).toBe(c.signing_input_hex);
    });

    it(`${c.name}: verifyAdminCommand(now=ts) is ${c.signature_valid ? "ok" : "BadSignature"}`, async () => {
      const args = argsFromCanonicalCbor(c.canonical_cbor_hex);
      const cmd = parseAdminCommand(c.decoded, args);
      if (c.signature_valid) {
        await expect(verifyAdminCommand(cmd, operatorPk, cmd.ts)).resolves.toBeUndefined();
      } else {
        await expectArtifactError(() => verifyAdminCommand(cmd, operatorPk, cmd.ts), "BadSignature");
      }
    });
  }

  it("rejects an admin command outside the clock-skew window", async () => {
    const args = argsFromCanonicalCbor(doc.cases[0].canonical_cbor_hex);
    const cmd = parseAdminCommand(doc.cases[0].decoded, args);
    await expectArtifactError(
      () => verifyAdminCommand(cmd, operatorPk, cmd.ts + 121n),
      "TimestampSkew",
    );
  });
});
