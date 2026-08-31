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
  HostDeviceCert,
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
  verifyHostDeviceCert,
  verifyHostOpKeyCert,
  verifyRevocationRecord,
} from "../src/artifacts.js";
import { ed25519PublicKeyFromSeed, ed25519Sign, x25519PublicKeyFromSeed } from "../src/backend.js";
import { deviceFpOf, rootFpOf } from "../src/fingerprint.js";
import {
  argsFromCanonicalCbor,
  loadSignedVectorFile,
  parseAdminCommand,
  parseAdmissionToken,
  parseCapability,
  parseDeviceCertificate,
  parseHostDeviceCert,
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

  // ---- Negative suite for the A10.34 device_fp/keys binding check (mirrors
  // crates/spindle-core/src/artifacts/device_cert.rs's `mod tests`) ----
  //
  // These are locally-generated fixtures (no fixed expected bytes) — they only need internally
  // self-consistent real Ed25519/X25519 keys, built with this package's own primitives.

  interface TestDevice {
    signSeed: Uint8Array;
    agreeSeed: Uint8Array;
    signPk: Uint8Array;
    agreePk: Uint8Array;
  }

  async function makeDevice(signSeedFill: number, agreeSeedFill: number): Promise<TestDevice> {
    const signSeed = new Uint8Array(32).fill(signSeedFill);
    const agreeSeed = new Uint8Array(32).fill(agreeSeedFill);
    const signPk = await ed25519PublicKeyFromSeed(signSeed);
    const agreePk = await x25519PublicKeyFromSeed(agreeSeed);
    return { signSeed, agreeSeed, signPk, agreePk };
  }

  async function issueTestDeviceCertificate(params: {
    rootSeed: Uint8Array;
    algId: number;
    signPk: Uint8Array;
    agreePk: Uint8Array;
    natsFp: Uint8Array;
    ts: bigint;
    exp: bigint;
  }): Promise<DeviceCertificate> {
    const deviceFp = await deviceFpOf(params.algId, params.signPk, params.agreePk);
    const unsigned: DeviceCertificate = {
      device_fp: deviceFp,
      alg_id: params.algId,
      sign_pk: params.signPk,
      agree_pk: params.agreePk,
      nats_fp: params.natsFp,
      ts: params.ts,
      exp: params.exp,
      sig_root: new Uint8Array(64),
    };
    const sig = await ed25519Sign(params.rootSeed, DeviceCertificate.signingInput(unsigned));
    return { ...unsigned, sig_root: sig };
  }

  it("rejects a tampered device_fp", async () => {
    const rootSeed = new Uint8Array(32).fill(0x02);
    const rootPkLocal = await ed25519PublicKeyFromSeed(rootSeed);
    const rootFpLocal = await rootFpOf(rootPkLocal);
    const dev = await makeDevice(0x51, 0x52);
    const cert = await issueTestDeviceCertificate({
      rootSeed,
      algId: 1,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      natsFp: new Uint8Array(32).fill(0xaa),
      ts: 1_000n,
      exp: 2_000n,
    });
    // Tamper device_fp only — the recompute-and-compare check runs before the signature check, so
    // this fails on DeviceFingerprintMismatch regardless of sig_root's (now-mismatched) validity.
    cert.device_fp = new Uint8Array(cert.device_fp);
    cert.device_fp[0] ^= 0xff;
    await expectArtifactError(
      () => verifyDeviceCertificate(cert, rootPkLocal, rootFpLocal, 1_500n),
      "DeviceFingerprintMismatch",
    );
  });

  it("rejects sign_pk swapped for another valid key", async () => {
    const rootSeed = new Uint8Array(32).fill(0x03);
    const rootPkLocal = await ed25519PublicKeyFromSeed(rootSeed);
    const rootFpLocal = await rootFpOf(rootPkLocal);
    const dev = await makeDevice(0x52, 0x53);
    const other = await makeDevice(0x54, 0x55);
    const cert = await issueTestDeviceCertificate({
      rootSeed,
      algId: 1,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      natsFp: new Uint8Array(32).fill(0xaa),
      ts: 1_000n,
      exp: 2_000n,
    });
    // Swap in a different, perfectly valid Ed25519 key — device_fp is left alone, so it now
    // commits to `dev`'s sign_pk while the certificate carries `other`'s.
    cert.sign_pk = other.signPk;
    await expectArtifactError(
      () => verifyDeviceCertificate(cert, rootPkLocal, rootFpLocal, 1_500n),
      "DeviceFingerprintMismatch",
    );
  });

  it("rejects agree_pk swapped for another valid key", async () => {
    const rootSeed = new Uint8Array(32).fill(0x04);
    const rootPkLocal = await ed25519PublicKeyFromSeed(rootSeed);
    const rootFpLocal = await rootFpOf(rootPkLocal);
    const dev = await makeDevice(0x56, 0x57);
    const other = await makeDevice(0x58, 0x59);
    const cert = await issueTestDeviceCertificate({
      rootSeed,
      algId: 1,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      natsFp: new Uint8Array(32).fill(0xaa),
      ts: 1_000n,
      exp: 2_000n,
    });
    cert.agree_pk = other.agreePk;
    await expectArtifactError(
      () => verifyDeviceCertificate(cert, rootPkLocal, rootFpLocal, 1_500n),
      "DeviceFingerprintMismatch",
    );
  });

  /** The three tests above all mutate a certificate *after* `issueTestDeviceCertificate` signed
   * it. In every one of those, `sig_root` still covers the pre-mutation bytes, so
   * `verifyDeviceCertificate` would reject them on the signature check alone even if the
   * `device_fp` recompute-and-compare in `verifyDeviceCertificate` were deleted entirely. They
   * exercise the signature check, not the binding check, and give no coverage of the latter.
   *
   * This test isolates the binding check: it builds a `DeviceCertificate` whose `device_fp` names
   * device A while `(alg_id, sign_pk, agree_pk)` are device B's, and then signs *that* exact,
   * internally-inconsistent content with a real root key — exactly as `issueTestDeviceCertificate`
   * would sign genuine content. `sig_root` is therefore completely valid over the certificate's
   * bytes; the only thing wrong with the certificate is the device_fp/key binding. The issuing
   * helper above can never produce this shape (it derives `device_fp` from the keys itself), so
   * the literal must be constructed by hand here.
   *
   * Why it matters: envelope verification pins peers by `device_fp`. A root that is malicious, or
   * merely buggy, could issue exactly this certificate. Without the recompute check, device B
   * would present device A's `device_fp` and be accepted as device A — full impersonation — while
   * still holding and using its own (B's) signing and agreement keys. */
  it("rejects a correctly-signed but internally-inconsistent certificate (device_fp names device A, keys are device B's)", async () => {
    const rootSeed = new Uint8Array(32).fill(0x05);
    const rootPkLocal = await ed25519PublicKeyFromSeed(rootSeed);
    const rootFpLocal = await rootFpOf(rootPkLocal);
    const deviceA = await makeDevice(0x5c, 0x5d);
    const deviceB = await makeDevice(0x5d, 0x5e);
    const deviceAFp = await deviceFpOf(1, deviceA.signPk, deviceA.agreePk);

    const unsigned: DeviceCertificate = {
      device_fp: deviceAFp,
      alg_id: 1,
      sign_pk: deviceB.signPk,
      agree_pk: deviceB.agreePk,
      nats_fp: new Uint8Array(32).fill(0xaa),
      ts: 1_000n,
      exp: 2_000n,
      sig_root: new Uint8Array(64),
    };
    // Sign the exact (inconsistent) content above, the same way issueTestDeviceCertificate does —
    // sig_root is therefore genuinely valid over this certificate's bytes.
    const sig = await ed25519Sign(rootSeed, DeviceCertificate.signingInput(unsigned));
    const cert: DeviceCertificate = { ...unsigned, sig_root: sig };

    await expectArtifactError(
      () => verifyDeviceCertificate(cert, rootPkLocal, rootFpLocal, 1_500n),
      "DeviceFingerprintMismatch",
    );
  });

  it("rejects an unsupported alg_id", async () => {
    const rootSeed = new Uint8Array(32).fill(0x06);
    const rootPkLocal = await ed25519PublicKeyFromSeed(rootSeed);
    const rootFpLocal = await rootFpOf(rootPkLocal);
    const dev = await makeDevice(0x5a, 0x5b);
    const cert = await issueTestDeviceCertificate({
      rootSeed,
      algId: 1,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      natsFp: new Uint8Array(32).fill(0xaa),
      ts: 1_000n,
      exp: 2_000n,
    });
    cert.alg_id = 2;
    await expectArtifactError(
      () => verifyDeviceCertificate(cert, rootPkLocal, rootFpLocal, 1_500n),
      "UnsupportedAlgId",
    );
  });

  it("rejects a wrong-length sign_pk", async () => {
    const rootSeed = new Uint8Array(32).fill(0x07);
    const rootPkLocal = await ed25519PublicKeyFromSeed(rootSeed);
    const rootFpLocal = await rootFpOf(rootPkLocal);
    const dev = await makeDevice(0x5c, 0x5d);
    const cert = await issueTestDeviceCertificate({
      rootSeed,
      algId: 1,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      natsFp: new Uint8Array(32).fill(0xaa),
      ts: 1_000n,
      exp: 2_000n,
    });
    cert.sign_pk = new Uint8Array(31).fill(0x01); // one byte short
    await expectArtifactError(
      () => verifyDeviceCertificate(cert, rootPkLocal, rootFpLocal, 1_500n),
      "InvalidPublicKey",
    );
  });

  it("rejects a wrong-length agree_pk", async () => {
    const rootSeed = new Uint8Array(32).fill(0x08);
    const rootPkLocal = await ed25519PublicKeyFromSeed(rootSeed);
    const rootFpLocal = await rootFpOf(rootPkLocal);
    const dev = await makeDevice(0x5e, 0x5f);
    const cert = await issueTestDeviceCertificate({
      rootSeed,
      algId: 1,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      natsFp: new Uint8Array(32).fill(0xaa),
      ts: 1_000n,
      exp: 2_000n,
    });
    cert.agree_pk = new Uint8Array(33).fill(0x02); // one byte long
    await expectArtifactError(
      () => verifyDeviceCertificate(cert, rootPkLocal, rootFpLocal, 1_500n),
      "InvalidPublicKey",
    );
  });
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

describe("host-device-cert.json", () => {
  const doc = loadSignedVectorFile("host-device-cert.json");
  const hostFp = hexToBytes(doc.signer.host_fp_hex as string);

  for (const c of doc.cases) {
    it(`${c.name}: signing input matches`, () => {
      const cert = parseHostDeviceCert(c.decoded);
      expect(bytesToHex(HostDeviceCert.signingInput(cert))).toBe(c.signing_input_hex);
    });

    it(`${c.name}: verifyHostDeviceCert(now=ts) is ${c.signature_valid ? "ok" : "BadSignature"}`, async () => {
      const cert = parseHostDeviceCert(c.decoded);
      if (c.signature_valid) {
        await expect(verifyHostDeviceCert(cert, hostFp, cert.ts)).resolves.toBeUndefined();
      } else {
        await expectArtifactError(
          () => verifyHostDeviceCert(cert, hostFp, cert.ts),
          "BadSignature",
        );
      }
    });
  }

  // ---- Locally-generated fixtures for the rest of spindle-core's negative suite (A10.35),
  // mirroring `crates/spindle-core/src/artifacts/host_device_cert.rs`'s own
  // `test_host`/`host_device`/`issue` helpers. These aren't golden-vector conformance checks (no
  // fixed expected bytes) — they only need internally self-consistent real Ed25519/X25519 keys,
  // built with this package's own primitives.

  interface TestHost {
    rootSeed: Uint8Array;
    rootPk: Uint8Array;
    rootFp: Uint8Array;
    opSeed: Uint8Array;
    opPk: Uint8Array;
    opCert: HostOpKeyCert;
  }

  async function makeTestHost(rootSeedFill: number, opSeedFill: number, opCertExp: bigint): Promise<TestHost> {
    const rootSeed = new Uint8Array(32).fill(rootSeedFill);
    const opSeed = new Uint8Array(32).fill(opSeedFill);
    const rootPk = await ed25519PublicKeyFromSeed(rootSeed);
    const rootFp = await rootFpOf(rootPk);
    const opPk = await ed25519PublicKeyFromSeed(opSeed);
    const unsigned: HostOpKeyCert = {
      host_op_pk: opPk,
      nats_fp: new Uint8Array(32).fill(0xfe),
      ts: 0n,
      exp: opCertExp,
      sig_host_root: new Uint8Array(64),
    };
    const sig = await ed25519Sign(rootSeed, HostOpKeyCert.signingInput(unsigned));
    return { rootSeed, rootPk, rootFp, opSeed, opPk, opCert: { ...unsigned, sig_host_root: sig } };
  }

  interface TestHostDevice {
    signSeed: Uint8Array;
    agreeSeed: Uint8Array;
    algId: number;
    signPk: Uint8Array;
    agreePk: Uint8Array;
  }

  async function makeHostDevice(signSeedFill: number, agreeSeedFill: number): Promise<TestHostDevice> {
    const signSeed = new Uint8Array(32).fill(signSeedFill);
    const agreeSeed = new Uint8Array(32).fill(agreeSeedFill);
    const signPk = await ed25519PublicKeyFromSeed(signSeed);
    const agreePk = await x25519PublicKeyFromSeed(agreeSeed);
    return { signSeed, agreeSeed, algId: 1, signPk, agreePk };
  }

  async function issueTestHostDeviceCert(params: {
    opSignerSeed: Uint8Array;
    hostFp: Uint8Array;
    hostRootPk: Uint8Array;
    opCert: HostOpKeyCert;
    algId: number;
    signPk: Uint8Array;
    agreePk: Uint8Array;
    ts: bigint;
    exp: bigint;
  }): Promise<HostDeviceCert> {
    const hostDeviceFp = await deviceFpOf(params.algId, params.signPk, params.agreePk);
    const unsigned: HostDeviceCert = {
      host_fp: params.hostFp,
      host_root_pk: params.hostRootPk,
      op_cert: HostOpKeyCert.toCanonicalBytes(params.opCert),
      host_device_fp: hostDeviceFp,
      alg_id: params.algId,
      sign_pk: params.signPk,
      agree_pk: params.agreePk,
      ts: params.ts,
      exp: params.exp,
      sig_host_op: new Uint8Array(64),
    };
    const sig = await ed25519Sign(params.opSignerSeed, HostDeviceCert.signingInput(unsigned));
    return { ...unsigned, sig_host_op: sig };
  }

  async function issue(host: TestHost, dev: TestHostDevice, ts: bigint, exp: bigint): Promise<HostDeviceCert> {
    return issueTestHostDeviceCert({
      opSignerSeed: host.opSeed,
      hostFp: host.rootFp,
      hostRootPk: host.rootPk,
      opCert: host.opCert,
      algId: dev.algId,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      ts,
      exp,
    });
  }

  it("issues and verifies a full round trip", async () => {
    const host = await makeTestHost(0x11, 0x12, 10_000n);
    const dev = await makeHostDevice(0x60, 0x61);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    await expect(verifyHostDeviceCert(cert, host.rootFp, 1_500n)).resolves.toBeUndefined();
  });

  it("rejects an unsupported alg_id", async () => {
    const host = await makeTestHost(0x13, 0x14, 10_000n);
    const dev = await makeHostDevice(0x62, 0x63);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    cert.alg_id = 2;
    await expectArtifactError(() => verifyHostDeviceCert(cert, host.rootFp, 1_500n), "UnsupportedAlgId");
  });

  it("rejects a wrong-length sign_pk", async () => {
    const host = await makeTestHost(0x15, 0x16, 10_000n);
    const dev = await makeHostDevice(0x64, 0x65);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    cert.sign_pk = new Uint8Array(31).fill(0x01); // one byte short
    await expectArtifactError(() => verifyHostDeviceCert(cert, host.rootFp, 1_500n), "InvalidPublicKey");
  });

  it("rejects a wrong-length agree_pk", async () => {
    const host = await makeTestHost(0x17, 0x18, 10_000n);
    const dev = await makeHostDevice(0x66, 0x67);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    cert.agree_pk = new Uint8Array(33).fill(0x02); // one byte long
    await expectArtifactError(() => verifyHostDeviceCert(cert, host.rootFp, 1_500n), "InvalidPublicKey");
  });

  it("rejects a tampered host_device_fp", async () => {
    // Tamper host_device_fp only — sig_host_op still covers the original (now-mismatched) value,
    // so this certificate is ALSO badly signed. Like the sign_pk/agree_pk swap tests below, this
    // alone cannot prove the binding recompute exists (deleting it would still fail here, just on
    // the signature check instead) — see "rejects a correctly-signed but internally-inconsistent
    // certificate" below for the test that isolates the binding check.
    const host = await makeTestHost(0x19, 0x1a, 10_000n);
    const dev = await makeHostDevice(0x68, 0x69);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    cert.host_device_fp = new Uint8Array(cert.host_device_fp);
    cert.host_device_fp[0] ^= 0xff;
    await expectArtifactError(
      () => verifyHostDeviceCert(cert, host.rootFp, 1_500n),
      "DeviceFingerprintMismatch",
    );
  });

  it("rejects sign_pk swapped for another valid key", async () => {
    const host = await makeTestHost(0x1b, 0x1c, 10_000n);
    const dev = await makeHostDevice(0x6a, 0x6b);
    const other = await makeHostDevice(0x6c, 0x6d);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    // Swap in a different, perfectly valid Ed25519 key — host_device_fp is left alone, so it now
    // commits to `dev`'s sign_pk while the certificate carries `other`'s.
    cert.sign_pk = other.signPk;
    await expectArtifactError(
      () => verifyHostDeviceCert(cert, host.rootFp, 1_500n),
      "DeviceFingerprintMismatch",
    );
  });

  it("rejects agree_pk swapped for another valid key", async () => {
    const host = await makeTestHost(0x1d, 0x1e, 10_000n);
    const dev = await makeHostDevice(0x6e, 0x6f);
    const other = await makeHostDevice(0x70, 0x71);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    cert.agree_pk = other.agreePk;
    await expectArtifactError(
      () => verifyHostDeviceCert(cert, host.rootFp, 1_500n),
      "DeviceFingerprintMismatch",
    );
  });

  /** **The most important test in this suite.** The tests above all mutate a certificate *after*
   * `issueTestHostDeviceCert` signed it, so `sig_host_op` still covers the pre-mutation bytes and
   * each would be rejected on the signature check alone even if the `host_device_fp`
   * recompute-and-compare in `verifyHostDeviceCert` (step 3) were deleted entirely. They exercise
   * the signature check, not the binding check, and give no real coverage of it.
   *
   * This test isolates the binding check: it builds a `HostDeviceCert` whose `host_device_fp`
   * names host device A while `(alg_id, sign_pk, agree_pk)` are host device B's, and then signs
   * *that* exact, internally-inconsistent content with a real, valid host operating key — exactly
   * as `issueTestHostDeviceCert` would sign genuine content. `sig_host_op` is therefore completely
   * valid over the certificate's bytes; the only thing wrong with the certificate is the
   * host_device_fp/key binding. The issuing helper above can never produce this shape (it derives
   * `host_device_fp` from the keys itself), so the literal must be constructed by hand here.
   *
   * Why it matters: envelope verification pins the host's peer identity by `device_fp`
   * (DESIGN.md §A4/A10.35: the host device fingerprint *is* the host's §A7 envelope identity). A
   * host op key that is malicious, or merely buggy, could issue exactly this certificate. Without
   * the recompute check, host device B would present host device A's `host_device_fp` and be
   * accepted as the host's envelope identity A — full impersonation of the host — while still
   * holding and using its own (B's) signing and agreement keys. */
  it("rejects a correctly-signed but internally-inconsistent certificate (host_device_fp names device A, keys are device B's)", async () => {
    const host = await makeTestHost(0x1f, 0x20, 10_000n);
    const deviceA = await makeHostDevice(0x72, 0x73);
    const deviceB = await makeHostDevice(0x74, 0x75);
    const deviceAFp = await deviceFpOf(1, deviceA.signPk, deviceA.agreePk);

    const unsigned: HostDeviceCert = {
      host_fp: host.rootFp,
      host_root_pk: host.rootPk,
      op_cert: HostOpKeyCert.toCanonicalBytes(host.opCert),
      host_device_fp: deviceAFp,
      alg_id: deviceB.algId,
      sign_pk: deviceB.signPk,
      agree_pk: deviceB.agreePk,
      ts: 1_000n,
      exp: 2_000n,
      sig_host_op: new Uint8Array(64),
    };
    // Sign the exact (inconsistent) content above, the same way issueTestHostDeviceCert does —
    // sig_host_op is therefore genuinely valid over this certificate's bytes.
    const sig = await ed25519Sign(host.opSeed, HostDeviceCert.signingInput(unsigned));
    const cert: HostDeviceCert = { ...unsigned, sig_host_op: sig };

    await expectArtifactError(
      () => verifyHostDeviceCert(cert, host.rootFp, 1_500n),
      "DeviceFingerprintMismatch",
    );
  });

  /** The certificate is fully valid and self-consistent (host_fp really is
   * SHA-256(host_root_pk), the chain and signature are genuine) — but the caller pinned a
   * DIFFERENT host_fp than the one this certificate declares. A client that fetched this
   * certificate for a host it did not intend to talk to must reject it. */
  it("rejects a host_fp that is not the caller's expected pinned fp", async () => {
    const host = await makeTestHost(0x21, 0x22, 10_000n);
    const dev = await makeHostDevice(0x76, 0x77);
    const cert = await issue(host, dev, 1_000n, 2_000n);

    const otherHostPk = await ed25519PublicKeyFromSeed(new Uint8Array(32).fill(0x99));
    const otherHostFp = await rootFpOf(otherHostPk);
    await expectArtifactError(
      () => verifyHostDeviceCert(cert, otherHostFp, 1_500n),
      "HostFingerprintMismatch",
    );
  });

  it("rejects a tampered host_root_pk", async () => {
    // host_fp is unchanged, but host_root_pk is swapped for a *different* (validly-encoded)
    // root's public key — SHA-256(host_root_pk) no longer matches the declared host_fp. Mirrors
    // capability.json's "swapped for a different root" test.
    const host = await makeTestHost(0x23, 0x24, 10_000n);
    const dev = await makeHostDevice(0x78, 0x79);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    const otherRootPk = await ed25519PublicKeyFromSeed(new Uint8Array(32).fill(0x9a));
    cert.host_root_pk = otherRootPk;
    await expectArtifactError(
      () => verifyHostDeviceCert(cert, host.rootFp, 1_500n),
      "HostFingerprintMismatch",
    );
  });

  it("rejects a malformed op_cert", async () => {
    const host = await makeTestHost(0x25, 0x26, 10_000n);
    const dev = await makeHostDevice(0x7a, 0x7b);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    cert.op_cert = new Uint8Array([0xff, 0xff, 0xff, 0xff]); // not valid canonical CBOR
    await expectArtifactError(() => verifyHostDeviceCert(cert, host.rootFp, 1_500n), "MalformedOpCert");
  });

  it("rejects an op_cert signed by the wrong root", async () => {
    // The op cert is validly signed, but by a DIFFERENT root than the one the certificate
    // declares as host_root_pk — so verifyHostOpKeyCert's own signature check must fail when
    // re-run against the declared host_root_pk.
    const realHost = await makeTestHost(0x27, 0x28, 10_000n);
    const impostorRootPk = await ed25519PublicKeyFromSeed(new Uint8Array(32).fill(0x7a));
    const impostorRootFp = await rootFpOf(impostorRootPk);
    const dev = await makeHostDevice(0x7c, 0x7d);
    const cert = await issueTestHostDeviceCert({
      opSignerSeed: realHost.opSeed,
      hostFp: impostorRootFp, // host_fp/host_root_pk declare the impostor root...
      hostRootPk: impostorRootPk,
      opCert: realHost.opCert, // ...but op_cert was actually signed by realHost's root
      algId: dev.algId,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      ts: 1_000n,
      exp: 2_000n,
    });
    await expectArtifactError(
      () => verifyHostDeviceCert(cert, impostorRootFp, 1_500n),
      "BadSignature",
    );
  });

  it("rejects a signature by a key the op_cert does not certify", async () => {
    // The op cert genuinely certifies host.opSeed's key, but the certificate is signed by some
    // other key instead — step 7 must reject even though steps 1-6 all pass.
    const host = await makeTestHost(0x29, 0x2a, 10_000n);
    const impostorSignerSeed = new Uint8Array(32).fill(0x6f);
    const dev = await makeHostDevice(0x7e, 0x7f);
    const cert = await issueTestHostDeviceCert({
      opSignerSeed: impostorSignerSeed, // not the key op_cert.host_op_pk names
      hostFp: host.rootFp,
      hostRootPk: host.rootPk,
      opCert: host.opCert,
      algId: dev.algId,
      signPk: dev.signPk,
      agreePk: dev.agreePk,
      ts: 1_000n,
      exp: 2_000n,
    });
    await expectArtifactError(() => verifyHostDeviceCert(cert, host.rootFp, 1_500n), "BadSignature");
  });

  it("rejects a bad signature", async () => {
    const host = await makeTestHost(0x2b, 0x2c, 10_000n);
    const dev = await makeHostDevice(0x80, 0x81);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    cert.sig_host_op = new Uint8Array(cert.sig_host_op);
    cert.sig_host_op[0] ^= 0xff;
    await expectArtifactError(() => verifyHostDeviceCert(cert, host.rootFp, 1_500n), "BadSignature");
  });

  it("rejects an expired certificate", async () => {
    const host = await makeTestHost(0x2d, 0x2e, 10_000n);
    const dev = await makeHostDevice(0x82, 0x83);
    const cert = await issue(host, dev, 1_000n, 2_000n);
    await expectArtifactError(() => verifyHostDeviceCert(cert, host.rootFp, 2_001n), "Expired");
  });

  it("rejects when the embedded op cert has itself expired, even though the certificate's own exp has not", async () => {
    // op_cert itself expires at 1_000, well before the certificate's own exp (2_000) — step 6 of
    // the chain must catch this even though the certificate's own exp check would pass.
    const host = await makeTestHost(0x2f, 0x30, 1_000n);
    const dev = await makeHostDevice(0x84, 0x85);
    const cert = await issue(host, dev, 0n, 2_000n);
    await expectArtifactError(() => verifyHostDeviceCert(cert, host.rootFp, 1_500n), "Expired");
  });
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
