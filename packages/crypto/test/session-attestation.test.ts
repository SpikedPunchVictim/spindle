// Tests for `verifySessionAttestation` (`../src/artifacts.ts`) — the TypeScript twin of
// `spindle-core`'s `session_attest.rs` verifier (Rust twin landing in parallel; not yet present
// when this file was written). `SessionAttestation` (`spindle-sess-attest-v1`, DESIGN.md §A3, §A4
// step 2, §A7b, added v0.9.29) is the A7b artifact that closes td-0bcab4:
// `DeviceCertificate.nats_fp` was carried on the wire to bind a device to one NATS session key,
// but no verifier in either language ever read it, so the bundle `{root_pk, device_cert, caps}`
// was a pure bearer token. `sig_device(nats_fp, ts)` fixes that by making the device's identity
// key actually exercised at CONNECT.
//
// A golden vector now exists too (`vectors/signed/session-attestation.json`, covered by
// `vectors.test.ts`'s `session-attestation.json` suite) — these remain as a separate,
// locally-generated fixture suite because they exercise cases the golden vector doesn't: the
// SessionKeyMismatch/clock-skew/wrong-device-key negative paths. Real Ed25519 signatures, built
// with this package's own primitives — the same convention as `vectors.test.ts`'s
// `issueTestDeviceCertificate` negative suite and `bootstrap.test.ts`'s fixture helpers.

import { SessionAttestation } from "@spindle/proto";
import { describe, expect, it } from "vitest";

import {
  ArtifactError,
  SESSION_ATTESTATION_CLOCK_SKEW_SECS,
  verifySessionAttestation,
} from "../src/artifacts.js";
import { ed25519PublicKeyFromSeed, ed25519Sign } from "../src/backend.js";

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

/** Builds a real, self-consistent `SessionAttestation` by signing
 * `SessionAttestation.signingInput` with a device's Ed25519 identity seed — mirrors
 * `vectors.test.ts`'s `issueTestDeviceCertificate` in spirit (sign the exact unsigned content,
 * never hand-roll bytes the production encoder should produce). */
async function issueTestAttestation(params: {
  deviceSeed: Uint8Array;
  natsFp: Uint8Array;
  ts: bigint;
}): Promise<SessionAttestation> {
  const unsigned: SessionAttestation = {
    nats_fp: params.natsFp,
    ts: params.ts,
    sig_device: new Uint8Array(64),
  };
  const sig = await ed25519Sign(params.deviceSeed, SessionAttestation.signingInput(unsigned));
  return { ...unsigned, sig_device: sig };
}

describe("verifySessionAttestation", () => {
  const deviceSeed = new Uint8Array(32).fill(0x11);
  const natsFp = new Uint8Array(32).fill(0xaa);

  it("round trip: a well-signed attestation naming the connecting session key verifies", async () => {
    const devicePk = await ed25519PublicKeyFromSeed(deviceSeed);
    const att = await issueTestAttestation({ deviceSeed, natsFp, ts: 1_000n });
    await expect(verifySessionAttestation(att, devicePk, natsFp, 1_000n)).resolves.toBeUndefined();
  });

  // td-0bcab4: this is the test that pins the defect closed. `DeviceCertificate.nats_fp` existed
  // to bind a device to one NATS session key, but no verifier in either language ever compared it
  // against the session actually being used, so a well-signed bundle was a bearer token usable
  // from any nkey. `verifySessionAttestation` makes `expectedNatsFp` a required argument (see its
  // doc comment) specifically so this cannot happen again: a well-signed attestation that names a
  // *different* session key than the one the caller is actually establishing must be rejected, not
  // silently accepted the way `nats_fp` always was.
  it("rejects a well-signed attestation naming a different session key (td-0bcab4)", async () => {
    const devicePk = await ed25519PublicKeyFromSeed(deviceSeed);
    const att = await issueTestAttestation({ deviceSeed, natsFp, ts: 1_000n });
    const someoneElsesNatsFp = new Uint8Array(32).fill(0xbb);
    await expectArtifactError(
      () => verifySessionAttestation(att, devicePk, someoneElsesNatsFp, 1_000n),
      "SessionKeyMismatch",
    );
  });

  it("rejects a tampered signature", async () => {
    const devicePk = await ed25519PublicKeyFromSeed(deviceSeed);
    const att = await issueTestAttestation({ deviceSeed, natsFp, ts: 1_000n });
    const tampered: SessionAttestation = {
      ...att,
      sig_device: new Uint8Array(att.sig_device),
    };
    tampered.sig_device[0] ^= 0xff;
    await expectArtifactError(
      () => verifySessionAttestation(tampered, devicePk, natsFp, 1_000n),
      "BadSignature",
    );
  });

  it("rejects a genuine signature verified against the wrong device key", async () => {
    const att = await issueTestAttestation({ deviceSeed, natsFp, ts: 1_000n });
    const otherDeviceSeed = new Uint8Array(32).fill(0x22);
    const otherDevicePk = await ed25519PublicKeyFromSeed(otherDeviceSeed);
    await expectArtifactError(
      () => verifySessionAttestation(att, otherDevicePk, natsFp, 1_000n),
      "BadSignature",
    );
  });

  describe("clock skew (SESSION_ATTESTATION_CLOCK_SKEW_SECS = ±120s)", () => {
    it("accepts exactly at the +120s boundary", async () => {
      const devicePk = await ed25519PublicKeyFromSeed(deviceSeed);
      const att = await issueTestAttestation({ deviceSeed, natsFp, ts: 1_000n });
      await expect(
        verifySessionAttestation(att, devicePk, natsFp, 1_000n + SESSION_ATTESTATION_CLOCK_SKEW_SECS),
      ).resolves.toBeUndefined();
    });

    it("accepts exactly at the -120s boundary", async () => {
      const devicePk = await ed25519PublicKeyFromSeed(deviceSeed);
      const att = await issueTestAttestation({ deviceSeed, natsFp, ts: 1_000n });
      await expect(
        verifySessionAttestation(att, devicePk, natsFp, 1_000n - SESSION_ATTESTATION_CLOCK_SKEW_SECS),
      ).resolves.toBeUndefined();
    });

    it("rejects 1 second past the +120s boundary", async () => {
      const devicePk = await ed25519PublicKeyFromSeed(deviceSeed);
      const att = await issueTestAttestation({ deviceSeed, natsFp, ts: 1_000n });
      await expectArtifactError(
        () =>
          verifySessionAttestation(
            att,
            devicePk,
            natsFp,
            1_000n + SESSION_ATTESTATION_CLOCK_SKEW_SECS + 1n,
          ),
        "TimestampSkew",
      );
    });

    it("rejects 1 second past the -120s boundary", async () => {
      const devicePk = await ed25519PublicKeyFromSeed(deviceSeed);
      const att = await issueTestAttestation({ deviceSeed, natsFp, ts: 1_000n });
      await expectArtifactError(
        () =>
          verifySessionAttestation(
            att,
            devicePk,
            natsFp,
            1_000n - SESSION_ATTESTATION_CLOCK_SKEW_SECS - 1n,
          ),
        "TimestampSkew",
      );
    });
  });
});
