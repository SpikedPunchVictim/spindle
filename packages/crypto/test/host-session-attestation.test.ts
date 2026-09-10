// Tests for `verifyHostSessionAttestation` (`../src/artifacts.ts`) — the TypeScript twin of
// `spindle-core`'s `host_session_attest.rs` verifier (Rust twin landing in parallel; not yet
// present when this file was written). `HostSessionAttestation` (`spindle-host-sess-attest-v1`,
// DESIGN.md §A4 step 3, §A7b, added v0.9.31) is the host-side mirror of `SessionAttestation` and
// closes td-583db5: `HostOpKeyCert.nats_fp` was meant to bind a host's operating key to one NATS
// session, but the only place that field was ever compared against the connecting session was a
// single manual comparison in `spindle-helper`'s `authz::decide_host_connect`, whose own comment
// noted no other caller did the same check. `sig_op(nats_fp, ts)` fixes that by moving the binding
// into its own per-connect artifact, signed by the host's operating key, with the same
// required-argument verifier shape `verifySessionAttestation` already has.
//
// Real Ed25519 signatures, built with this package's own primitives — the same convention as
// `session-attestation.test.ts`. Seeds are distinct from that file's.

import { HostSessionAttestation } from "@spindle/proto";
import { describe, expect, it } from "vitest";

import {
  ArtifactError,
  HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS,
  verifyHostSessionAttestation,
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

/** Builds a real, self-consistent `HostSessionAttestation` by signing
 * `HostSessionAttestation.signingInput` with a host operating key's Ed25519 seed — mirrors
 * `session-attestation.test.ts`'s `issueTestAttestation` in spirit (sign the exact unsigned
 * content, never hand-roll bytes the production encoder should produce). */
async function issueTestAttestation(params: {
  opSeed: Uint8Array;
  natsFp: Uint8Array;
  ts: bigint;
}): Promise<HostSessionAttestation> {
  const unsigned: HostSessionAttestation = {
    nats_fp: params.natsFp,
    ts: params.ts,
    sig_op: new Uint8Array(64),
  };
  const sig = await ed25519Sign(params.opSeed, HostSessionAttestation.signingInput(unsigned));
  return { ...unsigned, sig_op: sig };
}

describe("verifyHostSessionAttestation", () => {
  const opSeed = new Uint8Array(32).fill(0x71);
  const natsFp = new Uint8Array(32).fill(0xdd);

  it("round trip: a well-signed attestation naming the connecting session key verifies", async () => {
    const opPk = await ed25519PublicKeyFromSeed(opSeed);
    const att = await issueTestAttestation({ opSeed, natsFp, ts: 1_000n });
    await expect(verifyHostSessionAttestation(att, opPk, natsFp, 1_000n)).resolves.toBeUndefined();
  });

  // td-583db5: this is the test that pins the defect closed. `HostOpKeyCert.nats_fp` existed to
  // bind a host's operating key to one NATS session, but the only caller that ever compared it was
  // a single manual check in `decide_host_connect`, with a comment noting no other caller did the
  // same. `verifyHostSessionAttestation` makes `expectedNatsFp` a required argument (see its doc
  // comment) specifically so this cannot happen again: a well-signed attestation that names a
  // *different* session key than the one the caller is actually establishing must be rejected.
  it("rejects a well-signed attestation naming a different session key (td-583db5)", async () => {
    const opPk = await ed25519PublicKeyFromSeed(opSeed);
    const att = await issueTestAttestation({ opSeed, natsFp, ts: 1_000n });
    const someoneElsesNatsFp = new Uint8Array(32).fill(0xee);
    await expectArtifactError(
      () => verifyHostSessionAttestation(att, opPk, someoneElsesNatsFp, 1_000n),
      "HostSessionKeyMismatch",
    );
  });

  // Regression pin: `bytesEqual([], [])` is vacuously `true`, so a naive
  // `bytesEqual(expectedNatsFp, attestation.nats_fp)` binding check "verifies" a well-signed
  // attestation that names an empty `nats_fp` against a caller that (by bug or omission) also
  // supplies an empty `expectedNatsFp` — the check running and passing having bound nothing. This
  // must fail before the length guard exists and pass after it.
  it("rejects a well-signed attestation with an empty nats_fp verified against an empty expectedNatsFp", async () => {
    const opPk = await ed25519PublicKeyFromSeed(opSeed);
    const emptyFp = new Uint8Array(0);
    const att = await issueTestAttestation({ opSeed, natsFp: emptyFp, ts: 1_000n });
    await expectArtifactError(
      () => verifyHostSessionAttestation(att, opPk, emptyFp, 1_000n),
      "HostSessionKeyMismatch",
    );
  });

  it("rejects a 31-byte expectedNatsFp even when it otherwise matches attestation.nats_fp", async () => {
    const opPk = await ed25519PublicKeyFromSeed(opSeed);
    const shortFp = natsFp.slice(0, 31);
    const att = await issueTestAttestation({ opSeed, natsFp: shortFp, ts: 1_000n });
    await expectArtifactError(
      () => verifyHostSessionAttestation(att, opPk, shortFp, 1_000n),
      "HostSessionKeyMismatch",
    );
  });

  it("rejects a 33-byte expectedNatsFp even when it otherwise matches attestation.nats_fp", async () => {
    const opPk = await ed25519PublicKeyFromSeed(opSeed);
    const longFp = new Uint8Array(33).fill(0xdd);
    const att = await issueTestAttestation({ opSeed, natsFp: longFp, ts: 1_000n });
    await expectArtifactError(
      () => verifyHostSessionAttestation(att, opPk, longFp, 1_000n),
      "HostSessionKeyMismatch",
    );
  });

  it("rejects a tampered signature", async () => {
    const opPk = await ed25519PublicKeyFromSeed(opSeed);
    const att = await issueTestAttestation({ opSeed, natsFp, ts: 1_000n });
    const tampered: HostSessionAttestation = {
      ...att,
      sig_op: new Uint8Array(att.sig_op),
    };
    tampered.sig_op[0] ^= 0xff;
    await expectArtifactError(
      () => verifyHostSessionAttestation(tampered, opPk, natsFp, 1_000n),
      "BadSignature",
    );
  });

  it("rejects a genuine signature verified against the wrong operating key", async () => {
    const att = await issueTestAttestation({ opSeed, natsFp, ts: 1_000n });
    const otherOpSeed = new Uint8Array(32).fill(0x72);
    const otherOpPk = await ed25519PublicKeyFromSeed(otherOpSeed);
    await expectArtifactError(
      () => verifyHostSessionAttestation(att, otherOpPk, natsFp, 1_000n),
      "BadSignature",
    );
  });

  describe("clock skew (HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS = ±120s)", () => {
    it("accepts exactly at the +120s boundary", async () => {
      const opPk = await ed25519PublicKeyFromSeed(opSeed);
      const att = await issueTestAttestation({ opSeed, natsFp, ts: 1_000n });
      await expect(
        verifyHostSessionAttestation(
          att,
          opPk,
          natsFp,
          1_000n + HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS,
        ),
      ).resolves.toBeUndefined();
    });

    it("accepts exactly at the -120s boundary", async () => {
      const opPk = await ed25519PublicKeyFromSeed(opSeed);
      const att = await issueTestAttestation({ opSeed, natsFp, ts: 1_000n });
      await expect(
        verifyHostSessionAttestation(
          att,
          opPk,
          natsFp,
          1_000n - HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS,
        ),
      ).resolves.toBeUndefined();
    });

    it("rejects 1 second past the +120s boundary", async () => {
      const opPk = await ed25519PublicKeyFromSeed(opSeed);
      const att = await issueTestAttestation({ opSeed, natsFp, ts: 1_000n });
      await expectArtifactError(
        () =>
          verifyHostSessionAttestation(
            att,
            opPk,
            natsFp,
            1_000n + HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS + 1n,
          ),
        "TimestampSkew",
      );
    });

    it("rejects 1 second past the -120s boundary", async () => {
      const opPk = await ed25519PublicKeyFromSeed(opSeed);
      const att = await issueTestAttestation({ opSeed, natsFp, ts: 1_000n });
      await expectArtifactError(
        () =>
          verifyHostSessionAttestation(
            att,
            opPk,
            natsFp,
            1_000n - HOST_SESSION_ATTESTATION_CLOCK_SKEW_SECS - 1n,
          ),
        "TimestampSkew",
      );
    });
  });
});
