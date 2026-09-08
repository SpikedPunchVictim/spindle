// Tests for the device bootstrap state bundle (`../src/bootstrap.ts`) — the TypeScript twin of
// `crates/spindle-core/src/artifacts/bootstrap.rs`'s own `mod tests`. Mirrors that Rust test list
// one-for-one where the language allows (see each `it` block's comment for its Rust counterpart).
//
// These are locally-generated fixtures, not golden-vector conformance checks (no fixed expected
// bytes) — they only need internally self-consistent real Ed25519/X25519 keys and a real
// signature chain, built with this package's own primitives, mirroring `vectors.test.ts`'s own
// `makeTestHost`/`issueTestCapability`-style helpers (which in turn mirror
// `crates/spindle-core/src/artifacts/capability.rs`'s `test_host`/`issue`).

import { CapKind, Capability, HostOpKeyCert } from "@spindle/proto";
import type { BundleEntry } from "@spindle/proto";
import { MAX_BUNDLE_ENTRIES, QR_V40_M_CAPACITY_BYTES } from "@spindle/proto";
import { describe, expect, it } from "vitest";

import { ArtifactError } from "../src/artifacts.js";
import { ed25519PublicKeyFromSeed, ed25519Sign, x25519PublicKeyFromSeed } from "../src/backend.js";
import {
  BundleError,
  QrEcLevel,
  buildBootstrapBundle,
  verifyBootstrapBundle,
} from "../src/bootstrap.js";
import { base32EncodeNoPad, deviceFpOf, rootFpOf } from "../src/fingerprint.js";
import { bytesEqual } from "./helpers.js";

const ALG_ID_V1 = 1;

// ---- test fixtures: a real host (root + op key + op cert) and a real member capability for it,
// plus a real envelope device identity for the entry's sign_pk/agree_pk — same shape as
// `bootstrap.rs`'s own `TestHost`/`real_entry` helpers. ----

interface TestHost {
  rootSeed: Uint8Array;
  rootPk: Uint8Array;
  opSeed: Uint8Array;
  opPk: Uint8Array;
  opCert: HostOpKeyCert;
}

async function testHost(
  rootSeedFill: number,
  opSeedFill: number,
  opCertExp: bigint,
): Promise<TestHost> {
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

interface HostEnvelope {
  signPk: Uint8Array;
  agreePk: Uint8Array;
}

/** One host's envelope device identity, for building an entry's `sign_pk`/`agree_pk` — real keys,
 * distinct from the host's root/op keys, exactly as `bootstrap.rs`'s `host_envelope` does. */
async function hostEnvelope(seed: number): Promise<HostEnvelope> {
  const signSeed = new Uint8Array(32).fill(seed);
  const agreeSeed = new Uint8Array(32).fill((seed + 1) & 0xff);
  const signPk = await ed25519PublicKeyFromSeed(signSeed);
  const agreePk = await x25519PublicKeyFromSeed(agreeSeed);
  return { signPk, agreePk };
}

/** A real, mintable `BundleEntry`: a genuine host + a genuine `member` capability for it + genuine
 * envelope keys, exactly as `buildBootstrapBundle`'s caller would hold. Mirrors `bootstrap.rs`'s
 * `real_entry`. */
async function realEntry(
  hostSeed: number,
  envelopeSeed: number,
  capExp: bigint,
): Promise<{ host: TestHost; entry: BundleEntry }> {
  const host = await testHost(hostSeed, (hostSeed + 1) & 0xff, 10_000n);
  const hostFp = await rootFpOf(host.rootPk);
  const unsignedCap: Capability = {
    v: 1,
    host_fp: hostFp,
    host_root_pk: host.rootPk,
    op_cert: HostOpKeyCert.toCanonicalBytes(host.opCert),
    kind: CapKind.Member,
    subject: new Uint8Array(32).fill(0xaa),
    cap_epoch: 0n,
    exp: capExp,
    nonce: new Uint8Array(16).fill(0xaa),
    sig: new Uint8Array(64),
  };
  const sig = await ed25519Sign(host.opSeed, Capability.signingInput(unsignedCap));
  const cap: Capability = { ...unsignedCap, sig };

  const envelope = await hostEnvelope(envelopeSeed);
  const entry: BundleEntry = {
    sign_pk: envelope.signPk,
    agree_pk: envelope.agreePk,
    member_cap: cap,
  };
  return { host, entry };
}

async function expectBundleError(fn: () => Promise<unknown>): Promise<BundleError> {
  try {
    await fn();
  } catch (e) {
    expect(e).toBeInstanceOf(BundleError);
    return e as BundleError;
  }
  throw new Error("expected a BundleError, but nothing threw");
}

// ---- happy path ----

describe("buildBootstrapBundle / verifyBootstrapBundle", () => {
  // Rust: build_then_verify_round_trips_two_entries
  it("round trips two entries, deriving hostFp and hostDeviceFp on verify", async () => {
    const { host: hostA, entry: entryA } = await realEntry(0x10, 0x20, 10_000n);
    const { host: hostB, entry: entryB } = await realEntry(0x11, 0x21, 10_000n);
    const registry = "nats://registry.example:4222";

    const bundle = await buildBootstrapBundle(registry, [entryA, entryB], QrEcLevel.M);

    const verified = await verifyBootstrapBundle(bundle, 1_500n);
    expect(verified.registry).toBe(registry);
    expect(verified.entries).toHaveLength(2);

    const hosts = [hostA, hostB];
    for (let i = 0; i < verified.entries.length; i++) {
      const verifiedEntry = verified.entries[i];
      const expectedHostFp = await rootFpOf(hosts[i].rootPk);
      expect(bytesEqual(verifiedEntry.hostFp, expectedHostFp)).toBe(true);

      const { signPk, agreePk } = verifiedEntry;
      const expectedDeviceFp = await deviceFpOf(ALG_ID_V1, signPk, agreePk);
      expect(bytesEqual(verifiedEntry.hostDeviceFp, expectedDeviceFp)).toBe(true);
    }
  });

  // ---- version floor ----

  // Rust: verify_rejects_v_below_floor_before_any_crypto_runs
  it("rejects a v below the floor before any crypto runs", async () => {
    const { entry } = await realEntry(0x30, 0x31, 10_000n);
    const bundle = await buildBootstrapBundle("nats://x:4222", [entry], QrEcLevel.M);
    bundle.v = 0;

    const err = await expectBundleError(() => verifyBootstrapBundle(bundle, 1_500n));
    expect(err.kind).toBe("VersionTooLow");
    expect(err.found).toBe(0);
    expect(err.minimum).toBe(1);
  });

  // ---- per-entry failures, with the right index ----

  // Rust: rejects_expired_entry_at_the_right_index
  it("rejects an expired entry at the right index", async () => {
    const { entry: entryA } = await realEntry(0x40, 0x41, 10_000n);
    // entryB's capability expires at 1_000 — well before `now` below.
    const { entry: entryB } = await realEntry(0x42, 0x43, 1_000n);
    const bundle = await buildBootstrapBundle("nats://x:4222", [entryA, entryB], QrEcLevel.M);

    const err = await expectBundleError(() => verifyBootstrapBundle(bundle, 1_500n));
    expect(err.kind).toBe("Entry");
    expect(err.index).toBe(1);
    expect(err.source).toBeInstanceOf(ArtifactError);
    expect((err.source as ArtifactError).kind).toBe("Expired");
  });

  // Rust: rejects_entry_whose_cap_host_fp_is_corrupted
  it("rejects an entry whose cap's host_fp is corrupted", async () => {
    // NEUTER VERIFICATION: corrupt the cap's *carried* host_fp field and confirm rejection still
    // happens (via HostFingerprintMismatch). This proves the DERIVED value (SHA-256(host_root_pk),
    // recomputed inside verifyCapability) is what's authoritative — a carried host_fp could never
    // be trusted in its place, because corrupting it here is caught rather than silently accepted
    // or silently propagated into the verified output.
    const { entry } = await realEntry(0x44, 0x45, 10_000n);
    entry.member_cap.host_fp = entry.member_cap.host_fp.slice();
    entry.member_cap.host_fp[0] ^= 0xff;
    const bundle = await buildBootstrapBundle("nats://x:4222", [entry], QrEcLevel.M);

    const err = await expectBundleError(() => verifyBootstrapBundle(bundle, 1_500n));
    expect(err.kind).toBe("Entry");
    expect(err.index).toBe(0);
    expect((err.source as ArtifactError).kind).toBe("HostFingerprintMismatch");
  });

  // Rust: rejects_entry_with_malformed_agree_pk
  it("rejects an entry with a malformed agree_pk", async () => {
    const { entry } = await realEntry(0x46, 0x47, 10_000n);
    entry.agree_pk = new Uint8Array(31).fill(0x01); // one byte short
    const bundle = await buildBootstrapBundle("nats://x:4222", [entry], QrEcLevel.M);

    const err = await expectBundleError(() => verifyBootstrapBundle(bundle, 1_500n));
    expect(err.kind).toBe("Entry");
    expect(err.index).toBe(0);
    expect((err.source as ArtifactError).kind).toBe("InvalidPublicKey");
  });

  // ---- QR fit check ----

  // Rust: build_drops_entries_that_overflow_the_ec_m_budget
  it("drops entries that overflow the EC-M budget, reporting the exact fits count", async () => {
    // NEUTER VERIFICATION: deleting the fit check in `buildBootstrapBundle` (i.e. always returning
    // the bundle regardless of encoded size) would make this test fail, since it would never see
    // `TooLargeForQr` at all.
    //
    // Real entries measure ~530 B each; the EC-M budget is 2331 B. 6 real entries safely exceed it
    // regardless of small per-entry size drift, while staying well under MAX_BUNDLE_ENTRIES (32).
    const entries: BundleEntry[] = [];
    const entryFps: Uint8Array[] = [];
    for (let i = 0; i < 6; i++) {
      const { entry } = await realEntry(0x50 + i, 0x60 + i, 10_000n);
      entries.push(entry);
      entryFps.push(await rootFpOf(entry.member_cap.host_root_pk));
    }

    const err = await expectBundleError(() =>
      buildBootstrapBundle("nats://x:4222", entries, QrEcLevel.M),
    );
    expect(err.kind).toBe("TooLargeForQr");
    expect(err.ecLevel).toBe(QrEcLevel.M);
    expect(err.budgetBytes).toBe(QR_V40_M_CAPACITY_BYTES);
    expect(err.fits).toBeLessThan(6);
    const fits = err.fits as number;
    const dropped = err.dropped as Uint8Array[];
    expect(dropped).toHaveLength(6 - fits);
    for (let i = fits; i < 6; i++) {
      expect(bytesEqual(dropped[i - fits], entryFps[i])).toBe(true);
    }
  });

  // Rust: too_large_for_qr_display_prints_no_fingerprint
  it("the too-large-for-QR message reports only the count, never a fingerprint", async () => {
    // Regression guard for the redaction discipline documented on `BundleError.tooLargeForQr`: the
    // error's `message` must report only the dropped COUNT, never a dropped fingerprint's base32
    // form (which is what would reach a log line if this were ever logged).
    const entries: BundleEntry[] = [];
    const droppedFpsCandidate: Uint8Array[] = [];
    for (let i = 0; i < 6; i++) {
      const { entry } = await realEntry(0x70 + i, 0x80 + i, 10_000n);
      entries.push(entry);
      droppedFpsCandidate.push(await rootFpOf(entry.member_cap.host_root_pk));
    }

    const err = await expectBundleError(() =>
      buildBootstrapBundle("nats://x:4222", entries, QrEcLevel.M),
    );
    const fits = err.fits as number;
    const dropped = err.dropped as Uint8Array[];

    expect(err.message).toContain(String(dropped.length));

    for (let i = fits; i < droppedFpsCandidate.length; i++) {
      const base32 = base32EncodeNoPad(droppedFpsCandidate[i]);
      expect(err.message).not.toContain(base32);
    }
  });

  // ---- MAX_BUNDLE_ENTRIES cap on build, before any fit work ----

  // Rust: build_rejects_more_than_max_bundle_entries_before_fit_work
  it("rejects more than MAX_BUNDLE_ENTRIES before any fit work", async () => {
    const entries: BundleEntry[] = [];
    for (let i = 0; i < MAX_BUNDLE_ENTRIES + 1; i++) {
      const { entry } = await realEntry(i, (i + 100) & 0xff, 10_000n);
      entries.push(entry);
    }

    const err = await expectBundleError(() =>
      buildBootstrapBundle("nats://x:4222", entries, QrEcLevel.M),
    );
    expect(err.kind).toBe("TooManyEntries");
    expect(err.found).toBe(MAX_BUNDLE_ENTRIES + 1);
    expect(err.max).toBe(MAX_BUNDLE_ENTRIES);
  });
});
