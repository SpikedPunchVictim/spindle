// Verify functions for the A7b signed-artifact catalog, excluding `Envelope` (which has its own
// session/AEAD machinery — see `envelope.ts`). Each function takes a `@spindle/proto` wire struct,
// computes its `signingInput()` (already carrying the correct A7b domain tag — see
// `@spindle/proto`'s `tags` module), and verifies it with the correct key for that artifact kind
// per DESIGN.md §A7b. The TypeScript twin of `crates/spindle-core/src/artifacts/*.rs`.
//
// | Artifact | Signer |
// |---|---|
// | DeviceCertificate | identity root |
// | Capability | host operating key (embedded as `host_pk`; self-verifying) |
// | HostOpKeyCert | host root |
// | RevocationRecord | host op key or identity root |
// | AdmissionToken | operator admission key |
// | AdminCommand | operator admission key |
//
// This module never reads a system clock: every time check takes a caller-supplied `now: bigint`
// (Unix seconds), consistent with DESIGN.md §A7 ("clients compute an offset" from helper server
// time).

import {
  AdminCommand,
  AdmissionToken,
  Capability,
  DeviceCertificate,
  HostOpKeyCert,
  RevocationRecord,
} from "@spindle/proto";

import { type BackendOption, ed25519Verify } from "./backend.js";
import { rootFpOf } from "./fingerprint.js";

/** `|ts - now| <= 2 min` (DESIGN.md §A7b), same window as the envelope's clock-skew rule. */
export const ADMIN_COMMAND_CLOCK_SKEW_SECS = 120n;

/** Errors from verifying any A7b signed artifact in this module (DESIGN.md §A7b). Every `verify*`
 * function fails closed on the first check it fails — never silently. Mirrors `spindle-core`'s
 * `ArtifactError` enum. */
export type ArtifactErrorKind =
  | "BadSignature"
  | "InvalidSignatureEncoding"
  | "InvalidPublicKey"
  | "Expired"
  | "TimestampSkew"
  | "HostFingerprintMismatch"
  | "RootFingerprintMismatch";

export class ArtifactError extends Error {
  readonly kind: ArtifactErrorKind;

  private constructor(kind: ArtifactErrorKind, message: string) {
    super(message);
    this.name = "ArtifactError";
    this.kind = kind;
  }

  static badSignature(): ArtifactError {
    return new ArtifactError("BadSignature", "signature invalid");
  }
  static invalidSignatureEncoding(): ArtifactError {
    return new ArtifactError("InvalidSignatureEncoding", "malformed signature encoding (expected 64 bytes)");
  }
  static invalidPublicKey(): ArtifactError {
    return new ArtifactError("InvalidPublicKey", "malformed public key encoding (expected 32 bytes)");
  }
  static expired(): ArtifactError {
    return new ArtifactError("Expired", "artifact expired (now > exp)");
  }
  static timestampSkew(): ArtifactError {
    return new ArtifactError("TimestampSkew", "timestamp outside the allowed clock-skew window");
  }
  static hostFingerprintMismatch(): ArtifactError {
    return new ArtifactError(
      "HostFingerprintMismatch",
      "host_fp does not match SHA-256(host_pk) — capability is not self-verifying",
    );
  }
  static rootFingerprintMismatch(): ArtifactError {
    return new ArtifactError("RootFingerprintMismatch", "root_fp does not match the expected pinned root");
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function absDiff(a: bigint, b: bigint): bigint {
  return a > b ? a - b : b - a;
}

function checkExp(now: bigint, exp: bigint): void {
  if (now > exp) throw ArtifactError.expired();
}

function checkSkew(now: bigint, ts: bigint, maxSkewSecs: bigint): void {
  if (absDiff(now, ts) > maxSkewSecs) throw ArtifactError.timestampSkew();
}

function requireSignatureLen(sig: Uint8Array): void {
  if (sig.length !== 64) throw ArtifactError.invalidSignatureEncoding();
}

function requirePublicKeyLen(pk: Uint8Array): void {
  if (pk.length !== 32) throw ArtifactError.invalidPublicKey();
}

async function verifySigOrThrow(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  backend?: BackendOption["backend"],
): Promise<void> {
  requireSignatureLen(signature);
  const ok = await ed25519Verify(publicKey, message, signature, { backend });
  if (!ok) throw ArtifactError.badSignature();
}

/** Verifies a device certificate chains to `expectedRootFp` under `rootPk`, that `sig_root` is
 * valid, and that `now` is within `exp` (A7b: `exp` 1 y, re-signed on contact; replay rule: n/a,
 * revocable). */
export async function verifyDeviceCertificate(
  cert: DeviceCertificate,
  rootPk: Uint8Array,
  expectedRootFp: Uint8Array,
  now: bigint,
  opts?: BackendOption,
): Promise<void> {
  requirePublicKeyLen(rootPk);
  const rootFp = await rootFpOf(rootPk);
  if (!bytesEqual(rootFp, expectedRootFp)) throw ArtifactError.rootFingerprintMismatch();
  await verifySigOrThrow(rootPk, DeviceCertificate.signingInput(cert), cert.sig_root, opts?.backend);
  checkExp(now, cert.exp);
}

/** Verifies a capability's self-verifying property (`host_fp == SHA-256(host_pk)` — no external
 * root or registry lookup needed, DESIGN.md §A4), `sig_host`, and `exp`.
 *
 * **Ambiguity flagged, not resolved** (mirrors the note in `spindle-core`'s
 * `artifacts/capability.rs`): DESIGN.md §A7b's signed-artifact table lists `nbf = issue ts` as
 * part of a capability's time rule, but `spindle_proto::artifacts::Capability` — the schema of
 * record — has no `nbf` field. This function therefore checks only `exp`, matching the wire
 * schema that actually exists. */
export async function verifyCapability(cap: Capability, now: bigint, opts?: BackendOption): Promise<void> {
  requirePublicKeyLen(cap.host_pk);
  const expectedFp = await rootFpOf(cap.host_pk);
  if (!bytesEqual(expectedFp, cap.host_fp)) throw ArtifactError.hostFingerprintMismatch();
  await verifySigOrThrow(cap.host_pk, Capability.signingInput(cap), cap.sig_host, opts?.backend);
  checkExp(now, cap.exp);
}

/** Verifies a host operating-key certificate chains to `expectedRootFp`, that `sig_host_root` is
 * valid, and `now` is within `exp` (A7b: `exp` 90 d; replay rule: n/a, rotation). */
export async function verifyHostOpKeyCert(
  cert: HostOpKeyCert,
  hostRootPk: Uint8Array,
  expectedRootFp: Uint8Array,
  now: bigint,
  opts?: BackendOption,
): Promise<void> {
  requirePublicKeyLen(hostRootPk);
  const rootFp = await rootFpOf(hostRootPk);
  if (!bytesEqual(rootFp, expectedRootFp)) throw ArtifactError.rootFingerprintMismatch();
  await verifySigOrThrow(hostRootPk, HostOpKeyCert.signingInput(cert), cert.sig_host_root, opts?.backend);
  checkExp(now, cert.exp);
}

/** Verifies `sig` under `signerPk` (host op key or identity root — caller resolves which).
 * Revocation records carry **no expiry** (A7b: "none (permanent)") — only the signature is
 * checked here. The max-wins replay rule is a separate concern: see `isNewerEpoch`. */
export async function verifyRevocationRecord(
  rec: RevocationRecord,
  signerPk: Uint8Array,
  opts?: BackendOption,
): Promise<void> {
  requirePublicKeyLen(signerPk);
  await verifySigOrThrow(signerPk, RevocationRecord.signingInput(rec), rec.sig, opts?.backend);
}

/** A7b's max-wins replay rule for revocation records: a candidate epoch only takes effect if it is
 * strictly greater than the current high-water mark. Never decreases, never rolls back. */
export function isNewerEpoch(candidateEpoch: bigint, currentMaxEpoch: bigint): boolean {
  return candidateEpoch > currentMaxEpoch;
}

/** Verifies `sig_operator` and `exp` (A7b: `exp` days-scale, encoded as an absolute Unix-seconds
 * timestamp on the wire). Nonce-burn replay enforcement is durable helper-side state (CAS), not
 * this package's concern. */
export async function verifyAdmissionToken(
  tok: AdmissionToken,
  operatorPk: Uint8Array,
  now: bigint,
  opts?: BackendOption,
): Promise<void> {
  requirePublicKeyLen(operatorPk);
  await verifySigOrThrow(operatorPk, AdmissionToken.signingInput(tok), tok.sig_operator, opts?.backend);
  checkExp(now, tok.exp);
}

/** Verifies `sig` and `|ts - now| <= 2 min` (A7b). Per-signer monotonic `seq` plus nonce replay
 * tracking is durable caller-owned state (helper/host audit chain), not this package's concern. */
export async function verifyAdminCommand(
  command: AdminCommand,
  operatorPk: Uint8Array,
  now: bigint,
  opts?: BackendOption,
): Promise<void> {
  requirePublicKeyLen(operatorPk);
  await verifySigOrThrow(operatorPk, AdminCommand.signingInput(command), command.sig, opts?.backend);
  checkSkew(now, command.ts, ADMIN_COMMAND_CLOCK_SKEW_SECS);
}
