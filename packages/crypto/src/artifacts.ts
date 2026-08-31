// Verify functions for the A7b signed-artifact catalog, excluding `Envelope` (which has its own
// session/AEAD machinery — see `envelope.ts`). Each function takes a `@spindle/proto` wire struct,
// computes its `signingInput()` (already carrying the correct A7b domain tag — see
// `@spindle/proto`'s `tags` module), and verifies it with the correct key for that artifact kind
// per DESIGN.md §A7b. The TypeScript twin of `crates/spindle-core/src/artifacts/*.rs`.
//
// | Artifact | Signer |
// |---|---|
// | DeviceCertificate | identity root |
// | Capability | host operating key, certified by an embedded op_cert chained to host_root_pk (A10.30) |
// | HostDeviceCert | host operating key, certified by an embedded op_cert chained to host_root_pk (A10.35) |
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
  HostDeviceCert,
  HostOpKeyCert,
  RevocationRecord,
} from "@spindle/proto";

import { type BackendOption, ed25519Verify } from "./backend.js";
import { deviceFpOf, rootFpOf } from "./fingerprint.js";

/** The `alg_id` suite version byte (DESIGN.md §A4): `1` = Ed25519 / X25519 / AES-256-GCM. Mirrors
 * `spindle-core::identity::ALG_ID_V1`. */
const ALG_ID_V1 = 1;

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
  | "RootFingerprintMismatch"
  | "MalformedOpCert"
  | "DeviceFingerprintMismatch"
  | "UnsupportedAlgId";

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
      "host_fp does not match SHA-256(host_root_pk) — capability is not self-verifying",
    );
  }
  static rootFingerprintMismatch(): ArtifactError {
    return new ArtifactError("RootFingerprintMismatch", "root_fp does not match the expected pinned root");
  }
  static malformedOpCert(): ArtifactError {
    return new ArtifactError(
      "MalformedOpCert",
      "capability's embedded op_cert does not decode as a valid HostOpKeyCert",
    );
  }
  static deviceFingerprintMismatch(): ArtifactError {
    return new ArtifactError(
      "DeviceFingerprintMismatch",
      "device_fp does not match SHA-256(alg_id || sign_pk || agree_pk) — certificate is not self-verifying",
    );
  }
  static unsupportedAlgId(): ArtifactError {
    return new ArtifactError("UnsupportedAlgId", "alg_id is not a supported suite version");
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

/** Verifies a device certificate: `alg_id` is supported, `sign_pk`/`agree_pk` are the right
 * length, the certificate's own `device_fp` matches the recomputed fingerprint of its
 * `(alg_id, sign_pk, agree_pk)` (§A7b clarification 6 — the binding this v0.9.16 change exists to
 * enforce), it chains to `expectedRootFp` under `rootPk`, `sig_root` is valid, and `now` is within
 * `exp` (A7b time rule: `exp` 1 y, re-signed on contact; replay rule: n/a, revocable).
 *
 * Checks run cheap-structural-before-crypto (§A6): `alg_id` first (nothing else can even be
 * interpreted if it's wrong), then key-length checks, then the `device_fp` binding recompute, and
 * only then the root-fingerprint/signature/`exp` checks. */
export async function verifyDeviceCertificate(
  cert: DeviceCertificate,
  rootPk: Uint8Array,
  expectedRootFp: Uint8Array,
  now: bigint,
  opts?: BackendOption,
): Promise<void> {
  if (cert.alg_id !== ALG_ID_V1) throw ArtifactError.unsupportedAlgId();
  requirePublicKeyLen(cert.sign_pk);
  requirePublicKeyLen(cert.agree_pk);

  const recomputedDeviceFp = await deviceFpOf(cert.alg_id, cert.sign_pk, cert.agree_pk);
  if (!bytesEqual(recomputedDeviceFp, cert.device_fp)) throw ArtifactError.deviceFingerprintMismatch();

  requirePublicKeyLen(rootPk);
  const rootFp = await rootFpOf(rootPk);
  if (!bytesEqual(rootFp, expectedRootFp)) throw ArtifactError.rootFingerprintMismatch();
  await verifySigOrThrow(rootPk, DeviceCertificate.signingInput(cert), cert.sig_root, opts?.backend);
  checkExp(now, cert.exp);
}

/** Verifies a capability's full root -> operating-key -> capability chain (DESIGN.md §A4,
 * decision A10.30): no external root or registry lookup needed beyond the capability's own
 * embedded fields.
 *
 * 1. `host_fp == SHA-256(host_root_pk)` — the capability's declared root identity is
 *    self-consistent with its own `host_fp`.
 * 2. The embedded `op_cert` decodes as a `HostOpKeyCert` and verifies under `host_root_pk` (via
 *    `verifyHostOpKeyCert`, which also checks the op cert's own `exp` against `now`).
 * 3. `sig` verifies under the op cert's `host_op_pk` — i.e. the capability was actually signed by
 *    the operating key the root certified, not merely by *some* key.
 *
 * Each step's failure surfaces its own `ArtifactError` variant (steps 2/3 reuse
 * `verifyHostOpKeyCert`'s own variants for its half of the chain).
 */
export async function verifyCapability(cap: Capability, now: bigint, opts?: BackendOption): Promise<void> {
  // 1. host_fp == SHA-256(host_root_pk) — self-consistency of the capability's own fields.
  requirePublicKeyLen(cap.host_root_pk);
  const expectedFp = await rootFpOf(cap.host_root_pk);
  if (!bytesEqual(expectedFp, cap.host_fp)) throw ArtifactError.hostFingerprintMismatch();

  // 2. Decode + verify the embedded op cert chains to host_root_pk, including its own `exp`.
  let opCert: HostOpKeyCert;
  try {
    opCert = HostOpKeyCert.fromCanonicalBytes(cap.op_cert);
  } catch {
    throw ArtifactError.malformedOpCert();
  }
  await verifyHostOpKeyCert(opCert, cap.host_root_pk, cap.host_fp, now, opts);

  // 3. `sig` verifies under the op cert's own operating key.
  requirePublicKeyLen(opCert.host_op_pk);
  await verifySigOrThrow(opCert.host_op_pk, Capability.signingInput(cap), cap.sig, opts?.backend);

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

/** Verifies a host device certificate's full root -> operating-key -> device chain (DESIGN.md
 * §A4, decision A10.35): self-verifying exactly like `verifyCapability` (decision A10.30) — no
 * external root or registry lookup needed beyond the certificate's own embedded fields.
 *
 * **Deliberately stricter than `verifyCapability`**: `expectedHostFp` is a **required** parameter
 * here, not left to the caller to check separately. A client fetches this certificate from the
 * helper (`helper.devcert.get.<nfp>`) specifically to learn the host's envelope identity, and it
 * already pinned `host_fp` at enrollment — making the pin check a required argument means a
 * caller cannot forget to verify the certificate actually names the host it thinks it is talking
 * to. `verifyCapability` has no equivalent parameter because a capability's `host_fp` typically
 * *is* the value the caller is trying to look up, not a value it already holds and must
 * cross-check.
 *
 * Checks run cheap-structural-before-crypto (§A6), in this order:
 * 1. `alg_id` is a supported suite.
 * 2. `sign_pk` parses as Ed25519; `agree_pk` is exactly 32 bytes.
 * 3. `host_device_fp` recomputed from `(alg_id, sign_pk, agree_pk)` matches the certificate's own
 *    field (§A7b clarification 6's binding discipline, mirrored from `DeviceCertificate`/A10.34).
 * 4. `host_fp` matches the caller's pinned `expectedHostFp`.
 * 5. `host_fp == SHA-256(host_root_pk)` — self-consistency of the certificate's own fields (the
 *    same check `verifyCapability`'s step 1 performs).
 * 6. The embedded `op_cert` decodes as a `HostOpKeyCert` and chains to `host_root_pk` (including
 *    its own `exp`), via `verifyHostOpKeyCert`.
 * 7. `sig_host_op` verifies under the op cert's own certified operating key.
 * 8. `now` is within `exp`. */
export async function verifyHostDeviceCert(
  cert: HostDeviceCert,
  expectedHostFp: Uint8Array,
  now: bigint,
  opts?: BackendOption,
): Promise<void> {
  // 1. alg_id supported.
  if (cert.alg_id !== ALG_ID_V1) throw ArtifactError.unsupportedAlgId();

  // 2. sign_pk / agree_pk parse (length check).
  requirePublicKeyLen(cert.sign_pk);
  requirePublicKeyLen(cert.agree_pk);

  // 3. host_device_fp binding — recompute from the certificate's own preimage.
  const recomputedDeviceFp = await deviceFpOf(cert.alg_id, cert.sign_pk, cert.agree_pk);
  if (!bytesEqual(recomputedDeviceFp, cert.host_device_fp)) throw ArtifactError.deviceFingerprintMismatch();

  // 4. host_fp matches the caller's pinned expectation (required parameter — see doc comment).
  if (!bytesEqual(expectedHostFp, cert.host_fp)) throw ArtifactError.hostFingerprintMismatch();

  // 5. host_fp is self-consistent with the embedded host_root_pk.
  requirePublicKeyLen(cert.host_root_pk);
  const recomputedHostFp = await rootFpOf(cert.host_root_pk);
  if (!bytesEqual(recomputedHostFp, cert.host_fp)) throw ArtifactError.hostFingerprintMismatch();

  // 6. Decode + verify the embedded op cert chains to host_root_pk, including its own `exp`.
  let opCert: HostOpKeyCert;
  try {
    opCert = HostOpKeyCert.fromCanonicalBytes(cert.op_cert);
  } catch {
    throw ArtifactError.malformedOpCert();
  }
  await verifyHostOpKeyCert(opCert, cert.host_root_pk, cert.host_fp, now, opts);

  // 7. sig_host_op verifies under the op cert's own certified operating key.
  requirePublicKeyLen(opCert.host_op_pk);
  await verifySigOrThrow(opCert.host_op_pk, HostDeviceCert.signingInput(cert), cert.sig_host_op, opts?.backend);

  // 8. exp check.
  checkExp(now, cert.exp);
}
