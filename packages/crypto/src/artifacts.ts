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
// | AdminCommand | operator admission key (`verifyAdminCommand` also takes the operator identity it binds to — `expectedSignerFp` — as a required argument, td-0bcab4) |
// | SessionAttestation | device identity key (`verifySessionAttestation` likewise takes the value it binds — the connecting session's `nats_fp` — as a required argument rather than checking only a signature, td-0bcab4) |
//
// This module never reads a system clock: every time check takes a caller-supplied `now: bigint`
// (Unix seconds), consistent with DESIGN.md §A7 ("clients compute an offset" from helper server
// time).

import {
  ADMIN_COMMAND_MIN_V,
  AdminCommand,
  AdmissionToken,
  CAPABILITY_MIN_V,
  Capability,
  DeviceCertificate,
  HostDeviceCert,
  HostOpKeyCert,
  RevocationRecord,
  SessionAttestation,
} from "@spindle/proto";

import { ed25519 } from "@noble/curves/ed25519.js";

import { type BackendOption, ed25519Verify } from "./backend.js";
import { deviceFpOf, FINGERPRINT_LEN, rootFpOf } from "./fingerprint.js";

/** The `alg_id` suite version byte (DESIGN.md §A4): `1` = Ed25519 / X25519 / AES-256-GCM. Mirrors
 * `spindle-core::identity::ALG_ID_V1`. */
const ALG_ID_V1 = 1;

/** `|ts - now| <= 2 min` (DESIGN.md §A7b), same window as the envelope's clock-skew rule. */
export const ADMIN_COMMAND_CLOCK_SKEW_SECS = 120n;

/** A7b time rule for `SessionAttestation`: `ts` ±2 min against helper server time. */
export const SESSION_ATTESTATION_CLOCK_SKEW_SECS = 120n;

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
  | "UnsupportedAlgId"
  | "VersionTooLow"
  | "SessionKeyMismatch"
  | "SignerFingerprintMismatch";

export class ArtifactError extends Error {
  readonly kind: ArtifactErrorKind;
  /** Set for `VersionTooLow`. */
  readonly found?: number;
  readonly minimum?: number;

  private constructor(
    kind: ArtifactErrorKind,
    message: string,
    extra?: { found?: number; minimum?: number },
  ) {
    super(message);
    this.name = "ArtifactError";
    this.kind = kind;
    this.found = extra?.found;
    this.minimum = extra?.minimum;
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
  static versionTooLow(found: number, minimum: number): ArtifactError {
    return new ArtifactError(
      "VersionTooLow",
      `artifact version ${found} is below the minimum ${minimum}`,
      { found, minimum },
    );
  }
  static sessionKeyMismatch(): ArtifactError {
    return new ArtifactError(
      "SessionKeyMismatch",
      "session attestation does not name the connecting session key",
    );
  }
  static signerFingerprintMismatch(): ArtifactError {
    return new ArtifactError(
      "SignerFingerprintMismatch",
      "signer_fp does not match the expected admin command signer",
    );
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** True if `expected` and `actual` are both exactly `FINGERPRINT_LEN` (32) bytes AND equal.
 *
 * A fingerprint *binding* check (one artifact's identity field compared against a value the
 * caller already holds, e.g. `SessionAttestation.nats_fp` vs the connecting session key, or
 * `AdminCommand.signer_fp` vs the operator identity the caller expects) must not delegate straight
 * to `bytesEqual`: `bytesEqual([], [])` is vacuously `true`, so an attestation carrying an
 * empty/omitted binding field, checked by a caller that (by bug or omission) also supplies an
 * empty expected value, would "verify" a binding that was never actually compared. Rust gets this
 * for free — `expected_*_fp: &Fingerprint` is a newtype that can only ever hold exactly 32 bytes,
 * so the equivalent Rust comparison can't be fooled by a length-zero value on either side. This
 * function is the TS twin of that guarantee: it rejects any non-32-byte input on either side
 * before ever reaching `bytesEqual`. */
function fingerprintsMatch(expected: Uint8Array, actual: Uint8Array): boolean {
  return (
    expected.length === FINGERPRINT_LEN &&
    actual.length === FINGERPRINT_LEN &&
    bytesEqual(expected, actual)
  );
}

function absDiff(a: bigint, b: bigint): bigint {
  return a > b ? a - b : b - a;
}

/** The version-floor check shared by `verifyCapability` and `verifyAdminCommand` — deliberately
 * the very first check either function runs (cheapest possible rejection, before any signature or
 * expiry work). Mirrors `spindle-core`'s `check_min_v`. */
function checkMinV(found: number, minimum: number): void {
  if (found < minimum) throw ArtifactError.versionTooLow(found, minimum);
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

/** Validates a 32-byte Ed25519 public key: length, AND that it decodes as a canonically-encoded,
 * valid curve point (RFC 8032 §5.1.3). `ed25519.Point.fromBytes` called with no explicit `zip215`
 * argument defaults to the strict RFC-8032 decode (`zip215 = false`) and throws on a non-canonical
 * encoding (e.g. `y >= p`) or a byte string that is not a valid point at all.
 *
 * td-b8c68a: this closes a measured Rust/TS divergence. Bare `ed25519_dalek::VerifyingKey::from_bytes`
 * only performs the point-decompression half of this check — it never rejects a non-canonical `y`
 * — so the Rust side gained its own equivalent gate, `spindle_core::checked_verifying_key`, this
 * function's Rust-side twin. Both now reject exactly the same set of encodings.
 *
 * Exported (unlike this file's other `require*` helpers) so `test/key-validity.test.ts` can drive
 * `vectors/key-validity.json`'s cases against the real production check directly, the same way the
 * Rust twin's test calls the exported `checked_verifying_key` rather than reimplementing its logic
 * against the raw `ed25519.Point.fromBytes` primitive. */
export function requireEd25519PublicKey(pk: Uint8Array): void {
  if (pk.length !== 32) throw ArtifactError.invalidPublicKey();
  try {
    ed25519.Point.fromBytes(pk);
  } catch {
    throw ArtifactError.invalidPublicKey();
  }
}

/** Validates an X25519 public key: length ONLY — deliberately, not a point-validity check.
 *
 * `x25519_dalek::PublicKey::from` (the Rust side of this boundary) is infallible by construction:
 * every 32-byte string is accepted as a Montgomery u-coordinate candidate, including low-order
 * points. td-b8c68a measured this and confirmed there is no Rust/TS divergence to close here — do
 * NOT "complete" this into a point-validity check on either side; that would create a split where
 * none exists today. See `vectors/key-validity.json`'s X25519 low-order-point case, which pins
 * this deliberate agreement. */
function requireX25519PublicKeyLen(pk: Uint8Array): void {
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
  requireEd25519PublicKey(cert.sign_pk);
  requireX25519PublicKeyLen(cert.agree_pk);

  const recomputedDeviceFp = await deviceFpOf(cert.alg_id, cert.sign_pk, cert.agree_pk);
  if (!bytesEqual(recomputedDeviceFp, cert.device_fp)) throw ArtifactError.deviceFingerprintMismatch();

  requireEd25519PublicKey(rootPk);
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
  // 0. Version floor — cheapest possible rejection, checked before any signature or expiry work
  // (DESIGN.md §A7b: "Unknown `v` ⇒ reject").
  checkMinV(cap.v, CAPABILITY_MIN_V);

  // 1. host_fp == SHA-256(host_root_pk) — self-consistency of the capability's own fields.
  requireEd25519PublicKey(cap.host_root_pk);
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
  requireEd25519PublicKey(opCert.host_op_pk);
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
  requireEd25519PublicKey(hostRootPk);
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
  requireEd25519PublicKey(signerPk);
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
  requireEd25519PublicKey(operatorPk);
  await verifySigOrThrow(operatorPk, AdmissionToken.signingInput(tok), tok.sig_operator, opts?.backend);
  checkExp(now, tok.exp);
}

/** Verifies an admin command: it names `expectedSignerFp`, `sig` is valid under `operatorPk`, and
 * `|ts - now| <= 2 min` (A7b). Per-signer monotonic `seq` plus nonce replay tracking is durable
 * caller-owned state (helper/host audit chain), not this package's concern.
 *
 * **`expectedSignerFp` is a required argument, deliberately and non-negotiably.** This used to be
 * exactly the API shape that produced td-0bcab4: `command.signer_fp` is carried inside the
 * *signed* preimage — a well-signed command has skin in the game about who it claims to be from —
 * but a `verifyAdminCommand(command, operatorPk, now)` that never compared it against anything
 * would let a command bearing a valid signature from *some* key the caller trusted verify
 * regardless of whose `signer_fp` it named. That is the same bearer-token shape
 * `verifySessionAttestation` exists to close for `DeviceCertificate.nats_fp`: a signed binding
 * field that no verifier actually reads. There is no valid caller that wants the signature checked
 * without the binding, so this API does not offer one.
 *
 * Checks run cheap-structural-before-crypto (§A6), in this order:
 * 1. Version floor — cheapest possible rejection, checked before any other work (DESIGN.md §A7b:
 *    "Unknown `v` ⇒ reject").
 * 2. `expectedSignerFp` matches `command.signer_fp` — the check this function exists to enforce.
 *    Both sides must be exactly 32 bytes (`fingerprintsMatch`, not bare `bytesEqual`), for the
 *    same reason `verifySessionAttestation`'s `nats_fp` binding does: `bytesEqual([], [])` is
 *    vacuously `true`, so an unguarded comparison would let a well-signed command naming an empty
 *    `signer_fp` "verify" against a caller that (by bug or omission) also passes an empty
 *    `expectedSignerFp`.
 * 3. `operatorPk` parses as a valid Ed25519 public key, and `sig` verifies over
 *    `AdminCommand.signingInput(command)`.
 * 4. Clock skew (`ts` ±2 min). */
export async function verifyAdminCommand(
  command: AdminCommand,
  operatorPk: Uint8Array,
  expectedSignerFp: Uint8Array,
  now: bigint,
  opts?: BackendOption,
): Promise<void> {
  // 1. Version floor — cheapest possible rejection, checked before any signature, binding, or
  // timestamp work (DESIGN.md §A7b: "Unknown `v` ⇒ reject").
  checkMinV(command.v, ADMIN_COMMAND_MIN_V);

  // 2. signer_fp binding — the check this function exists to enforce (td-0bcab4's API shape).
  // Must run before the signature check: naming the wrong signer is a structural mismatch,
  // cheaper to reject than the crypto below.
  if (!fingerprintsMatch(expectedSignerFp, command.signer_fp)) {
    throw ArtifactError.signerFingerprintMismatch();
  }

  // 3. Signature.
  requireEd25519PublicKey(operatorPk);
  await verifySigOrThrow(operatorPk, AdminCommand.signingInput(command), command.sig, opts?.backend);

  // 4. Clock skew.
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
  requireEd25519PublicKey(cert.sign_pk);
  requireX25519PublicKeyLen(cert.agree_pk);

  // 3. host_device_fp binding — recompute from the certificate's own preimage.
  const recomputedDeviceFp = await deviceFpOf(cert.alg_id, cert.sign_pk, cert.agree_pk);
  if (!bytesEqual(recomputedDeviceFp, cert.host_device_fp)) throw ArtifactError.deviceFingerprintMismatch();

  // 4. host_fp matches the caller's pinned expectation (required parameter — see doc comment).
  if (!bytesEqual(expectedHostFp, cert.host_fp)) throw ArtifactError.hostFingerprintMismatch();

  // 5. host_fp is self-consistent with the embedded host_root_pk.
  requireEd25519PublicKey(cert.host_root_pk);
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
  requireEd25519PublicKey(opCert.host_op_pk);
  await verifySigOrThrow(opCert.host_op_pk, HostDeviceCert.signingInput(cert), cert.sig_host_op, opts?.backend);

  // 8. exp check.
  checkExp(now, cert.exp);
}

/** Verifies a session attestation: `sig_device(nats_fp, ts)` (DESIGN.md §A3, §A4 step 2, §A7b,
 * added v0.9.29) — the per-session binding by which a device's **identity** key authorizes
 * exactly one NATS session nkey. A7b properties: signer = the device identity key (`deviceSignPk`,
 * the same key certified in the device's own `DeviceCertificate.sign_pk`); time rule = `ts`
 * checked ±2 min against the caller-supplied `now` (`SESSION_ATTESTATION_CLOCK_SKEW_SECS`);
 * replay rule = n/a — the artifact is inert without the nkey secret it names, whose possession the
 * callout proves separately via the server-nonce signature. There is no `exp` field on this
 * artifact; the `ts` skew window is its sole time bound.
 *
 * **`expectedNatsFp` is a required argument, deliberately and non-negotiably.** This artifact
 * exists because of td-0bcab4: `DeviceCertificate.nats_fp` was carried on the wire for exactly
 * this purpose — binding a device to one NATS session key — and no verifier in either language
 * ever read it, so the bundle `{root_pk, device_cert, caps}` was a pure bearer token: the device's
 * identity key was never exercised at CONNECT, so anyone holding a copy could connect from any
 * nkey. A `verifySessionAttestation` that resolved for a well-signed attestation naming somebody
 * else's session key would reproduce that defect exactly, one artifact later — a verify function
 * that takes the artifact but not the value it is supposed to be bound to is exactly how this bug
 * happened. There is no valid caller that wants the signature checked without the binding, so this
 * API does not offer one.
 *
 * Checks run cheap-structural-before-crypto (§A6), in this order:
 * 1. `expectedNatsFp` matches `attestation.nats_fp` — the binding check td-0bcab4 exists for, run
 *    first because it is both the cheapest possible rejection and the one this function exists to
 *    enforce. Both sides must be exactly 32 bytes (`fingerprintsMatch`, not bare `bytesEqual`):
 *    `bytesEqual([], [])` is vacuously `true`, so an unguarded comparison would let a well-signed
 *    attestation naming an empty `nats_fp` "verify" against a caller that (by bug or omission)
 *    also passes an empty `expectedNatsFp` — the binding check running and passing having bound
 *    nothing. Rust's `expected_nats_fp: &Fingerprint` gets this for free from the `Fingerprint`
 *    newtype (always exactly 32 bytes); this length check is what gives the TS twin the same
 *    guarantee.
 * 2. Clock skew: `|now - attestation.ts| <= 2 min`, via the same `checkSkew` idiom
 *    `verifyAdminCommand` uses (its internal `absDiff` orders the subtraction to avoid
 *    underflow-wrap on the unsigned `now`/`ts` wire values).
 * 3. `deviceSignPk` parses as a valid Ed25519 public key, and `sig_device` verifies over
 *    `SessionAttestation.signingInput(attestation)`. */
export async function verifySessionAttestation(
  attestation: SessionAttestation,
  deviceSignPk: Uint8Array,
  expectedNatsFp: Uint8Array,
  now: bigint,
  opts?: BackendOption,
): Promise<void> {
  // 1. nats_fp binding — the check this artifact exists for (td-0bcab4). Must run before any
  // crypto work, per §A6, and before the skew check too: naming the wrong session key is a
  // structural mismatch, cheaper to reject than either the timestamp or the signature.
  if (!fingerprintsMatch(expectedNatsFp, attestation.nats_fp)) throw ArtifactError.sessionKeyMismatch();

  // 2. Clock skew.
  checkSkew(now, attestation.ts, SESSION_ATTESTATION_CLOCK_SKEW_SECS);

  // 3. Signature, under the device's own identity key.
  requireEd25519PublicKey(deviceSignPk);
  await verifySigOrThrow(
    deviceSignPk,
    SessionAttestation.signingInput(attestation),
    attestation.sig_device,
    opts?.backend,
  );
}
