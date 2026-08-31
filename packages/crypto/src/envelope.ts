// The A7 end-to-end signaling envelope (DESIGN.md §A7, ADR-004): the two-key signaling schedule
// (DESIGN.md §A7 "Key schedule", amended v0.9.14), `seal`/`open`, and every receiver MUST-check —
// the TypeScript twin of `crates/spindle-core/src/envelope.rs`.
//
// ```text
// Envelope { v, alg_id, from_fp, to_fp, sid, kind, seq, ts, eph_pk?, ciphertext, sig }
// Key schedule: two keys per session — the offer is the first message and the client has no
// peer ephemeral yet.
//   k0 (offer only)  = HKDF-SHA256(X25519(eph_c, dev_agree_h) || X25519(dev_agree_c, dev_agree_h),
//                                  info = "spindle-sess-boot-v1" || sid || from_fp || to_fp)
//   k1 (all others)  = HKDF-SHA256(X25519(eph_self, eph_peer) || X25519(dev_self, dev_agree_peer),
//                                  info = "spindle-sess-v1" || sid || from_fp || to_fp)
// AEAD:         AES-256-GCM, nonce = direction(1) || seq(11); AAD = canonical header
// sig:          Ed25519(dev_sign_from, "spindle-env-v1" || canonical(header) || ciphertext)
// ```
//
// **Two-key rationale**: the connect offer is sealed under `k0` because the client cannot know
// the host's ephemeral public key before the host replies — `k0`'s first DH term binds the
// client's ephemeral to the host's *static* agreement key instead of the host's ephemeral. From
// the host's answer onward, both directions use `k1`, a full ephemeral-ephemeral hybrid. The two
// `info` labels (`BOOT_KEY_INFO_DOMAIN` / `SESSION_KEY_INFO_DOMAIN`) are the *only* difference
// between `deriveBootstrapKey` and `deriveSessionKey` and are mandatory domain separation:
// without them the two keys would collapse onto the same derivation for the same `(sid, fromFp,
// toFp)`. A receiver decrypts `kind = offer` under `k0` and every other `kind` under `k1` — never
// both.
//
// **Session-role convention** (documented in `envelope.rs`'s module docs, reproduced here
// verbatim since it is the load-bearing interpretation this module follows): the `fromFp`/`toFp`
// fed into the session-key `info` are the *session's* fixed roles (conventionally the connecting
// client's `device_fp` as `fromFp`, the host's as `toFp`), established once when the session is
// created — **not** the per-message `Envelope.from_fp`/`Envelope.to_fp` fields, which flip
// depending on which side is currently sending. Both peers must call `deriveSessionKey` with the
// *same* `(fromFp, toFp)` pair regardless of which of them is sealing or opening a given message.

import { Envelope, type Envelope as EnvelopeType } from "@spindle/proto";

import { type BackendOption, ed25519Sign, ed25519Verify } from "./backend.js";
import { aesGcmOpen, aesGcmSeal, hkdfSha256 } from "./primitives.js";

/** KDF `info` domain prefix (DESIGN.md §A7). */
export const SESSION_KEY_INFO_DOMAIN = new TextEncoder().encode("spindle-sess-v1");

/** KDF `info` domain for `k0`, the offer-only bootstrap key (DESIGN.md §A7, amended v0.9.14). See
 * `deriveBootstrapKey`. */
export const BOOT_KEY_INFO_DOMAIN = new TextEncoder().encode("spindle-sess-boot-v1");

/** `|ts - now| <= 2 min` (DESIGN.md §A7b). */
export const CLOCK_SKEW_SECS = 120n;

/**
 * The 32-byte AES-256-GCM session key derived per A7. A plain `Uint8Array` — unlike
 * `spindle-core`'s `SessionKey`, JavaScript has no reliable way to zeroize memory on drop, so this
 * package makes no such claim; callers who need that guarantee must hold session keys in
 * non-extractable WebCrypto `CryptoKey`s themselves (out of scope here, since every artifact/
 * envelope signing input in this package needs raw bytes to hash/sign/encrypt).
 */
export type SessionKey = Uint8Array;

// Shared HKDF-SHA256 derivation body for both `deriveSessionKey` and `deriveBootstrapKey` — the
// two functions differ *only* in which `info` domain they pass here. Deliberately factored into
// one implementation: two independent copies of this body could drift, and a drift that silently
// made the two domains equal would destroy the domain separation DESIGN.md §A7 (v0.9.14) depends
// on to keep `k0`/`k1` distinct.
async function deriveKey(
  domain: Uint8Array,
  ephDh: Uint8Array,
  devDh: Uint8Array,
  sid: Uint8Array,
  fromFp: Uint8Array,
  toFp: Uint8Array,
): Promise<SessionKey> {
  const ikm = new Uint8Array(ephDh.length + devDh.length);
  ikm.set(ephDh, 0);
  ikm.set(devDh, ephDh.length);

  const info = new Uint8Array(domain.length + sid.length + fromFp.length + toFp.length);
  let offset = 0;
  info.set(domain, offset);
  offset += domain.length;
  info.set(sid, offset);
  offset += sid.length;
  info.set(fromFp, offset);
  offset += fromFp.length;
  info.set(toFp, offset);

  return hkdfSha256(ikm, info, 32);
}

/** `k1 = HKDF-SHA256(eph_dh || dev_dh, info = "spindle-sess-v1" || sid || from_fp || to_fp)`
 * (DESIGN.md §A7, amended v0.9.14): the key used for the host's answer and every message after
 * it, in both directions. `ephDh`/`devDh` are the two X25519 shared secrets (ephemeral-ephemeral
 * and device-device); see the module docs for the `fromFp`/`toFp` session-role convention, and
 * `deriveBootstrapKey` for `k0`, the offer-only sibling of this function. */
export async function deriveSessionKey(
  ephDh: Uint8Array,
  devDh: Uint8Array,
  sid: Uint8Array,
  fromFp: Uint8Array,
  toFp: Uint8Array,
): Promise<SessionKey> {
  return deriveKey(SESSION_KEY_INFO_DOMAIN, ephDh, devDh, sid, fromFp, toFp);
}

/** `k0 = HKDF-SHA256(eph_dh || dev_dh, info = "spindle-sess-boot-v1" || sid || from_fp || to_fp)`
 * (DESIGN.md §A7, amended v0.9.14): the key used to seal the connect offer only. The client
 * cannot know the host's ephemeral public key before the host replies, so the caller is expected
 * to pass an ephemeral-static X25519 shared secret as `ephDh` here (not the ephemeral-ephemeral
 * secret `deriveSessionKey` expects) — this function does no X25519 of its own, it only differs
 * from `deriveSessionKey` in the `info` domain (mandatory domain separation; see `deriveKey`'s
 * comment for why that must never drift). */
export async function deriveBootstrapKey(
  ephDh: Uint8Array,
  devDh: Uint8Array,
  sid: Uint8Array,
  fromFp: Uint8Array,
  toFp: Uint8Array,
): Promise<SessionKey> {
  return deriveKey(BOOT_KEY_INFO_DOMAIN, ephDh, devDh, sid, fromFp, toFp);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/** `direction(1) || seq(11)` nonce construction (DESIGN.md §A7). `direction` is derived from the
 * ordered `(fromFp, toFp)` pair of the *envelope being sealed/opened* so both peers compute the
 * same value for a given message, and the two directions of one session always occupy disjoint
 * nonce spaces. */
export function directionByte(fromFp: Uint8Array, toFp: Uint8Array): number {
  return compareBytes(fromFp, toFp) < 0 ? 0 : 1;
}

function buildNonce(direction: number, seq: bigint): Uint8Array {
  const nonce = new Uint8Array(12);
  nonce[0] = direction;
  let s = seq;
  for (let i = 11; i >= 4; i--) {
    nonce[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return nonce;
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

/** Every distinct failure `open` can produce (DESIGN.md §A7). Each `kind` corresponds to exactly
 * one MUST-check, mirroring `spindle-core`'s `EnvelopeError` enum, so a negative test can isolate
 * it. */
export type EnvelopeErrorKind =
  | "BadSignature"
  | "VersionTooLow"
  | "AlgIdTooLow"
  | "WrongRecipient"
  | "SenderRevoked"
  | "SidMismatch"
  | "SidBoundToDifferentSender"
  | "ReplaySeq"
  | "ClockSkew"
  | "KindMismatch"
  | "DecryptFailed"
  | "InvalidSignatureEncoding"
  | "InvalidFingerprint";

export class EnvelopeError extends Error {
  readonly kind: EnvelopeErrorKind;
  /** Set for `VersionTooLow`/`AlgIdTooLow`. */
  readonly actual?: number;
  readonly minimum?: number;

  private constructor(kind: EnvelopeErrorKind, message: string, extra?: { actual?: number; minimum?: number }) {
    super(message);
    this.name = "EnvelopeError";
    this.kind = kind;
    this.actual = extra?.actual;
    this.minimum = extra?.minimum;
  }

  static badSignature(): EnvelopeError {
    return new EnvelopeError("BadSignature", "signature invalid under the pinned key for from_fp");
  }
  static versionTooLow(actual: number, minimum: number): EnvelopeError {
    return new EnvelopeError(
      "VersionTooLow",
      `envelope version ${actual} is below the pinned minimum ${minimum}`,
      { actual, minimum },
    );
  }
  static algIdTooLow(actual: number, minimum: number): EnvelopeError {
    return new EnvelopeError(
      "AlgIdTooLow",
      `envelope alg_id ${actual} is below the pinned minimum ${minimum}`,
      { actual, minimum },
    );
  }
  static wrongRecipient(): EnvelopeError {
    return new EnvelopeError("WrongRecipient", "to_fp does not match this device (self)");
  }
  static senderRevoked(): EnvelopeError {
    return new EnvelopeError("SenderRevoked", "sender is not active / has been revoked");
  }
  static sidMismatch(): EnvelopeError {
    return new EnvelopeError("SidMismatch", "sid does not match the session this envelope was opened against");
  }
  static sidBoundToDifferentSender(): EnvelopeError {
    return new EnvelopeError(
      "SidBoundToDifferentSender",
      "sid is bound to a different from_fp than this envelope carries",
    );
  }
  static replaySeq(): EnvelopeError {
    return new EnvelopeError("ReplaySeq", "seq is not strictly increasing for (sid, direction)");
  }
  static clockSkew(): EnvelopeError {
    return new EnvelopeError("ClockSkew", "|ts - now| exceeds the allowed clock-skew window");
  }
  static kindMismatch(): EnvelopeError {
    return new EnvelopeError("KindMismatch", "kind does not match the expected subject");
  }
  static decryptFailed(): EnvelopeError {
    return new EnvelopeError("DecryptFailed", "AEAD decryption failed");
  }
  static invalidSignatureEncoding(): EnvelopeError {
    return new EnvelopeError("InvalidSignatureEncoding", "malformed signature encoding (expected 64 bytes)");
  }
  static invalidFingerprint(): EnvelopeError {
    return new EnvelopeError("InvalidFingerprint", "malformed fingerprint encoding in envelope field");
  }
}

/** Inputs to `seal`. */
export interface SealParams extends BackendOption {
  sessionKey: SessionKey;
  /** The sender's device Ed25519 signing seed — signs the envelope (`dev_sign_from` in
   * DESIGN.md §A7). */
  signSeed: Uint8Array;
  v: number;
  algId: number;
  fromFp: Uint8Array;
  toFp: Uint8Array;
  sid: Uint8Array;
  kind: number;
  seq: bigint;
  ts: bigint;
  ephPk?: Uint8Array;
  plaintext: Uint8Array;
}

/** Seals `plaintext` into a complete, signed `@spindle/proto` `Envelope` (DESIGN.md §A7): encrypts
 * under AES-256-GCM with AAD = canonical header, then signs
 * `"spindle-env-v1" || canonical(header) || ciphertext` with the sender's device key. */
export async function seal(params: SealParams): Promise<EnvelopeType> {
  const direction = directionByte(params.fromFp, params.toFp);
  const nonce = buildNonce(direction, params.seq);

  // Header fields never depend on `ciphertext`/`sig`, so `headerCanonicalBytes` below is correct
  // even though `ciphertext` is still an empty placeholder at this point.
  const env: EnvelopeType = {
    v: params.v,
    alg_id: params.algId,
    from_fp: params.fromFp,
    to_fp: params.toFp,
    sid: params.sid,
    kind: params.kind,
    seq: params.seq,
    ts: params.ts,
    eph_pk: params.ephPk,
    ciphertext: new Uint8Array(0),
    sig: new Uint8Array(0),
  };
  const aad = Envelope.headerCanonicalBytes(env);

  env.ciphertext = await aesGcmSeal(params.sessionKey, nonce, aad, params.plaintext);
  env.sig = await ed25519Sign(params.signSeed, Envelope.signingInput(env), { backend: params.backend });
  return env;
}

/** Inputs to `open`. Every field corresponds to one of A7's receiver MUST-checks; callers own the
 * durable state a real deployment needs (pinned keys, revocation sets, per-`(sid, direction)`
 * replay windows) and resolve it into these plain values before calling. */
export interface OpenParams extends BackendOption {
  sessionKey: SessionKey;
  /** The pinned public key for `from_fp` (or, for an invite redemption, the key carried in the
   * device certificate chained to a root — DESIGN.md §A7). Resolved by the caller. */
  pinnedSenderKey: Uint8Array;
  selfFp: Uint8Array;
  /** The sid this envelope is expected to belong to. */
  expectedSid: Uint8Array;
  /** Set once this sid has been bound to a sender on a prior envelope; omitted for the first
   * envelope of a session. */
  boundFromFp?: Uint8Array;
  /** The highest `seq` already accepted for this `(sid, direction)`; the incoming envelope's `seq`
   * must be strictly greater. Omitted for the first envelope of this direction. */
  minSeqExclusive?: bigint;
  now: bigint;
  minV: number;
  minAlgId: number;
  expectedKind: number;
  /** Caller-resolved: true if `from_fp` is revoked / not an active sender. */
  senderRevoked: boolean;
}

/** Verifies every A7 receiver MUST-check and, only if all pass, decrypts and returns the
 * plaintext. Any single failure is reported as a distinct `EnvelopeError` and the envelope must be
 * dropped (never given a distinguishable reply — DESIGN.md §A5/§A7). */
export async function open(params: OpenParams, env: EnvelopeType): Promise<Uint8Array> {
  if (env.v < params.minV) throw EnvelopeError.versionTooLow(env.v, params.minV);
  if (env.alg_id < params.minAlgId) throw EnvelopeError.algIdTooLow(env.alg_id, params.minAlgId);

  if (env.sig.length !== 64) throw EnvelopeError.invalidSignatureEncoding();
  const sigValid = await ed25519Verify(params.pinnedSenderKey, Envelope.signingInput(env), env.sig, {
    backend: params.backend,
  });
  if (!sigValid) throw EnvelopeError.badSignature();

  if (!bytesEqual(params.selfFp, env.to_fp)) throw EnvelopeError.wrongRecipient();
  if (params.senderRevoked) throw EnvelopeError.senderRevoked();
  if (!bytesEqual(env.sid, params.expectedSid)) throw EnvelopeError.sidMismatch();
  if (params.boundFromFp !== undefined && !bytesEqual(params.boundFromFp, env.from_fp)) {
    throw EnvelopeError.sidBoundToDifferentSender();
  }
  if (params.minSeqExclusive !== undefined && env.seq <= params.minSeqExclusive) {
    throw EnvelopeError.replaySeq();
  }
  if (absDiff(params.now, env.ts) > CLOCK_SKEW_SECS) throw EnvelopeError.clockSkew();
  if (env.kind !== params.expectedKind) throw EnvelopeError.kindMismatch();

  if (env.from_fp.length !== 32 || env.to_fp.length !== 32) throw EnvelopeError.invalidFingerprint();
  const direction = directionByte(env.from_fp, env.to_fp);
  const nonce = buildNonce(direction, env.seq);
  const aad = Envelope.headerCanonicalBytes(env);

  try {
    return await aesGcmOpen(params.sessionKey, nonce, aad, env.ciphertext);
  } catch {
    throw EnvelopeError.decryptFailed();
  }
}
