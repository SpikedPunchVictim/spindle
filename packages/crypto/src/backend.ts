// Dual-backend Ed25519/X25519: WebCrypto (Node 22's `globalThis.crypto.subtle`, and modern
// browsers — Firefox 129+, Safari 17+, Chrome 137+ per DESIGN.md §A7) as the primary
// implementation, `@noble/curves` as the fallback for runtimes lacking native support. This
// module owns only the two asymmetric primitives' backend split; HKDF-SHA256, AES-256-GCM, and
// SHA-256 are WebCrypto-only everywhere (DESIGN.md §A7: "AES-GCM/HKDF native") — those three are
// universally supported wherever `crypto.subtle` exists at all, unlike Ed25519/X25519, so there is
// no second implementation to select between and no dependency needed to provide one (`@noble/curves`
// is curve-only; it has no AEAD/HKDF/hash exports of its own).
//
// WebCrypto's Ed25519/X25519 `importKey` only accepts private keys as `pkcs8` or `jwk` — never
// `raw` (see the WICG Secure Curves spec) — but every seed in this codebase (identity roots,
// device keys, ephemeral session keys) is a raw 32-byte value, matching `ed25519-dalek`'s and
// `x25519-dalek`'s "the seed *is* the private key" convention. `wrapPkcs8` below prepends the
// fixed 16-byte PKCS8 DER prefix for each curve (SEQUENCE/INTEGER 0/AlgorithmIdentifier/OCTET
// STRING wrapper around the 32-byte key) so a raw seed can be imported directly. Deriving the
// public key for a given seed reuses the same trick in reverse: import the seed as an extractable
// private key, then export it as JWK — the JWK's `x` field is the public key the platform computed
// during import, letting us read it back out without a dedicated "public key of this scalar" API
// (WebCrypto has none). This construction was verified byte-identical to `spindle-core`'s
// `ed25519-dalek`/`x25519-dalek` output against `vectors/signed/envelope.json`'s real key material.

import { ed25519, x25519 } from "@noble/curves/ed25519.js";

import { asBufferSource } from "./bytes.js";

/** Which concrete implementation performed an Ed25519/X25519 operation. `"webcrypto"` is tried
 * first by default; `"noble"` is the fallback. Tests may pass either explicitly to force that
 * exact implementation (no fallback), e.g. to prove backend parity or to skip a WebCrypto-only
 * check on a runtime that lacks it. */
export type AsymmetricBackend = "webcrypto" | "noble";

/** Per-call backend override. Omitted (or `undefined`) means "try WebCrypto, fall back to
 * `@noble/curves` if WebCrypto throws (unsupported algorithm)" — the production default. */
export interface BackendOption {
  backend?: AsymmetricBackend;
}

function hasSubtleCrypto(): boolean {
  return typeof globalThis.crypto?.subtle?.importKey === "function";
}

// ---- PKCS8 wrapping (see module docs) ----

// `SEQUENCE { INTEGER 0, SEQUENCE { OID <curve> }, OCTET STRING { OCTET STRING <32-byte seed> } }`
// — fixed for every seed of a given curve; only the trailing 32 bytes vary.
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const X25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

function wrapPkcs8(prefix: Uint8Array, seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) {
    throw new RangeError(`wrapPkcs8: seed must be exactly 32 bytes, got ${seed.length}`);
  }
  const out = new Uint8Array(prefix.length + seed.length);
  out.set(prefix, 0);
  out.set(seed, prefix.length);
  return out;
}

// ---- base64url (JWK `x`/`d` fields only — not exported; this package's public API is bytes-in,
// bytes-out throughout) ----

const BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base64UrlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += BASE64_CHARS[b0 >> 2];
    out += BASE64_CHARS[((b0 & 0x03) << 4) | (b1 !== undefined ? b1 >> 4 : 0)];
    if (b1 !== undefined) out += BASE64_CHARS[((b1 & 0x0f) << 2) | (b2 !== undefined ? b2 >> 6 : 0)];
    if (b2 !== undefined) out += BASE64_CHARS[b2 & 0x3f];
  }
  return out.replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlDecode(s: string): Uint8Array {
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bytes: number[] = [];
  let buffer = 0;
  let bitsInBuffer = 0;
  for (const c of base64) {
    const value = BASE64_CHARS.indexOf(c);
    if (value === -1) continue; // ignore any stray padding/whitespace
    buffer = (buffer << 6) | value;
    bitsInBuffer += 6;
    if (bitsInBuffer >= 8) {
      bitsInBuffer -= 8;
      bytes.push((buffer >> bitsInBuffer) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

// ---- WebCrypto Ed25519 ----

async function webcryptoEd25519PublicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  const pkcs8 = wrapPkcs8(ED25519_PKCS8_PREFIX, seed);
  const key = await crypto.subtle.importKey("pkcs8", asBufferSource(pkcs8), { name: "Ed25519" }, true, [
    "sign",
  ]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (typeof jwk.x !== "string") throw new Error("webcrypto: Ed25519 JWK export missing `x`");
  return base64UrlDecode(jwk.x);
}

async function webcryptoEd25519Sign(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const pkcs8 = wrapPkcs8(ED25519_PKCS8_PREFIX, seed);
  const key = await crypto.subtle.importKey("pkcs8", asBufferSource(pkcs8), { name: "Ed25519" }, false, [
    "sign",
  ]);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, asBufferSource(message));
  return new Uint8Array(sig);
}

async function webcryptoEd25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", asBufferSource(publicKey), { name: "Ed25519" }, false, [
    "verify",
  ]);
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    asBufferSource(signature),
    asBufferSource(message),
  );
}

// ---- WebCrypto X25519 ----

async function webcryptoX25519PublicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  const pkcs8 = wrapPkcs8(X25519_PKCS8_PREFIX, seed);
  const key = await crypto.subtle.importKey("pkcs8", asBufferSource(pkcs8), { name: "X25519" }, true, [
    "deriveBits",
  ]);
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (typeof jwk.x !== "string") throw new Error("webcrypto: X25519 JWK export missing `x`");
  return base64UrlDecode(jwk.x);
}

async function webcryptoX25519SharedSecret(
  seed: Uint8Array,
  peerPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const pkcs8 = wrapPkcs8(X25519_PKCS8_PREFIX, seed);
  const privateKey = await crypto.subtle.importKey("pkcs8", asBufferSource(pkcs8), { name: "X25519" }, false, [
    "deriveBits",
  ]);
  const publicKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(peerPublicKey),
    { name: "X25519" },
    false,
    [],
  );
  const bits = await crypto.subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256);
  return new Uint8Array(bits);
}

// ---- noble/curves Ed25519/X25519 (synchronous under the hood; wrapped as async for a uniform
// backend-agnostic call surface) ----

async function nobleEd25519PublicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  return ed25519.getPublicKey(seed);
}

async function nobleEd25519Sign(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  return ed25519.sign(message, seed);
}

async function nobleEd25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    // noble throws on structurally invalid inputs (e.g. a non-canonical point) rather than
    // returning false; a verification failure of any kind must read as "invalid", not throw.
    return false;
  }
}

async function nobleX25519PublicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  return x25519.getPublicKey(seed);
}

async function nobleX25519SharedSecret(seed: Uint8Array, peerPublicKey: Uint8Array): Promise<Uint8Array> {
  return x25519.getSharedSecret(seed, peerPublicKey);
}

// ---- backend dispatch ----

async function withFallback<T>(
  explicit: AsymmetricBackend | undefined,
  webcrypto: () => Promise<T>,
  noble: () => Promise<T>,
): Promise<T> {
  if (explicit === "noble") return noble();
  if (explicit === "webcrypto") return webcrypto();
  // Auto: prefer WebCrypto, fall back to noble only if WebCrypto is unavailable or the specific
  // algorithm isn't supported by this runtime's implementation.
  if (!hasSubtleCrypto()) return noble();
  try {
    return await webcrypto();
  } catch {
    return noble();
  }
}

export function ed25519PublicKeyFromSeed(seed: Uint8Array, opts?: BackendOption): Promise<Uint8Array> {
  return withFallback(
    opts?.backend,
    () => webcryptoEd25519PublicKeyFromSeed(seed),
    () => nobleEd25519PublicKeyFromSeed(seed),
  );
}

export function ed25519Sign(
  seed: Uint8Array,
  message: Uint8Array,
  opts?: BackendOption,
): Promise<Uint8Array> {
  return withFallback(
    opts?.backend,
    () => webcryptoEd25519Sign(seed, message),
    () => nobleEd25519Sign(seed, message),
  );
}

export function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  opts?: BackendOption,
): Promise<boolean> {
  return withFallback(
    opts?.backend,
    () => webcryptoEd25519Verify(publicKey, message, signature),
    () => nobleEd25519Verify(publicKey, message, signature),
  );
}

export function x25519PublicKeyFromSeed(seed: Uint8Array, opts?: BackendOption): Promise<Uint8Array> {
  return withFallback(
    opts?.backend,
    () => webcryptoX25519PublicKeyFromSeed(seed),
    () => nobleX25519PublicKeyFromSeed(seed),
  );
}

export function x25519SharedSecret(
  seed: Uint8Array,
  peerPublicKey: Uint8Array,
  opts?: BackendOption,
): Promise<Uint8Array> {
  return withFallback(
    opts?.backend,
    () => webcryptoX25519SharedSecret(seed, peerPublicKey),
    () => nobleX25519SharedSecret(seed, peerPublicKey),
  );
}

/** Probes whether this runtime's WebCrypto actually supports Ed25519/X25519 (as opposed to merely
 * having `crypto.subtle` at all — e.g. an older browser has `subtle` but rejects the `"Ed25519"`
 * algorithm identifier). Used only by the backend-parity tests to decide whether to skip the
 * WebCrypto-forced cases with an explicit message, per DESIGN.md §A7's browser-support note; Node
 * 22 is expected to support both. Not memoized — this is test-only, called at most a few times. */
export async function probeWebCryptoSupport(): Promise<{ ed25519: boolean; x25519: boolean }> {
  if (!hasSubtleCrypto()) return { ed25519: false, x25519: false };
  const seed = new Uint8Array(32).fill(0x01);
  const ed25519Ok = await webcryptoEd25519PublicKeyFromSeed(seed)
    .then(() => true)
    .catch(() => false);
  const x25519Ok = await webcryptoX25519PublicKeyFromSeed(seed)
    .then(() => true)
    .catch(() => false);
  return { ed25519: ed25519Ok, x25519: x25519Ok };
}
