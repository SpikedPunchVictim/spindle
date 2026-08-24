// SHA-256, HKDF-SHA256, and AES-256-GCM — WebCrypto-only (DESIGN.md §A7: "AES-GCM/HKDF native").
// Unlike Ed25519/X25519 (backend.ts), these three have no `@noble/curves` fallback: they are
// universally available wherever `crypto.subtle` exists at all (Node 22 and every browser this
// project targets), and `@noble/curves` — the only runtime dependency this package is allowed to
// add — provides no hash/AEAD/KDF implementations to fall back to in the first place.

import { asBufferSource } from "./bytes.js";

/** `SHA-256(data)`. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", asBufferSource(data));
  return new Uint8Array(digest);
}

/**
 * HKDF-SHA256 with **no salt supplied** — matching the Rust `hkdf` crate's `Hkdf::new(None, ikm)`
 * (used by `spindle-core::envelope::derive_session_key`), which per RFC 5869 §2.2 extracts with
 * `salt` defaulted to `HashLen` (32, for SHA-256) zero bytes, not an empty/zero-length salt.
 * WebCrypto's `HKDF` algorithm requires an explicit `salt`, so this passes 32 zero bytes to
 * reproduce the same default.
 */
export async function hkdfSha256(
  ikm: Uint8Array,
  info: Uint8Array,
  length = 32,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", asBufferSource(ikm), "HKDF", false, [
    "deriveBits",
  ]);
  const zeroSalt = new Uint8Array(32); // HKDF-SHA256's HashLen — see doc comment above
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: asBufferSource(zeroSalt), info: asBufferSource(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** AES-256-GCM encrypt. `key` must be 32 bytes, `nonce` 12 bytes (DESIGN.md §A7:
 * `direction(1) || seq(11)`). Returns ciphertext with the 16-byte GCM tag appended (WebCrypto's
 * default, matching the Rust `aes-gcm` crate's default tag length). */
export async function aesGcmSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey("raw", asBufferSource(key), "AES-GCM", false, [
    "encrypt",
  ]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asBufferSource(nonce), additionalData: asBufferSource(aad) },
    cryptoKey,
    asBufferSource(plaintext),
  );
  return new Uint8Array(ciphertext);
}

/** AES-256-GCM decrypt. Throws (an opaque `DOMException`/`Error` — callers should treat *any*
 * throw here as an authentication failure, never inspect the message) if the tag does not verify. */
export async function aesGcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey("raw", asBufferSource(key), "AES-GCM", false, [
    "decrypt",
  ]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asBufferSource(nonce), additionalData: asBufferSource(aad) },
    cryptoKey,
    asBufferSource(ciphertext),
  );
  return new Uint8Array(plaintext);
}
