// Fingerprints (DESIGN.md §A4) — the TypeScript twin of `crates/spindle-core/src/fingerprint.rs`,
// `identity.rs`'s `root_fp_of`/`device_fp_of`, and `base32.rs`. The wire form of every fingerprint
// is always the 32 raw SHA-256 bytes; base32 (RFC 4648, no padding, lowercase) is a display-only
// encoding layered on top for UI/logs, never sent on the wire.

import { sha256 } from "./primitives.js";

/** Every Spindle fingerprint is a SHA-256 digest: 32 bytes. */
export const FINGERPRINT_LEN = 32;

const DEVICE_FP_DOMAIN = new TextEncoder().encode("spindle-dev-v1");

/** `root_fp = SHA-256(root_pk)` (DESIGN.md §A4) — also used for `host_fp = SHA-256(host_pk)`,
 * which is the identical construction over a host's (rather than a person's) Ed25519 public key. */
export async function rootFpOf(rootPk: Uint8Array): Promise<Uint8Array> {
  return sha256(rootPk);
}

/** `device_fp = SHA-256("spindle-dev-v1" || alg_id || sign_pk || agree_pk)` (DESIGN.md §A4). */
export async function deviceFpOf(
  algId: number,
  signPk: Uint8Array,
  agreePk: Uint8Array,
): Promise<Uint8Array> {
  const input = new Uint8Array(DEVICE_FP_DOMAIN.length + 1 + signPk.length + agreePk.length);
  let offset = 0;
  input.set(DEVICE_FP_DOMAIN, offset);
  offset += DEVICE_FP_DOMAIN.length;
  input[offset] = algId;
  offset += 1;
  input.set(signPk, offset);
  offset += signPk.length;
  input.set(agreePk, offset);
  return sha256(input);
}

const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

/** Encodes `data` as lowercase RFC 4648 base32 with no `=` padding — display-only, matching
 * `spindle-core`'s `base32::encode_no_pad` exactly (verified against its known-answer vectors). */
export function base32EncodeNoPad(data: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bitsInBuffer = 0;

  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bitsInBuffer += 8;
    while (bitsInBuffer >= 5) {
      bitsInBuffer -= 5;
      const idx = (buffer >> bitsInBuffer) & 0x1f;
      out += BASE32_ALPHABET[idx];
    }
  }
  if (bitsInBuffer > 0) {
    const idx = (buffer << (5 - bitsInBuffer)) & 0x1f;
    out += BASE32_ALPHABET[idx];
  }
  return out;
}
