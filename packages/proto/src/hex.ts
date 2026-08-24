// Hex <-> Uint8Array helpers. The golden vectors in /vectors encode byte fields as lowercase hex
// strings (see vectors/README.md); this module is the single place that crosses that boundary.

const HEX_RE = /^[0-9a-fA-F]*$/;

/** Decodes a lowercase (or uppercase) hex string to bytes. Throws on odd length or non-hex
 * characters. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex string (length ${hex.length})`);
  }
  if (!HEX_RE.test(hex)) {
    throw new Error("hexToBytes: input contains non-hex characters");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Encodes bytes to a lowercase hex string, matching the vectors' JSON convention. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}
