// Test-only helpers shared by the admin suite. None of this ships.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { bytesToHex, CborValue, hexToBytes, type CborValue as CborValueType } from "@spindle/proto";

import type { Signer } from "../src/signer.js";

const here = path.dirname(fileURLToPath(import.meta.url));

/** Repository `vectors/` directory, located the same way `packages/proto/test/helpers.ts` does:
 * from this file's own path, not the process cwd. */
export const vectorsDir = path.resolve(here, "..", "..", "..", "vectors");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function loadVectorFile(name: string): any {
  return JSON.parse(fs.readFileSync(path.join(vectorsDir, name), "utf8"));
}

/** Parses the generic `{type, value}` CBOR-tree shape used by `AdminCommand.args` in
 * `vectors/admin-command.json` (identical in spirit to `packages/proto/test/helpers.ts`'s
 * `parseCborTree`, copied rather than imported across a package boundary). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseCborTree(node: any): CborValueType {
  switch (node.type) {
    case "uint":
      return CborValue.uint(BigInt(node.value));
    case "negint":
      return CborValue.negint(BigInt(node.magnitude));
    case "bytes":
      return CborValue.bytes(hexToBytes(node.value));
    case "text":
      return CborValue.text(node.value);
    case "array":
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return CborValue.array((node.value as any[]).map(parseCborTree));
    case "map":
      return {
        kind: "map",
        value: (
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          node.value as Array<{ key: any; value: any }>
        ).map((e): [CborValueType, CborValueType] => [parseCborTree(e.key), parseCborTree(e.value)]),
      };
    case "bool":
      return CborValue.bool(node.value);
    case "null":
      return CborValue.null();
    default:
      throw new Error(`parseCborTree: unknown node type \`${node.type}\``);
  }
}

/** A known-valid Ed25519 public key (the signed admin-command vector's operator key). Used where a
 * fake signer must satisfy the 32-byte key check without actually signing. */
export const VALID_PUBLIC_KEY = hexToBytes(
  "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
);

/** A deterministic `Signer` for tests. The private key is never involved: `sign` returns whatever
 * the test supplies, and the identity is supplied explicitly (the real `signer_fp` contract is an
 * operator identity, not necessarily `SHA-256(public_key)`). */
export function fixedSigner(options: {
  fingerprint: Uint8Array;
  signature: Uint8Array;
  publicKey?: Uint8Array;
}): Signer & { signedMessages: Uint8Array[] } {
  const signedMessages: Uint8Array[] = [];
  return {
    signedMessages,
    async sign(message: Uint8Array): Promise<Uint8Array> {
      signedMessages.push(message);
      return options.signature;
    },
    async publicKey(): Promise<Uint8Array> {
      return options.publicKey ?? VALID_PUBLIC_KEY;
    },
    async fingerprint(): Promise<Uint8Array> {
      return options.fingerprint;
    },
  };
}

/** Convenience: the canonical hex of a byte array, used in redaction assertions. */
export function hex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}
