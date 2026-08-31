// Test-only helpers: golden-vector loading (`vectors/signed/*.json`) and per-artifact JSON ->
// `@spindle/proto` struct parsers. None of this ships in the published package — it exists only to
// drive the vitest suite against `/vectors/signed`, mirroring `@spindle/proto`'s
// `test/helpers.ts` conventions.

import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

import { hexToBytes } from "@spindle/proto";
import type {
  AdminCommand,
  AdmissionToken,
  Capability,
  DeviceCertificate,
  HostOpKeyCert,
  RevocationRecord,
} from "@spindle/proto";
import { CapKind, canonicalDecode } from "@spindle/proto";
import type { CborValue } from "@spindle/proto";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");
export const signedVectorsDir = path.resolve(packageRoot, "..", "..", "vectors", "signed");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function loadSignedVectorFile(name: string): any {
  const p = path.join(signedVectorsDir, name);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

// ---- per-artifact JSON -> struct parsers (mirrors @spindle/proto's test/helpers.ts) ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseCapability(d: any): Capability {
  return {
    v: Number(d.v),
    host_fp: hexToBytes(d.host_fp),
    host_root_pk: hexToBytes(d.host_root_pk),
    op_cert: hexToBytes(d.op_cert),
    kind: Number(d.kind) as CapKind,
    subject: hexToBytes(d.subject),
    cap_epoch: BigInt(d.cap_epoch),
    exp: BigInt(d.exp),
    nonce: hexToBytes(d.nonce),
    sig: hexToBytes(d.sig),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAdmissionToken(d: any): AdmissionToken {
  return {
    nonce: hexToBytes(d.nonce),
    exp: BigInt(d.exp),
    label: d.label,
    quota_profile: d.quota_profile,
    sig_operator: hexToBytes(d.sig_operator),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseDeviceCertificate(d: any): DeviceCertificate {
  return {
    device_fp: hexToBytes(d.device_fp),
    alg_id: Number(d.alg_id),
    sign_pk: hexToBytes(d.sign_pk),
    agree_pk: hexToBytes(d.agree_pk),
    nats_fp: hexToBytes(d.nats_fp),
    ts: BigInt(d.ts),
    exp: BigInt(d.exp),
    sig_root: hexToBytes(d.sig_root),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseRevocationRecord(d: any): RevocationRecord {
  return {
    host_fp: hexToBytes(d.host_fp),
    epoch: BigInt(d.epoch),
    revoked: (d.revoked as string[]).map(hexToBytes),
    ts: BigInt(d.ts),
    sig: hexToBytes(d.sig),
  };
}

// The vector JSON's `args` field is a generic CBOR-tree node (`{type, value}`), the same shape as
// canonical-cbor.json in the parent `/vectors` directory — decode it straight from the case's own
// `canonical_cbor_hex`/`signing_input_hex` instead of hand-parsing the tree: `AdminCommand.args`
// only needs to compare equal / round-trip through `canonicalDecode`, and this package has no
// crypto-independent reason to duplicate `@spindle/proto`'s test-only tree parser.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAdminCommand(d: any, argsCbor: CborValue): AdminCommand {
  return {
    v: Number(d.v),
    cmd: d.cmd,
    args: argsCbor,
    signer_fp: hexToBytes(d.signer_fp),
    seq: BigInt(d.seq),
    nonce: hexToBytes(d.nonce),
    ts: BigInt(d.ts),
    sig: hexToBytes(d.sig),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseHostOpKeyCert(d: any): HostOpKeyCert {
  return {
    host_op_pk: hexToBytes(d.host_op_pk),
    nats_fp: hexToBytes(d.nats_fp),
    ts: BigInt(d.ts),
    exp: BigInt(d.exp),
    sig_host_root: hexToBytes(d.sig_host_root),
  };
}

/** Decodes an `AdminCommand`'s `args` field out of the case's own `canonical_cbor_hex` (the map
 * entry keyed `"args"`) rather than hand-parsing the JSON `{type, value}` tree — see the comment
 * on `parseAdminCommand`. */
export function argsFromCanonicalCbor(canonicalCborHex: string): CborValue {
  const decoded = canonicalDecode(hexToBytes(canonicalCborHex));
  if (decoded.kind !== "map") throw new Error("argsFromCanonicalCbor: top-level item is not a map");
  for (const [k, v] of decoded.value) {
    if (k.kind === "text" && k.value === "args") return v;
  }
  throw new Error("argsFromCanonicalCbor: no `args` field found");
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
