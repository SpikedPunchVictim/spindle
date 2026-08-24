// Test-only helpers: golden-vector loading, the generic JSON `{type, value}` CBOR-tree parser
// used by canonical-cbor.json and AdminCommand.args, per-artifact JSON -> struct parsers, an
// order-independent/hex-friendly structural-equality normalizer, and the byte-level mutation
// helpers used by the negative (rejection) tests. None of this ships in the published package —
// it exists only to drive the vitest suite against /vectors.

import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

import { CborValue, canonicalEncode, type CborValue as CborValueType } from "../src/canonical.js";
import { hexToBytes, bytesToHex } from "../src/hex.js";
import type {
  Envelope,
  Capability,
  AdmissionToken,
  DeviceCertificate,
  RevocationRecord,
  AdminCommand,
  HostOpKeyCert,
} from "../src/artifacts.js";
import { CapKind } from "../src/artifacts.js";

// ---- vector file loading ----

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");
export const vectorsDir = path.resolve(packageRoot, "..", "..", "vectors");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function loadVectorFile(name: string): any {
  const p = path.join(vectorsDir, name);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

// ---- generic CBOR-tree parser (canonical-cbor.json `value`, AdminCommand.args) ----

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

// ---- per-artifact JSON -> struct parsers ----

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseEnvelope(d: any): Envelope {
  const env: Envelope = {
    v: Number(d.v),
    alg_id: Number(d.alg_id),
    from_fp: hexToBytes(d.from_fp),
    to_fp: hexToBytes(d.to_fp),
    sid: hexToBytes(d.sid),
    kind: Number(d.kind),
    seq: BigInt(d.seq),
    ts: BigInt(d.ts),
    ciphertext: hexToBytes(d.ciphertext),
    sig: hexToBytes(d.sig),
  };
  if (d.eph_pk !== undefined) env.eph_pk = hexToBytes(d.eph_pk);
  return env;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseCapability(d: any): Capability {
  return {
    v: Number(d.v),
    host_fp: hexToBytes(d.host_fp),
    host_pk: hexToBytes(d.host_pk),
    kind: Number(d.kind) as CapKind,
    subject: hexToBytes(d.subject),
    cap_epoch: BigInt(d.cap_epoch),
    exp: BigInt(d.exp),
    nonce: hexToBytes(d.nonce),
    sig_host: hexToBytes(d.sig_host),
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseAdminCommand(d: any): AdminCommand {
  return {
    v: Number(d.v),
    cmd: d.cmd,
    args: parseCborTree(d.args),
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

// ---- structural-equality normalizer ----
//
// Converts a value (an artifact struct, or a raw CborValue tree) into a plain, JSON-comparable
// shape: Uint8Array -> "hex:..." string, bigint -> "bigint:..." string, and CborValue `map`
// nodes -> a canonically-sorted array of [key, value] pairs (order-independent), mirroring the
// Rust `CborValue` `PartialEq` impl's set-based map comparison. Used with `expect(...).toEqual`
// so failures produce a readable diff instead of relying on `Uint8Array`/`bigint`-aware equality
// in the test runner.

const CBOR_KINDS = new Set(["uint", "negint", "bytes", "text", "array", "map", "bool", "null"]);

function isCborValueNode(v: unknown): v is CborValueType {
  return (
    typeof v === "object" &&
    v !== null &&
    "kind" in v &&
    typeof (v as { kind: unknown }).kind === "string" &&
    CBOR_KINDS.has((v as { kind: string }).kind)
  );
}

export function normalize(value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return `hex:${bytesToHex(value)}`;
  }
  if (typeof value === "bigint") {
    return `bigint:${value.toString()}`;
  }
  if (Array.isArray(value)) {
    return value.map(normalize);
  }
  if (isCborValueNode(value)) {
    switch (value.kind) {
      case "uint":
      case "negint":
        return { kind: value.kind, value: `bigint:${value.value.toString()}` };
      case "bytes":
        return { kind: "bytes", value: `hex:${bytesToHex(value.value)}` };
      case "text":
        return { kind: "text", value: value.value };
      case "array":
        return { kind: "array", value: value.value.map(normalize) };
      case "map": {
        const pairs = value.value.map(([k, v]) => [normalize(k), normalize(v)]);
        pairs.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
        return { kind: "map", value: pairs };
      }
      case "bool":
        return { kind: "bool", value: value.value };
      case "null":
        return { kind: "null" };
    }
  }
  if (typeof value === "object" && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = normalize(v);
    }
    return out;
  }
  return value;
}

// ---- byte-level mutation helpers (negative tests) ----

/** Writes a definite-length map header (`entries.length` must be < 24, true for every A7b
 * artifact) followed by each entry's own canonical bytes, in exactly the order given — no
 * sorting. Used to construct a structurally-valid-looking but non-canonically-ordered map. */
export function encodeMapUnsorted(entries: ReadonlyArray<[CborValueType, CborValueType]>): Uint8Array {
  if (entries.length >= 24) {
    throw new Error("encodeMapUnsorted: this helper only supports map counts < 24");
  }
  const out: number[] = [0xa0 | entries.length];
  for (const [k, v] of entries) {
    out.push(...canonicalEncode(k));
    out.push(...canonicalEncode(v));
  }
  return Uint8Array.from(out);
}

/** Swaps the first two entries of a decoded artifact map and re-encodes without sorting,
 * producing a map whose keys are (with overwhelming likelihood) no longer in strictly increasing
 * canonical order. */
export function swapFirstTwoEntries(mapValue: CborValueType): Uint8Array {
  if (mapValue.kind !== "map") throw new Error("swapFirstTwoEntries: not a map");
  const entries = mapValue.value.slice();
  if (entries.length < 2) throw new Error("swapFirstTwoEntries: need at least 2 entries");
  const tmp = entries[0];
  entries[0] = entries[1];
  entries[1] = tmp;
  return encodeMapUnsorted(entries);
}

/** Returns the header+argument bytes for `value` encoded one size class larger than its shortest
 * canonical form — i.e. deliberately non-shortest-form, major type 0 (uint) only. */
function nextFormBytes(value: bigint): number[] {
  if (value < 24n) {
    return [0x18, Number(value)];
  }
  if (value <= 0xffn) {
    return [0x19, 0x00, Number(value)];
  }
  if (value <= 0xffffn) {
    return [0x1a, 0x00, 0x00, Number((value >> 8n) & 0xffn), Number(value & 0xffn)];
  }
  if (value <= 0xffffffffn) {
    const out = [0x1b];
    for (let shift = 56; shift >= 0; shift -= 8) {
      out.push(Number((value >> BigInt(shift)) & 0xffn));
    }
    return out;
  }
  throw new Error("nextFormBytes: value already requires the maximal 8-byte form");
}

/** Re-encodes a decoded artifact map with the uint-valued field `key` written in a non-shortest
 * (but otherwise structurally valid) form — every other field's bytes and the overall key order
 * are left untouched. */
export function lengthenUintField(mapValue: CborValueType, key: string): Uint8Array {
  if (mapValue.kind !== "map") throw new Error("lengthenUintField: not a map");
  const entries = mapValue.value;
  if (entries.length >= 24) {
    throw new Error("lengthenUintField: this helper only supports map counts < 24");
  }
  const out: number[] = [0xa0 | entries.length];
  let mutated = false;
  for (const [k, v] of entries) {
    out.push(...canonicalEncode(k));
    if (k.kind === "text" && k.value === key) {
      if (v.kind !== "uint") {
        throw new Error(`lengthenUintField: field \`${key}\` is not a uint`);
      }
      out.push(...nextFormBytes(v.value));
      mutated = true;
    } else {
      out.push(...canonicalEncode(v));
    }
  }
  if (!mutated) throw new Error(`lengthenUintField: field \`${key}\` not found`);
  return Uint8Array.from(out);
}

/** Adds an extra, unrecognized key/value pair to a decoded artifact map and re-encodes it
 * (through the normal sorting encoder — the result is still fully canonical CBOR, just with an
 * extra field the artifact's closed schema does not declare). */
export function addUnknownKey(mapValue: CborValueType, key: string, value: CborValueType): Uint8Array {
  if (mapValue.kind !== "map") throw new Error("addUnknownKey: not a map");
  const entries: Array<[CborValueType, CborValueType]> = [
    ...mapValue.value,
    [CborValue.text(key), value],
  ];
  return canonicalEncode({ kind: "map", value: entries });
}
