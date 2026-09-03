// Canonical CBOR (RFC 8949 §4.2.1) — the TypeScript twin of
// `crates/spindle-proto/src/canonical.rs`. Hand-rolled rather than driven through a third-party
// CBOR library, for the same reason as the Rust side: canonical-form *rejection* on decode needs
// raw-byte-level control over exactly which bytes an encoder chose to emit for every item, which
// a general-purpose CBOR decoder's API abstracts away. This is the security property ADR-004
// calls out (signature malleability: two different byte strings must never decode to the "same"
// signed artifact), so this module owns the full byte-for-byte contract itself.
//
// Zero runtime dependencies; Uint8Array-based throughout so it works unmodified in the browser
// and in Node.
//
// Supported canonical CBOR subset (RFC 8949 §4.2.1, restricted further per DESIGN.md A7b) —
// mirrors `canonical.rs` exactly:
// - major type 0/1: unsigned/negative integers, shortest-form only
// - major type 2/3: byte strings / UTF-8 text strings, definite length, shortest-form length
// - major type 4/5: arrays / maps, definite length only; map keys sorted bytewise on their own
//   canonical encoding (RFC 8949 §4.2.1) and rejected on decode if not strictly increasing (this
//   also rejects duplicate keys, since duplicates cannot be strictly increasing)
// - major type 7: only `false` (0xf4), `true` (0xf5), `null` (0xf6) — no floats, no `undefined`,
//   no other simple values
// - tags (major type 6): always rejected — no tagged items appear on Spindle's wire
// - indefinite-length items and the `break` stop code: always rejected

/**
 * Maximum number of enclosing arrays/maps a decoded item may sit inside. Mirrors
 * `MAX_NESTING_DEPTH` in `canonical.rs` — same value, same rationale: `decodeOne` recurses once
 * per nesting level, so without a ceiling a small payload of repeated `0x81` (array, count 1)
 * bytes recurses without bound. In JS this raises a catchable `RangeError` (stack overflow)
 * rather than aborting the process the way the Rust decoder does, so the limit exists here
 * primarily to keep both decoders accepting exactly the same payloads. 32 is roughly ten times
 * the deepest structure this protocol actually produces: across all 84 canonical vectors in
 * `vectors/*.json`, the deepest reaches `depth` 3, in the same units compared against this
 * constant (top-level item at `depth` 0). Counting items instead of depth levels gives 4 —
 * state which convention you mean if you re-derive this.
 */
export const MAX_NESTING_DEPTH = 32;

/**
 * A canonical CBOR data item. Mirrors Rust's `CborValue` enum field-for-field.
 *
 * `{ kind: "negint", value: n }` represents the CBOR negative integer whose logical value is
 * `-1 - n` (i.e. major type 1 with argument `n`), matching RFC 8949's own encoding of negative
 * integers and `CborValue::NegInt(n)` in the Rust twin.
 *
 * `uint`/`negint` values are `bigint` (not `number`) so the full CBOR `u64` argument range is
 * representable without precision loss.
 */
export type CborValue =
  | { kind: "uint"; value: bigint }
  | { kind: "negint"; value: bigint }
  | { kind: "bytes"; value: Uint8Array }
  | { kind: "text"; value: string }
  | { kind: "array"; value: CborValue[] }
  /**
   * Key/value pairs in *insertion* order as constructed. `canonicalEncode` sorts them into
   * canonical (bytewise, on each key's own canonical encoding) order before emitting, so callers
   * never need to pre-sort. `canonicalDecode` only ever produces maps whose entries are already
   * in canonical order (it rejects anything else), so re-encoding a decoded value reproduces the
   * original bytes.
   */
  | { kind: "map"; value: Array<[CborValue, CborValue]> }
  | { kind: "bool"; value: boolean }
  | { kind: "null" };

export const CborValue = {
  uint(v: bigint | number): CborValue {
    return { kind: "uint", value: BigInt(v) };
  },
  negint(v: bigint | number): CborValue {
    return { kind: "negint", value: BigInt(v) };
  },
  bytes(v: Uint8Array): CborValue {
    return { kind: "bytes", value: v };
  },
  text(v: string): CborValue {
    return { kind: "text", value: v };
  },
  array(v: CborValue[]): CborValue {
    return { kind: "array", value: v };
  },
  /** Builds a `map` from `(field name, value)` pairs. Field names become `text` keys. Callers may
   * pass entries in any order — `canonicalEncode` sorts them canonically. */
  map(entries: Array<[string, CborValue]>): CborValue {
    return {
      kind: "map",
      value: entries.map(([k, v]): [CborValue, CborValue] => [{ kind: "text", value: k }, v]),
    };
  },
  bool(v: boolean): CborValue {
    return { kind: "bool", value: v };
  },
  null(): CborValue {
    return { kind: "null" };
  },
};

/**
 * Structural equality mirroring Rust's `impl PartialEq for CborValue`: `map` is compared
 * order-independently (as a set of key/value pairs) — two maps built with the same entries in
 * different insertion order are the same logical CBOR map, even though only one insertion order
 * (the canonical, bytewise-sorted one) is ever actually written to the wire by
 * [`canonicalEncode`]. Every other variant compares structurally, including `array`, where
 * element order is meaningful.
 */
export function cborValueEquals(a: CborValue, b: CborValue): boolean {
  if (a.kind !== b.kind) return false;
  switch (a.kind) {
    case "uint":
      return a.value === (b as typeof a).value;
    case "negint":
      return a.value === (b as typeof a).value;
    case "bytes":
      return bytesEqual(a.value, (b as typeof a).value);
    case "text":
      return a.value === (b as typeof a).value;
    case "array": {
      const bv = (b as typeof a).value;
      return (
        a.value.length === bv.length && a.value.every((item, i) => cborValueEquals(item, bv[i]))
      );
    }
    case "map": {
      const bv = (b as typeof a).value;
      if (a.value.length !== bv.length) return false;
      const containsPair = (
        haystack: Array<[CborValue, CborValue]>,
        [k, v]: [CborValue, CborValue],
      ) => haystack.some(([hk, hv]) => cborValueEquals(hk, k) && cborValueEquals(hv, v));
      return a.value.every((pair) => containsPair(bv, pair)) && bv.every((pair) => containsPair(a.value, pair));
    }
    case "bool":
      return a.value === (b as typeof a).value;
    case "null":
      return true;
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Bytewise comparison of two byte strings — shorter arrays that are a prefix of a longer one
 * sort first, matching Rust's `Vec<u8>`/`&[u8]` `Ord`. Used both to sort map entries and to check
 * strictly-increasing key order on decode. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/** Errors produced by the canonical CBOR decoder. Every instance carries the byte offset at which
 * the violation was detected, to make golden-vector debugging tractable. Mirrors Rust's
 * `CborError` enum: one variant per `kind`. */
export type CborErrorKind =
  | "UnexpectedEof"
  | "IndefiniteLength"
  | "NonShortestForm"
  | "ReservedAdditionalInfo"
  | "FloatNotAllowed"
  | "TagNotAllowed"
  | "SimpleNotAllowed"
  | "InvalidUtf8"
  | "MapKeyOrder"
  | "TrailingBytes"
  | "DepthLimitExceeded";

const CBOR_ERROR_MESSAGES: Record<CborErrorKind, string> = {
  UnexpectedEof: "unexpected end of input",
  IndefiniteLength: "indefinite-length items are not allowed in canonical CBOR",
  NonShortestForm: "integer/length not encoded in shortest form",
  ReservedAdditionalInfo: "reserved additional-info value",
  FloatNotAllowed: "floating-point values are not allowed",
  TagNotAllowed: "CBOR tags are not allowed",
  SimpleNotAllowed: "simple value not allowed",
  InvalidUtf8: "invalid UTF-8 in text string",
  MapKeyOrder: "map keys are not in strictly increasing canonical order",
  TrailingBytes: "trailing bytes after top-level item",
  DepthLimitExceeded: "nesting deeper than 32 levels",
};

export class CborError extends Error {
  readonly kind: CborErrorKind;
  readonly offset: number;

  constructor(kind: CborErrorKind, offset: number) {
    super(`${CBOR_ERROR_MESSAGES[kind]} (offset ${offset})`);
    this.name = "CborError";
    this.kind = kind;
    this.offset = offset;
  }
}

/**
 * Encodes a `CborValue` tree to canonical CBOR bytes.
 *
 * Throws if `value` nests more than {@link MAX_NESTING_DEPTH} arrays/maps deep. `CborValue`'s
 * `array()`/`map()` constructors are exported, so a future caller could in principle hand this
 * function a tree built by recursing over some other unbounded input. Without a ceiling, encoding
 * such a tree would recurse exactly the way `decodeOne` used to before it gained its own guard —
 * in the Rust twin that recursion aborts the process uncatchably (SIGABRT); in JS it would
 * eventually throw an engine `RangeError` at whatever depth the current call stack happens to
 * allow, which varies by engine and by how much stack the caller has already used. Throwing our
 * own bounded, deterministic error here keeps both languages agreeing on exactly which trees are
 * legal to encode, matching `canonical_encode`'s panic in `canonical.rs` — Rust panics, TS
 * throws, but both signal a programmer error (an over-deep in-memory value), not a protocol
 * violation like `canonicalDecode`'s typed `CborError`/`DepthLimitExceeded`.
 *
 * This function stays a plain function that throws rather than returning a `Result`-like union:
 * it has 22 TypeScript call sites plus 49 in the Rust twin, and every one today holds a
 * provably-shallow value (either built by this package's own flat struct-encoding code, or
 * round-tripped from the now-bounded decoder). Threading a fallible return through all 71 call
 * sites would turn each into an unwrap for zero present benefit.
 */
export function canonicalEncode(value: CborValue): Uint8Array {
  const out: number[] = [];
  encodeInto(value, out, 0);
  return Uint8Array.from(out);
}

/** Decodes exactly one canonical CBOR item from `bytes`, rejecting the item (and any trailing
 * bytes) if it is not fully canonical per RFC 8949 §4.2.1. */
export function canonicalDecode(bytes: Uint8Array): CborValue {
  const [value, consumed] = decodeOne(bytes, 0, 0);
  if (consumed !== bytes.length) {
    throw new CborError("TrailingBytes", consumed);
  }
  return value;
}

// ---- encode ----

function writeHeader(out: number[], major: number, value: bigint): void {
  const m = major << 5;
  if (value < 24n) {
    out.push(m | Number(value));
  } else if (value <= 0xffn) {
    out.push(m | 24);
    out.push(Number(value));
  } else if (value <= 0xffffn) {
    out.push(m | 25);
    out.push(Number((value >> 8n) & 0xffn));
    out.push(Number(value & 0xffn));
  } else if (value <= 0xffffffffn) {
    out.push(m | 26);
    for (let shift = 24; shift >= 0; shift -= 8) {
      out.push(Number((value >> BigInt(shift)) & 0xffn));
    }
  } else {
    out.push(m | 27);
    for (let shift = 56; shift >= 0; shift -= 8) {
      out.push(Number((value >> BigInt(shift)) & 0xffn));
    }
  }
}

const textEncoder = new TextEncoder();

/** Mirrors `encode_into` in `canonical.rs` exactly: the top-level call starts at `depth` 0, each
 * `array` element and each `map` key/value recurses at `depth + 1`, and the guard fires on entry
 * before any work happens. Keeping the counting convention identical to `decodeOne` (and to the
 * Rust twin) is what makes both sides agree on which trees are legal — see the symmetry test in
 * `test/canonical.test.ts`. */
function encodeInto(value: CborValue, out: number[], depth: number): void {
  if (depth > MAX_NESTING_DEPTH) {
    // Programmer-error signal (an over-deep in-memory value), not a protocol error — see
    // `canonicalEncode`'s doc comment. A bare `Error`, not `CborError`, following this file's
    // existing pattern for "should never happen" conditions (the `unreachable` branch below).
    throw new Error(
      `canonicalEncode: value nests deeper than MAX_NESTING_DEPTH (${MAX_NESTING_DEPTH}) levels; ` +
        "flatten the CborValue tree before encoding it",
    );
  }
  switch (value.kind) {
    case "uint":
      writeHeader(out, 0, value.value);
      return;
    case "negint":
      writeHeader(out, 1, value.value);
      return;
    case "bytes":
      writeHeader(out, 2, BigInt(value.value.length));
      for (const b of value.value) out.push(b);
      return;
    case "text": {
      const bytes = textEncoder.encode(value.value);
      writeHeader(out, 3, BigInt(bytes.length));
      for (const b of bytes) out.push(b);
      return;
    }
    case "array":
      writeHeader(out, 4, BigInt(value.value.length));
      for (const item of value.value) encodeInto(item, out, depth + 1);
      return;
    case "map": {
      const encoded: Array<[Uint8Array, Uint8Array]> = value.value.map(([k, v]) => {
        const kOut: number[] = [];
        encodeInto(k, kOut, depth + 1);
        const vOut: number[] = [];
        encodeInto(v, vOut, depth + 1);
        return [Uint8Array.from(kOut), Uint8Array.from(vOut)];
      });
      encoded.sort((a, b) => compareBytes(a[0], b[0]));
      writeHeader(out, 5, BigInt(encoded.length));
      for (const [kb, vb] of encoded) {
        for (const b of kb) out.push(b);
        for (const b of vb) out.push(b);
      }
      return;
    }
    case "bool":
      out.push(value.value ? 0xf5 : 0xf4);
      return;
    case "null":
      out.push(0xf6);
      return;
  }
}

// ---- decode ----

/** Reads the argument (integer value / length / count) for a major type whose additional-info
 * byte lives at `bytes[offset - 1]` (already consumed by the caller) with value `info`. Enforces
 * shortest-form encoding. */
function readArg(
  bytes: Uint8Array,
  offset: number,
  info: number,
  headOffset: number,
): [bigint, number] {
  if (info <= 23) {
    return [BigInt(info), offset];
  }
  if (info === 24) {
    if (offset >= bytes.length) throw new CborError("UnexpectedEof", offset);
    const b = bytes[offset];
    if (b < 24) throw new CborError("NonShortestForm", headOffset);
    return [BigInt(b), offset + 1];
  }
  if (info === 25) {
    const end = offset + 2;
    if (end > bytes.length) throw new CborError("UnexpectedEof", offset);
    const v = (bytes[offset] << 8) | bytes[offset + 1];
    if (v <= 0xff) throw new CborError("NonShortestForm", headOffset);
    return [BigInt(v), end];
  }
  if (info === 26) {
    const end = offset + 4;
    if (end > bytes.length) throw new CborError("UnexpectedEof", offset);
    const v =
      (bytes[offset] * 0x1000000 +
        (bytes[offset + 1] << 16) +
        (bytes[offset + 2] << 8) +
        bytes[offset + 3]) >>>
      0;
    if (v <= 0xffff) throw new CborError("NonShortestForm", headOffset);
    return [BigInt(v), end];
  }
  if (info === 27) {
    const end = offset + 8;
    if (end > bytes.length) throw new CborError("UnexpectedEof", offset);
    let v = 0n;
    for (let i = 0; i < 8; i++) {
      v = (v << 8n) | BigInt(bytes[offset + i]);
    }
    if (v <= 0xffffffffn) throw new CborError("NonShortestForm", headOffset);
    return [v, end];
  }
  if (info >= 28 && info <= 30) {
    throw new CborError("ReservedAdditionalInfo", headOffset);
  }
  // info === 31
  throw new CborError("IndefiniteLength", headOffset);
}

const textDecoder = new TextDecoder("utf-8", { fatal: true });

function decodeOne(bytes: Uint8Array, offset: number, depth: number): [CborValue, number] {
  if (depth > MAX_NESTING_DEPTH) {
    throw new CborError("DepthLimitExceeded", offset);
  }
  const headOffset = offset;
  if (offset >= bytes.length) throw new CborError("UnexpectedEof", offset);
  const b = bytes[offset];
  const major = b >> 5;
  const info = b & 0x1f;
  offset = offset + 1;

  switch (major) {
    case 0: {
      const [v, off] = readArg(bytes, offset, info, headOffset);
      return [{ kind: "uint", value: v }, off];
    }
    case 1: {
      const [v, off] = readArg(bytes, offset, info, headOffset);
      return [{ kind: "negint", value: v }, off];
    }
    case 2: {
      const [lenBig, off] = readArg(bytes, offset, info, headOffset);
      const len = Number(lenBig);
      const end = off + len;
      if (end > bytes.length) throw new CborError("UnexpectedEof", off);
      return [{ kind: "bytes", value: bytes.slice(off, end) }, end];
    }
    case 3: {
      const [lenBig, off] = readArg(bytes, offset, info, headOffset);
      const len = Number(lenBig);
      const end = off + len;
      if (end > bytes.length) throw new CborError("UnexpectedEof", off);
      const slice = bytes.slice(off, end);
      let s: string;
      try {
        s = textDecoder.decode(slice);
      } catch {
        throw new CborError("InvalidUtf8", off);
      }
      return [{ kind: "text", value: s }, end];
    }
    case 4: {
      const [countBig, offAfterHeader] = readArg(bytes, offset, info, headOffset);
      const count = Number(countBig);
      const items: CborValue[] = [];
      let off = offAfterHeader;
      for (let i = 0; i < count; i++) {
        const [item, next] = decodeOne(bytes, off, depth + 1);
        items.push(item);
        off = next;
      }
      return [{ kind: "array", value: items }, off];
    }
    case 5: {
      const [countBig, offAfterHeader] = readArg(bytes, offset, info, headOffset);
      const count = Number(countBig);
      const entries: Array<[CborValue, CborValue]> = [];
      let off = offAfterHeader;
      let prevKeyBytes: Uint8Array | null = null;
      for (let i = 0; i < count; i++) {
        const keyStart = off;
        const [key, afterKey] = decodeOne(bytes, off, depth + 1);
        const keyBytes = bytes.slice(keyStart, afterKey);
        if (prevKeyBytes !== null && compareBytes(keyBytes, prevKeyBytes) <= 0) {
          throw new CborError("MapKeyOrder", keyStart);
        }
        const [val, afterVal] = decodeOne(bytes, afterKey, depth + 1);
        entries.push([key, val]);
        prevKeyBytes = keyBytes;
        off = afterVal;
      }
      return [{ kind: "map", value: entries }, off];
    }
    case 6:
      throw new CborError("TagNotAllowed", headOffset);
    case 7:
      switch (info) {
        case 20:
          return [{ kind: "bool", value: false }, offset];
        case 21:
          return [{ kind: "bool", value: true }, offset];
        case 22:
          return [{ kind: "null" }, offset];
        case 23:
        case 24:
          throw new CborError("SimpleNotAllowed", headOffset);
        case 25:
        case 26:
        case 27:
          throw new CborError("FloatNotAllowed", headOffset);
        case 28:
        case 29:
        case 30:
          throw new CborError("ReservedAdditionalInfo", headOffset);
        default:
          // info === 31
          throw new CborError("IndefiniteLength", headOffset);
      }
    default:
      // major type is a 3-bit field (0-7); unreachable.
      throw new Error(`unreachable: major type ${major}`);
  }
}
