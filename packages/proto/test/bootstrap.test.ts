// Unit tests for the device bootstrap state bundle (DESIGN.md §A4:317-330) — the TS twin of
// `crates/spindle-proto/src/bootstrap.rs`. Covers round-trip, canonical key order, closed-schema
// rejection, and the length/count caps with hand-rolled fixtures, following the structure of
// `signaling.test.ts`'s hand-rolled parity section — plus, in the "vectors/bootstrap.json" describe
// block below, golden-vector conformance against the Rust-generated `vectors/bootstrap.json`
// (encode / decode / round-trip per case, and the same swap / lengthen / unknown-field mutation
// rejections `vectors.test.ts` applies to every A7b artifact), proving the TS and Rust encoders
// agree byte-for-byte for this type.

import { describe, expect, it } from "vitest";

import { CAPABILITY_CURRENT_V, CapKind, Capability } from "../src/artifacts.js";
import {
  BUNDLE_ENTRY_FIELDS,
  BUNDLE_FIELDS,
  BundleEntry,
  BundleWireError,
  DeviceBootstrapBundle,
  MAX_BUNDLE_ENTRIES,
  MAX_REGISTRY_LEN,
  type DeviceBootstrapBundle as DeviceBootstrapBundleType,
} from "../src/bootstrap.js";
import {
  CborError,
  CborValue,
  canonicalDecode,
  canonicalEncode,
  type CborValue as CborValueType,
} from "../src/canonical.js";
import { bytesToHex, hexToBytes } from "../src/hex.js";
import {
  addUnknownKey,
  lengthenUintField,
  loadVectorFile,
  normalize,
  parseBootstrapBundle,
  swapFirstTwoEntries,
} from "./helpers.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function expectThrows<E>(ctor: new (...args: any[]) => E, fn: () => unknown): E {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(ctor);
    return e as E;
  }
  throw new Error(`expected function to throw a ${ctor.name}, but it did not throw`);
}

/** A `Capability` with distinct, recognizable filler in every field, parameterized by `seed` so
 * callers building multiple entries get distinguishable caps. Mirrors `signaling.test.ts`'s
 * `sampleCapability`. */
function sampleCapability(seed: number): Capability {
  return {
    v: CAPABILITY_CURRENT_V,
    host_fp: new Uint8Array(32).fill(seed),
    host_root_pk: new Uint8Array(32).fill(seed + 1),
    op_cert: new Uint8Array(16).fill(seed + 2),
    kind: CapKind.Member,
    subject: new Uint8Array(32).fill(seed + 3),
    cap_epoch: BigInt(seed),
    exp: 1_800_000_000n,
    nonce: new Uint8Array(16).fill(seed + 4),
    sig: new Uint8Array(64).fill(seed + 5),
  };
}

function sampleEntry(seed: number): BundleEntry {
  return {
    sign_pk: new Uint8Array(32).fill(seed + 0x10),
    agree_pk: new Uint8Array(32).fill(seed + 0x20),
    member_cap: sampleCapability(seed),
  };
}

function sampleBundle(entryCount: number): DeviceBootstrapBundleType {
  const entries: BundleEntry[] = [];
  for (let i = 0; i < entryCount; i++) entries.push(sampleEntry(i * 0x10));
  return { v: 1, registry: "nats://registry.example.com:4222", entries };
}

describe("round trip", () => {
  it("round-trips a two-entry bundle", () => {
    const bundle = sampleBundle(2);
    const bytes = DeviceBootstrapBundle.toCanonicalBytes(bundle);
    const decoded = DeviceBootstrapBundle.fromCanonicalBytes(bytes);
    expect(normalize(decoded)).toEqual(normalize(bundle));
  });
});

describe("canonical key order", () => {
  it("bundle-level keys emit as v, entries, registry", () => {
    const bundle = sampleBundle(1);
    const cbor = DeviceBootstrapBundle.toCbor(bundle);
    const bytes = canonicalEncode(cbor);
    const decodedTree = canonicalDecode(bytes);
    if (decodedTree.kind !== "map") throw new Error("expected a map");
    const keys = decodedTree.value.map(([k]) => {
      if (k.kind !== "text") throw new Error("expected a text key");
      return k.value;
    });
    expect(keys).toEqual(["v", "entries", "registry"]);
  });

  it("entry-level keys emit as sign_pk, agree_pk, member_cap", () => {
    const entry = sampleEntry(0);
    const cbor = BundleEntry.toCbor(entry);
    const bytes = canonicalEncode(cbor);
    const decodedTree = canonicalDecode(bytes);
    if (decodedTree.kind !== "map") throw new Error("expected a map");
    const keys = decodedTree.value.map(([k]) => {
      if (k.kind !== "text") throw new Error("expected a text key");
      return k.value;
    });
    expect(keys).toEqual(["sign_pk", "agree_pk", "member_cap"]);
  });
});

// ------------------------------------------------------------------------------------------------
// NEUTER-VERIFICATION: the settled spec's explicit acceptance criterion is that carrying `host_fp`
// on the wire (rather than deriving it in `@spindle/crypto`) must fail a test. This constant
// assertion plus the "extra host_fp key rejected" test below are exactly that pair.
// ------------------------------------------------------------------------------------------------
describe("neuter verification: no carried host_fp", () => {
  it("BUNDLE_ENTRY_FIELDS is exactly [sign_pk, agree_pk, member_cap]", () => {
    // Adding a `host_fp` field to `BundleEntry` (instead of deriving it downstream) would change
    // this constant immediately, breaking this assertion before any decode-side test even runs.
    expect(BUNDLE_ENTRY_FIELDS).toEqual(["sign_pk", "agree_pk", "member_cap"]);
  });

  it("rejects an entry map carrying an extra host_fp key", () => {
    const entryCbor = BundleEntry.toCbor(sampleEntry(0));
    const mutatedBytes = addUnknownKey(entryCbor, "host_fp", CborValue.bytes(new Uint8Array(32)));
    const mutated = canonicalDecode(mutatedBytes);
    const err = expectThrows(BundleWireError, () => BundleEntry.fromCbor(mutated));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("UnknownField");
    expect(err.protoError?.field).toBe("host_fp");
  });
});

describe("unknown fields", () => {
  it("rejects a bundle map carrying an unrecognized top-level key", () => {
    const bundleCbor = DeviceBootstrapBundle.toCbor(sampleBundle(1));
    const mutatedBytes = addUnknownKey(bundleCbor, "bogus", CborValue.uint(0));
    const err = expectThrows(BundleWireError, () =>
      DeviceBootstrapBundle.fromCanonicalBytes(mutatedBytes),
    );
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("UnknownField");
    expect(err.protoError?.field).toBe("bogus");
  });
});

describe("registry length cap", () => {
  it("accepts exactly MAX_REGISTRY_LEN and rejects one byte longer", () => {
    const ok = { ...sampleBundle(1), registry: "r".repeat(MAX_REGISTRY_LEN) };
    expect(() =>
      DeviceBootstrapBundle.fromCanonicalBytes(DeviceBootstrapBundle.toCanonicalBytes(ok)),
    ).not.toThrow();

    const tooLong = { ...sampleBundle(1), registry: "r".repeat(MAX_REGISTRY_LEN + 1) };
    const err = expectThrows(BundleWireError, () =>
      DeviceBootstrapBundle.fromCanonicalBytes(DeviceBootstrapBundle.toCanonicalBytes(tooLong)),
    );
    expect(err.kind).toBe("RegistryTooLong");
    expect(err.max).toBe(MAX_REGISTRY_LEN);
    expect(err.actual).toBe(MAX_REGISTRY_LEN + 1);
    // Redaction discipline: the message never echoes the registry string itself.
    expect(err.message).not.toContain("r".repeat(MAX_REGISTRY_LEN + 1));
  });
});

describe("entry count cap", () => {
  it("accepts exactly MAX_BUNDLE_ENTRIES and rejects one more", () => {
    const ok = sampleBundle(MAX_BUNDLE_ENTRIES);
    expect(() =>
      DeviceBootstrapBundle.fromCanonicalBytes(DeviceBootstrapBundle.toCanonicalBytes(ok)),
    ).not.toThrow();

    const tooMany = sampleBundle(MAX_BUNDLE_ENTRIES + 1);
    const err = expectThrows(BundleWireError, () =>
      DeviceBootstrapBundle.fromCanonicalBytes(DeviceBootstrapBundle.toCanonicalBytes(tooMany)),
    );
    expect(err.kind).toBe("TooManyEntries");
    expect(err.max).toBe(MAX_BUNDLE_ENTRIES);
    expect(err.actual).toBe(MAX_BUNDLE_ENTRIES + 1);
  });
});

describe("missing required keys and wrong types", () => {
  it("rejects a bundle missing registry", () => {
    const cbor = CborValue.map([
      ["v", CborValue.uint(1)],
      ["entries", CborValue.array([])],
      // registry omitted
    ]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(BundleWireError, () =>
      DeviceBootstrapBundle.fromCanonicalBytes(bytes),
    );
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("MissingField");
    expect(err.protoError?.field).toBe("registry");
  });

  it("rejects a bundle missing entries", () => {
    const cbor = CborValue.map([
      ["v", CborValue.uint(1)],
      ["registry", CborValue.text("nats://x")],
      // entries omitted
    ]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(BundleWireError, () =>
      DeviceBootstrapBundle.fromCanonicalBytes(bytes),
    );
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("MissingField");
    expect(err.protoError?.field).toBe("entries");
  });

  it("rejects a bundle whose registry has the wrong CBOR type", () => {
    const cbor = CborValue.map([
      ["v", CborValue.uint(1)],
      ["registry", CborValue.uint(123)],
      ["entries", CborValue.array([])],
    ]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(BundleWireError, () =>
      DeviceBootstrapBundle.fromCanonicalBytes(bytes),
    );
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("WrongType");
    expect(err.protoError?.field).toBe("registry");
  });

  it("rejects a bundle whose entries has the wrong CBOR type", () => {
    const cbor = CborValue.map([
      ["v", CborValue.uint(1)],
      ["registry", CborValue.text("nats://x")],
      ["entries", CborValue.text("not-an-array")],
    ]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(BundleWireError, () =>
      DeviceBootstrapBundle.fromCanonicalBytes(bytes),
    );
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("WrongType");
    expect(err.protoError?.field).toBe("entries");
  });

  it("rejects an entry missing sign_pk", () => {
    const entryCbor = BundleEntry.toCbor(sampleEntry(0));
    if (entryCbor.kind !== "map") throw new Error("expected a map");
    const pruned: CborValueType = {
      kind: "map",
      value: entryCbor.value.filter(([k]) => !(k.kind === "text" && k.value === "sign_pk")),
    };
    const err = expectThrows(BundleWireError, () => BundleEntry.fromCbor(pruned));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("MissingField");
    expect(err.protoError?.field).toBe("sign_pk");
  });

  it("rejects an entry missing member_cap", () => {
    const entryCbor = BundleEntry.toCbor(sampleEntry(0));
    if (entryCbor.kind !== "map") throw new Error("expected a map");
    const pruned: CborValueType = {
      kind: "map",
      value: entryCbor.value.filter(([k]) => !(k.kind === "text" && k.value === "member_cap")),
    };
    const err = expectThrows(BundleWireError, () => BundleEntry.fromCbor(pruned));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("MissingField");
    expect(err.protoError?.field).toBe("member_cap");
  });

  it("rejects an entry whose sign_pk has the wrong CBOR type", () => {
    const cbor = CborValue.map([
      ["sign_pk", CborValue.text("not-bytes")],
      ["agree_pk", CborValue.bytes(new Uint8Array(32))],
      ["member_cap", Capability.toCbor(sampleCapability(0))],
    ]);
    const err = expectThrows(BundleWireError, () => BundleEntry.fromCbor(cbor));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("WrongType");
    expect(err.protoError?.field).toBe("sign_pk");
  });

  it("rejects an entry whose member_cap is missing a required inner field", () => {
    const capCbor = Capability.toCbor(sampleCapability(0));
    if (capCbor.kind !== "map") throw new Error("expected a map");
    const prunedCap: CborValueType = {
      kind: "map",
      value: capCbor.value.filter(([k]) => !(k.kind === "text" && k.value === "sig")),
    };
    const cbor = CborValue.map([
      ["sign_pk", CborValue.bytes(new Uint8Array(32).fill(1))],
      ["agree_pk", CborValue.bytes(new Uint8Array(32).fill(2))],
      ["member_cap", prunedCap],
    ]);
    const err = expectThrows(BundleWireError, () => BundleEntry.fromCbor(cbor));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("MissingField");
    expect(err.protoError?.field).toBe("sig");
  });
});

describe("BUNDLE_FIELDS", () => {
  it("contains exactly v, registry, entries", () => {
    expect([...BUNDLE_FIELDS].sort()).toEqual(["entries", "registry", "v"].sort());
  });
});

describe("non-canonical encoding rejection", () => {
  it("rejects a swapped top-level key order via ProtoError/Cbor/MapKeyOrder", () => {
    const bundle = sampleBundle(1);
    const canonicalBytes = DeviceBootstrapBundle.toCanonicalBytes(bundle);
    const mapValue = canonicalDecode(canonicalBytes);
    if (mapValue.kind !== "map") throw new Error("expected a map");
    const swapped: CborValueType = {
      kind: "map",
      value: [mapValue.value[1], mapValue.value[0], ...mapValue.value.slice(2)],
    };
    // Hand-encode the deliberately out-of-order map with a raw array-encoder (not
    // `canonicalEncode`, which would just re-sort it back into order) by writing the map header
    // and each already-encoded entry directly.
    const entryBytes = swapped.value.map(
      ([k, v]) => [canonicalEncode(k), canonicalEncode(v)] as const,
    );
    const totalLen =
      1 + entryBytes.reduce((sum, [k, v]) => sum + k.length + v.length, 0);
    const out = new Uint8Array(totalLen);
    out[0] = (5 << 5) | entryBytes.length; // map major type, definite-length count (small)
    let offset = 1;
    for (const [k, v] of entryBytes) {
      out.set(k, offset);
      offset += k.length;
      out.set(v, offset);
      offset += v.length;
    }
    const err = expectThrows(BundleWireError, () => DeviceBootstrapBundle.fromCanonicalBytes(out));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("Cbor");
    expect(err.protoError?.cborError?.kind).toBe("MapKeyOrder");
  });
});

// ------------------------------------------------------------------------------------------------
// Golden-vector conformance (vectors/bootstrap.json) — the cross-language check: any mismatch here
// means the TypeScript encoder disagrees with the Rust encoder that produced this vector file
// (`cargo run -p spindle-proto --bin gen-vectors`). Structured like `vectors.test.ts`'s
// `runArtifactSuite`, but standalone rather than folded into that shared helper: the bundle is not
// one of the eight A7b signed artifacts `vectors.test.ts` is scoped to (its header comment says so
// explicitly) — no `domain_tag`, no `signing_input_hex` — matching why `signaling.json` (also
// unsigned) gets its own dedicated test file rather than living in `vectors.test.ts`.
//
// NOTE ON DECODED SHAPE: `bootstrap.json`'s `decoded` field is the generic `{type, value}`
// CBOR-tree shape (shared with `signaling.json`/`canonical-cbor.json`/`AdminCommand.args`) rather
// than the flat field/hex-string object `capability.json` etc. use — see `parseBootstrapBundle`'s
// doc comment in `helpers.ts`.
// ------------------------------------------------------------------------------------------------

interface BootstrapCase {
  name: string;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  decoded: any;
  canonical_cbor_hex: string;
}

interface BootstrapDoc {
  description: string;
  cases: BootstrapCase[];
}

function firstUintFieldKey(mapValue: CborValueType): string {
  if (mapValue.kind !== "map") throw new Error("firstUintFieldKey: not a map");
  for (const [k, v] of mapValue.value) {
    if (k.kind === "text" && v.kind === "uint") return k.value;
  }
  throw new Error("firstUintFieldKey: no uint-valued field found");
}

describe("vectors/bootstrap.json", () => {
  const doc = loadVectorFile("bootstrap.json") as BootstrapDoc;

  for (const c of doc.cases) {
    describe(c.name, () => {
      it("encodes `decoded` to canonical_cbor_hex", () => {
        const value = parseBootstrapBundle(c.decoded);
        expect(bytesToHex(DeviceBootstrapBundle.toCanonicalBytes(value))).toBe(
          c.canonical_cbor_hex,
        );
      });

      it("decodes canonical_cbor_hex back to `decoded`", () => {
        const expectedValue = parseBootstrapBundle(c.decoded);
        const decoded = DeviceBootstrapBundle.fromCanonicalBytes(hexToBytes(c.canonical_cbor_hex));
        expect(normalize(decoded)).toEqual(normalize(expectedValue));
      });

      it("re-encoding the decoded struct reproduces canonical_cbor_hex", () => {
        const decoded = DeviceBootstrapBundle.fromCanonicalBytes(hexToBytes(c.canonical_cbor_hex));
        expect(bytesToHex(DeviceBootstrapBundle.toCanonicalBytes(decoded))).toBe(
          c.canonical_cbor_hex,
        );
      });
    });
  }

  describe("mutation rejection (first case)", () => {
    const first = doc.cases[0];
    const mapValue = canonicalDecode(hexToBytes(first.canonical_cbor_hex));

    it("rejects a swapped key order", () => {
      const mutated = swapFirstTwoEntries(mapValue);
      const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
      expect(cborErr.kind).toBe("MapKeyOrder");
      const err = expectThrows(BundleWireError, () =>
        DeviceBootstrapBundle.fromCanonicalBytes(mutated),
      );
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("Cbor");
      expect(err.protoError?.cborError?.kind).toBe("MapKeyOrder");
    });

    it("rejects a lengthened (non-shortest-form) integer field", () => {
      const key = firstUintFieldKey(mapValue);
      const mutated = lengthenUintField(mapValue, key);
      const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
      expect(cborErr.kind).toBe("NonShortestForm");
      const err = expectThrows(BundleWireError, () =>
        DeviceBootstrapBundle.fromCanonicalBytes(mutated),
      );
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("Cbor");
      expect(err.protoError?.cborError?.kind).toBe("NonShortestForm");
    });

    it("rejects an unrecognized field", () => {
      const mutated = addUnknownKey(mapValue, "bogus", CborValue.uint(0));
      expect(() => canonicalDecode(mutated)).not.toThrow();
      const err = expectThrows(BundleWireError, () =>
        DeviceBootstrapBundle.fromCanonicalBytes(mutated),
      );
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("UnknownField");
      expect(err.protoError?.field).toBe("bogus");
    });
  });

  describe("mutation rejection: nested entry map (one_entry_bundle)", () => {
    // Bonus coverage beyond the bundle-level mutations above: `swapFirstTwoEntries` here mutates a
    // *nested* `BundleEntry` map instead of the top-level bundle map. `CborValue` has no
    // "pre-encoded raw bytes" leaf to splice the mutated entry's bytes back into the surrounding
    // array/map tree via `canonicalEncode` (it would just re-sort the entry back into canonical
    // order), so — following the same hand-splice technique this file's own "non-canonical
    // encoding rejection" test above already uses for the top-level case — the mutated entry's raw
    // bytes are spliced directly into a hand-built outer map, leaving the two untouched top-level
    // fields (`v`, `registry`) normally canonical-encoded. Canonical top-level key order (v(1) <
    // entries(7) < registry(8), per `BUNDLE_FIELDS`'s doc comment in `bootstrap.ts`) is preserved
    // so only the nested entry is non-canonical.
    it("rejects a swapped key order inside a nested BundleEntry map", () => {
      const first = doc.cases.find((c) => c.name === "one_entry_bundle");
      if (first === undefined) throw new Error("vector case `one_entry_bundle` not found");
      const mapValue = canonicalDecode(hexToBytes(first.canonical_cbor_hex));
      if (mapValue.kind !== "map") throw new Error("expected a map");

      const vPair = mapValue.value.find(([k]) => k.kind === "text" && k.value === "v");
      const registryPair = mapValue.value.find(
        ([k]) => k.kind === "text" && k.value === "registry",
      );
      const entriesPair = mapValue.value.find(([k]) => k.kind === "text" && k.value === "entries");
      if (vPair === undefined || registryPair === undefined || entriesPair === undefined) {
        throw new Error("expected v/registry/entries fields");
      }
      const entriesArray = entriesPair[1];
      if (entriesArray.kind !== "array" || entriesArray.value.length !== 1) {
        throw new Error("expected a single-entry array");
      }
      const entryMap = entriesArray.value[0];
      const mutatedEntryBytes = swapFirstTwoEntries(entryMap);

      const vBytes = [...canonicalEncode(vPair[0]), ...canonicalEncode(vPair[1])];
      const registryBytes = [
        ...canonicalEncode(registryPair[0]),
        ...canonicalEncode(registryPair[1]),
      ];
      const entriesKeyBytes = canonicalEncode(entriesPair[0]);
      const out = Uint8Array.from([
        (5 << 5) | 3, // map major type, 3 entries — v, entries, registry, in canonical order
        ...vBytes,
        ...entriesKeyBytes,
        (4 << 5) | 1, // array major type, definite length 1
        ...mutatedEntryBytes,
        ...registryBytes,
      ]);

      const err = expectThrows(BundleWireError, () => DeviceBootstrapBundle.fromCanonicalBytes(out));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("Cbor");
      expect(err.protoError?.cborError?.kind).toBe("MapKeyOrder");
    });
  });
});
