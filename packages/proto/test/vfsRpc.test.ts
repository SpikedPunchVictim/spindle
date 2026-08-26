// Golden-vector conformance for the VFS RPC wire types (vectors/vfs-rpc.json) — the TS twin of
// `crates/spindle-proto/src/vfs_rpc.rs`. Covers both Stage 6 slice 3 (list/stat/read/mkdir/
// delete/whoami, eight error codes) and slice 4 (upload_open/upload_chunk/upload_commit/
// upload_abort, plus the `already_exists`/`file_changed` error codes added by the DESIGN.md
// v0.9.10 amendment). Unlike the seven A7b artifact vector files (see vectors.test.ts),
// vfs-rpc.json's `decoded` field is the same generic `{type, value}` CBOR-tree mirror
// canonical-cbor.json uses (see vectors/README.md's "vfs-rpc.json's shape" note) rather than a
// bespoke per-op JSON shape, since the ten ops carry different field sets. So each case is
// cross-checked three ways: (1) the generic tree round-trips to canonical_cbor_hex independent of
// this package's typed layer entirely (same check canonical.test.ts does), (2) the typed decoder
// (`VfsRequestEnvelope.fromCbor` / `VfsReply.fromCbor`) accepts that same generic tree and
// re-encodes it byte-identically, and (3) decoding canonical_cbor_hex directly through the typed
// layer reproduces the same typed value and re-encodes byte-identically. (2) and (3) together are
// the "decodes, re-encodes byte-identically, matches expected structure" check. The suite iterates
// every case in `doc.requests`/`doc.replies` (not a fixed count), so it automatically covers
// whatever `vectors/vfs-rpc.json` currently contains.
//
// Plus negative tests per the established convention (vectors.test.ts's "mutation rejection"
// block): swapped key order, a lengthened (non-shortest-form) integer field, and an unrecognized
// field, each asserted to be rejected — plus a few hand-rolled tests translating
// `vfs_rpc.rs`'s own inline unit tests (invalid op/error-code discriminants, out-of-range perms
// bitset, missing required field) that don't need vector coverage since they exercise rejection
// paths no golden vector encodes.

import { describe, expect, it } from "vitest";

import { CborError, CborValue, canonicalDecode, canonicalEncode, type CborValue as CborValueType } from "../src/canonical.js";
import { bytesToHex, hexToBytes } from "../src/hex.js";
import { ProtoError } from "../src/artifacts.js";
import {
  CURRENT_PROTOCOL_VERSION,
  DirEntry,
  EntryKind,
  MAX_LIST_PAGE,
  MAX_READ_CHUNK,
  MAX_UPLOAD_CHUNK,
  MIN_PROTOCOL_VERSION,
  UPLOAD_SESSION_TTL_SECS,
  VfsErrorCode,
  VfsPerms,
  VfsReply,
  VfsRequestEnvelope,
  vfsPermsContains,
  vfsPermsUnion,
} from "../src/vfsRpc.js";
import {
  addUnknownKey,
  lengthenUintField,
  loadVectorFile,
  normalize,
  parseCborTree,
  swapFirstTwoEntries,
} from "./helpers.js";

interface RpcCase {
  name: string;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  decoded: any;
  canonical_cbor_hex: string;
}

interface RpcDoc {
  description: string;
  requests: RpcCase[];
  replies: RpcCase[];
}

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

function firstUintFieldKey(mapValue: CborValueType): string {
  if (mapValue.kind !== "map") throw new Error("firstUintFieldKey: not a map");
  for (const [k, v] of mapValue.value) {
    if (k.kind === "text" && v.kind === "uint") return k.value;
  }
  throw new Error("firstUintFieldKey: no uint-valued field found");
}

const doc = loadVectorFile("vfs-rpc.json") as RpcDoc;

describe("vfs-rpc.json requests", () => {
  doc.requests.forEach((c, i) => {
    describe(`${c.name} [${i}]`, () => {
      it("generic CBOR tree round-trips to canonical_cbor_hex", () => {
        const tree = parseCborTree(c.decoded);
        expect(bytesToHex(canonicalEncode(tree))).toBe(c.canonical_cbor_hex);
      });

      it("typed decoder parses the vector's tree and re-encodes byte-identically", () => {
        const tree = parseCborTree(c.decoded);
        const typed = VfsRequestEnvelope.fromCbor(tree);
        expect(bytesToHex(VfsRequestEnvelope.toCanonicalBytes(typed))).toBe(c.canonical_cbor_hex);
      });

      it("decodes canonical_cbor_hex to the same typed value and re-encodes byte-identically", () => {
        const expected = VfsRequestEnvelope.fromCbor(parseCborTree(c.decoded));
        const decoded = VfsRequestEnvelope.fromCanonicalBytes(hexToBytes(c.canonical_cbor_hex));
        expect(normalize(decoded)).toEqual(normalize(expected));
        expect(bytesToHex(VfsRequestEnvelope.toCanonicalBytes(decoded))).toBe(c.canonical_cbor_hex);
      });
    });
  });

  describe("mutation rejection (first case)", () => {
    const first = doc.requests[0];
    const mapValue = canonicalDecode(hexToBytes(first.canonical_cbor_hex));

    it("rejects a swapped key order", () => {
      const mutated = swapFirstTwoEntries(mapValue);
      const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
      expect(cborErr.kind).toBe("MapKeyOrder");
      const protoErr = expectThrows(ProtoError, () => VfsRequestEnvelope.fromCanonicalBytes(mutated));
      expect(protoErr.kind).toBe("Cbor");
      expect(protoErr.cborError?.kind).toBe("MapKeyOrder");
    });

    it("rejects a lengthened (non-shortest-form) integer field", () => {
      const key = firstUintFieldKey(mapValue);
      const mutated = lengthenUintField(mapValue, key);
      const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
      expect(cborErr.kind).toBe("NonShortestForm");
      const protoErr = expectThrows(ProtoError, () => VfsRequestEnvelope.fromCanonicalBytes(mutated));
      expect(protoErr.kind).toBe("Cbor");
      expect(protoErr.cborError?.kind).toBe("NonShortestForm");
    });

    it("rejects an unrecognized field", () => {
      const mutated = addUnknownKey(mapValue, "bogus", CborValue.uint(0));
      expect(() => canonicalDecode(mutated)).not.toThrow();
      const protoErr = expectThrows(ProtoError, () => VfsRequestEnvelope.fromCanonicalBytes(mutated));
      expect(protoErr.kind).toBe("UnknownField");
      expect(protoErr.field).toBe("bogus");
    });
  });
});

describe("vfs-rpc.json replies", () => {
  doc.replies.forEach((c, i) => {
    describe(`${c.name} [${i}]`, () => {
      it("generic CBOR tree round-trips to canonical_cbor_hex", () => {
        const tree = parseCborTree(c.decoded);
        expect(bytesToHex(canonicalEncode(tree))).toBe(c.canonical_cbor_hex);
      });

      it("typed decoder parses the vector's tree and re-encodes byte-identically", () => {
        const tree = parseCborTree(c.decoded);
        const typed = VfsReply.fromCbor(tree);
        expect(bytesToHex(VfsReply.toCanonicalBytes(typed))).toBe(c.canonical_cbor_hex);
      });

      it("decodes canonical_cbor_hex to the same typed value and re-encodes byte-identically", () => {
        const expected = VfsReply.fromCbor(parseCborTree(c.decoded));
        const decoded = VfsReply.fromCanonicalBytes(hexToBytes(c.canonical_cbor_hex));
        expect(normalize(decoded)).toEqual(normalize(expected));
        expect(bytesToHex(VfsReply.toCanonicalBytes(decoded))).toBe(c.canonical_cbor_hex);
      });
    });
  });

  describe("mutation rejection (first case)", () => {
    const first = doc.replies[0];
    const mapValue = canonicalDecode(hexToBytes(first.canonical_cbor_hex));

    it("rejects a swapped key order", () => {
      const mutated = swapFirstTwoEntries(mapValue);
      const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
      expect(cborErr.kind).toBe("MapKeyOrder");
      const protoErr = expectThrows(ProtoError, () => VfsReply.fromCanonicalBytes(mutated));
      expect(protoErr.kind).toBe("Cbor");
      expect(protoErr.cborError?.kind).toBe("MapKeyOrder");
    });

    it("rejects a lengthened (non-shortest-form) integer field", () => {
      const key = firstUintFieldKey(mapValue);
      const mutated = lengthenUintField(mapValue, key);
      const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
      expect(cborErr.kind).toBe("NonShortestForm");
      const protoErr = expectThrows(ProtoError, () => VfsReply.fromCanonicalBytes(mutated));
      expect(protoErr.kind).toBe("Cbor");
      expect(protoErr.cborError?.kind).toBe("NonShortestForm");
    });

    it("rejects an unrecognized field", () => {
      const mutated = addUnknownKey(mapValue, "bogus", CborValue.uint(0));
      expect(() => canonicalDecode(mutated)).not.toThrow();
      const protoErr = expectThrows(ProtoError, () => VfsReply.fromCanonicalBytes(mutated));
      expect(protoErr.kind).toBe("UnknownField");
      expect(protoErr.field).toBe("bogus");
    });
  });
});

// ------------------------------------------------------------------------------------------------
// Hand-rolled parity tests translating vfs_rpc.rs's own inline `#[cfg(test)]` unit tests — these
// exercise round-tripping and rejection paths no golden vector encodes (constructed values,
// invalid discriminants), so they can't be vector-driven.
// ------------------------------------------------------------------------------------------------

describe("round-trips every request/reply variant (vfs_rpc.rs parity)", () => {
  function rtReq(env: VfsRequestEnvelope) {
    const bytes = VfsRequestEnvelope.toCanonicalBytes(env);
    const decoded = VfsRequestEnvelope.fromCanonicalBytes(bytes);
    expect(normalize(decoded)).toEqual(normalize(env));
  }

  function rtReply(reply: VfsReply) {
    const bytes = VfsReply.toCanonicalBytes(reply);
    const decoded = VfsReply.fromCanonicalBytes(bytes);
    expect(normalize(decoded)).toEqual(normalize(reply));
  }

  it("every request variant", () => {
    rtReq({ v: 1, request: { op: "list", path: "Photos/Vacation" } });
    rtReq({
      v: 1,
      request: { op: "list", path: "Photos", cursor: Uint8Array.from([1, 2, 3]), limit: 50 },
    });
    rtReq({ v: 1, request: { op: "stat", path: "Photos/img.jpg" } });
    rtReq({ v: 1, request: { op: "read", path: "Photos/img.jpg", offset: 65536n, len: 65536 } });
    rtReq({ v: 1, request: { op: "mkdir", path: "Photos/NewAlbum" } });
    rtReq({ v: 1, request: { op: "delete", path: "Photos/old.jpg" } });
    rtReq({ v: 1, request: { op: "whoami" } });
    rtReq({
      v: 1,
      request: {
        op: "upload_open",
        path: "Drop/incoming.bin",
        size: 1048576n,
        hash: new Uint8Array(32).fill(0xaa),
        manifest_sig: new Uint8Array(64).fill(0xbb),
      },
    });
    rtReq({
      v: 1,
      request: {
        op: "upload_chunk",
        session_id: new Uint8Array(16).fill(0x03),
        offset: 65536n,
        data: new Uint8Array(128).fill(0xcc),
      },
    });
    rtReq({
      v: 1,
      request: { op: "upload_commit", session_id: new Uint8Array(16).fill(0x03) },
    });
    rtReq({
      v: 1,
      request: { op: "upload_abort", session_id: new Uint8Array(16).fill(0x03) },
    });
  });

  it("every reply variant", () => {
    rtReply({
      op: "list",
      entries: [
        {
          name: "Vacation",
          kind: EntryKind.Dir,
          size: 0n,
          mtime: 1000n,
          perms_here: VfsPerms.BROWSE,
        },
      ],
      next_cursor: Uint8Array.from([9, 9]),
    });
    rtReply({ op: "list", entries: [] });
    rtReply({
      op: "stat",
      kind: EntryKind.File,
      size: 4096n,
      mtime: 2000n,
      perms_here: vfsPermsUnion(VfsPerms.BROWSE, VfsPerms.DOWNLOAD),
    });
    rtReply({ op: "read", data: new Uint8Array(128).fill(0xab), eof: true });
    rtReply({ op: "mkdir" });
    rtReply({ op: "delete" });
    rtReply({
      op: "whoami",
      member_display: "Alex",
      effective_paths: ["Photos/Vacation", "Drop"],
    });
    rtReply({
      op: "upload_open",
      session_id: new Uint8Array(16).fill(0x03),
      offset: 0n,
    });
    rtReply({
      op: "upload_open",
      session_id: new Uint8Array(16).fill(0x03),
      offset: 65536n,
    });
    rtReply({ op: "upload_chunk", offset: 131072n });
    rtReply({ op: "upload_commit" });
    rtReply({ op: "upload_abort" });
    for (const code of [
      VfsErrorCode.NotFound,
      VfsErrorCode.QuotaExceeded,
      VfsErrorCode.GrantsChanged,
      VfsErrorCode.ResumeExpired,
      VfsErrorCode.UploadRejected,
      VfsErrorCode.StorageFull,
      VfsErrorCode.Throttled,
      VfsErrorCode.UnsupportedVersion,
      VfsErrorCode.AlreadyExists,
      VfsErrorCode.FileChanged,
    ]) {
      rtReply({ op: "error", code });
    }
  });
});

describe("rejection parity with vfs_rpc.rs's inline unit tests", () => {
  it("rejects an unknown field", () => {
    const cbor = VfsRequestEnvelope.toCbor({ v: 1, request: { op: "whoami" } });
    if (cbor.kind !== "map") throw new Error("expected map");
    cbor.value.push([CborValue.text("bogus"), CborValue.uint(1)]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(ProtoError, () => VfsRequestEnvelope.fromCanonicalBytes(bytes));
    expect(err.kind).toBe("UnknownField");
    expect(err.field).toBe("bogus");
  });

  it("rejects a missing required field", () => {
    const cbor = VfsRequestEnvelope.toCbor({ v: 1, request: { op: "stat", path: "x" } });
    if (cbor.kind !== "map") throw new Error("expected map");
    cbor.value = cbor.value.filter(([k]) => !(k.kind === "text" && k.value === "path"));
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(ProtoError, () => VfsRequestEnvelope.fromCanonicalBytes(bytes));
    expect(err.kind).toBe("MissingField");
    expect(err.field).toBe("path");
  });

  it("rejects an invalid op discriminant and an invalid error code", () => {
    const badOp = CborValue.map([
      ["v", CborValue.uint(1)],
      ["op", CborValue.uint(99)],
    ]);
    const opErr = expectThrows(ProtoError, () =>
      VfsRequestEnvelope.fromCanonicalBytes(canonicalEncode(badOp)),
    );
    expect(opErr.kind).toBe("InvalidEnumValue");
    expect(opErr.field).toBe("op");
    expect(opErr.enumValue).toBe(99n);

    const badCode = CborValue.map([
      ["op", CborValue.uint(10)],
      ["code", CborValue.uint(99)],
    ]);
    const codeErr = expectThrows(ProtoError, () =>
      VfsReply.fromCanonicalBytes(canonicalEncode(badCode)),
    );
    expect(codeErr.kind).toBe("InvalidEnumValue");
    expect(codeErr.field).toBe("code");
    expect(codeErr.enumValue).toBe(99n);
  });

  it("rejects an out-of-range perms bitset", () => {
    const cbor = CborValue.map([
      ["op", CborValue.uint(1)],
      ["kind", CborValue.uint(0)],
      ["size", CborValue.uint(0)],
      ["mtime", CborValue.uint(0)],
      ["perms_here", CborValue.uint(0xff)],
    ]);
    const err = expectThrows(ProtoError, () =>
      VfsReply.fromCanonicalBytes(canonicalEncode(cbor)),
    );
    expect(err.kind).toBe("IntOutOfRange");
    expect(err.field).toBe("perms_here");
  });

  it("rejects an unknown field on an upload op (slice 4 parity)", () => {
    const cbor = VfsRequestEnvelope.toCbor({
      v: 1,
      request: { op: "upload_commit", session_id: Uint8Array.from([1]) },
    });
    if (cbor.kind !== "map") throw new Error("expected map");
    cbor.value.push([CborValue.text("bogus"), CborValue.uint(1)]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(ProtoError, () => VfsRequestEnvelope.fromCanonicalBytes(bytes));
    expect(err.kind).toBe("UnknownField");
    expect(err.field).toBe("bogus");
  });

  it("rejects a missing required field on upload_open (slice 4 parity)", () => {
    const cbor = VfsRequestEnvelope.toCbor({
      v: 1,
      request: {
        op: "upload_open",
        path: "x",
        size: 1n,
        hash: Uint8Array.from([1]),
        manifest_sig: Uint8Array.from([2]),
      },
    });
    if (cbor.kind !== "map") throw new Error("expected map");
    cbor.value = cbor.value.filter(([k]) => !(k.kind === "text" && k.value === "hash"));
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(ProtoError, () => VfsRequestEnvelope.fromCanonicalBytes(bytes));
    expect(err.kind).toBe("MissingField");
    expect(err.field).toBe("hash");
  });
});

describe("constants and bitset helpers (vfs_rpc.rs parity)", () => {
  it("MAX_READ_CHUNK and MAX_UPLOAD_CHUNK are both 64 KiB", () => {
    expect(MAX_READ_CHUNK).toBe(65536);
    expect(MAX_UPLOAD_CHUNK).toBe(65536);
  });

  it("MAX_LIST_PAGE, protocol version, and upload session TTL constants match the Rust twin", () => {
    expect(MAX_LIST_PAGE).toBe(500);
    expect(MIN_PROTOCOL_VERSION).toBe(1);
    expect(CURRENT_PROTOCOL_VERSION).toBe(1);
    expect(UPLOAD_SESSION_TTL_SECS).toBe(48 * 60 * 60);
  });

  it("all ten error codes are distinct and round-trip their u64 discriminant", () => {
    const codes = [
      VfsErrorCode.NotFound,
      VfsErrorCode.QuotaExceeded,
      VfsErrorCode.GrantsChanged,
      VfsErrorCode.ResumeExpired,
      VfsErrorCode.UploadRejected,
      VfsErrorCode.StorageFull,
      VfsErrorCode.Throttled,
      VfsErrorCode.UnsupportedVersion,
      VfsErrorCode.AlreadyExists,
      VfsErrorCode.FileChanged,
    ];
    codes.forEach((c, i) => expect(c).toBe(i));
  });

  it("vfsPermsUnion / vfsPermsContains mirror Rust's VfsPerms::union/contains", () => {
    const both = vfsPermsUnion(VfsPerms.BROWSE, VfsPerms.DOWNLOAD);
    expect(vfsPermsContains(both, VfsPerms.BROWSE)).toBe(true);
    expect(vfsPermsContains(both, VfsPerms.DOWNLOAD)).toBe(true);
    expect(vfsPermsContains(both, VfsPerms.UPLOAD)).toBe(false);
  });
});

describe("DirEntry (embedded shape, no top-level canonical-bytes wrapper — mirrors Rust)", () => {
  it("round-trips through to_cbor/from_cbor", () => {
    const entry: DirEntry = {
      name: "Vacation",
      kind: EntryKind.Dir,
      size: 0n,
      mtime: 1000n,
      perms_here: VfsPerms.BROWSE,
    };
    const decoded = DirEntry.fromCbor(DirEntry.toCbor(entry));
    expect(normalize(decoded)).toEqual(normalize(entry));
  });
});
