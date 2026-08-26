// VFS RPC wire types (DESIGN.md §A8 "VFS RPC" + "VFS error model"), Stage 6 slice 3 — the
// TypeScript twin of `crates/spindle-proto/src/vfs_rpc.rs`.
//
// These types carry the six read-side/metadata VFS operations across the control channel/stream
// once a session is authenticated — they are **not** one of the seven A7b signed-artifact kinds
// (no domain-separation tag, no `sig` field, no `tags.ts` involvement): §A8 places VFS RPC
// *inside* the already-authenticated, already-encrypted session, so per-message signing would be
// redundant with the transport's own integrity guarantee. Like every other wire type in this
// package, encoding is this package's canonical CBOR (`./canonical.js`) with the same
// closed-schema/strict-type discipline `artifacts.ts` uses (unknown fields rejected, missing
// required fields rejected) — this module reuses `artifacts.ts`'s `MapReader` and
// `decodeCanonicalOrThrow`, exactly as the Rust twin reuses its own `MapReader` `pub(crate)`.
//
// Scope (Stage 6 slice 3 — mirrors the Rust module's documented scope): in — `list`, `stat`,
// `read` (chunked, offset/len), `mkdir`, `delete`, `whoami`, and the `VfsErrorCode` typed error
// model. Out (slice 4, not implemented here): `upload`'s resumable-session wire types. The Rust
// source's `VfsErrorCode` currently has 8 variants (DESIGN.md's seven named codes plus this
// crate's own `UnsupportedVersion` addition); a parallel Stage 6 slice 4 Rust change is adding
// `already_exists` and `file_changed` plus Upload op types, but as of this twin those do not yet
// exist in the Rust source or in `vectors/vfs-rpc.json` — see the note above `VfsErrorCode` below
// for why they are deliberately NOT included here yet.
//
// Field names, op discriminant values, and error-code discriminant values below are taken
// directly from `crates/spindle-proto/src/vfs_rpc.rs` and cross-checked against every case in
// `vectors/vfs-rpc.json` (see `test/vfsRpc.test.ts`).

import { MapReader, ProtoError, decodeCanonicalOrThrow } from "./artifacts.js";
import { CborValue, canonicalEncode } from "./canonical.js";

/** Minimum protocol version this schema's server-side implementations accept (DESIGN.md §A8). */
export const MIN_PROTOCOL_VERSION = 1;
/** The protocol version this schema currently implements/produces. */
export const CURRENT_PROTOCOL_VERSION = 1;

/** Server-enforced maximum number of entries in one `list` reply page (mirrors
 * `spindle_proto::vfs_rpc::MAX_LIST_PAGE`). */
export const MAX_LIST_PAGE = 500;

/** Maximum bytes in one `read` reply chunk (DESIGN.md §A8, verbatim: "64 KiB chunks"). */
export const MAX_READ_CHUNK = 64 * 1024;

// ================================================================================================
// Small closed-set enums (wire: small unsigned integers, per this package's established convention)
// ================================================================================================

/** A `list`/`stat` entry's kind (mirrors Rust's `EntryKind`). */
export enum EntryKind {
  File = 0,
  Dir = 1,
}

function entryKindToCbor(k: EntryKind): CborValue {
  return CborValue.uint(k);
}

function entryKindFromU64(v: bigint): EntryKind {
  if (v === 0n) return EntryKind.File;
  if (v === 1n) return EntryKind.Dir;
  throw ProtoError.invalidEnumValue("kind", v);
}

/** The four grantable permissions, as they cross the wire (mirrors Rust's `VfsPerms` bitset).
 * Represented as a plain validated `number` (0-15) rather than a wrapper class — this package's
 * existing preference for lean value representations (see `CapKind` in `artifacts.ts`). Bit
 * assignment matches the Rust type's (`browse=1, download=2, upload=4, delete=8`). */
export const VfsPerms = {
  NONE: 0,
  BROWSE: 1 << 0,
  DOWNLOAD: 1 << 1,
  UPLOAD: 1 << 2,
  DELETE: 1 << 3,
} as const;

/** All four bits set — the only values accepted on decode (closed schema: an out-of-range bitset
 * is rejected, not silently masked). */
const VFS_PERMS_MAX_VALID = 0b1111;

export function vfsPermsUnion(a: number, b: number): number {
  return a | b;
}

export function vfsPermsContains(perms: number, other: number): boolean {
  return (perms & other) === other;
}

function vfsPermsFromReader(m: MapReader, key: string): number {
  const bits = m.u8(key);
  if (bits > VFS_PERMS_MAX_VALID) throw ProtoError.intOutOfRange(key);
  return bits;
}

/** DESIGN.md §A8 "VFS error model": the typed error codes returned *inside* the authenticated
 * session. Mirrors Rust's `VfsErrorCode` (8 variants as of this twin: DESIGN.md's seven named
 * codes plus the Rust crate's own `UnsupportedVersion` addition).
 *
 * **`already_exists` / `file_changed` are deliberately NOT included yet**: a parallel Rust task
 * (Stage 6 slice 4) is adding these two codes plus Upload op types, but as of this twin's
 * authoring, `crates/spindle-proto/src/vfs_rpc.rs` has not landed them and `vectors/vfs-rpc.json`
 * has no vector exercising them — adding discriminant values here would be a guess, not a mirror.
 * Extension is a one-line addition per code (add the variant here, one `case` line in
 * `vfsErrorCodeFromU64` below) once the Rust enum and vectors land. */
export enum VfsErrorCode {
  /** The requested path does not exist, OR the caller is not authorized to see it. */
  NotFound = 0,
  /** A per-member/per-share/per-transfer quota was exceeded. */
  QuotaExceeded = 1,
  /** The member's effective grants changed since an in-flight operation began. */
  GrantsChanged = 2,
  /** A resumable upload session's TTL expired. */
  ResumeExpired = 3,
  /** An uploaded file was rejected. */
  UploadRejected = 4,
  /** The host's free-space floor was reached. */
  StorageFull = 5,
  /** A rate limit was hit (post-auth, per-session/per-member VFS-op rate limit). */
  Throttled = 6,
  /** The request's `v` was below the server's `MIN_PROTOCOL_VERSION`. */
  UnsupportedVersion = 7,
}

function vfsErrorCodeToCbor(c: VfsErrorCode): CborValue {
  return CborValue.uint(c);
}

function vfsErrorCodeFromU64(v: bigint): VfsErrorCode {
  switch (v) {
    case 0n:
      return VfsErrorCode.NotFound;
    case 1n:
      return VfsErrorCode.QuotaExceeded;
    case 2n:
      return VfsErrorCode.GrantsChanged;
    case 3n:
      return VfsErrorCode.ResumeExpired;
    case 4n:
      return VfsErrorCode.UploadRejected;
    case 5n:
      return VfsErrorCode.StorageFull;
    case 6n:
      return VfsErrorCode.Throttled;
    case 7n:
      return VfsErrorCode.UnsupportedVersion;
    default:
      throw ProtoError.invalidEnumValue("code", v);
  }
}

// ================================================================================================
// list/stat entry shape
// ================================================================================================

/** One `list` reply entry — DESIGN.md §A8: `entries[{name, kind, size, mtime, perms_here}]`
 * (mirrors Rust's `DirEntry`). */
export interface DirEntry {
  name: string;
  kind: EntryKind;
  size: bigint;
  mtime: bigint;
  perms_here: number;
}

const DIR_ENTRY_FIELDS = ["name", "kind", "size", "mtime", "perms_here"] as const;

export const DirEntry = {
  toCbor(e: DirEntry): CborValue {
    return CborValue.map([
      ["name", CborValue.text(e.name)],
      ["kind", entryKindToCbor(e.kind)],
      ["size", CborValue.uint(e.size)],
      ["mtime", CborValue.uint(e.mtime)],
      ["perms_here", CborValue.uint(e.perms_here)],
    ]);
  },

  fromCbor(v: CborValue): DirEntry {
    const m = new MapReader(v);
    m.denyUnknownFields(DIR_ENTRY_FIELDS);
    return {
      name: m.text("name"),
      kind: entryKindFromU64(m.u64("kind")),
      size: m.u64("size"),
      mtime: m.u64("mtime"),
      perms_here: vfsPermsFromReader(m, "perms_here"),
    };
  },
};

// ================================================================================================
// Op discriminants (package-internal, mirrors Rust's private `ReqOp`/`ReplyOp` enums)
// ================================================================================================

enum ReqOp {
  List = 0,
  Stat = 1,
  Read = 2,
  Mkdir = 3,
  Delete = 4,
  Whoami = 5,
}

function reqOpFromU64(v: bigint): ReqOp {
  switch (v) {
    case 0n:
      return ReqOp.List;
    case 1n:
      return ReqOp.Stat;
    case 2n:
      return ReqOp.Read;
    case 3n:
      return ReqOp.Mkdir;
    case 4n:
      return ReqOp.Delete;
    case 5n:
      return ReqOp.Whoami;
    default:
      throw ProtoError.invalidEnumValue("op", v);
  }
}

enum ReplyOp {
  List = 0,
  Stat = 1,
  Read = 2,
  Mkdir = 3,
  Delete = 4,
  Whoami = 5,
  Error = 6,
}

function replyOpFromU64(v: bigint): ReplyOp {
  switch (v) {
    case 0n:
      return ReplyOp.List;
    case 1n:
      return ReplyOp.Stat;
    case 2n:
      return ReplyOp.Read;
    case 3n:
      return ReplyOp.Mkdir;
    case 4n:
      return ReplyOp.Delete;
    case 5n:
      return ReplyOp.Whoami;
    case 6n:
      return ReplyOp.Error;
    default:
      throw ProtoError.invalidEnumValue("op", v);
  }
}

// ================================================================================================
// Requests
// ================================================================================================

/** One of the six in-scope VFS RPC requests (DESIGN.md §A8), tagged by `op` — the same field name
 * the wire discriminant uses, per this package's `CborValue`-style tagged-union convention. All
 * paths are virtual, `/`-separated UTF-8 text (mirrors Rust's `VfsRequest`). */
export type VfsRequest =
  | { op: "list"; path: string; cursor?: Uint8Array; limit?: number }
  | { op: "stat"; path: string }
  | { op: "read"; path: string; offset: bigint; len: number }
  | { op: "mkdir"; path: string }
  | { op: "delete"; path: string }
  | { op: "whoami" };

const LIST_REQ_FIELDS = ["v", "op", "path", "cursor", "limit"] as const;
const STAT_REQ_FIELDS = ["v", "op", "path"] as const;
const READ_REQ_FIELDS = ["v", "op", "path", "offset", "len"] as const;
const MKDIR_REQ_FIELDS = ["v", "op", "path"] as const;
const DELETE_REQ_FIELDS = ["v", "op", "path"] as const;
const WHOAMI_REQ_FIELDS = ["v", "op"] as const;

/** A `VfsRequest` plus the protocol-version field every request carries (mirrors Rust's
 * `VfsRequestEnvelope`). Encoded as a single flat CBOR map. */
export interface VfsRequestEnvelope {
  v: number;
  request: VfsRequest;
}

export const VfsRequestEnvelope = {
  toCbor(env: VfsRequestEnvelope): CborValue {
    const vEntry: [string, CborValue] = ["v", CborValue.uint(env.v)];
    const req = env.request;
    let entries: Array<[string, CborValue]>;
    switch (req.op) {
      case "list": {
        entries = [vEntry, ["op", CborValue.uint(ReqOp.List)], ["path", CborValue.text(req.path)]];
        if (req.cursor !== undefined) entries.push(["cursor", CborValue.bytes(req.cursor)]);
        if (req.limit !== undefined) entries.push(["limit", CborValue.uint(req.limit)]);
        break;
      }
      case "stat":
        entries = [vEntry, ["op", CborValue.uint(ReqOp.Stat)], ["path", CborValue.text(req.path)]];
        break;
      case "read":
        entries = [
          vEntry,
          ["op", CborValue.uint(ReqOp.Read)],
          ["path", CborValue.text(req.path)],
          ["offset", CborValue.uint(req.offset)],
          ["len", CborValue.uint(req.len)],
        ];
        break;
      case "mkdir":
        entries = [vEntry, ["op", CborValue.uint(ReqOp.Mkdir)], ["path", CborValue.text(req.path)]];
        break;
      case "delete":
        entries = [vEntry, ["op", CborValue.uint(ReqOp.Delete)], ["path", CborValue.text(req.path)]];
        break;
      case "whoami":
        entries = [vEntry, ["op", CborValue.uint(ReqOp.Whoami)]];
        break;
    }
    return CborValue.map(entries);
  },

  toCanonicalBytes(env: VfsRequestEnvelope): Uint8Array {
    return canonicalEncode(VfsRequestEnvelope.toCbor(env));
  },

  fromCbor(v: CborValue): VfsRequestEnvelope {
    const m = new MapReader(v);
    const ver = m.u8("v");
    const op = reqOpFromU64(m.u64("op"));
    let request: VfsRequest;
    switch (op) {
      case ReqOp.List:
        m.denyUnknownFields(LIST_REQ_FIELDS);
        request = {
          op: "list",
          path: m.text("path"),
          cursor: m.optionalBytes("cursor"),
          limit: m.optionalU32("limit"),
        };
        break;
      case ReqOp.Stat:
        m.denyUnknownFields(STAT_REQ_FIELDS);
        request = { op: "stat", path: m.text("path") };
        break;
      case ReqOp.Read:
        m.denyUnknownFields(READ_REQ_FIELDS);
        request = { op: "read", path: m.text("path"), offset: m.u64("offset"), len: m.u32("len") };
        break;
      case ReqOp.Mkdir:
        m.denyUnknownFields(MKDIR_REQ_FIELDS);
        request = { op: "mkdir", path: m.text("path") };
        break;
      case ReqOp.Delete:
        m.denyUnknownFields(DELETE_REQ_FIELDS);
        request = { op: "delete", path: m.text("path") };
        break;
      case ReqOp.Whoami:
        m.denyUnknownFields(WHOAMI_REQ_FIELDS);
        request = { op: "whoami" };
        break;
    }
    return { v: ver, request };
  },

  fromCanonicalBytes(bytes: Uint8Array): VfsRequestEnvelope {
    return VfsRequestEnvelope.fromCbor(decodeCanonicalOrThrow(bytes));
  },
};

// ================================================================================================
// Replies
// ================================================================================================

/** One of the six in-scope VFS RPC replies, or the `error` reply (DESIGN.md §A8's error model),
 * tagged by `op` (mirrors Rust's `VfsReply`). */
export type VfsReply =
  | { op: "list"; entries: DirEntry[]; next_cursor?: Uint8Array }
  | { op: "stat"; kind: EntryKind; size: bigint; mtime: bigint; perms_here: number }
  | { op: "read"; data: Uint8Array; eof: boolean }
  | { op: "mkdir" }
  | { op: "delete" }
  | { op: "whoami"; member_display: string; effective_paths: string[] }
  | { op: "error"; code: VfsErrorCode };

const LIST_REPLY_FIELDS = ["op", "entries", "next_cursor"] as const;
const STAT_REPLY_FIELDS = ["op", "kind", "size", "mtime", "perms_here"] as const;
const READ_REPLY_FIELDS = ["op", "data", "eof"] as const;
const MKDIR_REPLY_FIELDS = ["op"] as const;
const DELETE_REPLY_FIELDS = ["op"] as const;
const WHOAMI_REPLY_FIELDS = ["op", "member_display", "effective_paths"] as const;
const ERROR_REPLY_FIELDS = ["op", "code"] as const;

export const VfsReply = {
  toCbor(reply: VfsReply): CborValue {
    switch (reply.op) {
      case "list": {
        const entries: Array<[string, CborValue]> = [
          ["op", CborValue.uint(ReplyOp.List)],
          ["entries", CborValue.array(reply.entries.map(DirEntry.toCbor))],
        ];
        if (reply.next_cursor !== undefined) {
          entries.push(["next_cursor", CborValue.bytes(reply.next_cursor)]);
        }
        return CborValue.map(entries);
      }
      case "stat":
        return CborValue.map([
          ["op", CborValue.uint(ReplyOp.Stat)],
          ["kind", entryKindToCbor(reply.kind)],
          ["size", CborValue.uint(reply.size)],
          ["mtime", CborValue.uint(reply.mtime)],
          ["perms_here", CborValue.uint(reply.perms_here)],
        ]);
      case "read":
        return CborValue.map([
          ["op", CborValue.uint(ReplyOp.Read)],
          ["data", CborValue.bytes(reply.data)],
          ["eof", CborValue.bool(reply.eof)],
        ]);
      case "mkdir":
        return CborValue.map([["op", CborValue.uint(ReplyOp.Mkdir)]]);
      case "delete":
        return CborValue.map([["op", CborValue.uint(ReplyOp.Delete)]]);
      case "whoami":
        return CborValue.map([
          ["op", CborValue.uint(ReplyOp.Whoami)],
          ["member_display", CborValue.text(reply.member_display)],
          [
            "effective_paths",
            CborValue.array(reply.effective_paths.map((p) => CborValue.text(p))),
          ],
        ]);
      case "error":
        return CborValue.map([
          ["op", CborValue.uint(ReplyOp.Error)],
          ["code", vfsErrorCodeToCbor(reply.code)],
        ]);
    }
  },

  toCanonicalBytes(reply: VfsReply): Uint8Array {
    return canonicalEncode(VfsReply.toCbor(reply));
  },

  fromCbor(v: CborValue): VfsReply {
    const m = new MapReader(v);
    const op = replyOpFromU64(m.u64("op"));
    switch (op) {
      case ReplyOp.List: {
        m.denyUnknownFields(LIST_REPLY_FIELDS);
        const raw = m.require("entries");
        if (raw.kind !== "array") throw ProtoError.wrongType("entries");
        const entries = raw.value.map((item) => DirEntry.fromCbor(item));
        return { op: "list", entries, next_cursor: m.optionalBytes("next_cursor") };
      }
      case ReplyOp.Stat:
        m.denyUnknownFields(STAT_REPLY_FIELDS);
        return {
          op: "stat",
          kind: entryKindFromU64(m.u64("kind")),
          size: m.u64("size"),
          mtime: m.u64("mtime"),
          perms_here: vfsPermsFromReader(m, "perms_here"),
        };
      case ReplyOp.Read:
        m.denyUnknownFields(READ_REPLY_FIELDS);
        return { op: "read", data: m.bytes("data"), eof: m.bool("eof") };
      case ReplyOp.Mkdir:
        m.denyUnknownFields(MKDIR_REPLY_FIELDS);
        return { op: "mkdir" };
      case ReplyOp.Delete:
        m.denyUnknownFields(DELETE_REPLY_FIELDS);
        return { op: "delete" };
      case ReplyOp.Whoami: {
        m.denyUnknownFields(WHOAMI_REPLY_FIELDS);
        const raw = m.require("effective_paths");
        if (raw.kind !== "array") throw ProtoError.wrongType("effective_paths");
        const effective_paths = raw.value.map((item) => {
          if (item.kind !== "text") throw ProtoError.wrongType("effective_paths");
          return item.value;
        });
        return { op: "whoami", member_display: m.text("member_display"), effective_paths };
      }
      case ReplyOp.Error:
        m.denyUnknownFields(ERROR_REPLY_FIELDS);
        return { op: "error", code: vfsErrorCodeFromU64(m.u64("code")) };
    }
  },

  fromCanonicalBytes(bytes: Uint8Array): VfsReply {
    return VfsReply.fromCbor(decodeCanonicalOrThrow(bytes));
  },
};
