// Admin reply envelope (provisional).
//
// DESIGN.md:1280 records that `registry.admin.>` has no handler yet, and neither DESIGN.md nor
// ADR-007 specifies a reply wire shape. This module defines the smallest canonical-CBOR envelope
// the client needs to distinguish success from a typed refusal:
//
//   { v: 1, ok: true,  result?: <any CborValue> }
//   { v: 1, ok: false, error: { code: <text>, message?: <text> } }
//
// It is deliberately closed-schema and versioned so that the helper handler, when it lands, either
// agrees with these bytes or forces a visible `ADMIN_REPLY_CURRENT_V` bump. Treat this as a
// proposed contract, not a cross-checked one: there is no Rust twin to compare against yet.
//
// `result` is an opaque `CborValue` for the same reason `AdminCommand.args` is: the per-command
// result shapes (host lists, invite tokens, audit pages) are not enumerated in the spec, and
// inventing ten schemas here would commit the helper to guesses. Absence of `result` is normal for
// commands that produce no value (mode switch, eviction, key rotation).

import { CborError, CborValue, canonicalDecode, canonicalEncode } from "@spindle/proto";

import { AdminError } from "./errors.js";

/** Minimum reply version this package accepts. */
export const ADMIN_REPLY_MIN_V = 1;
/** Reply version this package emits and understands. */
export const ADMIN_REPLY_CURRENT_V = 1;

/** A helper refusal: `code` is the machine-readable reason; `message` is optional human detail.
 * Both are peer-supplied and are never interpolated into `AdminError.message`. */
export interface AdminRefusal {
  code: string;
  message?: string;
}

/** Decoded reply envelope. */
export interface AdminReply {
  v: number;
  ok: boolean;
  /** Present only when `ok` is true; absent for commands with no result. */
  result?: CborValue;
  /** Present only when `ok` is false. */
  error?: AdminRefusal;
}

function malformed(): never {
  throw AdminError.malformedReply();
}

function requireMap(v: CborValue, allowed: readonly string[]): Map<string, CborValue> {
  if (v.kind !== "map") malformed();
  const out = new Map<string, CborValue>();
  for (const [key, value] of v.value) {
    if (key.kind !== "text") malformed();
    if (!allowed.includes(key.value)) malformed();
    out.set(key.value, value);
  }
  return out;
}

function requireText(v: CborValue | undefined): string {
  if (v === undefined || v.kind !== "text") malformed();
  return v.value;
}

function requireU8(v: CborValue | undefined): number {
  if (v === undefined || v.kind !== "uint" || v.value > 0xffn) malformed();
  return Number(v.value);
}

/** Decodes one canonical reply envelope. Any structural deviation — non-canonical CBOR, a
 * non-map, an unknown field, a missing required field, a mismatched `ok`/`result`/`error`
 * combination, or a version outside `[ADMIN_REPLY_MIN_V, ADMIN_REPLY_CURRENT_V]` — raises
 * {@link AdminError} `MalformedReply`. */
export function decodeAdminReply(bytes: Uint8Array): AdminReply {
  let decoded: CborValue;
  try {
    decoded = canonicalDecode(bytes);
  } catch (e) {
    // `CborError`'s message contains only byte offsets/reasons, but the reply is still rejected
    // with the package's uniform content-free error rather than exposing decoder internals.
    if (e instanceof CborError) malformed();
    throw e;
  }

  const map = requireMap(decoded, ["v", "ok", "result", "error"]);

  const v = requireU8(map.get("v"));
  if (v < ADMIN_REPLY_MIN_V) throw AdminError.malformedReply();
  if (v > ADMIN_REPLY_CURRENT_V) throw AdminError.malformedReply();

  const okValue = map.get("ok");
  if (okValue === undefined || okValue.kind !== "bool") malformed();
  const ok = okValue.value;

  if (ok) {
    if (map.has("error")) malformed();
    return { v, ok: true, result: map.get("result") };
  }

  if (map.has("result")) malformed();
  const errorValue = map.get("error");
  if (errorValue === undefined) malformed();
  const errorMap = requireMap(errorValue, ["code", "message"]);
  const code = requireText(errorMap.get("code"));
  const messageValue = errorMap.get("message");
  const message = messageValue === undefined ? undefined : requireText(messageValue);
  return { v, ok: false, error: { code, message } };
}

/** Encodes a reply envelope. Exported for tests and for a future helper-side encoder; the client
 * itself only decodes. Validates the same invariants `decodeAdminReply` enforces. */
export function encodeAdminReply(reply: AdminReply): Uint8Array {
  if (!Number.isInteger(reply.v) || reply.v < ADMIN_REPLY_MIN_V || reply.v > ADMIN_REPLY_CURRENT_V) {
    throw AdminError.invalidValue("reply.v");
  }

  const entries: Array<[string, CborValue]> = [
    ["v", CborValue.uint(reply.v)],
    ["ok", CborValue.bool(reply.ok)],
  ];

  if (reply.ok) {
    if (reply.error !== undefined) throw AdminError.invalidValue("reply.error");
    if (reply.result !== undefined) entries.push(["result", reply.result]);
  } else {
    if (reply.error === undefined) throw AdminError.invalidValue("reply.error");
    const errorEntries: Array<[string, CborValue]> = [
      ["code", CborValue.text(reply.error.code)],
    ];
    if (reply.error.message !== undefined) {
      errorEntries.push(["message", CborValue.text(reply.error.message)]);
    }
    entries.push(["error", CborValue.map(errorEntries)]);
  }

  try {
    return canonicalEncode(CborValue.map(entries));
  } catch (e) {
    if (e instanceof CborError) throw AdminError.invalidValue("reply");
    throw e;
  }
}
