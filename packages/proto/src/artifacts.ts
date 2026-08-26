// Wire types for the A7 envelope and the six other A7b signed-artifact kinds — the TypeScript
// twin of `crates/spindle-proto/src/artifacts.rs`.
//
// Every type here is a thin, lossless mapping to/from `CborValue` plus a canonical-bytes
// convenience wrapper. Field *values* are opaque (`Uint8Array` for fingerprints/keys/signatures,
// `bigint`/`number` for counters/timestamps) — this package has no crypto dependency and does not
// know or enforce expected byte lengths for a given `alg_id`; that belongs to `@spindle/crypto`.
// See the schema-choices table in `crates/spindle-proto/src/lib.rs` for every representational
// decision made here (map keys as short text strings, fingerprints/keys/sigs as byte strings,
// enums as small unsigned integers, optional fields represented by key omission rather than CBOR
// null).
//
// Decoding is strict in two ways beyond `canonicalDecode`'s own canonicality checks: a missing
// mandatory field is rejected, and a map containing any key outside the type's declared field set
// is rejected. This is a deliberate closed-schema choice for a v1, `v`-gated wire contract — see
// the schema table in `crates/spindle-proto/src/lib.rs`.

import { CborError, CborValue, canonicalDecode, canonicalEncode } from "./canonical.js";
import * as tags from "./tags.js";

/** Errors produced while converting between wire types and `CborValue`/bytes. Mirrors Rust's
 * `ProtoError` enum: one variant per `kind`. */
export type ProtoErrorKind =
  | "NotAMap"
  | "MissingField"
  | "UnknownField"
  | "KeyNotText"
  | "WrongType"
  | "IntOutOfRange"
  | "InvalidEnumValue"
  | "Cbor";

export class ProtoError extends Error {
  readonly kind: ProtoErrorKind;
  /** Set for `MissingField`, `UnknownField`, `WrongType`, `IntOutOfRange`, `InvalidEnumValue`. */
  readonly field?: string;
  /** Set for `InvalidEnumValue`. */
  readonly enumValue?: bigint;
  /** Set for `Cbor`. */
  readonly cborError?: CborError;

  private constructor(
    kind: ProtoErrorKind,
    message: string,
    extra?: { field?: string; enumValue?: bigint; cborError?: CborError },
  ) {
    super(message);
    this.name = "ProtoError";
    this.kind = kind;
    this.field = extra?.field;
    this.enumValue = extra?.enumValue;
    this.cborError = extra?.cborError;
  }

  static notAMap(): ProtoError {
    return new ProtoError("NotAMap", "top-level CBOR item is not a map");
  }
  static missingField(field: string): ProtoError {
    return new ProtoError("MissingField", `missing required field \`${field}\``, { field });
  }
  static unknownField(field: string): ProtoError {
    return new ProtoError("UnknownField", `unknown field \`${field}\``, { field });
  }
  static keyNotText(): ProtoError {
    return new ProtoError("KeyNotText", "map key is not a text string");
  }
  static wrongType(field: string): ProtoError {
    return new ProtoError("WrongType", `field \`${field}\` has the wrong CBOR type`, { field });
  }
  static intOutOfRange(field: string): ProtoError {
    return new ProtoError(
      "IntOutOfRange",
      `field \`${field}\` integer value is out of range`,
      { field },
    );
  }
  static invalidEnumValue(field: string, value: bigint): ProtoError {
    return new ProtoError(
      "InvalidEnumValue",
      `field \`${field}\` has unrecognized enum value ${value}`,
      { field, enumValue: value },
    );
  }
  static fromCbor(e: CborError): ProtoError {
    return new ProtoError("Cbor", e.message, { cborError: e });
  }
}

/** Read-side helper over a decoded `{kind: "map"}` value: field lookup plus the closed-schema
 * check (every key must be in the caller's declared allow-list). Exported (mirroring Rust's
 * `pub(crate) struct MapReader` in `artifacts.rs`) so `vfsRpc.ts` can reuse the identical
 * field-extraction discipline for the VFS RPC wire types instead of re-implementing it — same
 * package, same closed-schema/strict-type conventions. Not re-exported from `index.ts`: like the
 * Rust type, it is package-internal, not part of `@spindle/proto`'s public API. */
export class MapReader {
  private readonly entries: ReadonlyArray<[CborValue, CborValue]>;

  constructor(v: CborValue) {
    if (v.kind !== "map") throw ProtoError.notAMap();
    this.entries = v.value;
  }

  /** Rejects the map if it contains any key not in `allowed`. */
  denyUnknownFields(allowed: readonly string[]): void {
    for (const [k] of this.entries) {
      if (k.kind !== "text") throw ProtoError.keyNotText();
      if (!allowed.includes(k.value)) throw ProtoError.unknownField(k.value);
    }
  }

  get(key: string): CborValue | undefined {
    for (const [k, v] of this.entries) {
      if (k.kind === "text" && k.value === key) return v;
    }
    return undefined;
  }

  require(key: string): CborValue {
    const v = this.get(key);
    if (v === undefined) throw ProtoError.missingField(key);
    return v;
  }

  bytes(key: string): Uint8Array {
    const v = this.require(key);
    if (v.kind !== "bytes") throw ProtoError.wrongType(key);
    return v.value;
  }

  text(key: string): string {
    const v = this.require(key);
    if (v.kind !== "text") throw ProtoError.wrongType(key);
    return v.value;
  }

  u64(key: string): bigint {
    const v = this.require(key);
    if (v.kind !== "uint") throw ProtoError.wrongType(key);
    return v.value;
  }

  u8(key: string): number {
    const v = this.u64(key);
    if (v > 0xffn) throw ProtoError.intOutOfRange(key);
    return Number(v);
  }

  u16(key: string): number {
    const v = this.u64(key);
    if (v > 0xffffn) throw ProtoError.intOutOfRange(key);
    return Number(v);
  }

  u32(key: string): number {
    const v = this.u64(key);
    if (v > 0xffffffffn) throw ProtoError.intOutOfRange(key);
    return Number(v);
  }

  bool(key: string): boolean {
    const v = this.require(key);
    if (v.kind !== "bool") throw ProtoError.wrongType(key);
    return v.value;
  }

  bytesArray(key: string): Uint8Array[] {
    const v = this.require(key);
    if (v.kind !== "array") throw ProtoError.wrongType(key);
    return v.value.map((item) => {
      if (item.kind !== "bytes") throw ProtoError.wrongType(key);
      return item.value;
    });
  }

  optionalBytes(key: string): Uint8Array | undefined {
    const v = this.get(key);
    if (v === undefined) return undefined;
    if (v.kind !== "bytes") throw ProtoError.wrongType(key);
    return v.value;
  }

  optionalU32(key: string): number | undefined {
    const v = this.get(key);
    if (v === undefined) return undefined;
    if (v.kind !== "uint") throw ProtoError.wrongType(key);
    if (v.value > 0xffffffffn) throw ProtoError.intOutOfRange(key);
    return Number(v.value);
  }
}

function bytesArrayValue(items: readonly Uint8Array[]): CborValue {
  return CborValue.array(items.map((b) => CborValue.bytes(b)));
}

/** Decodes exactly one canonical CBOR item, converting a `CborError` into the equivalent
 * `ProtoError.Cbor` (mirrors Rust's `From<CborError> for ProtoError` firing through the `?`
 * operator in `from_canonical_bytes`). Exported for `vfsRpc.ts`'s reuse (package-internal, not
 * re-exported from `index.ts`) — same rationale as `MapReader` above. */
export function decodeCanonicalOrThrow(bytes: Uint8Array): CborValue {
  try {
    return canonicalDecode(bytes);
  } catch (e) {
    if (e instanceof CborError) throw ProtoError.fromCbor(e);
    throw e;
  }
}

/** `Capability.kind` (A4): `invite` (bearer, single-use) or `member` (issued post-redemption).
 * Encoded as a small unsigned integer (schema choice — see `lib.rs`). */
export enum CapKind {
  Invite = 0,
  Member = 1,
}

function capKindToCbor(k: CapKind): CborValue {
  return CborValue.uint(k);
}

function capKindFromU64(v: bigint): CapKind {
  if (v === 0n) return CapKind.Invite;
  if (v === 1n) return CapKind.Member;
  throw ProtoError.invalidEnumValue("kind", v);
}

// ============================================================================================
// Envelope (A7)
// ============================================================================================

/** `Envelope { v, alg_id, from_fp, to_fp, sid, kind, seq, ts, eph_pk?, ciphertext, sig }`
 * (DESIGN.md §A7). `eph_pk` is optional (absent on non-first messages of a session once the
 * session key is established) and represented by key omission — `undefined`, never CBOR `null`. */
export interface Envelope {
  v: number;
  alg_id: number;
  from_fp: Uint8Array;
  to_fp: Uint8Array;
  sid: Uint8Array;
  kind: number;
  seq: bigint;
  ts: bigint;
  eph_pk?: Uint8Array;
  ciphertext: Uint8Array;
  sig: Uint8Array;
}

const ENVELOPE_FIELDS = [
  "v",
  "alg_id",
  "from_fp",
  "to_fp",
  "sid",
  "kind",
  "seq",
  "ts",
  "eph_pk",
  "ciphertext",
  "sig",
] as const;

export const Envelope = {
  headerEntries(env: Envelope): Array<[string, CborValue]> {
    const entries: Array<[string, CborValue]> = [
      ["v", CborValue.uint(env.v)],
      ["alg_id", CborValue.uint(env.alg_id)],
      ["from_fp", CborValue.bytes(env.from_fp)],
      ["to_fp", CborValue.bytes(env.to_fp)],
      ["sid", CborValue.bytes(env.sid)],
      ["kind", CborValue.uint(env.kind)],
      ["seq", CborValue.uint(env.seq)],
      ["ts", CborValue.uint(env.ts)],
    ];
    if (env.eph_pk !== undefined) {
      entries.push(["eph_pk", CborValue.bytes(env.eph_pk)]);
    }
    return entries;
  },

  /** The canonical encoding of every field except `ciphertext` and `sig` — this is both the
   * AEAD's AAD and (via `Envelope.signingInput`) part of the signature preimage (A7). */
  headerCbor(env: Envelope): CborValue {
    return CborValue.map(Envelope.headerEntries(env));
  },

  headerCanonicalBytes(env: Envelope): Uint8Array {
    return canonicalEncode(Envelope.headerCbor(env));
  },

  toCbor(env: Envelope): CborValue {
    const entries = Envelope.headerEntries(env);
    entries.push(["ciphertext", CborValue.bytes(env.ciphertext)]);
    entries.push(["sig", CborValue.bytes(env.sig)]);
    return CborValue.map(entries);
  },

  toCanonicalBytes(env: Envelope): Uint8Array {
    return canonicalEncode(Envelope.toCbor(env));
  },

  fromCbor(v: CborValue): Envelope {
    const m = new MapReader(v);
    m.denyUnknownFields(ENVELOPE_FIELDS);
    return {
      v: m.u8("v"),
      alg_id: m.u8("alg_id"),
      from_fp: m.bytes("from_fp"),
      to_fp: m.bytes("to_fp"),
      sid: m.bytes("sid"),
      kind: m.u16("kind"),
      seq: m.u64("seq"),
      ts: m.u64("ts"),
      eph_pk: m.optionalBytes("eph_pk"),
      ciphertext: m.bytes("ciphertext"),
      sig: m.bytes("sig"),
    };
  },

  fromCanonicalBytes(bytes: Uint8Array): Envelope {
    return Envelope.fromCbor(decodeCanonicalOrThrow(bytes));
  },

  /** `"spindle-env-v1" || canonical(header) || ciphertext` (A7) — the Ed25519 signature preimage.
   * Note this is *not* `tags.signingInput(tag, canonical(full envelope))`: the envelope is the
   * one A7b artifact whose signing input is header-plus-raw-ciphertext rather than the canonical
   * encoding of the whole signed struct minus `sig`. */
  signingInput(env: Envelope): Uint8Array {
    const header = tags.signingInput(tags.ENVELOPE_V1, Envelope.headerCanonicalBytes(env));
    const out = new Uint8Array(header.length + env.ciphertext.length);
    out.set(header, 0);
    out.set(env.ciphertext, header.length);
    return out;
  },
};

// ============================================================================================
// Capability (A4)
// ============================================================================================

/** `Capability { v, host_fp, host_root_pk, op_cert, kind, subject, cap_epoch, exp, nonce, sig }`
 * (DESIGN.md §A4). */
export interface Capability {
  v: number;
  host_fp: Uint8Array;
  host_root_pk: Uint8Array;
  op_cert: Uint8Array;
  kind: CapKind;
  /** `root_fp` for a `member` cap, `device_fp` for an `invite` cap — opaque fingerprint bytes
   * either way; this package does not disambiguate further. */
  subject: Uint8Array;
  cap_epoch: bigint;
  exp: bigint;
  nonce: Uint8Array;
  sig: Uint8Array;
}

const CAPABILITY_FIELDS = [
  "v",
  "host_fp",
  "host_root_pk",
  "op_cert",
  "kind",
  "subject",
  "cap_epoch",
  "exp",
  "nonce",
  "sig",
] as const;

export const Capability = {
  unsignedEntries(cap: Capability): Array<[string, CborValue]> {
    return [
      ["v", CborValue.uint(cap.v)],
      ["host_fp", CborValue.bytes(cap.host_fp)],
      ["host_root_pk", CborValue.bytes(cap.host_root_pk)],
      ["op_cert", CborValue.bytes(cap.op_cert)],
      ["kind", capKindToCbor(cap.kind)],
      ["subject", CborValue.bytes(cap.subject)],
      ["cap_epoch", CborValue.uint(cap.cap_epoch)],
      ["exp", CborValue.uint(cap.exp)],
      ["nonce", CborValue.bytes(cap.nonce)],
    ];
  },

  unsignedCbor(cap: Capability): CborValue {
    return CborValue.map(Capability.unsignedEntries(cap));
  },

  toCbor(cap: Capability): CborValue {
    const entries = Capability.unsignedEntries(cap);
    entries.push(["sig", CborValue.bytes(cap.sig)]);
    return CborValue.map(entries);
  },

  toCanonicalBytes(cap: Capability): Uint8Array {
    return canonicalEncode(Capability.toCbor(cap));
  },

  fromCbor(v: CborValue): Capability {
    const m = new MapReader(v);
    m.denyUnknownFields(CAPABILITY_FIELDS);
    return {
      v: m.u8("v"),
      host_fp: m.bytes("host_fp"),
      host_root_pk: m.bytes("host_root_pk"),
      op_cert: m.bytes("op_cert"),
      kind: capKindFromU64(m.u64("kind")),
      subject: m.bytes("subject"),
      cap_epoch: m.u64("cap_epoch"),
      exp: m.u64("exp"),
      nonce: m.bytes("nonce"),
      sig: m.bytes("sig"),
    };
  },

  fromCanonicalBytes(bytes: Uint8Array): Capability {
    return Capability.fromCbor(decodeCanonicalOrThrow(bytes));
  },

  /** `"spindle-cap-v1" || canonical(self minus sig)` (A7b). */
  signingInput(cap: Capability): Uint8Array {
    return tags.signingInput(tags.CAPABILITY_V1, canonicalEncode(Capability.unsignedCbor(cap)));
  },
};

// ============================================================================================
// AdmissionToken (A3b)
// ============================================================================================

/** `AdmissionToken { nonce, exp, label, quota_profile, sig_operator }` (DESIGN.md §A3b).
 *
 * `exp` is encoded as an absolute Unix-seconds timestamp, consistent with every other `exp` field
 * in this package — A3b's "exp (days)" describes the *default duration* the operator picks when
 * minting the token, not the wire unit (see the schema table in `crates/spindle-proto/src/lib.rs`). */
export interface AdmissionToken {
  nonce: Uint8Array;
  exp: bigint;
  label: string;
  quota_profile: string;
  sig_operator: Uint8Array;
}

const ADMISSION_TOKEN_FIELDS = ["nonce", "exp", "label", "quota_profile", "sig_operator"] as const;

export const AdmissionToken = {
  unsignedEntries(tok: AdmissionToken): Array<[string, CborValue]> {
    return [
      ["nonce", CborValue.bytes(tok.nonce)],
      ["exp", CborValue.uint(tok.exp)],
      ["label", CborValue.text(tok.label)],
      ["quota_profile", CborValue.text(tok.quota_profile)],
    ];
  },

  unsignedCbor(tok: AdmissionToken): CborValue {
    return CborValue.map(AdmissionToken.unsignedEntries(tok));
  },

  toCbor(tok: AdmissionToken): CborValue {
    const entries = AdmissionToken.unsignedEntries(tok);
    entries.push(["sig_operator", CborValue.bytes(tok.sig_operator)]);
    return CborValue.map(entries);
  },

  toCanonicalBytes(tok: AdmissionToken): Uint8Array {
    return canonicalEncode(AdmissionToken.toCbor(tok));
  },

  fromCbor(v: CborValue): AdmissionToken {
    const m = new MapReader(v);
    m.denyUnknownFields(ADMISSION_TOKEN_FIELDS);
    return {
      nonce: m.bytes("nonce"),
      exp: m.u64("exp"),
      label: m.text("label"),
      quota_profile: m.text("quota_profile"),
      sig_operator: m.bytes("sig_operator"),
    };
  },

  fromCanonicalBytes(bytes: Uint8Array): AdmissionToken {
    return AdmissionToken.fromCbor(decodeCanonicalOrThrow(bytes));
  },

  /** `"spindle-adm-v1" || canonical(self minus sig_operator)` (A7b). */
  signingInput(tok: AdmissionToken): Uint8Array {
    return tags.signingInput(
      tags.ADMISSION_TOKEN_V1,
      canonicalEncode(AdmissionToken.unsignedCbor(tok)),
    );
  },
};

// ============================================================================================
// DeviceCertificate (A4)
// ============================================================================================

/** `DeviceCertificate { device_fp, nats_fp, ts, exp, sig_root }` (DESIGN.md §A4).
 *
 * **Label discrepancy**: see the discrepancy note on `DeviceCertificate` in
 * `crates/spindle-proto/src/artifacts.rs` — `label` is intentionally omitted from the wire
 * schema entirely; a decoded map carrying a `label` key is rejected as an unknown field. */
export interface DeviceCertificate {
  device_fp: Uint8Array;
  nats_fp: Uint8Array;
  ts: bigint;
  exp: bigint;
  sig_root: Uint8Array;
}

const DEVICE_CERT_FIELDS = ["device_fp", "nats_fp", "ts", "exp", "sig_root"] as const;

export const DeviceCertificate = {
  unsignedEntries(cert: DeviceCertificate): Array<[string, CborValue]> {
    return [
      ["device_fp", CborValue.bytes(cert.device_fp)],
      ["nats_fp", CborValue.bytes(cert.nats_fp)],
      ["ts", CborValue.uint(cert.ts)],
      ["exp", CborValue.uint(cert.exp)],
    ];
  },

  unsignedCbor(cert: DeviceCertificate): CborValue {
    return CborValue.map(DeviceCertificate.unsignedEntries(cert));
  },

  toCbor(cert: DeviceCertificate): CborValue {
    const entries = DeviceCertificate.unsignedEntries(cert);
    entries.push(["sig_root", CborValue.bytes(cert.sig_root)]);
    return CborValue.map(entries);
  },

  toCanonicalBytes(cert: DeviceCertificate): Uint8Array {
    return canonicalEncode(DeviceCertificate.toCbor(cert));
  },

  fromCbor(v: CborValue): DeviceCertificate {
    const m = new MapReader(v);
    m.denyUnknownFields(DEVICE_CERT_FIELDS);
    return {
      device_fp: m.bytes("device_fp"),
      nats_fp: m.bytes("nats_fp"),
      ts: m.u64("ts"),
      exp: m.u64("exp"),
      sig_root: m.bytes("sig_root"),
    };
  },

  fromCanonicalBytes(bytes: Uint8Array): DeviceCertificate {
    return DeviceCertificate.fromCbor(decodeCanonicalOrThrow(bytes));
  },

  /** `"spindle-dev-cert-v1" || canonical(self minus sig_root)` (A7b). */
  signingInput(cert: DeviceCertificate): Uint8Array {
    return tags.signingInput(
      tags.DEVICE_CERT_V1,
      canonicalEncode(DeviceCertificate.unsignedCbor(cert)),
    );
  },
};

// ============================================================================================
// RevocationRecord (A4)
// ============================================================================================

/** `RevocationRecord { host_fp, epoch, revoked: [fp...], ts, sig }` (DESIGN.md §A4). `revoked`
 * holds `root_fp`/`device_fp` fingerprints, mixed, opaque to this package. */
export interface RevocationRecord {
  host_fp: Uint8Array;
  epoch: bigint;
  revoked: Uint8Array[];
  ts: bigint;
  sig: Uint8Array;
}

const REVOCATION_FIELDS = ["host_fp", "epoch", "revoked", "ts", "sig"] as const;

export const RevocationRecord = {
  unsignedEntries(rec: RevocationRecord): Array<[string, CborValue]> {
    return [
      ["host_fp", CborValue.bytes(rec.host_fp)],
      ["epoch", CborValue.uint(rec.epoch)],
      ["revoked", bytesArrayValue(rec.revoked)],
      ["ts", CborValue.uint(rec.ts)],
    ];
  },

  unsignedCbor(rec: RevocationRecord): CborValue {
    return CborValue.map(RevocationRecord.unsignedEntries(rec));
  },

  toCbor(rec: RevocationRecord): CborValue {
    const entries = RevocationRecord.unsignedEntries(rec);
    entries.push(["sig", CborValue.bytes(rec.sig)]);
    return CborValue.map(entries);
  },

  toCanonicalBytes(rec: RevocationRecord): Uint8Array {
    return canonicalEncode(RevocationRecord.toCbor(rec));
  },

  fromCbor(v: CborValue): RevocationRecord {
    const m = new MapReader(v);
    m.denyUnknownFields(REVOCATION_FIELDS);
    return {
      host_fp: m.bytes("host_fp"),
      epoch: m.u64("epoch"),
      revoked: m.bytesArray("revoked"),
      ts: m.u64("ts"),
      sig: m.bytes("sig"),
    };
  },

  fromCanonicalBytes(bytes: Uint8Array): RevocationRecord {
    return RevocationRecord.fromCbor(decodeCanonicalOrThrow(bytes));
  },

  /** `"spindle-rev-v1" || canonical(self minus sig)` (A7b). */
  signingInput(rec: RevocationRecord): Uint8Array {
    return tags.signingInput(
      tags.REVOCATION_V1,
      canonicalEncode(RevocationRecord.unsignedCbor(rec)),
    );
  },
};

// ============================================================================================
// AdminCommand (A3b/A7b)
// ============================================================================================

/** `AdminCommand { v, cmd, args, signer_fp, seq, nonce, ts, sig }` (DESIGN.md §A3b/§A7b).
 *
 * `args` is an intentionally open `CborValue` (a canonical map, typically) — the admin surface
 * covers a growing set of commands (mode switch, admit/evict, quota changes, key rotation…) whose
 * argument shapes are not enumerated in DESIGN.md; this package carries `args` through opaquely
 * rather than pre-committing to a per-command schema at the wire-type level. */
export interface AdminCommand {
  v: number;
  cmd: string;
  args: CborValue;
  signer_fp: Uint8Array;
  seq: bigint;
  nonce: Uint8Array;
  ts: bigint;
  sig: Uint8Array;
}

const ADMIN_COMMAND_FIELDS = [
  "v",
  "cmd",
  "args",
  "signer_fp",
  "seq",
  "nonce",
  "ts",
  "sig",
] as const;

export const AdminCommand = {
  unsignedEntries(cmd: AdminCommand): Array<[string, CborValue]> {
    return [
      ["v", CborValue.uint(cmd.v)],
      ["cmd", CborValue.text(cmd.cmd)],
      ["args", cmd.args],
      ["signer_fp", CborValue.bytes(cmd.signer_fp)],
      ["seq", CborValue.uint(cmd.seq)],
      ["nonce", CborValue.bytes(cmd.nonce)],
      ["ts", CborValue.uint(cmd.ts)],
    ];
  },

  unsignedCbor(cmd: AdminCommand): CborValue {
    return CborValue.map(AdminCommand.unsignedEntries(cmd));
  },

  toCbor(cmd: AdminCommand): CborValue {
    const entries = AdminCommand.unsignedEntries(cmd);
    entries.push(["sig", CborValue.bytes(cmd.sig)]);
    return CborValue.map(entries);
  },

  toCanonicalBytes(cmd: AdminCommand): Uint8Array {
    return canonicalEncode(AdminCommand.toCbor(cmd));
  },

  fromCbor(v: CborValue): AdminCommand {
    const m = new MapReader(v);
    m.denyUnknownFields(ADMIN_COMMAND_FIELDS);
    return {
      v: m.u8("v"),
      cmd: m.text("cmd"),
      args: m.require("args"),
      signer_fp: m.bytes("signer_fp"),
      seq: m.u64("seq"),
      nonce: m.bytes("nonce"),
      ts: m.u64("ts"),
      sig: m.bytes("sig"),
    };
  },

  fromCanonicalBytes(bytes: Uint8Array): AdminCommand {
    return AdminCommand.fromCbor(decodeCanonicalOrThrow(bytes));
  },

  /** `"spindle-adm-cmd-v1" || canonical(self minus sig)` (A7b). */
  signingInput(cmd: AdminCommand): Uint8Array {
    return tags.signingInput(
      tags.ADMIN_COMMAND_V1,
      canonicalEncode(AdminCommand.unsignedCbor(cmd)),
    );
  },
};

// ============================================================================================
// HostOpKeyCert (A4)
// ============================================================================================

/** `HostOpKeyCert { host_op_pk, nats_fp, ts, exp, sig_host_root }` (DESIGN.md §A4). */
export interface HostOpKeyCert {
  host_op_pk: Uint8Array;
  nats_fp: Uint8Array;
  ts: bigint;
  exp: bigint;
  sig_host_root: Uint8Array;
}

const HOST_OP_KEY_CERT_FIELDS = ["host_op_pk", "nats_fp", "ts", "exp", "sig_host_root"] as const;

export const HostOpKeyCert = {
  unsignedEntries(cert: HostOpKeyCert): Array<[string, CborValue]> {
    return [
      ["host_op_pk", CborValue.bytes(cert.host_op_pk)],
      ["nats_fp", CborValue.bytes(cert.nats_fp)],
      ["ts", CborValue.uint(cert.ts)],
      ["exp", CborValue.uint(cert.exp)],
    ];
  },

  unsignedCbor(cert: HostOpKeyCert): CborValue {
    return CborValue.map(HostOpKeyCert.unsignedEntries(cert));
  },

  toCbor(cert: HostOpKeyCert): CborValue {
    const entries = HostOpKeyCert.unsignedEntries(cert);
    entries.push(["sig_host_root", CborValue.bytes(cert.sig_host_root)]);
    return CborValue.map(entries);
  },

  toCanonicalBytes(cert: HostOpKeyCert): Uint8Array {
    return canonicalEncode(HostOpKeyCert.toCbor(cert));
  },

  fromCbor(v: CborValue): HostOpKeyCert {
    const m = new MapReader(v);
    m.denyUnknownFields(HOST_OP_KEY_CERT_FIELDS);
    return {
      host_op_pk: m.bytes("host_op_pk"),
      nats_fp: m.bytes("nats_fp"),
      ts: m.u64("ts"),
      exp: m.u64("exp"),
      sig_host_root: m.bytes("sig_host_root"),
    };
  },

  fromCanonicalBytes(bytes: Uint8Array): HostOpKeyCert {
    return HostOpKeyCert.fromCbor(decodeCanonicalOrThrow(bytes));
  },

  /** `"spindle-host-cert-v1" || canonical(self minus sig_host_root)` (A7b). */
  signingInput(cert: HostOpKeyCert): Uint8Array {
    return tags.signingInput(
      tags.HOST_OP_KEY_CERT_V1,
      canonicalEncode(HostOpKeyCert.unsignedCbor(cert)),
    );
  },
};
