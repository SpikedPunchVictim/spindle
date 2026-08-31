// Signaling payload wire types (DESIGN.md §A6 "Signaling flows" + §A7's envelope, §A10.31/32's
// native↔native QUIC transport decision) — the TypeScript twin of
// `crates/spindle-proto/src/signaling.rs`. Promoted from `spikes/s2-signaling`'s crate-local
// `OfferPayload`/`AnswerPayload`/`IcePayload` types; see that spike's module doc for the empirical
// work that settled these fields, and the Rust twin's module doc for the full "what changed from
// the spike" rationale (canonical CBOR instead of JSON, `cert_fp` as a fixed 32-byte digest
// instead of a `"sha256:<hex>"` string, `transport` as a closed enum instead of free text, and
// explicit length caps on the text fields).
//
// Not one of the eight A7b signed-artifact kinds (no domain-separation tag, no `sig` field): like
// `vfsRpc.ts`, these payloads are never signed independently — an offer/answer/ICE payload is
// always the *plaintext* that gets AEAD-sealed inside an `Envelope` (`k0` for the offer, `k1` for
// everything after — DESIGN.md §A7's key schedule), and the envelope's own `spindle-env-v1`
// signature already covers it transitively.
//
// Field names, the `transport` discriminant values, and every length cap below are taken directly
// from `crates/spindle-proto/src/signaling.rs` and cross-checked against every case in
// `vectors/signaling.json` (see `test/signaling.test.ts`).

import { MapReader, ProtoError, decodeCanonicalOrThrow } from "./artifacts.js";
import { CborValue, canonicalEncode } from "./canonical.js";

/** Length of a `cert_fp` field in bytes — a SHA-256 digest (DESIGN.md §A10.32). */
export const CERT_FP_LEN = 32;

/** Maximum length, in bytes, of an ICE `ufrag`/`pwd` field. RFC 8445 §5.3 states 256 characters
 * as its own receive/generate ceiling for both — see the Rust twin's doc comment for the full
 * citation and the rationale for not also enforcing the RFC's *generation*-side minimums. */
export const MAX_UFRAG_LEN = 256;
/** See {@link MAX_UFRAG_LEN} — same RFC 8445 §5.3 ceiling, applied to `pwd`. */
export const MAX_PWD_LEN = 256;

/** Maximum length, in bytes, of one trickled ICE candidate line (an SDP `a=candidate` line body,
 * RFC 8839 §5.1). No RFC-mandated maximum exists; see the Rust twin's doc comment for why 1024 was
 * chosen (a generous multiple of real-world candidate line lengths, including `raddr`/`rport`
 * extensions). */
export const MAX_CANDIDATE_LEN = 1024;

/** Maximum length, in bytes, of the `inbox` field (a NATS subject string, DESIGN.md §A6). See the
 * Rust twin's doc comment for why 256 was chosen. */
export const MAX_INBOX_LEN = 256;

/** Spike-local `Envelope.kind` values, now the schema-of-record (DESIGN.md §A6's flow diagram:
 * `env{offer}` / `env{answer}` / `env{ice}`) — plain constants, not a field embedded in the
 * payloads themselves (mirrors the Rust twin exactly; see its module doc comment). */
export const KIND_OFFER = 1;
export const KIND_ANSWER = 2;
export const KIND_ICE = 3;

const textEncoder = new TextEncoder();

/** Errors produced while converting between the signaling wire types and `CborValue`/bytes.
 * Mirrors Rust's `SignalingError` enum: `kind: "Proto"` wraps every rejection kind `ProtoError`
 * already defines (missing/unknown field, wrong CBOR type, invalid enum discriminant, non-canonical
 * CBOR); `"TooLong"`/`"WrongLength"` are this module's own additions for the two rejection kinds
 * `ProtoError` has no variant for. */
export type SignalingErrorKind = "Proto" | "TooLong" | "WrongLength";

export class SignalingError extends Error {
  readonly kind: SignalingErrorKind;
  /** Set for `Proto`. */
  readonly protoError?: ProtoError;
  /** Set for `TooLong`/`WrongLength`. */
  readonly field?: string;
  /** Set for `TooLong`. */
  readonly max?: number;
  /** Set for `WrongLength`. */
  readonly expected?: number;
  /** Set for `TooLong`/`WrongLength`. */
  readonly actual?: number;

  private constructor(
    kind: SignalingErrorKind,
    message: string,
    extra?: { protoError?: ProtoError; field?: string; max?: number; expected?: number; actual?: number },
  ) {
    super(message);
    this.name = "SignalingError";
    this.kind = kind;
    this.protoError = extra?.protoError;
    this.field = extra?.field;
    this.max = extra?.max;
    this.expected = extra?.expected;
    this.actual = extra?.actual;
  }

  static proto(e: ProtoError): SignalingError {
    return new SignalingError("Proto", e.message, { protoError: e });
  }

  static tooLong(field: string, max: number, actual: number): SignalingError {
    return new SignalingError(
      "TooLong",
      `field \`${field}\` is ${actual} bytes long, exceeding the ${max}-byte cap`,
      { field, max, actual },
    );
  }

  static wrongLength(field: string, expected: number, actual: number): SignalingError {
    return new SignalingError(
      "WrongLength",
      `field \`${field}\` is ${actual} bytes long, expected exactly ${expected}`,
      { field, expected, actual },
    );
  }
}

/** Runs `fn`, converting any thrown `ProtoError` into the equivalent `SignalingError.proto` —
 * mirrors Rust's `From<ProtoError> for SignalingError` firing through the `?` operator. Anything
 * else (including an already-converted `SignalingError`) propagates unchanged. */
function wrapProtoErrors<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof ProtoError) throw SignalingError.proto(e);
    throw e;
  }
}

/** Rejects `s` if its UTF-8 byte length exceeds `max` (byte length, matching Rust's `str::len()`,
 * not JS's UTF-16-code-unit `string.length`). */
function checkMaxLen(field: string, s: string, max: number): void {
  const actual = textEncoder.encode(s).length;
  if (actual > max) throw SignalingError.tooLong(field, max, actual);
}

function readCappedText(m: MapReader, field: string, max: number): string {
  const s = m.text(field);
  checkMaxLen(field, s, max);
  return s;
}

function readCertFp(m: MapReader): Uint8Array {
  const bytes = m.bytes("cert_fp");
  if (bytes.length !== CERT_FP_LEN) {
    throw SignalingError.wrongLength("cert_fp", CERT_FP_LEN, bytes.length);
  }
  return bytes;
}

// ================================================================================================
// Transport (DESIGN.md §A6/§A10.31/32) — the only two transports a connect ever negotiates.
// ================================================================================================

/** The transport a `connect` negotiates (mirrors Rust's `Transport`). */
export enum Transport {
  /** Native↔native sessions (DESIGN.md §A10.31: quinn + standalone ICE, §A10.32). */
  Quic = 0,
  /** Any session with a browser peer (DESIGN.md §A10.31/32). */
  WebRtc = 1,
}

function transportToCbor(t: Transport): CborValue {
  return CborValue.uint(t);
}

function transportFromU64(v: bigint): Transport {
  if (v === 0n) return Transport.Quic;
  if (v === 1n) return Transport.WebRtc;
  throw ProtoError.invalidEnumValue("transport", v);
}

// ================================================================================================
// OfferPayload
// ================================================================================================

/** The client's connect offer (DESIGN.md §A6: `env{eph_pk_c, offer, inbox, ...}`) — mirrors Rust's
 * `OfferPayload`. `inbox` is a **binding** of the client's real NATS reply subject into signed
 * material — the §A7 envelope signature covers the ciphertext, so the payload is signed. A
 * conforming client MUST set `inbox` to the exact reply subject it listens on; a conforming host
 * MUST reject any offer whose decrypted `inbox` differs from the reply subject the transport
 * reported, in addition to §A6's cheaper `_INBOX_<c>.` prefix check (which stays first because it
 * needs no key — the equality check is only possible after decryption). Consequence: a broker
 * that substitutes a reply subject can only deny service, never silently redirect the answer
 * (DESIGN.md §A6/§A10.36). */
export interface OfferPayload {
  /** The client's real NATS reply subject, bound into signed material (DESIGN.md §A10.36) — see
   * this interface's doc comment. */
  inbox: string;
  transport: Transport;
  ufrag: string;
  pwd: string;
  /** SHA-256 digest, exactly {@link CERT_FP_LEN} bytes. */
  cert_fp: Uint8Array;
}

const OFFER_FIELDS = ["inbox", "transport", "ufrag", "pwd", "cert_fp"] as const;

export const OfferPayload = {
  toCbor(p: OfferPayload): CborValue {
    return CborValue.map([
      ["inbox", CborValue.text(p.inbox)],
      ["transport", transportToCbor(p.transport)],
      ["ufrag", CborValue.text(p.ufrag)],
      ["pwd", CborValue.text(p.pwd)],
      ["cert_fp", CborValue.bytes(p.cert_fp)],
    ]);
  },

  toCanonicalBytes(p: OfferPayload): Uint8Array {
    return canonicalEncode(OfferPayload.toCbor(p));
  },

  fromCbor(v: CborValue): OfferPayload {
    return wrapProtoErrors(() => {
      const m = new MapReader(v);
      m.denyUnknownFields(OFFER_FIELDS);
      return {
        inbox: readCappedText(m, "inbox", MAX_INBOX_LEN),
        transport: transportFromU64(m.u64("transport")),
        ufrag: readCappedText(m, "ufrag", MAX_UFRAG_LEN),
        pwd: readCappedText(m, "pwd", MAX_PWD_LEN),
        cert_fp: readCertFp(m),
      };
    });
  },

  fromCanonicalBytes(bytes: Uint8Array): OfferPayload {
    return wrapProtoErrors(() => OfferPayload.fromCbor(decodeCanonicalOrThrow(bytes)));
  },
};

// ================================================================================================
// AnswerPayload
// ================================================================================================

/** The host's connect answer (DESIGN.md §A6: `env{eph_pk_h, answer, ...}`) — mirrors Rust's
 * `AnswerPayload`. Mirrors `OfferPayload`'s fields minus `inbox` (the answer travels as the
 * `connect` request's own reply). */
export interface AnswerPayload {
  transport: Transport;
  ufrag: string;
  pwd: string;
  cert_fp: Uint8Array;
}

const ANSWER_FIELDS = ["transport", "ufrag", "pwd", "cert_fp"] as const;

export const AnswerPayload = {
  toCbor(p: AnswerPayload): CborValue {
    return CborValue.map([
      ["transport", transportToCbor(p.transport)],
      ["ufrag", CborValue.text(p.ufrag)],
      ["pwd", CborValue.text(p.pwd)],
      ["cert_fp", CborValue.bytes(p.cert_fp)],
    ]);
  },

  toCanonicalBytes(p: AnswerPayload): Uint8Array {
    return canonicalEncode(AnswerPayload.toCbor(p));
  },

  fromCbor(v: CborValue): AnswerPayload {
    return wrapProtoErrors(() => {
      const m = new MapReader(v);
      m.denyUnknownFields(ANSWER_FIELDS);
      return {
        transport: transportFromU64(m.u64("transport")),
        ufrag: readCappedText(m, "ufrag", MAX_UFRAG_LEN),
        pwd: readCappedText(m, "pwd", MAX_PWD_LEN),
        cert_fp: readCertFp(m),
      };
    });
  },

  fromCanonicalBytes(bytes: Uint8Array): AnswerPayload {
    return wrapProtoErrors(() => AnswerPayload.fromCbor(decodeCanonicalOrThrow(bytes)));
  },
};

// ================================================================================================
// IcePayload
// ================================================================================================

/** One trickled ICE message (DESIGN.md §A6: `env{ice}`) — mirrors Rust's `IcePayload`. Exactly one
 * of `candidate`/`end_of_candidates: true` is meaningful per envelope in normal operation, but
 * (matching the Rust twin and the original spike) the decoder does not assume or enforce this. */
export interface IcePayload {
  /** Omitted (key omission, never CBOR null) when there is no candidate — e.g. the
   * end-of-candidates marker. */
  candidate?: string;
  end_of_candidates: boolean;
}

const ICE_FIELDS = ["candidate", "end_of_candidates"] as const;

export const IcePayload = {
  toCbor(p: IcePayload): CborValue {
    const entries: Array<[string, CborValue]> = [];
    if (p.candidate !== undefined) {
      entries.push(["candidate", CborValue.text(p.candidate)]);
    }
    entries.push(["end_of_candidates", CborValue.bool(p.end_of_candidates)]);
    return CborValue.map(entries);
  },

  toCanonicalBytes(p: IcePayload): Uint8Array {
    return canonicalEncode(IcePayload.toCbor(p));
  },

  fromCbor(v: CborValue): IcePayload {
    return wrapProtoErrors(() => {
      const m = new MapReader(v);
      m.denyUnknownFields(ICE_FIELDS);
      const raw = m.get("candidate");
      let candidate: string | undefined;
      if (raw !== undefined) {
        if (raw.kind !== "text") throw ProtoError.wrongType("candidate");
        checkMaxLen("candidate", raw.value, MAX_CANDIDATE_LEN);
        candidate = raw.value;
      }
      return {
        candidate,
        end_of_candidates: m.bool("end_of_candidates"),
      };
    });
  },

  fromCanonicalBytes(bytes: Uint8Array): IcePayload {
    return wrapProtoErrors(() => IcePayload.fromCbor(decodeCanonicalOrThrow(bytes)));
  },
};
