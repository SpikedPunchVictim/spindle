// Device bootstrap state bundle (DESIGN.md §A4 "Adding a device (device bootstrap)", :317-330) —
// the TypeScript twin of `crates/spindle-proto/src/bootstrap.rs`. When a primary device enrolls a
// new device over the QR channel, it signs the new device's certificate *and* hands it this
// bundle: `{registry endpoint, [{sign_pk, agree_pk, member_cap}...]}` — enough state for the new
// device to reach every host the primary already belongs to, without a second round trip through
// each host to fetch its cap individually.
//
// **Deliberately NOT an A7b signed artifact**: no domain-separation tag (see `tags.ts` — there is
// none for this type), no `v`-gated `sig` field, not in the eight-kind catalog `artifacts.ts`
// covers. The bundle's only consumer is the new device, over the same local QR channel that
// conveys the root identity itself, so a signature would have no verifier that channel does not
// already establish independently. The one security-bearing value inside it — `member_cap` — is
// itself an independently verifiable signed `Capability` (nested here as a map, not opaque bytes,
// so a decoded-then-re-encoded copy is byte-identical and its signature still verifies).
//
// **HARD CONSTRAINT — this holds only while the bundle stays on the QR channel.** Relaying it
// over the network, cloud sync, or a file export makes it a signed artifact requiring its own §A7b
// catalog entry: a domain-separation tag, a time rule (an `exp` or equivalent staleness bound —
// today it has none, because the QR channel itself is the freshness/authenticity boundary), and a
// replay rule. Do not relax this without adding that entry first.
//
// `host_fp` and the host's `device_fp` are **derived, never carried** (DESIGN.md:320-322: "so no
// field of an entry can disagree with another"):
//   host_fp   = SHA-256(member_cap.host_root_pk)   -- the check `verify_capability` already makes
//   device_fp = device_fp_of(ALG_ID_V1, sign_pk, agree_pk)
// Both the derivation and `verify_capability` itself live in `@spindle/crypto`, never here — this
// module is wire carriage only (types, canonical CBOR, `deny_unknown_fields`, length/count caps,
// QR budget constants), matching the A9c boundary rule that `spindle-proto`/`@spindle/proto` carry
// zero crypto dependency. `spindle-core`'s `build_bootstrap_bundle`/`verify_bootstrap_bundle` (and
// their eventual `@spindle/crypto` twins) own building, verification, and the QR-fit check.
//
// This module also does **not** enforce `BUNDLE_MIN_V` against a decoded `v` — it decodes `v` and
// carries it through unchecked, exactly mirroring the Rust split: the version floor is
// `@spindle/crypto`'s check (the same layering `CAPABILITY_MIN_V`/`ADMIN_COMMAND_MIN_V` would use
// if this package enforced them, which it deliberately does not either — see those constants in
// `artifacts.ts`).

import { Capability, MapReader, ProtoError, decodeCanonicalOrThrow } from "./artifacts.js";
import { CborValue, canonicalEncode } from "./canonical.js";

/** Lower bound on `DeviceBootstrapBundle.v` a decoder accepts — **not enforced by this module**;
 * see this file's header comment. Exported so `@spindle/crypto` has a single source of truth for
 * the floor, exactly as `CAPABILITY_MIN_V`/`ADMIN_COMMAND_MIN_V` are for their artifacts. */
export const BUNDLE_MIN_V = 1;
/** The `v` this package emits when building a `DeviceBootstrapBundle` today. */
export const BUNDLE_CURRENT_V = 1;

// Why the bundle carries a wire `v` at all — a deliberate divergence from `lib.rs`'s schema-
// choices table, which says only `Envelope`/`Capability`/`AdminCommand` need one because the other
// four A7b artifacts get their version discriminant from their own domain-separation tag. The
// bundle has neither: it is not an A7b artifact (no tag), and DESIGN.md's own notation for it
// omits `v`. But with a closed schema (`deny_unknown_fields`) and no tag to fall back on, a v2
// bundle decoded by a v1 device would otherwise fail with a bare `UnknownField`, not a legible
// "unsupported version" — and the two ends can genuinely ship apart (an old primary enrolling a
// brand-new device). Hence `v`/`BUNDLE_MIN_V`/`BUNDLE_CURRENT_V` despite having no tag at all.

/** Maximum length, in UTF-8 bytes, of `DeviceBootstrapBundle.registry`. Same ceiling as
 * `MAX_INBOX_LEN` (`signaling.ts`) — the same scale of NATS endpoint text. No RFC caps a URL
 * length; 256 also bounds a pathological endpoint to under 9% of the QR L-level budget
 * ({@link QR_V40_L_CAPACITY_BYTES}) so it cannot silently eat the host list. */
export const MAX_REGISTRY_LEN = 256;

/** Maximum number of `BundleEntry` items a `DeviceBootstrapBundle` may carry — DESIGN.md:329's
 * "32-host presentation cap in §A4". Enforced here as a decode-side DoS bound (this module rejects
 * an oversized `entries` array before decoding any entry it contains); it is also the ceiling
 * `spindle-core`'s QR-fit check is measured against. */
export const MAX_BUNDLE_ENTRIES = 32;

/** ISO/IEC 18004 version-40 byte-mode data capacity, in bytes, at error-correction level L. Spec
 * constant, not measured — documentation for the QR-fit arithmetic that lives in `spindle-core`
 * (this package performs no QR encoding itself). */
export const QR_V40_L_CAPACITY_BYTES = 2953;
/** See {@link QR_V40_L_CAPACITY_BYTES} — same standard, error-correction level M. */
export const QR_V40_M_CAPACITY_BYTES = 2331;

/* MEASURED_ENTRY_BYTES is deliberately NOT mirrored here. Rust owns the measured bundle-entry
 * size (`crates/spindle-proto/src/bootstrap.rs`, currently 521 B) because a test pins it there --
 * `keeps_measured_entry_bytes_honest` in `spindle-core` measures a real entry's canonical
 * encoding and fails when it drifts. This package had a second copy with no such test; it sat
 * stale at 546 B (a pre-`nats_fp`-removal, 16-byte-cap-nonce figure) through a fully green TS
 * gate, along with the derived QR host counts in its doc comment. An undefended documentation
 * constant is exactly what failed, so it is deleted rather than re-synced (td-1d7eea). Nothing in
 * TypeScript ever read its value. If a TS consumer genuinely needs the figure, add it WITH a test
 * that measures a real entry -- do not restore a bare literal. */

/** Errors produced while converting between the bundle wire types and `CborValue`/bytes. Mirrors
 * the shape of `SignalingError`: `"Proto"` wraps every rejection kind `ProtoError` already defines
 * (missing/unknown field, wrong CBOR type, non-canonical CBOR, ...); `"RegistryTooLong"`/
 * `"TooManyEntries"` are this module's own additions for the two length/count caps `ProtoError` has
 * no variant for.
 *
 * REDACTION DISCIPLINE: neither `RegistryTooLong`'s nor `TooManyEntries`'s message ever echoes
 * field *content* — `registry` is a bare NATS endpoint string that must never appear in a log
 * line, so both carry only lengths and counts. `Proto`, however, can wrap
 * `ProtoError.UnknownField`, whose `.message` embeds a CBOR map key taken verbatim from the
 * peer's bytes — for this artifact specifically, potentially a hostile QR code a user scanned,
 * not a channel that has already authorized the sender. Use `.redacted()`, never `.message`, on
 * a `BundleWireError` anywhere it reaches a log call — see that method's doc comment. */
export type BundleWireErrorKind = "Proto" | "RegistryTooLong" | "TooManyEntries";

export class BundleWireError extends Error {
  readonly kind: BundleWireErrorKind;
  /** Set for `Proto`. */
  readonly protoError?: ProtoError;
  /** Set for `RegistryTooLong`/`TooManyEntries`. */
  readonly max?: number;
  /** Set for `RegistryTooLong`/`TooManyEntries`. */
  readonly actual?: number;

  private constructor(
    kind: BundleWireErrorKind,
    message: string,
    extra?: { protoError?: ProtoError; max?: number; actual?: number },
  ) {
    super(message);
    this.name = "BundleWireError";
    this.kind = kind;
    this.protoError = extra?.protoError;
    this.max = extra?.max;
    this.actual = extra?.actual;
  }

  static proto(e: ProtoError): BundleWireError {
    return new BundleWireError("Proto", e.message, { protoError: e });
  }

  static registryTooLong(max: number, actual: number): BundleWireError {
    return new BundleWireError(
      "RegistryTooLong",
      `\`registry\` is ${actual} bytes long, exceeding the ${max}-byte cap`,
      { max, actual },
    );
  }

  static tooManyEntries(max: number, actual: number): BundleWireError {
    return new BundleWireError(
      "TooManyEntries",
      `bundle has ${actual} entries, exceeding the ${max}-entry cap`,
      { max, actual },
    );
  }

  /** A log-safe rendering of this error, with every peer-controlled byte replaced by its shape —
   * mirrors `crates/spindle-proto/src/bootstrap.rs`'s `BundleWireError::redacted()` /
   * `RedactedBundleWireError` precisely, one layer up from `ProtoError.redacted()`. Only `Proto`
   * needs rewriting, by delegating to the wrapped `ProtoError`'s own `.redacted()`;
   * `RegistryTooLong`/`TooManyEntries` already carry only lengths/counts (see this class's doc
   * comment's "REDACTION DISCIPLINE" note), so they render exactly as `.message` always did.
   *
   * Use this, never `.message`/`.toString()`, anywhere a `BundleWireError` reaches a log call. */
  redacted(): string {
    if (this.kind === "Proto") {
      // `protoError` is declared optional (`ProtoError?`) so the type permits a `"Proto"`
      // instance with no `protoError`, even though the only construction path today —
      // `BundleWireError.proto()`, the constructor being `private` — always sets it. Fail
      // closed rather than falling through to `this.message` (unsafe, peer-controlled text) if
      // that ever stops being true: a future second `"Proto"` construction path that forgets to
      // set `protoError` must not silently reopen this leak.
      return this.protoError?.redacted() ?? "<BundleWireError: Proto with no protoError>";
    }
    return this.message;
  }
}

/** Runs `fn`, converting any thrown `ProtoError` into the equivalent `BundleWireError.proto` —
 * mirrors Rust's `From<ProtoError> for BundleError` firing through the `?` operator. Anything else
 * (including an already-converted `BundleWireError`, e.g. from a nested `BundleEntry.fromCbor`)
 * propagates unchanged. */
function wrapProtoErrors<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof ProtoError) throw BundleWireError.proto(e);
    throw e;
  }
}

const textEncoder = new TextEncoder();

function checkRegistryLen(registry: string): void {
  const actual = textEncoder.encode(registry).length;
  if (actual > MAX_REGISTRY_LEN) throw BundleWireError.registryTooLong(MAX_REGISTRY_LEN, actual);
}

// ================================================================================================
// BundleEntry
// ================================================================================================

/** One host's worth of bootstrap state (DESIGN.md §A4) — mirrors Rust's `BundleEntry`. EXACTLY
 * these three keys, nothing else, ever: there is deliberately no `host_fp` field here (see this
 * file's header comment) — a decoded map carrying one is rejected as an unknown field, which is
 * exactly what {@link BUNDLE_ENTRY_FIELDS} and the corresponding test in `bootstrap.test.ts` exist
 * to prove. */
export interface BundleEntry {
  /** The host's envelope Ed25519 verifying key (DESIGN.md §A7) — named `sign_pk`, not `host_pk`,
   * because `host_pk` was ambiguous between the host's root key and the envelope key a client
   * actually pins (DESIGN.md v0.9.22 amendment). */
  sign_pk: Uint8Array;
  /** The host's envelope X25519 public key (DESIGN.md §A7). See `sign_pk`'s doc comment for the
   * naming rationale. */
  agree_pk: Uint8Array;
  /** A nested `Capability` map — **not** opaque bytes, unlike `Capability.op_cert`'s convention.
   * Follows `AnswerPayload.member_cap`'s precedent (`signaling.ts`) instead: canonical decode
   * rejects non-canonical input, so a decoded-then-re-encoded `Capability` is byte-identical and
   * its signature still verifies. */
  member_cap: Capability;
}

/** The closed field set for a `BundleEntry` map. Also serves as the neuter-verification
 * acceptance criterion from the settled spec: adding a `host_fp` field to `BundleEntry` (rather
 * than deriving it, as `@spindle/crypto` does) breaks this constant immediately, and the
 * corresponding `bootstrap.test.ts` test asserts its exact contents for this reason. */
export const BUNDLE_ENTRY_FIELDS = ["sign_pk", "agree_pk", "member_cap"] as const;

export const BundleEntry = {
  toCbor(e: BundleEntry): CborValue {
    return CborValue.map([
      ["sign_pk", CborValue.bytes(e.sign_pk)],
      ["agree_pk", CborValue.bytes(e.agree_pk)],
      ["member_cap", Capability.toCbor(e.member_cap)],
    ]);
  },

  fromCbor(v: CborValue): BundleEntry {
    return wrapProtoErrors(() => {
      const m = new MapReader(v);
      m.denyUnknownFields(BUNDLE_ENTRY_FIELDS);
      return {
        sign_pk: m.bytes("sign_pk"),
        agree_pk: m.bytes("agree_pk"),
        member_cap: Capability.fromCbor(m.require("member_cap")),
      };
    });
  },
};

// ================================================================================================
// DeviceBootstrapBundle
// ================================================================================================

/** The device bootstrap state bundle itself (DESIGN.md §A4:317-330) — mirrors Rust's
 * `DeviceBootstrapBundle`. See this file's header comment for the full design rationale (why it is
 * unsigned, the hard constraint that confines it to the QR channel, and the layering that keeps
 * derivation and verification out of this package). */
export interface DeviceBootstrapBundle {
  /** Decoded and carried through unchecked — **not** validated against {@link BUNDLE_MIN_V} here;
   * see this file's header comment. */
  v: number;
  /** The registry endpoint, capped at {@link MAX_REGISTRY_LEN} UTF-8 bytes. */
  registry: string;
  /** At most {@link MAX_BUNDLE_ENTRIES} entries. */
  entries: BundleEntry[];
}

/** The closed field set for a `DeviceBootstrapBundle` map, fed to `denyUnknownFields`. Canonical
 * key order (length-first then bytewise, per `canonicalEncode`) is `v`(1) < `entries`(7) <
 * `registry`(8) — listed here in the type's natural field order instead, since membership, not
 * order, is all `denyUnknownFields` checks. */
export const BUNDLE_FIELDS = ["v", "registry", "entries"] as const;

function readEntries(m: MapReader): BundleEntry[] {
  const raw = m.require("entries");
  if (raw.kind !== "array") throw ProtoError.wrongType("entries");
  if (raw.value.length > MAX_BUNDLE_ENTRIES) {
    throw BundleWireError.tooManyEntries(MAX_BUNDLE_ENTRIES, raw.value.length);
  }
  return raw.value.map((item) => BundleEntry.fromCbor(item));
}

export const DeviceBootstrapBundle = {
  toCbor(b: DeviceBootstrapBundle): CborValue {
    return CborValue.map([
      ["v", CborValue.uint(b.v)],
      ["registry", CborValue.text(b.registry)],
      ["entries", CborValue.array(b.entries.map(BundleEntry.toCbor))],
    ]);
  },

  toCanonicalBytes(b: DeviceBootstrapBundle): Uint8Array {
    return canonicalEncode(DeviceBootstrapBundle.toCbor(b));
  },

  fromCbor(v: CborValue): DeviceBootstrapBundle {
    return wrapProtoErrors(() => {
      const m = new MapReader(v);
      m.denyUnknownFields(BUNDLE_FIELDS);
      // `v` is decoded and carried, never checked against BUNDLE_MIN_V — see the header comment.
      const version = m.u8("v");
      const registry = m.text("registry");
      checkRegistryLen(registry);
      const entries = readEntries(m);
      return { v: version, registry, entries };
    });
  },

  fromCanonicalBytes(bytes: Uint8Array): DeviceBootstrapBundle {
    return wrapProtoErrors(() => DeviceBootstrapBundle.fromCbor(decodeCanonicalOrThrow(bytes)));
  },
};
