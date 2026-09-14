// Invite payload container (DESIGN.md §A4's `invite` bullet and §A7b's "Not in the catalog above,
// deliberately" paragraph, `spindle-invite-v1`) — the TypeScript twin of
// `crates/spindle-proto/src/invite.rs`. What an invited person actually receives, as a QR code or
// a link, is not a bare capability: it is this container, carrying the already-signed
// `invite`-kind `Capability` plus the transport hints needed to act on it — where the registry is,
// and how to authenticate its TLS.
//
// Without those hints a scanned capability is inert. It names who may connect and to which host
// fingerprint, but not one byte about where to present it; a host has no listening address at all,
// only an outbound registry connection, and is addressed by fingerprint. The registry endpoint is
// therefore the only address an invite *can* carry (DESIGN.md §A4: "so clients need no baked-in
// registry address").
//
// **Unsigned, deliberately — read this before proposing to sign it.** The whole invite is trusted
// on first use, as one blob: this is where A10.3's `host_fp` pinning happens. An attacker who can
// rewrite `endpoints` can rewrite the `host_root_pk` inside `cap` in the same breath, so a
// signature over part of an atomically-trusted blob authenticates nothing while advertising a
// property the trust model does not provide. A rogue endpoint costs denial of service plus the
// metadata an interceptor already read off the capability; it can never impersonate the host,
// because every later exchange is checked against the pinned `host_fp`. The one security-bearing
// field, `cap`, is an independently verifiable signed `Capability` — `@spindle/crypto`'s
// `verifyCapability` proves it alone.
//
// **Addressed, not bearer (A10.46).** `cap.subject` is the invitee's identity root fingerprint,
// learned out of band before the invite was minted, so a stolen invite is inert without that
// person's root private key. This container adds no bearer-ness back: it carries no secret.
//
// **`INVITE_FORMAT_ID` is not a domain-separation tag** and is deliberately absent from `tags.ts`,
// which owns signature-preimage tags only. Nothing here is signed, so there is no preimage to
// separate, and it must never be used as a signing prefix.
//
// Wire carriage only, per the A9c boundary rule: this module encodes/decodes the CBOR shape and
// enforces length and count caps. It does not verify `cap`, derive `host_fp`, or connect to
// anything. base64url is hand-rolled here for the same reason the canonical CBOR codec is —
// `@spindle/proto` has zero runtime dependencies by design.
//
// REDACTION: no `InviteWireError` message echoes peer-supplied bytes or text. An invite arrives
// from a QR code a user was handed — attacker-controlled, with no delivery-channel trust
// established — so endpoints and pin bytes are reported by length and count only.

import { Capability, MapReader, ProtoError, decodeCanonicalOrThrow } from "./artifacts.js";
import { CborValue, canonicalEncode } from "./canonical.js";

/** The format identifier a scanner uses to recognise these bytes (DESIGN.md §A7b). NOT a
 * domain-separation tag — see this file's header comment. */
export const INVITE_FORMAT_ID = "spindle-invite-v1";

/** The floor `v` a decoder should accept — enforced by `@spindle/crypto`, not here, mirroring the
 * Rust split. */
export const INVITE_MIN_V = 1;

/** The `v` callers emit when building a container today. */
export const INVITE_CURRENT_V = 1;

/** Maximum UTF-8 byte length of one endpoint string. */
export const MAX_ENDPOINT_LEN = 256;

/** Maximum number of endpoints a container may carry. */
export const MAX_ENDPOINTS = 8;

/** Maximum byte length of a `PrivateCaRoot` DER. Note the QR consequence: a container carrying a
 * root near this cap will NOT fit a version-40 level-L QR (2953 B, and base64url inflates by 4/3).
 * The hardened profile is a link-delivered invite, not a scannable one. */
export const MAX_TLS_PIN_LEN = 2048;

// ================================================================================================
// TlsPin
// ================================================================================================

/** How the client should authenticate the registry's TLS certificate (DESIGN.md §A12 row 1's
 * optional hardened profile; §A14's private CA root). */
export type TlsPin =
  | { kind: "WebPki" }
  | { kind: "PrivateCaRoot"; root: Uint8Array };

/** `TlsPin`'s closed field set. */
export const TLS_PIN_FIELDS = ["kind", "root"] as const;

export const TlsPin = {
  webPki(): TlsPin {
    return { kind: "WebPki" };
  },

  privateCaRoot(root: Uint8Array): TlsPin {
    return { kind: "PrivateCaRoot", root };
  },

  toCbor(p: TlsPin): CborValue {
    // Key omission for the absent arm, matching this codebase's optional-field convention: a
    // WebPki pin carries no root, so it carries no `root` key at all.
    if (p.kind === "WebPki") return CborValue.map([["kind", CborValue.uint(0)]]);
    return CborValue.map([
      ["kind", CborValue.uint(1)],
      ["root", CborValue.bytes(p.root)],
    ]);
  },

  fromCbor(v: CborValue): TlsPin {
    return wrapProtoErrors(() => {
      const m = new MapReader(v);
      m.denyUnknownFields(TLS_PIN_FIELDS);
      const kind = m.u64("kind");
      if (kind === 0n) {
        // A `root` alongside `kind: 0` is a contradiction, not a harmless extra: it would let a
        // sender ship a private root every conforming client silently ignores, so two
        // implementations could disagree about which PKI was in force.
        if (m.get("root") !== undefined) throw InviteWireError.webPkiPinCarriesRoot();
        return TlsPin.webPki();
      }
      if (kind === 1n) {
        const root = m.bytes("root");
        if (root.length > MAX_TLS_PIN_LEN) {
          throw InviteWireError.tlsPinTooLong(MAX_TLS_PIN_LEN, root.length);
        }
        if (root.length === 0) throw InviteWireError.emptyPrivateCaRoot();
        return TlsPin.privateCaRoot(root);
      }
      throw ProtoError.invalidEnumValue("tls_pin.kind", kind);
    });
  },
};

// ================================================================================================
// InviteWireError
// ================================================================================================

export type InviteWireErrorKind =
  | "Proto"
  | "EndpointTooLong"
  | "TooManyEndpoints"
  | "NoEndpoints"
  | "TlsPinTooLong"
  | "EmptyPrivateCaRoot"
  | "WebPkiPinCarriesRoot"
  | "NoSupportedEndpoint"
  | "NotBase64Url";

/** Mirrors Rust's `InviteWireError`. Only the `Proto` arm can carry peer text (through
 * `ProtoError.UnknownField`); every other arm carries lengths and counts only. Use `.redacted()`,
 * never `.message`, anywhere this reaches a log call. */
export class InviteWireError extends Error {
  readonly kind: InviteWireErrorKind;
  readonly protoError?: ProtoError;
  readonly max?: number;
  readonly actual?: number;
  readonly offered?: number;
  readonly supported?: number;

  private constructor(
    kind: InviteWireErrorKind,
    message: string,
    extra?: {
      protoError?: ProtoError;
      max?: number;
      actual?: number;
      offered?: number;
      supported?: number;
    },
  ) {
    super(message);
    this.name = "InviteWireError";
    this.kind = kind;
    this.protoError = extra?.protoError;
    this.max = extra?.max;
    this.actual = extra?.actual;
    this.offered = extra?.offered;
    this.supported = extra?.supported;
  }

  static proto(e: ProtoError): InviteWireError {
    return new InviteWireError("Proto", e.message, { protoError: e });
  }

  static endpointTooLong(max: number, actual: number): InviteWireError {
    return new InviteWireError(
      "EndpointTooLong",
      `an endpoint is ${actual} bytes long, exceeding the ${max}-byte cap`,
      { max, actual },
    );
  }

  static tooManyEndpoints(max: number, actual: number): InviteWireError {
    return new InviteWireError(
      "TooManyEndpoints",
      `invite carries ${actual} endpoints, exceeding the ${max}-endpoint cap`,
      { max, actual },
    );
  }

  static noEndpoints(): InviteWireError {
    return new InviteWireError(
      "NoEndpoints",
      "invite carries no endpoints, so it cannot be acted on",
    );
  }

  static tlsPinTooLong(max: number, actual: number): InviteWireError {
    return new InviteWireError(
      "TlsPinTooLong",
      `tls_pin root is ${actual} bytes long, exceeding the ${max}-byte cap`,
      { max, actual },
    );
  }

  static emptyPrivateCaRoot(): InviteWireError {
    return new InviteWireError(
      "EmptyPrivateCaRoot",
      "tls_pin names a private CA root but carries no bytes",
    );
  }

  static webPkiPinCarriesRoot(): InviteWireError {
    return new InviteWireError(
      "WebPkiPinCarriesRoot",
      "tls_pin selects web PKI but also carries a root",
    );
  }

  static noSupportedEndpoint(offered: number, supported: number): InviteWireError {
    return new InviteWireError(
      "NoSupportedEndpoint",
      `none of the ${offered} offered endpoints uses one of the ${supported} supported schemes`,
      { offered, supported },
    );
  }

  static notBase64Url(): InviteWireError {
    return new InviteWireError("NotBase64Url", "input is not unpadded base64url");
  }

  /** A log-safe rendering, with every peer-controlled byte replaced by its shape. Only `Proto`
   * needs rewriting; everything else already carries lengths and counts only. Fails closed if a
   * future `Proto` construction path forgets to set `protoError`. */
  redacted(): string {
    if (this.kind === "Proto") {
      return this.protoError?.redacted() ?? "<InviteWireError: Proto with no protoError>";
    }
    return this.message;
  }
}

function wrapProtoErrors<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (e instanceof ProtoError) throw InviteWireError.proto(e);
    throw e;
  }
}

// ================================================================================================
// InvitePayload
// ================================================================================================

/** The invite payload container — mirrors Rust's `InvitePayload`. Unsigned; see this file's header
 * comment before proposing to change that. */
export interface InvitePayload {
  /** Decoded and carried through unchecked — the floor against {@link INVITE_MIN_V} belongs to
   * `@spindle/crypto`. */
  v: number;
  /** The signed `invite`-kind capability. `subject` is the invitee's `root_fp` (A10.46). */
  cap: Capability;
  /** Ordered registry endpoints, most preferred first. */
  endpoints: string[];
  /** How to authenticate the registry's TLS. */
  tls_pin: TlsPin;
}

/** The closed field set for an `InvitePayload` map.
 *
 * Deliberately absent: any host display name. Unauthenticated text rendered before trust is
 * established is a phishing surface — §A4 already bars labels from certificates for exactly this
 * reason — so the host sends its name over the E2E channel after connect. Adding a key here breaks
 * the corresponding test in `invite.test.ts`, which is the point. */
export const INVITE_FIELDS = ["v", "cap", "endpoints", "tls_pin"] as const;

const textEncoder = new TextEncoder();

function readEndpoints(m: MapReader): string[] {
  const raw = m.require("endpoints");
  if (raw.kind !== "array") throw ProtoError.wrongType("endpoints");
  if (raw.value.length === 0) throw InviteWireError.noEndpoints();
  if (raw.value.length > MAX_ENDPOINTS) {
    throw InviteWireError.tooManyEndpoints(MAX_ENDPOINTS, raw.value.length);
  }
  return raw.value.map((item) => {
    if (item.kind !== "text") throw ProtoError.wrongType("endpoints");
    const len = textEncoder.encode(item.value).length;
    if (len > MAX_ENDPOINT_LEN) throw InviteWireError.endpointTooLong(MAX_ENDPOINT_LEN, len);
    return item.value;
  });
}

export const InvitePayload = {
  toCbor(p: InvitePayload): CborValue {
    return CborValue.map([
      ["v", CborValue.uint(p.v)],
      ["cap", Capability.toCbor(p.cap)],
      ["endpoints", CborValue.array(p.endpoints.map((e) => CborValue.text(e)))],
      ["tls_pin", TlsPin.toCbor(p.tls_pin)],
    ]);
  },

  toCanonicalBytes(p: InvitePayload): Uint8Array {
    return canonicalEncode(InvitePayload.toCbor(p));
  },

  /** The QR/link text form: unpadded base64url of the canonical CBOR (DESIGN.md §A7b). */
  toBase64Url(p: InvitePayload): string {
    return base64UrlEncode(InvitePayload.toCanonicalBytes(p));
  },

  fromCbor(v: CborValue): InvitePayload {
    return wrapProtoErrors(() => {
      const m = new MapReader(v);
      m.denyUnknownFields(INVITE_FIELDS);
      const version = m.u8("v");
      const cap = Capability.fromCbor(m.require("cap"));
      const endpoints = readEndpoints(m);
      const tls_pin = TlsPin.fromCbor(m.require("tls_pin"));
      return { v: version, cap, endpoints, tls_pin };
    });
  },

  fromCanonicalBytes(bytes: Uint8Array): InvitePayload {
    return wrapProtoErrors(() => InvitePayload.fromCbor(decodeCanonicalOrThrow(bytes)));
  },

  fromBase64Url(s: string): InvitePayload {
    return InvitePayload.fromCanonicalBytes(base64UrlDecode(s));
  },

  /** Returns the first endpoint whose scheme appears in `supported`, in the container's own
   * preference order.
   *
   * THROWS when nothing matches. A client that silently found no usable endpoint would surface
   * later as an indefinite "registry degraded", which is a different diagnosis entirely — a
   * browser handed a `tls://`-only invite must say so at the moment it is scanned.
   *
   * `supported` holds scheme names without the `://`, e.g. `["wss"]` in a browser. */
  selectEndpoint(p: InvitePayload, supported: readonly string[]): string {
    for (const e of p.endpoints) {
      const i = e.indexOf("://");
      if (i > 0 && supported.some((s) => asciiLowerEq(e.slice(0, i), s))) return e;
    }
    throw InviteWireError.noSupportedEndpoint(p.endpoints.length, supported.length);
  },
};

/** ASCII-only case-insensitive equality — the exact semantics of Rust's `eq_ignore_ascii_case`.
 *
 * Deliberately NOT `a.toLowerCase() === b.toLowerCase()`: that applies a full Unicode fold, which
 * maps characters Rust's ASCII fold leaves alone (U+212A KELVIN SIGN → `k`, U+1E9E → `ß`). Using
 * it here would make this package accept an endpoint `spindle-proto` refuses. RFC 3986 §3.1 makes
 * a scheme ASCII by construction, so nothing legitimate is lost. */
function asciiLowerEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    let x = a.charCodeAt(i);
    let y = b.charCodeAt(i);
    if (x >= 0x41 && x <= 0x5a) x += 0x20;
    if (y >= 0x41 && y <= 0x5a) y += 0x20;
    if (x !== y) return false;
  }
  return true;
}

// ================================================================================================
// base64url (unpadded)
// ================================================================================================

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Encodes as unpadded base64url (RFC 4648 §5). Total — every input encodes. Hand-rolled rather
 * than using `btoa`, which is DOM-only and emits the standard alphabet with padding. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const remaining = bytes.length - i;
    const b0 = bytes[i]!;
    const b1 = remaining > 1 ? bytes[i + 1]! : 0;
    const b2 = remaining > 2 ? bytes[i + 2]! : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]!;
    if (remaining > 1) out += B64URL[(n >> 6) & 63]!;
    if (remaining > 2) out += B64URL[n & 63]!;
  }
  return out;
}

/** Decodes unpadded base64url. Rejects padding, any byte outside the alphabet, impossible lengths
 * (`len % 4 === 1`), and non-zero unused trailing bits — without that last rule one byte string
 * has several valid-looking encodings and two clients could disagree about whether two QR codes
 * are the same invite. */
export function base64UrlDecode(s: string): Uint8Array {
  if (s.length % 4 === 1) throw InviteWireError.notBase64Url();
  const out: number[] = [];
  for (let i = 0; i < s.length; i += 4) {
    const chunk = s.slice(i, i + 4);
    let n = 0;
    for (let j = 0; j < chunk.length; j++) {
      const v = B64URL.indexOf(chunk[j]!);
      if (v < 0) throw InviteWireError.notBase64Url();
      n |= v << (18 - 6 * j);
    }
    if (chunk.length === 4) {
      out.push((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
    } else if (chunk.length === 3) {
      if ((n & 0xff) !== 0) throw InviteWireError.notBase64Url();
      out.push((n >> 16) & 0xff, (n >> 8) & 0xff);
    } else if (chunk.length === 2) {
      if ((n & 0xffff) !== 0) throw InviteWireError.notBase64Url();
      out.push((n >> 16) & 0xff);
    } else {
      throw InviteWireError.notBase64Url();
    }
  }
  return new Uint8Array(out);
}
