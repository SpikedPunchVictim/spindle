// Invite payload container (`spindle-invite-v1`, DESIGN.md §A4 "Invites", A10.46, td-bbb933) —
// the TypeScript twin's test suite. Two halves:
//
//   1. a behavioural mirror of `crates/spindle-proto/src/invite.rs`'s own unit tests, test for
//      test, so the two implementations are held to the same rules rather than only to the same
//      bytes on the happy path;
//   2. golden-vector conformance against the Rust-generated `vectors/invite.json`.
//
// The second half alone would be insufficient. A golden vector is built from *valid* inputs, so
// it exercises only the accept path: every disagreement about what to *reject* — an unknown
// field, an over-long endpoint, a web-PKI pin that also carries a root — is outside its reach by
// construction. That is why the rejection tests below are mirrored individually rather than
// assumed to follow from byte-identical encoding.
//
// NOTE ON DECODED SHAPE: `invite.json`'s `decoded` field is the generic `{type, value}` CBOR-tree
// shape (shared with `bootstrap.json`/`signaling.json`), not the flat field/hex-string object
// `capability.json` etc. use — see `parseInvitePayload`'s doc comment in `helpers.ts`.

import { describe, expect, it } from "vitest";

import { CAPABILITY_CURRENT_V, CapKind, Capability, ProtoError } from "../src/artifacts.js";
import { CborValue, canonicalDecode, type CborValue as CborValueType } from "../src/canonical.js";
import { QR_V40_L_CAPACITY_BYTES } from "../src/bootstrap.js";
import { bytesToHex, hexToBytes } from "../src/hex.js";
import {
  base64UrlDecode,
  base64UrlEncode,
  INVITE_CURRENT_V,
  INVITE_FIELDS,
  INVITE_FORMAT_ID,
  InvitePayload,
  InviteWireError,
  MAX_ENDPOINT_LEN,
  MAX_ENDPOINTS,
  MAX_TLS_PIN_LEN,
  TlsPin,
} from "../src/invite.js";
import * as tags from "../src/tags.js";
import { addUnknownKey, loadVectorFile, normalize, parseInvitePayload } from "./helpers.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function expectThrows<E>(ctor: new (...args: any[]) => E, fn: () => unknown): E {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(ctor);
    return e as E;
  }
  throw new Error("expected a throw, got none");
}

function sampleCapability(): Capability {
  return {
    v: CAPABILITY_CURRENT_V,
    host_fp: new Uint8Array(32).fill(0x01),
    host_root_pk: new Uint8Array(32).fill(0x02),
    op_cert: new Uint8Array(16).fill(0x03),
    kind: CapKind.Invite,
    subject: new Uint8Array(32).fill(0x04),
    cap_epoch: 7n,
    exp: 1_800_000_000n,
    nonce: new Uint8Array(32).fill(0x05),
    sig: new Uint8Array(64).fill(0x06),
  };
}

/** The exact fixture `invite.rs`'s `sample_invite()` builds. Kept byte-identical on purpose: the
 * round-trip test below pins its canonical encoding, so a drift in either fixture shows up as a
 * hex mismatch rather than as two suites quietly testing different things. */
function sampleInvite(): InvitePayload {
  return {
    v: INVITE_CURRENT_V,
    cap: sampleCapability(),
    endpoints: ["wss://registry.example:443", "tls://registry.example:4222"],
    tls_pin: TlsPin.webPki(),
  };
}

const utf8 = new TextEncoder();

/** A container map whose `v` and `cap` are valid and whose `endpoints`/`tls_pin` are supplied
 * raw, so a test can make exactly those two fields invalid at once. */
function inviteMapWith(endpoints: CborValue, tlsPin: CborValue): CborValue {
  return CborValue.map([
    ["v", CborValue.uint(INVITE_CURRENT_V)],
    ["cap", Capability.toCbor(sampleCapability())],
    ["endpoints", endpoints],
    ["tls_pin", tlsPin],
  ]);
}

// ------------------------------------------------------------------------------------------------
// Round-trips
// ------------------------------------------------------------------------------------------------

describe("InvitePayload round-trips", () => {
  it("round-trips through canonical bytes", () => {
    const invite = sampleInvite();
    const bytes = InvitePayload.toCanonicalBytes(invite);
    expect(normalize(InvitePayload.fromCanonicalBytes(bytes))).toEqual(normalize(invite));
  });

  it("round-trips through base64url, unpadded", () => {
    const invite = sampleInvite();
    const text = InvitePayload.toBase64Url(invite);
    expect(text).not.toContain("=");
    expect(normalize(InvitePayload.fromBase64Url(text))).toEqual(normalize(invite));
  });

  it("round-trips a private CA root pin", () => {
    const invite: InvitePayload = {
      ...sampleInvite(),
      tls_pin: TlsPin.privateCaRoot(new Uint8Array(512).fill(0xab)),
    };
    const decoded = InvitePayload.fromCanonicalBytes(InvitePayload.toCanonicalBytes(invite));
    expect(normalize(decoded)).toEqual(normalize(invite));
  });
});

// ------------------------------------------------------------------------------------------------
// Closed schema
// ------------------------------------------------------------------------------------------------

describe("InvitePayload schema", () => {
  it("INVITE_FIELDS is exactly v, cap, endpoints, tls_pin", () => {
    expect([...INVITE_FIELDS]).toEqual(["v", "cap", "endpoints", "tls_pin"]);
  });

  // A host-supplied display name is a phishing surface: it renders next to a fingerprint the user
  // cannot read, so it would be trusted over the thing that actually identifies the host. The
  // schema is closed specifically so a later producer cannot smuggle one in.
  it("rejects an unknown field such as a host display name", () => {
    const m = InvitePayload.toCbor(sampleInvite());
    const mutated = addUnknownKey(m, "host_name", CborValue.text("Totally Real Host"));
    const err = expectThrows(InviteWireError, () => InvitePayload.fromCanonicalBytes(mutated));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("UnknownField");
    expect(err.protoError?.message).toContain("host_name");
  });
});

// ------------------------------------------------------------------------------------------------
// Endpoint rules
// ------------------------------------------------------------------------------------------------

describe("endpoint rules", () => {
  it("rejects an invite with no endpoints", () => {
    const invite: InvitePayload = { ...sampleInvite(), endpoints: [] };
    const err = expectThrows(InviteWireError, () =>
      InvitePayload.fromCbor(InvitePayload.toCbor(invite)),
    );
    expect(err.kind).toBe("NoEndpoints");
  });

  it("rejects more endpoints than the cap allows", () => {
    const endpoints = Array.from({ length: MAX_ENDPOINTS + 1 }, (_, i) => `wss://h${i}`);
    const invite: InvitePayload = { ...sampleInvite(), endpoints };
    const err = expectThrows(InviteWireError, () =>
      InvitePayload.fromCbor(InvitePayload.toCbor(invite)),
    );
    expect(err.kind).toBe("TooManyEndpoints");
    expect(err.max).toBe(MAX_ENDPOINTS);
    expect(err.actual).toBe(MAX_ENDPOINTS + 1);
  });

  it("rejects an endpoint longer than the cap", () => {
    const invite: InvitePayload = { ...sampleInvite(), endpoints: ["w".repeat(MAX_ENDPOINT_LEN + 1)] };
    const err = expectThrows(InviteWireError, () =>
      InvitePayload.fromCbor(InvitePayload.toCbor(invite)),
    );
    expect(err.kind).toBe("EndpointTooLong");
    expect(err.max).toBe(MAX_ENDPOINT_LEN);
    expect(err.actual).toBe(MAX_ENDPOINT_LEN + 1);
  });

  // The cap is on UTF-8 *bytes*, which is what Rust's `String::len()` returns. A TypeScript
  // reader measuring `String.length` counts UTF-16 units instead, so this endpoint — 129 chars,
  // 258 bytes — would pass there and fail in Rust: one implementation accepting an invite the
  // other refuses, which is the whole failure mode this twin exists to prevent.
  it("measures the endpoint cap in UTF-8 bytes, not UTF-16 units", () => {
    const endpoint = "é".repeat(129);
    expect(endpoint.length).toBeLessThan(MAX_ENDPOINT_LEN);
    expect(utf8.encode(endpoint).length).toBe(MAX_ENDPOINT_LEN + 2);
    const invite: InvitePayload = { ...sampleInvite(), endpoints: [endpoint] };
    const err = expectThrows(InviteWireError, () =>
      InvitePayload.fromCbor(InvitePayload.toCbor(invite)),
    );
    expect(err.kind).toBe("EndpointTooLong");
    expect(err.actual).toBe(MAX_ENDPOINT_LEN + 2);
  });
});

// ------------------------------------------------------------------------------------------------
// Decode order on multi-invalid input (twin with invite.rs)
// ------------------------------------------------------------------------------------------------

// Each input below is invalid in two places, so the assertion pins *which* error wins.
// `readEndpoints` applies the count rules immediately after reading the array and each endpoint's
// length during the item pass, before `fromCbor` ever looks at `tls_pin`; the Rust twin must do
// the same. A decoder that reordered those checks would still reject these, but with a different
// error kind — and two implementations that disagree about the first error will eventually
// disagree about validity. The corresponding Rust tests are
// `an_empty_endpoint_list_is_reported_before_an_invalid_tls_pin_kind`,
// `too_many_endpoints_are_reported_before_an_invalid_tls_pin_kind`, and
// `an_over_long_endpoint_is_reported_before_a_non_text_sibling`.
describe("decode order on multi-invalid input", () => {
  it("reports NoEndpoints before an invalid tls_pin kind", () => {
    const v = inviteMapWith(
      CborValue.array([]),
      CborValue.map([["kind", CborValue.uint(2)]]),
    );
    const err = expectThrows(InviteWireError, () => InvitePayload.fromCbor(v));
    expect(err.kind).toBe("NoEndpoints");
  });

  it("reports TooManyEndpoints before an invalid tls_pin kind", () => {
    const endpoints = Array.from({ length: MAX_ENDPOINTS + 1 }, (_, i) =>
      CborValue.text(`wss://h${i}`),
    );
    const v = inviteMapWith(
      CborValue.array(endpoints),
      CborValue.map([["kind", CborValue.uint(2)]]),
    );
    const err = expectThrows(InviteWireError, () => InvitePayload.fromCbor(v));
    expect(err.kind).toBe("TooManyEndpoints");
  });

  it("reports EndpointTooLong before a non-text sibling endpoint", () => {
    const v = inviteMapWith(
      CborValue.array([CborValue.text("w".repeat(MAX_ENDPOINT_LEN + 1)), CborValue.uint(42)]),
      TlsPin.toCbor(TlsPin.webPki()),
    );
    const err = expectThrows(InviteWireError, () => InvitePayload.fromCbor(v));
    expect(err.kind).toBe("EndpointTooLong");
  });
});

// ------------------------------------------------------------------------------------------------
// Endpoint selection — the loud-failure requirement
// ------------------------------------------------------------------------------------------------

describe("selectEndpoint", () => {
  it("returns the first supported endpoint in the container's own order", () => {
    const invite = sampleInvite();
    // The container lists wss first, then tls. A client supporting both must honour the
    // container's preference order, not its own argument order.
    expect(InvitePayload.selectEndpoint(invite, ["tls", "wss"])).toBe(
      "wss://registry.example:443",
    );
    expect(InvitePayload.selectEndpoint(invite, ["tls"])).toBe("tls://registry.example:4222");
  });

  // AC 5. A browser handed a `tls://`-only invite must fail at scan time, not degrade into an
  // indefinite "registry degraded" — a different diagnosis entirely (DESIGN.md §A4).
  it("fails loudly when no scheme is supported", () => {
    const invite: InvitePayload = {
      ...sampleInvite(),
      endpoints: ["tls://registry.example:4222", "nats://registry.example:4222"],
    };
    const err = expectThrows(InviteWireError, () =>
      InvitePayload.selectEndpoint(invite, ["wss"]),
    );
    expect(err.kind).toBe("NoSupportedEndpoint");
    expect(err.offered).toBe(2);
    expect(err.supported).toBe(1);
  });

  it("matches the scheme only at the start and only before a separator", () => {
    const invite: InvitePayload = {
      ...sampleInvite(),
      // `wss` appears in the host name and as a bare prefix with no `://`; neither is a scheme
      // match. A substring search would wrongly accept both.
      endpoints: ["tls://wss.example:4222", "wsshttp://example"],
    };
    const err = expectThrows(InviteWireError, () =>
      InvitePayload.selectEndpoint(invite, ["wss"]),
    );
    expect(err.kind).toBe("NoSupportedEndpoint");
  });

  it("is case-insensitive, as RFC 3986 §3.1 requires", () => {
    const invite: InvitePayload = { ...sampleInvite(), endpoints: ["WSS://registry.example:443"] };
    expect(InvitePayload.selectEndpoint(invite, ["wss"])).toBe("WSS://registry.example:443");
  });

  // The twin-divergence guard. `String.prototype.toLowerCase()` folds U+212A KELVIN SIGN to `k`,
  // which Rust's `eq_ignore_ascii_case` leaves alone. Had this package reached for the obvious
  // `toLowerCase()` comparison it would accept an endpoint `spindle-proto` refuses — and this is
  // the test that catches it. Its Rust counterpart is `scheme_matching_does_not_unicode_fold`.
  it("does not Unicode-fold the scheme", () => {
    const invite: InvitePayload = {
      ...sampleInvite(),
      endpoints: ["W\u{212A}\u{212A}://registry.example:443"],
    };
    expect("W\u{212A}\u{212A}".toLowerCase()).toBe("wkk"); // the trap, demonstrated
    expectThrows(InviteWireError, () => InvitePayload.selectEndpoint(invite, ["wkk"]));
  });
});

// ------------------------------------------------------------------------------------------------
// tls_pin rules
// ------------------------------------------------------------------------------------------------

describe("TlsPin", () => {
  it("rejects a web-PKI pin that also carries a root", () => {
    const v = CborValue.map([
      ["kind", CborValue.uint(0)],
      ["root", CborValue.bytes(new Uint8Array(8).fill(0xaa))],
    ]);
    const err = expectThrows(InviteWireError, () => TlsPin.fromCbor(v));
    expect(err.kind).toBe("WebPkiPinCarriesRoot");
  });

  it("rejects a private CA root pin with no bytes", () => {
    const v = CborValue.map([
      ["kind", CborValue.uint(1)],
      ["root", CborValue.bytes(new Uint8Array(0))],
    ]);
    const err = expectThrows(InviteWireError, () => TlsPin.fromCbor(v));
    expect(err.kind).toBe("EmptyPrivateCaRoot");
  });

  it("rejects a private CA root over the cap", () => {
    const v = CborValue.map([
      ["kind", CborValue.uint(1)],
      ["root", CborValue.bytes(new Uint8Array(MAX_TLS_PIN_LEN + 1).fill(0xaa))],
    ]);
    const err = expectThrows(InviteWireError, () => TlsPin.fromCbor(v));
    expect(err.kind).toBe("TlsPinTooLong");
    expect(err.max).toBe(MAX_TLS_PIN_LEN);
    expect(err.actual).toBe(MAX_TLS_PIN_LEN + 1);
  });

  it("rejects an unknown kind", () => {
    const v = CborValue.map([["kind", CborValue.uint(2)]]);
    const err = expectThrows(InviteWireError, () => TlsPin.fromCbor(v));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("InvalidEnumValue");
  });
});

// ------------------------------------------------------------------------------------------------
// The format id is not a signing tag
// ------------------------------------------------------------------------------------------------

// INVITE_FORMAT_ID identifies a container format; it is not a domain-separation tag and must never
// become one. Pinned here — as in Rust — so a later author cannot quietly move it into `tags.ts`
// and start prefixing signature preimages with it, at which point its relationship to the real
// tags (prefix-freeness) would suddenly matter and nothing would have checked it.
it("the format id is not usable as a signing tag", () => {
  const signingTags: Uint8Array[] = [
    tags.ENVELOPE_V1,
    tags.CAPABILITY_V1,
    tags.ADMISSION_TOKEN_V1,
    tags.DEVICE_CERT_V2,
    tags.REVOCATION_V1,
    tags.ADMIN_COMMAND_V1,
    tags.HOST_OP_KEY_CERT_V2,
    tags.HOST_DEVICE_CERT_V1,
    tags.SESSION_ATTESTATION_V1,
    tags.HOST_SESSION_ATTESTATION_V1,
  ];
  const id = new TextDecoder().decode(utf8.encode(INVITE_FORMAT_ID));
  for (const t of signingTags) {
    const text = new TextDecoder().decode(t);
    expect(text).not.toBe(id);
    expect(text.startsWith(id)).toBe(false);
    expect(id.startsWith(text)).toBe(false);
  }
});

// ------------------------------------------------------------------------------------------------
// base64url
// ------------------------------------------------------------------------------------------------

describe("base64url", () => {
  it("matches RFC 4648 §10's test vectors, unpadded", () => {
    for (const [input, expected] of [
      ["", ""],
      ["f", "Zg"],
      ["fo", "Zm8"],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg"],
      ["fooba", "Zm9vYmE"],
      ["foobar", "Zm9vYmFy"],
    ] as const) {
      expect(base64UrlEncode(utf8.encode(input))).toBe(expected);
      expect(base64UrlDecode(expected)).toEqual(utf8.encode(input));
    }
  });

  it("uses the URL-safe alphabet, not the standard one", () => {
    // 0xFB 0xFF 0xBF encodes to the two indices (62, 63) that differ between the alphabets.
    const encoded = base64UrlEncode(Uint8Array.from([0xfb, 0xff, 0xbf]));
    expect(encoded).toBe("-_-_");
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
  });

  it("rejects padding, impossible lengths, and standard-alphabet bytes", () => {
    expect(() => base64UrlDecode("Zm9vYg==")).toThrow(InviteWireError);
    expect(() => base64UrlDecode("Zm9vY")).toThrow(InviteWireError);
    expect(() => base64UrlDecode("Zm9+")).toThrow(InviteWireError);
  });

  // Without this rule a single byte string has several valid-looking encodings, so two clients
  // could disagree about whether two QR codes are the same invite — the canonicality argument
  // `canonical.ts` makes for CBOR, applied to the text layer.
  it("rejects non-zero unused trailing bits", () => {
    expect(base64UrlDecode("Zg")).toEqual(utf8.encode("f"));
    expect(() => base64UrlDecode("Zh")).toThrow(InviteWireError);
    expect(base64UrlDecode("Zm8")).toEqual(utf8.encode("fo"));
    expect(() => base64UrlDecode("Zm9")).toThrow(InviteWireError);
  });
});

// ------------------------------------------------------------------------------------------------
// Redaction
// ------------------------------------------------------------------------------------------------

describe("redaction", () => {
  it("no error variant echoes peer text or bytes", () => {
    const long = "e".repeat(MAX_ENDPOINT_LEN + 1);
    const invite: InvitePayload = { ...sampleInvite(), endpoints: [long] };
    const err = expectThrows(InviteWireError, () =>
      InvitePayload.fromCbor(InvitePayload.toCbor(invite)),
    );
    expect(`${err.message} / ${err.redacted()}`).not.toContain(long);
  });

  it("redacted() withholds an unknown field name", () => {
    const err = InviteWireError.proto(ProtoError.unknownField("secret_key_name"));
    expect(err.message).toContain("secret_key_name");
    expect(err.redacted()).not.toContain("secret_key_name");
  });
});

// ------------------------------------------------------------------------------------------------
// Size
// ------------------------------------------------------------------------------------------------

// Reports the encoded size of a baseline container built from this file's **test fixture**, and
// asserts only the property that matters at this layer: it fits a level-L QR. The number is
// deliberately not pinned — the fixture capability carries filler field widths (a 16-byte
// `op_cert`, where a real one is far larger), so pinning it would pin the fixture, not the
// artifact. The authoritative figure is measured through the production invite issuer.
it("a baseline invite fits a level-L QR", () => {
  const invite = sampleInvite();
  const text = InvitePayload.toBase64Url(invite);
  expect(text.length).toBeLessThan(QR_V40_L_CAPACITY_BYTES);
});

// ------------------------------------------------------------------------------------------------
// Golden-vector conformance (vectors/invite.json)
// ------------------------------------------------------------------------------------------------

interface InviteCase {
  name: string;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  decoded: any;
  canonical_cbor_hex: string;
  base64url: string;
}

interface InviteDoc {
  description: string;
  cases: InviteCase[];
}

describe("vectors/invite.json", () => {
  const doc = loadVectorFile("invite.json") as InviteDoc;

  // The corpus's own coverage, asserted rather than assumed. A golden vector pins the alphabet
  // only if some case's text actually *contains* the two characters that distinguish it — and
  // five of these six, built from runs of one repeated byte, contain neither. See the
  // `private_ca_root_alphabet_edges` case's description in `gen_vectors.rs`.
  it("exercises the URL-safe alphabet's distinguishing characters", () => {
    const all = doc.cases.map((c) => c.base64url).join("");
    expect(all).toContain("-");
    expect(all).toContain("_");
  });

  it("covers both tls_pin arms", () => {
    const kinds = new Set(doc.cases.map((c) => parseInvitePayload(c.decoded).tls_pin.kind));
    expect(kinds).toEqual(new Set(["WebPki", "PrivateCaRoot"]));
  });

  for (const c of doc.cases) {
    describe(c.name, () => {
      it("encodes `decoded` to canonical_cbor_hex", () => {
        const value = parseInvitePayload(c.decoded);
        expect(bytesToHex(InvitePayload.toCanonicalBytes(value))).toBe(c.canonical_cbor_hex);
      });

      it("decodes canonical_cbor_hex back to `decoded`", () => {
        const expectedValue = parseInvitePayload(c.decoded);
        const decoded = InvitePayload.fromCanonicalBytes(hexToBytes(c.canonical_cbor_hex));
        expect(normalize(decoded)).toEqual(normalize(expectedValue));
      });

      // The transport form, not just the CBOR: a person pastes this text into a client, so the
      // alphabet and the no-padding rule are as load-bearing as the byte encoding underneath.
      it("encodes to the vector's base64url text, and back", () => {
        const value = parseInvitePayload(c.decoded);
        expect(InvitePayload.toBase64Url(value)).toBe(c.base64url);
        expect(normalize(InvitePayload.fromBase64Url(c.base64url))).toEqual(normalize(value));
      });
    });
  }

  describe("mutation rejection (first case)", () => {
    const mapValue: CborValueType = canonicalDecode(hexToBytes(doc.cases[0]!.canonical_cbor_hex));

    it("rejects an unknown field added to the container", () => {
      const mutated = addUnknownKey(mapValue, "zz_unknown", CborValue.uint(1n));
      const err = expectThrows(InviteWireError, () => InvitePayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("UnknownField");
    });
  });
});
