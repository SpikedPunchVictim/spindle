// Golden-vector conformance for the signaling payload wire types (vectors/signaling.json) — the
// TS twin of `crates/spindle-proto/src/signaling.rs`. Covers `OfferPayload`/`AnswerPayload`/
// `IcePayload`: each vector case is cross-checked three ways, exactly as `vfsRpc.test.ts` does for
// `vectors/vfs-rpc.json` — (1) the generic `{type, value}` CBOR tree round-trips to
// `canonical_cbor_hex` independent of this package's typed layer, (2) the typed decoder accepts
// that same generic tree and re-encodes byte-identically, and (3) decoding `canonical_cbor_hex`
// directly through the typed layer reproduces the same typed value and re-encodes
// byte-identically.
//
// Plus negative tests per the established convention: swapped key order, a lengthened
// (non-shortest-form) integer field (offers/answers only — `IcePayload` has no uint-valued field
// to mutate), and an unrecognized field, each asserted to be rejected — plus hand-rolled parity
// tests translating `signaling.rs`'s own inline unit tests (boundary-length fields, invalid
// transport discriminant, wrong CBOR type / wrong length for `cert_fp`, missing required field,
// non-canonical encoding, the `KIND_*`/`Transport` discriminant constants).

import { describe, expect, it } from "vitest";

import {
  CborError,
  CborValue,
  canonicalDecode,
  canonicalEncode,
  type CborValue as CborValueType,
} from "../src/canonical.js";
import { bytesToHex, hexToBytes } from "../src/hex.js";
import { ProtoError } from "../src/artifacts.js";
import {
  AnswerPayload,
  CERT_FP_LEN,
  IcePayload,
  KIND_ANSWER,
  KIND_ICE,
  KIND_OFFER,
  MAX_CANDIDATE_LEN,
  MAX_INBOX_LEN,
  MAX_PWD_LEN,
  MAX_UFRAG_LEN,
  OfferPayload,
  SignalingError,
  Transport,
} from "../src/signaling.js";
import {
  addUnknownKey,
  lengthenUintField,
  loadVectorFile,
  normalize,
  parseCborTree,
  swapFirstTwoEntries,
} from "./helpers.js";

interface SignalingCase {
  name: string;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  decoded: any;
  canonical_cbor_hex: string;
}

interface SignalingDoc {
  description: string;
  offers: SignalingCase[];
  answers: SignalingCase[];
  ice: SignalingCase[];
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

const doc = loadVectorFile("signaling.json") as SignalingDoc;

interface Twin<T> {
  fromCbor(v: CborValueType): T;
  toCanonicalBytes(t: T): Uint8Array;
  fromCanonicalBytes(bytes: Uint8Array): T;
}

function describeVectorCases<T>(label: string, cases: SignalingCase[], twin: Twin<T>) {
  describe(label, () => {
    cases.forEach((c, i) => {
      describe(`${c.name} [${i}]`, () => {
        it("generic CBOR tree round-trips to canonical_cbor_hex", () => {
          const tree = parseCborTree(c.decoded);
          expect(bytesToHex(canonicalEncode(tree))).toBe(c.canonical_cbor_hex);
        });

        it("typed decoder parses the vector's tree and re-encodes byte-identically", () => {
          const tree = parseCborTree(c.decoded);
          const typed = twin.fromCbor(tree);
          expect(bytesToHex(twin.toCanonicalBytes(typed))).toBe(c.canonical_cbor_hex);
        });

        it("decodes canonical_cbor_hex to the same typed value and re-encodes byte-identically", () => {
          const expected = twin.fromCbor(parseCborTree(c.decoded));
          const decoded = twin.fromCanonicalBytes(hexToBytes(c.canonical_cbor_hex));
          expect(normalize(decoded)).toEqual(normalize(expected));
          expect(bytesToHex(twin.toCanonicalBytes(decoded))).toBe(c.canonical_cbor_hex);
        });
      });
    });
  });
}

describeVectorCases("signaling.json offers", doc.offers, OfferPayload);
describeVectorCases("signaling.json answers", doc.answers, AnswerPayload);
describeVectorCases("signaling.json ice", doc.ice, IcePayload);

describe("mutation rejection", () => {
  describe("offer (first case)", () => {
    const first = doc.offers[0];
    const mapValue = canonicalDecode(hexToBytes(first.canonical_cbor_hex));

    it("rejects a swapped key order", () => {
      const mutated = swapFirstTwoEntries(mapValue);
      const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
      expect(cborErr.kind).toBe("MapKeyOrder");
      const err = expectThrows(SignalingError, () => OfferPayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("Cbor");
      expect(err.protoError?.cborError?.kind).toBe("MapKeyOrder");
    });

    it("rejects a lengthened (non-shortest-form) integer field", () => {
      const key = firstUintFieldKey(mapValue);
      const mutated = lengthenUintField(mapValue, key);
      const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
      expect(cborErr.kind).toBe("NonShortestForm");
      const err = expectThrows(SignalingError, () => OfferPayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("Cbor");
      expect(err.protoError?.cborError?.kind).toBe("NonShortestForm");
    });

    it("rejects an unrecognized field", () => {
      const mutated = addUnknownKey(mapValue, "bogus", CborValue.uint(0));
      expect(() => canonicalDecode(mutated)).not.toThrow();
      const err = expectThrows(SignalingError, () => OfferPayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("UnknownField");
      expect(err.protoError?.field).toBe("bogus");
    });
  });

  describe("answer (first case)", () => {
    const first = doc.answers[0];
    const mapValue = canonicalDecode(hexToBytes(first.canonical_cbor_hex));

    it("rejects a swapped key order", () => {
      const mutated = swapFirstTwoEntries(mapValue);
      const err = expectThrows(SignalingError, () => AnswerPayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.cborError?.kind).toBe("MapKeyOrder");
    });

    it("rejects a lengthened (non-shortest-form) integer field", () => {
      const key = firstUintFieldKey(mapValue);
      const mutated = lengthenUintField(mapValue, key);
      const err = expectThrows(SignalingError, () => AnswerPayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.cborError?.kind).toBe("NonShortestForm");
    });

    it("rejects an unrecognized field", () => {
      const mutated = addUnknownKey(mapValue, "bogus", CborValue.uint(0));
      const err = expectThrows(SignalingError, () => AnswerPayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("UnknownField");
      expect(err.protoError?.field).toBe("bogus");
    });
  });

  describe("ice (first case)", () => {
    const first = doc.ice[0];
    const mapValue = canonicalDecode(hexToBytes(first.canonical_cbor_hex));

    it("rejects a swapped key order", () => {
      const mutated = swapFirstTwoEntries(mapValue);
      const err = expectThrows(SignalingError, () => IcePayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.cborError?.kind).toBe("MapKeyOrder");
    });

    it("rejects an unrecognized field", () => {
      const mutated = addUnknownKey(mapValue, "bogus", CborValue.uint(0));
      const err = expectThrows(SignalingError, () => IcePayload.fromCanonicalBytes(mutated));
      expect(err.kind).toBe("Proto");
      expect(err.protoError?.kind).toBe("UnknownField");
      expect(err.protoError?.field).toBe("bogus");
    });
  });
});

// ------------------------------------------------------------------------------------------------
// Hand-rolled parity tests translating signaling.rs's own inline `#[cfg(test)]` unit tests.
// ------------------------------------------------------------------------------------------------

function fp(byte: number): Uint8Array {
  return new Uint8Array(CERT_FP_LEN).fill(byte);
}

function sampleOffer(): OfferPayload {
  return {
    inbox: "_INBOX_abc123.x",
    transport: Transport.Quic,
    ufrag: "clientufrag1",
    pwd: "clientpassword1234567890ab",
    cert_fp: fp(0x11),
  };
}

function sampleAnswer(): AnswerPayload {
  return {
    transport: Transport.WebRtc,
    ufrag: "hostufrag1",
    pwd: "hostpassword1234567890abcd",
    cert_fp: fp(0x22),
  };
}

describe("round trips (signaling.rs parity)", () => {
  it("offer round-trips both transports", () => {
    for (const transport of [Transport.Quic, Transport.WebRtc]) {
      const offer = { ...sampleOffer(), transport };
      const bytes = OfferPayload.toCanonicalBytes(offer);
      const decoded = OfferPayload.fromCanonicalBytes(bytes);
      expect(normalize(decoded)).toEqual(normalize(offer));
    }
  });

  it("answer round-trips both transports", () => {
    for (const transport of [Transport.Quic, Transport.WebRtc]) {
      const answer = { ...sampleAnswer(), transport };
      const bytes = AnswerPayload.toCanonicalBytes(answer);
      const decoded = AnswerPayload.fromCanonicalBytes(bytes);
      expect(normalize(decoded)).toEqual(normalize(answer));
    }
  });

  it("ice round-trips a real candidate", () => {
    const ice: IcePayload = {
      candidate: "candidate:1 1 UDP 2130706431 10.0.0.1 54321 typ host",
      end_of_candidates: false,
    };
    const decoded = IcePayload.fromCanonicalBytes(IcePayload.toCanonicalBytes(ice));
    expect(normalize(decoded)).toEqual(normalize(ice));
  });

  it("ice round-trips the end-of-candidates marker with candidate omitted (not null)", () => {
    const ice: IcePayload = { end_of_candidates: true };
    const cbor = IcePayload.toCbor(ice);
    if (cbor.kind !== "map") throw new Error("expected map");
    expect(cbor.value).toHaveLength(1);
    expect(cbor.value[0][0]).toEqual(CborValue.text("end_of_candidates"));

    const decoded = IcePayload.fromCanonicalBytes(IcePayload.toCanonicalBytes(ice));
    expect(normalize(decoded)).toEqual(normalize(ice));
  });
});

describe("boundary lengths (signaling.rs parity)", () => {
  it("ufrag/pwd accept exactly the cap and reject one over", () => {
    const okUfrag = { ...sampleOffer(), ufrag: "u".repeat(MAX_UFRAG_LEN) };
    expect(() => OfferPayload.fromCanonicalBytes(OfferPayload.toCanonicalBytes(okUfrag))).not.toThrow();

    const tooLongUfrag = { ...sampleOffer(), ufrag: "u".repeat(MAX_UFRAG_LEN + 1) };
    const err = expectThrows(SignalingError, () =>
      OfferPayload.fromCanonicalBytes(OfferPayload.toCanonicalBytes(tooLongUfrag)),
    );
    expect(err.kind).toBe("TooLong");
    expect(err.field).toBe("ufrag");
    expect(err.max).toBe(MAX_UFRAG_LEN);
    expect(err.actual).toBe(MAX_UFRAG_LEN + 1);

    const okPwd = { ...sampleAnswer(), pwd: "p".repeat(MAX_PWD_LEN) };
    expect(() => AnswerPayload.fromCanonicalBytes(AnswerPayload.toCanonicalBytes(okPwd))).not.toThrow();

    const tooLongPwd = { ...sampleAnswer(), pwd: "p".repeat(MAX_PWD_LEN + 1) };
    const pwdErr = expectThrows(SignalingError, () =>
      AnswerPayload.fromCanonicalBytes(AnswerPayload.toCanonicalBytes(tooLongPwd)),
    );
    expect(pwdErr.kind).toBe("TooLong");
    expect(pwdErr.field).toBe("pwd");
    expect(pwdErr.max).toBe(MAX_PWD_LEN);
  });

  it("candidate accepts exactly the cap and rejects one over", () => {
    const ok: IcePayload = { candidate: "c".repeat(MAX_CANDIDATE_LEN), end_of_candidates: false };
    expect(() => IcePayload.fromCanonicalBytes(IcePayload.toCanonicalBytes(ok))).not.toThrow();

    const tooLong: IcePayload = {
      candidate: "c".repeat(MAX_CANDIDATE_LEN + 1),
      end_of_candidates: false,
    };
    const err = expectThrows(SignalingError, () =>
      IcePayload.fromCanonicalBytes(IcePayload.toCanonicalBytes(tooLong)),
    );
    expect(err.kind).toBe("TooLong");
    expect(err.field).toBe("candidate");
    expect(err.max).toBe(MAX_CANDIDATE_LEN);
    expect(err.actual).toBe(MAX_CANDIDATE_LEN + 1);
  });

  it("inbox accepts exactly the cap and rejects one over", () => {
    const ok = { ...sampleOffer(), inbox: "i".repeat(MAX_INBOX_LEN) };
    expect(() => OfferPayload.fromCanonicalBytes(OfferPayload.toCanonicalBytes(ok))).not.toThrow();

    const tooLong = { ...sampleOffer(), inbox: "i".repeat(MAX_INBOX_LEN + 1) };
    const err = expectThrows(SignalingError, () =>
      OfferPayload.fromCanonicalBytes(OfferPayload.toCanonicalBytes(tooLong)),
    );
    expect(err.kind).toBe("TooLong");
    expect(err.field).toBe("inbox");
    expect(err.max).toBe(MAX_INBOX_LEN);
  });
});

describe("rejection parity with signaling.rs's inline unit tests", () => {
  it("rejects a missing required field", () => {
    const cbor = CborValue.map([
      ["transport", CborValue.uint(Transport.Quic)],
      ["ufrag", CborValue.text("u")],
      ["pwd", CborValue.text("p")],
      // cert_fp omitted
    ]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(SignalingError, () => AnswerPayload.fromCanonicalBytes(bytes));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("MissingField");
    expect(err.protoError?.field).toBe("cert_fp");
  });

  it("rejects a non-canonical encoding", () => {
    // The "transport" field's value re-encoded in the non-shortest 1-byte-argument form.
    const answer = sampleAnswer();
    const canonicalBytes = AnswerPayload.toCanonicalBytes(answer);
    const mapValue = canonicalDecode(canonicalBytes);
    const mutated = lengthenUintField(mapValue, "transport");
    const err = expectThrows(SignalingError, () => AnswerPayload.fromCanonicalBytes(mutated));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("Cbor");
    expect(err.protoError?.cborError?.kind).toBe("NonShortestForm");
  });

  it("rejects a bad transport discriminant", () => {
    const cbor = CborValue.map([
      ["inbox", CborValue.text("x")],
      ["transport", CborValue.uint(99)],
      ["ufrag", CborValue.text("u")],
      ["pwd", CborValue.text("p")],
      ["cert_fp", CborValue.bytes(fp(0))],
    ]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(SignalingError, () => OfferPayload.fromCanonicalBytes(bytes));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("InvalidEnumValue");
    expect(err.protoError?.field).toBe("transport");
    expect(err.protoError?.enumValue).toBe(99n);
  });

  it("rejects the wrong CBOR type for cert_fp", () => {
    const cbor = CborValue.map([
      ["transport", CborValue.uint(Transport.Quic)],
      ["ufrag", CborValue.text("u")],
      ["pwd", CborValue.text("p")],
      ["cert_fp", CborValue.text("not-bytes")],
    ]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(SignalingError, () => AnswerPayload.fromCanonicalBytes(bytes));
    expect(err.kind).toBe("Proto");
    expect(err.protoError?.kind).toBe("WrongType");
    expect(err.protoError?.field).toBe("cert_fp");
  });

  it("rejects a wrong-length cert_fp", () => {
    const cbor = CborValue.map([
      ["transport", CborValue.uint(Transport.Quic)],
      ["ufrag", CborValue.text("u")],
      ["pwd", CborValue.text("p")],
      ["cert_fp", CborValue.bytes(new Uint8Array(31).fill(0xaa))],
    ]);
    const bytes = canonicalEncode(cbor);
    const err = expectThrows(SignalingError, () => AnswerPayload.fromCanonicalBytes(bytes));
    expect(err.kind).toBe("WrongLength");
    expect(err.field).toBe("cert_fp");
    expect(err.expected).toBe(CERT_FP_LEN);
    expect(err.actual).toBe(31);
  });
});

describe("constants (signaling.rs parity)", () => {
  it("KIND_* constants match the spike", () => {
    expect(KIND_OFFER).toBe(1);
    expect(KIND_ANSWER).toBe(2);
    expect(KIND_ICE).toBe(3);
  });

  it("Transport discriminants are stable", () => {
    expect(Transport.Quic).toBe(0);
    expect(Transport.WebRtc).toBe(1);
  });
});
