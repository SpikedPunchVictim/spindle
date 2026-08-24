// Golden-vector conformance for all seven A7b wire types (vectors/*.json, excluding
// canonical-cbor.json — see canonical.test.ts for that one) plus negative mutation tests: swap
// key order, lengthen an integer's encoding, and add an unrecognized field, each asserted to be
// rejected by the strict decoder / closed-schema artifact reader.
//
// Any mismatch here means the TypeScript encoder disagrees with the Rust encoder that produced
// these vectors (`cargo run -p spindle-proto --bin gen-vectors`) — see vectors/README.md.

import { describe, expect, it } from "vitest";

import { CborError, CborValue, canonicalDecode, type CborValue as CborValueType } from "../src/canonical.js";
import { bytesToHex, hexToBytes } from "../src/hex.js";
import {
  AdminCommand,
  AdmissionToken,
  Capability,
  DeviceCertificate,
  Envelope,
  HostOpKeyCert,
  ProtoError,
  RevocationRecord,
} from "../src/artifacts.js";
import {
  addUnknownKey,
  lengthenUintField,
  loadVectorFile,
  normalize,
  parseAdminCommand,
  parseAdmissionToken,
  parseCapability,
  parseDeviceCertificate,
  parseEnvelope,
  parseHostOpKeyCert,
  parseRevocationRecord,
  swapFirstTwoEntries,
} from "./helpers.js";

interface ArtifactCase {
  name: string;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  decoded: any;
  canonical_cbor_hex: string;
  signing_input_hex: string;
}

interface ArtifactDoc {
  artifact: string;
  domain_tag: string;
  cases: ArtifactCase[];
}

interface Descriptor<T> {
  fileName: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  parse: (d: any) => T;
  toCanonicalBytes: (v: T) => Uint8Array;
  fromCanonicalBytes: (bytes: Uint8Array) => T;
  signingInput: (v: T) => Uint8Array;
}

function runArtifactSuite<T>(desc: Descriptor<T>): void {
  describe(desc.fileName, () => {
    const doc = loadVectorFile(desc.fileName) as ArtifactDoc;

    for (const c of doc.cases) {
      describe(c.name, () => {
        it("encodes `decoded` to canonical_cbor_hex", () => {
          const value = desc.parse(c.decoded);
          expect(bytesToHex(desc.toCanonicalBytes(value))).toBe(c.canonical_cbor_hex);
        });

        it("decodes canonical_cbor_hex back to `decoded`", () => {
          const expectedValue = desc.parse(c.decoded);
          const decoded = desc.fromCanonicalBytes(hexToBytes(c.canonical_cbor_hex));
          expect(normalize(decoded)).toEqual(normalize(expectedValue));
        });

        it("re-encoding the decoded struct reproduces canonical_cbor_hex", () => {
          const decoded = desc.fromCanonicalBytes(hexToBytes(c.canonical_cbor_hex));
          expect(bytesToHex(desc.toCanonicalBytes(decoded))).toBe(c.canonical_cbor_hex);
        });

        it("produces the expected A7b signing_input_hex", () => {
          const value = desc.parse(c.decoded);
          expect(bytesToHex(desc.signingInput(value))).toBe(c.signing_input_hex);
        });
      });
    }

    describe("mutation rejection (first case)", () => {
      const first = doc.cases[0];
      const mapValue = canonicalDecode(hexToBytes(first.canonical_cbor_hex));

      it("rejects a swapped key order", () => {
        const mutated = swapFirstTwoEntries(mapValue);
        // Structurally broken canonical CBOR: the primitive decoder itself must reject it...
        const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
        expect(cborErr.kind).toBe("MapKeyOrder");
        // ...and so must the artifact-level decoder, wrapping the same underlying CborError.
        const protoErr = expectThrows(ProtoError, () => desc.fromCanonicalBytes(mutated));
        expect(protoErr.kind).toBe("Cbor");
        expect(protoErr.cborError?.kind).toBe("MapKeyOrder");
      });

      it("rejects a lengthened (non-shortest-form) integer field", () => {
        const key = firstUintFieldKey(mapValue);
        const mutated = lengthenUintField(mapValue, key);
        const cborErr = expectThrows(CborError, () => canonicalDecode(mutated));
        expect(cborErr.kind).toBe("NonShortestForm");
        const protoErr = expectThrows(ProtoError, () => desc.fromCanonicalBytes(mutated));
        expect(protoErr.kind).toBe("Cbor");
        expect(protoErr.cborError?.kind).toBe("NonShortestForm");
      });

      it("rejects an unrecognized field", () => {
        const mutated = addUnknownKey(mapValue, "bogus", CborValue.uint(0));
        // Structurally still fully canonical CBOR (extra key, correctly sorted)...
        expect(() => canonicalDecode(mutated)).not.toThrow();
        // ...but the artifact's closed schema rejects the unknown key.
        const protoErr = expectThrows(ProtoError, () => desc.fromCanonicalBytes(mutated));
        expect(protoErr.kind).toBe("UnknownField");
        expect(protoErr.field).toBe("bogus");
      });
    });
  });
}

function firstUintFieldKey(mapValue: CborValueType): string {
  if (mapValue.kind !== "map") throw new Error("firstUintFieldKey: not a map");
  for (const [k, v] of mapValue.value) {
    if (k.kind === "text" && v.kind === "uint") return k.value;
  }
  throw new Error("firstUintFieldKey: no uint-valued field found");
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

runArtifactSuite({
  fileName: "envelope.json",
  parse: parseEnvelope,
  toCanonicalBytes: Envelope.toCanonicalBytes,
  fromCanonicalBytes: Envelope.fromCanonicalBytes,
  signingInput: Envelope.signingInput,
});

runArtifactSuite({
  fileName: "capability.json",
  parse: parseCapability,
  toCanonicalBytes: Capability.toCanonicalBytes,
  fromCanonicalBytes: Capability.fromCanonicalBytes,
  signingInput: Capability.signingInput,
});

runArtifactSuite({
  fileName: "admission-token.json",
  parse: parseAdmissionToken,
  toCanonicalBytes: AdmissionToken.toCanonicalBytes,
  fromCanonicalBytes: AdmissionToken.fromCanonicalBytes,
  signingInput: AdmissionToken.signingInput,
});

runArtifactSuite({
  fileName: "device-certificate.json",
  parse: parseDeviceCertificate,
  toCanonicalBytes: DeviceCertificate.toCanonicalBytes,
  fromCanonicalBytes: DeviceCertificate.fromCanonicalBytes,
  signingInput: DeviceCertificate.signingInput,
});

runArtifactSuite({
  fileName: "revocation-record.json",
  parse: parseRevocationRecord,
  toCanonicalBytes: RevocationRecord.toCanonicalBytes,
  fromCanonicalBytes: RevocationRecord.fromCanonicalBytes,
  signingInput: RevocationRecord.signingInput,
});

runArtifactSuite({
  fileName: "admin-command.json",
  parse: parseAdminCommand,
  toCanonicalBytes: AdminCommand.toCanonicalBytes,
  fromCanonicalBytes: AdminCommand.fromCanonicalBytes,
  signingInput: AdminCommand.signingInput,
});

runArtifactSuite({
  fileName: "host-op-key-cert.json",
  parse: parseHostOpKeyCert,
  toCanonicalBytes: HostOpKeyCert.toCanonicalBytes,
  fromCanonicalBytes: HostOpKeyCert.fromCanonicalBytes,
  signingInput: HostOpKeyCert.signingInput,
});
