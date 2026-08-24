// A7b domain-separation tags — the TypeScript twin of `crates/spindle-proto/src/tags.rs`.
//
// Every signed artifact in Spindle is preceded, in its signature preimage, by a tag string unique
// to that artifact type (DESIGN.md §A7b). Because a handful of keys sign more than one artifact
// type — root keys sign both device certificates and self-revocations — the tags exist
// specifically so a signature valid for one artifact kind can never be replayed as valid for
// another kind signed by the same key (ADR-001 §A12 #41; ADR-004).
//
// This module owns only the tag bytes and the trivial `tag || bytes` concatenation helper. No
// cryptography lives here or anywhere in `@spindle/proto` (A9c boundary rule 3) — signing and
// verification are `@spindle/crypto`'s job.

const encoder = new TextEncoder();

/** `Envelope` (A7) — signed by the sender's device key. */
export const ENVELOPE_V1: Uint8Array = encoder.encode("spindle-env-v1");
/** `Capability` (A4) — signed by the host root, via the host operating key. */
export const CAPABILITY_V1: Uint8Array = encoder.encode("spindle-cap-v1");
/** `AdmissionToken` (A3b) — signed by the operator admission key. */
export const ADMISSION_TOKEN_V1: Uint8Array = encoder.encode("spindle-adm-v1");
/** `DeviceCertificate` (A4) — signed by the identity root. */
export const DEVICE_CERT_V1: Uint8Array = encoder.encode("spindle-dev-cert-v1");
/** `RevocationRecord` (A4) — signed by the host operating key or an identity root. */
export const REVOCATION_V1: Uint8Array = encoder.encode("spindle-rev-v1");
/** `AdminCommand` (A3b/A7b) — signed by the operator admission key. */
export const ADMIN_COMMAND_V1: Uint8Array = encoder.encode("spindle-adm-cmd-v1");
/** `HostOpKeyCert` (A4) — signed by the host root. */
export const HOST_OP_KEY_CERT_V1: Uint8Array = encoder.encode("spindle-host-cert-v1");

/**
 * Concatenates a domain tag with a byte string — `tag || bytes`. No hashing, no signing: this
 * module only assembles the exact byte sequence that `@spindle/crypto` will later sign or verify.
 *
 * For most artifact types `bytes` is the canonical CBOR encoding of the artifact with its
 * signature field omitted. `Envelope` is the one exception (A7): its signing input is
 * `tag || canonical(header) || ciphertext`, so `Envelope.signingInput` calls this helper with
 * just the header bytes and appends the ciphertext itself afterward — see `artifacts.ts`.
 */
export function signingInput(tag: Uint8Array, canonicalBytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(tag.length + canonicalBytes.length);
  out.set(tag, 0);
  out.set(canonicalBytes, tag.length);
  return out;
}
