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
/** `DeviceCertificate` (A4) — signed by the identity root. Bumped to v2 in v0.9.29: this artifact
 * carries no `v` field, so per DESIGN.md §A7b the domain tag *is* the version discriminant, and
 * v0.9.29 removed `nats_fp` from the certificate — a wire-visible change — which is expressed
 * here as `spindle-dev-cert-v1` -> `spindle-dev-cert-v2` rather than as a field-level version. */
export const DEVICE_CERT_V2: Uint8Array = encoder.encode("spindle-dev-cert-v2");
/** `RevocationRecord` (A4) — signed by the host operating key or an identity root. */
export const REVOCATION_V1: Uint8Array = encoder.encode("spindle-rev-v1");
/** `AdminCommand` (A3b/A7b) — signed by the operator admission key. */
export const ADMIN_COMMAND_V1: Uint8Array = encoder.encode("spindle-adm-cmd-v1");
/** `HostOpKeyCert` (A4) — signed by the host root. Bumped to v2 in v0.9.31: this artifact carries
 * no `v` field, so per DESIGN.md §A7b the domain tag *is* the version discriminant, and v0.9.31
 * removed `nats_fp` from the certificate — a wire-visible change — which is expressed here as
 * `spindle-host-cert-v1` -> `spindle-host-cert-v2` rather than as a field-level version
 * (td-583db5). The removed binding moved to the new `HOST_SESSION_ATTESTATION_V1`. */
export const HOST_OP_KEY_CERT_V2: Uint8Array = encoder.encode("spindle-host-cert-v2");
/** `HostDeviceCert` (A4/A10.35) — signed by the host operating key. */
export const HOST_DEVICE_CERT_V1: Uint8Array = encoder.encode("spindle-host-dev-cert-v1");
/** `SessionAttestation` (A4/A7b, added v0.9.29) — signed by the device identity key. Device
 * identity keys now sign two artifact types — `Envelope` (`spindle-env-v1`) and
 * `SessionAttestation` (`spindle-sess-attest-v1`) — both produced online by the same key on the
 * same connection, so this tag is the only thing preventing cross-artifact signature confusion
 * between them (DESIGN.md §A7b). */
export const SESSION_ATTESTATION_V1: Uint8Array = encoder.encode("spindle-sess-attest-v1");
/** `HostSessionAttestation` (A4/A7b, added v0.9.31, td-583db5) — signed by the host **operating**
 * key. That key now signs four artifact types — `Capability` (`spindle-cap-v1`),
 * `RevocationRecord` (`spindle-rev-v1`), `HostDeviceCert` (`spindle-host-dev-cert-v1`), and
 * `HostSessionAttestation` (`spindle-host-sess-attest-v1`) — so this tag is what prevents
 * cross-artifact signature confusion between them (DESIGN.md §A7b). */
export const HOST_SESSION_ATTESTATION_V1: Uint8Array = encoder.encode(
  "spindle-host-sess-attest-v1",
);

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
