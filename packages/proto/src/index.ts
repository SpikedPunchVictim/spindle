// @spindle/proto — the TypeScript twin of the Rust `spindle-proto` crate: wire types plus a
// small, hand-written canonical CBOR encoder/decoder (RFC 8949 §4.2.1) and the A7b
// signed-artifact domain-separation tags. Third-party CBOR libraries are not used here because
// they are not guaranteed byte-canonical; this package's output is verified byte-identical to
// the Rust encoder's via the golden vectors in /vectors, in CI. Not implemented yet — see
// IMPLEMENTATION_PLAN.md Stage 2.
