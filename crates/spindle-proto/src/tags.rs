//! A7b domain-separation tags.
//!
//! Every signed artifact in Spindle is preceded, in its signature preimage, by a tag string
//! unique to that artifact type (DESIGN.md §A7b). Because a handful of keys sign more than one
//! artifact type — root keys sign both device certificates and self-revocations — the tags exist
//! specifically so a signature valid for one artifact kind can never be replayed as valid for
//! another kind signed by the same key (ADR-001 §A12 #41; ADR-004).
//!
//! This module owns only the tag bytes and the trivial `tag || bytes` concatenation helper.
//! **No cryptography lives here or anywhere in `spindle-proto`** (A9c boundary rule 3) — signing
//! and verification are `spindle-core`'s job (Stage 3).

/// `Envelope` (A7) — signed by the sender's device key.
pub const ENVELOPE_V1: &[u8] = b"spindle-env-v1";
/// `Capability` (A4) — signed by the host root, via the host operating key.
pub const CAPABILITY_V1: &[u8] = b"spindle-cap-v1";
/// `AdmissionToken` (A3b) — signed by the operator admission key.
pub const ADMISSION_TOKEN_V1: &[u8] = b"spindle-adm-v1";
/// `DeviceCertificate` (A4) — signed by the identity root. Bumped to v2 in v0.9.29: this artifact
/// carries no `v` field, so per DESIGN.md §A7b the domain tag *is* the version discriminant, and
/// v0.9.29 removed `nats_fp` from the certificate — a wire-visible change — which is expressed
/// here as `spindle-dev-cert-v1` → `spindle-dev-cert-v2` rather than as a field-level version.
pub const DEVICE_CERT_V2: &[u8] = b"spindle-dev-cert-v2";
/// `RevocationRecord` (A4) — signed by the host operating key or an identity root.
pub const REVOCATION_V1: &[u8] = b"spindle-rev-v1";
/// `AdminCommand` (A3b/A7b) — signed by the operator admission key.
pub const ADMIN_COMMAND_V1: &[u8] = b"spindle-adm-cmd-v1";
/// `HostOpKeyCert` (A4) — signed by the host root. Bumped to v2 in v0.9.31: this artifact carries
/// no `v` field, so per DESIGN.md §A7b the domain tag *is* the version discriminant, and v0.9.31
/// removed `nats_fp` from the certificate — a wire-visible change — which is expressed here as
/// `spindle-host-cert-v1` → `spindle-host-cert-v2` rather than as a field-level version (td-583db5).
/// The removed binding moved to the new [`HOST_SESSION_ATTESTATION_V1`].
pub const HOST_OP_KEY_CERT_V2: &[u8] = b"spindle-host-cert-v2";
/// `HostDeviceCert` (A4/A10.35) — signed by the host operating key.
pub const HOST_DEVICE_CERT_V1: &[u8] = b"spindle-host-dev-cert-v1";
/// `SessionAttestation` (A4/A7b, added v0.9.29) — signed by the device identity key. Device
/// identity keys now sign two artifact types — `Envelope` (`spindle-env-v1`) and
/// `SessionAttestation` (`spindle-sess-attest-v1`) — both produced online by the same key on the
/// same connection, so this tag is the only thing preventing cross-artifact signature confusion
/// between them (DESIGN.md §A7b).
pub const SESSION_ATTESTATION_V1: &[u8] = b"spindle-sess-attest-v1";
/// `HostSessionAttestation` (A4/A7b, added v0.9.31, td-583db5) — signed by the host **operating**
/// key. That key now signs four artifact types — `Capability` (`spindle-cap-v1`),
/// `RevocationRecord` (`spindle-rev-v1`), `HostDeviceCert` (`spindle-host-dev-cert-v1`), and
/// `HostSessionAttestation` (`spindle-host-sess-attest-v1`) — so this tag is what prevents
/// cross-artifact signature confusion between them (DESIGN.md §A7b).
pub const HOST_SESSION_ATTESTATION_V1: &[u8] = b"spindle-host-sess-attest-v1";

/// Concatenates a domain tag with a byte string — `tag || bytes`. No hashing, no signing: this
/// crate only assembles the exact byte sequence that `spindle-core` will later sign or verify.
///
/// For most artifact types `bytes` is the canonical CBOR encoding of the artifact with its
/// signature field omitted. `Envelope` is the one exception (A7): its signing input is
/// `tag || canonical(header) || ciphertext`, so `Envelope::signing_input` calls this helper with
/// just the header bytes and appends the ciphertext itself afterward — see `artifacts.rs`.
pub fn signing_input(tag: &[u8], canonical_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + canonical_bytes.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(canonical_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concatenates_tag_and_bytes() {
        let out = signing_input(b"tag", &[1, 2, 3]);
        assert_eq!(out, vec![b't', b'a', b'g', 1, 2, 3]);
    }

    // `signing_input` is `tag || canonical_bytes` with no length prefix and no delimiter between
    // the two (see the fn doc above), so pairwise distinctness of the tags is not the property
    // that actually prevents cross-artifact preimage collision: if one tag were a byte-prefix of
    // another, a `canonical_bytes` for the shorter-tagged artifact could be chosen so that
    // `short_tag || bytes` reassembles, byte-for-byte, into `long_tag || bytes'` for some
    // `bytes'` — a signature over one artifact's preimage would then verify as a signature over
    // the other's. Prefix-freeness is what rules this out, and it subsumes plain distinctness:
    // two equal tags are trivially prefixes of each other.
    #[test]
    fn all_ten_tags_are_prefix_free() {
        let tags = [
            ENVELOPE_V1,
            CAPABILITY_V1,
            ADMISSION_TOKEN_V1,
            DEVICE_CERT_V2,
            REVOCATION_V1,
            ADMIN_COMMAND_V1,
            HOST_OP_KEY_CERT_V2,
            HOST_DEVICE_CERT_V1,
            SESSION_ATTESTATION_V1,
            HOST_SESSION_ATTESTATION_V1,
        ];
        for i in 0..tags.len() {
            for j in 0..tags.len() {
                if i != j {
                    assert!(
                        !tags[j].starts_with(tags[i]),
                        "tag at {i} ({:?}) is a byte-prefix of tag at {j} ({:?})",
                        tags[i],
                        tags[j]
                    );
                }
            }
        }
    }
}
