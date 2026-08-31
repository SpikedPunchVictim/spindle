//! `spindle-proto` — wire types and canonical CBOR encoding (RFC 8949 §4.2.1) shared by every
//! Spindle component, including the A7b signed-artifact domain-separation tags. This crate is
//! the bottom of the Rust dependency chain (`proto ← core ← {net, vfs} ← {host-core,
//! client-core}`) and per A9c boundary rule 3 it MUST NOT take a crypto dependency — signing and
//! verification belong to `spindle-core`.
//!
//! # Modules
//! - [`canonical`] — the canonical CBOR codec (encoder + strict decoder). See its module docs
//!   for why it is hand-rolled rather than built on `minicbor`.
//! - [`tags`] — the eight A7b domain-separation tags and the `tag || bytes` signing-input
//!   helper.
//! - [`artifacts`] — the eight A7b wire structures ([`Envelope`], [`Capability`],
//!   [`AdmissionToken`], [`DeviceCertificate`], [`RevocationRecord`], [`AdminCommand`],
//!   [`HostOpKeyCert`], [`HostDeviceCert`]).
//! - [`vfs_rpc`] — the VFS RPC wire types (DESIGN.md §A8), Stage 6 slice 3: request/reply types
//!   for `list`/`stat`/`read`/`mkdir`/`delete`/`whoami` and the typed VFS error-code model. Not
//!   one of the eight A7b signed artifacts (no domain tag, no `sig`) — see that module's doc
//!   comment for why.
//! - [`signaling`] — the connect/answer/trickle-ICE payload wire types (DESIGN.md §A6/§A7,
//!   §A10.31/32), promoted from `spikes/s2-signaling`'s crate-local types. Also not one of the
//!   eight A7b signed artifacts — see that module's doc comment for why.
//!
//! # Schema choices
//!
//! DESIGN.md specifies each artifact's *fields*; where it leaves a field's exact CBOR
//! representation open, this crate makes the following choices. These are now the schema of
//! record — the TypeScript twin in `@spindle/proto` must match every one of them exactly for the
//! golden vectors in `vectors/` to agree byte-for-byte.
//!
//! | Choice | Decision |
//! |---|---|
//! | Map keys | Short text strings equal to the Rust field name (e.g. `"from_fp"`), not integer keys. Chosen for debuggability of the wire format (vectors, packet captures) over the handful of bytes integer keys would save. |
//! | Map key sort | Bytewise on each key's own canonical CBOR encoding (RFC 8949 §4.2.1) — for same-length text keys this is byte-lexicographic, but shorter keys always sort before longer keys regardless of content (their length byte differs first). `canonical::encode` sorts automatically; callers never pre-sort. |
//! | Fingerprints / public keys / signatures / nonces / session/ciphertext bytes | CBOR byte strings (major type 2), never base32/base64 text. Base32 (`device_fp`'s display form per A4) is a *display* encoding layered on top by higher layers, not the wire format. |
//! | Fixed-size fields (32-byte fingerprints, 64-byte Ed25519 sigs, etc.) | Not length-checked by this crate — `alg_id` governs expected sizes and belongs to `spindle-core`; `spindle-proto` treats them as opaque variable-length byte strings so a future `alg_id` can change sizes without a wire-type change here. |
//! | Enums (`Capability.kind`) | Small unsigned integers (`invite = 0`, `member = 1`), not text strings — shortest canonical encoding, and the fixed discriminant set doesn't need self-description on the wire. |
//! | `AdminCommand.cmd` | A text string (not a small int) — unlike `Capability.kind`'s closed two-value set, the admin command set is open-ended and expected to grow (A3b); text keeps audit logs and CLI output human-legible without a side-table mapping ints to names. |
//! | `AdminCommand.args` | Carried as an opaque [`canonical::CborValue`] (typically a canonical map), not a fixed struct — DESIGN.md does not enumerate per-command argument shapes, and pre-committing to one here would need a wire-type change per new admin command. |
//! | Optional fields (`Envelope.eph_pk`) | Represented by **key omission**, never CBOR `null`. Keeps the "no floats, and minimal simple-value surface" posture consistent, and omission is itself informative (first-message-of-session vs. not) without an extra tag. |
//! | `exp` fields expressed as a duration in prose (`AdmissionToken.exp` "days", `Capability.exp` "weeks") | Encoded as an absolute Unix-seconds timestamp on the wire, exactly like every other `exp`/`ts` field. The prose duration is the *default* the issuer picks, not the wire unit. |
//! | Unknown/extra map keys | Rejected on decode (closed schema per artifact), alongside the usual missing-required-field check. A v1, `v`-gated wire contract has no forward-compat need for silently-ignored extension fields yet; loosening this later is backward compatible, tightening it would not be. |
//! | `DeviceCertificate.label` | **Omitted** — see the discrepancy note on [`artifacts::DeviceCertificate`]: A4's inline `sig_root(...)` notation names `label` as signed material, but A4's later enrollment paragraph states labels are host-local, renameable, and "never baked into certificates." This crate follows the later, more specific rule. |
//! | `v` field presence | Only `Envelope`, `Capability`, and `AdminCommand` carry an explicit wire-level `v` byte, matching DESIGN.md's own inline struct notations for each. `AdmissionToken`, `DeviceCertificate`, `RevocationRecord`, and `HostOpKeyCert` have no such field in their DESIGN.md notations even though A7b's prose says "every signed artifact shares... a version byte `v`" — for those four, the domain-separation tag itself is the version discriminant (a `spindle-*-v1`-signed artifact is a v1 artifact by construction; a hypothetical v2 would mint a new tag, e.g. `spindle-dev-cert-v2`). Flagged here as a second DESIGN.md tension, resolved the same way as the label discrepancy: by following the literal struct notation rather than the generalizing prose. |
//! | `Capability` host-identity chain (decision A10.30, 2026-08-24) | `Capability` carries `host_fp, host_root_pk, op_cert, ..., sig` — not the pre-A10.30 `host_fp, host_pk, ..., sig_host`. `host_fp = SHA-256(host_root_pk)` (root-derived, not operating-key-derived — S1 flagged the old op-key-derived `host_fp` as scoping-inconsistent with §A4/§A5's root-derived `host_fp`). `op_cert` is the existing [`artifacts::HostOpKeyCert`] artifact embedded whole as its own complete canonical CBOR encoding (an opaque byte string here — no second op-cert wire shape was invented); `sig` remains an Ed25519 signature by the operating key `op_cert` certifies, over the capability's own `spindle-cap-v1` signing input. `spindle-core::verify_capability` is what actually walks the chain (decode `op_cert`, re-run `verify_host_op_key_cert` against `host_root_pk`, then check `sig` under the op cert's `host_op_pk`) — this crate only carries the bytes. |
//!
//! # Canonical CBOR encoder
//!
//! [`canonical`] is hand-rolled rather than driven through `minicbor`'s own encoder/decoder —
//! see that module's docs for the full rationale (short version: canonical-form *rejection* on
//! decode needs raw-byte-level control that a general-purpose CBOR decoder's API abstracts away,
//! and this is a security property per ADR-004). This is a deviation from A9c's dependency
//! manifest table, which lists `minicbor` for this concern; the task brief that produced this
//! module explicitly left the choice open ("hand-rolled writer if cleaner — your call, document
//! it"). `spindle-proto`'s `Cargo.toml` has no dependency on `minicbor` as a result — the crate
//! has zero non-dev dependencies.

pub mod artifacts;
pub mod canonical;
pub mod signaling;
pub mod tags;
pub mod vfs_rpc;

pub use artifacts::{
    AdminCommand, AdmissionToken, CapKind, Capability, DeviceCertificate, Envelope, HostOpKeyCert,
    ProtoError, RevocationRecord,
};
pub use canonical::{canonical_decode, canonical_encode, CborError, CborValue};
pub use signaling::{
    AnswerPayload, IcePayload, OfferPayload, SignalingError, Transport, CERT_FP_LEN, KIND_ANSWER,
    KIND_ICE, KIND_OFFER, MAX_CANDIDATE_LEN, MAX_INBOX_LEN, MAX_PWD_LEN, MAX_UFRAG_LEN,
};
pub use vfs_rpc::{
    DirEntry, EntryKind, VfsErrorCode, VfsPerms, VfsReply, VfsRequest, VfsRequestEnvelope,
    CURRENT_PROTOCOL_VERSION, MAX_LIST_PAGE, MAX_READ_CHUNK, MAX_UPLOAD_CHUNK,
    MIN_PROTOCOL_VERSION, UPLOAD_SESSION_TTL_SECS,
};

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
