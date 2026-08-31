//! `spindle-core` — identity (identity roots, device certs), capabilities, the end-to-end
//! signaling envelope (A7), and signed artifacts generally (A7b). Depends only on
//! `spindle-proto` for wire types; per A9c boundary rule 3 nothing below `apps/*/src-tauri`
//! depends on `tauri`, and this crate sits below both `spindle-net` and `spindle-vfs` in the
//! dependency chain (`proto ← core ← {net, vfs} ← {host-core, client-core}`).
//!
//! # Modules
//! - [`fingerprint`] — [`Fingerprint`], the shared 32-byte SHA-256 identifier type (`root_fp`,
//!   `device_fp`, `host_fp`), with a base32 (RFC 4648, no padding, lowercase) `Display`.
//! - [`identity`] — [`RootKey`] (person/host identity root, pre-committed rotation) and
//!   [`DeviceKey`] (Ed25519 sign + X25519 agree keypair).
//! - [`artifacts`] — issue/verify functions for the six non-`Envelope` A7b signed-artifact types.
//! - [`envelope`] — the A7 end-to-end signaling envelope: session-key derivation, `seal`/`open`.
//!
//! # Design notes and ambiguities (reported, not silently resolved)
//!
//! - **Capability `nbf`**: DESIGN.md §A7b / ADR-003 list `nbf = issue ts` as part of a
//!   capability's time rule, but `spindle_proto::artifacts::Capability` (the schema of record)
//!   has no `nbf` field. [`artifacts::verify_capability`] therefore checks only `exp`. See that
//!   function's doc comment.
//! - **Root rotation has no proto wire type**: DESIGN.md §A4's `sig_old_root(new_root_pk)` /
//!   pre-committed-hash rotation is not one of spindle-proto's seven A7b-cataloged artifacts.
//!   [`identity::sign_root_rotation`]/[`identity::verify_root_rotation`] define their own minimal
//!   domain-separated signing input inside this crate rather than adding an unauthorized type to
//!   `spindle-proto`.
//! - **Session-key `from_fp`/`to_fp` are session roles, not per-message envelope fields**: see
//!   the [`envelope`] module docs for the interpretation this crate follows (DESIGN.md §A7 does
//!   not spell this out explicitly).
//! - **[`identity::sign_bytes`]/[`identity::verify_bytes`]** (Stage 6 slice 2 addition): generic
//!   raw-Ed25519-signature helpers over already domain-separated bytes, added so a crate that
//!   depends only on `spindle-core` (not directly on `ed25519-dalek`, per A9c boundary rule 3) can
//!   still produce/verify ad hoc signatures without needing to name `ed25519_dalek::Signature`
//!   itself. First consumer: `spindle-vfs`'s audit-chain `HeadSigner` trait (DESIGN.md §A4b
//!   "Audit log"), which must not gain a direct crypto dependency of its own.

pub mod artifacts;
pub mod envelope;
pub mod fingerprint;
pub mod identity;

mod base32;

pub use envelope::{
    derive_bootstrap_key, derive_session_key, direction_byte, open, seal, EnvelopeError,
    OpenParams, SealParams, SessionKey,
};
pub use fingerprint::{Fingerprint, FingerprintError, FINGERPRINT_LEN};
pub use identity::{
    device_fp_of, generate_next_root, root_fp_of, sign_bytes, sign_root_rotation, verify_bytes,
    verify_root_rotation, DeviceKey, IdentityError, NextRoot, RootKey, ALG_ID_V1,
};

/// Re-exported so downstream crates (e.g. `spindle-helper`) can name these types without taking
/// their own direct dependency on `ed25519-dalek` — per A9c's crate-layering law, use this
/// re-export rather than adding `ed25519-dalek` to a crate that is only supposed to depend on
/// `spindle-core`.
pub use ed25519_dalek::{SigningKey, VerifyingKey};
