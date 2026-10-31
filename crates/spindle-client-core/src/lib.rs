//! `spindle-client-core` — the client library: sessions, the pinning store, the transfer queue,
//! and key custody. This slice depends directly on `spindle-core` and `spindle-proto`; the
//! finished crate will also depend on `spindle-net` and `spindle-vfs`. Per A9c boundary rule 3
//! nothing below `apps/*/src-tauri` depends on `tauri` — the `apps/client` Tauri shell is a thin
//! IPC layer over this crate, and private key material never leaves it (keys/seeds/caps are never
//! sent over IPC).
//!
//! # Modules
//! - [`self_revocation`] — minting a root-signed `spindle-self-rev-v1` record (only the primary
//!   device holds the identity root) and depositing it on `helper.revoke.<own nfp>` through the
//!   [`self_revocation::RevokeTransport`] seam. That trait is what the app's authenticated NATS
//!   client implements; this crate takes no `async-nats` dependency, so it stays runtime-neutral
//!   and its tests need no broker. **No app wires this yet** — the module's functions have no
//!   production caller; the Tauri client shell and the primary device's key-custody flow are
//!   later slices.
//! - [`turn_credentials`] — fetching a coturn credential from the helper on
//!   `helper.turn.get.<own nfp>` through the [`turn_credentials::TurnCredentialTransport`] seam.
//!   Identity comes from the callout-granted subject token, the helper mints per `root_fp` against
//!   its quota, and the returned ICE URIs are handed back verbatim for the caller to turn into a
//!   transport config. **No app wires this yet** either; the module is the library-level client
//!   half.

pub mod self_revocation;
pub mod turn_credentials;

pub use self_revocation::{deposit_self_revocation, mint_self_revocation, DepositError};
pub use turn_credentials::{
    fetch_turn_credentials, TurnCredentialError, TurnCredentialTransport, TurnCredentialsReply,
};
