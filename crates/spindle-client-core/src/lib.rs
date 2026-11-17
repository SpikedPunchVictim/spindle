//! `spindle-client-core` — the client library: sessions, the pinning store, the transfer queue,
//! and key custody. It depends directly on `spindle-core`, `spindle-proto`, and `spindle-net`
//! (framing and transport types); `spindle-vfs` remains a dev-dependency for the integration
//! test that drives a real host store. Per A9c boundary rule 3 nothing below `apps/*/src-tauri`
//! depends on `tauri` — the `apps/client` Tauri shell is a thin IPC layer over this crate, and
//! private key material never leaves it (keys/seeds/caps are never sent over IPC).
//!
//! # Modules
//! - [`pinning`] — first-use host pinning from a verified invite, the key-change wall, and the
//!   [`pinning::PinStore`] seam the durable (keychain/IndexedDB) store implements. Rotation of a
//!   host's operating or envelope key keeps the root-derived `host_fp`, so it does not re-wall;
//!   a different root for a pinned identity is a wall with no auto-repin path.
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
//!   transport config. **No app wires this yet**; the module is the library-level client half.
//! - [`vfs_client`] — the client half of the VFS RPC control stream: framed request/reply over
//!   any `AsyncRead`/`AsyncWrite` pair, plus list/stat/read/mkdir/delete and the chunked upload
//!   state machine. No QUIC or key material: the session layer authenticates the transport above
//!   this module.

pub mod pinning;
pub mod self_revocation;
pub mod turn_credentials;
pub mod vfs_client;

pub use pinning::{HostObservation, HostPin, MemoryPinStore, PinStore, Pinning, PinningError};
pub use self_revocation::{deposit_self_revocation, mint_self_revocation, DepositError};
pub use turn_credentials::{
    fetch_turn_credentials, TurnCredentialError, TurnCredentialTransport, TurnCredentialsReply,
};
pub use vfs_client::{VfsClient, VfsClientError};
