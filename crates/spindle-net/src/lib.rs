//! `spindle-net` — the QUIC control-stream transport for native↔native VFS RPC sessions
//! (DESIGN.md §A8/A10.31-32), graduated in Stage 6 slice 5 from `spikes/s19-quic-transport`'s
//! proven quinn 0.11 recipe. Depends on `spindle-core`/`spindle-proto` directly; per A9c boundary
//! rule 3, nothing below `apps/*/src-tauri` depends on `tauri`, and this crate sits below
//! `spindle-host-core`/`spindle-client-core` in the dependency chain
//! (`proto ← core ← {net, vfs} ← {host-core, client-core}`) — `spindle-net` must never depend on
//! `spindle-vfs`/`spindle-host-core`/`spindle-client-core` (the direction is host-core -> net, not
//! the reverse).
//!
//! # Module map
//!
//! - [`framing`] — length-prefixed frames (4-byte big-endian length + payload, 256 KiB cap) over
//!   any `tokio::io::{AsyncRead, AsyncWrite}`. No QUIC dependency of its own.
//! - [`quic`] — [`quic::SessionCert`] (per-session self-signed cert + SHA-256 fingerprint),
//!   [`quic::QuicServer`]/[`quic::QuicClient`] (mutual fingerprint-pinned QUIC connections, one
//!   bidirectional control stream per session, ALPN [`quic::ALPN`]).
//! - [`signaling`] — NATS-mediated signaling (DESIGN.md §A6/§A7), graduated from
//!   `spikes/s2-signaling`: both peer roles' offer/answer/trickle-ICE exchange, wired to
//!   [`quic::QuicClient::from_socket`]/[`quic::QuicServer::from_socket`] above. See that module's
//!   own doc comment for its submodule map and the two injected traits its layering requires.
//!
//! # Scope
//!
//! **In**: binding the VFS RPC control stream to a real QUIC transport — framing, per-session cert
//! generation, mutual pinning, the control-stream handshake (`quic`); and, as of Stage 5 slice 3,
//! the NATS-mediated connect/trickle-ICE exchange that gets both peers to the point of calling
//! `from_socket` in the first place (`signaling`). The actual VFS RPC read/decode/dispatch/write
//! loop that runs *over* the resulting control stream lives in `spindle-host-core::serve` (that
//! crate depends on this one, not the reverse) — `signaling::host::SessionHandler` is this crate's
//! injection point for that loop.
//!
//! **Out** (future, unscheduled as of this slice): the NATS client's own connection/credential
//! setup (Auth Callout presentation) — this crate only ever takes an already-connected
//! `async_nats::Client` as a parameter, never connects one itself (see [`signaling`]'s module doc
//! comment); the browser-peer WebRTC data-channel transport (`webrtc-rs`, needed only when a
//! browser peer is on the other end — DESIGN.md §A8); STUN/TURN candidate gathering beyond
//! loopback/LAN host candidates (see [`signaling::ice`]'s module doc comment); and the client-side
//! transfer manager.

pub mod framing;
pub mod quic;
pub mod signaling;

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
