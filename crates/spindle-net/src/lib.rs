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
//!
//! # Scope
//!
//! **In** (this slice): binding the VFS RPC control stream to a real QUIC transport — framing,
//! per-session cert generation, mutual pinning, the control-stream handshake. The actual VFS RPC
//! read/decode/dispatch/write loop that runs *over* this transport lives in
//! `spindle-host-core::serve` (that crate depends on this one, not the reverse).
//!
//! **Out** (future, Stage 5 — unscheduled as of this slice): the NATS client + Auth Callout
//! credential presentation, the browser-peer WebRTC data-channel transport (`webrtc-rs`, needed
//! only when a browser peer is on the other end — DESIGN.md §A8), trickle ICE (standalone,
//! reused to punch the NAT for QUIC per §A8, not yet wired here), and the client-side transfer
//! manager. Envelope integration (both peers' QUIC certificate fingerprints traveling inside the
//! A7-verified `connect` envelope, per §A6) is likewise deferred — see [`quic`]'s module doc
//! comment's "Envelope integration (deferred)" section for exactly what this slice does instead.

pub mod framing;
pub mod quic;

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold() { /* compilation of this crate is the assertion */
    }
}
