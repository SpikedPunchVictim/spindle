//! Binds [`crate::server::VfsRpcServer::handle_bytes`] to a real duplex byte stream (Stage 6
//! slice 5 — DESIGN.md §A8 "One control stream (VFS RPC) + data streams"). The production caller
//! is `spindle_net::quic::ControlStream`'s `{send, recv}` halves, but [`serve_control_stream`]
//! itself has no QUIC dependency: it is generic over any `tokio::io::{AsyncRead, AsyncWrite}`
//! pair, exactly like [`spindle_net::framing`] itself (which this module calls directly — see
//! that module's doc comment for the wire format: a 4-byte big-endian length prefix, 256 KiB cap).
//!
//! # Loop shape
//!
//! `VfsRpcServer::handle_bytes` takes `&self` (its caches are `RefCell`-based — see
//! [`crate::server`]'s module doc comment — so it is intentionally `!Sync`, single-threaded by
//! design). That fact alone dictates this module's shape: **one task, one server, for the
//! lifetime of one control stream.** [`serve_control_stream`] takes the server **by value**
//! (not a `&VfsRpcServer<'_>`, not a `&mut`, and absolutely no `Arc<Mutex<_>>`/`unsafe impl Sync`
//! wrapper — the task brief is explicit that this crate must not introduce either) and drives it
//! in a plain read-dispatch-write loop on whatever task calls this function. Taking ownership is
//! precisely what avoids needing either of those forbidden wrappers: `VfsRpcServer` is
//! deliberately `!Sync` (its `RefCell` caches), so `&VfsRpcServer` is `!Send` and could not be
//! held across an await point inside the `Send` future a `spindle_net::signaling::SessionHandler`
//! must return (`SignalingHost::run` `tokio::spawn`s it) — an owned `VfsRpcServer<Store>` holds
//! only owned `Send` values, so the future built around it is `Send` automatically. The caller
//! keeps no handle to the server afterward, which is correct for a per-session server whose
//! caches die with the session: a real host process constructs one `VfsRpcServer` and one task
//! per accepted session, exactly mirroring `spindle_net::quic::QuicServer::accept`'s per-session
//! `ControlStream`.
//!
//! # Framing vs. decode violations: close, don't reply (DESIGN.md §A5)
//!
//! §A5 states pre-auth signaling rejections are "uniform silent drops" (DESIGN.md line ~401);
//! §A8's own error model explicitly scopes typed [`spindle_proto::VfsErrorCode`] replies to
//! *inside* an already-authenticated session ("the silent-drop rule applies only pre-auth" —
//! DESIGN.md §A8 "VFS error model"). A framing violation (an oversized length prefix, a truncated
//! frame) or a request that does not even decode as a [`spindle_proto::VfsRequestEnvelope`] (see
//! [`crate::server::VfsRpcServer::handle_bytes`]'s own doc comment: "deliberately distinct from
//! every `VfsErrorCode`") is neither — it is a transport-level protocol violation from a peer that
//! is, from this crate's perspective, already inside the authenticated session but sending bytes
//! that are not a request at all. There is no VFS-semantic outcome to name for that, so this
//! module follows the same posture §A5 applies pre-auth: close the connection rather than
//! synthesize a reply. [`ServeError`] carries just enough detail for the caller's own logs; it is
//! never encoded onto the wire.
//!
//! [`serve_control_stream`] returns `Ok(())` on a **clean** end (the peer closed its send side
//! between frames — [`spindle_net::framing::read_frame`]'s `Ok(None)`) and `Err(ServeError)` on
//! any framing/decode violation. Either way, closing the underlying transport connection (e.g.
//! `quinn::Connection::close`) is the caller's job — this function only owns the two stream
//! halves it was given, not the connection they belong to.

use crate::server::{SessionContext, VfsRpcServer};
use spindle_net::framing::{read_frame, write_frame, FramingError};
use spindle_vfs::store::Store;
use std::borrow::Borrow;
use tokio::io::{AsyncRead, AsyncWrite};

/// A framing-layer or decode-layer protocol violation — see the module doc comment for why
/// neither is a [`spindle_proto::VfsErrorCode`].
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// A [`spindle_net::framing`] violation: an oversized length prefix, or the stream ending
    /// mid-frame.
    #[error("framing protocol violation: {0}")]
    Framing(#[from] FramingError),
    /// A complete frame was read, but its bytes did not decode as a
    /// [`spindle_proto::VfsRequestEnvelope`] — see
    /// [`crate::server::VfsRpcServer::handle_bytes`]'s doc comment.
    #[error("request bytes did not decode as a VfsRequestEnvelope: {0}")]
    Decode(spindle_proto::ProtoError),
}

/// Drives one VFS RPC session's control stream to completion: read a frame, hand its bytes to
/// `server.handle_bytes`, write the reply frame, repeat — until the peer cleanly closes its send
/// side or a protocol violation occurs (see the module doc comment for which is which).
///
/// `ctx` is fixed for the lifetime of this call — DESIGN.md §A8's VFS RPC session is bound to one
/// `{member_id, device_fp}` pair for its whole duration (`spindle_host_core::server::
/// SessionContext`'s doc comment: authenticating a transport-level session down to these two
/// values is `spindle-net`'s responsibility, done once, before this loop starts — not re-derived
/// per request). `now_fn` is an injectable clock (`impl Fn() -> u64`, called once per request to
/// produce that request's audit timestamp) rather than a direct wall-clock read, so tests can
/// drive this loop with deterministic, controlled timestamps exactly like every other timestamp
/// in this crate's pipeline (`VfsRpcServer::handle_bytes`'s own `ts` parameter).
///
/// Generic over `R`/`W` rather than a single combined stream type: quinn already hands out
/// `SendStream`/`RecvStream` as two independent halves (see `spindle_net::quic::ControlStream`),
/// and this loop reads and writes them independently in strict request/reply lockstep anyway (VFS
/// RPC has no pipelining), so there is no combined-stream abstraction to gain by fusing them
/// first — two plain generic parameters is the boring, direct fit for `handle_bytes`'s `&self`
/// (no `&mut` needed, no lifetime gymnastics forced by this loop).
pub async fn serve_control_stream<S, R, W>(
    server: VfsRpcServer<S>,
    ctx: &SessionContext,
    now_fn: impl Fn() -> u64,
    mut recv: R,
    mut send: W,
) -> Result<(), ServeError>
where
    S: Borrow<Store>,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let Some(request_bytes) = read_frame(&mut recv).await? else {
            return Ok(()); // clean EOF between frames: the peer closed the control stream.
        };
        let ts = now_fn();
        let reply_bytes = server
            .handle_bytes(ctx, ts, &request_bytes)
            .map_err(ServeError::Decode)?;
        write_frame(&mut send, &reply_bytes).await?;
    }
}
