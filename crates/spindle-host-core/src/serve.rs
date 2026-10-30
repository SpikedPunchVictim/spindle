//! Binds the VFS RPC pipeline ([`crate::server::VfsRpcServer::handle`], under the per-share
//! upload/reconcile lock for ledger-mutating requests) to a real duplex byte stream (Stage 6
//! slice 5 — DESIGN.md §A8 "One control stream (VFS RPC) + data streams"). The production caller
//! is `spindle_net::quic::ControlStream`'s `{send, recv}` halves, but [`serve_control_stream`]
//! itself has no QUIC dependency: it is generic over any `tokio::io::{AsyncRead, AsyncWrite}`
//! pair, exactly like [`spindle_net::framing`] itself (which this module calls directly — see
//! that module's doc comment for the wire format: a 4-byte big-endian length prefix, 256 KiB cap).
//!
//! # Loop shape
//!
//! The loop decodes each frame, takes the share's upload/reconcile lock when the request can
//! mutate the upload ledger (`UploadCommit` or `Delete`, td-042e4f), then dispatches the decoded
//! request to `VfsRpcServer::handle`. This *is* the byte-level entry point: the old unlocked
//! `handle_bytes` wrapper was removed so no caller can reach a ledger-mutating path around the
//! lock. The lock acquisition is async, which is why it happens here rather than inside the
//! synchronous pipeline.
//!
//! `VfsRpcServer::handle` takes `&self` (its caches are `RefCell`-based — see
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
//! [`ServeError::Decode`], deliberately distinct from every `VfsErrorCode`) is neither — it is a
//! transport-level protocol violation from a peer that
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
use spindle_proto::VfsRequestEnvelope;
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
    /// [`spindle_proto::VfsRequestEnvelope`] — deliberately distinct from every
    /// [`spindle_proto::VfsErrorCode`].
    #[error("request bytes did not decode as a VfsRequestEnvelope: {0}")]
    Decode(spindle_proto::ProtoError),
}

/// Drives one VFS RPC session's control stream to completion: read a frame, hand its bytes to
/// `server.handle` (after the `UploadCommit` lock step above), write the reply frame, repeat — until the peer cleanly closes its send
/// side or a protocol violation occurs (see the module doc comment for which is which).
///
/// `ctx` is fixed for the lifetime of this call — DESIGN.md §A8's VFS RPC session is bound to one
/// `{member_id, device_fp}` pair for its whole duration (`spindle_host_core::server::
/// SessionContext`'s doc comment: authenticating a transport-level session down to these two
/// values is `spindle-net`'s responsibility, done once, before this loop starts — not re-derived
/// per request). `now_fn` is an injectable clock (`impl Fn() -> u64`, called once per request to
/// produce that request's audit timestamp) rather than a direct wall-clock read, so tests can
/// drive this loop with deterministic, controlled timestamps exactly like every other timestamp
/// in this crate's pipeline (the VFS pipeline's own `ts` parameter).
///
/// Generic over `R`/`W` rather than a single combined stream type: quinn already hands out
/// `SendStream`/`RecvStream` as two independent halves (see `spindle_net::quic::ControlStream`),
/// and this loop reads and writes them independently in strict request/reply lockstep anyway (VFS
/// RPC has no pipelining), so there is no combined-stream abstraction to gain by fusing them
/// first — two plain generic parameters is the boring, direct fit for `handle`'s `&self`
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
        let env =
            VfsRequestEnvelope::from_canonical_bytes(&request_bytes).map_err(ServeError::Decode)?;

        // td-042e4f: a request that mutates the upload ledger takes its share's in-process
        // upload/reconcile lock for the whole filesystem-then-database window. `UploadCommit`
        // (finalize -> record -> audit) and `Delete` (unlink -> `remove_uploads_under` -> audit)
        // both qualify; without the Delete half, a concurrent commit could re-create a file whose
        // fresh ledger row a delete then removes, leaving the same permanent undercount. The
        // registry is cloned (an `Arc` bump) **before** the await, and the guard is released before
        // the reply write, so neither `&server` nor the lock outlives its purpose. Holding
        // `&server` across the await would make this session future `!Send` — `VfsRpcServer` is
        // `!Sync` by design (see `crate::server`'s module docs). Other requests take no lock, and
        // a server with no registry installed behaves exactly as the unlocked pipeline did.
        let reply_bytes = {
            let share_id = server.ledger_share_for(&env.request, ctx.member_id);
            let locks = server.upload_locks();
            let _upload_guard = match (locks, share_id) {
                (Some(locks), Some(share_id)) => Some(locks.lock(share_id).await),
                _ => None,
            };
            server.handle(ctx, ts, env).to_canonical_bytes()
        };
        write_frame(&mut send, &reply_bytes).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::VfsRpcServer;
    use crate::upload_locks::UploadLedgerLocks;
    use spindle_core::Fingerprint;
    use spindle_proto::{VfsRequest, VfsRequestEnvelope};
    use spindle_vfs::model::ShareFlags;
    use spindle_vfs::store::Store;
    use std::time::Duration;
    use tokio::io::duplex;

    /// td-042e4f: the serve loop must take the share's ledger lock for `Delete`, not only for
    /// `UploadCommit`. A held lock keeps the pipeline from running at all, so no reply reaches the
    /// client; releasing it lets the request through. The request itself is denied later (no
    /// entitlement, no upload-enabled share) — irrelevant to this assertion, which is about
    /// pre-dispatch serialization.
    #[tokio::test]
    async fn a_delete_waits_for_the_share_lock_before_the_pipeline_runs() {
        let sandbox = tempfile::tempdir().expect("tempdir");
        let root = sandbox.path().join("drop");
        std::fs::create_dir_all(&root).expect("mkdir share root");
        let store = Store::open_in_memory().expect("open store");
        let member_id = store
            .add_member(Fingerprint::of_parts(&[b"alex"]), "alex", 0)
            .expect("add_member");
        store.activate_member(member_id).expect("activate_member");
        let share_id = store
            .add_share("Drop", "Drop", &root, ShareFlags::default(), &[], 0)
            .expect("add_share");

        let locks = UploadLedgerLocks::new();
        let held = locks.lock(share_id).await;
        let server = VfsRpcServer::new(store).with_upload_locks(locks);
        let ctx = SessionContext {
            member_id,
            device_fp: Fingerprint::of_parts(&[b"device"]),
        };

        let (client, server_io) = duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server_io);
        let envelope = VfsRequestEnvelope {
            v: 1,
            request: VfsRequest::Delete {
                path: "/Drop/a.txt".to_string(),
            },
        };
        write_frame(&mut client_write, &envelope.to_canonical_bytes())
            .await
            .expect("write request frame");

        let serve = serve_control_stream(server, &ctx, || 1u64, server_read, server_write);
        tokio::pin!(serve);

        let mut replied_while_held = false;
        tokio::select! {
            biased;
            frame = read_frame(&mut client_read) => {
                replied_while_held = frame.expect("framing").is_some();
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        assert!(
            !replied_while_held,
            "the Delete must not reach the pipeline while its share's lock is held"
        );

        drop(held);

        let reply = tokio::select! {
            biased;
            _ = &mut serve => panic!("the serve loop ended before replying"),
            frame = read_frame(&mut client_read) => frame
                .expect("framing")
                .expect("a reply frame once the lock is released"),
        };
        assert!(!reply.is_empty(), "the Delete produced a reply");
    }
}
