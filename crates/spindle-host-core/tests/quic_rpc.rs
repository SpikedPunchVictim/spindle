//! Stage 6 slice 5 end-to-end integration test: [`spindle_host_core::serve_control_stream`] driven
//! over a **real** localhost QUIC connection (`spindle_net::quic`), exercising a full VFS RPC
//! session through mutual-pinned TLS 1.3 and length-prefixed framing — not just the in-process
//! `VfsRpcServer::handle` calls `tests/rpc_negative.rs` already covers. Setup pattern (temp share +
//! seeded member) copied from that file's `Harness`.
//!
//! Requests are built and encoded via `spindle-proto`'s own types
//! (`VfsRequestEnvelope::to_canonical_bytes`) and decoded the same way on the way back
//! (`VfsReply::from_canonical_bytes`) — this test is therefore also a soft wire-vector check: if
//! the encode/decode round trip silently changed shape, the assertions below would fail even
//! though `VfsRpcServer::handle`'s own unit tests never touch the wire at all.

use spindle_core::identity::DeviceKey;
use spindle_core::{Fingerprint, SigningKey};
use spindle_host_core::{serve_control_stream, ServeError, SessionContext, VfsRpcServer};
use spindle_net::framing::{read_frame, write_frame, MAX_FRAME_LEN};
use spindle_net::quic::{QuicClient, QuicServer, SessionCert};
use spindle_vfs::model::{DevicePublicKeys, MemberId, Perms, ShareFlags, ShareId, VirtualPath};
use spindle_vfs::store::Store;
use std::net::SocketAddr;
use tempfile::TempDir;

// =================================================================================================
// Shared test scaffolding (copied/adapted from tests/rpc_negative.rs's Harness)
// =================================================================================================

struct Harness {
    sandbox: TempDir,
    store: Store,
}

impl Harness {
    fn new() -> Self {
        Harness {
            sandbox: tempfile::tempdir().expect("tempdir"),
            store: Store::open_in_memory().expect("open in-memory store"),
        }
    }

    fn real_root(&self, name: &str) -> std::path::PathBuf {
        let p = self.sandbox.path().join(name);
        std::fs::create_dir_all(&p).expect("mkdir real root");
        p
    }

    fn add_active_member(&self, display_name: &str) -> MemberId {
        let fp = Fingerprint::of_parts(&[display_name.as_bytes()]);
        let id = self
            .store
            .add_member(fp, display_name, 0)
            .expect("add member");
        self.store.activate_member(id).expect("activate member");
        id
    }

    /// Enrolls a device with a real Ed25519 signing keypair pinned as its `sign_pk` — mirrors
    /// `spindle_host_core::server`'s own private test helper of the same purpose (not reachable
    /// from this external integration test, so reimplemented here against the crate's public
    /// `Store`/`spindle-core` surface only). Also pins a real, matching `agree_pk`: `device_fp` is
    /// `DeviceKey`'s own binding hash over both keys, so `sign_pk`/`agree_pk`/`device_fp` genuinely
    /// rehash together (see `Store::member_for_device_fp`'s doc comment).
    fn add_signing_device(&self, member_id: MemberId, label: &str) -> (Fingerprint, SigningKey) {
        let sign_seed = {
            let mut seed = [0u8; 32];
            let digest = Fingerprint::of_parts(&[b"signing-key-seed", label.as_bytes()]);
            seed.copy_from_slice(digest.as_bytes());
            seed
        };
        let agree_seed = {
            let mut seed = [0u8; 32];
            let digest = Fingerprint::of_parts(&[b"agree-key-seed", label.as_bytes()]);
            seed.copy_from_slice(digest.as_bytes());
            seed
        };
        let dev = DeviceKey::from_seeds(sign_seed, agree_seed);
        let device_fp = dev.device_fp();
        let signing_key = SigningKey::from_bytes(&sign_seed);
        self.store
            .add_device(
                member_id,
                device_fp,
                label,
                0,
                Some(&DevicePublicKeys {
                    sign_pk: dev.sign_public_key().as_bytes().to_vec(),
                    agree_pk: dev.agree_public_key().as_bytes().to_vec(),
                }),
            )
            .expect("add signing device");
        (device_fp, signing_key)
    }

    fn add_share(&self, name: &str, mount_path: &str, flags: ShareFlags) -> ShareId {
        let root = self.real_root(name);
        self.store
            .add_share(name, mount_path, &root, flags, &[], 0)
            .expect("add share")
    }

    fn share_real_root(&self, share_id: ShareId) -> std::path::PathBuf {
        self.store
            .get_share(share_id)
            .expect("get_share")
            .expect("share exists")
            .real_root
    }

    fn grant(&self, member_id: MemberId, share_id: ShareId, subpath: &str, perms: Perms) {
        let group_name = format!("g-{}-{}-{}", member_id.0, share_id.0, subpath);
        let group_id = self
            .store
            .create_custom_group(&group_name)
            .expect("create group");
        self.store
            .add_member_to_group(member_id, group_id)
            .expect("join group");
        self.store
            .add_entitlement(
                group_id,
                share_id,
                &VirtualPath::parse(subpath).expect("valid subpath"),
                perms,
            )
            .expect("grant entitlement");
    }
}

/// This crate's own upload-manifest signing-input encoding
/// (`spindle_host_core::upload::manifest_signing_bytes`, `pub(crate)` and therefore unreachable
/// from this external test) — reimplemented here byte-for-byte from that function's documented
/// format (length-prefixed `path || size || hash`) so this test can build a manifest signature a
/// real client would produce identically.
fn manifest_signing_bytes(path: &str, size: u64, hash: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + path.len() + 8 + 8 + hash.len());
    buf.extend_from_slice(&(path.len() as u64).to_be_bytes());
    buf.extend_from_slice(path.as_bytes());
    buf.extend_from_slice(&size.to_be_bytes());
    buf.extend_from_slice(&(hash.len() as u64).to_be_bytes());
    buf.extend_from_slice(hash);
    buf
}

fn sign_manifest(signing_key: &SigningKey, path: &str, size: u64, hash: &[u8]) -> Vec<u8> {
    spindle_core::sign_bytes(signing_key, &manifest_signing_bytes(path, size, hash))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    Fingerprint::of_parts(&[data]).to_vec()
}

fn any_local_addr() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid socket addr")
}

// =================================================================================================
// Happy path: whoami -> list -> read -> upload_open/chunk/commit -> a denied op
// =================================================================================================

#[tokio::test(flavor = "multi_thread")]
async fn full_session_over_real_quic_control_stream() {
    use spindle_proto::{VfsErrorCode, VfsReply, VfsRequest, VfsRequestEnvelope};

    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let (device_fp, signing_key) = h.add_signing_device(member_id, "alex-laptop");

    let photos = h.add_share(
        "Photos",
        "Photos",
        ShareFlags {
            read_only: false,
            allow_upload: true,
            show_hidden: false,
        },
    );
    let photos_root = h.share_real_root(photos);
    std::fs::write(photos_root.join("a.jpg"), b"hello, spindle!").expect("write a.jpg");
    h.grant(
        member_id,
        photos,
        "",
        Perms::BROWSE | Perms::DOWNLOAD | Perms::UPLOAD | Perms::DELETE,
    );

    // A second share with no grant at all — the denied-op leg below.
    let _private = h.add_share("Private", "Private", ShareFlags::default());
    let private_root = h.share_real_root(_private);
    std::fs::write(private_root.join("secret.jpg"), b"nope").expect("write secret.jpg");

    let server_cert = SessionCert::generate().expect("server cert");
    let client_cert = SessionCert::generate().expect("client cert");
    let quic_server = QuicServer::bind(any_local_addr(), &server_cert, client_cert.fingerprint())
        .expect("bind quic server");
    let addr = quic_server.local_addr().expect("local_addr");
    let server_fp = server_cert.fingerprint();

    let upload_content = b"uploaded via quic control stream".to_vec();
    let upload_content_for_check = upload_content.clone();
    let upload_hash = sha256(&upload_content);
    let upload_path = "Photos/uploaded.bin".to_string();
    let upload_sig = sign_manifest(
        &signing_key,
        &upload_path,
        upload_content.len() as u64,
        &upload_hash,
    );

    // The client task returns its `Connection` handle rather than letting it drop at the end of
    // the async block: quinn drops => implicit `Connection::close`, which races the server's
    // final `read_frame` (a clean stream FIN from `send.finish()` below is enough for the server
    // loop to see `Ok(None)`, but an implicit whole-connection close beats it to the socket if
    // dropped too early — the same race already worked around in spindle-net's own QUIC tests).
    // Holding the connection alive until *after* `client_task.await` (below, following the
    // server's own clean-EOF assertion) sidesteps the race instead of asserting timing.
    let client_task = tokio::spawn(async move {
        let control = QuicClient::connect(addr, server_fp, &client_cert)
            .await
            .expect("client connect");
        let connection = control.connection;
        let mut send = control.send;
        let mut recv = control.recv;

        async fn roundtrip<W: tokio::io::AsyncWrite + Unpin, R: tokio::io::AsyncRead + Unpin>(
            send: &mut W,
            recv: &mut R,
            req: VfsRequestEnvelope,
        ) -> VfsReply {
            write_frame(send, &req.to_canonical_bytes())
                .await
                .expect("write request frame");
            let bytes = read_frame(recv)
                .await
                .expect("read reply frame")
                .expect("Some(frame): server must not hang up mid-session");
            VfsReply::from_canonical_bytes(&bytes).expect("reply decodes")
        }

        // whoami
        let reply = roundtrip(
            &mut send,
            &mut recv,
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::Whoami,
            },
        )
        .await;
        match reply {
            VfsReply::Whoami { member_display, .. } => assert_eq!(member_display, "Alex"),
            other => panic!("expected Whoami, got {other:?}"),
        }

        // list
        let reply = roundtrip(
            &mut send,
            &mut recv,
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::List {
                    path: "Photos".to_string(),
                    cursor: None,
                    limit: None,
                },
            },
        )
        .await;
        match reply {
            VfsReply::List { entries, .. } => {
                assert!(entries.iter().any(|e| e.name == "a.jpg"));
            }
            other => panic!("expected List, got {other:?}"),
        }

        // read (verify bytes)
        let reply = roundtrip(
            &mut send,
            &mut recv,
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::Read {
                    path: "Photos/a.jpg".to_string(),
                    offset: 0,
                    len: 64,
                },
            },
        )
        .await;
        match reply {
            VfsReply::Read { data, eof } => {
                assert_eq!(data, b"hello, spindle!");
                assert!(eof);
            }
            other => panic!("expected Read, got {other:?}"),
        }

        // upload_open
        let reply = roundtrip(
            &mut send,
            &mut recv,
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::UploadOpen {
                    path: upload_path.clone(),
                    size: upload_content.len() as u64,
                    hash: upload_hash.clone(),
                    manifest_sig: upload_sig.clone(),
                },
            },
        )
        .await;
        let session_id = match reply {
            VfsReply::UploadOpen { session_id, offset } => {
                assert_eq!(offset, 0);
                session_id
            }
            other => panic!("expected UploadOpen, got {other:?}"),
        };

        // upload_chunk (whole file in one chunk — well under MAX_UPLOAD_CHUNK)
        let reply = roundtrip(
            &mut send,
            &mut recv,
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::UploadChunk {
                    session_id: session_id.clone(),
                    offset: 0,
                    data: upload_content.clone(),
                },
            },
        )
        .await;
        match reply {
            VfsReply::UploadChunk { offset } => assert_eq!(offset, upload_content.len() as u64),
            other => panic!("expected UploadChunk, got {other:?}"),
        }

        // upload_commit (verify file lands is checked back in the main task, after this whole
        // session completes — see this test fn's tail)
        let reply = roundtrip(
            &mut send,
            &mut recv,
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::UploadCommit {
                    session_id: session_id.clone(),
                },
            },
        )
        .await;
        assert!(matches!(reply, VfsReply::UploadCommit));

        // a denied op: reading a path in a share this member has no grant on at all must come
        // back as the same typed error DESIGN.md §A4b requires for "unauthorized" (not_found).
        let reply = roundtrip(
            &mut send,
            &mut recv,
            VfsRequestEnvelope {
                v: 1,
                request: VfsRequest::Read {
                    path: "Private/secret.jpg".to_string(),
                    offset: 0,
                    len: 16,
                },
            },
        )
        .await;
        match reply {
            VfsReply::Error { code } => assert_eq!(code, VfsErrorCode::NotFound),
            other => panic!("expected Error(NotFound), got {other:?}"),
        }

        send.finish().expect("client finish send side");
        connection
    });

    let control = quic_server.accept().await.expect("server accept");
    let ctx = SessionContext {
        member_id,
        device_fp: Some(device_fp),
    };
    let server = VfsRpcServer::new(&h.store);
    // Deterministic clock: every request in this test gets the same audit timestamp, matching
    // this crate's "never a wall clock inside the pipeline" convention (`VfsRpcServer::handle`'s
    // own `ts` parameter) — the loop's `now_fn` seam this slice adds is exercised here, not just
    // documented.
    let result = serve_control_stream(server, &ctx, || 1u64, control.recv, control.send).await;
    assert!(
        result.is_ok(),
        "the control-stream loop must end cleanly once the client finishes its send side: {result:?}"
    );

    let _connection = client_task.await.expect("client task panicked");

    // Only now (after the server loop's clean-EOF return, which cannot happen until the client's
    // last read — `upload_commit`'s reply — has already completed) is it safe to assert the
    // uploaded file actually landed on disk.
    let landed = std::fs::read(h.share_real_root(photos).join("uploaded.bin"))
        .expect("uploaded file must exist under the share root");
    assert_eq!(landed, upload_content_for_check);
}

// =================================================================================================
// Negative (a): wrong expected server fingerprint fails at handshake
// =================================================================================================

#[tokio::test(flavor = "multi_thread")]
async fn client_with_wrong_expected_server_fp_fails_at_handshake() {
    let server_cert = SessionCert::generate().expect("server cert");
    let client_cert = SessionCert::generate().expect("client cert");
    let wrong_fp = SessionCert::generate().expect("decoy cert").fingerprint();

    let quic_server = QuicServer::bind(any_local_addr(), &server_cert, client_cert.fingerprint())
        .expect("bind quic server");
    let addr = quic_server.local_addr().expect("local_addr");

    let server_task = tokio::spawn(async move {
        // Never expected to yield a usable connection — this task only exists so the client's
        // failed handshake attempt has something to fail against, and to avoid hanging the test.
        let _ = quic_server.accept().await;
    });

    let result = QuicClient::connect(addr, wrong_fp, &client_cert).await;
    assert!(
        result.is_err(),
        "connecting with the wrong expected server fingerprint must fail"
    );

    server_task.abort();
}

// =================================================================================================
// Negative (b): client cert fingerprint mismatch is rejected by the server
// =================================================================================================

#[tokio::test(flavor = "multi_thread")]
async fn client_cert_fingerprint_mismatch_is_rejected() {
    let server_cert = SessionCert::generate().expect("server cert");
    let expected_client_cert = SessionCert::generate().expect("expected client cert");
    let actual_client_cert = SessionCert::generate().expect("actual (wrong) client cert");

    let quic_server = QuicServer::bind(
        any_local_addr(),
        &server_cert,
        expected_client_cert.fingerprint(),
    )
    .expect("bind quic server");
    let addr = quic_server.local_addr().expect("local_addr");

    let server_task = tokio::spawn(async move { quic_server.accept().await });

    // As in `spindle-net`'s own equivalent unit test: the client's TLS 1.3 handshake view can
    // race ahead of the server's rejection, so `connect` returning `Ok` here is not itself a
    // failure — the server's own rejection (checked below) is the property that matters.
    let client_result =
        QuicClient::connect(addr, server_cert.fingerprint(), &actual_client_cert).await;

    let server_result = server_task.await.expect("server task");
    assert!(
        server_result.is_err(),
        "the server must reject a client certificate that doesn't match the pinned fingerprint"
    );

    if let Ok(control) = client_result {
        // The server-side rejection is already established above; this block only proves the
        // client doesn't hang forever on a connection the server never actually accepted (i.e.
        // TLS 1.3's client-side "connected" view raced ahead of the server's own rejection — see
        // the comment above `client_result`). No specific close reason is asserted here (naming
        // `quinn::ConnectionError`'s variants would require this test crate to depend on `quinn`
        // directly, which it deliberately does not — see this file's module doc comment: requests
        // go through `spindle-proto`'s own types, not quinn's).
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            control.connection.closed(),
        )
        .await
        .expect("connection must close (not hang) after a rejected client cert");
    }
}

// =================================================================================================
// Negative (c): an oversized frame gets the connection closed, with no reply
// =================================================================================================

#[tokio::test(flavor = "multi_thread")]
async fn oversized_frame_is_a_protocol_violation_with_no_reply() {
    let h = Harness::new();
    let member_id = h.add_active_member("Alex");
    let (device_fp, _signing_key) = h.add_signing_device(member_id, "alex-laptop");

    let server_cert = SessionCert::generate().expect("server cert");
    let client_cert = SessionCert::generate().expect("client cert");
    let quic_server = QuicServer::bind(any_local_addr(), &server_cert, client_cert.fingerprint())
        .expect("bind quic server");
    let addr = quic_server.local_addr().expect("local_addr");
    let server_fp = server_cert.fingerprint();

    let client_task = tokio::spawn(async move {
        let control = QuicClient::connect(addr, server_fp, &client_cert)
            .await
            .expect("client connect");
        let mut send = control.send;
        let mut recv = control.recv;

        // A raw, hand-written oversized length prefix — deliberately bypassing
        // `spindle_net::framing::write_frame` (which refuses to emit one), simulating a
        // corrupt/hostile peer.
        let too_big = (MAX_FRAME_LEN + 1).to_be_bytes();
        send.write_all(&too_big)
            .await
            .expect("write bogus oversize length prefix");
        send.finish().ok();

        // No legitimate frame ever follows — the server must never send a reply to it.
        match read_frame(&mut recv).await {
            Ok(None) => {} // connection closed with nothing sent — no reply, as required
            Err(_) => {}   // the connection reset before a full frame arrived — also no reply
            Ok(Some(bytes)) => {
                panic!("server must never reply after an oversized frame, got {bytes:?}")
            }
        }
    });

    let control = quic_server.accept().await.expect("server accept");
    let ctx = SessionContext {
        member_id,
        device_fp: Some(device_fp),
    };
    let server = VfsRpcServer::new(&h.store);
    let result = serve_control_stream(server, &ctx, || 1u64, control.recv, control.send).await;
    assert!(
        matches!(result, Err(ServeError::Framing(_))),
        "an oversized frame must surface as a framing protocol violation, got {result:?}"
    );
    // Closing the connection is the caller's job (see `serve_control_stream`'s doc comment) —
    // done here exactly as a real host process would on this `Err`.
    control.connection.close(1u32.into(), b"protocol violation");

    client_task.await.expect("client task panicked");
}
