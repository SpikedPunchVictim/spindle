//! End-to-end: [`spindle_client_core::VfsClient`] against the real host serve loop over a real
//! localhost QUIC control stream (td-6e3e90). The setup mirrors
//! `spindle-host-core/tests/quic_rpc.rs`, but the client half is the production client module
//! instead of a hand-rolled request/reply closure.

use spindle_client_core::{VfsClient, VfsClientError};
use spindle_core::identity::DeviceKey;
use spindle_core::{Fingerprint, SigningKey};
use spindle_host_core::{serve_control_stream, SessionContext, VfsRpcServer};
use spindle_net::quic::{QuicClient, QuicServer, SessionCert};
use spindle_proto::vfs_rpc::{MAX_READ_CHUNK, MAX_UPLOAD_CHUNK};
use spindle_vfs::model::{DevicePublicKeys, MemberId, Perms, ShareFlags, ShareId, VirtualPath};
use spindle_vfs::store::Store;
use tempfile::TempDir;

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

    fn add_signing_device(&self, member_id: MemberId, label: &str) -> (Fingerprint, SigningKey) {
        let mut sign_seed = [0u8; 32];
        sign_seed.copy_from_slice(
            Fingerprint::of_parts(&[b"signing-key-seed", label.as_bytes()]).as_bytes(),
        );
        let mut agree_seed = [0u8; 32];
        agree_seed.copy_from_slice(
            Fingerprint::of_parts(&[b"agree-key-seed", label.as_bytes()]).as_bytes(),
        );
        let dev = DeviceKey::from_seeds(sign_seed, agree_seed);
        let device_fp = dev.device_fp();
        self.store
            .add_device(
                member_id,
                device_fp,
                label,
                0,
                Some(&DevicePublicKeys {
                    alg_id: spindle_core::ALG_ID_V1,
                    sign_pk: dev.sign_public_key().as_bytes().to_vec(),
                    agree_pk: dev.agree_public_key().as_bytes().to_vec(),
                }),
            )
            .expect("add signing device");
        (device_fp, SigningKey::from_bytes(&sign_seed))
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

#[tokio::test(flavor = "multi_thread")]
async fn list_stat_read_and_upload_over_a_real_quic_control_stream() {
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
    let read_body: Vec<u8> = (0..(2 * MAX_READ_CHUNK as usize + 123))
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(photos_root.join("a.txt"), &read_body).expect("write a.txt");
    h.grant(
        member_id,
        photos,
        "",
        Perms::BROWSE | Perms::DOWNLOAD | Perms::UPLOAD | Perms::DELETE,
    );
    let private = h.add_share("Private", "Private", ShareFlags::default());
    std::fs::write(h.share_real_root(private).join("secret.txt"), b"nope").expect("write secret");

    let server_cert = SessionCert::generate().expect("server cert");
    let client_cert = SessionCert::generate().expect("client cert");
    let quic_server = QuicServer::bind(
        "127.0.0.1:0".parse().expect("addr"),
        &server_cert,
        client_cert.fingerprint(),
    )
    .expect("bind quic server");
    let addr = quic_server.local_addr().expect("local_addr");
    let server_fp = server_cert.fingerprint();

    let store = h.store;
    let ctx = SessionContext {
        member_id,
        device_fp,
    };
    let server_task = tokio::spawn(async move {
        let control = quic_server.accept().await.expect("accept");
        serve_control_stream(
            VfsRpcServer::new(store),
            &ctx,
            || 0,
            control.recv,
            control.send,
        )
        .await
        .expect("serve control stream");
    });

    let control = QuicClient::connect(addr, server_fp, &client_cert)
        .await
        .expect("client connect");
    let mut client = VfsClient::new(control.recv, control.send);

    let (entries, _next) = client.list("Photos", None, None).await.expect("list");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"a.txt"), "listing: {names:?}");

    let stat = client.stat("Photos/a.txt").await.expect("stat");
    match stat {
        spindle_proto::vfs_rpc::VfsReply::Stat { size, .. } => {
            assert_eq!(size, read_body.len() as u64)
        }
        other => panic!("unexpected stat reply: {other:?}"),
    }

    let body = client.read_all("Photos/a.txt").await.expect("read_all");
    assert_eq!(body, read_body, "multi-chunk read_all");

    let upload: Vec<u8> = (0..(2 * MAX_UPLOAD_CHUNK as usize + 17))
        .map(|i| (i % 253) as u8)
        .collect();
    let hash = sha256(&upload);
    let upload_path = "Photos/uploaded.bin";
    let sig = sign_manifest(&signing_key, upload_path, upload.len() as u64, &hash);
    client
        .upload_file(upload_path, &upload, hash, sig)
        .await
        .expect("upload_file");
    assert_eq!(
        std::fs::read(photos_root.join("uploaded.bin")).expect("read uploaded"),
        upload,
        "multi-chunk upload_file"
    );

    // A resumed upload: send one chunk, then let upload_file reopen the same session and finish.
    let resumed_path = "Photos/resumed.bin";
    let resumed_hash = sha256(&upload);
    let resumed_sig = sign_manifest(
        &signing_key,
        resumed_path,
        upload.len() as u64,
        &resumed_hash,
    );
    let (session_id, offset) = client
        .upload_open(
            resumed_path,
            upload.len() as u64,
            resumed_hash.clone(),
            resumed_sig.clone(),
        )
        .await
        .expect("open upload");
    assert_eq!(offset, 0);
    let first = client
        .upload_chunk(&session_id, 0, upload[..MAX_UPLOAD_CHUNK as usize].to_vec())
        .await
        .expect("first chunk");
    assert_eq!(first, MAX_UPLOAD_CHUNK as u64);
    client
        .upload_file(resumed_path, &upload, resumed_hash, resumed_sig)
        .await
        .expect("resume and commit");
    assert_eq!(
        std::fs::read(photos_root.join("resumed.bin")).expect("read resumed"),
        upload,
        "resumed upload"
    );

    let denied = client
        .read_all("Private/secret.txt")
        .await
        .expect_err("no entitlement");
    assert!(
        matches!(denied, VfsClientError::Peer(_)),
        "a host refusal must surface as Peer, got {denied:?}"
    );

    // The client half has no close method; dropping it closes the QUIC connection after the
    // server's clean-EOF path. Wait for the server so a panic there is not swallowed.
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(5), server_task)
        .await
        .expect("server exits")
        .expect("server task");
}
