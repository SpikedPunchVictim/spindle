//! Live device-session proof (td-7c80c5): the production [`spindle_client_core::connect_device`]
//! authenticates through the real Auth Callout, opens a real QUIC session to a real
//! `SignalingHost`, and surfaces the host's member capability.
//!
//! `#[ignore]`d like the other live suites; run after
//! `docker compose -f deploy/docker-compose.yml up -d`:
//!
//! ```text
//! cargo test -p spindle-client-core --test live_device_session -- --ignored --nocapture
//! ```
//!
//! Random identity seeds per run, so the helper's durable revocation set cannot poison reruns.

use std::sync::Arc;
use std::time::Duration;

use spindle_client_core::{connect_device, DeviceSessionParams};
use spindle_core::identity::DeviceKey;
use spindle_core::Fingerprint;
use spindle_net::framing::{read_frame, write_frame};
use spindle_net::quic::ControlStream;
use spindle_net::signaling::{
    ConnectAuthorizer, ConnectDecision, ConnectOptions, HostIdentity, HostOptions, SessionHandler,
    SignalingHost, VerifiedDecision,
};
use spindle_proto::artifacts::Capability;
use spindle_test_fixtures::fixtures::{now, DeviceIdentity, HostRootIdentity};
use spindle_test_fixtures::{connect_host, nats_url};

struct AllowDevice {
    device_fp: Fingerprint,
    sign_pk: spindle_core::VerifyingKey,
    agree_pk: x25519_dalek::PublicKey,
    member_cap: Capability,
}

impl ConnectAuthorizer for AllowDevice {
    async fn authorize(&self, from_fp: &Fingerprint) -> ConnectDecision {
        if *from_fp == self.device_fp {
            ConnectDecision::Allow {
                sign_pk: self.sign_pk,
                agree_pk: self.agree_pk,
            }
        } else {
            ConnectDecision::Deny
        }
    }

    async fn on_verified(&self, _from_fp: &Fingerprint) -> VerifiedDecision {
        VerifiedDecision::Proceed {
            member_cap: Some(self.member_cap.clone()),
        }
    }
}

struct Echo;

impl SessionHandler for Echo {
    async fn handle_session(
        &self,
        _peer_device_fp: Fingerprint,
        mut control: ControlStream,
    ) -> ControlStream {
        if let Ok(Some(frame)) = read_frame(&mut control.recv).await {
            let _ = write_frame(&mut control.send, &frame).await;
        }
        control
    }
}

fn random_seed(tag: &[u8]) -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed[..tag.len().min(32)].copy_from_slice(&tag[..tag.len().min(32)]);
    seed
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, then `cargo test -p spindle-client-core --test live_device_session -- --ignored --nocapture`"]
async fn a_device_session_authenticates_and_surfaces_the_member_cap() {
    let url = nats_url();
    let now = now();
    let exp = now + 3_600;

    let client = DeviceIdentity::new(
        random_seed(b"root"),
        random_seed(b"dev-sign"),
        random_seed(b"dev-agree"),
    );
    let host_root = HostRootIdentity::new(random_seed(b"host-root"), random_seed(b"host-op"));
    let host_device = DeviceKey::from_seeds(
        random_seed(b"host-dev-sign"),
        random_seed(b"host-dev-agree"),
    );
    let host_device_fp = host_device.device_fp();
    let host_sign_pk = host_device.sign_public_key();
    let host_agree_pk = host_device.agree_public_key();

    let cap = host_root.member_capability(client.root_fp(), exp, random_seed(b"nonce").to_vec());
    let device_cert = client.certificate(now, exp);
    let device_root_pk = client.root.public_key().to_bytes();

    let (host_nats, _host_events) = connect_host(&url, &host_root, exp).await;
    let host = Arc::new(SignalingHost::new(
        host_nats,
        host_device,
        host_root.host_fp,
        AllowDevice {
            device_fp: client.device_fp,
            sign_pk: client.device_key().sign_public_key(),
            agree_pk: client.device_key().agree_public_key(),
            member_cap: cap.clone(),
        },
        Echo,
    ));
    let host_task = tokio::spawn({
        let host = Arc::clone(&host);
        async move {
            host.run(HostOptions {
                bind_ip: "127.0.0.1".parse().expect("host bind ip"),
                ..HostOptions::default()
            })
            .await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let host_identity = HostIdentity {
        host_fp: host_root.host_fp,
        device_fp: host_device_fp,
        sign_pk: host_sign_pk,
        agree_pk: host_agree_pk,
    };
    let session = connect_device(DeviceSessionParams {
        nats_url: &url,
        device: client.device_key(),
        device_cert: &device_cert,
        device_root_pk: &device_root_pk,
        caps: std::slice::from_ref(&cap),
        host: host_identity,
        connect: ConnectOptions {
            bind_ip: "127.0.0.1".parse().expect("bind ip"),
            ..ConnectOptions::default()
        },
        now,
    })
    .await
    .expect("device session");

    assert_eq!(session.device_fp, client.device_fp);
    assert_eq!(
        session
            .member_cap
            .as_ref()
            .map(|cap| cap.to_canonical_bytes()),
        Some(cap.to_canonical_bytes()),
        "the host's member cap must surface on the session"
    );

    // A real byte round trip over the control stream proves the QUIC session, not just the answer.
    let mut control = session.control;
    let payload = b"live-device-session".to_vec();
    write_frame(&mut control.send, &payload)
        .await
        .expect("write");
    let echoed = read_frame(&mut control.recv)
        .await
        .expect("read")
        .expect("echo frame");
    assert_eq!(echoed, payload);

    host_task.abort();
}
