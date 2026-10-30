//! Lab-only across-NAT S2 harness (td-c694b2).
//!
//! This crate exists to answer one question: what is the production signaling stack's
//! offer->usable-stream latency when the two peers sit behind **different NATs**? It drives
//! `spindle_net::signaling::{SignalingHost, SignalingClient}` unchanged; only the membership
//! decision is replaced with the live tests' `RegistryAuthorizer` test double (a fixed map of
//! device fingerprints to keys), because membership policy is not the thing being measured.
//!
//! The fixed seeds below are lab stand-ins, not production key material:
//! - `host_fp` is an arbitrary 32-byte subject-scoping token (the `<hfp>` in `host.<hfp>.*`).
//! - the host envelope device is `[0xB3; 32]`/`[0xB4; 32]`; the client is `[0xC1; 32]`/`[0xC2; 32]`.
//!
//! The NATS server these binaries talk to is a lab-local unauthenticated instance: the production
//! Auth Callout/subject scoping is deliberately not exercised here (the live tests already cover
//! it), and the client still sets the `_INBOX_<device_fp>` prefix the host's reply-prefix check
//! requires.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use spindle_core::identity::DeviceKey;
use spindle_core::{Fingerprint, VerifyingKey};
use spindle_net::framing::{read_frame, write_frame};
use spindle_net::quic::ControlStream;
use spindle_net::signaling::{
    ConnectAuthorizer, ConnectDecision, HostIdentity, SessionHandler, VerifiedDecision,
};
use x25519_dalek::PublicKey as X25519PublicKey;

pub const HOST_FP_BYTES: [u8; 32] = [0xB1; 32];

pub fn host_fp() -> Fingerprint {
    Fingerprint::from_slice(&HOST_FP_BYTES).expect("32-byte fingerprint")
}

pub fn host_device() -> DeviceKey {
    DeviceKey::from_seeds([0xB3; 32], [0xB4; 32])
}

pub fn client_device() -> DeviceKey {
    DeviceKey::from_seeds([0xC1; 32], [0xC2; 32])
}

/// The client's view of the host: subject-scoping fp, envelope device fp, and the envelope keys.
pub fn host_identity() -> HostIdentity {
    let device = host_device();
    HostIdentity {
        host_fp: host_fp(),
        device_fp: device.device_fp(),
        sign_pk: device.sign_public_key(),
        agree_pk: device.agree_public_key(),
    }
}

/// The live tests' `RegistryAuthorizer`, reduced to what this harness needs: allow exactly the
/// devices in the registry and return no member cap.
pub struct RegistryAuthorizer {
    registry: HashMap<Fingerprint, (VerifyingKey, X25519PublicKey)>,
}

impl RegistryAuthorizer {
    pub fn new(devices: &[&DeviceKey]) -> Self {
        let registry = devices
            .iter()
            .map(|d| (d.device_fp(), (d.sign_public_key(), d.agree_public_key())))
            .collect();
        Self { registry }
    }
}

impl ConnectAuthorizer for RegistryAuthorizer {
    async fn authorize(&self, from_fp: &Fingerprint) -> ConnectDecision {
        match self.registry.get(from_fp).copied() {
            Some((sign_pk, agree_pk)) => ConnectDecision::Allow { sign_pk, agree_pk },
            None => ConnectDecision::Deny,
        }
    }

    async fn on_verified(&self, _from_fp: &Fingerprint) -> VerifiedDecision {
        VerifiedDecision::Proceed { member_cap: None }
    }
}

/// Echoes one length-prefixed frame and prints a JSON event when the QUIC control stream becomes
/// usable. `t_ms` is relative to the host process start, so the driver can correlate it with the
/// client's attempt timestamps.
pub struct EchoHandler {
    start: Instant,
    sessions: Arc<AtomicUsize>,
}

impl EchoHandler {
    pub fn new(start: Instant) -> Self {
        Self {
            start,
            sessions: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn sessions(&self) -> Arc<AtomicUsize> {
        self.sessions.clone()
    }
}

impl SessionHandler for EchoHandler {
    async fn handle_session(
        &self,
        peer_device_fp: Fingerprint,
        mut control: ControlStream,
    ) -> ControlStream {
        let session = self.sessions.fetch_add(1, Ordering::SeqCst) + 1;
        println!(
            "{}",
            serde_json::json!({
                "event": "quic_usable",
                "peer_fp": peer_device_fp.to_string(),
                "session": session,
                "t_ms": self.start.elapsed().as_secs_f64() * 1000.0,
            })
        );
        match read_frame(&mut control.recv).await {
            Ok(Some(frame)) => {
                if let Err(error) = write_frame(&mut control.send, &frame).await {
                    eprintln!("[host] echo write failed: {error}");
                }
            }
            Ok(None) => eprintln!("[host] client closed the control stream before sending a frame"),
            Err(error) => eprintln!("[host] echo read failed: {error}"),
        }
        control
    }
}

pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite latencies"));
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    })
}
