//! Device session: authenticate to the NATS Auth Callout as a device and open a host session
//! (DESIGN.md §A4/A6, td-7c80c5).
//!
//! This is the client-side counterpart of `spindle-hostd`'s `connect_host`. It mints a fresh
//! per-connection nkey, a [`SessionAttestation`] binding that nkey to the device identity key, and
//! the device arm of the CONNECT `auth_token` (td-e38932's production encoder), then hands the
//! authenticated `async_nats::Client` to [`spindle_net::signaling::SignalingClient`]. The returned
//! [`DeviceSession`] owns the QUIC control stream and the member capability from the host's
//! answer (`td-c74122`'s deferred consumer, now built).
//!
//! # What the caller supplies
//!
//! The device's identity key and the certificate the host issued for it, the **host root public
//! key** the invite carried, and the member capabilities to present. `async_nats::Client` is built
//! here rather than accepted from the caller because the CONNECT token has to be attached at
//! connect time; the NATS URL and connect options are the caller's policy.
//!
//! # Secrets
//!
//! The nkey seed, the attestation, and the token exist only inside this function. The session
//! holds the `async_nats::Client`, which already authenticated; no error or `Debug` rendering
//! carries the token or key material.

use base64::Engine as _;
use spindle_core::artifacts::issue_session_attestation;
use spindle_core::clock_diagnostics::{
    diagnose_clock_from_capabilities, ClockDiagnosis, ClockDiagnosticError,
};
use spindle_core::identity::DeviceKey;
use spindle_core::Fingerprint;
use spindle_net::quic::ControlStream;
use spindle_net::signaling::{ConnectOptions, HostIdentity, SignalingClient, SignalingError};
use spindle_proto::artifacts::{Capability, DeviceCertificate};
use spindle_proto::auth_token::encode_device_auth_token;

use crate::self_revocation::TransportError;
use crate::turn_credentials::{
    fetch_turn_ice_config, TurnCredentialError, TurnCredentialTransport,
};

/// One authenticated device session with a host.
pub struct DeviceSession {
    /// The callout-authenticated NATS connection. Kept for later helper requests (TURN
    /// credentials, self-revocation) on the same session identity.
    pub nats: async_nats::Client,
    /// The mutually fingerprint-pinned QUIC control stream.
    pub control: ControlStream,
    /// The host's current member capability from its answer, when present.
    pub member_cap: Option<Capability>,
    pub device_fp: Fingerprint,
    pub host: HostIdentity,
}

/// Inputs for one device connect attempt.
pub struct DeviceSessionParams<'a> {
    pub nats_url: &'a str,
    /// This device's identity key. Consumed: the signaling client owns it for the session.
    pub device: DeviceKey,
    /// The host-issued certificate for `device`.
    pub device_cert: &'a DeviceCertificate,
    /// This device's **identity root** public key — the `root_pk` field of the device envelope.
    /// The helper derives `root_fp` from it and requires every presented capability's subject to
    /// match. It is not the host's key.
    pub device_root_pk: &'a [u8; 32],
    /// Capabilities to present. Encoded once into the CONNECT token.
    pub caps: &'a [Capability],
    pub host: HostIdentity,
    pub connect: ConnectOptions,
    /// Unix seconds for the session attestation.
    pub now: u64,
    /// When true, fetch a helper-minted TURN credential over this session and overwrite
    /// `connect.ice.turn` (STUN list and punch window are preserved). A refusal or an unusable URI
    /// fails the session; the caller decides whether to retry without TURN.
    pub use_helper_turn: bool,
}

/// Why a device session could not be established. `Display` omits NATS and signaling internals.
#[derive(Debug, thiserror::Error)]
pub enum DeviceSessionError {
    #[error("the supplied device certificate is not this device's certificate")]
    CertificateMismatch,
    #[error("could not mint or read the session nkey")]
    Nkey(#[source] nkeys::error::Error),
    #[error("the NATS connection was refused or unreachable")]
    Nats(#[source] async_nats::ConnectError),
    #[error("signaling failed")]
    Signaling(#[from] SignalingError),
    #[error("TURN credential request failed")]
    Turn(#[from] TurnCredentialError),
    #[error(
        "local clock is {behind_by_seconds}s behind the signed op-cert lower bound (A10.42);          refusing to mint a SessionAttestation that cannot be accepted"
    )]
    ClockProvablyBehind {
        behind_by_seconds: i64,
        bound_ts: u64,
    },
    #[error("a held capability's embedded op cert could not be decoded for the clock check")]
    ClockDiagnostics(#[source] ClockDiagnosticError),
}

/// The helper credential transport over this session's authenticated NATS connection.
struct NatsTurnTransport {
    nats: async_nats::Client,
}

impl TurnCredentialTransport for NatsTurnTransport {
    async fn request(&self, subject: &str, payload: Vec<u8>) -> Result<Vec<u8>, TransportError> {
        let reply = self
            .nats
            .request(subject.to_string(), payload.into())
            .await
            .map_err(|error| Box::new(error) as TransportError)?;
        Ok(reply.payload.to_vec())
    }
}

/// Connects this device to `host` through the real Auth Callout and opens the host session.
pub async fn connect_device(
    params: DeviceSessionParams<'_>,
) -> Result<DeviceSession, DeviceSessionError> {
    let DeviceSessionParams {
        nats_url,
        device,
        device_cert,
        device_root_pk,
        caps,
        host,
        connect,
        now,
        use_helper_turn,
    } = params;

    let device_fp = device.device_fp();
    if device_cert.device_fp.as_slice() != device_fp.as_bytes() {
        return Err(DeviceSessionError::CertificateMismatch);
    }

    // A10.42 leg (1): before minting, prove the local clock is not behind a signed lower bound
    // already carried by the held bundle. This is a diagnostic, never an input to validity; a
    // provably-behind clock makes the attestation's `ts` unacceptable to the host's ±2 min window,
    // so refusing here is the honest failure. The ambiguous (all caps expired) case still
    // proceeds — a connect-only cap refresh is legitimate.
    match diagnose_clock_from_capabilities(now, caps, &[])
        .map_err(DeviceSessionError::ClockDiagnostics)?
    {
        ClockDiagnosis::ProvablyBehind {
            behind_by,
            bound_ts,
        } => {
            return Err(DeviceSessionError::ClockProvablyBehind {
                behind_by_seconds: behind_by.diagnostic_seconds(),
                bound_ts,
            })
        }
        ClockDiagnosis::Ambiguous { .. } | ClockDiagnosis::NoEvidenceOfSkew => {}
    }

    let session = nkeys::KeyPair::new_user();
    let (_prefix, raw_nkey) =
        nkeys::from_public_key(&session.public_key()).map_err(DeviceSessionError::Nkey)?;
    let nats_fp = Fingerprint::of_parts(&[&raw_nkey]);
    let attestation = issue_session_attestation(&device, nats_fp, now);
    let cap_bytes: Vec<Vec<u8>> = caps.iter().map(Capability::to_canonical_bytes).collect();
    let envelope = encode_device_auth_token(
        device_root_pk,
        &device_cert.to_canonical_bytes(),
        &attestation.to_canonical_bytes(),
        &cap_bytes,
    );
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope);

    let nats = async_nats::ConnectOptions::new()
        .nkey(session.seed().map_err(DeviceSessionError::Nkey)?)
        .token(token)
        .custom_inbox_prefix(format!("_INBOX_{device_fp}"))
        .connect(nats_url)
        .await
        .map_err(DeviceSessionError::Nats)?;

    let mut connect = connect;
    if use_helper_turn {
        let transport = NatsTurnTransport { nats: nats.clone() };
        connect.ice = fetch_turn_ice_config(
            &transport,
            &nats_fp.to_string(),
            connect.ice.punch_window,
            connect.ice.stun_servers.clone(),
        )
        .await?;
    }

    let signaling = SignalingClient::new(nats.clone(), device);
    let (control, member_cap) = signaling.connect_with_cap(&host, connect).await?;
    Ok(DeviceSession {
        nats,
        control,
        member_cap,
        device_fp,
        host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::{issue_device_certificate, issue_host_op_key_cert};
    use spindle_core::identity::RootKey;
    use spindle_core::SigningKey;
    fn params_for<'a>(
        device: DeviceKey,
        cert: &'a DeviceCertificate,
        root_pk: &'a [u8; 32],
    ) -> DeviceSessionParams<'a> {
        DeviceSessionParams {
            nats_url: "nats://127.0.0.1:4222",
            device,
            device_cert: cert,
            device_root_pk: root_pk,
            caps: &[],
            host: HostIdentity {
                host_fp: Fingerprint::of_parts(&[b"host"]),
                device_fp: Fingerprint::of_parts(&[b"host-device"]),
                sign_pk: SigningKey::from_bytes(&[0x11; 32]).verifying_key(),
                agree_pk: x25519_dalek::PublicKey::from([0x12; 32]),
            },
            connect: ConnectOptions::default(),
            now: 1_755_907_200,
            use_helper_turn: false,
        }
    }

    /// Rejects a certificate for another device before any network work.
    #[tokio::test]
    async fn a_certificate_for_another_device_is_refused() {
        let root = RootKey::from_seed([0x01; 32]);
        let device = DeviceKey::from_seeds([0x02; 32], [0x03; 32]);
        let other = DeviceKey::from_seeds([0x04; 32], [0x05; 32]);
        let cert = issue_device_certificate(
            &root,
            other.alg_id(),
            &other.sign_public_key(),
            &other.agree_public_key(),
            0,
            2_000_000,
        );
        let root_pk = root.public_key().to_bytes();
        let error = match connect_device(params_for(device, &cert, &root_pk)).await {
            Ok(_) => panic!("a foreign certificate must be refused"),
            Err(error) => error,
        };
        assert!(matches!(error, DeviceSessionError::CertificateMismatch));
    }

    /// The session token is the production encoder's bytes, and the attestation's subject is the
    /// session nkey, not the device fingerprint. The token itself never leaves the function; this
    /// test pins the two derivations it depends on.
    #[test]
    fn the_certificate_binding_and_attestation_domain_are_distinct() {
        let root = RootKey::from_seed([0x01; 32]);
        let device = DeviceKey::from_seeds([0x02; 32], [0x03; 32]);
        let cert = issue_device_certificate(
            &root,
            device.alg_id(),
            &device.sign_public_key(),
            &device.agree_public_key(),
            0,
            2_000_000,
        );
        let _op = issue_host_op_key_cert(
            &root,
            &SigningKey::from_bytes(&[0x06; 32]).verifying_key(),
            0,
            2_000_000,
        );
        assert_eq!(cert.device_fp.as_slice(), device.device_fp().as_bytes());
        let attest = issue_session_attestation(&device, Fingerprint::of_parts(&[b"nats"]), 7);
        assert_eq!(attest.nats_fp.len(), 32);
        assert_eq!(attest.sig_device.len(), 64);
    }

    /// A10.42 leg (1) negative test: a local clock provably behind the signed op-cert lower bound
    /// refuses before any network attempt (the URL here is unreachable; a network error would
    /// prove the ordering wrong).
    #[tokio::test]
    async fn a_provably_behind_clock_refuses_before_connecting() {
        use spindle_core::artifacts::{issue_capability, issue_host_op_key_cert};
        use spindle_proto::artifacts::CapKind;

        let now = 1_755_907_200u64;
        let root = RootKey::from_seed([0x21; 32]);
        let device = DeviceKey::from_seeds([0x22; 32], [0x23; 32]);
        let cert = issue_device_certificate(
            &root,
            device.alg_id(),
            &device.sign_public_key(),
            &device.agree_public_key(),
            now,
            now + 86_400,
        );
        let op_signing = SigningKey::from_bytes(&[0x24; 32]);
        // Issued an hour in the future: local `now` is provably behind this signed bound.
        let op_cert = issue_host_op_key_cert(
            &root,
            &op_signing.verifying_key(),
            now + 3_600,
            now + 86_400,
        );
        let cap = issue_capability(
            &root.public_key(),
            &op_cert,
            &op_signing,
            CapKind::Member,
            root.root_fp(),
            0,
            now + 7_200,
            vec![0x25; 32],
        );
        let root_pk = root.public_key().to_bytes();
        let mut params = params_for(device, &cert, &root_pk);
        params.caps = std::slice::from_ref(&cap);
        params.nats_url = "nats://127.0.0.1:1";

        let error = match connect_device(params).await {
            Ok(_) => panic!("a provably-behind clock must refuse"),
            Err(error) => error,
        };
        assert!(
            matches!(error, DeviceSessionError::ClockProvablyBehind { .. }),
            "expected the clock check to run before NATS, got {error:?}"
        );
    }
}
