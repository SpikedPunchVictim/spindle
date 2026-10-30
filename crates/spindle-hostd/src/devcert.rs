//! The host's `HostDeviceCert` mint and publish path (DESIGN.md §A5/§A5b, decisions A10.35 and
//! A10.37): every host connect republishes its envelope identity to `registry.devcert.<host_fp>`,
//! where the broker helper caches it for out-of-band distribution.
//!
//! # Cadence: every host connect, and every reconnect [A10.37]
//!
//! A10.37 is explicit that the host publishes on `registry.devcert.<hfp>` **on every connect to
//! the registry**, not only when it has rotated a key. The reason is structural: a client's first
//! `host.<hfp>.connect` message is an A7 envelope sealed to the host's agreement key, so the client
//! must already hold the host's device certificate *before* it can address the host at all. The
//! certificate therefore cannot be fetched in band, and an offline host can supply nothing. The
//! helper's cached copy is the only path a long-enrolled member has to a host that has rotated its
//! device key. Republishing unconditionally is cheap and removes every "did we remember to publish
//! after that restart?" failure mode.
//!
//! The cadence lives in [`crate::connect::connect_host`], not in the binary: that function mints
//! the certificate before connecting, keeps its canonical bytes, publishes once after a successful
//! connect, and republishes **the same cached bytes** on every later [`async_nats::Event::Connected`]
//! (async-nats has no separate reconnected variant — a reconnect emits `Connected` again). The
//! cached bytes are reused within one connection because `ts` is part of the signed preimage: a
//! mid-connection re-mint would change it even though the keys do not. A **new connection** (a
//! caller-supervised reconnect) calls `connect_host` with a fresh `now` and therefore re-mints the
//! certificate with a fresh `ts` — same keys, same `device_fp`, same `exp`, different bytes — and
//! its explicit publish replaces the helper's cached copy. A library consumer that calls
//! `connect_host` gets the cadence for free.
//!
//! # Why a fresh certificate replaces the cached one on every restart [A10.44]
//!
//! The envelope [`DeviceKey`](spindle_core::identity::DeviceKey) is ephemeral: A10.44 makes it
//! fresh per process, so `device_fp` changes at every start. The certificate minted here embeds
//! that process's `sign_pk`/`agree_pk`, so a restart *must* replace the helper's cached copy or
//! clients would keep sealing offers to a key that no longer exists. The helper's store is
//! last-write-wins (see `spindle_helper::devcert`'s module docs), which makes the unconditional
//! republish both necessary and sufficient — no epoch or freshness rule is needed on either side.
//! The op key is ephemeral per process too (A10.43), and the op certificate embedded in the host
//! device certificate is the one [`crate::HostIdentity`] minted for this process.
//!
//! # Why a plain `publish`, with no ack [§A5]
//!
//! DESIGN.md §A5's subject table lists `registry.devcert.<hfp>` as **publish-only**: it has no
//! reply, so there is nothing to request and no broker ack to wait for.
//! [`async_nats::Client::publish`] reflects that: its `Result` is a **local** outcome — the message
//! was queued to the client's connection task and was not over `max_payload` — not proof that a
//! subscriber received it. A connection-level failure (a permission violation, a dropped
//! connection) surfaces later through the client's event callback/close, never through this
//! `Result`. This function is therefore fire-and-forget by construction, and its success only
//! means "handed to the client".
//!
//! # Why a publish failure keeps the connection from serving
//!
//! [`crate::connect::connect_host`] publishes before it returns the client, and it propagates a
//! local publish or flush failure as [`crate::connect::ConnectError`]. The headless binary only
//! builds and runs a `HostDaemon` — the thing that accepts connects — after `connect_host`
//! succeeds, so a client can never reach the host on a connection whose certificate was not at
//! least handed to the server. Such an attempt is logged and retried with a fresh credential (see
//! `src/main.rs`'s reconnect loop); it is never served on. The ordering is the point: otherwise the
//! very first connect after a restart can fail against the previous process's certificate. A
//! library consumer gets the same guarantee as an `Err` from `connect_host` and decides for itself.
//!
//! `publish` alone is queued, not delivered, which is why the connect path follows it with
//! [`async_nats::Client::flush`]: a flush completes only once the server has accepted everything
//! written so far on that connection. That still does not order the host's publish against the
//! helper's *ingest* on a different connection, so a client fetch immediately afterwards may need
//! a bounded retry — the live test does exactly that. A failure that is only observable
//! server-side (a permission violation, say) cannot be seen through either call; it surfaces
//! through the connection event callback or a later close.

use spindle_core::artifacts::{issue_host_device_cert, HostOpKeyCert};
use spindle_core::{DeviceKey, Fingerprint, SigningKey, VerifyingKey};
use spindle_proto::artifacts::HostDeviceCert;

use crate::HostIdentity;

/// The `registry.devcert.` subject prefix; `<hfp>` follows it as the final subject token (the
/// same shape `spindle_helper::devcert` uses for ingestion).
pub const DEVICE_CERT_SUBJECT_PREFIX: &str = "registry.devcert.";

/// Everything [`publish_device_cert`] can fail with.
///
/// `async_nats::PublishError`'s `Display` carries a fixed kind (`max payload size exceeded` /
/// `failed to send message`) plus a source description of lengths or a closed queue — never the
/// payload bytes, so it is safe to log under this crate's redaction policy. The flush error is
/// stringified for the same reason: its type is not re-exported by async-nats 0.35, and its
/// `Display` is the same kind of static text.
#[derive(Debug, thiserror::Error)]
pub enum DevCertPublishError {
    /// The NATS client refused the publish locally (the payload exceeded `max_payload`, or the
    /// client's command queue was closed). See this module's "Why a plain `publish`" section: this
    /// is a local error, not a broker acknowledgement.
    #[error("publishing the host device certificate failed: {0}")]
    Publish(#[from] async_nats::PublishError),

    /// The follow-up flush failed, so delivery to the server could not be confirmed.
    #[error("flushing the host device certificate publish failed: {0}")]
    Flush(String),
}

/// Mints this process's [`HostDeviceCert`] at `now`.
///
/// The certificate is signed by the host **operating** key and chains root → op → device
/// (A10.35): [`issue_host_device_cert`] derives `host_device_fp` from the envelope keys and signs
/// the whole content with `identity.op_signing`.
///
/// Its `exp` is deliberately `identity.op_cert.exp`, not `now + TTL`: the certificate's chain is
/// only valid while the embedded op certificate is, so copying that `exp` makes it impossible for
/// the device certificate to outlive the op cert that signs it. For an identity straight out of
/// [`crate::mint_host_identity`] this is the same instant as `now + HOST_OP_CERT_TTL_SECS`
/// (A7b/A10.45), but deriving it from the op cert keeps the invariant when the two are minted at
/// different times — which is exactly what A10.45's renewal does: it renews only the op cert,
/// and the device certificate re-minted on the following connect inherits the new `exp`.
pub fn mint_device_cert(identity: &HostIdentity, now: u64) -> HostDeviceCert {
    mint_device_cert_from_parts(
        &identity.op_signing,
        identity.host_fp,
        &identity.root.public_key(),
        &identity.op_cert,
        &identity.device,
        now,
    )
}

/// [`mint_device_cert`] over the individual pieces of a [`HostIdentity`], for callers that hold
/// them as a borrowed [`crate::connect::HostConnectCredentials`] rather than as a whole identity.
///
/// The certificate depends only on these six values; `mint_device_cert` delegates here so there
/// is exactly one construction site.
pub(crate) fn mint_device_cert_from_parts(
    op_signing: &SigningKey,
    host_fp: Fingerprint,
    host_root_pk: &VerifyingKey,
    op_cert: &HostOpKeyCert,
    device: &DeviceKey,
    now: u64,
) -> HostDeviceCert {
    issue_host_device_cert(
        op_signing,
        host_fp,
        host_root_pk,
        op_cert,
        device.alg_id(),
        &device.sign_public_key(),
        &device.agree_public_key(),
        now,
        op_cert.exp,
    )
}

/// The one subject this host publishes its certificate on: `registry.devcert.<hfp>`, where the
/// `<hfp>` token is the base32 `Display` of the host's own root fingerprint. The callout grants a
/// host `pub registry.devcert.<own>` only (`spindle_helper::permissions::host_permissions`), so
/// this is the sole subject a well-behaved host can use.
pub fn device_cert_subject(identity: &HostIdentity) -> String {
    device_cert_subject_for(identity.host_fp)
}

/// [`device_cert_subject`] from the root fingerprint alone, for callers holding a borrowed
/// [`crate::connect::HostConnectCredentials`] instead of a whole [`HostIdentity`].
pub(crate) fn device_cert_subject_for(host_fp: Fingerprint) -> String {
    format!("{DEVICE_CERT_SUBJECT_PREFIX}{host_fp}")
}

/// Mints and publishes this process's [`HostDeviceCert`] to `registry.devcert.<host_fp>`, then
/// flushes to confirm the server accepted the write.
///
/// This is a one-shot helper. The production cadence lives in [`crate::connect::connect_host`],
/// which caches the canonical bytes so a reconnect republishes the same certificate rather than
/// re-minting it. See this module's "Why a plain `publish`" section for exactly what the calls can
/// and cannot observe: the payload is the certificate's canonical CBOR encoding, which is what the
/// helper decodes and stores verbatim.
pub async fn publish_device_cert(
    client: &async_nats::Client,
    identity: &HostIdentity,
    now: u64,
) -> Result<(), DevCertPublishError> {
    let cert = mint_device_cert(identity, now);
    client
        .publish(
            device_cert_subject(identity),
            cert.to_canonical_bytes().into(),
        )
        .await?;
    client
        .flush()
        .await
        .map_err(|error| DevCertPublishError::Flush(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mint_host_identity, HOST_OP_CERT_TTL_SECS, ROOT_SEED_LEN};
    use spindle_core::artifacts::verify_host_device_cert;

    const NOW: u64 = 1_700_000_000;

    fn identity() -> HostIdentity {
        mint_host_identity([0x6a; ROOT_SEED_LEN], NOW)
    }

    #[test]
    fn minted_certificate_verifies_and_embeds_this_process_envelope_identity() {
        let identity = identity();

        let cert = mint_device_cert(&identity, NOW);

        verify_host_device_cert(&cert, &identity.host_fp, NOW)
            .expect("a freshly minted host device certificate must verify at its issue time");

        assert_eq!(
            cert.op_cert,
            identity.op_cert.to_canonical_bytes(),
            "the certificate must embed this process's op cert bytes verbatim"
        );
        assert_eq!(
            cert.sign_pk,
            identity.device.sign_public_key().as_bytes().to_vec(),
            "sign_pk must be this process's envelope signing key"
        );
        assert_eq!(
            cert.agree_pk,
            identity.device.agree_public_key().as_bytes().to_vec(),
            "agree_pk must be this process's envelope agreement key"
        );
        assert_eq!(
            cert.host_device_fp,
            identity.device_fp.to_vec(),
            "host_device_fp must be this process's envelope fingerprint"
        );
        assert_eq!(cert.ts, NOW);
        assert_eq!(
            cert.exp, identity.op_cert.exp,
            "the device certificate must expire with the op certificate that signs it, not \
             outlive it"
        );
        assert_eq!(cert.exp, NOW + HOST_OP_CERT_TTL_SECS);
    }

    #[test]
    fn the_subject_is_the_hosts_own_base32_fingerprint_under_the_registry_prefix() {
        let identity = identity();
        assert_eq!(
            device_cert_subject(&identity),
            format!("registry.devcert.{}", identity.host_fp)
        );
    }
}
