//! Production invite issuance (DESIGN.md §A4's `invite` bullet and decision A10.46; §A7b's
//! `spindle-invite-v1` container): signs the `invite`-kind capability and assembles the
//! [`InvitePayload`] container that [`spindle_proto::invite`] carries. This module is the host-side
//! twin of that crate's bytes-only codec: the container's shape and caps live there, the signing
//! keys, clock, and nonce live here.
//!
//! [`InviteIssuer`] deliberately mirrors [`crate::authorize::RootKeyCapIssuer`]'s shape — the same
//! root → operating-key chain through `issue_capability`, the same chainable consuming-self
//! setters — so the two kinds of capability this host mints differ only in the fields DESIGN.md
//! says they differ in. What is **not** shared is the nonce, and that split is load-bearing.
//!
//! # The nonce is a fresh CSPRNG draw, not the member-cap derivation [security-bearing]
//!
//! DESIGN.md §A7b's signed-artifact replay table gives an invite cap the rule "nonce burn
//! (idempotent replay of result)", and §A4's `invite` bullet makes the **host** the enforcer: on
//! redemption it stores `nonce → {member_id, issued_cap}` and either replays or refuses by that
//! key. A predictable nonce would turn that table into something an attacker can target — guess
//! the next invite nonce and you can collide with, or force, someone else's redemption slot — so
//! this issuer draws 32 bytes from [`rand::rngs::OsRng`] on every call.
//!
//! `crate::authorize::default_member_cap_nonce` must **not** be reused here. It is deterministic
//! on purpose, and its doc comment states why: the replay table says a member cap's nonce is
//! "n/a", so deriving it from `(subject, now)` costs nothing and buys nothing. Reusing that
//! construction for invites would give two invites for the same subject in the same wall-clock
//! second the same nonce — precisely the value the burn table keys on — and would silently couple
//! an invite's replay resistance to the member cap's deliberate lack of it. The two sources are
//! separate functions rather than one parameterized by kind.
//!
//! # Addressed, not bearer (A10.46)
//!
//! `subject` is the invitee's **identity root fingerprint**, learned out of band before the invite
//! is minted; §A4's "stolen invite is inert without that person's root private key" rule then
//! applies with no special case. This API accepts a [`Fingerprint`] and nothing looser — there is
//! no way to ask for an unaddressed invite — and callers must pass the invitee's `root_fp`, never
//! a device fp, so every root-certified device of that person can redeem it.
//!
//! # Validated before return
//!
//! [`InvitePayload::validate`] runs on the assembled container before it is returned. The producer
//! is the last point at which a bad endpoint list or pin is still the caller's own bug with the
//! caller's context to fix it; after that it is a link every recipient's client rejects. Because
//! that method is also what [`InvitePayload::from_cbor`] calls after decoding, a produced payload
//! and a decoded one are held to one set of rules, not two.
//!
//! # Time
//!
//! [`InviteIssuer::new`] uses the real wall clock via `crate::authorize::wall_clock_now_secs`
//! (widened to `pub(crate)` for this second caller rather than copied, so the two issuers cannot
//! drift into different units; that function's five-byte-CBOR-band test covers this path too) and
//! [`INVITE_DEFAULT_TTL_SECS`] (§A4: invite `exp` is in **hours**, "default 24 h,
//! owner-adjustable"). Chain [`InviteIssuer::with_now_fn`], [`InviteIssuer::with_nonce_fn`],
//! and/or [`InviteIssuer::with_ttl_secs`] to inject a seam; production code should leave all three
//! at their defaults.
//!
//! # No production caller yet
//!
//! Nothing in this workspace calls [`InviteIssuer`] today: the host admin surface is its intended
//! caller, and this slice lands the producer only (td-bbb933 AC 3). The type is production code —
//! its constructor, default nonce source, and clock are the real ones — but wiring it to an admin
//! command is a separate step.

use crate::authorize::wall_clock_now_secs;
use rand::rngs::OsRng;
use rand::RngCore;
use spindle_core::artifacts::issue_capability;
use spindle_core::{Fingerprint, SigningKey, VerifyingKey};
use spindle_proto::artifacts::{CapKind, HostOpKeyCert};
use spindle_proto::invite::{InvitePayload, InviteWireError, TlsPin, INVITE_CURRENT_V};

/// An invite capability's default lifetime: DESIGN.md §A4's invite bullet — `exp` in hours,
/// "default 24 h, owner-adjustable". `24 * 60 * 60 == 86_400` seconds.
pub const INVITE_DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// The nonce width [`InviteIssuer`] draws. 32 bytes matches the capability's other opaque
/// 32-byte fields and is what [`spindle_proto::invite::MEASURED_INVITE_BYTES`] is measured with;
/// the burn table treats the nonce as an opaque key, so any fixed 256-bit value would do.
///
/// Public so a caller writing an injected nonce can name the width, but **type-enforced**:
/// [`InviteIssuer::with_nonce_fn`] accepts only `Fn() -> [u8; INVITE_NONCE_LEN]`, so a narrower
/// or wider nonce cannot be expressed rather than merely being discouraged. That matters because
/// the measured-size test exercises the production nonce only: an injected 16-byte nonce would
/// mint a smaller container that no test measures.
pub const INVITE_NONCE_LEN: usize = 32;

/// The default `nonce_fn` [`InviteIssuer::new`] installs: a fresh [`OsRng`] draw per call. See the
/// module doc comment's "The nonce is a fresh CSPRNG draw" section for why this is not
/// `crate::authorize::default_member_cap_nonce`.
fn fresh_invite_nonce() -> [u8; INVITE_NONCE_LEN] {
    let mut nonce = [0u8; INVITE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

type BoxedNowFn = Box<dyn Fn() -> u64 + Send + Sync + 'static>;
type BoxedNonceFn = Box<dyn Fn() -> [u8; INVITE_NONCE_LEN] + Send + Sync + 'static>;

/// The production invite issuer: mints `invite`-kind capabilities chained to this host's root
/// identity and wraps each in the `spindle-invite-v1` container (DESIGN.md §A4/§A7b, A10.46).
///
/// The issuer holds no redemption state. Single-use is enforced by the host's burn table at
/// redemption time (§A4: "nonce burned on redemption; the helper cannot enforce single-use"), so
/// minting here is stateless and a crash between mint and delivery only costs the caller a
/// reissue.
pub struct InviteIssuer {
    host_root_pk: VerifyingKey,
    op_cert: HostOpKeyCert,
    op_signing: SigningKey,
    now_fn: BoxedNowFn,
    nonce_fn: BoxedNonceFn,
    ttl_secs: u64,
}

impl InviteIssuer {
    /// Builds an issuer using the real wall clock (`crate::authorize::wall_clock_now_secs`), a
    /// fresh [`OsRng`]-drawn 32-byte nonce per call (`fresh_invite_nonce`), and
    /// [`INVITE_DEFAULT_TTL_SECS`]. Chain [`Self::with_now_fn`], [`Self::with_nonce_fn`], and/or
    /// [`Self::with_ttl_secs`] to replace any subset; the setters are independent so a test can
    /// pin, say, both the clock and the TTL without giving up the production nonce — the same
    /// reasoning [`crate::authorize::RootKeyCapIssuer::new`]'s doc comment gives for its setters.
    pub fn new(host_root_pk: VerifyingKey, op_cert: HostOpKeyCert, op_signing: SigningKey) -> Self {
        InviteIssuer {
            host_root_pk,
            op_cert,
            op_signing,
            now_fn: Box::new(wall_clock_now_secs),
            nonce_fn: Box::new(fresh_invite_nonce),
            ttl_secs: INVITE_DEFAULT_TTL_SECS,
        }
    }

    /// As [`Self::new`] built it, but with an explicit `now_fn` — a deterministic clock for tests.
    /// Chainable with [`Self::with_nonce_fn`] and [`Self::with_ttl_secs`].
    pub fn with_now_fn(self, now_fn: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        InviteIssuer {
            now_fn: Box::new(now_fn),
            ..self
        }
    }

    /// As [`Self::new`] built it, but with an explicit `nonce_fn`.
    ///
    /// The closure returns a fixed-size `[u8; INVITE_NONCE_LEN]`, so a replacement cannot change
    /// the nonce's width — only its bytes. **`InviteIssuer::new`'s nonce is security-bearing** —
    /// see the module doc comment before reaching for this. A replacement that is not
    /// CSPRNG-sourced and per-call-fresh weakens the §A7b nonce-burn rule; the legitimate uses are
    /// tests that need a fixed value (a deterministic size check, a replay of the same container),
    /// not production. Chainable with [`Self::with_now_fn`] and [`Self::with_ttl_secs`].
    pub fn with_nonce_fn(
        self,
        nonce_fn: impl Fn() -> [u8; INVITE_NONCE_LEN] + Send + Sync + 'static,
    ) -> Self {
        InviteIssuer {
            nonce_fn: Box::new(nonce_fn),
            ..self
        }
    }

    /// As [`Self::new`] built it, but with an explicit `ttl_secs` instead of
    /// [`INVITE_DEFAULT_TTL_SECS`]. Chainable with [`Self::with_now_fn`] and
    /// [`Self::with_nonce_fn`].
    pub fn with_ttl_secs(self, ttl_secs: u64) -> Self {
        InviteIssuer { ttl_secs, ..self }
    }

    /// Issues an invite container for `subject` at `cap_epoch`, with `exp = now + ttl_secs`.
    ///
    /// `subject` is the invitee's `root_fp` (A10.46 addressed invites — never a device fp).
    /// `endpoints` and `tls_pin` are the transport hints the recipient needs; the assembled
    /// container is validated before it is returned, so a caller cannot mint a payload its own
    /// decoder would reject. Errors are [`InviteWireError`] from that validation only.
    ///
    /// Signing itself is infallible, but this method does not check its inputs' validity: the
    /// caller must supply an `op_cert` that is unexpired at mint time and that certifies
    /// `op_signing`. A mismatched or expired pair still produces a signed capability, but one no
    /// recipient will accept (`verify_capability` re-checks the chain and the op cert's own
    /// `exp`). Provisioning and rotating that pair is the caller's responsibility.
    pub fn issue_invite(
        &self,
        subject: Fingerprint,
        cap_epoch: u64,
        endpoints: Vec<String>,
        tls_pin: TlsPin,
    ) -> Result<InvitePayload, InviteWireError> {
        let now = (self.now_fn)();
        let exp = now + self.ttl_secs;
        let nonce = (self.nonce_fn)().to_vec();

        let cap = issue_capability(
            &self.host_root_pk,
            &self.op_cert,
            &self.op_signing,
            CapKind::Invite,
            subject,
            cap_epoch,
            exp,
            nonce,
        );

        let payload = InvitePayload {
            v: INVITE_CURRENT_V,
            cap,
            endpoints,
            tls_pin,
        };
        payload.validate()?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::{issue_host_op_key_cert, verify_capability};
    use spindle_core::identity::RootKey;
    use spindle_proto::bootstrap::QR_V40_L_CAPACITY_BYTES;
    use spindle_proto::invite::{
        MAX_ENDPOINTS, MAX_ENDPOINT_LEN, MAX_TLS_PIN_LEN, MEASURED_INVITE_BYTES,
    };

    /// The measurement timestamp every fixture uses: a 5-byte CBOR uint, the band the workspace's
    /// measured figures assume (see `authorize.rs`'s `wall_clock_now_secs` band test).
    const NOW: u64 = 1_755_907_200;

    /// A production [`InviteIssuer`] — built by [`InviteIssuer::new`], so the nonce stays at
    /// `fresh_invite_nonce` — with only the wall clock pinned. Mirrors `authorize.rs`'s
    /// `realistic_cap_issuer`: the embedded `HostOpKeyCert` carries realistic Unix-second
    /// timestamps, because CBOR encodes integers in their shortest form and the measured size
    /// depends on those widths (a placeholder `u64::MAX / 2` would encode wider).
    fn realistic_invite_issuer(now: u64) -> InviteIssuer {
        const NINETY_DAYS: u64 = 90 * 86_400;
        let root = RootKey::from_seed([0x90; 32]);
        let op_signing = SigningKey::from_bytes(&[0x91; 32]);
        let op_cert =
            issue_host_op_key_cert(&root, &op_signing.verifying_key(), now, now + NINETY_DAYS);
        InviteIssuer::new(root.public_key(), op_cert, op_signing).with_now_fn(move || now)
    }

    fn baseline_endpoints() -> Vec<String> {
        vec![
            "wss://registry.example:443".to_string(),
            "tls://registry.example:4222".to_string(),
        ]
    }

    /// The exact baseline whose size [`MEASURED_INVITE_BYTES`] names.
    fn baseline_invite(issuer: &InviteIssuer) -> InvitePayload {
        issuer
            .issue_invite(
                Fingerprint::of_parts(&[b"invite-measure-subject"]),
                7,
                baseline_endpoints(),
                TlsPin::WebPki,
            )
            .expect("issue_invite")
    }

    // ---- the measurement ----------------------------------------------------------------------

    /// Pins [`MEASURED_INVITE_BYTES`] end to end through [`InviteIssuer`], the production
    /// constructor — not through a helper or a hand-built fixture. A fixture's size would pin the
    /// fixture; this goes red for a rewired nonce length, a drifted capability field, or any
    /// change to the container's own encoding. The clock is the only injected seam, so the
    /// measured path is otherwise the real one.
    #[test]
    fn production_issuer_mints_invites_at_exactly_measured_invite_bytes() {
        let payload = baseline_invite(&realistic_invite_issuer(NOW));
        let cbor = payload.to_canonical_bytes();
        let text = payload.to_base64url();

        assert_eq!(
            cbor.len(),
            MEASURED_INVITE_BYTES,
            "the PRODUCTION invite issuer encoded a baseline invite to {} B, but \
             MEASURED_INVITE_BYTES is {} B. That constant is the container's published size \
             basis; if this delta is genuine, re-measure the constant (and any DESIGN.md figure \
             built on it) together. Cap nonce length is {} B (expected 32)",
            cbor.len(),
            MEASURED_INVITE_BYTES,
            payload.cap.nonce.len()
        );
        assert!(
            text.len() < QR_V40_L_CAPACITY_BYTES,
            "a baseline invite must fit a version-40 level-L QR: {} B base64url >= {} B capacity",
            text.len(),
            QR_V40_L_CAPACITY_BYTES
        );
        assert_eq!(
            payload.cap.nonce.len(),
            32,
            "the production issuer's nonce must be exactly 32 bytes"
        );
        assert_eq!(
            InvitePayload::from_canonical_bytes(&cbor).expect("decode the measured bytes"),
            payload,
            "the measured bytes must round-trip"
        );
    }

    // ---- defaults -----------------------------------------------------------------------------

    /// A literal, not [`INVITE_DEFAULT_TTL_SECS`]: a test written against the named constant
    /// would leave the number itself free to change.
    #[test]
    fn invite_default_ttl_is_exactly_86_400_seconds() {
        assert_eq!(INVITE_DEFAULT_TTL_SECS, 86_400);
    }

    #[test]
    fn the_default_ttl_makes_exp_now_plus_86_400() {
        let payload = baseline_invite(&realistic_invite_issuer(NOW));
        assert_eq!(payload.cap.exp, NOW + 86_400);
    }

    /// `with_ttl_secs` is otherwise unexercised: wiring it back to the default constant would
    /// leave every other test green, so this pins the override end to end.
    #[test]
    fn with_ttl_secs_replaces_the_default() {
        let payload = realistic_invite_issuer(NOW)
            .with_ttl_secs(3_600)
            .issue_invite(
                Fingerprint::of_parts(&[b"invite-measure-subject"]),
                7,
                baseline_endpoints(),
                TlsPin::WebPki,
            )
            .expect("issue_invite");
        assert_eq!(payload.cap.exp, NOW + 3_600);
    }

    #[test]
    fn two_production_calls_get_different_nonces_of_32_bytes() {
        let issuer = realistic_invite_issuer(NOW);

        let first = baseline_invite(&issuer);
        let second = baseline_invite(&issuer);

        assert_eq!(first.cap.nonce.len(), 32);
        assert_eq!(second.cap.nonce.len(), 32);
        assert_ne!(
            first.cap.nonce, second.cap.nonce,
            "the production issuer must draw a fresh OsRng nonce on every call — a repeat is the \
             §A7b burn-table collision this nonce source exists to prevent"
        );
    }

    // ---- the minted capability ------------------------------------------------------------------

    #[test]
    fn the_issued_cap_is_an_addressed_invite_that_verifies_end_to_end() {
        let subject = Fingerprint::of_parts(&[b"invitee-root"]);
        let payload = realistic_invite_issuer(NOW)
            .issue_invite(subject, 7, baseline_endpoints(), TlsPin::WebPki)
            .expect("issue_invite");

        assert_eq!(payload.v, INVITE_CURRENT_V);
        assert_eq!(payload.cap.kind, CapKind::Invite);
        assert_eq!(payload.cap.subject, subject.to_vec());
        assert_eq!(payload.cap.cap_epoch, 7);
        assert_eq!(payload.cap.exp, NOW + INVITE_DEFAULT_TTL_SECS);

        // The full root -> operating key -> capability chain, checked by the production verifier.
        verify_capability(&payload.cap, NOW).expect("the issued capability must verify end to end");
    }

    // ---- validation of the assembled container -------------------------------------------------

    #[test]
    fn issue_invite_rejects_an_empty_endpoint_list() {
        let err = realistic_invite_issuer(NOW)
            .issue_invite(
                Fingerprint::of_parts(&[b"invitee"]),
                7,
                Vec::new(),
                TlsPin::WebPki,
            )
            .expect_err("must reject");
        assert_eq!(err, InviteWireError::NoEndpoints);
    }

    #[test]
    fn issue_invite_rejects_more_endpoints_than_the_container_cap() {
        let endpoints = (0..=MAX_ENDPOINTS).map(|i| format!("wss://h{i}")).collect();
        let err = realistic_invite_issuer(NOW)
            .issue_invite(
                Fingerprint::of_parts(&[b"invitee"]),
                7,
                endpoints,
                TlsPin::WebPki,
            )
            .expect_err("must reject");
        assert_eq!(
            err,
            InviteWireError::TooManyEndpoints {
                max: MAX_ENDPOINTS,
                actual: MAX_ENDPOINTS + 1,
            }
        );
    }

    /// The cap is **bytes**, not characters: 129 copies of `é` are 129 chars (under the
    /// 256-character reading) and 258 UTF-8 bytes (over the 256-byte cap). A char-count check
    /// would let this through on the producer side while the shared decoder still sees bytes.
    #[test]
    fn issue_invite_counts_endpoint_bytes_not_characters() {
        let endpoint = "é".repeat(129);
        assert_eq!(endpoint.chars().count(), 129);
        assert_eq!(endpoint.len(), 258);

        let err = realistic_invite_issuer(NOW)
            .issue_invite(
                Fingerprint::of_parts(&[b"invitee"]),
                7,
                vec![endpoint],
                TlsPin::WebPki,
            )
            .expect_err("must reject");
        assert_eq!(
            err,
            InviteWireError::EndpointTooLong {
                max: MAX_ENDPOINT_LEN,
                actual: 258,
            }
        );
    }

    #[test]
    fn issue_invite_rejects_a_private_ca_root_over_the_cap() {
        let err = realistic_invite_issuer(NOW)
            .issue_invite(
                Fingerprint::of_parts(&[b"invitee"]),
                7,
                baseline_endpoints(),
                TlsPin::PrivateCaRoot(vec![0xAA; MAX_TLS_PIN_LEN + 1]),
            )
            .expect_err("must reject");
        assert_eq!(
            err,
            InviteWireError::TlsPinTooLong {
                max: MAX_TLS_PIN_LEN,
                actual: MAX_TLS_PIN_LEN + 1,
            }
        );
    }

    #[test]
    fn issue_invite_rejects_an_empty_private_ca_root() {
        let err = realistic_invite_issuer(NOW)
            .issue_invite(
                Fingerprint::of_parts(&[b"invitee"]),
                7,
                baseline_endpoints(),
                TlsPin::PrivateCaRoot(Vec::new()),
            )
            .expect_err("must reject");
        assert_eq!(err, InviteWireError::EmptyPrivateCaRoot);
    }

    // ---- the injected seam ----------------------------------------------------------------------

    /// Injecting the nonce must change only the nonce's bytes: the payload still encodes,
    /// decodes back to itself, verifies end to end, and keeps the measured size (the injected
    /// value is the same 32-byte width the production draw uses). The decode round-trip is the
    /// real assertion here; calling `validate` on the just-issued payload would only repeat a
    /// check `issue_invite` already ran.
    #[test]
    fn an_injected_nonce_fn_still_produces_a_valid_payload() {
        let payload = realistic_invite_issuer(NOW)
            .with_nonce_fn(|| [0xCD; INVITE_NONCE_LEN])
            .issue_invite(
                Fingerprint::of_parts(&[b"invitee"]),
                3,
                baseline_endpoints(),
                TlsPin::WebPki,
            )
            .expect("issue_invite");

        assert_eq!(payload.cap.nonce, vec![0xCD; 32]);
        assert_eq!(
            InvitePayload::from_canonical_bytes(&payload.to_canonical_bytes())
                .expect("the injected-nonce payload must decode"),
            payload
        );
        verify_capability(&payload.cap, NOW).expect("still a full valid chain");
        assert_eq!(
            payload.to_canonical_bytes().len(),
            MEASURED_INVITE_BYTES,
            "a same-width injected nonce must not change the container size"
        );
    }
}
