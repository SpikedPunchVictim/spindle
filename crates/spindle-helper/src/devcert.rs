//! `registry.devcert.<hfp>` ingestion + `helper.devcert.get.<nfp>` fetch — the broker helper's
//! durable `HostDeviceCert` distribution cache (DESIGN.md §A5/§A5b, decision A10.37).
//!
//! A host mints a `HostDeviceCert` (`spindle_core::artifacts::issue_host_device_cert`), publishes
//! it on its own `registry.devcert.<own_host_fp>` subject on **every** registry connect (A10.37),
//! and [`ingest_device_cert`] stores the bytes via [`HelperView::record_device_cert`]. A client
//! that needs a host's §A7 envelope identity *before* it can address that host — the first
//! `host.<hfp>.connect` message is sealed to the host's agreement key, so the certificate cannot
//! be fetched in band — asks this helper on `helper.devcert.get.<nfp>`, and
//! [`handle_devcert_get`] serves it only when the named host is in the caller's own session
//! record. Follows `revoke.rs`/`turn.rs`/`presence.rs`'s shape closely: pure/NATS-free, no
//! `async-nats` type appears anywhere in this module's API — `src/bin/helper.rs` is the only
//! caller that ever touches an actual subscription.
//!
//! # Identity check on ingest: subject token == cert `host_fp`, NOT a signature check [deliberate]
//! DESIGN.md §A5's subject table states the admission rule for `registry.devcert.<hfp>` verbatim:
//! "helper asserts subject token == the cert's `host_fp`". [`ingest_device_cert`] implements
//! exactly that comparison and nothing more — it never calls
//! `spindle_core::artifacts::verify_host_device_cert`, even though that verifier now exists and
//! could walk the root → op → device chain entirely from the certificate's own embedded fields
//! (`host_root_pk`, `op_cert`), and even though session records have retained `root_pk` for
//! member connections since v0.9.47. **A stricter check is possible today but was not selected.**
//! Three reasons, in order of weight:
//!
//! 1. **§A10.37 makes this helper an untrusted carrier by construction.** The certificate must
//!    reach the peer over a self-verifying chain, "never by trusting the carrier", so the client
//!    verifies it to its pinned root and a bad certificate served from here fails there. Verifying
//!    on ingest would grant the registry a trust role DESIGN.md deliberately withholds — and would
//!    make this helper the authority on which certificates are valid, a job its own comment in
//!    §A10.37 says it must not have.
//! 2. **A verifier here would impose this helper's clock and `exp` policy on every client.** The
//!    certificate carries `ts`/`exp`; a helper that rejects on its own `now` can silently drop a
//!    genuinely minted certificate around a rotation or under clock skew, removing the only
//!    out-of-band distribution path the client has. The client — which holds the pinned root and
//!    the session context — is the correct place for that policy.
//! 3. **The specified rule is the only one this helper needs to prevent cross-host writes.** NATS
//!    itself scopes the subject: the callout grants a host connection `pub
//!    registry.devcert.<own_host_fp>` only (`permissions::host_permissions`), so a message that
//!    reaches this handler already arrived on a subject NATS enforced. The equality check closes
//!    the remaining gap — a host publishing a certificate that names a *different* `host_fp` on
//!    its own scoped subject — exactly as `revoke.rs`'s identical check does for
//!    `registry.revoke.<hfp>`.
//!
//! # Last write wins [deliberate]
//! [`HelperView::record_device_cert`] replaces the stored bytes unconditionally. There is no epoch,
//! replay, or freshness rule here and none is wanted: the host republishes on every registry
//! connect, and its `device_fp` changes on every restart (A4 / A10.43 decision 44), so the only
//! sensible meaning of the cache is "the certificate this host most recently published". A
//! first-wins store would strand every client on the first process lifetime's certificate; a
//! history would grow without bound for a value nothing reads retroactively. The certificate's own
//! `ts`/`exp` fields, checked by the consuming client, are the freshness signal — not this store's
//! arrival order.
//!
//! # Fetch identity: the subject token, never the payload [mirrors turn.rs]
//! `helper.devcert.get.<nfp>` is parametrized by the caller's **session nkey** `<nfp>`, exactly
//! like `helper.turn.get.<nfp>` (v0.9.7/A12 #45) and `helper.presence.get.<nfp>` (v0.9.8). The
//! callout only grants a member connection `pub helper.devcert.get.<own_nats_fp>`
//! (`permissions::client_member_permissions`), so the subject a request arrives on is the one
//! identity fact about the caller that cannot have been forged; [`handle_devcert_get`] takes the
//! subject as a parameter, parses `<nfp>` from it, and authorizes from the session record keyed by
//! that fingerprint. The request body names only a **target host**, never the caller.
//!
//! The body's `host_fp` is checked against the session record's `host_fps`. A host the caller
//! holds no capability for and a host the caller does hold but for which this helper has cached no
//! certificate produce the **same** reply, byte for byte (`"no device certificate available"`), so
//! this subject cannot be used to enumerate hosts: the caller learns nothing about a host it could
//! not already address. An unparseable `host_fp` is treated as "not held" for the same reason — it
//! cannot name a real host, and answering differently would still be an oracle on parsing, not on
//! state.
//!
//! # Wire schema
//! ```text
//! subject: registry.devcert.<hfp>   (hfp = base32 Display of the publishing host's own host_fp;
//!                                    the callout grants a host `pub registry.devcert.<own>` only,
//!                                    see permissions::host_permissions)
//! payload: canonical CBOR encoding of a spindle_proto::artifacts::HostDeviceCert
//!          (`{host_fp, host_root_pk, op_cert, host_device_fp, alg_id, sign_pk, agree_pk, ts,
//!          exp, sig_host_op}`, A10.35/A10.37), decoded via
//!          HostDeviceCert::from_canonical_bytes — strict decoding: that type's `from_cbor`
//!          calls `MapReader::deny_unknown_fields`, so an unrecognized field is a decode error,
//!          not silently ignored. The accepted bytes are stored verbatim.
//! reply:   none. This subject is publish-only (DESIGN.md §A5's subject table lists no reply for
//!          it), so `ingest_device_cert` returns an outcome for `src/bin/helper.rs` to log, never
//!          a payload to publish back.
//!
//! subject: helper.devcert.get.<nfp>  (nfp = base32 Display of the caller's session-nkey
//!                                     fingerprint — same encoding/parsing rules as every other
//!                                     `<...fp>` subject token; see permissions.rs's module doc)
//! request: {"host_fp":"<base32 Display of the target host_fp>"}   (unknown fields ignored, same
//!          serde-default tolerance as turn.rs's request type)
//! reply ok: {"cert":"<base64url (URL_SAFE_NO_PAD) of the stored canonical CBOR bytes>"}
//! reply err: {"error":"<human-readable reason>"} — one of:
//!   - "malformed subject"              the subject token is not a Fingerprint
//!   - "no live session for this caller"  no session record for the subject's <nfp>
//!   - "malformed request"              the body is not the JSON object above
//!   - "no device certificate available"  UNIFORM: the target is not in the caller's session
//!                                        host_fps, OR this helper has no cached certificate for
//!                                        it. These two cases are byte-identical on the wire.
//! ```
//! `base64url (no padding)` is the same encoding `auth_token.rs` uses for a canonical-CBOR wire
//! value; the client decodes it straight back into `HostDeviceCert::from_canonical_bytes`.
//!
//! # Out of scope (DESIGN.md items this module deliberately does not implement)
//! **Per-host token bucket rate limiting.** DESIGN.md §A5's subject-table row for
//! `registry.devcert.<hfp>` specifies one explicitly ("per-host token bucket"), and §A5b repeats
//! it while recording the subject as unimplemented. This crate has no rate limiter of any kind
//! today — no token-bucket type, no `ratelimit` module anywhere under `crates/spindle-helper`
//! (grep confirms it). The obvious graduation candidate is
//! `crates/spindle-host-core/src/ratelimit.rs`, which already implements one for a different
//! crate, but porting or sharing it across crates is undone work, not something to silently
//! assume is unnecessary. Flagged here rather than omitted without comment: every certificate on a
//! well-formed, correctly-scoped subject is accepted and stored today, with no limit whatsoever on
//! how often a host may publish them.
//!
//! **Signature/chain verification on ingest** — see the "Identity check" section above; not a gap,
//! a documented non-goal for this helper-side check.

use base64::Engine;
use serde::{Deserialize, Serialize};
use spindle_core::Fingerprint;
use spindle_proto::artifacts::HostDeviceCert;

use crate::authz::HelperView;

/// The `registry.devcert.` subject prefix; `<hfp>` follows it as the final subject token (same
/// shape as `revoke.rs`'s `registry.revoke.` prefix).
const INGEST_SUBJECT_PREFIX: &str = "registry.devcert.";

/// The `helper.devcert.get.` subject prefix; `<nfp>` follows it as the final subject token (same
/// shape as `turn.rs`'s `helper.turn.get.` / `presence.rs`'s `helper.presence.get.` prefixes).
const FETCH_SUBJECT_PREFIX: &str = "helper.devcert.get.";

/// The reply for a caller with no live session record. Distinct from the target-host error below
/// because it is a fact about the *caller*, not about any host: a connected caller already knows
/// whether it has a session, and this answer reveals nothing about anyone else's.
const NO_LIVE_SESSION_ERROR: &str = "no live session for this caller";

/// The **uniform** reply for "the named host is not in your session" and "this helper has no
/// certificate for that host". Byte-identical on purpose — see the module doc's "Fetch identity"
/// section: distinguishing them would let a caller probe which hosts the helper holds
/// certificates for, including hosts it holds no capability for.
const NO_CERT_ERROR: &str = "no device certificate available";

/// Why an incoming `registry.devcert.<hfp>` message was refused. **Internal use only** (logging,
/// this module's own test suite) — there is no reply on this subject to put a message on at all
/// (see the module doc's wire schema), so unlike `authz::RefusalReason` this never needs a
/// uniform-wire concern; each variant's `Display` is exactly what `src/bin/helper.rs` should log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DevCertRejection {
    #[error("malformed subject")]
    MalformedSubject,
    #[error("payload did not decode as a HostDeviceCert")]
    UndecodablePayload,
    #[error("cert host_fp does not match the publishing subject's own host_fp")]
    HostFpMismatch,
}

/// The result of [`ingest_device_cert`]: either the certificate was accepted and durably stored,
/// or it was refused for one specific, distinguishable reason (see [`DevCertRejection`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevCertIngestOutcome {
    /// Accepted and written via [`HelperView::record_device_cert`]. `cert_len` is the payload
    /// length in bytes, reported for the caller's log line; the bytes themselves are never logged.
    Accepted {
        host_fp: Fingerprint,
        cert_len: usize,
    },
    Rejected(DevCertRejection),
}

/// The fetch request body. Only `host_fp` is read; the caller's identity comes from the subject
/// (see the module doc). Deliberately *not* `#[serde(deny_unknown_fields)]`: an unrecognized field
/// is ignored, matching `turn.rs`'s request type and serde's default struct behavior, so a client
/// that adds a field later does not start failing against an older helper.
#[derive(Debug, Deserialize)]
struct DevCertGetRequest {
    host_fp: String,
}

/// The fetch reply. Mirrors `TurnGetReply`/`PresenceGetReply`'s "one struct, optional fields"
/// convention: exactly one of `cert`/`error` is present, and the absent one is skipped rather
/// than serialized as `null`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevCertGetReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DevCertGetReply {
    fn err(message: impl Into<String>) -> Self {
        Self {
            cert: None,
            error: Some(message.into()),
        }
    }

    fn ok(cert: String) -> Self {
        Self {
            cert: Some(cert),
            error: None,
        }
    }
}

/// Decodes and admits one `registry.devcert.<hfp>` publish: durably stores the certificate via
/// `view` if, and only if, the payload decodes as a [`HostDeviceCert`] whose `host_fp` field
/// equals the subject token's `<hfp>` (see the module doc's "Identity check" section for why that
/// equality — not a signature check — is the whole of this admission rule). Pure with respect to
/// NATS — `src/bin/helper.rs` is the only caller that touches an actual subscription; there is no
/// reply to publish back (see the module doc's wire schema), so this returns an outcome for
/// logging, not payload bytes.
pub fn ingest_device_cert(
    subject: &str,
    payload: &[u8],
    view: &mut impl HelperView,
) -> DevCertIngestOutcome {
    let Some(subject_host_fp) = crate::parse_fp_after_prefix(subject, INGEST_SUBJECT_PREFIX) else {
        return DevCertIngestOutcome::Rejected(DevCertRejection::MalformedSubject);
    };

    let Ok(cert) = HostDeviceCert::from_canonical_bytes(payload) else {
        return DevCertIngestOutcome::Rejected(DevCertRejection::UndecodablePayload);
    };

    let Ok(cert_host_fp) = Fingerprint::from_slice(&cert.host_fp) else {
        return DevCertIngestOutcome::Rejected(DevCertRejection::UndecodablePayload);
    };

    // The security-load-bearing check (see the module doc's "Identity check" section): the
    // certificate is trusted as *this host's* only because NATS itself only ever let this
    // subject's publisher reach `registry.devcert.<subject_host_fp>`. A certificate whose own
    // `host_fp` names a different host is refused outright, before anything is written.
    if cert_host_fp != subject_host_fp {
        return DevCertIngestOutcome::Rejected(DevCertRejection::HostFpMismatch);
    }

    // Stored verbatim: the client re-verifies exactly the bytes the host signed, not a
    // re-encoding this helper produced. Last write wins — see the module doc.
    view.record_device_cert(cert_host_fp, payload.to_vec());

    DevCertIngestOutcome::Accepted {
        host_fp: cert_host_fp,
        cert_len: payload.len(),
    }
}

/// Parses the caller's `nats_fp` out of a `helper.devcert.get.<nfp>` subject, via the shared
/// [`crate::parse_fp_after_prefix`] helper every `<...fp>` subject parser in this crate uses.
fn parse_subject_nats_fp(subject: &str) -> Option<Fingerprint> {
    crate::parse_fp_after_prefix(subject, FETCH_SUBJECT_PREFIX)
}

/// Decodes and authorizes one `helper.devcert.get.<nfp>` request, returning the JSON reply payload
/// to publish back. Pure with respect to NATS — takes the subject the request arrived on, the raw
/// request payload bytes, the current time, and the store; `src/bin/helper.rs` is the only caller
/// that touches an actual NATS connection (and it re-checks `msg.reply` before publishing, because
/// NATS authorizes the PUB subject and not the reply field — see that file's module doc).
///
/// Caller identity comes from `subject` alone (the callout-granted permission already proved this
/// connection owns that `nats_fp` — see the module doc); `payload` names only a target host.
pub fn handle_devcert_get(
    subject: &str,
    payload: &[u8],
    now: u64,
    view: &mut impl HelperView,
) -> String {
    let reply = handle_devcert_get_inner(subject, payload, now, view);
    serde_json::to_string(&reply).expect("DevCertGetReply always serializes")
}

fn handle_devcert_get_inner(
    subject: &str,
    payload: &[u8],
    now: u64,
    view: &mut impl HelperView,
) -> DevCertGetReply {
    let Some(nats_fp) = parse_subject_nats_fp(subject) else {
        return DevCertGetReply::err("malformed subject");
    };

    // Identity first: without a live session record for the subject token there is no caller to
    // authorize, and parsing the body first would let a sessionless caller distinguish request
    // shapes without ever naming itself.
    let Some(session) = view.session_record(&nats_fp, now) else {
        return DevCertGetReply::err(NO_LIVE_SESSION_ERROR);
    };

    // The body is required (unlike `helper.turn.get.<nfp>`, whose request carries no field):
    // this subject's whole purpose is to name a host.
    let Ok(request) = serde_json::from_slice::<DevCertGetRequest>(payload) else {
        return DevCertGetReply::err("malformed request");
    };

    // A token that does not decode as a Fingerprint cannot name a host in `host_fps`, so it is
    // answered by the same uniform error as a host the caller does not hold — never a distinct
    // "bad fingerprint" response (see the module doc's "Fetch identity" section).
    let Ok(host_fp) = request.host_fp.parse::<Fingerprint>() else {
        return DevCertGetReply::err(NO_CERT_ERROR);
    };

    // The enumeration guard: serve only what the caller's own session record already names. This
    // check must happen *before* the store lookup, so a host outside the session is never even
    // consulted — its presence or absence in the cache cannot leak through timing or wording.
    if !session.host_fps.contains(&host_fp) {
        return DevCertGetReply::err(NO_CERT_ERROR);
    }

    let Some(cert) = view.device_cert(&host_fp) else {
        return DevCertGetReply::err(NO_CERT_ERROR);
    };

    DevCertGetReply::ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cert))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::AdmissionMode;
    use crate::memory_store::InMemoryHelperView;
    use crate::session::SessionRecord;
    use spindle_core::SigningKey;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    fn store() -> InMemoryHelperView {
        InMemoryHelperView::new(
            AdmissionMode::Open,
            SigningKey::from_bytes(&[0x88; 32]).verifying_key(),
        )
    }

    fn ingest_subject_for(host_fp: &Fingerprint) -> String {
        format!("registry.devcert.{host_fp}")
    }

    fn fetch_subject_for(nats_fp: &Fingerprint) -> String {
        format!("helper.devcert.get.{nats_fp}")
    }

    /// Builds a structurally canonical `HostDeviceCert`. This module never verifies the
    /// signature or the key material (see the module doc), so fabricated key bytes are enough to
    /// produce a well-formed, decodable certificate; only `host_fp` is load-bearing here. The
    /// client-side tests below decode the same bytes back and compare the whole struct.
    fn cert_for(host_fp: Fingerprint) -> HostDeviceCert {
        HostDeviceCert {
            host_fp: host_fp.to_vec(),
            host_root_pk: vec![0x11; 32],
            op_cert: vec![0x22; 8],
            host_device_fp: vec![0x33; 32],
            alg_id: 1,
            sign_pk: vec![0x44; 32],
            agree_pk: vec![0x55; 32],
            ts: 1_000,
            exp: 2_000,
            sig_host_op: vec![0x66; 64],
        }
    }

    fn cert_bytes_for(host_fp: Fingerprint) -> Vec<u8> {
        cert_for(host_fp).to_canonical_bytes()
    }

    fn put_session(
        view: &mut InMemoryHelperView,
        nats_fp: Fingerprint,
        hosts: Vec<Fingerprint>,
        exp: u64,
    ) {
        view.put_session_record(SessionRecord::new(
            nats_fp,
            fp(b"root"),
            Some([0x99; 32]),
            Some(fp(b"device")),
            hosts,
            "member".to_string(),
            exp,
        ));
    }

    fn parse_reply(reply: &str) -> DevCertGetReply {
        serde_json::from_str(reply).expect("handler always emits JSON")
    }

    // ---- ingest_device_cert: happy path -----------------------------------------------------

    #[test]
    fn well_formed_cert_on_matching_subject_is_stored_verbatim() {
        let mut s = store();
        let host_fp = fp(b"host-a");
        let bytes = cert_bytes_for(host_fp);

        let outcome = ingest_device_cert(&ingest_subject_for(&host_fp), &bytes, &mut s);

        assert_eq!(
            outcome,
            DevCertIngestOutcome::Accepted {
                host_fp,
                cert_len: bytes.len(),
            }
        );
        assert_eq!(
            s.device_cert(&host_fp),
            Some(bytes),
            "the exact published bytes must be stored, not a re-encoding"
        );
    }

    // ---- ingest_device_cert: the isolating negative test ------------------------------------

    #[test]
    fn host_fp_mismatch_is_rejected_and_stores_nothing() {
        let mut s = store();
        let subject_host_fp = fp(b"subject-token-host");
        let cert_host_fp = fp(b"a-totally-different-host");
        let bytes = cert_bytes_for(cert_host_fp);

        let outcome = ingest_device_cert(&ingest_subject_for(&subject_host_fp), &bytes, &mut s);

        assert_eq!(
            outcome,
            DevCertIngestOutcome::Rejected(DevCertRejection::HostFpMismatch),
            "a certificate claiming a different host_fp than the subject token must be refused"
        );
        assert_eq!(
            s.device_cert(&subject_host_fp),
            None,
            "nothing must be stored under the subject's own host_fp"
        );
        assert_eq!(
            s.device_cert(&cert_host_fp),
            None,
            "nothing must be stored under the certificate's claimed host_fp either"
        );
    }

    // ---- ingest_device_cert: malformed subject ----------------------------------------------

    #[test]
    fn malformed_subject_is_rejected() {
        let mut s = store();
        let bytes = cert_bytes_for(fp(b"whatever-host"));

        assert_eq!(
            ingest_device_cert("registry.devcert.", &bytes, &mut s),
            DevCertIngestOutcome::Rejected(DevCertRejection::MalformedSubject),
            "empty token after the prefix must be refused"
        );
        assert_eq!(
            ingest_device_cert("registry.devcert.not-a-fingerprint!!", &bytes, &mut s),
            DevCertIngestOutcome::Rejected(DevCertRejection::MalformedSubject),
            "a token that doesn't decode as a Fingerprint must be refused"
        );
        assert_eq!(
            ingest_device_cert("registry.devcert", &bytes, &mut s),
            DevCertIngestOutcome::Rejected(DevCertRejection::MalformedSubject),
            "missing the trailing <hfp> token entirely must be refused"
        );
        assert_eq!(
            ingest_device_cert(&format!("registry.revoke.{}", fp(b"x")), &bytes, &mut s),
            DevCertIngestOutcome::Rejected(DevCertRejection::MalformedSubject),
            "a sibling registry subject must not be accepted here"
        );
    }

    // ---- ingest_device_cert: undecodable payload --------------------------------------------

    #[test]
    fn undecodable_payload_is_rejected() {
        let mut s = store();
        let host_fp = fp(b"host-with-garbage-payload");

        let outcome = ingest_device_cert(&ingest_subject_for(&host_fp), b"not cbor at all", &mut s);

        assert_eq!(
            outcome,
            DevCertIngestOutcome::Rejected(DevCertRejection::UndecodablePayload)
        );
        assert_eq!(s.device_cert(&host_fp), None);
    }

    // ---- ingest_device_cert: last write wins ------------------------------------------------

    #[test]
    fn a_second_ingest_replaces_the_stored_bytes() {
        let mut s = store();
        let host_fp = fp(b"host-republish");
        let first = cert_bytes_for(host_fp);
        // A genuinely different, still-valid certificate: same host, different device key.
        let mut second_cert = cert_for(host_fp);
        second_cert.host_device_fp = vec![0x77; 32];
        second_cert.sign_pk = vec![0x78; 32];
        second_cert.agree_pk = vec![0x79; 32];
        second_cert.ts = 1_500;
        let second = second_cert.to_canonical_bytes();
        assert_ne!(first, second);

        let first_outcome = ingest_device_cert(&ingest_subject_for(&host_fp), &first, &mut s);
        assert!(matches!(
            first_outcome,
            DevCertIngestOutcome::Accepted { .. }
        ));
        assert_eq!(s.device_cert(&host_fp), Some(first));

        let second_outcome = ingest_device_cert(&ingest_subject_for(&host_fp), &second, &mut s);
        assert!(matches!(
            second_outcome,
            DevCertIngestOutcome::Accepted { .. }
        ));
        assert_eq!(
            s.device_cert(&host_fp),
            Some(second),
            "a republish must replace the previously stored certificate"
        );
    }

    // ---- parse_subject_nats_fp --------------------------------------------------------------

    #[test]
    fn fetch_parse_subject_round_trips_a_fingerprint() {
        let nats_fp = fp(b"nats-parse-round-trip");
        assert_eq!(
            parse_subject_nats_fp(&fetch_subject_for(&nats_fp)),
            Some(nats_fp)
        );
    }

    #[test]
    fn fetch_parse_subject_rejects_wrong_prefix_or_bad_token() {
        let nats_fp = fp(b"nats-wrong-prefix");
        assert_eq!(parse_subject_nats_fp("helper.devcert.get"), None);
        assert_eq!(parse_subject_nats_fp("helper.devcert.get."), None);
        assert_eq!(
            parse_subject_nats_fp(&format!("helper.turn.get.{nats_fp}")),
            None
        );
        assert_eq!(
            parse_subject_nats_fp("helper.devcert.get.not-a-fingerprint!!"),
            None
        );
    }

    // ---- handle_devcert_get: success --------------------------------------------------------

    #[test]
    fn serves_the_cert_when_the_named_host_is_in_the_callers_session() {
        let mut s = store();
        let nats_fp = fp(b"nats-caller");
        let host_fp = fp(b"host-held");
        let bytes = cert_bytes_for(host_fp);
        s.record_device_cert(host_fp, bytes.clone());
        put_session(&mut s, nats_fp, vec![host_fp], 10_000);

        let body = serde_json::to_vec(&serde_json::json!({ "host_fp": host_fp.to_string() }))
            .expect("request serializes");
        let reply = handle_devcert_get(&fetch_subject_for(&nats_fp), &body, 1_000, &mut s);
        let parsed = parse_reply(&reply);
        assert!(parsed.error.is_none(), "expected a certificate: {reply}");
        let encoded = parsed.cert.expect("cert present");

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("reply cert is base64url");
        assert_eq!(
            decoded, bytes,
            "the served bytes must be the stored canonical CBOR, verbatim"
        );
        assert_eq!(
            HostDeviceCert::from_canonical_bytes(&decoded).expect("decodes"),
            cert_for(host_fp),
            "the client must be able to decode back to the same HostDeviceCert"
        );
    }

    #[test]
    fn cert_for_a_host_the_caller_holds_is_served_even_when_other_hosts_are_cached() {
        let mut s = store();
        let nats_fp = fp(b"nats-caller-multi");
        let held = fp(b"host-held-multi");
        let other = fp(b"host-not-held-multi");
        s.record_device_cert(held, cert_bytes_for(held));
        s.record_device_cert(other, cert_bytes_for(other));
        put_session(&mut s, nats_fp, vec![held], 10_000);

        let body = serde_json::to_vec(&serde_json::json!({ "host_fp": held.to_string() })).unwrap();
        let reply = handle_devcert_get(&fetch_subject_for(&nats_fp), &body, 1_000, &mut s);
        assert!(
            parse_reply(&reply).cert.is_some(),
            "held host must be served"
        );
    }

    // ---- handle_devcert_get: uniform refusal / non-enumeration ------------------------------

    #[test]
    fn host_outside_the_session_gets_the_same_reply_as_a_host_with_no_cached_cert() {
        let mut s = store();
        let nats_fp = fp(b"nats-caller-uniform");
        let held_but_uncertified = fp(b"host-held-no-cert");
        let not_held_but_certified = fp(b"host-not-held-with-cert");
        s.record_device_cert(
            not_held_but_certified,
            cert_bytes_for(not_held_but_certified),
        );
        put_session(&mut s, nats_fp, vec![held_but_uncertified], 10_000);

        let body_for = |host: &Fingerprint| {
            serde_json::to_vec(&serde_json::json!({ "host_fp": host.to_string() })).unwrap()
        };

        // In the session, but the helper has never seen its certificate.
        let no_cert_reply = handle_devcert_get(
            &fetch_subject_for(&nats_fp),
            &body_for(&held_but_uncertified),
            1_000,
            &mut s,
        );
        // Not in the session at all — the helper *does* hold a certificate for it.
        let not_held_reply = handle_devcert_get(
            &fetch_subject_for(&nats_fp),
            &body_for(&not_held_but_certified),
            1_000,
            &mut s,
        );

        assert_eq!(
            no_cert_reply, not_held_reply,
            "the two cases must be byte-identical: any difference is an enumeration oracle"
        );
        assert_eq!(
            parse_reply(&no_cert_reply).error.as_deref(),
            Some(NO_CERT_ERROR)
        );
    }

    #[test]
    fn no_live_session_is_refused_with_its_own_message() {
        let mut s = store();
        let nats_fp = fp(b"nats-no-session");
        let body =
            serde_json::to_vec(&serde_json::json!({ "host_fp": fp(b"h").to_string() })).unwrap();
        let reply = handle_devcert_get(&fetch_subject_for(&nats_fp), &body, 1_000, &mut s);
        assert_eq!(
            parse_reply(&reply).error.as_deref(),
            Some("no live session for this caller")
        );
    }

    #[test]
    fn expired_session_is_treated_as_no_session() {
        let mut s = store();
        let nats_fp = fp(b"nats-expired");
        put_session(&mut s, nats_fp, vec![fp(b"host-expired")], 500);
        let body =
            serde_json::to_vec(&serde_json::json!({ "host_fp": fp(b"host-expired").to_string() }))
                .unwrap();
        let reply = handle_devcert_get(&fetch_subject_for(&nats_fp), &body, 1_000, &mut s);
        assert_eq!(
            parse_reply(&reply).error.as_deref(),
            Some("no live session for this caller")
        );
    }

    #[test]
    fn an_unparseable_host_fp_gets_the_uniform_no_cert_reply() {
        let mut s = store();
        let nats_fp = fp(b"nats-bad-host-token");
        put_session(&mut s, nats_fp, vec![fp(b"host-real")], 10_000);
        let body =
            serde_json::to_vec(&serde_json::json!({ "host_fp": "not-a-fingerprint!!" })).unwrap();
        let reply = handle_devcert_get(&fetch_subject_for(&nats_fp), &body, 1_000, &mut s);
        assert_eq!(
            parse_reply(&reply).error.as_deref(),
            Some(NO_CERT_ERROR),
            "a bad host token must not get a distinguishable reply"
        );
    }

    #[test]
    fn malformed_request_body_is_refused() {
        let mut s = store();
        let nats_fp = fp(b"nats-malformed-body");
        put_session(&mut s, nats_fp, vec![fp(b"host-x")], 10_000);
        let bodies: [&[u8]; 4] = [b"", b"not json", b"{}", br#"{"host_fp":42}"#];
        for body in bodies {
            let reply = handle_devcert_get(&fetch_subject_for(&nats_fp), body, 1_000, &mut s);
            assert_eq!(
                parse_reply(&reply).error.as_deref(),
                Some("malformed request"),
                "body {body:?} must be refused"
            );
        }
    }

    #[test]
    fn malformed_subject_is_refused() {
        let mut s = store();
        let body =
            serde_json::to_vec(&serde_json::json!({ "host_fp": fp(b"h").to_string() })).unwrap();
        for subject in [
            "helper.devcert.get",
            "helper.devcert.get.",
            "helper.devcert.get.not-a-fingerprint",
        ] {
            let reply = handle_devcert_get(subject, &body, 1_000, &mut s);
            assert_eq!(
                parse_reply(&reply).error.as_deref(),
                Some("malformed subject"),
                "subject {subject} must be refused"
            );
        }
    }

    #[test]
    fn unknown_request_fields_are_ignored() {
        let mut s = store();
        let nats_fp = fp(b"nats-unknown-fields");
        let host_fp = fp(b"host-unknown-fields");
        s.record_device_cert(host_fp, cert_bytes_for(host_fp));
        put_session(&mut s, nats_fp, vec![host_fp], 10_000);
        let body = serde_json::to_vec(&serde_json::json!({
            "host_fp": host_fp.to_string(),
            "nfp": fp(b"attacker-claims-this-in-body").to_string(),
        }))
        .unwrap();
        let reply = handle_devcert_get(&fetch_subject_for(&nats_fp), &body, 1_000, &mut s);
        assert!(
            parse_reply(&reply).cert.is_some(),
            "an unknown field must not break the request: {reply}"
        );
    }
}
