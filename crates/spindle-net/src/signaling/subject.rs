//! NATS subject construction and parsing for DESIGN.md §A6's connect/signaling flow, matching the
//! exact shapes `spindle-helper::permissions` already grants (proved against the live composed
//! stack's real Auth Callout scoping by `spikes/s2-signaling`'s RESULTS.md, "Keep" section):
//!
//! - `host.<h>.connect` — the client's connect request (host subscribes, client publishes+awaits
//!   a reply).
//! - `host.<h>.sess.<c>.<sid>.c2h` / `.h2c` — per-session trickled ICE, client->host and
//!   host->client respectively (`<sid>` is the session id, lowercase-hex encoded).
//! - `_INBOX_<fp>.>` — a device's own reply-subject prefix (checked, not just constructed here —
//!   see [`reply_prefix_ok`]).

use spindle_core::Fingerprint;

/// Lowercase-hex encoding of a session id for use as a NATS subject token. `sid` is arbitrary
/// bytes (DESIGN.md §A6 does not fix its length; this crate's own callers mint 16-byte ids — see
/// `signaling::wire::fresh_sid`), and NATS subject tokens cannot safely carry raw bytes (`.`
/// terminates a token; NATS subjects are conventionally ASCII), so this is the wire encoding for
/// the sid when it appears in a subject (never for the sid carried inside the envelope itself,
/// which stays raw bytes — DESIGN.md §A7).
pub fn sid_token(sid: &[u8]) -> String {
    sid.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_sid_token(token: &str) -> Option<Vec<u8>> {
    if token.is_empty() || !token.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(token.len() / 2);
    let bytes = token.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        // Reject uppercase hex: `sid_token` only ever emits lowercase, and accepting a second,
        // non-canonical spelling of the same sid would let two subjects that decode to the same
        // bytes look different to a naive string comparison elsewhere.
        if !bytes[i].is_ascii_digit() && !bytes[i].is_ascii_lowercase() {
            return None;
        }
        if !bytes[i + 1].is_ascii_digit() && !bytes[i + 1].is_ascii_lowercase() {
            return None;
        }
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// The client's connect request subject (DESIGN.md §A6): host subscribes, client publishes and
/// awaits exactly one reply (the answer).
pub fn connect_subject(host_fp: &Fingerprint) -> String {
    format!("host.{host_fp}.connect")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceDirection {
    /// Client -> host trickled ICE (`.c2h`).
    ClientToHost,
    /// Host -> client trickled ICE (`.h2c`).
    HostToClient,
}

impl IceDirection {
    fn suffix(self) -> &'static str {
        match self {
            IceDirection::ClientToHost => "c2h",
            IceDirection::HostToClient => "h2c",
        }
    }
}

/// One session's trickled-ICE subject for `direction` (DESIGN.md §A6).
pub fn session_subject(
    host_fp: &Fingerprint,
    client_fp: &Fingerprint,
    sid: &[u8],
    direction: IceDirection,
) -> String {
    format!(
        "host.{host_fp}.sess.{client_fp}.{}.{}",
        sid_token(sid),
        direction.suffix()
    )
}

/// The host's single wildcard subscription covering every live session's client->host trickled
/// ICE traffic (`spindle-helper::permissions`' own `host.<h>.sess.*.*.h2c`-shaped publish-allow
/// precedent, mirrored here for the host's `c2h` subscribe side).
pub fn c2h_wildcard(host_fp: &Fingerprint) -> String {
    format!("host.{host_fp}.sess.*.*.c2h")
}

/// A NATS session subject's decomposed tokens, once parsed by [`parse_session_subject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSubject {
    pub host_fp: Fingerprint,
    pub client_fp: Fingerprint,
    pub sid: Vec<u8>,
    pub direction: IceDirection,
}

/// Parses `host.<h>.sess.<c>.<sid_hex>.<c2h|h2c>` back into its components. Used to enforce the
/// subject-level twin of DESIGN.md §A7's `sid`/`from_fp` binding checks: an envelope's own `sid`/
/// `from_fp` fields and the NATS subject it actually arrived on are two independent bindings
/// (nothing stops a sender from publishing a validly-sealed envelope for session A to session B's
/// subject), so a receiver must check both agree — see [`crate::signaling::error::SignalingError`]
/// ::`SubjectMismatch`'s doc comment.
pub fn parse_session_subject(subject: &str) -> Option<SessionSubject> {
    let mut parts = subject.split('.');
    let host_lit = parts.next()?;
    let host_fp_tok = parts.next()?;
    let sess_lit = parts.next()?;
    let client_fp_tok = parts.next()?;
    let sid_tok = parts.next()?;
    let dir_tok = parts.next()?;
    if parts.next().is_some() {
        return None; // trailing tokens -- not this shape
    }
    if host_lit != "host" || sess_lit != "sess" {
        return None;
    }
    let direction = match dir_tok {
        "c2h" => IceDirection::ClientToHost,
        "h2c" => IceDirection::HostToClient,
        _ => return None,
    };
    let host_fp: Fingerprint = host_fp_tok.parse().ok()?;
    let client_fp: Fingerprint = client_fp_tok.parse().ok()?;
    let sid = decode_sid_token(sid_tok)?;
    Some(SessionSubject {
        host_fp,
        client_fp,
        sid,
        direction,
    })
}

/// DESIGN.md §A6/§A7: NATS's own permission system does not verify a request's reply-to subject
/// actually belongs to its claimed sender — `spikes/s2-signaling`'s RESULTS.md (Check 2) proved
/// this empirically against the live composed stack (an offer with a reply subject that did not
/// match `_INBOX_<from_fp>.` was accepted by the server and delivered to the host like any other
/// request). The host MUST perform this check itself before trusting a decrypted offer's routing.
pub fn reply_prefix_ok(reply: Option<&str>, from_fp: &Fingerprint) -> bool {
    let expected_prefix = format!("_INBOX_{from_fp}.");
    reply.is_some_and(|r| r.starts_with(&expected_prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::identity::DeviceKey;

    fn fp(seed: u8) -> Fingerprint {
        DeviceKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32]).device_fp()
    }

    // ---- sid_token / decode_sid_token ----

    #[test]
    fn sid_token_round_trips() {
        let sid = vec![0x00, 0x01, 0xAB, 0xFF, 0x10];
        let token = sid_token(&sid);
        assert_eq!(token, "0001abff10");
        assert_eq!(decode_sid_token(&token), Some(sid));
    }

    #[test]
    fn sid_token_rejects_uppercase() {
        // sid_token itself only ever emits lowercase; a subject carrying uppercase hex must not
        // be accepted as an alternate spelling of the same sid.
        assert_eq!(decode_sid_token("00AB"), None);
    }

    #[test]
    fn sid_token_rejects_odd_length_and_empty() {
        assert_eq!(decode_sid_token("abc"), None);
        assert_eq!(decode_sid_token(""), None);
    }

    #[test]
    fn sid_token_rejects_non_hex_characters() {
        assert_eq!(decode_sid_token("zz01"), None);
    }

    // ---- subject construction ----

    #[test]
    fn connect_subject_shape() {
        let h = fp(1);
        assert_eq!(connect_subject(&h), format!("host.{h}.connect"));
    }

    #[test]
    fn session_subject_shape_both_directions() {
        let h = fp(1);
        let c = fp(2);
        let sid = vec![0xDE, 0xAD];
        assert_eq!(
            session_subject(&h, &c, &sid, IceDirection::ClientToHost),
            format!("host.{h}.sess.{c}.dead.c2h")
        );
        assert_eq!(
            session_subject(&h, &c, &sid, IceDirection::HostToClient),
            format!("host.{h}.sess.{c}.dead.h2c")
        );
    }

    #[test]
    fn c2h_wildcard_shape() {
        let h = fp(1);
        assert_eq!(c2h_wildcard(&h), format!("host.{h}.sess.*.*.c2h"));
    }

    // ---- parse_session_subject: round trip ----

    #[test]
    fn parse_round_trips_construction_both_directions() {
        let h = fp(3);
        let c = fp(4);
        let sid = vec![1, 2, 3, 4, 5, 6, 7, 8];
        for dir in [IceDirection::ClientToHost, IceDirection::HostToClient] {
            let subject = session_subject(&h, &c, &sid, dir);
            let parsed = parse_session_subject(&subject).expect("parses");
            assert_eq!(parsed.host_fp, h);
            assert_eq!(parsed.client_fp, c);
            assert_eq!(parsed.sid, sid);
            assert_eq!(parsed.direction, dir);
        }
    }

    // ---- parse_session_subject: negative cases ----

    #[test]
    fn parse_rejects_wrong_literal_tokens() {
        let h = fp(5);
        let c = fp(6);
        assert!(parse_session_subject(&format!("nothost.{h}.sess.{c}.ab.c2h")).is_none());
        assert!(parse_session_subject(&format!("host.{h}.notsess.{c}.ab.c2h")).is_none());
    }

    #[test]
    fn parse_rejects_unknown_direction() {
        let h = fp(5);
        let c = fp(6);
        assert!(parse_session_subject(&format!("host.{h}.sess.{c}.ab.sideways")).is_none());
    }

    #[test]
    fn parse_rejects_wrong_token_count() {
        let h = fp(5);
        let c = fp(6);
        // Too few tokens.
        assert!(parse_session_subject(&format!("host.{h}.sess.{c}.ab")).is_none());
        // Too many tokens.
        assert!(parse_session_subject(&format!("host.{h}.sess.{c}.ab.c2h.extra")).is_none());
    }

    #[test]
    fn parse_rejects_malformed_fingerprint_tokens() {
        let c = fp(6);
        assert!(parse_session_subject(&format!("host.not-base32!!.sess.{c}.ab.c2h")).is_none());
        let h = fp(5);
        assert!(parse_session_subject(&format!("host.{h}.sess.not-base32!!.ab.c2h")).is_none());
    }

    #[test]
    fn parse_rejects_malformed_sid_token() {
        let h = fp(5);
        let c = fp(6);
        assert!(parse_session_subject(&format!("host.{h}.sess.{c}.nothex!.c2h")).is_none());
        assert!(parse_session_subject(&format!("host.{h}.sess.{c}.abc.c2h")).is_none());
    }

    #[test]
    fn parse_does_not_match_the_hosts_own_wildcard_subscription_string() {
        // c2h_wildcard is a subscribe pattern (contains literal '*' tokens), never a concrete
        // subject a real envelope arrives on -- it must not parse as one.
        let h = fp(5);
        assert!(parse_session_subject(&c2h_wildcard(&h)).is_none());
    }

    // ---- reply_prefix_ok ----

    #[test]
    fn reply_prefix_ok_accepts_the_real_prefix() {
        let fp1 = fp(7);
        assert!(reply_prefix_ok(Some(&format!("_INBOX_{fp1}.abc123")), &fp1));
    }

    #[test]
    fn reply_prefix_ok_rejects_missing_reply() {
        let fp1 = fp(7);
        assert!(!reply_prefix_ok(None, &fp1));
    }

    #[test]
    fn reply_prefix_ok_rejects_a_different_devices_prefix() {
        let fp1 = fp(7);
        let fp2 = fp(8);
        assert!(!reply_prefix_ok(
            Some(&format!("_INBOX_{fp2}.abc123")),
            &fp1
        ));
    }

    #[test]
    fn reply_prefix_ok_rejects_extra_characters_spliced_before_the_dot() {
        // The exact bypass a naive `starts_with(&format!("_INBOX_{fp}"))` (missing the trailing
        // dot) would miss: text inserted between the real fingerprint and the required separator.
        let fp1 = fp(7);
        assert!(!reply_prefix_ok(
            Some(&format!("_INBOX_{fp1}evilstuff.abc123")),
            &fp1
        ));
    }

    #[test]
    fn reply_prefix_ok_rejects_the_prefix_appearing_mid_subject() {
        let fp1 = fp(7);
        assert!(!reply_prefix_ok(
            Some(&format!("prefix._INBOX_{fp1}.abc123")),
            &fp1
        ));
    }
}
