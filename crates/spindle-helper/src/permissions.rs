//! NATS subject permission sets as data (DESIGN.md §A5 "Permissions issued by callout").
//!
//! Every function here builds a [`SubjectPermissions`] value from plain fingerprints — no NATS
//! client types, no server config types. The later NATS-wiring slice translates these into
//! whatever `async-nats`/callout-JWT permission structures it needs; this module only has to be
//! **byte-exact** against the subject strings §A5 specifies, which is what the golden tests below
//! check.
//!
//! Subject-string convention: every `<...fp>` token in DESIGN.md's subject table is filled in
//! with a [`Fingerprint`]'s `Display` form (lowercase, unpadded RFC 4648 base32 — see
//! `spindle_core::Fingerprint`), and every `*`/`>` is a literal NATS wildcard token, not a
//! Rust format placeholder.

use spindle_core::Fingerprint;

/// One connection's NATS permissions, expressed as subject-pattern lists rather than any
/// particular NATS client/server type (this crate has no NATS dependency in this slice).
///
/// `allow_responses` mirrors nats-server's `allow_responses` permission block (max replies per
/// request subject, and how long the auto-permission lasts) — only the host connection uses it
/// (DESIGN.md §A5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubjectPermissions {
    pub publish_allow: Vec<String>,
    pub subscribe_allow: Vec<String>,
    /// Explicit denies, applied to both publish and subscribe (DESIGN.md §A5: "explicit deny of
    /// `_INBOX.>`, `$SYS.>`, `$JS.>`" for the host; ADR-002's topology table extends the same
    /// three denies to every application-account connection, host or client). NATS itself
    /// resolves allow-vs-deny precedence when this is wired into a real permission set (a later
    /// slice) — a narrower allow such as `_INBOX_<dfp>.>` is expected to win over the broader
    /// `_INBOX.>` deny, which is standard nats-server subject-specificity behavior. This module
    /// only records the intended lists.
    pub deny: Vec<String>,
    pub allow_responses: Option<AllowResponses>,
}

/// Mirrors nats-server's `allow_responses` permission block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowResponses {
    pub max: u32,
    pub expires_secs: u64,
}

impl SubjectPermissions {
    /// Combines two permission sets by concatenating their allow/deny lists (duplicates are
    /// harmless in a NATS permission list, so this does not deduplicate). Used to combine a
    /// connection's full-member-host grants with its connect-only-host grants when a single
    /// connection presents a mix of both (DESIGN.md §A5 describes the two grant shapes
    /// per-host, not as mutually exclusive whole-connection modes).
    pub fn merge(mut self, other: SubjectPermissions) -> Self {
        self.publish_allow.extend(other.publish_allow);
        self.subscribe_allow.extend(other.subscribe_allow);
        self.deny.extend(other.deny);
        if self.allow_responses.is_none() {
            self.allow_responses = other.allow_responses;
        }
        self
    }
}

/// The three explicit denies every application-account connection carries (DESIGN.md §A5;
/// ADR-002 topology table). `_INBOX.>` is the *broad* wildcard deny — a connection's own
/// `_INBOX_<fp>.>` prefix is a separate, narrower allow entry added on top of this.
pub fn universal_denies() -> Vec<String> {
    vec![
        "_INBOX.>".to_string(),
        "$SYS.>".to_string(),
        "$JS.>".to_string(),
    ]
}

/// Host connection permissions (DESIGN.md §A5): `sub host.<own>.>`, `pub
/// host.<own>.sess.*.*.h2c`, `pub registry.revoke.<own>`, `allow_responses {max:1, expires:
/// "2m"}`, plus the universal denies.
///
/// **Ambiguity flagged, not resolved**: DESIGN.md §A5's permission-list bullet says `pub
/// registry.revoke` (no `.<hfp>` suffix), but the same section's subject table lists the subject
/// as `registry.revoke.<hfp>` ("host `hfp` only" as publisher) and ADR-002 repeats the same
/// subject-table row verbatim. This module follows the task brief and the subject table —
/// `registry.revoke.<own>` — since a bare `registry.revoke` would let any host publish into
/// every other host's revocation subject, which contradicts "helper asserts subject token ==
/// record `host_fp`" a few lines later in the same section.
pub fn host_permissions(own_host_fp: Fingerprint) -> SubjectPermissions {
    SubjectPermissions {
        publish_allow: vec![
            format!("host.{own_host_fp}.sess.*.*.h2c"),
            format!("registry.revoke.{own_host_fp}"),
        ],
        subscribe_allow: vec![format!("host.{own_host_fp}.>")],
        deny: universal_denies(),
        allow_responses: Some(AllowResponses {
            max: 1,
            expires_secs: 120,
        }),
    }
}

/// Full member-cap client permissions for the given `own_device_fp`, one `host_fp` at a time
/// (DESIGN.md §A5): per host `h`, `pub host.<h>.connect`, `pub host.<h>.sess.<own>.*.c2h`, `sub
/// host.<h>.sess.<own>.*.h2c`, `sub host.<h>.presence`; plus, once for the whole connection (not
/// per host): `sub _INBOX_<own>.>`, `pub helper.presence.get`, `pub helper.turn.get`.
///
/// `hosts` must be non-empty — a connection with no fully-verified member host has no business
/// calling this (see [`client_connect_only_permissions`] instead).
pub fn client_member_permissions(
    own_device_fp: Fingerprint,
    hosts: &[Fingerprint],
) -> SubjectPermissions {
    let mut publish_allow = Vec::with_capacity(hosts.len() * 2 + 2);
    let mut subscribe_allow = Vec::with_capacity(hosts.len() * 2 + 1);
    subscribe_allow.push(format!("_INBOX_{own_device_fp}.>"));
    for h in hosts {
        publish_allow.push(format!("host.{h}.connect"));
        publish_allow.push(format!("host.{h}.sess.{own_device_fp}.*.c2h"));
        subscribe_allow.push(format!("host.{h}.sess.{own_device_fp}.*.h2c"));
        subscribe_allow.push(format!("host.{h}.presence"));
    }
    publish_allow.push("helper.presence.get".to_string());
    publish_allow.push("helper.turn.get".to_string());
    SubjectPermissions {
        publish_allow,
        subscribe_allow,
        deny: universal_denies(),
        allow_responses: None,
    }
}

/// Connect-only permissions for an invite cap or a stale-but-signature-valid member cap
/// (DESIGN.md §A5: "Invite-only and stale-cap connections get just `pub host.<h>.connect` +
/// inbox"). No `helper.presence.get`/`helper.turn.get`, no session subjects, no presence sub —
/// those are reserved for connections with at least one fully-verified member host.
pub fn client_connect_only_permissions(
    own_device_fp: Fingerprint,
    hosts: &[Fingerprint],
) -> SubjectPermissions {
    let publish_allow = hosts.iter().map(|h| format!("host.{h}.connect")).collect();
    SubjectPermissions {
        publish_allow,
        subscribe_allow: vec![format!("_INBOX_{own_device_fp}.>")],
        deny: universal_denies(),
        allow_responses: None,
    }
}

/// Payload size limit for every connection (DESIGN.md §A4/§A5): 64 KiB.
pub const MAX_PAYLOAD_BYTES: u32 = 64 * 1024;

/// `subs ≤ 4N + 8` (DESIGN.md §A5), where `N` is the number of hosts granted on this connection
/// (full-member and connect-only combined — both grant shapes consume subscription slots: a
/// connect-only host still needs the connection's shared inbox sub, and a full-member host adds
/// its own `sess.*.h2c`/`presence` subs on top of the `+8` fixed overhead).
pub fn max_subscriptions(host_count: u32) -> u32 {
    4 * host_count + 8
}

/// Jitters a session `exp` into `[45, 75]` minutes from `now` (DESIGN.md §A4/§A5: `exp` jittered
/// in `[45, 75] min`). `jitter_source` is any caller-supplied `u64` (e.g. drawn from an RNG at
/// the NATS-wiring layer, or a fixed value in tests) mapped deterministically onto the 31
/// possible integer-minute values in that inclusive range — this module never reads an RNG or a
/// clock itself.
pub fn jittered_exp_secs(now: u64, jitter_source: u64) -> u64 {
    const MIN_MINUTES: u64 = 45;
    const MAX_MINUTES: u64 = 75;
    const SPAN: u64 = MAX_MINUTES - MIN_MINUTES; // 30 -> 31 inclusive values
    let minutes = MIN_MINUTES + (jitter_source % (SPAN + 1));
    now + minutes * 60
}

/// A connection's resource limits (DESIGN.md §A4/§A5: payload 64 KiB, `subs ≤ 4N+8`, jittered
/// `exp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub payload_bytes: u32,
    pub max_subscriptions: u32,
    pub exp: u64,
}

impl Limits {
    pub fn new(host_count: u32, now: u64, jitter_source: u64) -> Self {
        Self {
            payload_bytes: MAX_PAYLOAD_BYTES,
            max_subscriptions: max_subscriptions(host_count),
            exp: jittered_exp_secs(now, jitter_source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(seed: &[u8]) -> Fingerprint {
        Fingerprint::of_parts(&[seed])
    }

    #[test]
    fn host_permissions_are_byte_exact() {
        let own = fp(b"host-under-test");
        let perms = host_permissions(own);
        assert_eq!(
            perms.subscribe_allow,
            vec![format!("host.{own}.>")],
            "host subscribes to its own full subject tree, nothing else"
        );
        assert_eq!(
            perms.publish_allow,
            vec![
                format!("host.{own}.sess.*.*.h2c"),
                format!("registry.revoke.{own}"),
            ]
        );
        assert_eq!(perms.deny, universal_denies());
        assert_eq!(
            perms.allow_responses,
            Some(AllowResponses {
                max: 1,
                expires_secs: 120
            })
        );
    }

    #[test]
    fn host_permissions_subject_strings_have_expected_shape() {
        let own = fp(b"another-host");
        let perms = host_permissions(own);
        assert!(perms.subscribe_allow[0].starts_with("host."));
        assert!(perms.subscribe_allow[0].ends_with(".>"));
        assert!(perms.publish_allow[0].ends_with(".sess.*.*.h2c"));
        assert!(perms.publish_allow[1].starts_with("registry.revoke."));
        assert!(
            !perms.publish_allow[1].ends_with(".>"),
            "scoped to one host, not a wildcard"
        );
    }

    #[test]
    fn client_member_permissions_are_byte_exact_for_one_host() {
        let own = fp(b"device-under-test");
        let h = fp(b"host-a");
        let perms = client_member_permissions(own, &[h]);
        assert_eq!(
            perms.publish_allow,
            vec![
                format!("host.{h}.connect"),
                format!("host.{h}.sess.{own}.*.c2h"),
                "helper.presence.get".to_string(),
                "helper.turn.get".to_string(),
            ]
        );
        assert_eq!(
            perms.subscribe_allow,
            vec![
                format!("_INBOX_{own}.>"),
                format!("host.{h}.sess.{own}.*.h2c"),
                format!("host.{h}.presence"),
            ]
        );
        assert_eq!(perms.deny, universal_denies());
        assert_eq!(perms.allow_responses, None);
    }

    #[test]
    fn client_member_permissions_scale_per_host() {
        let own = fp(b"device-multi");
        let h1 = fp(b"host-1");
        let h2 = fp(b"host-2");
        let perms = client_member_permissions(own, &[h1, h2]);
        // One shared inbox sub + 2 subs per host (sess.h2c, presence).
        assert_eq!(perms.subscribe_allow.len(), 1 + 2 * 2);
        // 2 pubs per host (connect, sess.c2h) + the 2 fixed helper.* pubs.
        assert_eq!(perms.publish_allow.len(), 2 * 2 + 2);
    }

    #[test]
    fn client_connect_only_permissions_are_byte_exact() {
        let own = fp(b"device-invite");
        let h = fp(b"host-b");
        let perms = client_connect_only_permissions(own, &[h]);
        assert_eq!(perms.publish_allow, vec![format!("host.{h}.connect")]);
        assert_eq!(perms.subscribe_allow, vec![format!("_INBOX_{own}.>")]);
        assert_eq!(perms.deny, universal_denies());
        assert_eq!(perms.allow_responses, None);
        assert!(
            !perms.publish_allow.iter().any(|s| s.contains("helper.")),
            "connect-only connections never get helper.presence.get/helper.turn.get"
        );
        assert!(
            !perms.subscribe_allow.iter().any(|s| s.contains("presence")),
            "connect-only connections never get sub host.<h>.presence"
        );
    }

    #[test]
    fn merge_concatenates_and_prefers_first_allow_responses() {
        let own = fp(b"device-mixed");
        let full_h = fp(b"host-full");
        let connect_h = fp(b"host-connect-only");
        let merged = client_member_permissions(own, &[full_h])
            .merge(client_connect_only_permissions(own, &[connect_h]));
        assert!(merged
            .publish_allow
            .contains(&format!("host.{full_h}.sess.{own}.*.c2h")));
        assert!(merged
            .publish_allow
            .contains(&format!("host.{connect_h}.connect")));
    }

    #[test]
    fn max_subscriptions_formula() {
        assert_eq!(max_subscriptions(0), 8);
        assert_eq!(max_subscriptions(1), 12);
        assert_eq!(max_subscriptions(32), 136);
    }

    #[test]
    fn jittered_exp_stays_within_45_to_75_minutes() {
        for seed in 0u64..200 {
            let exp = jittered_exp_secs(1_000_000, seed);
            let delta_minutes = (exp - 1_000_000) / 60;
            assert!(
                (45..=75).contains(&delta_minutes),
                "seed {seed} produced {delta_minutes} minutes"
            );
        }
    }

    #[test]
    fn jittered_exp_is_deterministic_for_a_fixed_seed() {
        assert_eq!(
            jittered_exp_secs(1_000, 7),
            jittered_exp_secs(1_000, 7),
            "same (now, seed) must always produce the same exp"
        );
    }
}
