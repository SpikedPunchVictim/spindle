//! The callout's session record (DESIGN.md §A5): `nats_fp → {root_fp, host_fps, quota_profile,
//! exp}`, written on every successful auth so the helper can authorize the non-callout requests
//! (`helper.presence.get`, `helper.turn.get`) that a live connection makes later. This module
//! defines only the plain data type and its constructor — durable storage (the keyed `nats_fp →
//! ...` map itself) is a [`crate::authz::HelperView`] concern, wired to Postgres in a later
//! slice.

use spindle_core::Fingerprint;

/// One connection's session record (DESIGN.md §A5), keyed externally by `nats_fp` (this struct
/// carries `nats_fp` as a field rather than being wrapped in a map itself, so callers choose
/// their own storage shape).
///
/// **Ambiguity flagged, not resolved**: DESIGN.md §A5 introduces this record in the context of
/// *client* connections ("on each successful auth the callout writes `nats_fp → {root_fp,
/// host_fps, quota_profile, exp}`"), and `quota_profile` elsewhere (§A3b) is populated only from
/// a **host's** admission record. Two interpretive choices this slice makes, neither spelled out
/// in DESIGN.md:
/// 1. **Host connections also get a session record**, reusing this same shape, since the helper
///    needs *some* record to authorize a host's later `helper.*` calls too. `root_fp` holds the
///    host's own `host_fp` and `host_fps` holds `[own_host_fp]` for a host connection — a stretch
///    of the field's client-oriented name, kept because introducing a second, near-identical
///    struct for hosts seemed like needless duplication for a single-field semantic difference.
/// 2. **A client/device session's `quota_profile`** has no described source at all (only hosts
///    have admission-record quota profiles). [`crate::authz`] fills it with the fixed placeholder
///    `"member"` for client connections. A later slice should replace this once — if ever — a
///    real per-member quota concept exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub nats_fp: Fingerprint,
    pub root_fp: Fingerprint,
    pub host_fps: Vec<Fingerprint>,
    pub quota_profile: String,
    pub exp: u64,
}

impl SessionRecord {
    pub fn new(
        nats_fp: Fingerprint,
        root_fp: Fingerprint,
        host_fps: Vec<Fingerprint>,
        quota_profile: String,
        exp: u64,
    ) -> Self {
        Self {
            nats_fp,
            root_fp,
            host_fps,
            quota_profile,
            exp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_stores_fields_verbatim() {
        let nats_fp = Fingerprint::of_parts(&[b"nats"]);
        let root_fp = Fingerprint::of_parts(&[b"root"]);
        let host_fps = vec![Fingerprint::of_parts(&[b"host-a"])];
        let rec = SessionRecord::new(
            nats_fp,
            root_fp,
            host_fps.clone(),
            "member".to_string(),
            1_234,
        );
        assert_eq!(rec.nats_fp, nats_fp);
        assert_eq!(rec.root_fp, root_fp);
        assert_eq!(rec.host_fps, host_fps);
        assert_eq!(rec.quota_profile, "member");
        assert_eq!(rec.exp, 1_234);
    }
}
