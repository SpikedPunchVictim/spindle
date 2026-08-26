//! Upload-session state (DESIGN.md §A8 "transfer manager" / "upload sessions"), Stage 6 slice 4.
//!
//! DESIGN.md's session object shape is exact: `{id, member, path, size, hash, offset, expires}`.
//! [`UploadSession`] carries those seven fields plus the bookkeeping `crate::server::VfsRpcServer`
//! needs to enforce the rest of §A8's rules against it (`share_id` split out of `path` once
//! resolved, `manifest_sig` and the signer's device fingerprint for signature verification, and
//! the `grants_version`/`cap_epoch` values observed at open time, to detect "an entitlement change
//! mid-transfer" — DESIGN.md §A8: "aborts the session").
//!
//! [`UploadSessions`] is an in-memory, per-`VfsRpcServer`-instance table — like
//! `crate::cache::GrantsCache`/`crate::identity_cache::IdentityCache`, a `RefCell` (not a `Mutex`:
//! no cross-thread sharing requirement in this slice, see `cache`'s module doc comment for the
//! same reasoning). Sessions are **not** persisted to the `Store` — DESIGN.md does not ask for
//! upload sessions to survive a host restart (only the *files themselves*, once committed, are
//! durable), and losing in-flight sessions on restart is an acceptable, documented behavior: a
//! client resumes by calling `upload_open` again, which — finding no matching live session — just
//! starts over from offset 0. [`UploadSessions::gc_expired`] is a plain callable method, not a
//! background timer: wiring it to a scheduler (a periodic host-process tick) is application
//! territory, exactly as the task brief requires ("GC entry point, no background thread").
//!
//! Session ids are generated via `spindle_core::Fingerprint::of_parts` over the session's
//! identifying fields plus a monotonic per-server counter and the open timestamp — **not**
//! cryptographically random, a deliberate, documented choice: `spindle-host-core` has no `rand`
//! dependency, and every session-scoped call (`upload_chunk`/`upload_commit`/`upload_abort`)
//! independently re-checks that the caller's `member_id` owns the session before doing anything
//! with it (see `crate::server::VfsRpcServer`'s upload handlers), so a guessed id alone can never
//! act on another member's session. Guessability is therefore not this design's security boundary;
//! a later slice can swap in real randomness (a `rand` dependency) without changing that boundary.

use spindle_core::Fingerprint;
use spindle_vfs::model::{MemberId, ShareId, VirtualPath};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

/// DESIGN.md §A8's upload session object, `{id, member, path, size, hash, offset, expires}`, plus
/// this crate's bookkeeping additions — see the module doc comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UploadSession {
    pub(crate) id: Vec<u8>,
    pub(crate) member_id: MemberId,
    pub(crate) share_id: ShareId,
    /// The share-relative virtual subpath the file will land at on commit (DESIGN.md's `path`,
    /// split into `share_id` + this by the mount table at `upload_open` time, mirroring how every
    /// other op in `crate::server` carries `(share, subpath)` rather than a raw string).
    pub(crate) subpath: VirtualPath,
    pub(crate) size: u64,
    pub(crate) hash: Vec<u8>,
    pub(crate) manifest_sig: Vec<u8>,
    /// The device whose key `manifest_sig` must verify under (DESIGN.md §A8: "signed ... by the
    /// sending device's key"). `None` if the caller's session carries no device fingerprint (e.g.
    /// a test `SessionContext`) — such a session can never pass commit's signature check, by
    /// design (see `crate::server::VfsRpcServer::verify_manifest_signature`'s doc comment).
    pub(crate) signer_device_fp: Option<Fingerprint>,
    pub(crate) offset: u64,
    pub(crate) expires: u64,
    /// `grants_version`/`cap_epoch` observed when this session was opened (or last resumed) —
    /// compared against their current values on every subsequent `upload_chunk`/`upload_commit`
    /// to detect DESIGN.md §A8's "entitlement change mid-transfer" (see
    /// `crate::server::VfsRpcServer::check_entitlement_unchanged`).
    pub(crate) grants_version_at_open: u64,
    pub(crate) cap_epoch_at_open: u64,
}

/// The in-memory upload-session table for one `VfsRpcServer` — see the module doc comment.
pub(crate) struct UploadSessions {
    sessions: RefCell<HashMap<Vec<u8>, UploadSession>>,
    next_id: Cell<u64>,
}

impl UploadSessions {
    pub(crate) fn new() -> Self {
        UploadSessions {
            sessions: RefCell::new(HashMap::new()),
            next_id: Cell::new(0),
        }
    }

    /// Opens a new session, or — if a still-live one already exists for the same
    /// `(member_id, share_id, subpath, size, hash)` — resumes it (DESIGN.md §A8: "resume via
    /// next-expected-offset"): refreshes its TTL and stored `manifest_sig`, and returns its
    /// current offset unchanged. Two different `(size, hash)` pairs for the same path are treated
    /// as two independent sessions (deliberately: a client re-uploading a genuinely different
    /// file at the same path should not resume mid-way through unrelated old bytes) — the older
    /// one simply ages out via [`Self::gc_expired`] once its TTL passes, or can be discarded
    /// explicitly via `upload_abort`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_or_resume(
        &self,
        member_id: MemberId,
        share_id: ShareId,
        subpath: &VirtualPath,
        size: u64,
        hash: &[u8],
        manifest_sig: &[u8],
        signer_device_fp: Option<Fingerprint>,
        now: u64,
        ttl_secs: u64,
        grants_version: u64,
        cap_epoch: u64,
    ) -> UploadSession {
        let mut sessions = self.sessions.borrow_mut();
        if let Some(existing) = sessions.values_mut().find(|s| {
            s.member_id == member_id
                && s.share_id == share_id
                && s.subpath == *subpath
                && s.size == size
                && s.hash == hash
                && s.expires > now
        }) {
            existing.manifest_sig = manifest_sig.to_vec();
            existing.signer_device_fp = signer_device_fp;
            existing.expires = now.saturating_add(ttl_secs);
            return existing.clone();
        }

        let n = self.next_id.get();
        self.next_id.set(n.wrapping_add(1));
        let id = Fingerprint::of_parts(&[
            &member_id.0.to_be_bytes(),
            &share_id.0.to_be_bytes(),
            subpath.to_path_string().as_bytes(),
            &now.to_be_bytes(),
            &n.to_be_bytes(),
        ])
        .to_vec();

        let session = UploadSession {
            id: id.clone(),
            member_id,
            share_id,
            subpath: subpath.clone(),
            size,
            hash: hash.to_vec(),
            manifest_sig: manifest_sig.to_vec(),
            signer_device_fp,
            offset: 0,
            expires: now.saturating_add(ttl_secs),
            grants_version_at_open: grants_version,
            cap_epoch_at_open: cap_epoch,
        };
        sessions.insert(id, session.clone());
        session
    }

    /// A clone of the session, if `id` names one owned by `member_id`. Ownership is checked here,
    /// centrally, rather than left to each caller — see the module doc comment on why session ids
    /// are not this design's security boundary.
    pub(crate) fn get_owned(&self, id: &[u8], member_id: MemberId) -> Option<UploadSession> {
        self.sessions
            .borrow()
            .get(id)
            .filter(|s| s.member_id == member_id)
            .cloned()
    }

    pub(crate) fn set_offset(&self, id: &[u8], new_offset: u64) {
        if let Some(s) = self.sessions.borrow_mut().get_mut(id) {
            s.offset = new_offset;
        }
    }

    /// Removes and returns the session named `id`, if any (commit/abort, or an internal
    /// entitlement-change/GC eviction).
    pub(crate) fn remove(&self, id: &[u8]) -> Option<UploadSession> {
        self.sessions.borrow_mut().remove(id)
    }

    /// Removes and returns every session whose TTL has passed as of `now` (DESIGN.md §A8: 48h
    /// TTL). See the module doc comment: callable, no background thread.
    pub(crate) fn gc_expired(&self, now: u64) -> Vec<UploadSession> {
        let mut sessions = self.sessions.borrow_mut();
        let expired: Vec<Vec<u8>> = sessions
            .iter()
            .filter(|(_, s)| s.expires <= now)
            .map(|(id, _)| id.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|id| sessions.remove(&id))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sessions.borrow().len()
    }
}

/// This crate's chosen encoding for the bytes an upload manifest's signature covers — DESIGN.md
/// §A8 says the manifest is "signed" but does not specify a byte-for-byte encoding. Length-prefixed
/// (not naive concatenation) so `("ab", 1, [])` and `("a", 1, [b'b'])`-style field-boundary
/// ambiguities can never produce the same signing input for two different manifests.
pub(crate) fn manifest_signing_bytes(path: &str, size: u64, hash: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + path.len() + 8 + 8 + hash.len());
    buf.extend_from_slice(&(path.len() as u64).to_be_bytes());
    buf.extend_from_slice(path.as_bytes());
    buf.extend_from_slice(&size.to_be_bytes());
    buf.extend_from_slice(&(hash.len() as u64).to_be_bytes());
    buf.extend_from_slice(hash);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vp(s: &str) -> VirtualPath {
        VirtualPath::parse(s).expect("valid virtual path")
    }

    #[test]
    fn open_or_resume_creates_new_session_at_offset_zero() {
        let sessions = UploadSessions::new();
        let s = sessions.open_or_resume(
            MemberId(1),
            ShareId(1),
            &vp("incoming.bin"),
            100,
            &[1, 2, 3],
            &[9, 9],
            None,
            1000,
            48 * 60 * 60,
            0,
            0,
        );
        assert_eq!(s.offset, 0);
        assert_eq!(s.expires, 1000 + 48 * 60 * 60);
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn open_or_resume_resumes_matching_live_session() {
        let sessions = UploadSessions::new();
        let first = sessions.open_or_resume(
            MemberId(1),
            ShareId(1),
            &vp("incoming.bin"),
            100,
            &[1, 2, 3],
            &[9, 9],
            None,
            1000,
            48 * 60 * 60,
            0,
            0,
        );
        sessions.set_offset(&first.id, 40);

        let second = sessions.open_or_resume(
            MemberId(1),
            ShareId(1),
            &vp("incoming.bin"),
            100,
            &[1, 2, 3],
            &[9, 9, 9], // re-signed, but same manifest content
            None,
            2000,
            48 * 60 * 60,
            0,
            0,
        );
        assert_eq!(second.id, first.id, "must resume, not create a new session");
        assert_eq!(second.offset, 40, "resumed session keeps its progress");
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn open_or_resume_does_not_resume_an_expired_session() {
        let sessions = UploadSessions::new();
        let first = sessions.open_or_resume(
            MemberId(1),
            ShareId(1),
            &vp("incoming.bin"),
            100,
            &[1, 2, 3],
            &[9, 9],
            None,
            1000,
            10, // TTL 10s
            0,
            0,
        );
        let second = sessions.open_or_resume(
            MemberId(1),
            ShareId(1),
            &vp("incoming.bin"),
            100,
            &[1, 2, 3],
            &[9, 9],
            None,
            5000, // long past expiry
            10,
            0,
            0,
        );
        assert_ne!(second.id, first.id);
    }

    #[test]
    fn get_owned_rejects_wrong_member() {
        let sessions = UploadSessions::new();
        let s = sessions.open_or_resume(
            MemberId(1),
            ShareId(1),
            &vp("incoming.bin"),
            100,
            &[1, 2, 3],
            &[9, 9],
            None,
            1000,
            48 * 60 * 60,
            0,
            0,
        );
        assert!(sessions.get_owned(&s.id, MemberId(1)).is_some());
        assert!(sessions.get_owned(&s.id, MemberId(2)).is_none());
    }

    #[test]
    fn gc_expired_removes_only_expired_sessions() {
        let sessions = UploadSessions::new();
        let expiring = sessions.open_or_resume(
            MemberId(1),
            ShareId(1),
            &vp("a.bin"),
            10,
            &[1],
            &[1],
            None,
            0,
            100,
            0,
            0,
        );
        let fresh = sessions.open_or_resume(
            MemberId(1),
            ShareId(1),
            &vp("b.bin"),
            10,
            &[2],
            &[2],
            None,
            50,
            100,
            0,
            0,
        );
        // `expiring` expires at 100, `fresh` at 150 (opened later, same TTL) — GC at 120 sits
        // strictly between the two, so exactly one session is reaped. (Deliberately not 150: that
        // instant is `fresh`'s own boundary too, and `gc_expired`'s `expires <= now` threshold is
        // intentionally consistent with `open_or_resume`'s own "resumable iff `expires > now`"
        // rule, so `fresh` would no longer be resumable at exactly its own expiry either — this
        // test isolates the "only genuinely expired sessions are reaped" behavior, not that exact
        // boundary case.)
        let gone = sessions.gc_expired(120);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].id, expiring.id);
        assert_eq!(sessions.len(), 1);
        assert!(sessions.get_owned(&fresh.id, MemberId(1)).is_some());
    }

    #[test]
    fn manifest_signing_bytes_is_unambiguous_across_field_boundaries() {
        let a = manifest_signing_bytes("ab", 1, &[]);
        let b = manifest_signing_bytes("a", 1, b"b");
        assert_ne!(a, b);
    }
}
