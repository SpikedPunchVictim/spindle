//! Admin command verification, replay guard, and reply envelope (DESIGN.md §A3b, td-efea19).
//!
//! This is the pure core of the `registry.admin.>` plane. It decodes an [`AdminCommand`], verifies
//! it with the operator key and the required `signer_fp` binding, enforces the per-signer
//! monotonic `seq` plus a nonce-replay guard, dispatches the command, and encodes a reply envelope
//! byte-compatible with `@spindle/admin`'s provisional codec.
//!
//! **Not in this module, deliberately:** the NATS subject subscription, the mTLS/operator-identity
//! gate, the durable Postgres replay/audit state, and the stateful command implementations. Those
//! are the remaining slices of td-efea19; every command here answers `not_implemented`, which the
//! client can distinguish from a malformed or replayed command.
//!
//! The plane is a **verifier, not a login** (DESIGN.md §A3b): there is no session, password, or
//! CSRF surface here.

use std::collections::{HashMap, HashSet};

use spindle_core::artifacts::{verify_admin_command, ArtifactError};
use spindle_core::Fingerprint;
use spindle_core::VerifyingKey;
use spindle_proto::artifacts::AdminCommand;
use spindle_proto::canonical::{canonical_encode, CborValue};

/// Reply envelope version this module emits and understands.
pub const ADMIN_REPLY_V: u8 = 1;

/// The reply shapes `@spindle/admin` decodes: `{v, ok, result?}` or `{v, ok, error:{code,message?}}`.
#[derive(Debug, Clone, PartialEq)]
pub enum AdminReply {
    Ok {
        result: Option<CborValue>,
    },
    Refused {
        code: String,
        message: Option<String>,
    },
}

impl AdminReply {
    pub fn to_cbor(&self) -> CborValue {
        let mut entries = vec![
            ("v", CborValue::uint(ADMIN_REPLY_V as u64)),
            ("ok", CborValue::Bool(matches!(self, Self::Ok { .. }))),
        ];
        match self {
            Self::Ok {
                result: Some(result),
            } => entries.push(("result", result.clone())),
            Self::Ok { result: None } => {}
            Self::Refused { code, message } => {
                let mut error = vec![("code", CborValue::text(code.clone()))];
                if let Some(message) = message {
                    error.push(("message", CborValue::text(message.clone())));
                }
                entries.push(("error", CborValue::map(error)));
            }
        }
        CborValue::map(entries)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode(&self.to_cbor())
    }
}

/// Why a command was refused before dispatch.
#[derive(Debug, thiserror::Error)]
pub enum AdminRefusal {
    #[error("admin command is not canonical CBOR")]
    Malformed,
    #[error("admin command failed verification")]
    Verify(#[source] ArtifactError),
    #[error("admin command sequence was already used by this signer")]
    Replay,
    #[error("unknown admin command")]
    UnknownCommand,
    #[error("command is not implemented yet")]
    NotImplemented,
}

impl AdminRefusal {
    fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Verify(_) => "verification_failed",
            Self::Replay => "replay",
            Self::UnknownCommand => "unknown_command",
            Self::NotImplemented => "not_implemented",
        }
    }
}

/// Durable-state seam for the replay guard. The in-memory implementation backs tests; the
/// Postgres-backed slice implements the same contract durably and leader-only (A10.23).
pub trait AdminReplayState {
    fn last_seq(&self, signer_fp: &Fingerprint) -> Option<u64>;
    fn nonce_seen(&self, signer_fp: &Fingerprint, nonce: &[u8]) -> bool;
    /// Records `(seq, nonce)` as used. Returns false (and records nothing) on a conflict.
    fn record(&mut self, signer_fp: &Fingerprint, seq: u64, nonce: &[u8]) -> bool;
}

/// Process-lifetime replay state. Not durable; the Postgres slice replaces it.
#[derive(Debug, Default)]
pub struct InMemoryAdminReplay {
    seqs: HashMap<[u8; 32], u64>,
    nonces: HashSet<([u8; 32], Vec<u8>)>,
}

impl AdminReplayState for InMemoryAdminReplay {
    fn last_seq(&self, signer_fp: &Fingerprint) -> Option<u64> {
        self.seqs.get(signer_fp.as_bytes()).copied()
    }

    fn nonce_seen(&self, signer_fp: &Fingerprint, nonce: &[u8]) -> bool {
        self.nonces
            .contains(&(*signer_fp.as_bytes(), nonce.to_vec()))
    }

    fn record(&mut self, signer_fp: &Fingerprint, seq: u64, nonce: &[u8]) -> bool {
        if self.last_seq(signer_fp).is_some_and(|last| seq <= last)
            || self.nonce_seen(signer_fp, nonce)
        {
            return false;
        }
        self.seqs.insert(*signer_fp.as_bytes(), seq);
        self.nonces.insert((*signer_fp.as_bytes(), nonce.to_vec()));
        true
    }
}

/// The command surface, matching `@spindle/admin`'s documented names and ADR-007.
pub const ADMIN_COMMANDS: &[&str] = &[
    "set_mode",
    "mint_invite",
    "revoke_invite",
    "pre_register_host",
    "list_hosts",
    "suspend_host",
    "evict_host",
    "set_quota_profile",
    "rotate_admission_key",
    "read_audit_log",
];

/// Verifies, replay-checks, and dispatches admin commands.
pub struct AdminService<S: AdminReplayState> {
    operator_pk: VerifyingKey,
    expected_signer_fp: Fingerprint,
    replay: S,
}

impl<S: AdminReplayState> AdminService<S> {
    pub fn new(operator_pk: VerifyingKey, expected_signer_fp: Fingerprint, replay: S) -> Self {
        Self {
            operator_pk,
            expected_signer_fp,
            replay,
        }
    }

    /// Handles one raw command and returns the reply envelope bytes. Refusals are ordinary replies,
    /// not transport errors, so the client sees the typed `code`.
    pub fn handle(&mut self, bytes: &[u8], now: u64) -> Vec<u8> {
        match self.try_handle(bytes, now) {
            Ok(reply) => reply,
            Err(refusal) => AdminReply::Refused {
                code: refusal.code().to_string(),
                message: None,
            }
            .to_canonical_bytes(),
        }
    }

    fn try_handle(&mut self, bytes: &[u8], now: u64) -> Result<Vec<u8>, AdminRefusal> {
        let command =
            AdminCommand::from_canonical_bytes(bytes).map_err(|_| AdminRefusal::Malformed)?;
        verify_admin_command(&command, &self.operator_pk, &self.expected_signer_fp, now)
            .map_err(AdminRefusal::Verify)?;

        if !ADMIN_COMMANDS.contains(&command.cmd.as_str()) {
            return Err(AdminRefusal::UnknownCommand);
        }
        if !self
            .replay
            .record(&self.expected_signer_fp, command.seq, &command.nonce)
        {
            return Err(AdminRefusal::Replay);
        }

        // The stateful command implementations are the next slice of td-efea19. A typed
        // not_implemented is deliberately distinguishable from a malformed/replayed command.
        Err(AdminRefusal::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spindle_core::artifacts::issue_admin_command;
    use spindle_core::SigningKey;
    use spindle_proto::canonical::canonical_decode;

    const NOW: u64 = 1_755_907_200;

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[0x31; 32])
    }

    fn signer_fp() -> Fingerprint {
        Fingerprint::of_parts(&[b"operator"])
    }

    fn service() -> AdminService<InMemoryAdminReplay> {
        AdminService::new(
            operator().verifying_key(),
            signer_fp(),
            InMemoryAdminReplay::default(),
        )
    }

    fn command(op: &SigningKey, cmd: &str, seq: u64, nonce: u8, ts: u64) -> AdminCommand {
        issue_admin_command(
            op,
            1,
            cmd.to_string(),
            CborValue::Null,
            signer_fp().to_vec(),
            seq,
            vec![nonce; 16],
            ts,
        )
    }

    fn decode_reply(bytes: &[u8]) -> (bool, Option<String>) {
        let map = canonical_decode(bytes).expect("reply is canonical CBOR");
        let map = map.as_map().expect("reply is a map");
        let ok = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("ok"))
            .and_then(|(_, v)| match v {
                CborValue::Bool(ok) => Some(*ok),
                _ => None,
            })
            .expect("ok field");
        let code = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("error"))
            .and_then(|(_, v)| v.as_map())
            .and_then(|error| {
                error
                    .iter()
                    .find(|(k, _)| k.as_text() == Some("code"))
                    .and_then(|(_, c)| c.as_text().map(str::to_string))
            });
        (ok, code)
    }

    #[test]
    fn a_valid_command_passes_verification_and_answers_not_implemented() {
        let op = operator();
        let mut service = service();
        let reply = service.handle(
            &command(&op, "set_mode", 1, 0x01, NOW).to_canonical_bytes(),
            NOW,
        );
        assert_eq!(
            decode_reply(&reply),
            (false, Some("not_implemented".into()))
        );
    }

    #[test]
    fn a_forged_signature_is_refused() {
        let mut service = service();
        let forged = command(&SigningKey::from_bytes(&[0x32; 32]), "set_mode", 1, 1, NOW);
        let reply = service.handle(&forged.to_canonical_bytes(), NOW);
        assert_eq!(
            decode_reply(&reply),
            (false, Some("verification_failed".into()))
        );
    }

    #[test]
    fn a_wrong_signer_binding_is_refused() {
        let op = operator();
        let mut bad = command(&op, "set_mode", 1, 2, NOW);
        bad.signer_fp = Fingerprint::of_parts(&[b"someone-else"]).to_vec();
        let mut service = service();
        let reply = service.handle(&bad.to_canonical_bytes(), NOW);
        assert_eq!(
            decode_reply(&reply),
            (false, Some("verification_failed".into()))
        );
    }

    #[test]
    fn a_replayed_sequence_or_nonce_is_refused() {
        let op = operator();
        let mut service = service();
        let first = command(&op, "list_hosts", 7, 3, NOW).to_canonical_bytes();
        assert_eq!(
            decode_reply(&service.handle(&first, NOW)).1.as_deref(),
            Some("not_implemented")
        );
        // Same seq, fresh nonce.
        let same_seq = command(&op, "list_hosts", 7, 4, NOW).to_canonical_bytes();
        assert_eq!(
            decode_reply(&service.handle(&same_seq, NOW)).1.as_deref(),
            Some("replay")
        );
        // Later seq, same nonce.
        let same_nonce = command(&op, "list_hosts", 8, 3, NOW).to_canonical_bytes();
        assert_eq!(
            decode_reply(&service.handle(&same_nonce, NOW)).1.as_deref(),
            Some("replay")
        );
    }

    #[test]
    fn an_unknown_command_is_refused() {
        let op = operator();
        let mut service = service();
        let reply = service.handle(
            &command(&op, "drop_everything", 1, 5, NOW).to_canonical_bytes(),
            NOW,
        );
        assert_eq!(
            decode_reply(&reply),
            (false, Some("unknown_command".into()))
        );
    }

    #[test]
    fn a_stale_or_malformed_command_is_refused() {
        let op = operator();
        let mut service = service();
        let stale = command(&op, "set_mode", 1, 6, NOW - 121).to_canonical_bytes();
        assert_eq!(
            decode_reply(&service.handle(&stale, NOW)).1.as_deref(),
            Some("verification_failed")
        );
        assert_eq!(
            decode_reply(&service.handle(b"not cbor", NOW)),
            (false, Some("malformed".into()))
        );
    }

    #[test]
    fn reply_envelope_is_the_provisional_client_shape() {
        let ok = AdminReply::Ok {
            result: Some(CborValue::text("x")),
        }
        .to_canonical_bytes();
        let map = canonical_decode(&ok).expect("canonical");
        let map = map.as_map().expect("map");
        assert!(map
            .iter()
            .any(|(k, v)| k.as_text() == Some("v") && v == &CborValue::uint(1)));
        let refused = AdminReply::Refused {
            code: "replay".into(),
            message: Some("already used".into()),
        }
        .to_canonical_bytes();
        let map = canonical_decode(&refused).expect("canonical");
        assert!(map
            .as_map()
            .expect("map")
            .iter()
            .any(|(k, _)| k.as_text() == Some("error")));
    }
}
