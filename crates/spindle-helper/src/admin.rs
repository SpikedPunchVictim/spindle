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

use crate::authz::{AdmissionMode, HostState};
use spindle_proto::artifacts::AdminCommand;
use spindle_proto::canonical::{canonical_encode, CborValue};

/// Reply envelope version this module emits and understands.
pub const ADMIN_REPLY_V: u8 = 1;
/// Maximum audit rows returned by `read_audit_log`.
pub const MAX_AUDIT_PAGE: u32 = 500;

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
    #[error("command arguments are malformed")]
    BadArgs,
    #[error("target host was not found")]
    NotFound,
    #[error("admin state store failed")]
    State(#[source] AdminStateError),
}

impl AdminRefusal {
    fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Verify(_) => "verification_failed",
            Self::Replay => "replay",
            Self::UnknownCommand => "unknown_command",
            Self::NotImplemented => "not_implemented",
            Self::BadArgs => "invalid_args",
            Self::NotFound => "not_found",
            Self::State(state) => state.code(),
        }
    }
}

/// Why the durable admin state could not be read or written.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminStateError {
    #[error("admin state store failed")]
    Backend,
    /// This backend cannot perform the command yet (the in-memory dev backend has no durable
    /// admission mode to change).
    #[error("admin command is not supported by this backend")]
    Unsupported,
}

impl AdminStateError {
    fn code(&self) -> &'static str {
        match self {
            Self::Backend => "state_failed",
            Self::Unsupported => "not_implemented",
        }
    }
}

/// A stateful command whose SQL must share one transaction with the replay insert and audit row.
pub enum AdminMutation<'a> {
    SetMode(AdmissionMode),
    PreRegisterHost {
        host_fp: &'a Fingerprint,
        label: &'a str,
        quota_profile: &'a str,
    },
    SetQuotaProfile {
        host_fp: &'a Fingerprint,
        quota_profile: &'a str,
    },
    SetHostState {
        host_fp: &'a Fingerprint,
        state: HostState,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOutcome {
    Applied,
    NotFound,
}

/// Durable-state seam: the anti-replay guard and the hash-chained audit append. The in-memory
/// implementation backs tests; `PgStore` implements it durably (migration 0005).
pub trait AdminState {
    /// True if `seq` is not strictly newer than this signer's last accepted seq, or the nonce was
    /// already used.
    fn is_replay(
        &self,
        signer_fp: &Fingerprint,
        seq: u64,
        nonce: &[u8],
    ) -> Result<bool, AdminStateError>;
    /// Records `(seq, nonce)` and appends the audit entry in one transaction. Returns false (and
    /// records nothing) if another writer won the same seq/nonce.
    fn commit(
        &mut self,
        ts: u64,
        signer_fp: &Fingerprint,
        seq: u64,
        nonce: &[u8],
        cmd: &str,
        result_code: &str,
    ) -> Result<bool, AdminStateError>;

    /// Read-only commands. The memory backend has no admission records, so its list is empty.
    fn list_hosts(&mut self) -> Result<CborValue, AdminStateError>;
    /// The most recent `limit` audit rows, newest first.
    fn read_audit_log(&mut self, limit: u32) -> Result<CborValue, AdminStateError>;
    /// Durable admission-mode change (A3b `set_mode`). Backends without durable mode refuse.
    fn set_mode(&mut self, mode: AdmissionMode) -> Result<(), AdminStateError>;
    /// Pre-register a host (A3b) by creating its admission record. Idempotent for an existing
    /// record: it does not rewrite label/quota.
    fn pre_register_host(
        &mut self,
        host_fp: &Fingerprint,
        label: &str,
        quota_profile: &str,
    ) -> Result<(), AdminStateError>;
    /// Update an existing admission record's quota profile. False when no record exists.
    fn set_quota_profile(
        &mut self,
        host_fp: &Fingerprint,
        quota_profile: &str,
    ) -> Result<bool, AdminStateError>;
    /// Set the operator lifecycle flag. `Evicted` is terminal for new connections.
    fn set_host_state(
        &mut self,
        host_fp: &Fingerprint,
        state: HostState,
    ) -> Result<(), AdminStateError>;

    /// Executes a stateful command, its replay insert, and its audit row in one transaction.
    /// `Ok(None)` means the seq/nonce was already used and nothing was written.
    fn commit_mutation(
        &mut self,
        ts: u64,
        signer_fp: &Fingerprint,
        seq: u64,
        nonce: &[u8],
        cmd: &str,
        mutation: AdminMutation<'_>,
    ) -> Result<Option<MutationOutcome>, AdminStateError>;
}

/// Process-lifetime replay state. Not durable; the Postgres slice replaces it.
#[derive(Debug, Default)]
pub struct InMemoryAdminReplay {
    seqs: HashMap<[u8; 32], u64>,
    nonces: HashSet<([u8; 32], Vec<u8>)>,
    audit: Vec<(u64, [u8; 32], u64, String, String)>,
}

impl InMemoryAdminReplay {
    fn last_seq(&self, signer_fp: &Fingerprint) -> Option<u64> {
        self.seqs.get(signer_fp.as_bytes()).copied()
    }

    fn nonce_seen(&self, signer_fp: &Fingerprint, nonce: &[u8]) -> bool {
        self.nonces
            .contains(&(*signer_fp.as_bytes(), nonce.to_vec()))
    }
}

impl AdminState for InMemoryAdminReplay {
    fn is_replay(
        &self,
        signer_fp: &Fingerprint,
        seq: u64,
        nonce: &[u8],
    ) -> Result<bool, AdminStateError> {
        Ok(self.last_seq(signer_fp).is_some_and(|last| seq <= last)
            || self.nonce_seen(signer_fp, nonce))
    }

    fn commit(
        &mut self,
        _ts: u64,
        signer_fp: &Fingerprint,
        seq: u64,
        nonce: &[u8],
        _cmd: &str,
        _result_code: &str,
    ) -> Result<bool, AdminStateError> {
        if self.is_replay(signer_fp, seq, nonce)? {
            return Ok(false);
        }
        self.seqs.insert(*signer_fp.as_bytes(), seq);
        self.nonces.insert((*signer_fp.as_bytes(), nonce.to_vec()));
        self.audit.push((
            _ts,
            *signer_fp.as_bytes(),
            seq,
            _cmd.to_string(),
            _result_code.to_string(),
        ));
        if self.audit.len() > 1024 {
            self.audit.remove(0);
        }
        Ok(true)
    }

    fn list_hosts(&mut self) -> Result<CborValue, AdminStateError> {
        Ok(CborValue::array(Vec::new()))
    }

    fn set_mode(&mut self, _mode: AdmissionMode) -> Result<(), AdminStateError> {
        Err(AdminStateError::Unsupported)
    }

    fn pre_register_host(
        &mut self,
        _host_fp: &Fingerprint,
        _label: &str,
        _quota_profile: &str,
    ) -> Result<(), AdminStateError> {
        Err(AdminStateError::Unsupported)
    }

    fn set_quota_profile(
        &mut self,
        _host_fp: &Fingerprint,
        _quota_profile: &str,
    ) -> Result<bool, AdminStateError> {
        Err(AdminStateError::Unsupported)
    }

    fn set_host_state(
        &mut self,
        _host_fp: &Fingerprint,
        _state: HostState,
    ) -> Result<(), AdminStateError> {
        Err(AdminStateError::Unsupported)
    }

    fn commit_mutation(
        &mut self,
        _ts: u64,
        _signer_fp: &Fingerprint,
        _seq: u64,
        _nonce: &[u8],
        _cmd: &str,
        _mutation: AdminMutation<'_>,
    ) -> Result<Option<MutationOutcome>, AdminStateError> {
        Err(AdminStateError::Unsupported)
    }

    fn read_audit_log(&mut self, limit: u32) -> Result<CborValue, AdminStateError> {
        let rows = self
            .audit
            .iter()
            .rev()
            .take(limit as usize)
            .map(|(ts, signer, seq, cmd, code)| {
                CborValue::map(vec![
                    ("ts", CborValue::uint(*ts)),
                    ("signer_fp", CborValue::bytes(signer.to_vec())),
                    ("seq", CborValue::uint(*seq)),
                    ("cmd", CborValue::text(cmd.clone())),
                    ("result_code", CborValue::text(code.clone())),
                ])
            })
            .collect();
        Ok(CborValue::array(rows))
    }
}

fn refusal_bytes(refusal: &AdminRefusal) -> Vec<u8> {
    AdminReply::Refused {
        code: refusal.code().to_string(),
        message: None,
    }
    .to_canonical_bytes()
}

fn parse_host_fp(args: &CborValue) -> Option<Fingerprint> {
    let map = args.as_map()?;
    map.iter()
        .find(|(k, _)| k.as_text() == Some("host_fp"))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| Fingerprint::from_slice(&bytes).ok())
}

fn parse_host_args(args: &CborValue, needs_label: bool) -> Option<(Fingerprint, String, String)> {
    let map = args.as_map()?;
    let host_fp = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("host_fp"))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| Fingerprint::from_slice(&bytes).ok())?;
    let quota = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("quota_profile"))
        .and_then(|(_, v)| v.as_text())?;
    if quota.is_empty() {
        return None;
    }
    let label = if needs_label {
        let label = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("label"))
            .and_then(|(_, v)| v.as_text())?;
        if label.is_empty() {
            return None;
        }
        label.to_string()
    } else {
        String::new()
    };
    Some((host_fp, label, quota.to_string()))
}

fn parse_mode(args: &CborValue) -> Option<AdmissionMode> {
    let map = args.as_map()?;
    let mode = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("mode"))
        .and_then(|(_, v)| v.as_text())?;
    match mode {
        "open" => Some(AdmissionMode::Open),
        "invite" => Some(AdmissionMode::Invite),
        "closed" => Some(AdmissionMode::Closed),
        _ => None,
    }
}

/// Why the admin plane is not started.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminPlaneError {
    #[error("no operator key is configured; the admin plane is disabled")]
    NoOperatorKey,
    #[error(
        "the admin plane requires a TLS NATS_URL (A3b mTLS); set ADMIN_ALLOW_PLAINTEXT=1 only for a \
         local dev stack"
    )]
    PlaintextRefused,
}

/// Deployment gate for the admin plane. The command signature is the authorization; transport
/// authentication is the operator identity's NATS/mTLS connection (DESIGN.md §A3b), so a plaintext
/// NATS URL is refused unless the operator explicitly opts out for a dev stack.
pub fn admin_plane_allowed(
    nats_url: &str,
    operator_configured: bool,
    allow_plaintext: bool,
) -> Result<(), AdminPlaneError> {
    if !operator_configured {
        return Err(AdminPlaneError::NoOperatorKey);
    }
    if !allow_plaintext && !nats_url.starts_with("tls://") {
        return Err(AdminPlaneError::PlaintextRefused);
    }
    Ok(())
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
pub struct AdminService<S: AdminState> {
    operator_pk: VerifyingKey,
    expected_signer_fp: Fingerprint,
    replay: S,
}

impl<S: AdminState> AdminService<S> {
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

    /// Stateful commands execute their SQL, replay insert, and audit row in one backend
    /// transaction. A backend without durable commands falls back to an audited
    /// `not_implemented`, so the seq/nonce is still consumed exactly once.
    fn commit_stateful(
        &mut self,
        now: u64,
        command: &AdminCommand,
        mutation: AdminMutation<'_>,
    ) -> Result<Vec<u8>, AdminRefusal> {
        match self.replay.commit_mutation(
            now,
            &self.expected_signer_fp,
            command.seq,
            &command.nonce,
            &command.cmd,
            mutation,
        ) {
            Ok(Some(MutationOutcome::Applied)) => {
                Ok(AdminReply::Ok { result: None }.to_canonical_bytes())
            }
            Ok(Some(MutationOutcome::NotFound)) => Ok(refusal_bytes(&AdminRefusal::NotFound)),
            Ok(None) => Err(AdminRefusal::Replay),
            Err(AdminStateError::Unsupported) => {
                if !self
                    .replay
                    .commit(
                        now,
                        &self.expected_signer_fp,
                        command.seq,
                        &command.nonce,
                        &command.cmd,
                        AdminRefusal::NotImplemented.code(),
                    )
                    .map_err(AdminRefusal::State)?
                {
                    return Err(AdminRefusal::Replay);
                }
                Ok(refusal_bytes(&AdminRefusal::NotImplemented))
            }
            Err(error) => Err(AdminRefusal::State(error)),
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
        if self
            .replay
            .is_replay(&self.expected_signer_fp, command.seq, &command.nonce)
            .map_err(AdminRefusal::State)?
        {
            return Err(AdminRefusal::Replay);
        }

        // Read-only commands are implemented here; the stateful ones remain typed not_implemented
        // until their store transitions exist (slice 4 of td-efea19).
        let (reply, result_code) = match command.cmd.as_str() {
            "list_hosts" => (
                AdminReply::Ok {
                    result: Some(self.replay.list_hosts().map_err(AdminRefusal::State)?),
                },
                "ok",
            ),
            "pre_register_host" => match parse_host_args(&command.args, true) {
                Some((host_fp, label, quota)) => {
                    return self.commit_stateful(
                        now,
                        &command,
                        AdminMutation::PreRegisterHost {
                            host_fp: &host_fp,
                            label: &label,
                            quota_profile: &quota,
                        },
                    )
                }
                None => (
                    AdminReply::Refused {
                        code: AdminRefusal::BadArgs.code().to_string(),
                        message: None,
                    },
                    "invalid_args",
                ),
            },
            "set_quota_profile" => match parse_host_args(&command.args, false) {
                Some((host_fp, _label, quota)) => {
                    return self.commit_stateful(
                        now,
                        &command,
                        AdminMutation::SetQuotaProfile {
                            host_fp: &host_fp,
                            quota_profile: &quota,
                        },
                    )
                }
                None => (
                    AdminReply::Refused {
                        code: AdminRefusal::BadArgs.code().to_string(),
                        message: None,
                    },
                    "invalid_args",
                ),
            },
            "suspend_host" | "evict_host" => match parse_host_fp(&command.args) {
                None => (
                    AdminReply::Refused {
                        code: AdminRefusal::BadArgs.code().to_string(),
                        message: None,
                    },
                    "invalid_args",
                ),
                Some(host_fp) => {
                    let host_state = if command.cmd == "evict_host" {
                        HostState::Evicted
                    } else {
                        HostState::Suspended
                    };
                    return self.commit_stateful(
                        now,
                        &command,
                        AdminMutation::SetHostState {
                            host_fp: &host_fp,
                            state: host_state,
                        },
                    );
                }
            },
            "set_mode" => match parse_mode(&command.args) {
                None => (
                    AdminReply::Refused {
                        code: AdminRefusal::BadArgs.code().to_string(),
                        message: None,
                    },
                    "invalid_args",
                ),
                Some(mode) => {
                    return self.commit_stateful(now, &command, AdminMutation::SetMode(mode))
                }
            },
            "read_audit_log" => (
                AdminReply::Ok {
                    result: Some(
                        self.replay
                            .read_audit_log(MAX_AUDIT_PAGE)
                            .map_err(AdminRefusal::State)?,
                    ),
                },
                "ok",
            ),
            _ => (
                AdminReply::Refused {
                    code: AdminRefusal::NotImplemented.code().to_string(),
                    message: None,
                },
                AdminRefusal::NotImplemented.code(),
            ),
        };
        if !self
            .replay
            .commit(
                now,
                &self.expected_signer_fp,
                command.seq,
                &command.nonce,
                &command.cmd,
                result_code,
            )
            .map_err(AdminRefusal::State)?
        {
            return Err(AdminRefusal::Replay);
        }
        Ok(reply.to_canonical_bytes())
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
            &command(&op, "mint_invite", 1, 0x01, NOW).to_canonical_bytes(),
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
        let first = command(&op, "mint_invite", 7, 3, NOW).to_canonical_bytes();
        assert_eq!(
            decode_reply(&service.handle(&first, NOW)).1.as_deref(),
            Some("not_implemented")
        );
        // Same seq, fresh nonce.
        let same_seq = command(&op, "mint_invite", 7, 4, NOW).to_canonical_bytes();
        assert_eq!(
            decode_reply(&service.handle(&same_seq, NOW)).1.as_deref(),
            Some("replay")
        );
        // Later seq, same nonce.
        let same_nonce = command(&op, "mint_invite", 8, 3, NOW).to_canonical_bytes();
        assert_eq!(
            decode_reply(&service.handle(&same_nonce, NOW)).1.as_deref(),
            Some("replay")
        );
    }

    fn result_array_len(bytes: &[u8]) -> usize {
        let map = canonical_decode(bytes).expect("canonical reply");
        let map = map.as_map().expect("reply map");
        map.iter()
            .find(|(k, _)| k.as_text() == Some("result"))
            .and_then(|(_, v)| v.as_array())
            .map(|rows| rows.len())
            .expect("result array")
    }

    #[test]
    fn set_mode_requires_a_valid_argument_and_a_durable_backend() {
        let op = operator();
        let with_mode = |mode: &str| {
            issue_admin_command(
                &op,
                1,
                "set_mode".to_string(),
                CborValue::map(vec![("mode", CborValue::text(mode))]),
                signer_fp().to_vec(),
                1,
                vec![0x21; 16],
                NOW,
            )
        };
        let mut durable = service();
        assert_eq!(
            decode_reply(&durable.handle(&with_mode("closed").to_canonical_bytes(), NOW))
                .1
                .as_deref(),
            Some("not_implemented"),
            "the in-memory backend has no durable mode"
        );
        let mut bad_mode = service();
        assert_eq!(
            decode_reply(&bad_mode.handle(&with_mode("bogus").to_canonical_bytes(), NOW))
                .1
                .as_deref(),
            Some("invalid_args")
        );
        let missing = issue_admin_command(
            &op,
            1,
            "set_mode".to_string(),
            CborValue::Null,
            signer_fp().to_vec(),
            1,
            vec![0x22; 16],
            NOW,
        );
        let mut bad_args = service();
        assert_eq!(
            decode_reply(&bad_args.handle(&missing.to_canonical_bytes(), NOW))
                .1
                .as_deref(),
            Some("invalid_args")
        );
    }

    #[test]
    fn host_commands_on_the_memory_backend_are_not_implemented_and_validate_args() {
        let op = operator();
        let host_fp = Fingerprint::of_parts(&[b"host"]);
        let args = |label: Option<&str>, quota: &str| {
            let mut entries = vec![
                ("host_fp", CborValue::bytes(host_fp.as_bytes().to_vec())),
                ("quota_profile", CborValue::text(quota)),
            ];
            if let Some(label) = label {
                entries.push(("label", CborValue::text(label)));
            }
            CborValue::map(entries)
        };
        let cmd = |name: &str, args: CborValue, seq: u64, nonce: u8| {
            issue_admin_command(
                &op,
                1,
                name.to_string(),
                args,
                signer_fp().to_vec(),
                seq,
                vec![nonce; 16],
                NOW,
            )
        };

        let mut first = service();
        assert_eq!(
            decode_reply(&first.handle(
                &cmd("pre_register_host", args(Some("h"), "gold"), 1, 0x31).to_canonical_bytes(),
                NOW
            ))
            .1
            .as_deref(),
            Some("not_implemented")
        );
        let mut second = service();
        assert_eq!(
            decode_reply(&second.handle(
                &cmd("pre_register_host", args(None, "gold"), 1, 0x32).to_canonical_bytes(),
                NOW
            ))
            .1
            .as_deref(),
            Some("invalid_args")
        );
        let mut third = service();
        assert_eq!(
            decode_reply(&third.handle(
                &cmd("set_quota_profile", args(None, ""), 1, 0x33).to_canonical_bytes(),
                NOW
            ))
            .1
            .as_deref(),
            Some("invalid_args")
        );
    }

    #[test]
    fn host_lifecycle_commands_validate_args_and_refuse_on_memory() {
        let op = operator();
        let host_fp = Fingerprint::of_parts(&[b"host"]);
        let args = CborValue::map(vec![(
            "host_fp",
            CborValue::bytes(host_fp.as_bytes().to_vec()),
        )]);
        let cmd = |name: &str, args: CborValue, seq: u64, nonce: u8| {
            issue_admin_command(
                &op,
                1,
                name.to_string(),
                args,
                signer_fp().to_vec(),
                seq,
                vec![nonce; 16],
                NOW,
            )
        };
        let mut backend = service();
        assert_eq!(
            decode_reply(&backend.handle(
                &cmd("suspend_host", args, 1, 0x41).to_canonical_bytes(),
                NOW
            ))
            .1
            .as_deref(),
            Some("not_implemented")
        );
        let mut bad = service();
        assert_eq!(
            decode_reply(&bad.handle(
                &cmd("evict_host", CborValue::Null, 1, 0x42).to_canonical_bytes(),
                NOW
            ))
            .1
            .as_deref(),
            Some("invalid_args")
        );
    }

    #[test]
    fn read_only_commands_return_results() {
        let op = operator();
        let mut service = service();
        let list = service.handle(
            &command(&op, "list_hosts", 1, 0x11, NOW).to_canonical_bytes(),
            NOW,
        );
        assert_eq!(decode_reply(&list), (true, None));
        assert_eq!(result_array_len(&list), 0);

        let audit = service.handle(
            &command(&op, "read_audit_log", 2, 0x12, NOW).to_canonical_bytes(),
            NOW,
        );
        assert_eq!(decode_reply(&audit), (true, None));
        assert_eq!(
            result_array_len(&audit),
            1,
            "the audit read sees the previous list_hosts entry, not itself"
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
    fn the_admin_deployment_gate_requires_a_tls_url_unless_opted_out() {
        assert_eq!(
            admin_plane_allowed("nats://localhost:4222", false, true),
            Err(AdminPlaneError::NoOperatorKey)
        );
        assert_eq!(
            admin_plane_allowed("nats://localhost:4222", true, false),
            Err(AdminPlaneError::PlaintextRefused)
        );
        assert_eq!(
            admin_plane_allowed("nats://localhost:4222", true, true),
            Ok(())
        );
        assert_eq!(
            admin_plane_allowed("tls://registry:4222", true, false),
            Ok(())
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
