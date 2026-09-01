//! `spindle-helper`'s real service binary: the NATS Auth Callout responder (DESIGN.md §A4, §A5),
//! wiring the pure decision core (`spindle_helper::authz`) to a live `nats-server`.
//!
//! Graduated from `spikes/s1-callout/src/bin/responder.rs` (docs/SPIKES.md §S1 — **PASS**,
//! 19/19 automated checks against a live `nats-server:2.10-alpine` v2.10.29, 2026-08-24; full
//! record in `spikes/s1-callout/RESULTS.md`). What changed graduating it: config now comes from
//! env/flags instead of being spike-hardcoded, `println!`/`eprintln!` became `tracing`, errors
//! are typed (`spindle_helper::natsjwt::NatsJwtError`, `spindle_helper::auth_token::AuthTokenError`)
//! instead of `anyhow`, the in-memory store lives in the library
//! (`spindle_helper::memory_store::InMemoryHelperView`) behind the swappable
//! `spindle_helper::authz::HelperView` trait, and shutdown is graceful (`Ctrl-C`/`SIGINT` drains
//! the responder loop instead of the process being killed out from under it). The actual
//! decision-making — `spindle_helper::authz::{decide_device_connect, decide_host_connect}` — is
//! untouched: this binary is wiring, not policy.
//!
//! # Two connections (DESIGN.md §A5 "Helper account bridging [DEFAULT]", ADR-002's topology
//! table, confirmed by S1's `bridging_callout_account_cannot_reach_app_subjects` check)
//! NATS accounts are hard subject-space boundaries, not permission lists — no `pub`/`sub`
//! permission list on one connection can reach a different account's subject space. This binary
//! therefore holds **two separate connections**, matching what S1 empirically proved is required:
//! - `callout_client` — on the system/auth account, authenticated with `CALLOUT_USER_SEED` (an
//!   nkey exempted from the callout itself via the server's `auth_callout.auth_users`).
//!   Subscribes to `$SYS.REQ.USER.AUTH` and is the only connection this slice's responder loop
//!   uses.
//! - `app_client` — on the application account, authenticated with `APP_CONN_SEED` (a second
//!   exempted nkey, distinct from `APP_ACCOUNT_SEED`, which is the account's own *signing* key
//!   used to sign User JWTs and is never used to open a connection). Answers `helper.turn.get.
//!   <nfp>` and `helper.presence.get.<nfp>`, publishes `host.<hfp>.presence` deltas, and ingests
//!   `registry.revoke.<hfp>` publishes (leg 2 of DESIGN.md §A4's revoke -> kick -> reject chain —
//!   see `spindle_helper::revoke`'s module doc; this subject is publish-only, no reply). The rest
//!   of `registry.*` request/reply remains later work. Optional: if `APP_CONN_SEED` is unset, this
//!   binary logs a warning per degraded feature and runs with the callout connection only.
//!
//! # Presence (DESIGN.md §A3/§A6, subject parametrized in v0.9.8 the same way `helper.turn.get`
//! was in v0.9.7)
//! A dedicated `sys_client` (genuine SYS-account connection — see `sys_conn_seed`'s doc comment
//! below for why `callout_client`'s AUTH-account membership is not sufficient) subscribes to
//! `$SYS.ACCOUNT.*.CONNECT` and `$SYS.ACCOUNT.*.DISCONNECT` and, once at startup, requests
//! `$SYS.REQ.SERVER.PING.CONNZ` to seed [`spindle_helper::presence::ConnectionMap`] with whatever
//! connections predate this process (see `seed_maps`'s doc comment for the exact fold logic and
//! its one flagged gap — that same request now also seeds the kick relay's `KickMap`, see this
//! file's "Kick relay" section below). Every DISCONNECT additionally triggers
//! [`HelperView::delete_session_record`] for that connection's `nats_fp`, host or device alike
//! (DESIGN.md §A5's "cleaned up on DISCONNECT/expiry"). See `spindle_helper::presence`'s own
//! module doc for the wire schema, and this file's `seed_maps`/`user_from_sys_event` doc
//! comments and their `#[cfg(test)] mod tests` for the real, live-verified `$SYS`/CONNZ payload
//! shapes (spikes/s5-presence, docs/SPIKES.md §S5 — two shapes were wrong on the first pass, see
//! that spike's RESULTS.md), and the explicit list of what's still out of scope (kick relay,
//! split-brain, multi-server `CONNZ`, leader-only publishing).
//!
//! # Kick relay (DESIGN.md §A3/§A4, S9 leg 3 — see `spindle_helper::kick`'s module doc for the
//! pure planning core)
//! A revocation accepted on `app_client` (`registry.revoke.<hfp>`) is planned against `kick_map`,
//! which is armed from two independent sources: live `$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT`
//! advisories on `sys_client` below, and the same startup `$SYS.REQ.SERVER.PING.CONNZ` reply that
//! seeds presence (`seed_maps`). Because the advisory and revocation paths are two separate TCP
//! connections with no ordering guarantee between them, a revocation can be planned before its
//! own triggering CONNECT advisory has arrived — a real defect found and fixed post-graduation
//! (not a spike finding): the failing sequence was CONNECT queued -> revoke processed against an
//! unarmed map -> CONNECT drained too late to matter. [`kick::KickPlan::unresolved`] exists so
//! that miss is a named retry list, not a silently-dropped count: the revoke branch schedules a
//! delayed re-plan (`KICK_REPLAN_DELAY` below — sized to outlast the advisory backlog, not
//! guessed), and anything still unresolved after that falls back to an on-demand
//! `connz_kick_fallback` request, which is the honest last word — if the server's own connection
//! table doesn't know about it either, there is nothing left to kick.
//!
//! # `verify_nkey_sig` (DESIGN.md §A4 step 1: "signing the server nonce with its session nkey")
//! Satisfied the same way S1 proved it: the authorization request's `connect_opts.sig` is the
//! client's session nkey signing the server-issued nonce (`client_info.nonce`), verified via
//! `nkeys::KeyPair::from_public_key(connect_opts.nkey)?.verify(nonce, sig)`. `connect_opts.nkey`
//! (== `client_info.user`) is the client's *actual* presented nkey — distinct from
//! `nats.user_nkey`, a server-generated per-request correlation key used only to address the
//! response (see `spindle_helper::natsjwt`'s module docs).
//!
//! # Store
//! Runs with `spindle_helper::memory_store::InMemoryHelperView` — not durable, dev/demo only (see
//! that module's docs). A Postgres-backed `HelperView` (Stage 4 slice 3) drops in at the single
//! construction site below with no change to the rest of this file.

use base64::Engine;
use futures_util::StreamExt;
use nkeys::KeyPair;
use spindle_helper::auth_token::{self, DecodedAuthToken};
use spindle_helper::authz::{
    self, AdmissionMode, AdmissionRecord, AuthzDecision, DeviceConnectPresented, HelperView,
    HostConnectPresented,
};
use spindle_helper::kick;
use spindle_helper::memory_store::InMemoryHelperView;
use spindle_helper::natsjwt::{self, NatsJwtError};
use spindle_helper::permissions::{Limits, SubjectPermissions};
use spindle_helper::pg_store::PgStore;
use spindle_helper::presence;
use spindle_helper::revoke;
use spindle_helper::session::SessionRecord;
use spindle_helper::turn::{self, TurnConfig};
use std::env;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ================================================================================================
// Config
// ================================================================================================

/// Runtime configuration: env vars first, then `--flag value` overrides (flags win). Every field
/// has a `--help`-documented env-var equivalent so this binary runs the same way under
/// `docker compose` (env-only) and interactively (flags for quick overrides).
struct Config {
    nats_url: String,
    /// nkey seed for the callout/system-account connection (exempted from the callout itself).
    callout_user_seed: String,
    /// The application account's own signing key — signs every User JWT and
    /// `AuthorizationResponse` this responder issues. Never used to open a connection.
    app_account_seed: String,
    /// The target account NAME (`aud` on the issued User JWT) — see `natsjwt`'s module docs on
    /// why this must be a name, not a public key.
    account_name: String,
    /// nkey seed for the helper's own application-account connection. Optional in this slice
    /// (nothing here uses it yet); see this file's module docs.
    app_conn_seed: Option<String>,
    /// nkey seed for a dedicated, genuine-SYS-account connection. Required to actually *receive*
    /// `$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT` presence events — spikes/s5-presence (docs/
    /// SPIKES.md §S5) found live that these are ordinary pub/sub broadcasts published on the SYS
    /// account, unlike `$SYS.REQ.USER.AUTH`/`$SYS.REQ.SERVER.PING.CONNZ` (special-cased request/
    /// reply subjects nats-server answers to any `auth_callout.auth_users` connection regardless
    /// of its own account). Unset → those subscriptions are opened on `callout_client` as before
    /// and will silently never fire outside a SYS-account connection; loud warning, not fatal
    /// (mirrors `app_conn_seed`'s optionality — dev flexibility over hard-failing).
    sys_conn_seed: Option<String>,
    /// Operator admission-key seed, for verifying presented admission tokens. Falls back to a
    /// fixed dev-only key (matching the S1 spike) if unset — loud warning, never for production.
    operator_seed: Option<String>,
    admission_mode: AdmissionMode,
    /// Postgres connection string (Stage 4 slice 3). Set → `PgStore` (durable, migrations run at
    /// startup, fail fast if unreachable). Unset → `InMemoryHelperView` (ephemeral, dev/demo).
    database_url: Option<String>,
    /// coturn's `static-auth-secret` (DESIGN.md §A8). Unset → `helper.turn.get.<nfp>` replies
    /// with a clear "TURN not configured" error instead of minting anything.
    turn_secret: Option<String>,
    /// Comma-separated ICE server URIs handed back verbatim in `helper.turn.get.<nfp>` replies.
    turn_uris: Vec<String>,
    turn_ttl_secs: u64,
    turn_monthly_quota: u64,
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("missing required env var {0} (or --{1} flag)")]
    Missing(&'static str, &'static str),
    #[error("invalid value {given:?} for --admission-mode / ADMISSION_MODE (expected open|invite|closed)")]
    BadAdmissionMode { given: String },
    #[error("--{0} requires a value")]
    FlagMissingValue(String),
    #[error("unrecognized argument: {0}")]
    UnknownArg(String),
    #[error("invalid value {given:?} for --{flag} / {env_var} (expected a non-negative integer)")]
    BadInteger {
        flag: &'static str,
        env_var: &'static str,
        given: String,
    },
}

const HELP: &str = r#"spindle-helper — the NATS Auth Callout responder (DESIGN.md §A4/§A5)

USAGE:
    spindle-helper [FLAGS]

Every flag has an env-var equivalent (flags override the env var if both are set):
    --nats-url <url>            NATS_URL            (default: nats://127.0.0.1:4222)
    --callout-seed <seed>       CALLOUT_USER_SEED    (required)
    --app-account-seed <seed>   APP_ACCOUNT_SEED     (required)
    --account-name <name>       ACCOUNT_NAME         (default: APP)
    --app-conn-seed <seed>      APP_CONN_SEED        (optional; application-account connection)
    --sys-conn-seed <seed>      SYS_CONN_SEED        (optional; genuine SYS-account connection for
                                                       $SYS.ACCOUNT.*.CONNECT|DISCONNECT — falls
                                                       back to the callout connection, which won't
                                                       receive them, if unset)
    --operator-seed <seed>      OPERATOR_SEED        (optional; dev-only fallback key if unset)
    --admission-mode <mode>     ADMISSION_MODE       (open|invite|closed; default: open)
    --database-url <url>        DATABASE_URL         (optional; Postgres — unset uses the in-memory store)
    --turn-secret <secret>      TURN_SECRET          (optional; unset refuses helper.turn.get.<nfp> requests)
    --turn-uris <a,b,...>       TURN_URIS            (comma-separated; default: empty)
    --turn-ttl-secs <n>         TURN_TTL_SECS         (default: 3600)
    --turn-monthly-quota <n>    TURN_MONTHLY_QUOTA    (default: 1000)
    -h, --help                  show this message
"#;

impl Config {
    fn from_env_and_args(mut args: impl Iterator<Item = String>) -> Result<Config, ConfigError> {
        let mut nats_url = env::var("NATS_URL").ok();
        let mut callout_user_seed = env::var("CALLOUT_USER_SEED").ok();
        let mut app_account_seed = env::var("APP_ACCOUNT_SEED").ok();
        let mut account_name = env::var("ACCOUNT_NAME").ok();
        let mut app_conn_seed = env::var("APP_CONN_SEED").ok();
        let mut sys_conn_seed = env::var("SYS_CONN_SEED").ok();
        let mut operator_seed = env::var("OPERATOR_SEED").ok();
        let mut admission_mode = env::var("ADMISSION_MODE").ok();
        let mut database_url = env::var("DATABASE_URL").ok();
        let mut turn_secret = env::var("TURN_SECRET").ok();
        let mut turn_uris = env::var("TURN_URIS").ok();
        let mut turn_ttl_secs = env::var("TURN_TTL_SECS").ok();
        let mut turn_monthly_quota = env::var("TURN_MONTHLY_QUOTA").ok();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print!("{HELP}");
                    std::process::exit(0);
                }
                "--nats-url" => {
                    nats_url = Some(
                        args.next()
                            .ok_or_else(|| ConfigError::FlagMissingValue("nats-url".to_string()))?,
                    )
                }
                "--callout-seed" => {
                    callout_user_seed =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("callout-seed".to_string())
                        })?)
                }
                "--app-account-seed" => {
                    app_account_seed = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("app-account-seed".to_string())
                    })?)
                }
                "--account-name" => {
                    account_name =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("account-name".to_string())
                        })?)
                }
                "--app-conn-seed" => {
                    app_conn_seed = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("app-conn-seed".to_string())
                    })?)
                }
                "--sys-conn-seed" => {
                    sys_conn_seed = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("sys-conn-seed".to_string())
                    })?)
                }
                "--operator-seed" => {
                    operator_seed = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("operator-seed".to_string())
                    })?)
                }
                "--admission-mode" => {
                    admission_mode = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("admission-mode".to_string())
                    })?)
                }
                "--database-url" => {
                    database_url =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("database-url".to_string())
                        })?)
                }
                "--turn-secret" => {
                    turn_secret =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("turn-secret".to_string())
                        })?)
                }
                "--turn-uris" => {
                    turn_uris =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("turn-uris".to_string())
                        })?)
                }
                "--turn-ttl-secs" => {
                    turn_ttl_secs = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("turn-ttl-secs".to_string())
                    })?)
                }
                "--turn-monthly-quota" => {
                    turn_monthly_quota = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("turn-monthly-quota".to_string())
                    })?)
                }
                other => return Err(ConfigError::UnknownArg(other.to_string())),
            }
        }

        let admission_mode = match admission_mode.as_deref().unwrap_or("open") {
            "open" => AdmissionMode::Open,
            "invite" => AdmissionMode::Invite,
            "closed" => AdmissionMode::Closed,
            other => {
                return Err(ConfigError::BadAdmissionMode {
                    given: other.to_string(),
                })
            }
        };

        let turn_ttl_secs = match turn_ttl_secs {
            Some(s) => s.parse::<u64>().map_err(|_| ConfigError::BadInteger {
                flag: "turn-ttl-secs",
                env_var: "TURN_TTL_SECS",
                given: s,
            })?,
            None => 3_600,
        };
        let turn_monthly_quota = match turn_monthly_quota {
            Some(s) => s.parse::<u64>().map_err(|_| ConfigError::BadInteger {
                flag: "turn-monthly-quota",
                env_var: "TURN_MONTHLY_QUOTA",
                given: s,
            })?,
            None => 1_000,
        };
        let turn_uris = turn_uris
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Config {
            nats_url: nats_url.unwrap_or_else(|| "nats://127.0.0.1:4222".to_string()),
            callout_user_seed: callout_user_seed
                .ok_or(ConfigError::Missing("CALLOUT_USER_SEED", "callout-seed"))?,
            app_account_seed: app_account_seed
                .ok_or(ConfigError::Missing("APP_ACCOUNT_SEED", "app-account-seed"))?,
            account_name: account_name.unwrap_or_else(|| "APP".to_string()),
            app_conn_seed,
            sys_conn_seed,
            operator_seed,
            admission_mode,
            database_url,
            turn_secret,
            turn_uris,
            turn_ttl_secs,
            turn_monthly_quota,
        })
    }
}

// ================================================================================================
// main
// ================================================================================================

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match Config::from_env_and_args(env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("spindle-helper: {e}\n\n{HELP}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = run(config).await {
        tracing::error!(error = %e, "spindle-helper exiting on fatal error");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

// ================================================================================================
// Store selection (Stage 4 slice 3): `DATABASE_URL` set → durable `PgStore`; unset →
// `InMemoryHelperView` (ephemeral, dev/demo — see that module's own doc comment).
//
// `authz::decide_device_connect`/`decide_host_connect` and `handle_one` below are generic over
// `impl HelperView` (static dispatch), not `dyn HelperView` — `HelperView`'s methods take `&mut
// impl HelperView` themselves in a couple of call sites' surrounding generic bounds, which are
// `Sized` by default, so a bare trait object doesn't satisfy them without `?Sized` plumbing that
// would ripple beyond this file. A small enum wrapper that delegates every method is the smallest
// diff that lets one `run()` body construct either concrete store and hand it to the same generic
// call sites.
// ================================================================================================

enum Store {
    Memory(Box<InMemoryHelperView>),
    Pg(PgStore),
}

impl HelperView for Store {
    fn revocation_epoch(&mut self, host_fp: &spindle_core::Fingerprint) -> u64 {
        match self {
            Store::Memory(s) => s.revocation_epoch(host_fp),
            Store::Pg(s) => s.revocation_epoch(host_fp),
        }
    }

    fn is_revoked(
        &mut self,
        host_fp: &spindle_core::Fingerprint,
        subject: &spindle_core::Fingerprint,
    ) -> bool {
        match self {
            Store::Memory(s) => s.is_revoked(host_fp, subject),
            Store::Pg(s) => s.is_revoked(host_fp, subject),
        }
    }

    fn admission_mode(&mut self) -> AdmissionMode {
        match self {
            Store::Memory(s) => s.admission_mode(),
            Store::Pg(s) => s.admission_mode(),
        }
    }

    fn admission_record(&mut self, host_fp: &spindle_core::Fingerprint) -> Option<AdmissionRecord> {
        match self {
            Store::Memory(s) => s.admission_record(host_fp),
            Store::Pg(s) => s.admission_record(host_fp),
        }
    }

    fn operator_pk(&mut self) -> spindle_core::VerifyingKey {
        match self {
            Store::Memory(s) => s.operator_pk(),
            Store::Pg(s) => s.operator_pk(),
        }
    }

    fn burn_admission_token(
        &mut self,
        host_fp: spindle_core::Fingerprint,
        nonce: Vec<u8>,
        label: String,
        quota_profile: String,
        admitted_at: u64,
    ) -> Option<AdmissionRecord> {
        match self {
            Store::Memory(s) => {
                s.burn_admission_token(host_fp, nonce, label, quota_profile, admitted_at)
            }
            Store::Pg(s) => {
                s.burn_admission_token(host_fp, nonce, label, quota_profile, admitted_at)
            }
        }
    }

    fn put_session_record(&mut self, record: SessionRecord) {
        match self {
            Store::Memory(s) => s.put_session_record(record),
            Store::Pg(s) => s.put_session_record(record),
        }
    }

    fn session_record(
        &mut self,
        nats_fp: &spindle_core::Fingerprint,
        now: u64,
    ) -> Option<SessionRecord> {
        match self {
            Store::Memory(s) => s.session_record(nats_fp, now),
            Store::Pg(s) => s.session_record(nats_fp, now),
        }
    }

    fn delete_session_record(&mut self, nats_fp: &spindle_core::Fingerprint) {
        match self {
            Store::Memory(s) => s.delete_session_record(nats_fp),
            Store::Pg(s) => s.delete_session_record(nats_fp),
        }
    }

    fn sessions_for_subject(
        &mut self,
        subject: &spindle_core::Fingerprint,
        now: u64,
    ) -> Vec<SessionRecord> {
        match self {
            Store::Memory(s) => s.sessions_for_subject(subject, now),
            Store::Pg(s) => s.sessions_for_subject(subject, now),
        }
    }

    fn record_turn_issuance(
        &mut self,
        root_fp: &spindle_core::Fingerprint,
        now: u64,
        monthly_quota: u64,
    ) -> Result<u64, u64> {
        match self {
            Store::Memory(s) => s.record_turn_issuance(root_fp, now, monthly_quota),
            Store::Pg(s) => s.record_turn_issuance(root_fp, now, monthly_quota),
        }
    }

    fn record_revocation(
        &mut self,
        host_fp: spindle_core::Fingerprint,
        epoch: u64,
        revoked_subjects: &[spindle_core::Fingerprint],
    ) {
        match self {
            Store::Memory(s) => s.record_revocation(host_fp, epoch, revoked_subjects),
            Store::Pg(s) => s.record_revocation(host_fp, epoch, revoked_subjects),
        }
    }

    fn purge_expired_sessions(&mut self, now: u64) {
        match self {
            Store::Memory(s) => s.purge_expired_sessions(now),
            Store::Pg(s) => s.purge_expired_sessions(now),
        }
    }
}

/// Waits on `sub` if present, otherwise never resolves — lets an optional `async_nats::Subscriber`
/// sit as a `tokio::select!` branch that simply never fires when the application connection (and
/// therefore `helper.turn.get.<nfp>`) isn't configured (`APP_CONN_SEED` unset).
async fn next_or_pending(sub: &mut Option<async_nats::Subscriber>) -> Option<async_nats::Message> {
    match sub {
        Some(s) => s.next().await,
        None => std::future::pending().await,
    }
}

/// How long the revoke branch waits before re-planning kicks against `kick_map`'s later state,
/// after an initial [`kick::kicks_for_revocation`] plan reports one or more
/// [`kick::KickPlan::unresolved`] sessions (this file's "Kick relay" module-doc section explains
/// why a miss here isn't necessarily permanent: the CONNECT advisory that would have armed
/// `kick_map` may simply not have arrived on `sys_client` yet, independently of the revocation
/// that already landed on `app_client`).
///
/// Sized from measurement, not guessed: the failing run that exposed this defect had a queued-
/// advisory-to-drain backlog of about 15.6 ms. `250` ms is roughly an order of magnitude of
/// headroom over that, cheap because a revocation with an unresolved session is expected to be
/// rare, and short enough that a legitimately-gone connection is still kicked promptly by the
/// `connz_kick_fallback` a still-unresolved retry falls through to.
const KICK_REPLAN_DELAY: Duration = Duration::from_millis(250);

async fn run(config: Config) -> anyhow::Result<()> {
    let app_kp = KeyPair::from_seed(&config.app_account_seed)
        .map_err(|e| anyhow::anyhow!("bad APP_ACCOUNT_SEED: {e}"))?;

    let operator_pk = match &config.operator_seed {
        Some(seed) => {
            let (_, raw) =
                nkeys::decode_seed(seed).map_err(|e| anyhow::anyhow!("bad OPERATOR_SEED: {e}"))?;
            verifying_key_from_raw(&raw)?
        }
        None => {
            tracing::warn!(
                "OPERATOR_SEED not set — using a fixed dev-only operator key; admission tokens \
                 signed by any real operator will never verify. Never use this in production."
            );
            verifying_key_from_raw(&[0xEE; 32])?
        }
    };

    tracing::info!(admission_mode = ?config.admission_mode, "starting spindle-helper");

    let callout_client = async_nats::ConnectOptions::with_nkey(config.callout_user_seed.clone())
        .connect(&config.nats_url)
        .await?;
    tracing::info!("callout/system connection established, subscribing to $SYS.REQ.USER.AUTH");

    // The application-account connection (DESIGN.md §A5's two-connection bridging — see this
    // file's module docs). Optional in this slice's callout wiring, but Stage 4 slice 3's
    // `helper.turn.get.<nfp>` handling needs it — see the `turn_sub` subscription below.
    let app_client = match &config.app_conn_seed {
        Some(seed) => {
            let client = async_nats::ConnectOptions::with_nkey(seed.clone())
                .connect(&config.nats_url)
                .await?;
            tracing::info!("application-account connection established");
            Some(client)
        }
        None => {
            tracing::warn!(
                "APP_CONN_SEED not set — running with the callout connection only; helper.turn.get.<nfp> \
                 and future presence/registry work will need it"
            );
            None
        }
    };

    // `helper.turn.get.*` — DESIGN.md §A5 v0.9.7 (A12 #45): the subject is parametrized by the
    // caller's own `nats_fp` (the callout only ever grants `pub helper.turn.get.<own_nats_fp>`,
    // see `permissions::client_member_permissions`), so this subscription wildcards the final
    // token and `handle_turn_get` recovers `<nfp>` from `msg.subject` itself, never from the
    // payload.
    let mut turn_sub: Option<async_nats::Subscriber> = match &app_client {
        Some(client) => Some(client.subscribe("helper.turn.get.*").await?),
        None => None,
    };

    let turn_config = match &config.turn_secret {
        Some(secret) => Some(TurnConfig {
            secret: secret.clone(),
            uris: config.turn_uris.clone(),
            ttl_secs: config.turn_ttl_secs,
            monthly_quota: config.turn_monthly_quota,
        }),
        None => {
            tracing::warn!(
                "TURN_SECRET not set — helper.turn.get.<nfp> will refuse every request with \
                 'TURN not configured'"
            );
            None
        }
    };

    // Store selection (Stage 4 slice 3): DATABASE_URL set → durable PgStore (migrations run here,
    // fail fast on any connection/migration error); unset → ephemeral InMemoryHelperView.
    let mut store = match &config.database_url {
        Some(url) => {
            tracing::info!("DATABASE_URL set — connecting to Postgres and running migrations");
            let pg = PgStore::connect(url, config.admission_mode, operator_pk)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("failed to connect to Postgres / run migrations: {e}")
                })?;
            tracing::info!("Postgres store ready");
            Store::Pg(pg)
        }
        None => {
            tracing::warn!(
                "DATABASE_URL not set — running with the in-memory store; every revocation, \
                 admission, session, and TURN-usage fact is lost on restart. Never use this in \
                 production."
            );
            Store::Memory(Box::new(InMemoryHelperView::new(
                config.admission_mode,
                operator_pk,
            )))
        }
    };

    let mut sub = callout_client.subscribe("$SYS.REQ.USER.AUTH").await?;

    // Presence (DESIGN.md §A3/§A6 — see this file's module docs). `$SYS.ACCOUNT.*.CONNECT` and
    // `.DISCONNECT` are ordinary pub/sub broadcasts published *on* the SYS account (unlike
    // `$SYS.REQ.USER.AUTH`/`$SYS.REQ.SERVER.PING.CONNZ`, which nats-server answers to any
    // `auth_callout.auth_users` connection regardless of its own account) — spikes/s5-presence
    // (docs/SPIKES.md §S5) found live that subscribing for them on `callout_client` (an AUTH-
    // account connection) silently receives nothing. `sys_client` is a dedicated connection with
    // genuine SYS-account membership; falls back to `callout_client` (with a loud warning) if
    // `SYS_CONN_SEED` is unset, matching that pre-S5 (broken) behavior rather than hard-failing.
    let sys_client = match &config.sys_conn_seed {
        Some(seed) => {
            let client = async_nats::ConnectOptions::with_nkey(seed.clone())
                .connect(&config.nats_url)
                .await?;
            tracing::info!("SYS-account connection established");
            Some(client)
        }
        None => {
            tracing::warn!(
                "SYS_CONN_SEED not set — subscribing to $SYS.ACCOUNT.*.CONNECT|DISCONNECT on the \
                 callout connection instead, which is not a SYS-account member and will silently \
                 never receive them (see spikes/s5-presence/RESULTS.md's root-cause writeup)"
            );
            None
        }
    };
    let sys_ref = sys_client.as_ref().unwrap_or(&callout_client);

    let mut connect_sub: Option<async_nats::Subscriber> =
        Some(sys_ref.subscribe("$SYS.ACCOUNT.*.CONNECT").await?);
    let mut disconnect_sub: Option<async_nats::Subscriber> =
        Some(sys_ref.subscribe("$SYS.ACCOUNT.*.DISCONNECT").await?);

    // `helper.presence.get.*` — same subject-parametrization shape as `helper.turn.get.*` above
    // (DESIGN.md v0.9.8, pending doc amendment — see `spindle_helper::presence`'s module doc).
    let mut presence_sub: Option<async_nats::Subscriber> = match &app_client {
        Some(client) => Some(client.subscribe("helper.presence.get.*").await?),
        None => None,
    };

    // `registry.revoke.*` — DESIGN.md §A5: the subject is parametrized by the publishing host's
    // own `host_fp` (the callout only ever grants a host `pub registry.revoke.<own_host_fp>`, see
    // `permissions::host_permissions`), so this subscription wildcards the final token and
    // `revoke::ingest_revocation` recovers `<hfp>` from `msg.subject` itself and checks it against
    // the decoded record's own `host_fp` field (see that module's doc comment). Publish-only: no
    // reply is ever sent on this subject.
    let mut revoke_sub: Option<async_nats::Subscriber> = match &app_client {
        Some(client) => Some(client.subscribe("registry.revoke.*").await?),
        None => None,
    };

    // Kick relay (DESIGN.md §A3, S9 leg 3 — see `spindle_helper::kick`'s module doc, and this
    // file's own "Kick relay" module-doc section above). `seed_maps` seeds BOTH maps from the same
    // one CONNZ reply now — `kick_map` used to be fed *only* from live
    // `$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT` events below with no CONNZ-seeding equivalent; that
    // gap is what let a connection established before this helper process started sit unkickable
    // until its next CONNECT, and closing it is exactly `kick.rs`'s former "Out of scope" section
    // graduating (see that module doc's current version).
    let (mut presence_map, mut kick_map) = seed_maps(sys_ref, &mut store, now_secs()).await;

    // Delayed kick re-plan channel (see this file's "Kick relay" module-doc section and
    // `KICK_REPLAN_DELAY`'s own doc comment below). The revoke branch pushes
    // `kick::UnresolvedSession`s here from a spawned `sleep`-then-send task rather than sleeping
    // inline in the select loop itself — the loop must keep servicing every other branch
    // (including the very CONNECT advisory a retry is waiting on) while the delay elapses. `64` is
    // a generous bound on in-flight retries: one send per accepted revocation with a partial miss,
    // not per unresolved session, and revocations are not expected to be a high-frequency subject.
    let (kick_retry_tx, mut kick_retry_rx) =
        tokio::sync::mpsc::channel::<Vec<kick::UnresolvedSession>>(64);

    // Test-only delayed `kick_map` arming channel (see
    // `SPINDLE_HELPER_TEST_ADVISORY_DELAY_MS`'s doc comment at its one use site in the connect
    // branch below for why this exists and why an inline sleep there was wrong). Same shape as
    // `kick_retry_tx`/`kick_retry_rx` above: the delay is a spawned `sleep`-then-send task, never
    // an in-branch `.await` on the sleep itself, so the select loop keeps servicing every other
    // branch (in particular `$SYS.REQ.USER.AUTH`) while the simulated late advisory is in flight.
    // `8` is a generous bound for a test-only knob that only ever fires when the env var is set.
    let (delayed_arm_tx, mut delayed_arm_rx) =
        tokio::sync::mpsc::channel::<(String, String, u64)>(8);

    // Periodic best-effort cleanup of expired session records (DESIGN.md §A9b: "a cleanup path
    // for expired rows (on-read filter + periodic delete — keep simple)"). The on-read `exp`
    // filter in `HelperView::session_record` already makes this a non-correctness-affecting
    // housekeeping task, not a latency-sensitive one, hence the generous interval.
    let mut purge_interval = tokio::time::interval(Duration::from_secs(300));
    purge_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    tracing::info!("responder ready");
    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal received, draining responder loop");
                break;
            }
            msg = sub.next() => {
                let Some(msg) = msg else {
                    tracing::warn!("$SYS.REQ.USER.AUTH subscription ended unexpectedly");
                    break;
                };
                let Some(reply) = msg.reply.clone() else {
                    continue;
                };
                let resp = match handle_one(&msg.payload, &config.account_name, &app_kp, &mut store, &mut presence_map) {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::error!(error = %e, "internal error building callout response");
                        encode_refusal(&msg.payload, &app_kp)
                    }
                };
                if let Some(resp) = resp {
                    if let Err(e) = callout_client.publish(reply, resp.into()).await {
                        tracing::error!(error = %e, "failed to publish callout response");
                    }
                    let _ = callout_client.flush().await;
                }
            }
            msg = next_or_pending(&mut turn_sub) => {
                let Some(msg) = msg else {
                    tracing::warn!("helper.turn.get.* subscription ended unexpectedly");
                    turn_sub = None;
                    continue;
                };
                let Some(reply) = msg.reply.clone() else {
                    continue;
                };
                let reply_payload = turn::handle_turn_get(
                    msg.subject.as_str(),
                    &msg.payload,
                    turn_config.as_ref(),
                    &mut store,
                    now_secs(),
                );
                if let Some(client) = &app_client {
                    if let Err(e) = client.publish(reply, reply_payload.into()).await {
                        tracing::error!(error = %e, "failed to publish helper.turn.get.<nfp> response");
                    }
                    let _ = client.flush().await;
                }
            }
            msg = next_or_pending(&mut presence_sub) => {
                let Some(msg) = msg else {
                    tracing::warn!("helper.presence.get.* subscription ended unexpectedly");
                    presence_sub = None;
                    continue;
                };
                let Some(reply) = msg.reply.clone() else {
                    continue;
                };
                let reply_payload = presence::handle_presence_get(
                    msg.subject.as_str(),
                    &mut store,
                    &presence_map,
                    now_secs(),
                );
                if let Some(client) = &app_client {
                    if let Err(e) = client.publish(reply, reply_payload.into()).await {
                        tracing::error!(error = %e, "failed to publish helper.presence.get.<nfp> response");
                    }
                    let _ = client.flush().await;
                }
            }
            msg = next_or_pending(&mut revoke_sub) => {
                let Some(msg) = msg else {
                    tracing::warn!("registry.revoke.* subscription ended unexpectedly");
                    revoke_sub = None;
                    continue;
                };
                // Publish-only subject (DESIGN.md §A5's subject table lists no reply) — an
                // unparseable or hostile message here never takes the responder down, and there
                // is nothing to publish back either way.
                match revoke::ingest_revocation(msg.subject.as_str(), &msg.payload, &mut store) {
                    revoke::RevokeOutcome::Accepted { host_fp, epoch, revoked_count } => {
                        tracing::info!(
                            %host_fp,
                            epoch,
                            revoked_count,
                            "registry.revoke.<hfp> record accepted"
                        );

                        // Leg 3 (S9): kick every live connection the revocation reaches. This
                        // re-decodes the payload to recover the actual `revoked` fingerprints —
                        // `RevokeOutcome::Accepted` only reports a count (see `revoke.rs`'s doc
                        // comment on that type), and `ingest_revocation` already proved the
                        // payload decodes (it returned `Accepted`), so a decode failure here is
                        // not expected to ever happen; if it somehow did, no kicks are issued for
                        // this record rather than panicking.
                        match spindle_proto::artifacts::RevocationRecord::from_canonical_bytes(&msg.payload) {
                            Ok(record) => {
                                let revoked_fps: Vec<spindle_core::Fingerprint> = record
                                    .revoked
                                    .iter()
                                    .filter_map(|b| spindle_core::Fingerprint::from_slice(b).ok())
                                    .collect();
                                let plan = kick::kicks_for_revocation(
                                    &revoked_fps,
                                    &kick_map,
                                    &mut store,
                                    now_secs(),
                                );
                                if !plan.unresolved.is_empty() {
                                    // `warn!`, not `info!`: this is the exact fail-open this
                                    // defect fix exists for — a revoked session that looked
                                    // unkickable only because its own CONNECT advisory hadn't
                                    // drained into `kick_map` yet (two independent connections,
                                    // no ordering guarantee between `sys_client` and `app_client`
                                    // — see this file's "Kick relay" module-doc section). A
                                    // security-relevant fail-open must survive a production `warn`
                                    // filter, not get buried at `info`.
                                    tracing::warn!(
                                        %host_fp,
                                        unresolved = plan.unresolved.len(),
                                        "revocation matched live session records with no known \
                                         connection to kick yet — scheduling a delayed re-plan"
                                    );
                                    // Do NOT sleep inline here: stalling this `select!` loop for
                                    // `KICK_REPLAN_DELAY` would also stall the very CONNECT
                                    // advisory the retry is waiting on, defeating the fix. Spawn a
                                    // separate task that sleeps and then hands the unresolved list
                                    // back to the loop over `kick_retry_tx`.
                                    let retry_tx = kick_retry_tx.clone();
                                    let unresolved = plan.unresolved;
                                    tokio::spawn(async move {
                                        tokio::time::sleep(KICK_REPLAN_DELAY).await;
                                        let _ = retry_tx.send(unresolved).await;
                                    });
                                }
                                for target in plan.targets {
                                    issue_kick(sys_ref, &target).await;
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    %host_fp,
                                    error = ?e,
                                    "accepted revocation's payload failed to re-decode for the \
                                     kick relay — no kicks issued for this record"
                                );
                            }
                        }
                    }
                    revoke::RevokeOutcome::Rejected(reason) => {
                        tracing::warn!(
                            subject = %msg.subject,
                            reason = %reason,
                            "registry.revoke.<hfp> record rejected"
                        );
                    }
                }
            }
            msg = next_or_pending(&mut connect_sub) => {
                let Some(msg) = msg else {
                    tracing::warn!("$SYS.ACCOUNT.*.CONNECT subscription ended unexpectedly");
                    connect_sub = None;
                    continue;
                };
                // Raw-sample capture for spikes/s5-presence's RESULTS.md (docs/SPIKES.md §S5,
                // task g): the exact shape of a real $SYS.ACCOUNT.*.CONNECT event, ground truth
                // for user_from_sys_event's doc comment's assumption. Debug-level only.
                tracing::debug!(
                    subject = %msg.subject,
                    payload = %String::from_utf8_lossy(&msg.payload),
                    "raw $SYS.ACCOUNT.*.CONNECT event"
                );
                let Some(user_pk) = user_from_sys_event(&msg.payload) else {
                    tracing::warn!(
                        payload = %String::from_utf8_lossy(&msg.payload),
                        "CONNECT event had no recognizable client.user — ignoring"
                    );
                    continue;
                };
                // Kick-relay feed (DESIGN.md §A3, S9): a malformed/missing server.id or
                // client.id just means this connection isn't kickable yet — never fatal, and
                // never blocks presence tracking below.
                if let Some((server_id, cid)) = kick_coords_from_sys_event(&msg.payload) {
                    // TEST-ONLY INSTRUMENTATION, no-op unless explicitly configured. Set
                    // `SPINDLE_HELPER_TEST_ADVISORY_DELAY_MS` to make this defect's race
                    // deterministic under test: it delays arming `kick_map` for this CONNECT by
                    // the given number of milliseconds, which is exactly the window a queued
                    // advisory sat in on the failing run this fix addresses (see this file's
                    // "Kick relay" module-doc section and `KICK_REPLAN_DELAY`'s doc comment for
                    // the measured ~15.6 ms backlog this reproduces on demand). Never read in
                    // production — no env var means no delay and no behavior change at all.
                    //
                    // An inline `tokio::time::sleep` right here — tried first — is WRONG, not just
                    // suboptimal: `tokio::select!` runs exactly one branch's body at a time, so
                    // sleeping inside this branch stalls the *entire* loop, including the
                    // `$SYS.REQ.USER.AUTH` callout branch above. Proved live: with this hook set to
                    // 2000 ms, the helper's own startup connections each stalled the loop for 2 s,
                    // the callout never got a chance to answer, and every subsequent CONNECT was
                    // refused with an unrelated-looking `authorization violation` — the helper log
                    // showed no activity at all after "responder ready". A late CONNECT advisory
                    // must delay only the *arming of `kick_map`*, not the responder's ability to
                    // service anything else, so — mirroring `kick_retry_tx`/`kick_retry_rx` above —
                    // this defers the `kick_map.connect` call itself to a spawned task that sleeps
                    // and then hands the coordinates back to the loop over `delayed_arm_tx`, rather
                    // than blocking this branch on the sleep.
                    match env::var("SPINDLE_HELPER_TEST_ADVISORY_DELAY_MS")
                        .ok()
                        .and_then(|s| s.parse::<u64>().ok())
                        .filter(|&ms| ms > 0)
                    {
                        Some(delay_ms) => {
                            let arm_tx = delayed_arm_tx.clone();
                            let user_pk = user_pk.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                let _ = arm_tx.send((user_pk, server_id, cid)).await;
                            });
                        }
                        None => kick_map.connect(&user_pk, server_id, cid),
                    }
                }
                if let Some(delta) = presence_map.connect(&user_pk, now_secs()) {
                    publish_presence_delta(&app_client, delta).await;
                }
            }
            msg = next_or_pending(&mut disconnect_sub) => {
                let Some(msg) = msg else {
                    tracing::warn!("$SYS.ACCOUNT.*.DISCONNECT subscription ended unexpectedly");
                    disconnect_sub = None;
                    continue;
                };
                tracing::debug!(
                    subject = %msg.subject,
                    payload = %String::from_utf8_lossy(&msg.payload),
                    "raw $SYS.ACCOUNT.*.DISCONNECT event"
                );
                let Some(user_pk) = user_from_sys_event(&msg.payload) else {
                    tracing::warn!(
                        payload = %String::from_utf8_lossy(&msg.payload),
                        "DISCONNECT event had no recognizable client.user — ignoring"
                    );
                    continue;
                };
                // Kick-relay feed first: it owns the only authoritative record of which `cid` is currently
                // live for this `nats_fp`, and its verdict gates the session-record delete below. An event
                // with no parseable `(server.id, client.id)` yields no verdict at all, so it touches neither
                // the kick map nor the session record — but it must still fall through to the presence
                // handling below, which needs only the user nkey `user_from_sys_event` already returned.
                let verdict = match kick_coords_from_sys_event(&msg.payload) {
                    Some((_, cid)) => kick_map.disconnect(&user_pk, cid),
                    None => {
                        tracing::warn!(
                            payload = %String::from_utf8_lossy(&msg.payload),
                            "DISCONNECT event had no recognizable server.id/client.id — cannot tell a live \
                             disconnect from a stale one, so neither the kick map nor the session record is \
                             touched; the record's own `exp` still retires it (DESIGN.md §A5). Presence is \
                             still updated below, which needs only the user nkey."
                        );
                        kick::DisconnectVerdict::Unknown
                    }
                };

                // Eager session-record cleanup (DESIGN.md §A5 "cleaned up on DISCONNECT/expiry")
                // applies to every disconnecting user, host or device alike — decoupled from the
                // presence map below, which only exists for registered hosts.
                //
                // Gated on the kick map's verdict so that a *stale* DISCONNECT — one superseded
                // by a newer CONNECT reusing the same `nats_fp`, see `kick::KickMap`'s module
                // doc's "Reconnect" section — cannot evict a live session's record. Deleting it
                // would be the silent half of the missed-kick defect: a later revocation would
                // find no session at all via `sessions_for_subject` and would never kick the
                // revoked device.
                //
                // Only `Current` deletes. `Superseded` must not (that is the bug). `Unknown` must
                // not either: it means either a duplicate DISCONNECT whose record is already gone
                // (so the delete would be a no-op anyway) or a connection this map never saw,
                // where there is no evidence the record is dead. Both non-deleting cases are safe
                // to skip because the store filters on `exp` at read time in every impl
                // (`HelperView::session_record` / `sessions_for_subject`), so a record left behind
                // here is already invisible to every reader, and `purge_expired_sessions`
                // reclaims the row. The asymmetry is deliberate: a skipped delete costs a dead row
                // until expiry, while a wrong delete silently un-revokes a device.
                if verdict == kick::DisconnectVerdict::Current {
                    if let Ok(nats_fp) = auth_token::nats_fp_of_nkey(&user_pk) {
                        store.delete_session_record(&nats_fp);
                    }
                }
                if let Some(delta) = presence_map.disconnect(&user_pk, now_secs()) {
                    publish_presence_delta(&app_client, delta).await;
                }
            }
            // Test-only delayed `kick_map` arming (see `SPINDLE_HELPER_TEST_ADVISORY_DELAY_MS`'s
            // doc comment in the connect branch above). Declared after the connect/disconnect
            // branches for consistency with the retry branch just below, but — unlike that
            // branch's `biased;` ordering, which is load-bearing — this one's position doesn't
            // actually matter: it only ever fires under the test-only env var, and its only job is
            // to arm `kick_map` a bit later than a real CONNECT would, not to race anything else
            // in this loop.
            Some((user_pk, server_id, cid)) = delayed_arm_rx.recv() => {
                kick_map.connect(&user_pk, server_id, cid);
            }
            // Delayed kick re-plan (this file's "Kick relay" module-doc section). Declared AFTER
            // the connect and disconnect branches above — under `biased;`, that ordering is
            // load-bearing, not incidental: it guarantees that if a CONNECT advisory for one of
            // these `unresolved` sessions is *also* ready at this same poll, it gets drained into
            // `kick_map` first, so the re-plan below reads the map's newest state rather than
            // racing it the same way the original bug did.
            Some(unresolved) = kick_retry_rx.recv() => {
                let mut still_unresolved = Vec::new();
                for u in unresolved {
                    match kick_map.target_for(&u) {
                        Some(target) => {
                            tracing::info!(
                                nats_fp = %target.nats_fp,
                                matched_subject = %target.matched_subject,
                                "delayed kick re-plan resolved a session the original plan missed"
                            );
                            issue_kick(sys_ref, &target).await;
                        }
                        None => still_unresolved.push(u),
                    }
                }
                if !still_unresolved.is_empty() {
                    // Spawned, not awaited inline: `connz_kick_fallback` carries its own 5s
                    // timeout (see `connz_request`'s doc comment) and must not stall this loop.
                    let sys_client = sys_ref.clone();
                    tokio::spawn(connz_kick_fallback(sys_client, still_unresolved));
                }
            }
            _ = purge_interval.tick() => {
                store.purge_expired_sessions(now_secs());
            }
        }
    }

    tracing::info!("spindle-helper shut down cleanly");
    Ok(())
}

// ================================================================================================
// Presence wiring (DESIGN.md §A3/§A6) — bridges `$SYS` events/CONNZ into
// `spindle_helper::presence::ConnectionMap`. See that module's own doc comment for the pure
// connection-tracking logic and wire schema; everything below is I/O only.
// ================================================================================================

/// Extracts the client's session-nkey public-key string (`client.user`) from a `$SYS.ACCOUNT.*.
/// CONNECT`/`.DISCONNECT` event payload. Modeled tolerantly via `serde_json::Value` (matching
/// `handle_one`'s own style for external wire shapes) rather than a typed struct: the `async-nats`
/// crate this binary depends on does not model `$SYS` event payloads at all (confirmed by
/// grepping its source for `ConnectEvent`/`DisconnectEvent`/`client_info` — zero matches; these
/// events only ever reach a subscriber as raw JSON). Verified live by spikes/s5-presence (docs/
/// SPIKES.md §S5, RESULTS.md's captured samples): a real event is `{"type":"io.nats.server.
/// advisory.v1.client_connect"` (or `.client_disconnect`), ..., "client": {"user": "<pubkey>",
/// "acc": "APP", "start": ..., "id": <cid>, ...}}` — the assumed `{"client": {"user": "<pubkey>",
/// ...}}` shape this function relies on matched exactly, no parsing change needed. A disconnect's
/// `client.reason` was observed as `"Client Closed"` for a clean close and `"Stale Connection"`
/// for the SIGSTOP dead-socket scenario (unused by this function, noted for future reference).
/// Any other shape (or a missing/non-string `user`) is treated as "ignore this event," not a
/// fatal error — an unrecognized or malformed system event should never take the responder down.
fn user_from_sys_event(payload: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    value
        .get("client")?
        .get("user")?
        .as_str()
        .map(|s| s.to_string())
}

/// Extracts `(server_id, cid)` from a `$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT` event payload — the
/// kick relay's per-connection coordinates (DESIGN.md §A3, S9). `server_id` is `server.id`, `cid`
/// is `client.id` — both established live by `spikes/s9-revoke-kick/RESULTS.md` fact 3 ("The
/// server id is at `server.id` in every ... advisory. The cid is at `client.id`"). Kept as a
/// sibling of [`user_from_sys_event`] above rather than folded into it (same tolerant
/// `serde_json::Value` style, same "malformed event is ignored, never fatal" rule) so a payload
/// missing only these two fields still resolves `client.user` normally for presence tracking.
fn kick_coords_from_sys_event(payload: &[u8]) -> Option<(String, u64)> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let server_id = value.get("server")?.get("id")?.as_str()?.to_string();
    let cid = value.get("client")?.get("id")?.as_u64()?;
    Some((server_id, cid))
}

/// Issues one `$SYS.REQ.SERVER.<server_id>.KICK` request for `target` on `sys_client` (the
/// SYS-account connection `spikes/s9-revoke-kick/RESULTS.md` confirmed live is permitted to issue
/// KICK) and logs the outcome. **A reply is not success** — RESULTS.md's single most important
/// finding (fact 5) is that a failed kick still returns a reply (an error object), never a
/// transport failure, so treating "a reply arrived" as "it worked" reports phantom kicks. Success
/// is signaled purely by the *absence* of an `error` key in the reply (RESULTS.md §4 — there is
/// no positive success marker to check for instead), so this parses the reply body and checks for
/// that key explicitly rather than short-circuiting on `Ok(reply)`.
///
/// A transport failure, a timeout, or an unparseable/error reply is logged at `error!` and
/// swallowed — never propagated — so one failed kick can never take the responder down or stop
/// the rest of a revocation's batch of kicks from being attempted (`src/bin/helper.rs`'s only
/// caller loops over every [`kick::KickTarget`] regardless of this call's outcome).
async fn issue_kick(sys_client: &async_nats::Client, target: &kick::KickTarget) {
    let subject = format!("$SYS.REQ.SERVER.{}.KICK", target.server_id);
    let payload = match serde_json::to_vec(&serde_json::json!({ "cid": target.cid })) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize a KICK request payload");
            return;
        }
    };

    let reply = match tokio::time::timeout(
        Duration::from_secs(5),
        sys_client.request(subject.clone(), payload.into()),
    )
    .await
    {
        Ok(Ok(reply)) => reply,
        Ok(Err(e)) => {
            tracing::error!(
                error = %e,
                subject = %subject,
                cid = target.cid,
                nats_fp = %target.nats_fp,
                "KICK request failed (transport)"
            );
            return;
        }
        Err(_) => {
            tracing::error!(
                subject = %subject,
                cid = target.cid,
                nats_fp = %target.nats_fp,
                "KICK request timed out"
            );
            return;
        }
    };

    let value: serde_json::Value = match serde_json::from_slice(&reply.payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                error = %e,
                subject = %subject,
                cid = target.cid,
                nats_fp = %target.nats_fp,
                reply = %String::from_utf8_lossy(&reply.payload),
                "KICK reply was not valid JSON — treating as failed, not successful"
            );
            return;
        }
    };

    // Success is the ABSENCE of an "error" key (RESULTS.md §4) — never inferred from the reply
    // merely having arrived (fact 5). A failed kick still gets a well-formed reply.
    if let Some(error) = value.get("error") {
        tracing::error!(
            subject = %subject,
            cid = target.cid,
            nats_fp = %target.nats_fp,
            matched_subject = %target.matched_subject,
            server_error = %error,
            "KICK request was answered but failed"
        );
        return;
    }

    tracing::info!(
        subject = %subject,
        cid = target.cid,
        nats_fp = %target.nats_fp,
        matched_subject = %target.matched_subject,
        "kicked a revoked connection"
    );
}

/// Publishes one `host.<hfp>.presence` delta (DESIGN.md §A6: "push deltas `{host_fp, state,
/// last_seen}` only") on `app_client`, or logs a degraded-mode warning and drops it if
/// `APP_CONN_SEED` is unset — the same pattern `helper.turn.get.<nfp>` already uses when the
/// application connection is absent.
async fn publish_presence_delta(
    app_client: &Option<async_nats::Client>,
    delta: presence::PresenceDelta,
) {
    let Some(client) = app_client else {
        tracing::warn!(
            host_fp = %delta.host_fp,
            "APP_CONN_SEED not set — dropping a host.<hfp>.presence delta"
        );
        return;
    };
    let subject = format!("host.{}.presence", delta.host_fp);
    let payload = match serde_json::to_vec(&delta.entry) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize a presence delta");
            return;
        }
    };
    if let Err(e) = client.publish(subject, payload.into()).await {
        tracing::error!(error = %e, "failed to publish a host.<hfp>.presence delta");
    }
    let _ = client.flush().await;
}

/// Performs one `$SYS.REQ.SERVER.PING.CONNZ` round trip and returns the parsed reply body.
/// Shared by [`seed_maps`] (startup backfill of both maps) and `connz_kick_fallback` (an
/// on-demand retry when even the delayed re-plan in the revoke branch still can't resolve a
/// session) so the request shape and the 5s timeout live in exactly one place. Returns `None` on
/// any transport/timeout/parse failure — logging that failure is each caller's own job, since the
/// two callers want differently-worded warnings for what is otherwise the same failure (a startup
/// backfill silently starting empty reads very differently from an in-flight kick retry giving
/// up).
///
/// `{"auth": true}` is nats-server's `ConnzOptions.Username` field (JSON key `"auth"`) — spikes/
/// s5-presence (docs/SPIKES.md §S5) found live that an empty request body gets back a CONNZ reply
/// whose `connections[]` entries have NO `"user"` field at all (cid/ip/port/etc. only), silently
/// defeating every seed. Requesting `auth` info is what makes the server include it (see that
/// spike's RESULTS.md for the captured before/after payload samples).
async fn connz_request(sys_client: &async_nats::Client) -> Result<serde_json::Value, ConnzError> {
    let request_payload = serde_json::json!({ "auth": true });
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        sys_client.request(
            "$SYS.REQ.SERVER.PING.CONNZ",
            serde_json::to_vec(&request_payload)
                .expect("static json! value always serializes")
                .into(),
        ),
    )
    .await
    .map_err(|_| ConnzError::Timeout)?
    .map_err(|e| ConnzError::Transport(e.to_string()))?;

    serde_json::from_slice(&reply.payload).map_err(|e| ConnzError::BadJson(e.to_string()))
}

/// Why a [`connz_request`] round trip failed to produce a usable reply — carried instead of
/// logging inline so each caller can word its own warning (see that function's doc comment).
enum ConnzError {
    Transport(String),
    Timeout,
    BadJson(String),
}

/// The concrete `server.id` a CONNZ reply's rows share — top level, sibling of `data` (see
/// `kick.rs`'s module doc: there is no broadcast KICK form, a `server_id` is always required to
/// kick any of them). `None` here means every row in this reply is unkickable; it has no bearing
/// on presence seeding, which doesn't need a server id at all.
fn connz_server_id(value: &serde_json::Value) -> Option<&str> {
    value.get("server")?.get("id")?.as_str()
}

/// The CONNZ reply's `connections` array, tolerating either the documented `data.connections`
/// wrapping or a bare top-level `connections` (kept from [`seed_maps`]'s original doc comment,
/// unchanged by this refactor: "a bare top-level `connections` array is also tolerated in case of
/// a differently-wrapped reply").
fn connz_connections(value: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    value
        .get("data")
        .and_then(|d| d.get("connections"))
        .or_else(|| value.get("connections"))
        .and_then(|c| c.as_array())
}

/// Seeds a fresh [`presence::ConnectionMap`] *and* a fresh [`kick::KickMap`] from one shared
/// `$SYS.REQ.SERVER.PING.CONNZ` reply at startup (DESIGN.md §A6: "CONNZ on start + ... deltas";
/// DESIGN.md §A3/S9 for the kick relay). Renamed from `seed_presence_map` when this graduated to
/// seed both maps — one reply already carries everything both need (`server.id` at the top level,
/// `cid` and `authorized_user` per row), so a second request would just be redundant load on
/// `nats-server`. Best-effort for both: any failure (timeout, unparseable reply, an unrecognized
/// shape) is a warning, not a fatal error — presence self-heals from
/// `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` deltas and the kick relay self-heals the same way (plus the
/// delayed-re-plan/CONNZ-fallback path in the revoke branch, see this file's "Kick relay"
/// module-doc section) as connections churn, so starting either map empty is safe, just
/// momentarily stale.
///
/// Multi-server `CONNZ` aggregation (a cluster's `$SYS.REQ.SERVER.PING.CONNZ` fans out to every
/// node in the cluster and each node replies separately) is explicitly deferred to the HA slice
/// (DESIGN.md §A6/S8) — this takes only the first reply, matching a single-helper-instance
/// deployment.
///
/// Payload shape verified live by spikes/s5-presence (docs/SPIKES.md §S5 — see RESULTS.md for
/// the captured samples, before and after both fixes below): the reply is `{"server": {"id":
/// ..., ...}, "data": {"connections": [{"authorized_user": "<pubkey>", "account": "<account
/// name>", "cid": ..., "ip": ..., ...}, ...], ...}, ...}`; a bare top-level `connections` array is
/// also tolerated in case of a differently-wrapped reply. Two live-only gotchas, both found by
/// S5's restart-reseed scenario failing and both required together to fix it:
/// 1. The request body must be `{"auth": true}` (nats-server's `ConnzOptions.Username`, JSON key
///    `"auth"`) — an empty request body gets a reply with no identity field on any connection at
///    all.
/// 2. Even with `auth: true`, the identity field is named `"authorized_user"`, not `"user"` as
///    first assumed (`"user"` is kept as a tolerant fallback below, never observed in practice).
///
/// # Host-user resolution gap (flagged ambiguity, not silently resolved) — presence only
/// [`presence::ConnectionMap::register_host_user`] is normally populated live, at the moment a
/// host's callout succeeds (`handle_one`'s Host branch, below). CONNZ rows for connections
/// established *before this helper process started* were never seen by that code path, so there
/// is no `user_pk -> host_fp` binding for them yet — nothing in the CONNZ row itself names a
/// `host_fp`. This function closes that gap the only way available without extending the wire
/// schema: for each row's `user` (nkey pubkey), it derives `nats_fp` exactly as the callout does
/// (`auth_token::nats_fp_of_nkey`) and looks up that `nats_fp`'s durable session record. A record
/// whose `host_fps` is the single-element, self-referential `[root_fp]` — the shape
/// `decide_host_connect` always builds for a host connection (see `authz.rs`) — is recognized as
/// a host session, and its `root_fp` (== `host_fp`) is registered before folding the connection
/// in. A connection with no durable session record at all (the in-memory store was never durable
/// to begin with, or the record already expired) is silently skipped for presence: from CONNZ
/// alone it's indistinguishable from a device or the helper's own connection, and presence for it
/// simply reads "offline/unknown" until its own next CONNECT/DISCONNECT cycle re-establishes it
/// live. **This gap does not apply to kick-map seeding below**: unlike presence, every connection
/// with a usable `cid` and a live session record is kickable, host or device alike — there is no
/// "only hosts" restriction on the kick relay (DESIGN.md §A3's kick relay reaches any revoked
/// `root_fp`/`device_fp`, not just hosts).
async fn seed_maps(
    sys_client: &async_nats::Client,
    store: &mut Store,
    now: u64,
) -> (presence::ConnectionMap, kick::KickMap) {
    let mut presence_map = presence::ConnectionMap::new();
    let mut kick_map = kick::KickMap::new();

    let value = match connz_request(sys_client).await {
        Ok(v) => v,
        Err(ConnzError::Transport(e)) => {
            tracing::warn!(
                error = %e,
                "CONNZ request failed — starting presence and kick maps empty"
            );
            return (presence_map, kick_map);
        }
        Err(ConnzError::Timeout) => {
            tracing::warn!("CONNZ request timed out — starting presence and kick maps empty");
            return (presence_map, kick_map);
        }
        Err(ConnzError::BadJson(e)) => {
            tracing::warn!(
                error = %e,
                "CONNZ reply was not valid JSON — starting presence and kick maps empty"
            );
            return (presence_map, kick_map);
        }
    };

    // Raw-sample capture for spikes/s5-presence's RESULTS.md (docs/SPIKES.md §S5, task g): the
    // exact shape of a real $SYS.REQ.SERVER.PING.CONNZ reply, ground truth for this function's
    // doc comment's assumption. Debug-level only.
    tracing::debug!(reply = %value, "raw $SYS.REQ.SERVER.PING.CONNZ reply");

    // Missing top-level server.id only sinks kick-map seeding (see kick.rs's module doc: there's
    // no broadcast KICK form, a concrete server_id is always required) — presence has no such
    // dependency, so it proceeds below regardless.
    let server_id = connz_server_id(&value);
    if server_id.is_none() {
        tracing::warn!(
            "CONNZ reply had no top-level server.id — kick map will start empty; presence \
             seeding is unaffected"
        );
    }

    let Some(connections) = connz_connections(&value) else {
        tracing::warn!(
            "CONNZ reply had no recognizable connections array — starting presence and kick maps \
             empty"
        );
        return (presence_map, kick_map);
    };

    for conn in connections {
        let Some(user_pk) = connz_row_user_pk(conn) else {
            continue;
        };
        let Ok(nats_fp) = auth_token::nats_fp_of_nkey(user_pk) else {
            continue;
        };
        let Some(session) = store.session_record(&nats_fp, now) else {
            continue;
        };

        // Kick-map seeding: every connection with a live session record is kickable, host or
        // device alike — deliberately NOT gated on `is_host_session` below (see this function's
        // doc comment's last paragraph).
        if let (Some(server_id), Some(cid)) = (server_id, connz_row_cid(conn)) {
            kick_map.connect(user_pk, server_id, cid);
        }

        let is_host_session = session.host_fps.len() == 1 && session.host_fps[0] == session.root_fp;
        if !is_host_session {
            continue;
        }
        presence_map.register_host_user(user_pk.to_string(), session.root_fp);
        // Discard the delta: nothing is subscribed to host.<hfp>.presence yet this early in
        // startup, and every seeded connection is by definition not a fresh transition.
        let _ = presence_map.connect(user_pk, now);
    }

    (presence_map, kick_map)
}

/// The CONNZ fallback for a session a delayed kick re-plan still couldn't resolve (this file's
/// "Kick relay" module-doc section, and `KICK_REPLAN_DELAY`'s doc comment). By the time this runs,
/// both the natural `$SYS.ACCOUNT.*.CONNECT` advisory feed and one delayed re-plan against it have
/// already had their chance — an on-demand CONNZ snapshot is the last independent source of truth
/// left: it asks `nats-server` directly, bypassing this helper's own advisory-ingestion pipeline
/// entirely, so it succeeds even if that pipeline itself is what's stuck or backlogged.
///
/// Reuses [`connz_request`]/[`connz_server_id`]/[`connz_connections`]/[`connz_row_user_pk`]/
/// [`connz_row_cid`] — the exact same parsing [`seed_maps`] uses — rather than re-implementing any
/// of it; only the fold logic differs (matching against a specific `unresolved` list instead of
/// seeding two fresh maps from scratch).
///
/// Spawned by the revoke branch rather than awaited inline (`connz_request` carries its own 5s
/// timeout, which must not stall the responder's `select!` loop). Anything still unresolved after
/// this is the honest end of the chain, logged at `warn!` with the count and the fingerprints —
/// the session record exists, but the server's own connection table doesn't know about it either,
/// so there is nothing left to kick.
async fn connz_kick_fallback(
    sys_client: async_nats::Client,
    unresolved: Vec<kick::UnresolvedSession>,
) {
    let value = match connz_request(&sys_client).await {
        Ok(v) => v,
        Err(ConnzError::Transport(e)) => {
            tracing::warn!(
                error = %e,
                unresolved = unresolved.len(),
                "CONNZ kick-fallback request failed — these sessions remain unresolved"
            );
            return;
        }
        Err(ConnzError::Timeout) => {
            tracing::warn!(
                unresolved = unresolved.len(),
                "CONNZ kick-fallback request timed out — these sessions remain unresolved"
            );
            return;
        }
        Err(ConnzError::BadJson(e)) => {
            tracing::warn!(
                error = %e,
                unresolved = unresolved.len(),
                "CONNZ kick-fallback reply was not valid JSON — these sessions remain unresolved"
            );
            return;
        }
    };

    let Some(server_id) = connz_server_id(&value) else {
        tracing::warn!(
            unresolved = unresolved.len(),
            "CONNZ kick-fallback reply had no top-level server.id — these sessions remain unresolved"
        );
        return;
    };

    let Some(connections) = connz_connections(&value) else {
        tracing::warn!(
            unresolved = unresolved.len(),
            "CONNZ kick-fallback reply had no recognizable connections array — these sessions \
             remain unresolved"
        );
        return;
    };

    // Index by nats_fp so the connections loop below is a single pass regardless of how many
    // sessions are still unresolved, not O(rows * unresolved).
    let mut still_unresolved: std::collections::HashMap<_, _> =
        unresolved.into_iter().map(|u| (u.nats_fp, u)).collect();

    for conn in connections {
        if still_unresolved.is_empty() {
            break;
        }
        let Some(user_pk) = connz_row_user_pk(conn) else {
            continue;
        };
        let Ok(nats_fp) = auth_token::nats_fp_of_nkey(user_pk) else {
            continue;
        };
        let Some(u) = still_unresolved.remove(&nats_fp) else {
            continue;
        };
        let Some(cid) = connz_row_cid(conn) else {
            // Put it back — this row identified the session but had no usable cid, so it's still
            // genuinely unresolved, not a spurious "found and removed."
            still_unresolved.insert(nats_fp, u);
            continue;
        };
        let target = kick::KickTarget {
            server_id: server_id.to_string(),
            cid,
            nats_fp: u.nats_fp,
            matched_subject: u.matched_subject,
        };
        tracing::info!(
            nats_fp = %target.nats_fp,
            matched_subject = %target.matched_subject,
            "CONNZ kick fallback resolved a session the delayed re-plan still missed"
        );
        issue_kick(&sys_client, &target).await;
    }

    if !still_unresolved.is_empty() {
        let fingerprints: Vec<String> = still_unresolved.keys().map(|fp| fp.to_string()).collect();
        tracing::warn!(
            unresolved = still_unresolved.len(),
            nats_fps = ?fingerprints,
            "CONNZ kick fallback still could not resolve these sessions — the server's own \
             connection table doesn't know about them either, nothing left to kick"
        );
    }
}

/// Extracts a CONNZ connection row's authorized-user nkey pubkey. Split out of [`seed_maps`]'s
/// loop so the field-name lookup — the exact thing spikes/s5-presence (docs/SPIKES.md §S5) got
/// wrong on the first pass — is independently unit-testable against the real captured shape (see
/// the tests below), without needing a live NATS server. Real nats-server rows (with `{"auth":
/// true}` requested) name this field `"authorized_user"`; `"user"` is a tolerant fallback that has
/// never actually been observed.
fn connz_row_user_pk(conn: &serde_json::Value) -> Option<&str> {
    conn.get("authorized_user")
        .or_else(|| conn.get("user"))
        .and_then(|u| u.as_str())
}

/// Extracts a CONNZ connection row's `cid` — the kick relay's other half of a target, alongside
/// [`connz_server_id`] (DESIGN.md §A3, S9). Split out for the same testability reason as
/// [`connz_row_user_pk`]. Note the shape contrast with `$SYS.ACCOUNT.*.CONNECT`/`.DISCONNECT`
/// events: `kick_coords_from_sys_event` reads this same fact from a nested `client.id`, but a
/// CONNZ row has it at its own top level.
fn connz_row_cid(conn: &serde_json::Value) -> Option<u64> {
    conn.get("cid").and_then(|c| c.as_u64())
}

fn verifying_key_from_raw(raw: &[u8]) -> anyhow::Result<spindle_core::VerifyingKey> {
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected a 32-byte key, got {} bytes", raw.len()))?;
    Ok(spindle_core::SigningKey::from_bytes(&arr).verifying_key())
}

// ================================================================================================
// Callout handling — graduated from spikes/s1-callout/src/bin/responder.rs, unchanged decision
// logic (spindle_helper::authz), typed errors instead of anyhow.
// ================================================================================================

#[derive(Debug, thiserror::Error)]
enum HandleError {
    #[error("callout request payload is not valid UTF-8")]
    NonUtf8Payload,
    #[error(transparent)]
    Jwt(#[from] NatsJwtError),
    #[error("callout request claims missing {0}")]
    MissingClaim(&'static str),
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A non-cryptographic per-call jitter source (`permissions::Limits` jitters `exp` into a
/// 30-minute window — not a security-sensitive value; see `permissions::jittered_exp_secs`'s doc
/// comment). Wall-clock nanoseconds change on every call, which is all the variety this needs —
/// no RNG dependency required.
fn jitter_source() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Translates `spindle_helper::permissions::SubjectPermissions` into the NATS v2 User-JWT `nats`
/// claims object.
fn permissions_to_nats_claims(
    perms: &SubjectPermissions,
    payload_bytes: u32,
    max_subs: u32,
    allowed_connection_types: &[&str],
) -> serde_json::Value {
    let resp = perms
        .allow_responses
        .map(|ar| (ar.max, ar.expires_secs as i64 * 1_000_000_000));
    natsjwt::user_nats_claims(
        &perms.publish_allow,
        &perms.subscribe_allow,
        &perms.deny,
        resp,
        max_subs as i64,
        payload_bytes as i64,
        allowed_connection_types,
    )
}

fn encode_refusal(request_payload: &[u8], app_kp: &KeyPair) -> Option<String> {
    let req_str = std::str::from_utf8(request_payload).ok()?;
    let claims = natsjwt::decode_claims_unverified(req_str).ok()?;
    let user_nkey = claims["nats"]["user_nkey"].as_str()?.to_string();
    let server_id = claims["nats"]["server_id"]["id"].as_str()?.to_string();
    let inner = natsjwt::response_err(authz::UNIFORM_REFUSAL_MESSAGE);
    let resp_claims =
        natsjwt::authorization_response(&app_kp.public_key(), &server_id, &user_nkey, inner);
    natsjwt::encode(resp_claims, app_kp).ok()
}

fn handle_one(
    request_payload: &[u8],
    account_name: &str,
    app_kp: &KeyPair,
    view: &mut impl HelperView,
    presence_map: &mut presence::ConnectionMap,
) -> Result<Option<String>, HandleError> {
    let req_str = std::str::from_utf8(request_payload).map_err(|_| HandleError::NonUtf8Payload)?;
    let claims = natsjwt::decode_claims_unverified(req_str)?;

    // `nats.user_nkey` is a server-generated per-request correlation key — NOT the client's
    // actual presented nkey. See spindle_helper::natsjwt's module docs.
    let user_nkey = claims["nats"]["user_nkey"]
        .as_str()
        .ok_or(HandleError::MissingClaim("nats.user_nkey"))?
        .to_string();
    let server_id = claims["nats"]["server_id"]["id"]
        .as_str()
        .ok_or(HandleError::MissingClaim("nats.server_id.id"))?
        .to_string();
    let nonce = claims["nats"]["client_info"]["nonce"]
        .as_str()
        .unwrap_or("")
        .to_string();
    // The client's *actual* presented nkey — `connect_opts.nkey` (== `client_info.user`) — is
    // what `connect_opts.sig` signs `nonce` with. Distinct from `user_nkey` above.
    let connect_nkey = claims["nats"]["connect_opts"]["nkey"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let sig_b64 = claims["nats"]["connect_opts"]["sig"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let auth_token_str = claims["nats"]["connect_opts"]["auth_token"]
        .as_str()
        .map(|s| s.to_string());

    let now = now_secs();
    let jitter = jitter_source();

    let respond_ok = |perms: SubjectPermissions,
                      limits: Limits,
                      max_hosts: u32|
     -> Option<String> {
        let nats_claims = permissions_to_nats_claims(
            &perms,
            limits.payload_bytes,
            limits.max_subscriptions.max(4 * max_hosts + 8),
            &["STANDARD", "WEBSOCKET"],
        );
        let user_claims_val = natsjwt::user_claims(
            &app_kp.public_key(),
            account_name,
            &user_nkey,
            limits.exp,
            nats_claims,
        );
        let user_jwt = natsjwt::encode(user_claims_val, app_kp).ok()?;
        let inner = natsjwt::response_ok(user_jwt);
        let resp_claims =
            natsjwt::authorization_response(&app_kp.public_key(), &server_id, &user_nkey, inner);
        natsjwt::encode(resp_claims, app_kp).ok()
    };

    let respond_err = |msg: &str| -> Option<String> {
        let inner = natsjwt::response_err(msg);
        let resp_claims =
            natsjwt::authorization_response(&app_kp.public_key(), &server_id, &user_nkey, inner);
        natsjwt::encode(resp_claims, app_kp).ok()
    };

    let verify_nkey_sig = || -> bool {
        if nonce.is_empty() || sig_b64.is_empty() || connect_nkey.is_empty() {
            return false;
        }
        let Ok(kp) = KeyPair::from_public_key(&connect_nkey) else {
            return false;
        };
        let Ok(sig) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&sig_b64) else {
            return false;
        };
        kp.verify(nonce.as_bytes(), &sig).is_ok()
    };

    let Some(auth_token_str) = auth_token_str else {
        // No auth_token at all: uniform refusal (DESIGN.md §A5 Sybil/flood defense).
        return Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE));
    };

    let decoded = match auth_token::decode_auth_token(&auth_token_str) {
        Ok(d) => d,
        Err(_) => return Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE)),
    };

    match decoded {
        DecodedAuthToken::Device(d) => {
            let Ok(root_pk) = spindle_core::VerifyingKey::from_bytes(&d.root_pk_bytes) else {
                return Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE));
            };
            let Ok(nats_fp) = auth_token::nats_fp_of_nkey(&connect_nkey) else {
                return Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE));
            };
            let presented = DeviceConnectPresented {
                root_pk,
                device_cert: d.device_cert,
                caps: d.caps,
                nats_fp,
            };
            let decision =
                authz::decide_device_connect(&presented, verify_nkey_sig, now, view, jitter);
            match decision {
                AuthzDecision::Authorized(auth) => {
                    let host_count = auth.session_record.host_fps.len() as u32;
                    // DESIGN.md §A5: "on each successful auth the callout writes nats_fp →
                    // {root_fp, host_fps, quota_profile, exp} to the helper store" — Stage 4
                    // slice 2 computed this record but never persisted it (see
                    // HelperView::put_session_record's doc comment). Stage 4 slice 3's
                    // helper.turn.get.<nfp> needs it to authorize non-callout requests.
                    view.put_session_record(auth.session_record);
                    Ok(respond_ok(auth.permissions, auth.limits, host_count))
                }
                AuthzDecision::Refused(reason) => {
                    tracing::debug!(%reason, "device connection refused");
                    Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE))
                }
            }
        }
        DecodedAuthToken::Host(h) => {
            let Ok(host_root_pk) = spindle_core::VerifyingKey::from_bytes(&h.host_root_pk_bytes)
            else {
                return Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE));
            };
            let Ok(nats_fp) = auth_token::nats_fp_of_nkey(&connect_nkey) else {
                return Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE));
            };
            let presented = HostConnectPresented {
                host_root_pk,
                host_op_cert: h.host_op_cert,
                admission_token: h.admission_token,
                nats_fp,
            };
            let decision =
                authz::decide_host_connect(&presented, verify_nkey_sig, now, view, jitter);
            match decision {
                AuthzDecision::Authorized(auth) => {
                    // DESIGN.md §A3/§A6: the presence map needs a `user_pk -> host_fp` binding to
                    // ever recognize this connection's own future CONNECT/DISCONNECT events — the
                    // callout is the only place that knows both facts at once. For a host
                    // connection, `root_fp == host_fp` (see `authz.rs`'s `decide_host_connect`).
                    let host_fp = auth.session_record.root_fp;
                    view.put_session_record(auth.session_record);
                    presence_map.register_host_user(connect_nkey, host_fp);
                    Ok(respond_ok(auth.permissions, auth.limits, 1))
                }
                AuthzDecision::Refused(reason) => {
                    tracing::debug!(%reason, "host connection refused");
                    Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE))
                }
            }
        }
    }
}

// ================================================================================================
// Tests — real captured $SYS/CONNZ payload shapes (spikes/s5-presence, docs/SPIKES.md §S5).
//
// These are narrow, pure-function tests of the two parsing boundaries whose assumed shapes were
// (partly) wrong until validated live against a real nats-server:2.10.29: `connz_row_user_pk`
// (CONNZ's `"authorized_user"` vs. the originally-assumed `"user"`) and `user_from_sys_event`
// (the `$SYS.ACCOUNT.*.CONNECT|DISCONNECT` `client.user` shape, which turned out to already match
// what was assumed). Both fixtures below are trimmed real replies captured via this binary's own
// `tracing::debug!` instrumentation during an S5 run (see spikes/s5-presence/RESULTS.md for the
// untrimmed originals) — not hand-invented JSON.
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// One row of a real `$SYS.REQ.SERVER.PING.CONNZ` reply, captured with `{"auth": true}` in
    /// the request (spikes/s5-presence's fix — an empty request body's rows have no identity
    /// field at all, see `connz_row_no_auth_requested_has_no_identity_field` below).
    const REAL_CONNZ_ROW_WITH_AUTH: &str = r#"{
        "account":"APP","authorized_user":"UAOUJCRS3HXWQ2GKAA2PZA7QA5WQN3QTPTBSFX2KYC2XTY7P67U2252X",
        "cid":20,"idle":"0s","in_bytes":0,"in_msgs":0,"ip":"172.26.0.4","issuer_key":"APP",
        "kind":"Client","lang":"rust","last_activity":"2026-08-26T04:40:26.092235Z",
        "out_bytes":0,"out_msgs":0,"pending_bytes":0,"port":34748,"rtt":"384µs",
        "start":"2026-08-26T04:40:26.061902097Z","subscriptions":2,"type":"nats","uptime":"0s",
        "version":"0.35.1"
    }"#;

    /// One row of a real `$SYS.REQ.SERVER.PING.CONNZ` reply captured *before* the `{"auth":
    /// true}` fix — no `"user"` or `"authorized_user"` field at all. This is what
    /// `seed_presence_map` silently skipped every row as, live, before spikes/s5-presence found
    /// the fix (docs/SPIKES.md §S5's restart-reseed scenario failed until both this and the
    /// field-name fix landed).
    const REAL_CONNZ_ROW_NO_AUTH_REQUESTED: &str = r#"{
        "cid":19,"idle":"0s","in_bytes":0,"in_msgs":0,"ip":"172.26.0.4","kind":"Client",
        "lang":"rust","last_activity":"2026-08-26T04:34:36.267987921Z","out_bytes":0,
        "out_msgs":0,"pending_bytes":0,"port":34544,"rtt":"5.156167ms",
        "start":"2026-08-26T04:34:36.219214254Z","subscriptions":1,"type":"nats","uptime":"0s",
        "version":"0.35.1"
    }"#;

    /// A real `$SYS.ACCOUNT.APP.CONNECT` event payload, captured live.
    const REAL_CONNECT_EVENT: &str = r#"{
        "type":"io.nats.server.advisory.v1.client_connect","id":"HoUqrLYsWsMsv9m8ZFLQUF",
        "timestamp":"2026-08-26T04:33:42.221103549Z",
        "server":{"name":"ND4QZW2IXGFJBFLOVVIDZ4LDNLA3QEBLUXXODP2OAKO2GRCT26GSIJNK",
            "host":"0.0.0.0","id":"ND4QZW2IXGFJBFLOVVIDZ4LDNLA3QEBLUXXODP2OAKO2GRCT26GSIJNK",
            "ver":"2.10.29","jetstream":false,"flags":0,"seq":22,
            "time":"2026-08-26T04:33:42.221243091Z"},
        "client":{"start":"2026-08-26T04:33:42.202549549Z","host":"151.101.42.132","id":10,
            "acc":"APP","user":"UCCDYXIJL3ARVUAHY6QMJWI34OI7QL525CQKOOJSPVKW3NZMEKC2VTE3",
            "lang":"rust","ver":"0.35.1","issuer_key":"APP","kind":"Client","client_type":"nats"}
    }"#;

    /// A real `$SYS.ACCOUNT.APP.DISCONNECT` event payload from the SIGSTOP dead-socket scenario —
    /// note `"reason":"Stale Connection"`, distinct from a clean close's `"Client Closed"`.
    const REAL_DISCONNECT_EVENT_STALE: &str = r#"{
        "type":"io.nats.server.advisory.v1.client_disconnect","id":"HoUqrLYsWsMsv9m8ZFLR1N",
        "timestamp":"2026-08-26T04:34:24.677784847Z",
        "server":{"name":"ND4QZW2IXGFJBFLOVVIDZ4LDNLA3QEBLUXXODP2OAKO2GRCT26GSIJNK",
            "host":"0.0.0.0","id":"ND4QZW2IXGFJBFLOVVIDZ4LDNLA3QEBLUXXODP2OAKO2GRCT26GSIJNK",
            "ver":"2.10.29","jetstream":false,"flags":0,"seq":43,
            "time":"2026-08-26T04:34:24.678288347Z"},
        "client":{"start":"2026-08-26T04:33:42.521603508Z","host":"151.101.42.132","id":13,
            "acc":"APP","user":"UB5AUMGSNEAINIEWVEYRRSDD4PX6LUWDNO7OLOFCAJCT7IZLLARZWP6N",
            "lang":"rust","ver":"0.35.1","rtt":801000,"stop":"2026-08-26T04:34:24.677784847Z",
            "issuer_key":"APP","kind":"Client","client_type":"nats"},
        "sent":{"msgs":0,"bytes":0},"received":{"msgs":0,"bytes":0},"reason":"Stale Connection"
    }"#;

    #[test]
    fn connz_row_with_auth_requested_yields_authorized_user() {
        let row: serde_json::Value = serde_json::from_str(REAL_CONNZ_ROW_WITH_AUTH).unwrap();
        assert_eq!(
            connz_row_user_pk(&row),
            Some("UAOUJCRS3HXWQ2GKAA2PZA7QA5WQN3QTPTBSFX2KYC2XTY7P67U2252X")
        );
    }

    #[test]
    fn connz_row_no_auth_requested_has_no_identity_field() {
        let row: serde_json::Value =
            serde_json::from_str(REAL_CONNZ_ROW_NO_AUTH_REQUESTED).unwrap();
        assert_eq!(connz_row_user_pk(&row), None);
    }

    #[test]
    fn connz_row_falls_back_to_user_field_when_present() {
        let row = serde_json::json!({ "user": "UABC123" });
        assert_eq!(connz_row_user_pk(&row), Some("UABC123"));
    }

    #[test]
    fn connz_row_prefers_authorized_user_over_user_if_both_present() {
        let row = serde_json::json!({ "authorized_user": "UAAA", "user": "UBBB" });
        assert_eq!(connz_row_user_pk(&row), Some("UAAA"));
    }

    #[test]
    fn real_connect_event_yields_client_user() {
        assert_eq!(
            user_from_sys_event(REAL_CONNECT_EVENT.as_bytes()),
            Some("UCCDYXIJL3ARVUAHY6QMJWI34OI7QL525CQKOOJSPVKW3NZMEKC2VTE3".to_string())
        );
    }

    #[test]
    fn real_stale_disconnect_event_yields_client_user() {
        assert_eq!(
            user_from_sys_event(REAL_DISCONNECT_EVENT_STALE.as_bytes()),
            Some("UB5AUMGSNEAINIEWVEYRRSDD4PX6LUWDNO7OLOFCAJCT7IZLLARZWP6N".to_string())
        );
    }
}
