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
//! - `_app_client` — on the application account, authenticated with `APP_CONN_SEED` (a second
//!   exempted nkey, distinct from `APP_ACCOUNT_SEED`, which is the account's own *signing* key
//!   used to sign User JWTs and is never used to open a connection). Established but otherwise
//!   idle in this slice — presence (`host.<hfp>.presence` publishing from `$SYS` events) and
//!   `registry.*`/`helper.*` request/reply are Stage 4 slice 3+ work. Optional: if
//!   `APP_CONN_SEED` is unset, this binary logs a warning and runs with the callout connection
//!   only, since nothing in this slice actually needs the application connection yet.
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
    self, AdmissionMode, AuthzDecision, DeviceConnectPresented, HostConnectPresented,
};
use spindle_helper::memory_store::InMemoryHelperView;
use spindle_helper::natsjwt::{self, NatsJwtError};
use spindle_helper::permissions::{Limits, SubjectPermissions};
use std::env;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// Operator admission-key seed, for verifying presented admission tokens. Falls back to a
    /// fixed dev-only key (matching the S1 spike) if unset — loud warning, never for production.
    operator_seed: Option<String>,
    admission_mode: AdmissionMode,
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
    --operator-seed <seed>      OPERATOR_SEED        (optional; dev-only fallback key if unset)
    --admission-mode <mode>     ADMISSION_MODE       (open|invite|closed; default: open)
    -h, --help                  show this message
"#;

impl Config {
    fn from_env_and_args(mut args: impl Iterator<Item = String>) -> Result<Config, ConfigError> {
        let mut nats_url = env::var("NATS_URL").ok();
        let mut callout_user_seed = env::var("CALLOUT_USER_SEED").ok();
        let mut app_account_seed = env::var("APP_ACCOUNT_SEED").ok();
        let mut account_name = env::var("ACCOUNT_NAME").ok();
        let mut app_conn_seed = env::var("APP_CONN_SEED").ok();
        let mut operator_seed = env::var("OPERATOR_SEED").ok();
        let mut admission_mode = env::var("ADMISSION_MODE").ok();

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

        Ok(Config {
            nats_url: nats_url.unwrap_or_else(|| "nats://127.0.0.1:4222".to_string()),
            callout_user_seed: callout_user_seed
                .ok_or(ConfigError::Missing("CALLOUT_USER_SEED", "callout-seed"))?,
            app_account_seed: app_account_seed
                .ok_or(ConfigError::Missing("APP_ACCOUNT_SEED", "app-account-seed"))?,
            account_name: account_name.unwrap_or_else(|| "APP".to_string()),
            app_conn_seed,
            operator_seed,
            admission_mode,
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
    // file's module docs). Optional in this slice; nothing below reads `_app_client` yet, but
    // establishing it here is what makes Stage 4 slice 3's presence/TURN/registry work a
    // same-file addition rather than a re-plumbing.
    let _app_client = match &config.app_conn_seed {
        Some(seed) => {
            let client = async_nats::ConnectOptions::with_nkey(seed.clone())
                .connect(&config.nats_url)
                .await?;
            tracing::info!("application-account connection established");
            Some(client)
        }
        None => {
            tracing::warn!(
                "APP_CONN_SEED not set — running with the callout connection only; presence/TURN/\
                 registry work (Stage 4 slice 3+) will need it"
            );
            None
        }
    };

    let mut sub = callout_client.subscribe("$SYS.REQ.USER.AUTH").await?;
    let mut view = InMemoryHelperView::new(config.admission_mode, operator_pk);

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
                let resp = match handle_one(&msg.payload, &config.account_name, &app_kp, &mut view) {
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
        }
    }

    tracing::info!("spindle-helper shut down cleanly");
    Ok(())
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
    view: &mut InMemoryHelperView,
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
                AuthzDecision::Authorized(auth) => Ok(respond_ok(auth.permissions, auth.limits, 1)),
                AuthzDecision::Refused(reason) => {
                    tracing::debug!(%reason, "host connection refused");
                    Ok(respond_err(authz::UNIFORM_REFUSAL_MESSAGE))
                }
            }
        }
    }
}
