//! The headless `spindle-hostd` binary: one host identity, a supervised sequence of NATS
//! connections, and one [`HostDaemon::run`] future per connection (td-539ffa slice 3;
//! reconnect supervision is td-6242d2).
//!
//! # Why this binary exists
//!
//! [`HostDaemon`] is deliberately a library (see `src/lib.rs`'s module doc comment): `apps/host`'s
//! Tauri shell will call it in-process, with a NATS client and key custody of its own. A server
//! deployment has neither of those, so this binary is the other shape — the headless one. It owns
//! the seed-file custody path, the first-run recovery-phrase ceremony, per-start identity minting
//! (A10.43/A10.44), and the run loop. The CONNECT `auth_token` and the per-connect `HostDeviceCert`
//! publish to `registry.devcert.<host_fp>` (A10.37) both ride on
//! [`spindle_hostd::connect::connect_host`], so the binary gets the publish cadence — including
//! republishes after a reconnect — without owning it.
//! The Tauri shell never executes this file; it keeps calling the library directly, per the crate
//! manifest's comment.
//!
//! # What does not survive, and what does
//!
//! Only the root seed persists (DESIGN.md A10.41). The operating key and envelope device key are
//! minted fresh at every start, so `host_fp` survives a restart while `device_fp` does not. The
//! recovery phrase is delivered **once**, at explicit enrollment, and only to a channel that is
//! not a log pipeline: stdout when stdout is a terminal, otherwise the operator-configured
//! `--recovery-phrase-file`. Everything else this process says goes to stderr through `tracing`.
//!
//! # A lost NATS connection is not process-fatal
//!
//! The CONNECT `auth_token` is valid only for the session that presented it: async-nats 0.35
//! replays the static token on an automatic reconnect (`connector.rs:193`), and the host session
//! attestation inside it is valid for only ±2 minutes. [`spindle_hostd::connect`] therefore bounds
//! that internal retry (`.max_reconnects(1)`); when it fails, `HostDaemon::run` returns promptly
//! and this binary's supervised loop takes over.
//!
//! The loop calls `connect_host` again on every attempt, so each connection gets a **fresh**
//! per-session nkey, `HostSessionAttestation`, `auth_token`, and `HostDeviceCert` publish. What
//! must **not** churn is the process's envelope device key: A10.44 regenerates it per process, not
//! per reconnect, and A10.45 forbids churning it mid-process, so `device_fp` stays the same across
//! reconnects within one process (the certificate is re-minted with a fresh `ts` on every
//! connection — same keys, same `device_fp`, same `exp` — because `ts` is inside the signed
//! preimage). The admission token is presented until the first connect **succeeds** (A3b): a failed
//! attempt may never have reached the callout, so it is not consumed; re-presenting a token that
//! did reach it is harmless because burning the same host+nonce is idempotent (A4).
//!
//! Failure handling is precise: a TLS or server-address parse failure is fatal immediately (retrying
//! cannot fix misconfiguration); an authorization refusal **at CONNECT** is fatal only after it has
//! persisted across [`MAX_CONSECUTIVE_AUTH_REFUSALS`] attempts (>2.5 minutes of continuous backoff),
//! because NATS reports a helper that is still re-subscribing after a broker restart with the same
//! undifferentiated `authorization violation` it reports for a revoked host; every other failure
//! (DNS, I/O, timeout, a `HostDaemon::run` failure) retries with a 1 s-to-30 s exponential backoff.
//! `SIGINT`/`SIGTERM` return `SUCCESS` at any point, including during the backoff.
//!
//! # Mid-process certificate renewal [A10.45]
//!
//! The serving loop also owns renewal. The renewal instant is two-thirds of the operating
//! certificate's lifetime ([`next_renewal_at`]), leaving a one-third retry window. When it fires,
//! the binary reloads the root seed from custody (the root is not kept resident between renewals),
//! mints a **new operating key** and re-issues the op cert under that root, then `continue`s the
//! outer loop. That is deliberately **a planned reconnect**: `connect_host` re-authenticates with
//! the new operating key and re-mints/re-publishes the `HostDeviceCert` under it, while the
//! process's envelope `DeviceKey` (the same `Arc`) is untouched — so both `host_fp` and
//! `device_fp` are unchanged across a renewal.
//!
//! On a failed renewal (seed reload, root change, or issuance) the process keeps serving the
//! sessions it already has, flips a [`GateableCapIssuer`] gate off so no **new** member capability
//! is minted, logs the reason, and retries after [`RENEWAL_RETRY_SECS`] (clamped to the
//! certificate's remaining lifetime). It stops with `ExitCode::FAILURE` only when
//! `now >= op_cert.exp`: serving an expired certificate is worse than stopping.
//!
//! The certificate lifetime is `SPINDLE_HOST_OP_CERT_TTL_SECS`/`--op-cert-ttl-secs` (default
//! A7b's 90 days, maximum the same). Shortening it shortens the renewal point, the retry window,
//! and the expiry proportionally, which is what `tests/live_renewal.rs` exercises live.
//!
//! # Metrics
//!
//! The Prometheus exporter (A10.51) is installed once here, and only when `SPINDLE_METRICS_ADDR`
//! is set. Unset means no global recorder is installed and every `metrics` macro is a no-op. The
//! library itself never installs a recorder.
//!
//! # Upload-ledger reconcile surfaces (td-042e4f)
//!
//! `--reconcile-once` / `SPINDLE_HOST_RECONCILE_ONCE` is an operator repair action: it runs before
//! the seed/NATS/metrics wiring, needs no identity, touches every share's ledger against disk and
//! then both quota counter tables, and exits. Because it is a separate process, it cannot share the
//! in-process per-share upload lock the serving host uses; it must be run with the host **stopped**
//! (SQLite still prevents corruption, but a live commit can be mis-reconciled). It also operates
//! only on an existing Spindle store — an absent, zero-byte, or foreign database is refused, not
//! created or migrated. `--reconcile-interval-secs` / `SPINDLE_HOST_RECONCILE_INTERVAL_SECS`
//! instead schedules **only** the disk -> ledger sweep on a timer while the host serves, under the
//! same per-share lock every session's `UploadCommit` takes. The split is deliberate:
//! DB-vs-filesystem skew has ongoing sources, while ledger-vs-counter drift is impossible by
//! construction, so the counter reconcile is a repair tool rather than routine maintenance.
//! Neither surface is tied to a client connect. See `reconcile_surface`'s module doc comment for the
//! lock interaction.
//!
//! # Redaction
//!
//! Every fingerprint in a log line is rendered through `Fingerprint::redacted()`. Credentials,
//! tokens, and the recovery phrase are never logged at all.

mod config;

use std::env;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusBuilder;
use rand::rngs::OsRng;
use rand::RngCore as _;
use spindle_core::{RootKey, SigningKey, VerifyingKey};
use spindle_host_core::{RootKeyCapIssuer, UploadLedgerLocks};
use spindle_hostd::connect::{connect_host, ConnectError, HostConnectCredentials};
#[cfg(unix)]
use spindle_hostd::keystore::{create_secret_file, open_secret_file};
use spindle_hostd::reconcile_surface::{
    reconcile_once, run_scheduled_disk_sweep, ReconcileOnceError,
};
use spindle_hostd::{
    format_recovery_phrase, mint_host_identity_with_ttl, parse_recovery_phrase,
    renew_operating_identity_with_ttl, wall_clock_now_secs, GateableCapIssuer, HostDaemon,
    HostDaemonError, HostIdentity, HostKeyStore, HostOptions, KeyStoreError, SeedFileStore,
    ROOT_SEED_LEN,
};
use spindle_proto::artifacts::{AdmissionToken, HostOpKeyCert};
use spindle_vfs::store::StoreError;

use crate::config::Config;

#[tokio::main]
async fn main() -> ExitCode {
    // stderr, not the `tracing_subscriber` default of stdout: stdout is reserved for the
    // recovery phrase this binary may print exactly once, and mixing logs into it would make the
    // one secret this process emits harder to isolate (and, operationally, make logs and
    // machine-readable output the same stream).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match Config::from_env_and_args(env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(
                error = %error, // redaction-ok: ConfigError Display names flags/env vars, static parse text, and the operator's own --bind-ip/boolean/--op-cert-ttl-secs input (non-secret configuration values); ConfigError::unknown_arg truncates at '=' so a --restore-seed value is never embedded
                "invalid host daemon configuration; run with --help for usage"
            );
            return ExitCode::FAILURE;
        }
    };

    // An operator repair action, not a serving mode: run it before the metrics, seed, identity,
    // and NATS wiring so it works on a host with none of them, then exit. `run` is never reached
    // with this flag set.
    if config.reconcile_once {
        // Serving-only settings are not silently dropped: say so before exiting, so an operator
        // who combined them with the one-shot action sees why they had no effect. (Enrollment
        // actions are a hard config error instead — see `ConfigError::ConflictingEnrollment`.)
        if config.reconcile_interval_secs.is_some() {
            tracing::warn!(
                "--reconcile-interval-secs / SPINDLE_HOST_RECONCILE_INTERVAL_SECS is ignored with \
                 --reconcile-once: the one-shot action exits instead of serving"
            );
        }
        if config.metrics_addr.is_some() {
            tracing::warn!(
                "--metrics-addr / SPINDLE_METRICS_ADDR is ignored with --reconcile-once: the \
                 one-shot action exits before installing the exporter"
            );
        }
        return run_reconcile_once(&config.store);
    }

    init_metrics_exporter(config.metrics_addr.as_deref());

    run(config).await
}

/// Runs the `--reconcile-once` operator action and maps its outcome to the documented exit code.
///
/// `SUCCESS` means every share's ledger was swept against disk **and** both counter tables were
/// recomputed. A share that could not be swept (logged with the others by `reconcile_once`) or a
/// failed counter reconcile is `FAILURE`; failing to open the store or list its shares is also
/// `FAILURE`. The per-share and summary lines are logged by `reconcile_once` itself.
fn run_reconcile_once(store_path: &Path) -> ExitCode {
    match reconcile_once(store_path) {
        Ok(report) if !report.failed() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(ReconcileOnceError::StoreAbsent(path)) => {
            tracing::error!(
                path = %path.display(), // redaction-ok: operator-configured SPINDLE_HOST_STORE path (operator-config exemption, lib.rs), never member data
                "the configured host store does not exist; refusing to create an empty one. Fix \
                 the path, or start the host once so its store exists, then re-run \
                 --reconcile-once"
            );
            ExitCode::FAILURE
        }
        Err(ReconcileOnceError::Store(StoreError::NotASpindleStore {
            user_version,
            missing,
        })) => {
            tracing::error!(
                path = %store_path.display(), // redaction-ok: operator-configured SPINDLE_HOST_STORE path (operator-config exemption, lib.rs), never member data
                user_version,
                missing = ?missing, // static Spindle table names, never member data
                "the file at the configured host store path is not an existing Spindle store; \
                 refusing to create or migrate it. Point --store at the host's real database"
            );
            ExitCode::FAILURE
        }
        Err(ReconcileOnceError::Store(_)) => {
            // Deliberately not `%error`: StoreError's Display can carry filesystem paths.
            tracing::error!(
                "the one-shot upload-ledger reconciliation could not open the configured host \
                 store or list its shares; nothing was reconciled"
            );
            ExitCode::FAILURE
        }
    }
}

/// The running half of `main`: custody, identity, connect, daemon. Every failure logs its own
/// content-free cause and returns [`ExitCode::FAILURE`]; there is no error type crossing this
/// boundary because there is no caller to report to.
async fn run(config: Config) -> ExitCode {
    // The scheduled disk -> ledger sweep (td-042e4f). It is deliberately not per client connect:
    // it runs on its own timer and opens its own store connection on every tick. The sender is
    // held for this function's whole lifetime; dropping it — on any return, including the
    // shutdown-signal arms below — wakes the sweep task's `changed()` and stops it. A failed tick
    // logs and retries on the next interval; it never takes the host down.
    // One registry is shared by every session's upload commit and the scheduled sweep; that shared
    // lock is what stops the sweep from deleting a ledger row a concurrent commit just inserted.
    let upload_locks = UploadLedgerLocks::new();
    let _reconcile_stop = match config.reconcile_interval_secs {
        Some(interval_secs) => {
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            tracing::info!(
                interval_secs,
                "scheduled upload-ledger disk sweep enabled (disk -> ledger only; the counter \
                 reconcile stays operator-only). It shares the per-share upload lock with live \
                 commits, uses its own store connection, and takes short Immediate transactions, \
                 so it can briefly block session writes"
            );
            tokio::spawn(run_scheduled_disk_sweep(
                config.store.clone(),
                std::time::Duration::from_secs(interval_secs),
                upload_locks.clone(),
                stop_rx,
            ));
            Some(stop_tx)
        }
        None => None,
    };

    // Serving mode's requirements. The parser enforces both when `--reconcile-once` is absent, and
    // `main` returns from the one-shot path without calling this function, so `None` here is an
    // internal invariant violation rather than an operator error.
    let (Some(nats_url), Some(seed_file)) =
        (config.nats_url.as_deref(), config.seed_file.as_deref())
    else {
        tracing::error!(
            "internal configuration error: serving mode started without a NATS URL or seed file"
        );
        return ExitCode::FAILURE;
    };

    let seed_store = SeedFileStore::new(seed_file);
    let mut seed = match prepare_root_seed(&config, &seed_store) {
        Ok(seed) => seed,
        Err(()) => return ExitCode::FAILURE,
    };

    let identity =
        mint_host_identity_with_ttl(seed, wall_clock_now_secs(), config.op_cert_ttl_secs);
    // The seed was copied out of the store into this stack array only so it could mint the
    // identity. Nothing below needs it; a renewal reloads it from custody. Do not leave the copy
    // resident for the process's life.
    seed.fill(0);
    tracing::info!(
        host_fp = %identity.host_fp.redacted(),
        device_fp = %identity.device_fp.redacted(),
        "host identity minted for this process"
    );

    // The admission token's *authority* remains the helper: this process does not re-implement
    // the callout's signature, expiry, or nonce checks, and never will (a second, driftable
    // verifier is worse than none). It does decode the configured file once at startup, because
    // embedding a newline-padded or empty file verbatim would only surface later as a uniform
    // callout refusal that names nothing. An unreadable or non-canonical configured file is a
    // startup failure, not a silent "connect without a token" — that would turn a typo into a
    // confusing refusal later.
    let admission_token_bytes = match &config.admission_token_file {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => {
                if let Err(error) = AdmissionToken::from_canonical_bytes(&bytes) {
                    tracing::error!(
                        path = %path.display(),
                        error = %error, // redaction-ok: ProtoError Display is static schema text, field names, and CBOR byte offsets; it never echoes the file's bytes
                        "the configured admission token file is not a canonical AdmissionToken; \
                         the helper would refuse this token at CONNECT (a trailing newline or an \
                         empty file is the usual cause)"
                    );
                    return ExitCode::FAILURE;
                }
                tracing::info!(
                    path = %path.display(),
                    len = bytes.len(),
                    "admission token file read and decoded"
                );
                Some(bytes)
            }
            Err(error) => {
                tracing::error!(
                    path = %path.display(),
                    error = %error, // redaction-ok: std::io::Error from fs::read of the operator-configured admission-token file — OS error kind/text only, never the file's bytes; the path is its own separately-logged field
                    "failed to read the configured admission token file"
                );
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    // Decompose the identity so the root private key can be dropped **before** the reconnect loop
    // starts. Only `root`'s public half survives (inside the borrowed credentials view); the
    // operating key and envelope device key must live for the process's life, because every
    // reconnect re-authenticates with them and A10.44/A10.45 keep `device_fp` stable within one
    // process. `op_signing`/`op_cert` are mutable because A10.45's renewal replaces them;
    // `device` is not, because a renewal must not re-mint it. `host_fp`/`device_fp` are `Copy`
    // copies of values already logged.
    let HostIdentity {
        root,
        mut op_signing,
        mut op_cert,
        device,
        host_fp,
        device_fp,
    } = identity;
    let host_root_pk = root.public_key();
    // The issuer built below and the credentials view above need only these public/borrowed
    // pieces. Dropping the root private key here means its wrapped `SigningKey` (which zeroizes on
    // drop) is gone before any reconnect attempt; nothing below signs as the root, including a
    // renewal (which reloads the seed and drops that root again in
    // `reload_seed_and_renew`).
    drop(root);
    tracing::debug!(
        host_fp = %host_fp.redacted(),
        device_fp = %device_fp.redacted(),
        "root private key dropped after the identity was decomposed for reconnects"
    );

    let device = Arc::new(device);

    // The gate the running daemon's cap issuer observes. A failed renewal flips it off so
    // existing sessions keep running while no new capability is minted (A10.45); a successful
    // renewal flips it back before the planned reconnect.
    let issuance_gate = Arc::new(AtomicBool::new(true));

    // Two-thirds of this process's current operating-certificate lifetime. Recomputed after
    // every successful renewal; a failed renewal pushes it to the retry instant instead.
    let mut renew_at = next_renewal_at(op_cert.ts, op_cert.exp);

    // Only `bind_ip` is configurable in this slice; the lifecycle durations and the concurrency
    // cap keep `HostOptions`' defaults (taken from one `default()` value rather than restated
    // here, so a future default change cannot silently disagree with this binary).
    let defaults = HostOptions::default();
    let options = HostOptions {
        bind_ip: config.bind_ip,
        ice_timeout: defaults.ice_timeout,
        session_close_timeout: defaults.session_close_timeout,
        max_concurrent_connects: defaults.max_concurrent_connects,
        // Only `bind_ip` is configurable in this slice, so gathering stays host-only (the
        // default empty `IceConfig`). STUN/TURN operator configuration is td-c3badf's
        // follow-up surface, not this binary's.
        ice: defaults.ice,
    };

    // The admission token stays present until a connect **succeeds**. A failed attempt may never
    // have reached the callout (server down, DNS, timeout), and in `invite`/`closed` admission a
    // host that was never admitted would then be refused forever; a retry that did burn the same
    // host+nonce is safe because the burn is idempotent (A4). After a successful first connect it
    // is cleared, because A3b's already-admitted host connects on its certificate alone.
    let mut admission_token_bytes = admission_token_bytes;

    // One signal future for the whole loop: it installs the OS handlers on its first poll and is
    // polled again in every `select!` below, including each backoff sleep, so Ctrl-C/SIGTERM at any
    // point — connected, connecting, or waiting to retry — returns `SUCCESS`.
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    // Backoff and refusal-streak state. `attempt` counts consecutive failed attempts since the
    // host last *served* (`HostDaemon::run` returned `Ok`), so a daemon failing immediately after a
    // successful connect still ramps rather than re-CONNECTing once a second.
    let mut reconnects = ReconnectState::default();

    loop {
        // A10.45: serving an expired certificate is worse than stopping. Checked here, after every
        // successful connect, and on every failed renewal retry — the only ways this loop can wake.
        if let Err(()) = ensure_op_cert_unexpired(&op_cert, wall_clock_now_secs()) {
            return ExitCode::FAILURE;
        }

        // The borrowed view is rebuilt from the *current* operating credentials on every attempt:
        // a successful renewal replaces `op_signing`/`op_cert`, and the next connection must present
        // those, not the ones this process started with. `device` is the same `Arc` throughout, so
        // `device_fp` never moves (A10.44/A10.45).
        let credentials = HostConnectCredentials {
            host_root_pk,
            op_signing: &op_signing,
            op_cert: &op_cert,
            host_fp,
            device: &device,
        };

        // A non-secret discriminator for the live renewal proof: the certificate this connection
        // is about to present. A renewal replaces both the operating key and the certificate, so
        // the post-renewal line must carry a strictly later `op_cert_ts` than the first. Logged
        // immediately before `connect_host` on every attempt; no key material.
        tracing::info!(
            op_cert_ts = op_cert.ts,
            op_cert_exp = op_cert.exp,
            "connecting to NATS with the operating-key certificate"
        );

        // A fresh wall-clock read at every attempt, not a timestamp captured at process start: the
        // attestation's `ts` is checked against a ±2 minute server-time window (see `connect`'s
        // module docs), and this loop exists precisely to survive an outage longer than that.
        let connected = tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received");
                return ExitCode::SUCCESS;
            }
            result = connect_host(
                &credentials,
                nats_url,
                admission_token_bytes.as_deref(),
                wall_clock_now_secs(),
            ) => result,
        };

        let (client, devcert_publisher) = match connected {
            Ok(connected) => {
                // A successful connect consumes the admission token: from here on this host is
                // admitted, so A3b says it connects on its certificate alone.
                clear_admission_token_after_connect(&mut admission_token_bytes, true);
                // A successful connect ends any authorization-refusal streak. It deliberately does
                // not reset the backoff: that is reset only by a served connection below.
                reconnects.connected();
                connected
            }
            Err(error) => {
                // async-nats reports an unanswered callout request with the same undifferentiated
                // `authorization violation` as a revoked host (the helper answers both that way), so
                // a refusal is retried under the normal backoff until it has persisted across
                // MAX_CONSECUTIVE_AUTH_REFUSALS attempts. TLS and server-address parse failures
                // cannot become correct by retrying and are fatal at once.
                let class = classify_connect_error(&error);
                match reconnects.connect_failed(class) {
                    ConnectFailure::Misconfigured => {
                        tracing::error!(
                            error = %error, // redaction-ok: ConnectError Display is nkeys length/prefix/checksum text (Nkey arm), async_nats::ConnectError's kind text plus DNS/IO/TLS source text and the NATS server's own refusal text (Nats arm), async_nats::PublishError's fixed kind plus a length/closed-queue source (Publish arm), or the same kind of static text from a failed flush (Flush arm); it never carries the auth_token, the nkey seed, the certificate payload, or any Spindle member peer's bytes
                            "NATS connection failed in a way retrying cannot fix (TLS or server \
                             address misconfiguration); exiting"
                        );
                        return ExitCode::FAILURE;
                    }
                    ConnectFailure::RefusedForGood => {
                        tracing::error!(
                            error = %error, // redaction-ok: same ConnectError Display as above; never the auth_token, the nkey seed, the certificate payload, or any Spindle member peer's bytes
                            consecutive_refusals = reconnects.auth_refusals,
                            "NATS refused the host's credentials on every attempt across the whole \
                             backoff window; treating the host as revoked or misconfigured and \
                             exiting"
                        );
                        return ExitCode::FAILURE;
                    }
                    ConnectFailure::Retry(delay) => {
                        if class == ConnectFailureClass::AuthorizationRefusal {
                            // Includes the helper-still-re-subscribing case: NATS reports that as the
                            // same refusal, and it resolves on its own well inside the window.
                            tracing::warn!(
                                error = %error, // redaction-ok: same ConnectError Display as above; never the auth_token, the nkey seed, the certificate payload, or any Spindle member peer's bytes
                                consecutive_refusals = reconnects.auth_refusals,
                                max_consecutive_refusals = MAX_CONSECUTIVE_AUTH_REFUSALS,
                                delay_secs = delay.as_secs(),
                                "NATS refused the host's credentials; retrying (a helper that is \
                                 still re-subscribing after a broker restart answers the same way \
                                 as a revoked host)"
                            );
                        } else {
                            tracing::error!(
                                error = %error, // redaction-ok: same ConnectError Display as above; never the auth_token, the nkey seed, the certificate payload, or any Spindle member peer's bytes
                                delay_secs = delay.as_secs(),
                                "failed to connect the host to NATS; retrying with fresh credentials"
                            );
                        }
                        let delay =
                            clamp_to_certificate_expiry(delay, &op_cert, wall_clock_now_secs());
                        if sleep_or_shutdown(delay, shutdown.as_mut()).await {
                            tracing::info!("shutdown signal received");
                            return ExitCode::SUCCESS;
                        }
                        continue;
                    }
                }
            }
        };

        // `connect_host` has already published this process's `HostDeviceCert` (A10.37) and flushed
        // it before returning, so the host's identity is advertised before the daemon starts
        // serving. Its failure is folded into the connect error arm above.

        // A connect can outlive the certificate it presented; never start serving on one that is
        // already expired.
        if let Err(()) = ensure_op_cert_unexpired(&op_cert, wall_clock_now_secs()) {
            return ExitCode::FAILURE;
        }

        // The issuer is rebuilt for every connection from the identity the connection presented,
        // so every capability this host mints chains to the root the Auth Callout just
        // authenticated. It is recreated rather than moved because `HostDaemon` consumes it; the
        // operating key and certificate change only on an A10.45 renewal (otherwise only the
        // session credential is fresh). `GateableCapIssuer` shares `issuance_gate` with the
        // renewal arm below: a failed renewal turns issuance off without taking this daemon, and
        // the sessions it already serves, down. See `HostDaemon::with_cap_issuer`'s doc comment
        // for why the daemon takes this seam rather than owning key custody itself.
        let issuer = GateableCapIssuer::new(
            RootKeyCapIssuer::new(host_root_pk, op_cert.clone(), op_signing.clone()),
            Arc::clone(&issuance_gate),
        );
        let daemon =
            HostDaemon::new_shared(client, Arc::clone(&device), host_fp, config.store.clone())
                .with_cap_issuer(Box::new(issuer))
                .with_upload_locks(upload_locks.clone());

        let outcome = {
            // The daemon future is one-shot, and a *failed* renewal must keep this same daemon —
            // and so its live sessions — running. That is why renewal is an arm of this inner
            // select rather than an unconditional `continue` of the outer loop: only a successful
            // renewal (or the daemon returning) breaks it.
            // `HostOptions` is `Clone` (not `Copy`) since td-c3badf gave it an `IceConfig`;
            // this daemon's config is fixed for the process, so each renewal round reuses a copy.
            let run = daemon.run(options.clone());
            tokio::pin!(run);
            loop {
                let now = wall_clock_now_secs();
                let renewal_delay = std::time::Duration::from_secs(renew_at.saturating_sub(now));
                tokio::select! {
                    // `biased` and the shutdown branch first are deliberate: `shutdown_signal`
                    // installs the OS signal handlers on its first poll, and this branch keeps a
                    // SIGINT/SIGTERM from racing the daemon's own startup work below.
                    biased;
                    _ = &mut shutdown => {
                        tracing::info!("shutdown signal received");
                        // Dropping the daemon drops the NATS client and its SQLite connections;
                        // dropping the guard aborts the reconnect-republish pump and releases its
                        // client clone. The signaling run loop has no separate shutdown channel
                        // (`HostDaemon::run`'s doc comment), so there is nothing else to drain.
                        drop(devcert_publisher);
                        return ExitCode::SUCCESS;
                    }
                    result = &mut run => break ServingOutcome::Daemon(result),
                    _ = tokio::time::sleep(renewal_delay) => {
                        // A10.45: if the certificate actually expired before this attempt could
                        // succeed, stop serving rather than present it.
                        let now = wall_clock_now_secs();
                        if let Err(()) = ensure_op_cert_unexpired(&op_cert, now) {
                            return ExitCode::FAILURE;
                        }
                        match reload_seed_and_renew(
                            &seed_store,
                            &host_root_pk,
                            now,
                            config.op_cert_ttl_secs,
                        ) {
                            Ok((new_signing, new_cert)) => {
                                op_signing = new_signing;
                                op_cert = new_cert;
                                renew_at = next_renewal_at(op_cert.ts, op_cert.exp);
                                issuance_gate.store(true, Ordering::Release);
                                tracing::info!(
                                    ts = op_cert.ts,
                                    exp = op_cert.exp,
                                    "operating-key certificate renewed; reconnecting with fresh \
                                     credentials (a renewal is a planned reconnect)"
                                );
                                break ServingOutcome::Renewed;
                            }
                            Err(error) => {
                                // A10.45's failure rule: keep this daemon serving, refuse to
                                // issue *new* capabilities, log the reason, retry.
                                issuance_gate.store(false, Ordering::Release);
                                let now = wall_clock_now_secs();
                                if let Err(()) = ensure_op_cert_unexpired(&op_cert, now) {
                                    return ExitCode::FAILURE;
                                }
                                // Wake at the fixed retry instant, or at `exp` if that comes
                                // first, so the expiry check can never be delayed past the
                                // certificate's life.
                                let retry_in = RENEWAL_RETRY_SECS.min(op_cert.exp - now);
                                renew_at = now.saturating_add(retry_in);
                                tracing::error!(
                                    error = %error, // redaction-ok: RenewalError Display wraps KeyStoreError (operator-configured seed path, octal mode or byte count, and io::Error OS text) or static root-change text; it never carries the seed, a private key, or member data
                                    retry_in_secs = retry_in,
                                    "operating-key certificate renewal failed; keeping existing \
                                     sessions alive, refusing to issue new capabilities, and \
                                     retrying"
                                );
                                // Deliberately stay in this select: the daemon and every session
                                // it already serves are untouched.
                            }
                        }
                    }
                }
            }
        };

        // The guard must not outlive the connection it serves: the next iteration publishes on a
        // fresh client. Dropping it aborts this iteration's pump and releases its client clone.
        drop(devcert_publisher);

        let delay = match outcome {
            ServingOutcome::Renewed => {
                // A renewal is a planned reconnect: go straight back to `connect_host`, which
                // re-authenticates with the new operating key and re-mints/re-publishes the
                // device certificate under it. No backoff — this connection served healthily.
                reconnects.served();
                continue;
            }
            ServingOutcome::Daemon(result) => match result {
                Ok(()) => {
                    // The signaling loop only returns `Ok(())` when the NATS client closes. That
                    // is now the normal "connection lost" signal, not a terminal condition:
                    // reconnect with a fresh per-session credential (A4 step 3) while keeping this
                    // process's envelope `device_fp` (A10.44/A10.45). A served connection also
                    // resets the backoff.
                    let delay = reconnects.served_and_lost();
                    tracing::warn!(
                        delay_secs = delay.as_secs(),
                        "host daemon signaling loop ended because the NATS connection closed; \
                         reconnecting with fresh credentials"
                    );
                    delay
                }
                Err(error) => {
                    // `HostDaemonError`'s `Display` forwards `SignalingError`/`StoreError`
                    // bodies, some of which carry peer-supplied CBOR keys, untruncated subjects,
                    // member paths, or full fingerprints. `HostDaemon::run` has already logged the
                    // redacted cause; this line names which stage failed without repeating the
                    // unsafe text.
                    //
                    // Every `run` failure is retryable, and it advances the backoff (only a
                    // connection that actually *served* resets it). There is deliberately no
                    // text-matching here for an authorization refusal: a revoked host is refused
                    // at its next CONNECT, where async-nats's typed error kind is classified;
                    // `run`'s error type carries no such kind.
                    let stage = match error {
                        HostDaemonError::Store(_) => "opening the host store",
                        HostDaemonError::Signaling(_) => "the signaling run loop",
                    };
                    let delay = reconnects.run_failed();
                    tracing::error!(
                        stage = stage,
                        delay_secs = delay.as_secs(),
                        "host daemon failed; the redacted cause was logged above; reconnecting \
                         with fresh credentials"
                    );
                    delay
                }
            },
        };

        // Never sleep past the certificate's expiry: the expiry check at the top of the loop must
        // run at `exp`, even while backing off from a lost connection.
        let delay = clamp_to_certificate_expiry(delay, &op_cert, wall_clock_now_secs());
        if sleep_or_shutdown(delay, shutdown.as_mut()).await {
            tracing::info!("shutdown signal received");
            return ExitCode::SUCCESS;
        }
    }
}

/// Shortens a reconnect/backoff wait so it cannot carry the loop past `op_cert.exp`.
///
/// A10.45 says the host stops serving when the certificate expires; while disconnected it is
/// not serving, but the expiry check still lives at the top of the loop, so the loop must wake at
/// `exp` rather than finishing an ordinary backoff first.
fn clamp_to_certificate_expiry(
    delay: std::time::Duration,
    op_cert: &HostOpKeyCert,
    now: u64,
) -> std::time::Duration {
    let remaining = op_cert.exp.saturating_sub(now);
    delay.min(std::time::Duration::from_secs(remaining))
}

/// Waits `delay` or until `shutdown` resolves, returning `true` when a shutdown signal won.
///
/// The reconnect backoff must be interruptible: a SIGINT/SIGTERM during a 30 s wait has to return
/// `SUCCESS` instead of being deferred until the sleep ends.
async fn sleep_or_shutdown<F: std::future::Future<Output = ()>>(
    delay: std::time::Duration,
    shutdown: std::pin::Pin<&mut F>,
) -> bool {
    tokio::select! {
        biased;
        _ = shutdown => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

/// How long a failed A10.45 renewal waits before retrying.
///
/// A fixed interval rather than the reconnect backoff: renewal has a one-third-of-`exp` window
/// (30 days at the default 90-day lifetime), so the retry rate should stay flat and small — a
/// keychain that is transiently locked should recover within a minute, not after an exponentially
/// growing delay. The sleep is clamped to the certificate's remaining lifetime so the
/// expiry check always runs at `exp` at the latest.
const RENEWAL_RETRY_SECS: u64 = 60;

/// Where a served connection ended: the daemon returned, or a renewal succeeded and the caller
/// should reconnect with the new operating credentials.
enum ServingOutcome {
    /// `HostDaemon::run` returned (connection lost or a run failure).
    Daemon(Result<(), HostDaemonError>),
    /// A10.45 renewal succeeded; the outer loop must reconnect (a planned reconnect).
    Renewed,
}

/// The instant A10.45 says renewal starts: **two-thirds of `exp`**, i.e.
/// `ts + 2 * (exp - ts) / 3`.
///
/// For A7b's 90-day certificate that is day 60, leaving a 30-day retry window. The arithmetic is
/// done in `u128` so a pathological `exp` cannot overflow the multiplication, and the result
/// saturates rather than wrapping. A certificate whose `exp` is at or before `ts` renews at `ts`
/// (the caller's expiry check stops it); this function never panics.
fn next_renewal_at(ts: u64, exp: u64) -> u64 {
    let lifetime = u128::from(exp.saturating_sub(ts));
    let offset = u64::try_from(lifetime * 2 / 3).unwrap_or(u64::MAX);
    ts.saturating_add(offset)
}

/// Returns `Ok(())` while `now` is inside the certificate's lifetime, and logs + returns `Err(())`
/// once it has expired.
///
/// A10.45: "it stops serving only when the certificate actually expires". Serving an expired
/// operating certificate means every capability that embeds it stops verifying, so the process
/// exits `FAILURE` instead.
fn ensure_op_cert_unexpired(op_cert: &HostOpKeyCert, now: u64) -> Result<(), ()> {
    if now < op_cert.exp {
        return Ok(());
    }
    tracing::error!(
        now = now,
        exp = op_cert.exp,
        "the operating-key certificate has expired; exiting rather than serving an expired \
         credential"
    );
    Err(())
}

/// Why an A10.45 renewal attempt failed.
#[derive(Debug, thiserror::Error)]
enum RenewalError {
    /// The root seed could not be reloaded from custody (absent, wrong length, too-wide mode, or
    /// an I/O error). `KeyStoreError`'s `Display` names the operator-configured path, mode, and
    /// byte count; it never carries the seed.
    #[error("reloading the host root seed failed: {0}")]
    Seed(#[from] KeyStoreError),
    /// The seed file changed on disk to a different root between start-up and renewal. Minting a
    /// certificate under that root would contradict the `host_root_pk` every connection presents,
    /// so the attempt fails rather than producing a credential the callout cannot verify.
    #[error("the seed file now encodes a different root identity than this process started with")]
    RootChanged,
}

/// Reloads the root seed and mints only the operating half of the identity (A10.45).
///
/// The root is loaded **here** and its private key is dropped when this function returns, so it
/// is never resident between renewals. The envelope `DeviceKey` is not an input: a renewal must
/// keep `device_fp` unchanged.
fn reload_seed_and_renew(
    seed_store: &SeedFileStore,
    host_root_pk: &VerifyingKey,
    now: u64,
    ttl_secs: u64,
) -> Result<(SigningKey, HostOpKeyCert), RenewalError> {
    let mut seed = seed_store.load_root_seed()?;
    if &RootKey::from_seed(seed).public_key() != host_root_pk {
        seed.fill(0);
        return Err(RenewalError::RootChanged);
    }
    // The seed is reloaded from custody for each renewal; wipe this stack copy as soon as the
    // operating key and certificate have been minted from it.
    let renewed = renew_operating_identity_with_ttl(seed, now, ttl_secs);
    seed.fill(0);
    Ok(renewed)
}

/// The reconnect backoff: 1 s, doubling per consecutive failed attempt, capped at 30 s.
///
/// `attempt` is the number of consecutive failures since the host last **served** (0 for the first
/// retry after a served connection), so the first reconnect is prompt. The cap keeps a long outage
/// from turning into an ever-longer wait, while leaving a failed-but-reachable broker a bounded
/// probe rate.
fn reconnect_delay(attempt: u32) -> std::time::Duration {
    const CAP_SECS: u64 = 30;
    // 2^5 = 32 is already past the cap; clamping the shift avoids overflow for large attempt
    // counts (which cannot occur in practice, though `attempt` saturates above).
    let secs = 1u64 << attempt.min(5);
    std::time::Duration::from_secs(secs.min(CAP_SECS))
}

/// Consecutive authorization refusals after which the process gives up.
///
/// Ten refusals span delays 1+2+4+8+16+30+30+30+30 = 151 s (>2.5 minutes) of continuous refusal.
/// That is far longer than a helper needs to re-subscribe after a broker restart — NATS answers an
/// unanswered callout request with the same undifferentiated `authorization violation` it answers a
/// revoked host with — yet short enough that a genuinely revoked host is reported, not retried
/// forever.
const MAX_CONSECUTIVE_AUTH_REFUSALS: u32 = 10;

/// How one `connect_host` failure is classified for the reconnect loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectFailureClass {
    /// TLS or server-address parsing cannot become correct by retrying: operator misconfiguration.
    Misconfiguration,
    /// async-nats's typed `authorization violation` at CONNECT. Retried under the normal backoff,
    /// but fatal once [`MAX_CONSECUTIVE_AUTH_REFUSALS`] consecutive refusals span the whole window.
    AuthorizationRefusal,
    /// DNS, I/O, timeout, or a local nkey/publish/flush error: retry.
    Transient,
}

/// Classifies a failed connect. The classification is a pure function of the error, so the loop's
/// refusal-window behavior is unit-testable without a broker.
fn classify_connect_error(error: &ConnectError) -> ConnectFailureClass {
    match error {
        ConnectError::Nats(error) => match error.kind() {
            async_nats::ConnectErrorKind::Tls | async_nats::ConnectErrorKind::ServerParse => {
                ConnectFailureClass::Misconfiguration
            }
            async_nats::ConnectErrorKind::AuthorizationViolation => {
                ConnectFailureClass::AuthorizationRefusal
            }
            _ => ConnectFailureClass::Transient,
        },
        ConnectError::Nkey(_) | ConnectError::Publish(_) | ConnectError::Flush(_) => {
            ConnectFailureClass::Transient
        }
    }
}

/// What the loop should do after a failed connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectFailure {
    /// Wait this long, then try again.
    Retry(std::time::Duration),
    /// A TLS or server-address parse failure: exit `FAILURE`.
    Misconfigured,
    /// Authorization was refused on every attempt across the whole bounded window: exit `FAILURE`.
    RefusedForGood,
}

/// Backoff and refusal-streak state for the reconnect loop.
#[derive(Debug, Default)]
struct ReconnectState {
    /// Consecutive failed attempts since the host last **served** (`HostDaemon::run` returned
    /// `Ok`). A successful `connect_host` alone does not reset this: a daemon that fails right
    /// after connecting (an unwritable store, say) must keep backing off instead of re-CONNECTing
    /// every second.
    attempt: u32,
    /// Consecutive [`ConnectFailureClass::AuthorizationRefusal`]s with no other outcome between.
    auth_refusals: u32,
}

impl ReconnectState {
    /// A `connect_host` success: clears the refusal streak. Deliberately leaves `attempt` alone.
    fn connected(&mut self) {
        self.auth_refusals = 0;
    }

    /// A connection served and ended by a **planned** reconnect (an A10.45 renewal): the next
    /// reconnect is prompt and the backoff resets.
    fn served(&mut self) {
        self.attempt = 0;
    }

    /// `HostDaemon::run` returned `Ok(())` — the host served, then lost its connection. The next
    /// reconnect is prompt, and the returned delay is the first backoff step.
    fn served_and_lost(&mut self) -> std::time::Duration {
        self.served();
        self.advance()
    }

    /// A `HostDaemon::run` failure: always retryable, and it advances the backoff.
    fn run_failed(&mut self) -> std::time::Duration {
        self.advance()
    }

    /// A `connect_host` failure, classified by [`classify_connect_error`].
    fn connect_failed(&mut self, class: ConnectFailureClass) -> ConnectFailure {
        match class {
            ConnectFailureClass::Misconfiguration => ConnectFailure::Misconfigured,
            ConnectFailureClass::AuthorizationRefusal => {
                self.auth_refusals = self.auth_refusals.saturating_add(1);
                if self.auth_refusals >= MAX_CONSECUTIVE_AUTH_REFUSALS {
                    return ConnectFailure::RefusedForGood;
                }
                ConnectFailure::Retry(self.advance())
            }
            ConnectFailureClass::Transient => {
                self.auth_refusals = 0;
                ConnectFailure::Retry(self.advance())
            }
        }
    }

    fn advance(&mut self) -> std::time::Duration {
        let delay = reconnect_delay(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        delay
    }
}

/// Clears the admission token once a connect has **succeeded** (A3b). A failed attempt must leave
/// it in place: the call may never have reached the callout (server down, DNS, timeout), and a host
/// that was never admitted still needs its bootstrap credential on the next attempt. Re-presenting
/// a token that did reach the callout is safe because burning the same host+nonce is idempotent
/// (A4).
fn clear_admission_token_after_connect(token: &mut Option<Vec<u8>>, connected: bool) {
    if connected {
        *token = None;
    }
}

/// Resolves when the process is asked to stop: Ctrl-C (SIGINT) everywhere, and SIGTERM on Unix.
///
/// Docker and systemd stop a container/service with SIGTERM, so installing only `ctrl_c()` would
/// leave a supervised deployment waiting for the SIGKILL that follows its grace period. The log
/// line names which signal fired; both use the "shutdown signal received" prefix the binary's
/// live test asserts on. A failure to install the SIGTERM handler is a warning, never fatal:
/// Ctrl-C still works, which is the one signal this process cannot lose.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(terminate) => terminate,
            Err(error) => {
                tracing::warn!(
                    error = %error, // redaction-ok: std::io::Error from signal-handler registration is OS error text, never member data
                    "could not install the SIGTERM handler; Ctrl-C (SIGINT) still shuts down"
                );
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!("shutdown signal received (SIGINT)");
                }
                return;
            }
        };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if result.is_ok() {
                    tracing::info!("shutdown signal received (SIGINT)");
                }
            }
            _ = terminate.recv() => {
                tracing::info!("shutdown signal received (SIGTERM)");
            }
        }
    }

    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("shutdown signal received (SIGINT)");
        }
    }
}

/// Resolves the root seed according to DESIGN.md A10.41's enrollment rule, then returns it.
///
/// - Seed present → use it. If an enrollment action was also requested, refuse: an existing
///   seed's `host_fp` is what every member is bound to, and overwriting it (which
///   `SeedFileStore::store_root_seed` would refuse anyway) must fail before anything is touched.
/// - Seed absent + `--init` → fill 32 bytes from the OS CSPRNG, store, and deliver the recovery
///   phrase once (stdout on a terminal, otherwise a configured phrase file).
/// - Seed absent + `--restore-seed-file <path>` or `SPINDLE_HOST_RESTORE_SEED` → parse the
///   phrase's seed and store it.
/// - Seed absent + none → refuse, naming every way to proceed. Never generate implicitly:
///   A10.41(b) makes an absent seed a refusal to start, not a quiet first run.
fn prepare_root_seed(config: &Config, store: &SeedFileStore) -> Result<[u8; ROOT_SEED_LEN], ()> {
    let enrollment_requested =
        config.init || config.restore_seed.is_some() || config.restore_seed_file.is_some();

    match store.load_root_seed() {
        Ok(seed) => {
            if enrollment_requested {
                tracing::error!(
                    path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
                    "an enrollment action was given but a host root seed already exists; \
                     refusing to overwrite the identity every member of this host is bound to"
                );
                return Err(());
            }
            Ok(seed)
        }
        Err(KeyStoreError::Absent { .. }) => {
            if config.init {
                init_root_seed(config, store)
            } else if enrollment_requested {
                restore_root_seed(config, store)
            } else {
                tracing::error!(
                    path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
                    "host root seed is absent and no enrollment action was given; refusing to \
                     generate one implicitly (DESIGN.md A10.41). Run once with --init to enroll \
                     this host, with --restore-seed-file <path> or SPINDLE_HOST_RESTORE_SEED to \
                     restore an existing identity."
                );
                Err(())
            }
        }
        Err(error) => {
            tracing::error!(
                path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
                error = %error, // redaction-ok: KeyStoreError Display names the operator-configured seed path and octal mode/byte count (A10.41 refusal diagnostic) plus any io::Error OS text; no peer bytes, identifiers, or secrets (operator-config exemption, lib.rs)
                "failed to load the host root seed"
            );
            if enrollment_requested {
                tracing::error!(
                    path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
                    "the configured enrollment source was NOT used because the existing seed file \
                     is unusable (wrong length, a wider mode, or an I/O error; the cause is \
                     logged above for this path). Move or repair that file before re-running \
                     enrollment."
                );
            }
            Err(())
        }
    }
}

/// Restores a seed from `--restore-seed-file` or `SPINDLE_HOST_RESTORE_SEED`. Only reached when
/// the seed file is absent and at least one of those sources is configured.
fn restore_root_seed(config: &Config, store: &SeedFileStore) -> Result<[u8; ROOT_SEED_LEN], ()> {
    let phrase = match restore_phrase(config) {
        Ok(phrase) => phrase,
        Err(()) => return Err(()),
    };
    let seed = match parse_recovery_phrase(&phrase) {
        Ok(seed) => seed,
        Err(error) => {
            // `RecoveryPhraseError` describes the encoding fault only; it never carries the
            // phrase.
            tracing::error!(
                error = %error, // redaction-ok: RecoveryPhraseError Display is static encoding-fault text and byte counts only; it never carries the phrase
                "--restore-seed-file/SPINDLE_HOST_RESTORE_SEED did not contain a valid host recovery phrase"
            );
            return Err(());
        }
    };
    if let Err(error) = store.store_root_seed(&seed) {
        tracing::error!(
            path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
            error = %error, // redaction-ok: KeyStoreError Display names the operator-configured seed path and octal mode/byte count (A10.41 refusal diagnostic) plus any io::Error OS text; no peer bytes, identifiers, or secrets (operator-config exemption, lib.rs)
            "failed to store the restored host root seed"
        );
        return Err(());
    }
    tracing::info!(
        path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
        "host root seed restored from the recovery phrase"
    );
    Ok(seed)
}

/// Returns the configured restore phrase. There is no precedence question: [`Config`] refuses
/// both sources at once, so at most one is present.
fn restore_phrase(config: &Config) -> Result<String, ()> {
    if let Some(phrase) = &config.restore_seed {
        return Ok(phrase.clone());
    }
    let Some(path) = &config.restore_seed_file else {
        // Unreachable: `prepare_root_seed` only calls this when a restore source is present.
        tracing::error!("no restore phrase source is configured");
        return Err(());
    };
    match read_phrase_file(path) {
        Ok(phrase) => Ok(phrase),
        Err(error) => {
            tracing::error!(
                path = %path.display(), // redaction-ok: operator-configured restore-seed path (operator-config exemption, lib.rs)
                error = %error, // redaction-ok: KeyStoreError Display names the operator-configured path, octal mode, or io::Error OS text; it never carries the file's contents
                "failed to read the configured --restore-seed-file"
            );
            Err(())
        }
    }
}

/// Reads a restore phrase file under the same POSIX discipline as the root seed itself: the
/// parent directory at most `0700` and the file at most `0600`, with the mode and ownership checks
/// applied to the descriptor the bytes are read from. Resolving the path once
/// (`open_secret_file`) is what closes the substitution window a check-then-`read_to_string(path)`
/// pair leaves open. A wider, symlinked, or foreign-owned entry is refused by naming the path and
/// the fact found.
#[cfg(unix)]
fn read_phrase_file(path: &Path) -> Result<String, KeyStoreError> {
    let mut file = open_secret_file(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|source| KeyStoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(text)
}

/// `#[cfg(not(unix))]` only: mode bits are not meaningful, and the seed-file store this binary
/// depends on is unsupported here, so refusing is consistent with the rest of the custody path.
#[cfg(not(unix))]
fn read_phrase_file(_path: &Path) -> Result<String, KeyStoreError> {
    Err(KeyStoreError::UnsupportedPlatform)
}

/// Generates, stores, and delivers a first-run root seed. `--init` only.
fn init_root_seed(config: &Config, store: &SeedFileStore) -> Result<[u8; ROOT_SEED_LEN], ()> {
    init_root_seed_with(config, store, std::io::stdout().is_terminal())
}

/// [`init_root_seed`] with the terminal check injected so the refusal ordering is testable
/// without a real TTY.
fn init_root_seed_with(
    config: &Config,
    store: &SeedFileStore,
    stdout_is_terminal: bool,
) -> Result<[u8; ROOT_SEED_LEN], ()> {
    // Resolve and *open* the phrase sink before generating or storing anything. A seed whose
    // phrase cannot be delivered — no sink, a wider-than-0700 parent, an existing phrase file,
    // an unwritable directory — creates an identity nobody can ever recover, and this is the last
    // point at which refusing leaves nothing persisted. Opening here also means the only failure
    // left after `store_root_seed` is the data write itself.
    let sink = match phrase_sink_for(config, stdout_is_terminal) {
        Ok(sink) => sink,
        Err(()) => return Err(()),
    };

    let mut seed = [0u8; ROOT_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    if let Err(error) = store.store_root_seed(&seed) {
        // The phrase file was created (empty, 0600) before this failure. Leaving it behind would
        // make the next `--init` fail on `create_new` with no obvious cause, so remove it.
        if let PhraseSink::File { path, .. } = &sink {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(remove_error) if remove_error.kind() == std::io::ErrorKind::NotFound => {}
                Err(remove_error) => tracing::warn!(
                    path = %path.display(), // redaction-ok: operator-configured recovery-phrase path (operator-config exemption, lib.rs)
                    error = %remove_error, // redaction-ok: std::io::Error OS text only, never the phrase (the file is empty at this point)
                    "could not remove the empty recovery phrase file after the seed store failed; delete it before retrying --init"
                ),
            }
        }
        tracing::error!(
            path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
            error = %error, // redaction-ok: KeyStoreError Display names the operator-configured seed path and octal mode/byte count (A10.41 refusal diagnostic) plus any io::Error OS text; no peer bytes, identifiers, or secrets (operator-config exemption, lib.rs)
            "failed to store the newly generated host root seed"
        );
        return Err(());
    }

    // A plain write, not `tracing`: this is the one secret this process ever emits, and a
    // subscriber's formatting/filtering/aggregation pipeline is exactly where it must never end
    // up. The write result is checked on both paths: the seed is already persisted, so a failed
    // delivery must say so loudly rather than exit as if enrollment succeeded.
    let phrase = format_recovery_phrase(&seed);
    match sink {
        PhraseSink::Stdout => {
            let mut stdout = std::io::stdout();
            if let Err(error) = writeln!(stdout, "{phrase}").and_then(|()| stdout.flush()) {
                tracing::error!(
                    error = %error, // redaction-ok: std::io::Error OS text only (broken pipe, closed descriptor); never the phrase
                    "the host root seed is now persisted, but its recovery phrase could NOT be \
                     written to stdout; this identity cannot be recovered without that phrase"
                );
                return Err(());
            }
            tracing::warn!(
                path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
                "the host recovery phrase was written once to stdout above. Anyone holding \
                 it can restore this host's root identity and act as this host. Store it \
                 offline; never paste it into a log, ticket, or shell history."
            );
        }
        PhraseSink::File { path, mut file } => {
            let write_result = writeln!(file, "{phrase}").and_then(|()| file.flush());
            if let Err(error) = write_result {
                // Do not leave a half-written phrase behind: a zero-length or partial file is
                // not recoverable material and would make the next `--init` fail on `create_new`.
                drop(file);
                match std::fs::remove_file(&path) {
                    Ok(()) => tracing::error!(
                        path = %path.display(), // redaction-ok: operator-configured recovery-phrase path (operator-config exemption, lib.rs)
                        error = %error, // redaction-ok: std::io::Error OS text only; never the phrase
                        "the host root seed is now persisted, but its recovery phrase could NOT \
                         be written to the configured phrase file; the partial file was removed, \
                         and this identity cannot be recovered without that phrase"
                    ),
                    Err(remove_error) if remove_error.kind() == std::io::ErrorKind::NotFound => {
                        tracing::error!(
                            path = %path.display(), // redaction-ok: operator-configured recovery-phrase path (operator-config exemption, lib.rs)
                            error = %error, // redaction-ok: std::io::Error OS text only; never the phrase
                            "the host root seed is now persisted, but its recovery phrase could \
                             NOT be written to the configured phrase file (the partial file had \
                             already disappeared); this identity cannot be recovered without \
                             that phrase"
                        )
                    }
                    Err(remove_error) => tracing::error!(
                        path = %path.display(), // redaction-ok: operator-configured recovery-phrase path (operator-config exemption, lib.rs)
                        error = %error, // redaction-ok: std::io::Error OS text only; never the phrase
                        remove_error = %remove_error, // redaction-ok: std::io::Error OS text only; never the phrase
                        "the host root seed is now persisted, but its recovery phrase could NOT \
                         be written to the configured phrase file, and the partial file could NOT \
                         be removed; delete that file and treat this identity as unrecoverable \
                         without the phrase"
                    ),
                }
                return Err(());
            }
            tracing::warn!(
                path = %path.display(), // redaction-ok: operator-configured recovery-phrase path (operator-config exemption, lib.rs)
                "the host recovery phrase was written once to the configured file. Anyone \
                 holding it can restore this host's root identity and act as this host. Move \
                 the file offline and delete it; never paste the phrase into a log, ticket, or \
                 shell history."
            );
        }
    }
    Ok(seed)
}

/// Where the one-time recovery phrase can be delivered without passing through a log pipeline.
enum PhraseSink {
    /// stdout is a terminal, so the phrase goes to the operator directly and nowhere else.
    Stdout,
    /// stdout is redirected (a service manager, a pipe, a log collector); this is an already-open
    /// fresh `0600` file in a `0700` parent, created before the seed is persisted so that a path
    /// problem cannot leave a stored seed whose phrase has nowhere to go.
    File { path: PathBuf, file: std::fs::File },
}

/// Chooses the phrase sink, refusing before any seed exists when neither channel is usable. The
/// terminal check is injected so the refusal ordering is testable without a real TTY.
fn phrase_sink_for(config: &Config, stdout_is_terminal: bool) -> Result<PhraseSink, ()> {
    if stdout_is_terminal {
        return Ok(PhraseSink::Stdout);
    }
    match &config.recovery_phrase_file {
        Some(path) => match open_phrase_file(path) {
            Ok(file) => Ok(PhraseSink::File {
                path: path.clone(),
                file,
            }),
            Err(error) => {
                tracing::error!(
                    path = %path.display(), // redaction-ok: operator-configured recovery-phrase path (operator-config exemption, lib.rs)
                    error = %error, // redaction-ok: KeyStoreError Display names the operator-configured path and octal mode or io::Error OS text; it never carries a phrase
                    "the configured recovery phrase file cannot be created; refusing to generate \
                     a host root seed whose phrase could not be delivered"
                );
                Err(())
            }
        },
        None => {
            tracing::error!(
                "stdout is not a terminal and no recovery phrase file is configured; refusing \
                 to generate a host root seed before its phrase can be delivered. Persisting a \
                 seed whose phrase could only reach a log stream (or nowhere) would create an \
                 identity nobody could ever recover. Set SPINDLE_HOST_RECOVERY_PHRASE_FILE or \
                 --recovery-phrase-file <path>, or run --init in a terminal."
            );
            Err(())
        }
    }
}

/// Opens a new `0600` phrase file inside a `0700` parent, refusing to overwrite an existing file.
/// [`create_secret_file`] opens and checks the parent once and then creates the entry through
/// that descriptor with `O_CREAT | O_EXCL | O_NOFOLLOW`, so the existence check is atomic and a
/// re-pointed path cannot redirect the write.
#[cfg(unix)]
fn open_phrase_file(path: &Path) -> Result<std::fs::File, KeyStoreError> {
    create_secret_file(path)
}

/// `#[cfg(not(unix))]` only: see [`read_phrase_file`].
#[cfg(not(unix))]
fn open_phrase_file(_path: &Path) -> Result<std::fs::File, KeyStoreError> {
    Err(KeyStoreError::UnsupportedPlatform)
}

/// Installs the Prometheus exporter once, iff `SPINDLE_METRICS_ADDR`/`--metrics-addr` is set.
///
/// A10.51 places the host's exporter in this binary. The behavior matches
/// `crates/spindle-helper/src/bin/helper.rs`'s `init_metrics_exporter`, deliberately: an
/// unparseable address or a bind/set-recorder failure is a **warning**, never fatal — the daemon
/// must keep serving even if the scrape endpoint cannot start, and every metrics macro stays a
/// no-op when no recorder was installed. The listener has no authentication or TLS; prefer a
/// loopback bind unless the network is trusted. The address is operator configuration, not a
/// member identity or endpoint, so logging it is permitted under this crate's redaction policy.
fn init_metrics_exporter(metrics_addr: Option<&str>) {
    let Some(raw_addr) = metrics_addr else {
        return;
    };
    let addr = match raw_addr.parse::<SocketAddr>() {
        Ok(addr) => addr,
        Err(error) => {
            tracing::warn!(
                error = %error, // redaction-ok: std::net::AddrParseError Display is static text ("invalid socket address syntax"), never the input
                "invalid SPINDLE_METRICS_ADDR/--metrics-addr — metrics exporter disabled"
            );
            return;
        }
    };
    match PrometheusBuilder::new().with_http_listener(addr).install() {
        Ok(()) => tracing::info!(
            %addr,
            "metrics exporter listening (Prometheus scrape endpoint)"
        ),
        Err(error) => tracing::warn!(
            error = %error, // redaction-ok: metrics_exporter_prometheus::BuildError Display is static build/bind/recorder text, no member identifiers or payload bytes
            "metrics exporter could not be installed — metrics disabled"
        ),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use spindle_hostd::HOST_OP_CERT_TTL_SECS;
    use tempfile::TempDir;

    use super::*;

    fn private_dir() -> TempDir {
        let dir = TempDir::new().expect("temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        dir
    }

    /// The fields under test, with everything else required by [`Config`] filled in directly:
    /// no environment variable is read, so these tests cannot be affected by the developer's
    /// shell and need no environment lock.
    fn test_config(dir: &Path) -> Config {
        Config {
            nats_url: Some("nats://example.test:4222".to_string()),
            seed_file: Some(dir.join("host.seed")),
            store: dir.join("host.db"),
            bind_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            admission_token_file: None,
            recovery_phrase_file: None,
            init: true,
            restore_seed: None,
            restore_seed_file: None,
            metrics_addr: None,
            op_cert_ttl_secs: HOST_OP_CERT_TTL_SECS,
            reconcile_once: false,
            reconcile_interval_secs: None,
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// `test_config` always supplies the serving-mode seed path; these tests only exercise custody.
    fn configured_seed_path(config: &Config) -> &Path {
        config
            .seed_file
            .as_deref()
            .expect("test config always has a seed file")
    }

    /// The HIGH regression: a non-TTY stdout with no phrase file must be refused *before* the
    /// seed is generated and stored, not after.
    #[test]
    fn init_refuses_before_persisting_when_stdout_is_not_a_terminal_and_no_phrase_file_is_configured(
    ) {
        let dir = private_dir();
        let config = test_config(dir.path());
        let store = SeedFileStore::new(configured_seed_path(&config));

        assert!(init_root_seed_with(&config, &store, false).is_err());
        assert!(
            !configured_seed_path(&config).exists(),
            "the refusal must happen before the seed is persisted"
        );
    }

    /// The other side of the same ordering: a phrase path that fails its A10.41 parent-mode check
    /// is refused before the seed exists, so no unrecoverable identity is left on disk.
    #[test]
    fn init_refuses_a_phrase_file_in_a_wider_parent_before_persisting() {
        let seed_dir = private_dir();
        let wide_dir = TempDir::new().expect("wide temp dir");
        set_mode(wide_dir.path(), 0o755);
        let phrase_path = wide_dir.path().join("recovery.phrase");

        let mut config = test_config(seed_dir.path());
        config.recovery_phrase_file = Some(phrase_path.clone());
        let store = SeedFileStore::new(configured_seed_path(&config));

        assert!(init_root_seed_with(&config, &store, false).is_err());
        assert!(
            !configured_seed_path(&config).exists(),
            "a phrase-path refusal must happen before the seed is persisted"
        );
        assert!(
            !phrase_path.exists(),
            "the refused phrase file must not be created"
        );
    }

    #[test]
    fn opening_a_phrase_file_refuses_an_existing_file() {
        let dir = private_dir();
        let path = dir.path().join("recovery.phrase");
        fs::write(&path, b"already here").expect("write existing phrase file");
        set_mode(&path, 0o600);

        match open_phrase_file(&path) {
            Err(KeyStoreError::Io { source, .. }) => {
                assert_eq!(source.kind(), std::io::ErrorKind::AlreadyExists)
            }
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
        assert_eq!(
            fs::read(&path).expect("existing file is untouched"),
            b"already here"
        );
    }

    /// If the seed store loses its race, the phrase file opened before it is removed rather than
    /// left behind as an empty file that would block the next `--init` on `create_new`.
    #[test]
    fn a_failed_seed_store_removes_the_already_created_phrase_file() {
        let dir = private_dir();
        let mut config = test_config(dir.path());
        let phrase_path = dir.path().join("recovery.phrase");
        config.recovery_phrase_file = Some(phrase_path.clone());
        fs::write(configured_seed_path(&config), [0x11; ROOT_SEED_LEN]).expect("pre-existing seed");
        set_mode(configured_seed_path(&config), 0o600);

        let store = SeedFileStore::new(configured_seed_path(&config));
        assert!(init_root_seed_with(&config, &store, false).is_err());
        assert!(
            !phrase_path.exists(),
            "the empty phrase file must be removed when the seed store fails"
        );
        assert_eq!(
            fs::read(configured_seed_path(&config)).expect("pre-existing seed survives"),
            [0x11; ROOT_SEED_LEN]
        );
    }

    #[test]
    fn read_phrase_file_rejects_a_wider_file_mode() {
        let dir = private_dir();
        let path = dir.path().join("restore.phrase");
        fs::write(&path, b"any phrase").expect("write phrase file");
        set_mode(&path, 0o644);

        match read_phrase_file(&path) {
            Err(KeyStoreError::SeedFileModeTooWide { mode, .. }) => assert_eq!(mode, 0o644),
            other => panic!("expected SeedFileModeTooWide, got {other:?}"),
        }
    }

    /// The read path resolves the phrase file once, through a checked parent descriptor. A
    /// symlinked entry is refused by `O_NOFOLLOW` rather than followed to a `0600` target.
    #[test]
    fn read_phrase_file_rejects_a_symlinked_entry() {
        let dir = private_dir();
        let target = dir.path().join("elsewhere.phrase");
        fs::write(&target, b"any phrase").expect("write link target");
        set_mode(&target, 0o600);
        let link = dir.path().join("restore.phrase");
        std::os::unix::fs::symlink(&target, &link).expect("symlink phrase file");

        match read_phrase_file(&link) {
            Err(KeyStoreError::SymlinkRefused { path }) => assert_eq!(path, link),
            other => panic!("expected SymlinkRefused, got {other:?}"),
        }
    }

    /// Creating a phrase file uses `O_CREAT | O_EXCL | O_NOFOLLOW` relative to the checked parent,
    /// so a pre-existing symlink at the name is refused without writing through it.
    #[test]
    fn open_phrase_file_refuses_a_preexisting_symlink() {
        let dir = private_dir();
        let target = dir.path().join("target.phrase");
        fs::write(&target, b"original").expect("write link target");
        set_mode(&target, 0o600);
        let link = dir.path().join("recovery.phrase");
        std::os::unix::fs::symlink(&target, &link).expect("symlink phrase file");

        match open_phrase_file(&link) {
            Err(KeyStoreError::Io { source, .. }) => {
                assert_eq!(source.kind(), std::io::ErrorKind::AlreadyExists)
            }
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
        assert_eq!(
            fs::read(&target).expect("link target is untouched"),
            b"original"
        );
        assert_eq!(
            fs::read_link(&link).expect("the link itself survives"),
            target
        );
    }

    #[test]
    fn an_empty_restore_phrase_file_is_rejected() {
        let dir = private_dir();
        let path = dir.path().join("restore.phrase");
        fs::write(&path, b"").expect("write empty phrase file");
        set_mode(&path, 0o600);

        let text = read_phrase_file(&path).expect("a 0600 empty file is readable");
        assert!(
            parse_recovery_phrase(&text).is_err(),
            "an empty phrase must never restore a seed"
        );
    }

    /// A10.45's cadence is **two-thirds of `exp`**, which is day 60 of A7b's 90-day certificate;
    /// the remaining third is the retry window.
    #[test]
    fn renewal_starts_at_two_thirds_of_the_certificate_lifetime() {
        assert_eq!(next_renewal_at(1_000, 1_090), 1_060);
        assert_eq!(next_renewal_at(0, 9), 6, "6 s into a 9 s certificate");

        let ts = 1_700_000_000;
        let exp = ts + HOST_OP_CERT_TTL_SECS;
        assert_eq!(
            next_renewal_at(ts, exp),
            ts + 2 * HOST_OP_CERT_TTL_SECS / 3,
            "the default certificate renews at day 60, not day 90"
        );
        assert_eq!(
            HOST_OP_CERT_TTL_SECS,
            90 * 24 * 60 * 60,
            "A7b's bound this cadence is defined against"
        );
    }

    /// A certificate with no lifetime (or an inverted one) renews at its own `ts`; the callers'
    /// expiry check, not this arithmetic, decides what to do then.
    #[test]
    fn a_zero_or_inverted_lifetime_renews_at_the_certificate_start() {
        assert_eq!(next_renewal_at(500, 500), 500);
        assert_eq!(next_renewal_at(500, 400), 500);
    }

    /// The renewal instant is inclusive of `ts` and never leaves `u64`, even for a pathological
    /// certificate lifetime.
    #[test]
    fn the_renewal_instant_stays_inside_the_certificate_window() {
        assert_eq!(next_renewal_at(0, u64::MAX), u64::MAX / 3 * 2);
        assert_eq!(next_renewal_at(u64::MAX - 2, u64::MAX), u64::MAX - 1);
    }

    /// A10.45 stops serving at `exp`, not before and not after.
    #[test]
    fn an_operating_certificate_is_refused_at_and_after_its_expiry() {
        let identity = mint_host_identity_with_ttl([0x11; ROOT_SEED_LEN], 1_000, 9);

        assert!(ensure_op_cert_unexpired(&identity.op_cert, 1_008).is_ok());
        assert!(
            ensure_op_cert_unexpired(&identity.op_cert, 1_009).is_err(),
            "now == exp means the certificate has expired"
        );
        assert!(ensure_op_cert_unexpired(&identity.op_cert, 1_010).is_err());
    }

    /// The renewal path reloads the seed itself, and refuses a seed file that now names a
    /// different root: certifying under it would contradict the `host_root_pk` every connection
    /// presents.
    #[test]
    fn a_renewal_reloads_the_seed_and_refuses_a_different_root() {
        let dir = private_dir();
        let seed_path = dir.path().join("host.seed");
        fs::write(&seed_path, [0x31; ROOT_SEED_LEN]).expect("write seed file");
        set_mode(&seed_path, 0o600);
        let store = SeedFileStore::new(seed_path);

        let same_root = RootKey::from_seed([0x31; ROOT_SEED_LEN]).public_key();
        let (signing, cert) = reload_seed_and_renew(&store, &same_root, 1_000, 9)
            .expect("the seed file still names the process's root");
        assert_eq!(cert.host_op_pk, signing.verifying_key().as_bytes().to_vec());
        assert_eq!(cert.exp, 1_009);

        let different_root = RootKey::from_seed([0x32; ROOT_SEED_LEN]).public_key();
        assert!(
            matches!(
                reload_seed_and_renew(&store, &different_root, 1_000, 9),
                Err(RenewalError::RootChanged)
            ),
            "a swapped seed file must fail the renewal, not certify a foreign root"
        );
    }

    /// A reconnect backoff must not carry the loop past `exp`; the loop wakes at expiry and the
    /// top-of-loop check stops it.
    #[test]
    fn a_backoff_wait_is_clamped_to_the_certificate_expiry() {
        use std::time::Duration;

        let identity = mint_host_identity_with_ttl([0x12; ROOT_SEED_LEN], 1_000, 90);
        let backoff = Duration::from_secs(30);

        assert_eq!(
            clamp_to_certificate_expiry(backoff, &identity.op_cert, 1_000),
            backoff,
            "a wait that ends before `exp` is unchanged"
        );
        assert_eq!(
            clamp_to_certificate_expiry(backoff, &identity.op_cert, 1_070),
            Duration::from_secs(20),
            "the wait ends at `exp`, not after it"
        );
        assert_eq!(
            clamp_to_certificate_expiry(backoff, &identity.op_cert, 1_090),
            Duration::ZERO
        );
        assert_eq!(
            clamp_to_certificate_expiry(backoff, &identity.op_cert, 2_000),
            Duration::ZERO,
            "an already-expired certificate never yields a positive wait"
        );
    }

    /// Backoff ramps across both connect and `daemon.run` failures, and is reset only by a
    /// connection that actually served before it was lost — not merely by a successful CONNECT.
    /// This pins the whole sequence, including a run-error iteration.
    #[test]
    fn backoff_ramps_across_connect_and_run_failures_and_resets_only_after_serving() {
        use std::time::Duration;

        let mut state = ReconnectState::default();
        assert_eq!(
            state.connect_failed(ConnectFailureClass::Transient),
            ConnectFailure::Retry(Duration::from_secs(1))
        );
        assert_eq!(
            state.connect_failed(ConnectFailureClass::Transient),
            ConnectFailure::Retry(Duration::from_secs(2))
        );
        assert_eq!(
            state.connect_failed(ConnectFailureClass::Transient),
            ConnectFailure::Retry(Duration::from_secs(4))
        );

        // A successful CONNECT alone must not reset the ramp.
        state.connected();
        assert_eq!(state.run_failed(), Duration::from_secs(8));
        assert_eq!(state.run_failed(), Duration::from_secs(16));

        // A connection that served and was then lost does reset it.
        assert_eq!(state.served_and_lost(), Duration::from_secs(1));
        assert_eq!(state.run_failed(), Duration::from_secs(2));
    }

    /// Ten consecutive authorization refusals are fatal; nine are not, and a transient failure in
    /// between restarts the streak (the helper-still-re-subscribing case).
    #[test]
    fn authorization_refusals_are_fatal_only_after_the_bounded_window() {
        use std::time::Duration;

        let mut state = ReconnectState::default();
        for expected in [1u64, 2, 4, 8, 16, 30, 30, 30, 30] {
            assert_eq!(
                state.connect_failed(ConnectFailureClass::AuthorizationRefusal),
                ConnectFailure::Retry(Duration::from_secs(expected))
            );
        }
        assert_eq!(
            state.connect_failed(ConnectFailureClass::AuthorizationRefusal),
            ConnectFailure::RefusedForGood
        );
        assert_eq!(
            state.auth_refusals, MAX_CONSECUTIVE_AUTH_REFUSALS,
            "the window is exactly the configured number of consecutive refusals"
        );

        // A transient failure with no refusal in between resets the streak.
        let mut state = ReconnectState::default();
        for _ in 0..5 {
            assert!(matches!(
                state.connect_failed(ConnectFailureClass::AuthorizationRefusal),
                ConnectFailure::Retry(_)
            ));
        }
        assert!(matches!(
            state.connect_failed(ConnectFailureClass::Transient),
            ConnectFailure::Retry(_)
        ));
        for _ in 0..9 {
            assert!(matches!(
                state.connect_failed(ConnectFailureClass::AuthorizationRefusal),
                ConnectFailure::Retry(_)
            ));
        }
        assert_eq!(
            state.connect_failed(ConnectFailureClass::AuthorizationRefusal),
            ConnectFailure::RefusedForGood
        );
    }

    #[test]
    fn a_misconfiguration_class_is_fatal_without_a_backoff_step() {
        let mut state = ReconnectState::default();
        assert_eq!(
            state.connect_failed(ConnectFailureClass::Misconfiguration),
            ConnectFailure::Misconfigured
        );
    }

    /// An unparseable server address is a `ServerParse` failure, which must be classified as
    /// permanent misconfiguration rather than retried. No broker is needed: parsing fails locally.
    #[tokio::test]
    async fn a_malformed_server_address_is_classified_as_misconfiguration() {
        let error = match async_nats::connect("definitely not a server address").await {
            Ok(_) => panic!("an unparseable server address must not connect"),
            Err(error) => ConnectError::Nats(error),
        };
        assert_eq!(
            classify_connect_error(&error),
            ConnectFailureClass::Misconfiguration,
            "a server-address parse failure cannot be fixed by retrying"
        );
    }

    /// The admission token must survive a failed attempt and be consumed only by a successful one.
    /// A first attempt that never reached the callout must not strand a never-admitted host.
    #[test]
    fn admission_token_survives_a_failed_connect_and_is_cleared_by_a_successful_one() {
        let mut token = Some(vec![0xA5u8; 11]);

        clear_admission_token_after_connect(&mut token, false);
        assert_eq!(
            token.as_deref(),
            Some(&[0xA5u8; 11][..]),
            "a failed attempt must not consume the bootstrap token"
        );

        clear_admission_token_after_connect(&mut token, true);
        assert!(token.is_none(), "a successful connect consumes the token");

        clear_admission_token_after_connect(&mut token, true);
        assert!(token.is_none(), "clearing is idempotent");
    }
}
