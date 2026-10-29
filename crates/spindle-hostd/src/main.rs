//! The headless `spindle-hostd` binary: one host identity, one NATS connection, one
//! [`HostDaemon::run`] future (td-539ffa slice 3).
//!
//! # Why this binary exists
//!
//! [`HostDaemon`] is deliberately a library (see `src/lib.rs`'s module doc comment): `apps/host`'s
//! Tauri shell will call it in-process, with a NATS client and key custody of its own. A server
//! deployment has neither of those, so this binary is the other shape — the headless one. It owns
//! the seed-file custody path, the first-run recovery-phrase ceremony, per-start identity minting
//! (A10.43/A10.44), the CONNECT `auth_token` (via
//! [`spindle_hostd::connect::connect_host`]), and the run loop.
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
//! # A lost NATS connection is process-fatal in this slice
//!
//! The CONNECT `auth_token` is minted once per process ([`connect_host`]), and async-nats 0.35
//! replays that static token on an automatic reconnect (`connector.rs:193`). The host session
//! attestation inside it is valid for only ±2 minutes, so a reconnect later than that window is
//! refused by the Auth Callout. [`spindle_hostd::connect`] therefore bounds reconnects, and this
//! binary treats a closed connection as terminal: [`HostDaemon::run`] ends, the process exits
//! non-zero, and a supervised restart re-mints the session credential (a fresh process gets a
//! fresh nkey, attestation, and token per A10.43/A10.44). A NATS blip is process-fatal by design;
//! supervised restart is the recovery.
//!
//! A mid-process certificate renewal (A10.45: re-issue the operating certificate at two-thirds of
//! its 90-day lifetime) is **not wired here**. A process that outlives `HOST_OP_CERT_TTL_SECS`
//! will keep presenting an expired certificate; that is a known gap in
//! [`spindle_hostd::identity`], not a property this binary silently works around.
//!
//! # Metrics
//!
//! The Prometheus exporter (A10.51) is installed once here, and only when `SPINDLE_METRICS_ADDR`
//! is set. Unset means no global recorder is installed and every `metrics` macro is a no-op. The
//! library itself never installs a recorder.
//!
//! # Redaction
//!
//! Every fingerprint in a log line is rendered through `Fingerprint::redacted()`. Credentials,
//! tokens, and the recovery phrase are never logged at all.

mod config;

use std::env;
use std::io::{IsTerminal as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use metrics_exporter_prometheus::PrometheusBuilder;
use rand::rngs::OsRng;
use rand::RngCore as _;
use spindle_host_core::RootKeyCapIssuer;
use spindle_hostd::connect::connect_host;
#[cfg(unix)]
use spindle_hostd::keystore::{check_file_mode, check_parent_mode};
use spindle_hostd::{
    format_recovery_phrase, mint_host_identity, parse_recovery_phrase, wall_clock_now_secs,
    HostDaemon, HostDaemonError, HostIdentity, HostKeyStore, HostOptions, KeyStoreError,
    SeedFileStore, ROOT_SEED_LEN,
};
use spindle_proto::artifacts::AdmissionToken;

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
                error = %error, // redaction-ok: ConfigError Display names flags/env vars, static parse text, and the operator's own --bind-ip/boolean input; ConfigError::unknown_arg truncates at '=' so a --restore-seed value is never embedded
                "invalid host daemon configuration; run with --help for usage"
            );
            return ExitCode::FAILURE;
        }
    };

    init_metrics_exporter(config.metrics_addr.as_deref());

    run(config).await
}

/// The running half of `main`: custody, identity, connect, daemon. Every failure logs its own
/// content-free cause and returns [`ExitCode::FAILURE`]; there is no error type crossing this
/// boundary because there is no caller to report to.
async fn run(config: Config) -> ExitCode {
    let seed_store = SeedFileStore::new(config.seed_file.as_path());
    let seed = match prepare_root_seed(&config, &seed_store) {
        Ok(seed) => seed,
        Err(()) => return ExitCode::FAILURE,
    };

    let identity = mint_host_identity(seed, wall_clock_now_secs());
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

    // A fresh wall-clock read at the call, not a timestamp captured at process start: the
    // attestation's `ts` is checked against a ±2 minute server-time window (see
    // `connect`'s module docs).
    let client = match connect_host(
        &identity,
        &config.nats_url,
        admission_token_bytes,
        wall_clock_now_secs(),
    )
    .await
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(
                error = %error, // redaction-ok: ConnectError Display is nkeys length/prefix/checksum text (Nkey arm) or async_nats::ConnectError's kind text plus DNS/IO/TLS source text and the NATS server's own refusal text (Nats arm); it never carries the auth_token, the nkey seed, or any Spindle member peer's bytes
                "failed to connect the host to NATS"
            );
            return ExitCode::FAILURE;
        }
    };

    // The issuer is built from the same identity the connection presented, so every capability
    // this host mints chains to the root the Auth Callout just authenticated. See
    // `HostDaemon::with_cap_issuer`'s doc comment for why the daemon takes this seam rather than
    // owning key custody itself.
    let issuer = RootKeyCapIssuer::new(
        identity.root.public_key(),
        identity.op_cert.clone(),
        identity.op_signing.clone(),
    );

    // Every consumer of the identity has now been served: `connect_host` presented it,
    // `RootKeyCapIssuer` owns the public half and its own signing copies, and the daemon needs
    // only the envelope device key and the root fingerprint. Destructure so the root private key
    // (and the operating key, whose private half the issuer already cloned) is dropped before the
    // daemon starts — its wrapped `SigningKey` zeroizes on drop. `host_fp`/`device_fp` are `Copy`
    // copies of values already logged; nothing below signs as the root.
    let HostIdentity {
        root: _,
        op_signing: _,
        op_cert: _,
        device,
        host_fp,
        device_fp,
    } = identity;
    tracing::debug!(
        host_fp = %host_fp.redacted(),
        device_fp = %device_fp.redacted(),
        "root private key dropped after the capability issuer was built"
    );

    let daemon = HostDaemon::new(client, device, host_fp, config.store.clone())
        .with_cap_issuer(Box::new(issuer));

    // Only `bind_ip` is configurable in this slice; the lifecycle durations and the concurrency
    // cap keep `HostOptions`' defaults (taken from one `default()` value rather than restated
    // here, so a future default change cannot silently disagree with this binary).
    let defaults = HostOptions::default();
    let options = HostOptions {
        bind_ip: config.bind_ip,
        ice_timeout: defaults.ice_timeout,
        session_close_timeout: defaults.session_close_timeout,
        max_concurrent_connects: defaults.max_concurrent_connects,
    };

    tokio::select! {
        // `biased` and the shutdown branch first are deliberate: `shutdown_signal` installs the
        // OS signal handlers on its first poll, and doing that before `daemon.run` logs "host
        // daemon starting" closes the startup window in which a SIGINT/SIGTERM still has its
        // default (process-killing) disposition.
        biased;
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
            // Dropping the daemon drops the NATS client and its SQLite connections. The signaling
            // run loop has no separate shutdown channel (`HostDaemon::run`'s doc comment), so
            // there is nothing else to drain.
            ExitCode::SUCCESS
        }
        result = daemon.run(options) => match result {
            Ok(()) => {
                // The signaling loop only returns `Ok(())` when the NATS client closes; a
                // command/request failure is the `Err` arm. Treating this as a clean exit would
                // report success for a host that is no longer reachable.
                tracing::error!(
                    "host daemon signaling loop ended because the NATS connection closed; the \
                     host is no longer reachable. Its CONNECT credential is minted once per \
                     process and cannot be replayed after the attestation's ±2 minute window, so \
                     restarting the process is what re-authenticates it (a fresh nkey, \
                     attestation, and token)"
                );
                ExitCode::FAILURE
            }
            Err(error) => {
                // `HostDaemonError`'s `Display` forwards `SignalingError`/`StoreError` bodies,
                // some of which carry peer-supplied CBOR keys, untruncated subjects, member paths,
                // or full fingerprints. `HostDaemon::run` has already logged the redacted cause;
                // this line names which stage failed without repeating the unsafe text.
                let stage = match error {
                    HostDaemonError::Store(_) => "opening the host store",
                    HostDaemonError::Signaling(_) => "the signaling run loop",
                };
                tracing::error!(
                    stage = stage,
                    "host daemon failed; the redacted cause was logged above"
                );
                ExitCode::FAILURE
            }
        },
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
/// parent directory at most `0700` and the file at most `0600`, checked before the phrase is
/// copied into this process. A wider entry is refused by naming the path and mode found.
#[cfg(unix)]
fn read_phrase_file(path: &Path) -> Result<String, KeyStoreError> {
    check_parent_mode(path)?;
    check_file_mode(path)?;
    std::fs::read_to_string(path).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// `#[cfg(not(unix))]` only: mode bits are not meaningful, and the seed-file store this binary
/// depends on is unsupported here, so refusing is consistent with the rest of the custody path.
#[cfg(not(unix))]
fn read_phrase_file(_path: &Path) -> Result<String, KeyStoreError> {
    Err(KeyStoreError::UnsupportedPlatform)
}

/// Generates, stores, and delivers a first-run root seed. `--init` only.
fn init_root_seed(config: &Config, store: &SeedFileStore) -> Result<[u8; ROOT_SEED_LEN], ()> {
    // Decide where the phrase can actually go *before* generating or storing anything. A seed
    // whose phrase is written into a log pipeline (or nowhere) creates an identity nobody can
    // ever recover; this is the last point at which refusing leaves nothing persisted.
    let sink = match phrase_sink(config) {
        Ok(sink) => sink,
        Err(()) => return Err(()),
    };

    let mut seed = [0u8; ROOT_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    if let Err(error) = store.store_root_seed(&seed) {
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
        PhraseSink::File(path) => {
            if let Err(error) = write_phrase_file(&path, &phrase) {
                tracing::error!(
                    path = %path.display(), // redaction-ok: operator-configured recovery-phrase path (operator-config exemption, lib.rs)
                    error = %error, // redaction-ok: KeyStoreError Display names the operator-configured path and octal mode or io::Error OS text; it never carries the phrase
                    "the host root seed is now persisted, but its recovery phrase could NOT be \
                     written to the configured phrase file; this identity cannot be recovered \
                     without that phrase"
                );
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
    /// stdout is redirected (a service manager, a pipe, a log collector); the phrase goes to a
    /// fresh `0600` file instead and the operator is told to move it offline and delete it.
    File(PathBuf),
}

/// Chooses the phrase sink, refusing before any seed exists when neither channel is usable.
fn phrase_sink(config: &Config) -> Result<PhraseSink, ()> {
    if std::io::stdout().is_terminal() {
        return Ok(PhraseSink::Stdout);
    }
    match &config.recovery_phrase_file {
        Some(path) => Ok(PhraseSink::File(path.clone())),
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

/// Writes `phrase` to a new `0600` file inside a `0700` parent (`check_parent_mode`, shared with
/// [`SeedFileStore`] rather than re-implemented), refusing to overwrite an existing file.
/// `create_new` makes the existence check atomic, so a second enrollment cannot silently replace
/// a phrase the operator may already have stored elsewhere.
#[cfg(unix)]
fn write_phrase_file(path: &Path, phrase: &str) -> Result<(), KeyStoreError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    check_parent_mode(path)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| KeyStoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    writeln!(file, "{phrase}").map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// `#[cfg(not(unix))]` only: see [`read_phrase_file`].
#[cfg(not(unix))]
fn write_phrase_file(_path: &Path, _phrase: &str) -> Result<(), KeyStoreError> {
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
