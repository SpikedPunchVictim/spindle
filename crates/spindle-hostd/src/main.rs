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
//! recovery phrase is printed **once**, to **stdout**, by a plain `println!` rather than through
//! `tracing`: a secret must not enter a log pipeline or aggregator. Everything else this process
//! says goes to stderr through `tracing`.
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
use std::net::SocketAddr;
use std::process::ExitCode;

use metrics_exporter_prometheus::PrometheusBuilder;
use rand::rngs::OsRng;
use rand::RngCore as _;
use spindle_host_core::RootKeyCapIssuer;
use spindle_hostd::connect::connect_host;
use spindle_hostd::{
    format_recovery_phrase, mint_host_identity, parse_recovery_phrase, wall_clock_now_secs,
    HostDaemon, HostDaemonError, HostKeyStore, HostOptions, KeyStoreError, SeedFileStore,
    ROOT_SEED_LEN,
};

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

    // The admission token is opaque to this process: the helper is the verifier, and this binary
    // deliberately does not re-implement its validation (a second, driftable verifier is worse
    // than none). An unreadable configured file is a startup failure, not a silent "connect
    // without a token" — that would turn a typo into a confusing callout refusal later.
    let admission_token_bytes = match &config.admission_token_file {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => {
                tracing::info!(
                    path = %path.display(),
                    len = bytes.len(),
                    "admission token file read"
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
    let daemon = HostDaemon::new(
        client,
        identity.device,
        identity.host_fp,
        config.store.clone(),
    )
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
        result = daemon.run(options) => match result {
            Ok(()) => {
                tracing::info!("host daemon exited cleanly");
                ExitCode::SUCCESS
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
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received");
            // Dropping the daemon drops the NATS client and its SQLite connections. The signaling
            // run loop has no separate shutdown channel (`HostDaemon::run`'s doc comment), so
            // there is nothing else to drain.
            ExitCode::SUCCESS
        }
    }
}

/// Resolves the root seed according to DESIGN.md A10.41's enrollment rule, then returns it.
///
/// - Seed present → use it. If `--init`/`--restore-seed` was also given, refuse: an existing
///   seed's `host_fp` is what every member is bound to, and overwriting it (which
///   `SeedFileStore::store_root_seed` would refuse anyway) must fail before anything is touched.
/// - Seed absent + `--restore-seed <phrase>` → parse and store the phrase's seed.
/// - Seed absent + `--init` → fill 32 bytes from the OS CSPRNG, store, and print the recovery
///   phrase once.
/// - Seed absent + neither → refuse, naming both ways to proceed. Never generate implicitly:
///   A10.41(b) makes an absent seed a refusal to start, not a quiet first run.
fn prepare_root_seed(config: &Config, store: &SeedFileStore) -> Result<[u8; ROOT_SEED_LEN], ()> {
    match store.load_root_seed() {
        Ok(seed) => {
            if config.init || config.restore_seed.is_some() {
                tracing::error!(
                    path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
                    "--init/--restore-seed was given but a host root seed already exists; \
                     refusing to overwrite the identity every member of this host is bound to"
                );
                return Err(());
            }
            Ok(seed)
        }
        Err(KeyStoreError::Absent { .. }) => {
            if let Some(phrase) = &config.restore_seed {
                let seed = match parse_recovery_phrase(phrase) {
                    Ok(seed) => seed,
                    Err(error) => {
                        // `RecoveryPhraseError` describes the encoding fault only; it never
                        // carries the phrase.
                        tracing::error!(
                            error = %error, // redaction-ok: RecoveryPhraseError Display is static encoding-fault text and byte counts only; it never carries the phrase
                            "--restore-seed did not contain a valid host recovery phrase"
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
            } else if config.init {
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

                // Plain `println!`, not `tracing`: this is the one secret this process ever
                // prints, and a subscriber's formatting/filtering/aggregation pipeline is exactly
                // where it must never end up. stdout is reserved for this phrase — all logs go to
                // stderr (see `main`).
                println!("{}", format_recovery_phrase(&seed));
                tracing::warn!(
                    path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
                    "the host recovery phrase was written once to stdout above. Anyone holding \
                     it can restore this host's root identity and act as this host. Store it \
                     offline; never paste it into a log, ticket, or shell history."
                );
                Ok(seed)
            } else {
                tracing::error!(
                    path = %store.path().display(), // redaction-ok: operator-configured host seed path (SPINDLE_HOST_SEED_FILE/--seed-file), never member data (operator-config exemption, lib.rs)
                    "host root seed is absent and neither --init nor --restore-seed was given; \
                     refusing to generate one implicitly (DESIGN.md A10.41). Run once with \
                     --init to enroll this host, or with --restore-seed <phrase> to restore an \
                     existing identity."
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
