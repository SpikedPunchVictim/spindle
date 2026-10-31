//! Runtime configuration for the `spindle-hostd` binary: env vars first, then `--flag value`
//! overrides (flags win), hand-parsed in the same style as
//! `crates/spindle-helper/src/bin/helper.rs` so the two service binaries are configured the same
//! way. No `clap`: the flag set is small, and the helper's parser is the precedent this workspace
//! already runs in production.
//!
//! # Why every variable is `SPINDLE_`-prefixed
//!
//! The helper owns the unprefixed names (`NATS_URL`, `METRICS_ADDR`, `ADMISSION_MODE`, ...). A
//! host and a helper can legitimately run in the same shell or container, and a developer often
//! exports both stacks' variables at once; sharing `NATS_URL` or `METRICS_ADDR` would make one
//! process silently inherit the other's endpoint. `SPINDLE_`-prefixing the host's whole set keeps
//! the two configurations independent — the only thing a shared name could do is collide.
//!
//! # One-shot enrollment flags
//!
//! `--init`, `--restore-seed-file <path>`, and `SPINDLE_HOST_RESTORE_SEED` are all enrollment
//! actions, and DESIGN.md A10.41(b) forbids any of them from being an implicit fallback on an
//! absent seed. They are mutually exclusive (`ConfigError::ConflictingEnrollment`) and, in
//! `main`, refused outright when a seed file already exists rather than silently overwriting the
//! identity every member of this host is bound to.
//!
//! There is deliberately no inline `--restore-seed <phrase>` flag. A phrase passed in argv is
//! visible to every process listing on the machine and is written into shell history; the file
//! flag and the environment variable (`/proc/<pid>/environ` of the same user only, no shell
//! history) are the two exposed spellings. A rejected `--restore-seed=<phrase>` token is still
//! truncated at `=` by [`ConfigError::unknown_arg`], so the removal cannot turn into a leak.

use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use spindle_hostd::reconcile_surface::MIN_SWEEP_INTERVAL_SECS;
use spindle_hostd::HOST_OP_CERT_TTL_SECS;
use spindle_net::signaling::{IceConfig, TurnConfig, TurnCredentials, MAX_TURN_TTL, MIN_TURN_TTL};

/// Runtime configuration for one host process.
#[derive(Debug)]
pub(crate) struct Config {
    /// `SPINDLE_NATS_URL` / `--nats-url`. Required in serving mode; `None` only with
    /// `--reconcile-once`, which never connects (and so needs no broker).
    pub(crate) nats_url: Option<String>,
    /// `SPINDLE_HOST_SEED_FILE` / `--seed-file`. Required in serving mode; `None` only with
    /// `--reconcile-once`, which never mints an identity. `SeedFileStore` enforces the `0600`
    /// file / `0700` directory rule of DESIGN.md A10.41.
    pub(crate) seed_file: Option<PathBuf>,
    /// `SPINDLE_HOST_STORE` / `--store`. Required; the SQLite database `HostDaemon::run` opens.
    pub(crate) store: PathBuf,
    /// `SPINDLE_HOST_BIND_IP` / `--bind-ip`. Defaults to `0.0.0.0`, matching `HostOptions::default`.
    pub(crate) bind_ip: IpAddr,
    /// `SPINDLE_ADMISSION_TOKEN_FILE` / `--admission-token-file`. `None` means this connect
    /// presents no admission token at all (`auth_token`'s host arm omits the key), which is the
    /// normal shape for an already-admitted host (DESIGN.md §A3b).
    pub(crate) admission_token_file: Option<PathBuf>,
    /// `SPINDLE_HOST_RECOVERY_PHRASE_FILE` / `--recovery-phrase-file <path>`. Required with
    /// `--init` when stdout is not a terminal: the recovery phrase must land in a file the
    /// operator can move offline, never in a log pipeline. Ignored when stdout is a terminal,
    /// where the phrase is printed instead.
    pub(crate) recovery_phrase_file: Option<PathBuf>,
    /// `SPINDLE_HOST_INIT` (`1`/`true`) / `--init`. Generate a root seed on first run, printing
    /// the recovery phrase once (to stdout, or to `recovery_phrase_file` when stdout is not a
    /// terminal).
    pub(crate) init: bool,
    /// `SPINDLE_HOST_RESTORE_SEED` only. Restore an existing identity from its recovery phrase on
    /// first run. There is no flag spelling: argv is visible to other processes and shell history.
    pub(crate) restore_seed: Option<String>,
    /// `--restore-seed-file <path>` (no env-var equivalent). Read the recovery phrase from a file
    /// whose mode is at most `0600` inside a directory of at most `0700`. A file keeps the phrase
    /// out of argv and out of the shell history the inline flag would have written it to.
    pub(crate) restore_seed_file: Option<PathBuf>,
    /// `SPINDLE_METRICS_ADDR` / `--metrics-addr`. `Some` installs the Prometheus exporter in
    /// `main`; `None` leaves every metrics macro a no-op.
    pub(crate) metrics_addr: Option<String>,
    /// `SPINDLE_HOST_OP_CERT_TTL_SECS` / `--op-cert-ttl-secs`. Lifetime of every operating-key
    /// certificate this process mints, in seconds. Defaults to A7b's 90-day
    /// [`HOST_OP_CERT_TTL_SECS`], which is also the maximum: the knob exists to shorten every
    /// window proportionally (renewal point, retry window, and expiry), not to lengthen the
    /// design's bound. The minimum is [`MIN_OP_CERT_TTL_SECS`] (3 s), so the two-thirds renewal
    /// point still leaves at least one second before expiry instead of landing on `ts`.
    pub(crate) op_cert_ttl_secs: u64,
    /// `SPINDLE_HOST_RECONCILE_ONCE` (`1`/`true`/`0`/`false`) / `--reconcile-once`. Run one
    /// operator repair pass against `store` — every share's upload ledger against disk, then both
    /// counter tables from the ledger — and exit. This path needs no NATS connection, seed, or
    /// host identity; it is an operator tool, not a serving mode.
    pub(crate) reconcile_once: bool,
    /// `SPINDLE_HOST_RECONCILE_INTERVAL_SECS` / `--reconcile-interval-secs`. `Some` schedules the
    /// disk -> ledger sweep while the host serves; `None` leaves startup and serving unchanged.
    /// The ledger -> counters reconcile is deliberately **not** schedulable — see `HELP` and
    /// `reconcile_surface`'s module doc comment.
    pub(crate) reconcile_interval_secs: Option<u64>,
    /// `SPINDLE_STUN_SERVERS` / `--stun-servers`. STUN servers this host queries for
    /// server-reflexive candidates, in the operator's order, with duplicates collapsed. Empty is
    /// the historical host-candidate-only behaviour.
    pub(crate) stun_servers: Vec<SocketAddr>,
    /// `SPINDLE_TURN_SERVER` / `--turn-server` plus exactly one credential form
    /// (`SPINDLE_TURN_USERNAME`+`SPINDLE_TURN_CREDENTIAL`, or
    /// `SPINDLE_TURN_SECRET`+`SPINDLE_TURN_LABEL`+`SPINDLE_TURN_TTL_SECS`). `None` means no relay.
    /// `Some` makes TURN available to the library. Selection is the library's A10.54 punch-first
    /// policy: attempt a punch for the shared `punch_window` (3 s default), then fall back to
    /// relay; both peers must configure TURN and the same window. This surface deliberately
    /// exposes no window knob. Credentials are redacted in
    /// [`TurnConfig`]/[`TurnCredentials`]' `Debug` implementations; this struct never holds a
    /// credential outside that type.
    pub(crate) turn: Option<TurnConfig>,
}

/// Everything [`Config::from_env_and_args`] can reject.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("missing required env var {0} (or --{1} flag)")]
    Missing(&'static str, &'static str),
    #[error("--{0} requires a value")]
    FlagMissingValue(String),
    #[error(
        "invalid value {given:?} for --bind-ip / SPINDLE_HOST_BIND_IP (expected an IP address)"
    )]
    BadBindIp { given: String },
    #[error("invalid value {given:?} for --init / SPINDLE_HOST_INIT (expected 1|true|0|false)")]
    BadBoolean { given: String },
    #[error(
        "invalid value {given:?} for --op-cert-ttl-secs / SPINDLE_HOST_OP_CERT_TTL_SECS (expected \
         a whole number of seconds in {min}..={max}, where {max} is the 90-day A7b lifetime)"
    )]
    BadOpCertTtl { given: String, min: u64, max: u64 },
    #[error(
        "invalid value {given:?} for --reconcile-interval-secs / \
         SPINDLE_HOST_RECONCILE_INTERVAL_SECS (expected a whole number of seconds >= {min})"
    )]
    BadReconcileInterval { given: String, min: u64 },
    #[error(
        "--init, --restore-seed-file, and SPINDLE_HOST_RESTORE_SEED cannot be combined with each \
         other or with --reconcile-once; choose one action"
    )]
    ConflictingEnrollment,
    #[error(
        "invalid value {given:?} for --stun-servers / SPINDLE_STUN_SERVERS (expected a \
         comma-separated list of host:port socket addresses; empty entries are not allowed)"
    )]
    BadStunServers { given: String },
    #[error(
        "invalid value {given:?} for --turn-server / SPINDLE_TURN_SERVER (expected a host:port \
         socket address)"
    )]
    BadTurnServer { given: String },
    #[error(
        "invalid value {given:?} for --turn-ttl-secs / SPINDLE_TURN_TTL_SECS (expected a whole \
         number of seconds in {min}..={max})"
    )]
    BadTurnTtl { given: String, min: u64, max: u64 },
    #[error(
        "--turn-server / SPINDLE_TURN_SERVER requires exactly one credential form: the static pair \
         --turn-username + --turn-credential (SPINDLE_TURN_USERNAME + SPINDLE_TURN_CREDENTIAL), or \
         the REST-secret form --turn-secret + --turn-label (SPINDLE_TURN_SECRET + \
         SPINDLE_TURN_LABEL)"
    )]
    MissingTurnCredentials,
    #[error(
        "TURN credentials were configured without --turn-server / SPINDLE_TURN_SERVER; set the \
         server or remove the credentials"
    )]
    TurnCredentialsWithoutServer,
    #[error(
        "static TURN credentials (--turn-username/--turn-credential, SPINDLE_TURN_USERNAME/\
         SPINDLE_TURN_CREDENTIAL) and REST-secret credentials (--turn-secret/--turn-label, \
         SPINDLE_TURN_SECRET/SPINDLE_TURN_LABEL) cannot be combined; choose one form"
    )]
    MixedTurnCredentials,
    #[error(
        "incomplete TURN credential form: the static pair needs both --turn-username and \
         --turn-credential (SPINDLE_TURN_USERNAME, SPINDLE_TURN_CREDENTIAL); the REST-secret form \
         needs both --turn-secret and --turn-label (SPINDLE_TURN_SECRET, SPINDLE_TURN_LABEL)"
    )]
    IncompleteTurnCredentials,
    /// Only the part of the argument before the first `=` is ever kept — see
    /// [`ConfigError::unknown_arg`], which is the only way this variant is constructed.
    #[error("unrecognized argument: {0} (any `=<value>` suffix is withheld — it may be a secret)")]
    UnknownArg(String),
}

impl ConfigError {
    /// Builds [`ConfigError::UnknownArg`] from a raw argv token, keeping only the part before the
    /// first `=`.
    ///
    /// This parser is space-separated, so the common `--flag=value` spelling of a *recognized*
    /// flag falls through to the unknown-argument arm with the value still attached. The removed
    /// inline enrollment flag and a hand-written `SPINDLE_HOST_RESTORE_SEED`-style spelling both
    /// make that shape a phrase-bearing token, and echoing it into a log is the same credential
    /// leak `helper.rs`'s identically named helper exists to prevent. Truncating at the `=` keeps
    /// the diagnosis without the secret.
    fn unknown_arg(arg: &str) -> ConfigError {
        ConfigError::UnknownArg(arg.split('=').next().unwrap_or("").to_string())
    }
}

const HELP: &str = r#"spindle-hostd — the headless Spindle host daemon

USAGE:
    spindle-hostd [FLAGS]

Every flag has an env-var equivalent unless the entry says "(no env equivalent)"; flags override
the env var if both are set:
    --nats-url <url>            SPINDLE_NATS_URL             (required)
    --seed-file <path>          SPINDLE_HOST_SEED_FILE       (required; file mode 0600, parent 0700)
    --store <path>              SPINDLE_HOST_STORE           (required; SQLite database path)
    --bind-ip <ip>              SPINDLE_HOST_BIND_IP         (default: 0.0.0.0)
    --admission-token-file <p>  SPINDLE_ADMISSION_TOKEN_FILE (optional; unset sends no token)
    --init                      SPINDLE_HOST_INIT            (1|true|0|false; generate a seed on
                                                             first run)
    --recovery-phrase-file <p>  SPINDLE_HOST_RECOVERY_PHRASE_FILE
                                                             (required with --init when stdout is
                                                             not a terminal; the file must not
                                                             exist, mode 0600, parent 0700)
    --restore-seed-file <path>  (no env equivalent)          (restore an existing identity once;
                                                             phrase file mode 0600, parent 0700)
    --metrics-addr <addr>       SPINDLE_METRICS_ADDR         (optional; Prometheus scrape listener,
                                                             e.g. 127.0.0.1:9100. Unset → no
                                                             recorder is installed)
    --op-cert-ttl-secs <n>      SPINDLE_HOST_OP_CERT_TTL_SECS (optional; operating-certificate
                                                             lifetime in seconds, 3..=7776000,
                                                             default 7776000 = 90 days. Shortening
                                                             it shortens the renewal point, the
                                                             retry window, and the expiry together)
    --reconcile-once            SPINDLE_HOST_RECONCILE_ONCE  (1|true|0|false; run one operator
                                                             repair pass and exit — every share's
                                                             upload ledger is reconciled against
                                                             disk, then both quota counter tables
                                                             are recomputed from that ledger. Needs
                                                             no NATS connection, seed, or host
                                                             identity, but RUN IT WITH THE HOST
                                                             STOPPED: it is a separate process and
                                                             cannot share the in-process per-share
                                                             upload lock, so a live commit can be
                                                             mis-reconciled. The store must already
                                                             exist and be a Spindle store; it is
                                                             never created or migrated from foreign
                                                             contents. This flag exits, so
                                                             --reconcile-interval-secs and
                                                             --metrics-addr are ignored with it)
    --reconcile-interval-secs <n> SPINDLE_HOST_RECONCILE_INTERVAL_SECS
                                                             (optional; while serving, sweep every
                                                             share's upload ledger against disk
                                                             every <n> seconds, n >= 60. Only the
                                                             disk sweep is scheduled; the counter
                                                             reconcile is operator-only, see below.
                                                             Each sweep shares the per-share upload
                                                             lock with live commits, opens its own
                                                             store connection, and takes short
                                                             Immediate transactions, so it can
                                                             briefly block session writes)
    --stun-servers <a:3478,...> SPINDLE_STUN_SERVERS        (optional; comma-separated STUN
                                                             server socket addresses used to gather
                                                             server-reflexive candidates. Entries
                                                             are trimmed, empty entries are
                                                             rejected, duplicates are collapsed.
                                                             Unset means host candidates only; an
                                                             exported empty list is an error)
    --turn-server <addr>        SPINDLE_TURN_SERVER         (optional; TURN relay server. When
                                                             set, the library punches first for
                                                             its punch window (3 s default here)
                                                             and falls back to relay)
    --turn-username <name>      SPINDLE_TURN_USERNAME       (static TURN credentials: both
    --turn-credential <secret>  SPINDLE_TURN_CREDENTIAL       --turn-username and
                                                             --turn-credential are required)
    --turn-secret <secret>      SPINDLE_TURN_SECRET         (coturn use-auth-secret REST
    --turn-label <label>        SPINDLE_TURN_LABEL            credentials: both --turn-secret and
    --turn-ttl-secs <n>         SPINDLE_TURN_TTL_SECS         --turn-label are required; <n> is
                                                             the minted credential lifetime in
                                                             seconds, 1..=86400, default 3600)
    -h, --help                  show this message

A TURN server requires exactly one credential form: the static pair, or the REST-secret
secret+label pair. A partial form, a mix of both forms, or credentials without --turn-server is a
configuration error. STUN and TURN may each be set alone, both together, or neither; with neither,
the daemon gathers host candidates only (the historical behaviour).

When TURN is configured, the library punches first for the shared punch window (3 s default; this
daemon exposes no window knob and uses that default) and falls back to relay when the window
expires without a selected pair. Both peers must configure TURN and use the same window: a split
outcome fails the QUIC handshake and the caller retries. Configure STUN as well for the punch to
cross a NAT; the relay fallback works without it. Credentials come only from the operator's static
pair or REST secret: this daemon has no helper-minted credentials (helper.turn.get.<nfp>) yet.

A first run (no seed file) requires exactly one of --init, --restore-seed-file <path>, or
SPINDLE_HOST_RESTORE_SEED. There is deliberately no inline --restore-seed <phrase> flag: a phrase
in argv is visible to every process listing and is written to shell history.

Only the disk -> ledger sweep is schedulable. DB-vs-filesystem skew has genuine ongoing sources (a
crash between a filesystem operation and its ledger write, or an owner editing an uploaded file
out of band), while ledger-vs-counter drift cannot occur in normal operation — both move in one
Immediate transaction. The counter reconcile is therefore a repair tool for a bug: run it
explicitly with --reconcile-once, never on a schedule.
"#;

impl Config {
    pub(crate) fn from_env_and_args(
        mut args: impl Iterator<Item = String>,
    ) -> Result<Config, ConfigError> {
        let mut nats_url = env::var("SPINDLE_NATS_URL").ok();
        let mut seed_file = env::var("SPINDLE_HOST_SEED_FILE").ok();
        let mut store = env::var("SPINDLE_HOST_STORE").ok();
        let mut bind_ip = env::var("SPINDLE_HOST_BIND_IP").ok();
        let mut admission_token_file = env::var("SPINDLE_ADMISSION_TOKEN_FILE").ok();
        let mut recovery_phrase_file = env::var("SPINDLE_HOST_RECOVERY_PHRASE_FILE").ok();
        let mut init = env::var("SPINDLE_HOST_INIT").ok();
        let restore_seed = env::var("SPINDLE_HOST_RESTORE_SEED").ok();
        let mut restore_seed_file = None;
        let mut metrics_addr = env::var("SPINDLE_METRICS_ADDR").ok();
        let mut op_cert_ttl_secs = env::var("SPINDLE_HOST_OP_CERT_TTL_SECS").ok();
        let mut reconcile_once = env::var("SPINDLE_HOST_RECONCILE_ONCE").ok();
        let mut reconcile_interval_secs = env::var("SPINDLE_HOST_RECONCILE_INTERVAL_SECS").ok();
        let mut stun_servers = env::var("SPINDLE_STUN_SERVERS").ok();
        let mut turn_server = env::var("SPINDLE_TURN_SERVER").ok();
        let mut turn_username = env::var("SPINDLE_TURN_USERNAME").ok();
        let mut turn_credential = env::var("SPINDLE_TURN_CREDENTIAL").ok();
        let mut turn_secret = env::var("SPINDLE_TURN_SECRET").ok();
        let mut turn_label = env::var("SPINDLE_TURN_LABEL").ok();
        let mut turn_ttl_secs = env::var("SPINDLE_TURN_TTL_SECS").ok();

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
                "--seed-file" => {
                    seed_file =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("seed-file".to_string())
                        })?)
                }
                "--store" => {
                    store = Some(
                        args.next()
                            .ok_or_else(|| ConfigError::FlagMissingValue("store".to_string()))?,
                    )
                }
                "--bind-ip" => {
                    bind_ip = Some(
                        args.next()
                            .ok_or_else(|| ConfigError::FlagMissingValue("bind-ip".to_string()))?,
                    )
                }
                "--admission-token-file" => {
                    admission_token_file = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("admission-token-file".to_string())
                    })?)
                }
                "--init" => init = Some("true".to_string()),
                "--recovery-phrase-file" => {
                    recovery_phrase_file = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("recovery-phrase-file".to_string())
                    })?)
                }
                "--restore-seed-file" => {
                    restore_seed_file = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("restore-seed-file".to_string())
                    })?)
                }
                "--metrics-addr" => {
                    metrics_addr =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("metrics-addr".to_string())
                        })?)
                }
                "--op-cert-ttl-secs" => {
                    op_cert_ttl_secs = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("op-cert-ttl-secs".to_string())
                    })?)
                }
                "--reconcile-once" => reconcile_once = Some("true".to_string()),
                "--reconcile-interval-secs" => {
                    reconcile_interval_secs = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("reconcile-interval-secs".to_string())
                    })?)
                }
                "--stun-servers" => {
                    stun_servers =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("stun-servers".to_string())
                        })?)
                }
                "--turn-server" => {
                    turn_server =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("turn-server".to_string())
                        })?)
                }
                "--turn-username" => {
                    turn_username = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("turn-username".to_string())
                    })?)
                }
                "--turn-credential" => {
                    turn_credential = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("turn-credential".to_string())
                    })?)
                }
                "--turn-secret" => {
                    turn_secret =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("turn-secret".to_string())
                        })?)
                }
                "--turn-label" => {
                    turn_label =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("turn-label".to_string())
                        })?)
                }
                "--turn-ttl-secs" => {
                    turn_ttl_secs = Some(args.next().ok_or_else(|| {
                        ConfigError::FlagMissingValue("turn-ttl-secs".to_string())
                    })?)
                }
                other => return Err(ConfigError::unknown_arg(other)),
            }
        }

        let bind_ip = match bind_ip {
            Some(given) => given
                .parse::<IpAddr>()
                .map_err(|_| ConfigError::BadBindIp { given })?,
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let init = match init {
            Some(given) => parse_bool(&given)?,
            None => false,
        };
        let op_cert_ttl_secs = match op_cert_ttl_secs {
            Some(given) => parse_op_cert_ttl(&given)?,
            None => HOST_OP_CERT_TTL_SECS,
        };
        let reconcile_once = match reconcile_once {
            Some(given) => parse_bool(&given)?,
            None => false,
        };
        let reconcile_interval_secs = match reconcile_interval_secs {
            Some(given) => Some(parse_reconcile_interval(&given)?),
            None => None,
        };
        let stun_servers = match stun_servers {
            Some(given) => parse_stun_servers(&given)?,
            None => Vec::new(),
        };
        let turn_server = match turn_server {
            Some(given) => {
                Some(
                    given
                        .parse::<SocketAddr>()
                        .map_err(|_| ConfigError::BadTurnServer {
                            given: given.clone(),
                        })?,
                )
            }
            None => None,
        };
        let turn_ttl_secs = match turn_ttl_secs {
            Some(given) => Some(parse_turn_ttl(&given)?),
            None => None,
        };
        let turn = resolve_turn(
            turn_server,
            turn_username,
            turn_credential,
            turn_secret,
            turn_label,
            turn_ttl_secs,
        )?;
        if init && (restore_seed.is_some() || restore_seed_file.is_some()) {
            return Err(ConfigError::ConflictingEnrollment);
        }
        // Two restore sources would leave which phrase wins to parser order — the same ambiguity
        // the init/restore conflict refuses. One enrollment path per first run.
        if restore_seed.is_some() && restore_seed_file.is_some() {
            return Err(ConfigError::ConflictingEnrollment);
        }
        // `--reconcile-once` is a repair action that exits before identity custody is touched. An
        // enrollment action alongside it would be silently dropped (the one-shot path never calls
        // `prepare_root_seed`), so refuse rather than let an operator believe they enrolled.
        if reconcile_once && (init || restore_seed.is_some() || restore_seed_file.is_some()) {
            return Err(ConfigError::ConflictingEnrollment);
        }

        // The one-shot repair is an operator tool, not a serving mode: it opens the store, heals
        // it, and exits. It never connects to NATS and never touches identity custody, so a broker
        // URL and a seed file are not requirements for it. Serving mode requires both, exactly as
        // before.
        let nats_url = if reconcile_once {
            nats_url
        } else {
            Some(nats_url.ok_or(ConfigError::Missing("SPINDLE_NATS_URL", "nats-url"))?)
        };
        let seed_file = if reconcile_once {
            seed_file.map(PathBuf::from)
        } else {
            Some(PathBuf::from(seed_file.ok_or(ConfigError::Missing(
                "SPINDLE_HOST_SEED_FILE",
                "seed-file",
            ))?))
        };

        Ok(Config {
            nats_url,
            seed_file,
            store: PathBuf::from(store.ok_or(ConfigError::Missing("SPINDLE_HOST_STORE", "store"))?),
            bind_ip,
            admission_token_file: admission_token_file.map(PathBuf::from),
            recovery_phrase_file: recovery_phrase_file.map(PathBuf::from),
            init,
            restore_seed,
            restore_seed_file: restore_seed_file.map(PathBuf::from),
            metrics_addr,
            op_cert_ttl_secs,
            reconcile_once,
            reconcile_interval_secs,
            stun_servers,
            turn,
        })
    }

    /// The library [`IceConfig`] these operator settings describe.
    ///
    /// Empty settings (the default) produce `IceConfig::default()`, so a host with no STUN/TURN
    /// configuration behaves exactly as it did before this surface existed. The built value is
    /// immutable for the process and is threaded into every `HostOptions` the reconnect loop
    /// builds (see `main::host_options_from_config`).
    pub(crate) fn ice_config(&self) -> IceConfig {
        IceConfig {
            stun_servers: self.stun_servers.clone(),
            turn: self.turn.clone(),
            // No punch-policy knob belongs to this surface: any library default (e.g. a
            // punch-first window) is taken from `IceConfig::default()` rather than restated here.
            ..IceConfig::default()
        }
    }
}

/// Default lifetime of a locally-minted REST-secret TURN credential, in seconds. Matches the
/// reference stack's helper `TURN_TTL_SECS` (`deploy/docker-compose.yml`).
const DEFAULT_TURN_TTL_SECS: u64 = 3600;

/// Parses `SPINDLE_STUN_SERVERS` / `--stun-servers`: a comma-separated list of `host:port` socket
/// addresses. Entries are trimmed, empty entries are rejected rather than skipped (a trailing or
/// doubled comma is a typo, not "no server"), and duplicates are collapsed while keeping the
/// operator's order.
fn parse_stun_servers(given: &str) -> Result<Vec<SocketAddr>, ConfigError> {
    let mut servers: Vec<SocketAddr> = Vec::new();
    for entry in given.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::BadStunServers {
                given: given.to_string(),
            });
        }
        let server = trimmed
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::BadStunServers {
                given: given.to_string(),
            })?;
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    Ok(servers)
}

/// Parses `SPINDLE_TURN_TTL_SECS` / `--turn-ttl-secs`: a whole number of seconds inside the range
/// the library's REST-secret credential minting accepts. The bounds are the library's exported
/// [`MIN_TURN_TTL`]/[`MAX_TURN_TTL`], not a copy, so config validation and mint-time validation
/// cannot drift apart. Out-of-range values are configuration errors rather than a clamped or "no
/// expiry" credential.
fn parse_turn_ttl(given: &str) -> Result<u64, ConfigError> {
    let invalid = || ConfigError::BadTurnTtl {
        given: given.to_string(),
        min: MIN_TURN_TTL.as_secs(),
        max: MAX_TURN_TTL.as_secs(),
    };
    let seconds = given.parse::<u64>().map_err(|_| invalid())?;
    if !(MIN_TURN_TTL..=MAX_TURN_TTL).contains(&Duration::from_secs(seconds)) {
        return Err(invalid());
    }
    Ok(seconds)
}

/// Resolves the TURN settings into the one credential form the operator configured.
///
/// `Ok(None)` means no TURN at all (nothing set). A TURN server requires exactly one complete
/// form: the static username/credential pair, or the REST-secret secret/label pair (with the
/// default TTL when `ttl_secs` is unset). A partial form, a mix of both forms, or credentials
/// without a server are hard errors: each would otherwise either send coturn a half credential or
/// silently drop an operator's setting. The config is resolved once, at startup, so the library's
/// per-session credential path never sees a configuration it would have to reject.
fn resolve_turn(
    server: Option<SocketAddr>,
    username: Option<String>,
    credential: Option<String>,
    secret: Option<String>,
    label: Option<String>,
    ttl_secs: Option<u64>,
) -> Result<Option<TurnConfig>, ConfigError> {
    // The TTL is only part of the REST-secret form. Setting it alone is an incomplete REST form,
    // not a silently ignored extra: the operator plainly intended REST credentials.
    let static_any = username.is_some() || credential.is_some();
    let rest_any = secret.is_some() || label.is_some() || ttl_secs.is_some();
    if static_any && rest_any {
        return Err(ConfigError::MixedTurnCredentials);
    }

    let credentials = if static_any {
        let (Some(username), Some(credential)) = (username, credential) else {
            return Err(ConfigError::IncompleteTurnCredentials);
        };
        Some(TurnCredentials::Static {
            username,
            credential,
        })
    } else if rest_any {
        let (Some(secret), Some(label)) = (secret, label) else {
            return Err(ConfigError::IncompleteTurnCredentials);
        };
        Some(TurnCredentials::RestSecret {
            secret,
            label,
            ttl: Duration::from_secs(ttl_secs.unwrap_or(DEFAULT_TURN_TTL_SECS)),
        })
    } else {
        None
    };

    match (server, credentials) {
        (Some(server), Some(credentials)) => Ok(Some(TurnConfig {
            server,
            credentials,
        })),
        (None, None) => Ok(None),
        (None, Some(_)) => Err(ConfigError::TurnCredentialsWithoutServer),
        (Some(_), None) => Err(ConfigError::MissingTurnCredentials),
    }
}

/// Shortest operating-certificate lifetime the knob accepts, in seconds.
///
/// A10.45's renewal point is two-thirds of `exp`, so a 1 s certificate would renew at `ts` and a
/// 2 s one at `ts + 1`, leaving a host either reconnecting continuously or with a one-second
/// window in which a connect slower than that exits the process at expiry. Three seconds puts
/// the renewal point at `ts + 2` and keeps a full second before expiry — small enough to exercise
/// the path live (the live tests use 9 s), large enough not to be self-defeating.
const MIN_OP_CERT_TTL_SECS: u64 = 3;

/// The rejection value for every form [`parse_op_cert_ttl`] refuses.
fn invalid_op_cert_ttl(given: &str) -> ConfigError {
    ConfigError::BadOpCertTtl {
        given: given.to_string(),
        min: MIN_OP_CERT_TTL_SECS,
        max: HOST_OP_CERT_TTL_SECS,
    }
}

/// Parses the operating-certificate lifetime: a whole number of seconds in
/// [`MIN_OP_CERT_TTL_SECS`]`..=`A7b's 90-day bound. Zero (and the one- and two-second lifetimes
/// that make the two-thirds renewal point coincide with, or sit one second before, expiry) is
/// refused, and anything above the design bound is a configuration mistake rather than a longer
/// rotation policy — the knob's documented purpose is shortening every window proportionally.
fn parse_op_cert_ttl(given: &str) -> Result<u64, ConfigError> {
    let seconds = given
        .parse::<u64>()
        .map_err(|_| invalid_op_cert_ttl(given))?;
    if !(MIN_OP_CERT_TTL_SECS..=HOST_OP_CERT_TTL_SECS).contains(&seconds) {
        return Err(invalid_op_cert_ttl(given));
    }
    Ok(seconds)
}

/// Parses the scheduled-sweep interval: a whole number of seconds, at least
/// [`MIN_SWEEP_INTERVAL_SECS`] (the library's floor, used here so the config knob and the
/// scheduler's own clamp cannot drift apart). Zero and non-numeric values are configuration
/// errors rather than "run continuously" or "disabled"; `SPINDLE_HOST_RECONCILE_INTERVAL_SECS`
/// being unset is the one spelling of disabled.
fn parse_reconcile_interval(given: &str) -> Result<u64, ConfigError> {
    let seconds = given
        .parse::<u64>()
        .map_err(|_| ConfigError::BadReconcileInterval {
            given: given.to_string(),
            min: MIN_SWEEP_INTERVAL_SECS,
        })?;
    if seconds < MIN_SWEEP_INTERVAL_SECS {
        return Err(ConfigError::BadReconcileInterval {
            given: given.to_string(),
            min: MIN_SWEEP_INTERVAL_SECS,
        });
    }
    Ok(seconds)
}

/// Parses the `1`/`true`/`0`/`false` forms `SPINDLE_HOST_INIT` accepts. Case-sensitive, matching
/// this workspace's other enum-valued env vars (`ADMISSION_MODE`'s `open|invite|closed`), so a
/// typo is a startup error rather than a silently false flag.
fn parse_bool(given: &str) -> Result<bool, ConfigError> {
    match given {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(ConfigError::BadBoolean {
            given: given.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    /// `from_env_and_args` reads process-global state, so these tests must not run concurrently
    /// and must not inherit whatever the developer's shell exported.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const ENV_NAMES: [&str; 19] = [
        "SPINDLE_NATS_URL",
        "SPINDLE_HOST_SEED_FILE",
        "SPINDLE_HOST_STORE",
        "SPINDLE_HOST_BIND_IP",
        "SPINDLE_ADMISSION_TOKEN_FILE",
        "SPINDLE_HOST_RECOVERY_PHRASE_FILE",
        "SPINDLE_HOST_INIT",
        "SPINDLE_HOST_RESTORE_SEED",
        "SPINDLE_METRICS_ADDR",
        "SPINDLE_HOST_OP_CERT_TTL_SECS",
        "SPINDLE_HOST_RECONCILE_ONCE",
        "SPINDLE_HOST_RECONCILE_INTERVAL_SECS",
        "SPINDLE_STUN_SERVERS",
        "SPINDLE_TURN_SERVER",
        "SPINDLE_TURN_USERNAME",
        "SPINDLE_TURN_CREDENTIAL",
        "SPINDLE_TURN_SECRET",
        "SPINDLE_TURN_LABEL",
        "SPINDLE_TURN_TTL_SECS",
    ];

    /// Clears every variable this module reads, applies `vars`, and restores the previous
    /// process environment on drop (including on a panic).
    struct CleanEnv {
        _lock: MutexGuard<'static, ()>,
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl CleanEnv {
        fn new(vars: &[(&'static str, &str)]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
            let saved = ENV_NAMES
                .iter()
                .map(|name| (*name, env::var_os(name)))
                .collect();
            for name in ENV_NAMES {
                env::remove_var(name);
            }
            for (name, value) in vars {
                env::set_var(name, value);
            }
            CleanEnv { _lock: lock, saved }
        }
    }

    impl Drop for CleanEnv {
        fn drop(&mut self) {
            for (name, value) in self.saved.drain(..) {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }
    }

    fn parse(args: &[&str]) -> Result<Config, ConfigError> {
        Config::from_env_and_args(args.iter().map(|arg| arg.to_string()))
    }

    const REQUIRED_ENV: [(&str, &str); 3] = [
        ("SPINDLE_NATS_URL", "nats://example.test:4222"),
        ("SPINDLE_HOST_SEED_FILE", "/tmp/spindle/host.seed"),
        ("SPINDLE_HOST_STORE", "/tmp/spindle/host.db"),
    ];

    #[test]
    fn optional_settings_take_their_documented_defaults() {
        let _env = CleanEnv::new(&REQUIRED_ENV);
        let config = parse(&[]).expect("required env only is a valid configuration");

        assert_eq!(config.bind_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(config.admission_token_file, None);
        assert_eq!(config.recovery_phrase_file, None);
        assert!(!config.init);
        assert_eq!(config.restore_seed, None);
        assert_eq!(config.restore_seed_file, None);
        assert_eq!(config.metrics_addr, None);
        assert_eq!(
            config.op_cert_ttl_secs, HOST_OP_CERT_TTL_SECS,
            "an unset knob must keep A7b's 90-day lifetime"
        );
        assert!(!config.reconcile_once, "the one-shot repair is opt-in");
        assert_eq!(
            config.reconcile_interval_secs, None,
            "an unset interval must leave startup and serving unchanged"
        );
        assert_eq!(
            config.stun_servers,
            Vec::<SocketAddr>::new(),
            "an unset STUN list must stay empty (host candidates only)"
        );
        assert_eq!(
            config.turn, None,
            "an unset TURN server must keep the host punch-only"
        );
        assert_eq!(
            config.ice_config(),
            IceConfig::default(),
            "empty settings must produce exactly the library's pre-STUN/TURN configuration"
        );
    }

    #[test]
    fn every_field_is_readable_from_the_environment_alone() {
        let mut vars = REQUIRED_ENV.to_vec();
        vars.extend([
            ("SPINDLE_HOST_BIND_IP", "127.0.0.1"),
            ("SPINDLE_ADMISSION_TOKEN_FILE", "/tmp/spindle/admission.bin"),
            (
                "SPINDLE_HOST_RECOVERY_PHRASE_FILE",
                "/tmp/spindle/recovery.txt",
            ),
            ("SPINDLE_HOST_INIT", "true"),
            ("SPINDLE_METRICS_ADDR", "127.0.0.1:9100"),
            ("SPINDLE_HOST_OP_CERT_TTL_SECS", "9"),
            // `SPINDLE_HOST_RECONCILE_ONCE=true` is deliberately not set here: it conflicts with
            // `SPINDLE_HOST_INIT=true` (an enrollment action), and the dedicated reconcile-settings
            // test below covers its environment spelling with no enrollment action present.
            ("SPINDLE_HOST_RECONCILE_INTERVAL_SECS", "120"),
            (
                "SPINDLE_STUN_SERVERS",
                "192.0.2.1:3478, [2001:db8::1]:3478,192.0.2.1:3478",
            ),
            ("SPINDLE_TURN_SERVER", "203.0.113.1:3478"),
            ("SPINDLE_TURN_SECRET", "rest-secret"),
            ("SPINDLE_TURN_LABEL", "host-a"),
            ("SPINDLE_TURN_TTL_SECS", "120"),
        ]);
        let _env = CleanEnv::new(&vars);
        let config = parse(&[]).expect("full env configuration parses");

        assert_eq!(config.nats_url.as_deref(), Some("nats://example.test:4222"));
        assert_eq!(
            config.seed_file,
            Some(PathBuf::from("/tmp/spindle/host.seed"))
        );
        assert_eq!(config.store, PathBuf::from("/tmp/spindle/host.db"));
        assert_eq!(config.bind_ip, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(
            config.admission_token_file,
            Some(PathBuf::from("/tmp/spindle/admission.bin"))
        );
        assert_eq!(
            config.recovery_phrase_file,
            Some(PathBuf::from("/tmp/spindle/recovery.txt"))
        );
        assert!(config.init);
        assert_eq!(config.metrics_addr.as_deref(), Some("127.0.0.1:9100"));
        assert_eq!(config.op_cert_ttl_secs, 9);
        assert!(!config.reconcile_once);
        assert_eq!(config.reconcile_interval_secs, Some(120));
        assert_eq!(
            config.stun_servers,
            vec![
                "192.0.2.1:3478".parse().expect("v4 STUN"),
                "[2001:db8::1]:3478".parse().expect("v6 STUN"),
            ],
            "the environment list is trimmed and its duplicate collapsed"
        );
        assert_eq!(
            config.turn,
            Some(TurnConfig {
                server: "203.0.113.1:3478".parse().expect("TURN server"),
                credentials: TurnCredentials::RestSecret {
                    secret: "rest-secret".to_string(),
                    label: "host-a".to_string(),
                    ttl: Duration::from_secs(120),
                },
            }),
            "the environment spelling selects the REST-secret form"
        );
    }

    #[test]
    fn flags_override_the_environment() {
        let _env = CleanEnv::new(&REQUIRED_ENV);
        let config = parse(&[
            "--nats-url",
            "nats://flag.test:4222",
            "--seed-file",
            "/tmp/flag/host.seed",
            "--store",
            "/tmp/flag/host.db",
            "--bind-ip",
            "192.0.2.7",
            "--admission-token-file",
            "/tmp/flag/admission.bin",
            "--init",
            "--recovery-phrase-file",
            "/tmp/flag/recovery.txt",
            "--metrics-addr",
            "127.0.0.1:9200",
            "--op-cert-ttl-secs",
            "30",
            "--stun-servers",
            "192.0.2.9:3478,192.0.2.9:3478",
            "--turn-server",
            "203.0.113.9:3478",
            "--turn-username",
            "static-user",
            "--turn-credential",
            "static-credential",
        ])
        .expect("flags parse");

        assert_eq!(config.nats_url.as_deref(), Some("nats://flag.test:4222"));
        assert_eq!(config.seed_file, Some(PathBuf::from("/tmp/flag/host.seed")));
        assert_eq!(config.store, PathBuf::from("/tmp/flag/host.db"));
        assert_eq!(config.bind_ip, IpAddr::from([192, 0, 2, 7]));
        assert_eq!(
            config.admission_token_file,
            Some(PathBuf::from("/tmp/flag/admission.bin"))
        );
        assert_eq!(
            config.recovery_phrase_file,
            Some(PathBuf::from("/tmp/flag/recovery.txt"))
        );
        assert!(config.init);
        assert_eq!(config.metrics_addr.as_deref(), Some("127.0.0.1:9200"));
        assert_eq!(config.op_cert_ttl_secs, 30);
        assert!(!config.reconcile_once);
        assert_eq!(config.reconcile_interval_secs, None);
        assert_eq!(
            config.stun_servers,
            vec!["192.0.2.9:3478".parse().expect("STUN server")],
            "flag list is deduplicated"
        );
        assert_eq!(
            config.turn,
            Some(TurnConfig {
                server: "203.0.113.9:3478".parse().expect("TURN server"),
                credentials: TurnCredentials::Static {
                    username: "static-user".to_string(),
                    credential: "static-credential".to_string(),
                },
            }),
            "the static pair selects the Static form"
        );
    }

    /// TURN settings follow the same precedence as every other setting: the environment alone
    /// selects the REST-secret form, and a flag overrides only the value it names (here the STUN
    /// list, the server, and the TTL), leaving the environment's secret/label in place.
    #[test]
    fn turn_settings_come_from_the_environment_and_flags_override_it() {
        let mut vars = REQUIRED_ENV.to_vec();
        vars.extend([
            ("SPINDLE_STUN_SERVERS", "192.0.2.1:3478"),
            ("SPINDLE_TURN_SERVER", "203.0.113.1:3478"),
            ("SPINDLE_TURN_SECRET", "env-secret"),
            ("SPINDLE_TURN_LABEL", "env-label"),
            ("SPINDLE_TURN_TTL_SECS", "120"),
        ]);
        let _env = CleanEnv::new(&vars);
        let config = parse(&[
            "--stun-servers",
            "198.51.100.2:3478,198.51.100.3:3478",
            "--turn-server",
            "203.0.113.2:3478",
            "--turn-ttl-secs",
            "300",
        ])
        .expect("flags override their environment spellings");

        assert_eq!(
            config.stun_servers,
            vec![
                "198.51.100.2:3478".parse().expect("STUN server"),
                "198.51.100.3:3478".parse().expect("STUN server"),
            ],
            "the flag replaces the whole STUN list"
        );
        assert_eq!(
            config.turn,
            Some(TurnConfig {
                server: "203.0.113.2:3478".parse().expect("TURN server"),
                credentials: TurnCredentials::RestSecret {
                    secret: "env-secret".to_string(),
                    label: "env-label".to_string(),
                    ttl: Duration::from_secs(300),
                },
            }),
            "the flag TTL overrides the environment TTL; the env secret/label are unchanged"
        );
    }

    /// The STUN list and the TURN relay are independent: either may be set alone, both together,
    /// or neither (which is exactly the historical host-candidate-only configuration).
    #[test]
    fn stun_and_turn_may_be_configured_together_either_alone_or_neither() {
        let _env = CleanEnv::new(&REQUIRED_ENV);

        let neither = parse(&[]).expect("neither is valid");
        assert!(neither.stun_servers.is_empty());
        assert_eq!(neither.turn, None);

        let stun_only = parse(&["--stun-servers", "192.0.2.1:3478"]).expect("STUN alone is valid");
        assert_eq!(
            stun_only.stun_servers,
            vec!["192.0.2.1:3478".parse().expect("STUN server")]
        );
        assert_eq!(stun_only.turn, None);

        let turn_only = parse(&[
            "--turn-server",
            "203.0.113.1:3478",
            "--turn-username",
            "user",
            "--turn-credential",
            "credential",
        ])
        .expect("TURN alone is valid");
        assert!(turn_only.stun_servers.is_empty());
        assert!(turn_only.turn.is_some());

        let both = parse(&[
            "--stun-servers",
            "192.0.2.1:3478",
            "--turn-server",
            "203.0.113.1:3478",
            "--turn-username",
            "user",
            "--turn-credential",
            "credential",
        ])
        .expect("STUN and TURN together are valid");
        assert_eq!(both.stun_servers.len(), 1);
        assert!(both.turn.is_some());
    }

    /// A TURN server needs exactly one credential form. Partial forms, both forms at once, and
    /// credentials without a server are all refused rather than sent to coturn half-configured or
    /// silently dropped.
    #[test]
    fn partial_mixed_and_serverless_turn_credentials_are_rejected() {
        {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            let cases: [(&[&str], &str); 8] = [
                (&["--turn-server", "203.0.113.1:3478"], "missing"),
                (
                    &["--turn-server", "203.0.113.1:3478", "--turn-username", "u"],
                    "incomplete",
                ),
                (
                    &[
                        "--turn-server",
                        "203.0.113.1:3478",
                        "--turn-credential",
                        "c",
                    ],
                    "incomplete",
                ),
                (
                    &["--turn-server", "203.0.113.1:3478", "--turn-secret", "s"],
                    "incomplete",
                ),
                (
                    &["--turn-server", "203.0.113.1:3478", "--turn-label", "l"],
                    "incomplete",
                ),
                (
                    &["--turn-server", "203.0.113.1:3478", "--turn-ttl-secs", "60"],
                    "incomplete",
                ),
                (
                    &[
                        "--turn-server",
                        "203.0.113.1:3478",
                        "--turn-username",
                        "u",
                        "--turn-credential",
                        "c",
                        "--turn-secret",
                        "s",
                        "--turn-label",
                        "l",
                    ],
                    "mixed",
                ),
                (
                    &["--turn-username", "u", "--turn-credential", "c"],
                    "serverless",
                ),
            ];

            for (args, expected) in cases {
                let error = parse(args).expect_err("invalid TURN configuration");
                let actual = match &error {
                    ConfigError::MissingTurnCredentials => "missing",
                    ConfigError::IncompleteTurnCredentials => "incomplete",
                    ConfigError::MixedTurnCredentials => "mixed",
                    ConfigError::TurnCredentialsWithoutServer => "serverless",
                    other => panic!("unexpected error for {args:?}: {other:?}"),
                };
                assert_eq!(actual, expected, "wrong error for {args:?}");
                let message = error.to_string();
                assert!(
                    message.contains("SPINDLE_TURN_") || message.contains("--turn-"),
                    "the error must name the setting spellings: {message}"
                );
            }
        }

        // The same rule applies to the environment spelling: a complete pair with no server is
        // serverless credentials, not a partial form.
        let mut vars = REQUIRED_ENV.to_vec();
        vars.extend([("SPINDLE_TURN_SECRET", "s"), ("SPINDLE_TURN_LABEL", "l")]);
        let _env = CleanEnv::new(&vars);
        assert!(matches!(
            parse(&[]).expect_err("credentials without a server are invalid"),
            ConfigError::TurnCredentialsWithoutServer
        ));
    }

    /// A malformed STUN or TURN address is a startup error from either source; the error names the
    /// setting, not a silently skipped server.
    #[test]
    fn bad_stun_and_turn_socket_addresses_are_rejected_from_either_source() {
        {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            match parse(&["--stun-servers", "not-an-address"]) {
                Err(ConfigError::BadStunServers { given }) => assert_eq!(given, "not-an-address"),
                other => panic!("expected BadStunServers, got {other:?}"),
            }
            match parse(&["--turn-server", "not-an-address"]) {
                Err(ConfigError::BadTurnServer { given }) => assert_eq!(given, "not-an-address"),
                other => panic!("expected BadTurnServer, got {other:?}"),
            }
        }

        let mut vars = REQUIRED_ENV.to_vec();
        vars.extend([
            ("SPINDLE_STUN_SERVERS", "192.0.2.1"),
            ("SPINDLE_TURN_SERVER", "203.0.113.1"),
        ]);
        let _env = CleanEnv::new(&vars);
        match parse(&[]) {
            Err(ConfigError::BadStunServers { given }) => assert_eq!(given, "192.0.2.1"),
            other => panic!("expected BadStunServers, got {other:?}"),
        }
        match parse(&["--stun-servers", "192.0.2.1:3478"]) {
            Err(ConfigError::BadTurnServer { given }) => assert_eq!(given, "203.0.113.1"),
            other => panic!("expected BadTurnServer, got {other:?}"),
        }
    }

    /// `SPINDLE_STUN_SERVERS` entries are trimmed and deduplicated; an empty entry (a trailing or
    /// doubled comma, or an exported empty string) is a typo and is refused rather than skipped.
    #[test]
    fn stun_lists_are_trimmed_deduplicated_and_reject_empty_entries() {
        {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            let config = parse(&[
                "--stun-servers",
                " 192.0.2.1:3478 , 192.0.2.2:3478 , 192.0.2.1:3478 ",
            ])
            .expect("whitespace is trimmed and the duplicate collapsed");
            assert_eq!(
                config.stun_servers,
                vec![
                    "192.0.2.1:3478".parse().expect("first"),
                    "192.0.2.2:3478".parse().expect("second"),
                ],
                "the operator's order is kept"
            );

            for invalid in [
                "192.0.2.1:3478,",
                "192.0.2.1:3478,,192.0.2.2:3478",
                "192.0.2.1:3478, not-an-address",
                "",
            ] {
                match parse(&["--stun-servers", invalid]) {
                    Err(ConfigError::BadStunServers { given }) => assert_eq!(given, invalid),
                    other => panic!("expected BadStunServers for {invalid:?}, got {other:?}"),
                }
            }
        }

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("SPINDLE_STUN_SERVERS", ""));
        let _env = CleanEnv::new(&vars);
        assert!(matches!(
            parse(&[]).expect_err("an empty exported list is not 'no servers'"),
            ConfigError::BadStunServers { .. }
        ));
    }

    /// The REST-secret TTL accepts the same range the library's credential minting enforces:
    /// 1 second through 24 hours, with 1 hour as the default when the knob is unset.
    #[test]
    fn rest_secret_turn_ttls_accept_one_second_through_twenty_four_hours() {
        // The bounds are the library's, not a copy: these assert the invariants hostd relies on
        // rather than restating a second set of numbers that could drift.
        assert!(MIN_TURN_TTL < MAX_TURN_TTL);
        assert!(
            (MIN_TURN_TTL..=MAX_TURN_TTL).contains(&Duration::from_secs(DEFAULT_TURN_TTL_SECS)),
            "the default TTL must be inside the library's accepted range"
        );

        {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            let ttl_of = |config: Config| match config.turn {
                Some(TurnConfig {
                    credentials: TurnCredentials::RestSecret { ttl, .. },
                    ..
                }) => ttl,
                other => panic!("expected REST-secret TURN credentials, got {other:?}"),
            };

            let defaulted = parse(&[
                "--turn-server",
                "203.0.113.1:3478",
                "--turn-secret",
                "s",
                "--turn-label",
                "l",
            ])
            .expect("REST credentials without a TTL use the default");
            assert_eq!(
                ttl_of(defaulted),
                Duration::from_secs(DEFAULT_TURN_TTL_SECS)
            );

            for valid in [MIN_TURN_TTL.as_secs(), 3_600, MAX_TURN_TTL.as_secs()] {
                let value = valid.to_string();
                let config = parse(&[
                    "--turn-server",
                    "203.0.113.1:3478",
                    "--turn-secret",
                    "s",
                    "--turn-label",
                    "l",
                    "--turn-ttl-secs",
                    value.as_str(),
                ])
                .expect("in-range TTL");
                assert_eq!(ttl_of(config), Duration::from_secs(valid), "value {valid}");
            }

            let invalid_ttls = [
                "0".to_string(),
                (MAX_TURN_TTL + Duration::from_secs(1))
                    .as_secs()
                    .to_string(),
                "-1".to_string(),
                "not-a-number".to_string(),
            ];
            for invalid in &invalid_ttls {
                match parse(&[
                    "--turn-server",
                    "203.0.113.1:3478",
                    "--turn-secret",
                    "s",
                    "--turn-label",
                    "l",
                    "--turn-ttl-secs",
                    invalid.as_str(),
                ]) {
                    Err(ConfigError::BadTurnTtl { given, min, max }) => {
                        assert_eq!(given, *invalid);
                        assert_eq!((min, max), (MIN_TURN_TTL.as_secs(), MAX_TURN_TTL.as_secs()));
                    }
                    other => panic!("expected BadTurnTtl for {invalid:?}, got {other:?}"),
                }
            }
        }

        let mut vars = REQUIRED_ENV.to_vec();
        vars.extend([
            ("SPINDLE_TURN_SERVER", "203.0.113.1:3478"),
            ("SPINDLE_TURN_SECRET", "s"),
            ("SPINDLE_TURN_LABEL", "l"),
            ("SPINDLE_TURN_TTL_SECS", "0"),
        ]);
        let _env = CleanEnv::new(&vars);
        match parse(&[]) {
            Err(ConfigError::BadTurnTtl { given, .. }) => assert_eq!(given, "0"),
            other => panic!("expected BadTurnTtl, got {other:?}"),
        }
    }

    /// Both reconcile knobs are readable from the environment alone, and a flag overrides the
    /// environment when both are present (the same rule every other setting follows).
    #[test]
    fn reconcile_settings_come_from_the_environment_and_flags_override_it() {
        {
            let mut vars = REQUIRED_ENV.to_vec();
            vars.extend([
                ("SPINDLE_HOST_RECONCILE_ONCE", "true"),
                ("SPINDLE_HOST_RECONCILE_INTERVAL_SECS", "120"),
            ]);
            let _env = CleanEnv::new(&vars);
            let config = parse(&[]).expect("env-only reconcile settings parse");
            assert!(config.reconcile_once);
            assert_eq!(config.reconcile_interval_secs, Some(120));
        }

        {
            let mut vars = REQUIRED_ENV.to_vec();
            vars.extend([
                ("SPINDLE_HOST_RECONCILE_ONCE", "false"),
                ("SPINDLE_HOST_RECONCILE_INTERVAL_SECS", "120"),
            ]);
            let _env = CleanEnv::new(&vars);
            let config = parse(&["--reconcile-once", "--reconcile-interval-secs", "300"])
                .expect("flags override the environment");
            assert!(
                config.reconcile_once,
                "the bare flag must override an env value of false"
            );
            assert_eq!(
                config.reconcile_interval_secs,
                Some(300),
                "the flag value must override the environment value"
            );
        }
    }

    /// Zero is not a spelling of "disabled" (unset is), and neither is a sub-minute cadence or a
    /// non-numeric value. Both sources go through the same parser.
    #[test]
    fn invalid_reconcile_intervals_are_rejected() {
        for invalid in ["0", "59", "not-a-number", "-1"] {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            match parse(&["--reconcile-interval-secs", invalid]) {
                Err(ConfigError::BadReconcileInterval { given, min }) => {
                    assert_eq!(given, invalid);
                    assert_eq!(min, MIN_SWEEP_INTERVAL_SECS);
                }
                other => panic!("expected BadReconcileInterval for {invalid:?}, got {other:?}"),
            }
        }

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("SPINDLE_HOST_RECONCILE_INTERVAL_SECS", "0"));
        let _env = CleanEnv::new(&vars);
        match parse(&[]) {
            Err(ConfigError::BadReconcileInterval { given, .. }) => assert_eq!(given, "0"),
            other => panic!("expected BadReconcileInterval, got {other:?}"),
        }
    }

    /// The one-shot repair is an operator tool, not a serving mode: it never connects to NATS and
    /// never touches identity custody, so only the store it repairs is required.
    #[test]
    fn the_one_shot_reconcile_needs_only_the_store() {
        let _env = CleanEnv::new(&[]);
        let config = parse(&["--reconcile-once", "--store", "/tmp/spindle/host.db"])
            .expect("the one-shot repair must not require a NATS URL or a seed file");
        assert!(config.reconcile_once);
        assert_eq!(config.nats_url, None);
        assert_eq!(config.seed_file, None);
        assert_eq!(config.store, PathBuf::from("/tmp/spindle/host.db"));
    }

    /// A one-shot repair exits before identity custody runs, so an enrollment action alongside it
    /// would be silently dropped. Refuse the combination rather than let the operator believe they
    /// enrolled (or restored) an identity.
    #[test]
    fn reconcile_once_cannot_be_combined_with_an_enrollment_action() {
        {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            for args in [
                vec!["--reconcile-once", "--init"],
                vec!["--reconcile-once", "--restore-seed-file", "/tmp/phrase.txt"],
            ] {
                match parse(&args) {
                    Err(ConfigError::ConflictingEnrollment) => {}
                    other => panic!("expected ConflictingEnrollment for {args:?}, got {other:?}"),
                }
            }
        }

        let mut vars = REQUIRED_ENV.to_vec();
        vars.push(("SPINDLE_HOST_RESTORE_SEED", "words in a phrase"));
        let _env = CleanEnv::new(&vars);
        match parse(&["--reconcile-once"]) {
            Err(ConfigError::ConflictingEnrollment) => {}
            other => panic!("expected ConflictingEnrollment, got {other:?}"),
        }
    }

    /// The knob exists to exercise renewal live and to let an operator tighten rotation, so its
    /// valid range is three seconds (the smallest lifetime whose two-thirds renewal point still
    /// leaves a second before expiry) through A7b's 90-day bound.
    #[test]
    fn the_operating_certificate_lifetime_accepts_three_seconds_through_ninety_days() {
        {
            let mut env = REQUIRED_ENV.to_vec();
            env.push(("SPINDLE_HOST_OP_CERT_TTL_SECS", "9"));
            let _env = CleanEnv::new(&env);
            assert_eq!(
                parse(&[]).expect("env lifetime").op_cert_ttl_secs,
                9,
                "the environment spelling must be parsed"
            );
        }

        let _env = CleanEnv::new(&REQUIRED_ENV);
        for valid in [
            MIN_OP_CERT_TTL_SECS,
            9,
            HOST_OP_CERT_TTL_SECS / 2,
            HOST_OP_CERT_TTL_SECS,
        ] {
            let value = valid.to_string();
            let config = parse(&["--op-cert-ttl-secs", value.as_str()]).expect("valid lifetime");
            assert_eq!(config.op_cert_ttl_secs, valid, "value {valid}");
        }
    }

    #[test]
    fn zero_sub_three_and_absurd_operating_certificate_lifetimes_are_rejected() {
        for invalid in [
            "0".to_string(),
            (MIN_OP_CERT_TTL_SECS - 1).to_string(),
            (MIN_OP_CERT_TTL_SECS - 2).to_string(),
            (HOST_OP_CERT_TTL_SECS + 1).to_string(),
            u64::MAX.to_string(),
            "not-a-number".to_string(),
        ] {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            match parse(&["--op-cert-ttl-secs", invalid.as_str()]) {
                Err(ConfigError::BadOpCertTtl { given, min, max }) => {
                    assert_eq!(given, invalid);
                    assert_eq!(min, MIN_OP_CERT_TTL_SECS);
                    assert_eq!(max, HOST_OP_CERT_TTL_SECS);
                }
                other => panic!("expected BadOpCertTtl for {invalid:?}, got {other:?}"),
            }
        }

        // The environment spelling is validated by the same parser.
        let mut env = REQUIRED_ENV.to_vec();
        env.push(("SPINDLE_HOST_OP_CERT_TTL_SECS", "0"));
        let _env = CleanEnv::new(&env);
        match parse(&[]) {
            Err(ConfigError::BadOpCertTtl { given, .. }) => assert_eq!(given, "0"),
            other => panic!("expected BadOpCertTtl, got {other:?}"),
        }
    }

    #[test]
    fn the_restore_phrase_comes_from_a_file_or_the_environment_but_never_argv_inline() {
        {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            let config = parse(&["--restore-seed-file", "/tmp/flag/recovery.txt"])
                .expect("--restore-seed-file parses");
            assert_eq!(config.restore_seed, None);
            assert_eq!(
                config.restore_seed_file,
                Some(PathBuf::from("/tmp/flag/recovery.txt"))
            );
        }

        {
            let mut vars = REQUIRED_ENV.to_vec();
            vars.push(("SPINDLE_HOST_RESTORE_SEED", "words in a phrase"));
            let _env = CleanEnv::new(&vars);
            let config = parse(&[]).expect("the environment phrase parses");
            assert_eq!(config.restore_seed.as_deref(), Some("words in a phrase"));
            assert_eq!(config.restore_seed_file, None);
        }

        {
            // The inline flag is gone on purpose: argv is visible to process listings and lands
            // in shell history. It must be rejected as an unknown argument, and its value must
            // not be echoed back.
            let _env = CleanEnv::new(&REQUIRED_ENV);
            match parse(&["--restore-seed", "words in a phrase"]) {
                Err(ConfigError::UnknownArg(arg)) => assert_eq!(arg, "--restore-seed"),
                other => panic!("expected UnknownArg, got {other:?}"),
            }
        }
    }

    #[test]
    fn missing_required_settings_name_both_the_env_var_and_the_flag() {
        {
            let _env = CleanEnv::new(&[]);
            let error = parse(&[]).expect_err("no required setting is present");
            let message = error.to_string();
            assert!(message.contains("SPINDLE_NATS_URL"), "{message}");
            assert!(message.contains("--nats-url"), "{message}");
        }

        {
            let _env = CleanEnv::new(&REQUIRED_ENV[..1]);
            let error = parse(&[]).expect_err("seed file setting is absent");
            let message = error.to_string();
            assert!(message.contains("SPINDLE_HOST_SEED_FILE"), "{message}");
            assert!(message.contains("--seed-file"), "{message}");
        }

        {
            let _env = CleanEnv::new(&REQUIRED_ENV[..2]);
            let error = parse(&[]).expect_err("store setting is absent");
            let message = error.to_string();
            assert!(message.contains("SPINDLE_HOST_STORE"), "{message}");
            assert!(message.contains("--store"), "{message}");
        }
    }

    #[test]
    fn an_unparseable_bind_address_is_rejected_from_either_source() {
        let mut env = REQUIRED_ENV.to_vec();
        env.push(("SPINDLE_HOST_BIND_IP", "not-an-ip"));
        {
            let _env = CleanEnv::new(&env);
            match parse(&[]) {
                Err(ConfigError::BadBindIp { given }) => assert_eq!(given, "not-an-ip"),
                other => panic!("expected BadBindIp, got {other:?}"),
            }
        }

        let _env = CleanEnv::new(&REQUIRED_ENV);
        match parse(&["--bind-ip", "999.1.1.1"]) {
            Err(ConfigError::BadBindIp { given }) => assert_eq!(given, "999.1.1.1"),
            other => panic!("expected BadBindIp, got {other:?}"),
        }
    }

    #[test]
    fn the_init_boolean_accepts_only_the_documented_spellings() {
        for (given, expected) in [("1", true), ("true", true), ("0", false), ("false", false)] {
            let mut env = REQUIRED_ENV.to_vec();
            env.push(("SPINDLE_HOST_INIT", given));
            {
                let _env = CleanEnv::new(&env);
                assert_eq!(parse(&[]).expect(given).init, expected, "value {given}");
            }
        }

        let mut env = REQUIRED_ENV.to_vec();
        env.push(("SPINDLE_HOST_INIT", "yes"));
        {
            let _env = CleanEnv::new(&env);
            match parse(&[]) {
                Err(ConfigError::BadBoolean { given }) => assert_eq!(given, "yes"),
                other => panic!("expected BadBoolean, got {other:?}"),
            }
        }

        let _env = CleanEnv::new(&REQUIRED_ENV);
        assert!(parse(&["--init"]).expect("--init is a bare flag").init);
    }

    #[test]
    fn enrollment_sources_are_rejected_together() {
        {
            let _env = CleanEnv::new(&REQUIRED_ENV);
            match parse(&["--init", "--restore-seed-file", "/tmp/phrase.txt"]) {
                Err(ConfigError::ConflictingEnrollment) => {}
                other => panic!("expected ConflictingEnrollment, got {other:?}"),
            }
        }

        let mut env = REQUIRED_ENV.to_vec();
        env.push(("SPINDLE_HOST_RESTORE_SEED", "words in a phrase"));
        {
            let _env = CleanEnv::new(&env);
            match parse(&["--init"]) {
                Err(ConfigError::ConflictingEnrollment) => {}
                other => panic!("expected ConflictingEnrollment, got {other:?}"),
            }
            match parse(&["--restore-seed-file", "/tmp/phrase.txt"]) {
                Err(ConfigError::ConflictingEnrollment) => {}
                other => panic!("expected ConflictingEnrollment, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_unknown_flag_does_not_echo_a_value_after_an_equals_sign() {
        let _env = CleanEnv::new(&REQUIRED_ENV);
        match parse(&["--restore-seed=this-is-a-secret-phrase"]) {
            Err(ConfigError::UnknownArg(arg)) => {
                assert_eq!(arg, "--restore-seed");
                assert!(!arg.contains("secret"));
            }
            other => panic!("expected UnknownArg, got {other:?}"),
        }
    }
}
