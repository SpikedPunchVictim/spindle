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
//! `--init` and `--restore-seed <phrase>` are both enrollment actions, and DESIGN.md A10.41(b)
//! forbids either from being an implicit fallback on an absent seed. They are mutually exclusive
//! (`ConfigError::ConflictingEnrollment`) and, in `main`, refused outright when a seed file
//! already exists rather than silently overwriting the identity every member of this host is
//! bound to.

use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

/// Runtime configuration for one host process.
#[derive(Debug)]
pub(crate) struct Config {
    /// `SPINDLE_NATS_URL` / `--nats-url`. Required.
    pub(crate) nats_url: String,
    /// `SPINDLE_HOST_SEED_FILE` / `--seed-file`. Required; `SeedFileStore` enforces the `0600`
    /// file / `0700` directory rule of DESIGN.md A10.41.
    pub(crate) seed_file: PathBuf,
    /// `SPINDLE_HOST_STORE` / `--store`. Required; the SQLite database `HostDaemon::run` opens.
    pub(crate) store: PathBuf,
    /// `SPINDLE_HOST_BIND_IP` / `--bind-ip`. Defaults to `0.0.0.0`, matching `HostOptions::default`.
    pub(crate) bind_ip: IpAddr,
    /// `SPINDLE_ADMISSION_TOKEN_FILE` / `--admission-token-file`. `None` means this connect
    /// presents no admission token at all (`auth_token`'s host arm omits the key), which is the
    /// normal shape for an already-admitted host (DESIGN.md §A3b).
    pub(crate) admission_token_file: Option<PathBuf>,
    /// `SPINDLE_HOST_INIT` (`1`/`true`) / `--init`. Generate a root seed on first run, printing
    /// the recovery phrase once.
    pub(crate) init: bool,
    /// `SPINDLE_HOST_RESTORE_SEED` / `--restore-seed <phrase>`. Restore an existing identity from
    /// its recovery phrase on first run.
    pub(crate) restore_seed: Option<String>,
    /// `SPINDLE_METRICS_ADDR` / `--metrics-addr`. `Some` installs the Prometheus exporter in
    /// `main`; `None` leaves every metrics macro a no-op.
    pub(crate) metrics_addr: Option<String>,
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
    #[error("--init and --restore-seed cannot be combined; choose one enrollment path")]
    ConflictingEnrollment,
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
    /// flag falls through to the unknown-argument arm with the value still attached. One of this
    /// binary's flags takes a recovery phrase (`--restore-seed`), and echoing that into a log is
    /// the same credential leak `helper.rs`'s identically named helper exists to prevent.
    /// Truncating at the `=` keeps the diagnosis without the secret.
    fn unknown_arg(arg: &str) -> ConfigError {
        ConfigError::UnknownArg(arg.split('=').next().unwrap_or("").to_string())
    }
}

const HELP: &str = r#"spindle-hostd — the headless Spindle host daemon

USAGE:
    spindle-hostd [FLAGS]

Every flag has an env-var equivalent (flags override the env var if both are set):
    --nats-url <url>            SPINDLE_NATS_URL             (required)
    --seed-file <path>          SPINDLE_HOST_SEED_FILE       (required; file mode 0600, parent 0700)
    --store <path>              SPINDLE_HOST_STORE           (required; SQLite database path)
    --bind-ip <ip>              SPINDLE_HOST_BIND_IP         (default: 0.0.0.0)
    --admission-token-file <p>  SPINDLE_ADMISSION_TOKEN_FILE (optional; unset sends no token)
    --init                      SPINDLE_HOST_INIT            (1|true|0|false; generate a seed on
                                                             first run)
    --restore-seed <phrase>     SPINDLE_HOST_RESTORE_SEED    (restore an existing identity once)
    --metrics-addr <addr>       SPINDLE_METRICS_ADDR         (optional; Prometheus scrape listener,
                                                             e.g. 127.0.0.1:9100. Unset → no
                                                             recorder is installed)
    -h, --help                  show this message

A first run (no seed file) requires exactly one of --init or --restore-seed <phrase>.
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
        let mut init = env::var("SPINDLE_HOST_INIT").ok();
        let mut restore_seed = env::var("SPINDLE_HOST_RESTORE_SEED").ok();
        let mut metrics_addr = env::var("SPINDLE_METRICS_ADDR").ok();

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
                "--restore-seed" => {
                    restore_seed =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("restore-seed".to_string())
                        })?)
                }
                "--metrics-addr" => {
                    metrics_addr =
                        Some(args.next().ok_or_else(|| {
                            ConfigError::FlagMissingValue("metrics-addr".to_string())
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
        if init && restore_seed.is_some() {
            return Err(ConfigError::ConflictingEnrollment);
        }

        Ok(Config {
            nats_url: nats_url.ok_or(ConfigError::Missing("SPINDLE_NATS_URL", "nats-url"))?,
            seed_file: PathBuf::from(
                seed_file.ok_or(ConfigError::Missing("SPINDLE_HOST_SEED_FILE", "seed-file"))?,
            ),
            store: PathBuf::from(store.ok_or(ConfigError::Missing("SPINDLE_HOST_STORE", "store"))?),
            bind_ip,
            admission_token_file: admission_token_file.map(PathBuf::from),
            init,
            restore_seed,
            metrics_addr,
        })
    }
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

    const ENV_NAMES: [&str; 8] = [
        "SPINDLE_NATS_URL",
        "SPINDLE_HOST_SEED_FILE",
        "SPINDLE_HOST_STORE",
        "SPINDLE_HOST_BIND_IP",
        "SPINDLE_ADMISSION_TOKEN_FILE",
        "SPINDLE_HOST_INIT",
        "SPINDLE_HOST_RESTORE_SEED",
        "SPINDLE_METRICS_ADDR",
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
        assert!(!config.init);
        assert_eq!(config.restore_seed, None);
        assert_eq!(config.metrics_addr, None);
    }

    #[test]
    fn every_field_is_readable_from_the_environment_alone() {
        let mut vars = REQUIRED_ENV.to_vec();
        vars.extend([
            ("SPINDLE_HOST_BIND_IP", "127.0.0.1"),
            ("SPINDLE_ADMISSION_TOKEN_FILE", "/tmp/spindle/admission.bin"),
            ("SPINDLE_HOST_INIT", "true"),
            ("SPINDLE_METRICS_ADDR", "127.0.0.1:9100"),
        ]);
        let _env = CleanEnv::new(&vars);
        let config = parse(&[]).expect("full env configuration parses");

        assert_eq!(config.nats_url, "nats://example.test:4222");
        assert_eq!(config.seed_file, PathBuf::from("/tmp/spindle/host.seed"));
        assert_eq!(config.store, PathBuf::from("/tmp/spindle/host.db"));
        assert_eq!(config.bind_ip, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(
            config.admission_token_file,
            Some(PathBuf::from("/tmp/spindle/admission.bin"))
        );
        assert!(config.init);
        assert_eq!(config.metrics_addr.as_deref(), Some("127.0.0.1:9100"));
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
            "--metrics-addr",
            "127.0.0.1:9200",
        ])
        .expect("flags parse");

        assert_eq!(config.nats_url, "nats://flag.test:4222");
        assert_eq!(config.seed_file, PathBuf::from("/tmp/flag/host.seed"));
        assert_eq!(config.store, PathBuf::from("/tmp/flag/host.db"));
        assert_eq!(config.bind_ip, IpAddr::from([192, 0, 2, 7]));
        assert_eq!(
            config.admission_token_file,
            Some(PathBuf::from("/tmp/flag/admission.bin"))
        );
        assert!(config.init);
        assert_eq!(config.metrics_addr.as_deref(), Some("127.0.0.1:9200"));
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
    fn init_and_restore_seed_are_rejected_together() {
        let _env = CleanEnv::new(&REQUIRED_ENV);
        match parse(&["--init", "--restore-seed", "aaaa"]) {
            Err(ConfigError::ConflictingEnrollment) => {}
            other => panic!("expected ConflictingEnrollment, got {other:?}"),
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
