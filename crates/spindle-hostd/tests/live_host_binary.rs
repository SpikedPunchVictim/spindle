#![cfg(unix)]
//! Live smoke test for the `spindle-hostd` binary itself (td-539ffa slice 3): first-run
//! enrollment, graceful SIGINT shutdown, and identity survival across a restart.
//!
//! # What this proves that `tests/live_hostd.rs` does not
//!
//! `live_hostd.rs` drives the library's [`spindle_hostd::HostDaemon`] directly with a
//! callout-authenticated client the test built itself. This file instead executes the shipped
//! binary: it proves the binary's own startup path — `SPINDLE_HOST_INIT` enrollment, the
//! seed-file mode, the recovery phrase on stdout, the real NATS connect through
//! `spindle_hostd::connect::connect_host`, the `HostDaemon` assembly, and `Ctrl-C` handling — and
//! that the one persisted artifact (the root seed) makes `host_fp` survive a second start.
//!
//! # Gating
//!
//! This test is `#[ignore]`d, so `cargo test --workspace` reports it as `ignored` rather than
//! running it. It is **not** the "silently no-op when an env var is unset" shape: when run, an
//! unreachable stack is a hard failure whose message includes the captured stderr, never a skip.
//! A test that passes without running is the exact false-green this repo has already been bitten
//! by (see `live_hostd.rs`'s own module doc comment).
//!
//! Run with:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml up -d
//! cargo test -p spindle-hostd --test live_host_binary -- --ignored --nocapture
//! ```
//!
//! `NATS_URL` overrides the stack's TCP listener (default `nats://127.0.0.1:4222`); the binary
//! itself is given that URL through `SPINDLE_NATS_URL`, its own prefixed variable.
//!
//! # Rebuild the helper image after any A7b wire-schema change
//!
//! Exactly as in `live_hostd.rs`: the helper runs as a prebuilt container image, so any change to
//! an A7b artifact's wire schema or to `spindle-helper` requires
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml build helper
//! docker compose -f deploy/docker-compose.yml up -d --no-deps helper
//! ```
//!
//! or this test fails at CONNECT with an `authorization violation` that looks unrelated to the
//! change that caused it.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Cargo sets this for every integration test in a package that has a `[[bin]]` target.
const BINARY: &str = env!("CARGO_BIN_EXE_spindle-hostd");
const STARTUP_MARKER: &str = "host daemon starting";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// A temp directory with the `0700` parent mode DESIGN.md A10.41 requires, so the binary's own
/// `SeedFileStore` checks can succeed.
fn private_tempdir() -> TempDir {
    let dir = TempDir::new().expect("create temp dir for the host's seed and store");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    dir
}

/// Lines read from the child's stderr as they arrive, plus the full transcript for failure
/// messages.
struct StderrCapture {
    lines: Receiver<String>,
    transcript: Arc<Mutex<String>>,
}

impl StderrCapture {
    fn start(child: &mut Child) -> Self {
        let stderr = child
            .stderr
            .take()
            .expect("child stderr is piped by spawn_host");
        let (sender, lines) = mpsc::channel();
        let transcript = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&transcript);
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if let Ok(mut transcript) = sink.lock() {
                    transcript.push_str(&line);
                    transcript.push('\n');
                }
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        StderrCapture { lines, transcript }
    }

    fn transcript(&self) -> String {
        self.transcript
            .lock()
            .map(|transcript| transcript.clone())
            .unwrap_or_default()
    }
}

/// Spawns the shipped binary against the live stack. `init` is the difference between a first run
/// (`SPINDLE_HOST_INIT=1`) and a restart (no enrollment flag at all).
fn spawn_host(dir: &TempDir, init: bool) -> (Child, StderrCapture) {
    let mut command = Command::new(BINARY);
    command
        .env("SPINDLE_HOST_SEED_FILE", dir.path().join("host.seed"))
        .env("SPINDLE_HOST_STORE", dir.path().join("host.db"))
        .env("SPINDLE_NATS_URL", spindle_test_fixtures::nats_url())
        .env("SPINDLE_HOST_BIND_IP", "127.0.0.1")
        // `info` is the binary's own default; setting it explicitly keeps this test independent
        // of whatever the surrounding shell exported. `NO_COLOR` keeps the startup line free of
        // ANSI escapes so the fingerprint field can be compared textually.
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if init {
        command.env("SPINDLE_HOST_INIT", "1");
    }
    let mut child = command.spawn().expect("spawn the spindle-hostd binary");
    let stderr = StderrCapture::start(&mut child);
    (child, stderr)
}

fn wait_for_line(capture: &StderrCapture, marker: &str) -> String {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match capture.lines.recv_timeout(remaining) {
            Ok(line) if line.contains(marker) => return line,
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    panic!(
        "the host binary never logged `{marker}` within {}s\ncaptured stderr:\n{}",
        STARTUP_TIMEOUT.as_secs(),
        capture.transcript()
    );
}

/// The redacted `host_fp` field from a `host daemon starting` line, e.g. `host_fp=abcdef…`.
fn redacted_host_fp(startup_line: &str) -> String {
    const FIELD: &str = "host_fp=";
    let start = startup_line
        .find(FIELD)
        .unwrap_or_else(|| panic!("no `{FIELD}` field in startup line: {startup_line:?}"))
        + FIELD.len();
    let rest = &startup_line[start..];
    let end = rest
        .find(|character: char| character.is_whitespace())
        .unwrap_or(rest.len());
    assert!(!rest[..end].is_empty(), "empty host_fp field");
    rest[..end].to_string()
}

fn send_sigint(child: &Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("run kill -INT");
    assert!(status.success(), "kill -INT {} failed", child.id());
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait on the host child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the host binary did not exit within {}s of SIGINT",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Reads the child's stdout after it has exited. Only the recovery phrase is ever written there;
/// all logs go to stderr.
fn read_stdout(child: &mut Child) -> String {
    let mut stdout = child
        .stdout
        .take()
        .expect("child stdout is piped by spawn_host");
    let mut text = String::new();
    stdout
        .read_to_string(&mut text)
        .expect("read the host binary's stdout");
    text
}

/// Finds the one line that is a 52-character lowercase base32 recovery phrase grouped into
/// thirteen four-character groups.
fn recovery_phrase(stdout: &str) -> &str {
    stdout
        .lines()
        .find(|line| {
            let groups: Vec<&str> = line.split(' ').collect();
            groups.len() == 13
                && groups.iter().all(|group| {
                    group.len() == 4
                        && group
                            .chars()
                            .all(|character| matches!(character, 'a'..='z' | '2'..='7'))
                })
        })
        .unwrap_or_else(|| {
            panic!("stdout did not contain a recovery phrase (13 groups of 4 base32 characters):\n{stdout:?}")
        })
}

#[test]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-hostd --test live_host_binary -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly with the captured stderr — this test \
            never skips."]
fn first_run_enrolls_shuts_down_cleanly_and_restarts_with_the_same_host_fp() {
    let dir = private_tempdir();
    let seed_path = dir.path().join("host.seed");

    // ---- first run: explicit enrollment ------------------------------------------------
    let (mut first, first_stderr) = spawn_host(&dir, true);
    let first_startup = wait_for_line(&first_stderr, STARTUP_MARKER);
    let first_host_fp = redacted_host_fp(&first_startup);

    send_sigint(&first);
    let first_status = wait_for_exit(&mut first, SHUTDOWN_TIMEOUT);
    assert!(
        first_status.success(),
        "the first run must exit successfully on SIGINT, got {first_status}\ncaptured stderr:\n{}",
        first_stderr.transcript()
    );

    let first_stdout = read_stdout(&mut first);
    let phrase = recovery_phrase(&first_stdout);
    assert_eq!(
        phrase.chars().filter(|character| *character != ' ').count(),
        52,
        "the recovery phrase must encode 32 bytes as 52 base32 characters: {phrase:?}"
    );
    assert_eq!(phrase.split(' ').count(), 13, "phrase must be 13 groups");
    assert!(
        first_stdout.contains(phrase),
        "the recovery phrase must be written to stdout, not only somewhere else"
    );

    let metadata = fs::metadata(&seed_path).expect("the first run must have created the seed file");
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o600,
        "the seed file must be mode 0600 (DESIGN.md A10.41)"
    );

    // ---- restart: no enrollment flag, same seed, same host_fp ---------------------------
    let (mut second, second_stderr) = spawn_host(&dir, false);
    let second_startup = wait_for_line(&second_stderr, STARTUP_MARKER);
    let second_host_fp = redacted_host_fp(&second_startup);

    send_sigint(&second);
    let second_status = wait_for_exit(&mut second, SHUTDOWN_TIMEOUT);
    assert!(
        second_status.success(),
        "the restart must exit successfully on SIGINT, got {second_status}\ncaptured stderr:\n{}",
        second_stderr.transcript()
    );

    assert_eq!(
        first_host_fp, second_host_fp,
        "host_fp must survive a restart: it is derived from the persisted root seed \
         (DESIGN.md A10.41). A different redacted value means the binary minted a new seed \
         instead of loading the existing one, or logged a different identity"
    );
}
