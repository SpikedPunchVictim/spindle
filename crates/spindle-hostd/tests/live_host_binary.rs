#![cfg(unix)]
//! Live smoke test for the `spindle-hostd` binary itself (td-539ffa slice 3): first-run
//! enrollment, graceful SIGINT shutdown, identity survival across a restart, and a restore from
//! the delivered recovery phrase into a fresh directory.
//!
//! # What this proves that `tests/live_hostd.rs` does not
//!
//! `live_hostd.rs` drives the library's [`spindle_hostd::HostDaemon`] directly with a
//! callout-authenticated client the test built itself. This file instead executes the shipped
//! binary: it proves the binary's own startup path — `SPINDLE_HOST_INIT` enrollment, the `0600`
//! seed and recovery-phrase files, the real NATS connect through
//! `spindle_hostd::connect::connect_host`, the `HostDaemon` assembly, and `Ctrl-C` handling — and
//! that the one persisted artifact (the root seed) makes `host_fp` survive a second start. It
//! also restores the phrase delivered by the first run into a **fresh** directory and asserts the
//! same `host_fp`, which ties the delivered phrase to the persisted seed. Because the test pipes
//! stdout, the binary uses the non-TTY `--recovery-phrase-file` sink and the phrase is read back
//! from that file.
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
/// (`SPINDLE_HOST_INIT=1`) and a restart (no enrollment flag at all). `extra_env` carries the
/// enrollment source for the restore round-trip.
fn spawn_host(dir: &TempDir, init: bool) -> (Child, StderrCapture) {
    spawn_host_with_env(dir, init, &[])
}

fn spawn_host_with_env(
    dir: &TempDir,
    init: bool,
    extra_env: &[(&str, &str)],
) -> (Child, StderrCapture) {
    let mut command = Command::new(BINARY);
    command
        .env("SPINDLE_HOST_SEED_FILE", dir.path().join("host.seed"))
        .env("SPINDLE_HOST_STORE", dir.path().join("host.db"))
        .env("SPINDLE_NATS_URL", spindle_test_fixtures::nats_url())
        .env("SPINDLE_HOST_BIND_IP", "127.0.0.1")
        // The test pipes stdout, so the binary correctly refuses to print the recovery phrase
        // into it (that would be a log pipeline). Point it at the non-TTY phrase-file sink; the
        // file is read back below and then used for the restore round-trip.
        .env(
            "SPINDLE_HOST_RECOVERY_PHRASE_FILE",
            dir.path().join("recovery.phrase"),
        )
        // `info` is the binary's own default; setting it explicitly keeps this test independent
        // of whatever the surrounding shell exported. `NO_COLOR` keeps the startup line free of
        // ANSI escapes so the fingerprint field can be compared textually.
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in extra_env {
        command.env(name, value);
    }
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
/// thirteen four-character groups. This is the finder's shape check, not an assertion about what
/// the binary does with the phrase.
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
            panic!(
                "text did not contain a recovery phrase (13 groups of 4 base32 characters):\n{stdout:?}"
            )
        })
}

#[test]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-hostd --test live_host_binary -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly with the captured stderr — this test \
            never skips."]
fn first_run_enrolls_shuts_down_cleanly_and_the_printed_phrase_restores_the_same_host_fp() {
    let dir = private_tempdir();
    let seed_path = dir.path().join("host.seed");

    // ---- first run: explicit enrollment ------------------------------------------------
    let (mut first, first_stderr) = spawn_host(&dir, true);
    let first_startup = wait_for_line(&first_stderr, STARTUP_MARKER);
    let first_host_fp = redacted_host_fp(&first_startup);

    // A signal sent to a process that has already exited proves nothing about signal handling.
    assert!(
        first
            .try_wait()
            .expect("try_wait on the first host child")
            .is_none(),
        "the first run exited before SIGINT could be delivered\ncaptured stderr:\n{}",
        first_stderr.transcript()
    );
    send_sigint(&first);
    let first_status = wait_for_exit(&mut first, SHUTDOWN_TIMEOUT);
    assert!(
        first_status.success(),
        "the first run must exit successfully on SIGINT, got {first_status}\ncaptured stderr:\n{}",
        first_stderr.transcript()
    );
    // Drain the signal handler's own line before checking the transcript: `wait_for_exit`
    // returns when the process exits, which can be a hair before the stderr reader thread has
    // appended the final line.
    wait_for_line(&first_stderr, "shutdown signal received");
    assert!(
        first_stderr
            .transcript()
            .contains("shutdown signal received"),
        "the SIGINT handler's own log line must be in the captured transcript:\n{}",
        first_stderr.transcript()
    );

    let first_stdout = read_stdout(&mut first);
    assert!(
        first_stdout.is_empty(),
        "with stdout redirected, the phrase must go to the configured phrase file, not into the \
         log stream; got:\n{first_stdout:?}"
    );
    let phrase_path = dir.path().join("recovery.phrase");
    let phrase_text =
        fs::read_to_string(&phrase_path).expect("the first run must write the phrase file");
    let phrase = recovery_phrase(&phrase_text).to_string();
    assert_eq!(
        fs::metadata(&phrase_path)
            .expect("the phrase file's metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "the recovery phrase file must be mode 0600, like the seed file"
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

    assert!(
        second
            .try_wait()
            .expect("try_wait on the restarted host child")
            .is_none(),
        "the restart exited before SIGINT could be delivered\ncaptured stderr:\n{}",
        second_stderr.transcript()
    );
    send_sigint(&second);
    let second_status = wait_for_exit(&mut second, SHUTDOWN_TIMEOUT);
    assert!(
        second_status.success(),
        "the restart must exit successfully on SIGINT, got {second_status}\ncaptured stderr:\n{}",
        second_stderr.transcript()
    );
    wait_for_line(&second_stderr, "shutdown signal received");

    assert_eq!(
        first_host_fp, second_host_fp,
        "host_fp must survive a restart: it is derived from the persisted root seed \
         (DESIGN.md A10.41). A different redacted value means the binary minted a new seed \
         instead of loading the existing one, or logged a different identity"
    );

    // The phrase is delivered once, at enrollment; a normal start must write nothing to stdout.
    let second_stdout = read_stdout(&mut second);
    assert!(
        second_stdout.is_empty(),
        "a normal start must not write to stdout (the recovery phrase is an enrollment-only \
         secret), got:\n{second_stdout:?}"
    );

    // ---- restore: the phrase delivered by run 1 really is the persisted seed -------------
    let restore_dir = private_tempdir();
    let (mut restored, restored_stderr) = spawn_host_with_env(
        &restore_dir,
        false,
        &[("SPINDLE_HOST_RESTORE_SEED", phrase.as_str())],
    );
    let restored_startup = wait_for_line(&restored_stderr, STARTUP_MARKER);
    let restored_host_fp = redacted_host_fp(&restored_startup);

    assert_eq!(
        first_host_fp, restored_host_fp,
        "a fresh directory restored from the phrase printed by the first run must mint the same \
         host_fp. A different value means the printed phrase does not encode the persisted seed"
    );

    assert!(
        restored
            .try_wait()
            .expect("try_wait on the restored host child")
            .is_none(),
        "the restored run exited before SIGINT could be delivered\ncaptured stderr:\n{}",
        restored_stderr.transcript()
    );
    send_sigint(&restored);
    let restored_status = wait_for_exit(&mut restored, SHUTDOWN_TIMEOUT);
    assert!(
        restored_status.success(),
        "the restored run must exit successfully on SIGINT, got {restored_status}\ncaptured stderr:\n{}",
        restored_stderr.transcript()
    );
    wait_for_line(&restored_stderr, "shutdown signal received");

    let restored_stdout = read_stdout(&mut restored);
    assert!(
        restored_stdout.is_empty(),
        "a restore must not reprint the phrase (the operator already holds it), got:\n{restored_stdout:?}"
    );
}
