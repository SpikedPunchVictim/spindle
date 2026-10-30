#![cfg(unix)]
//! Live proof of A10.45's **failed-renewal** rule (td-81ef38): when a mid-process renewal cannot
//! reload the root seed, the host keeps serving, refuses to issue new capabilities, logs the
//! reason, retries — and stops only when the certificate actually expires.
//!
//! # What this proves
//!
//! The binary starts with `SPINDLE_HOST_OP_CERT_TTL_SECS=9` (renewal instant: 6 s). Once its first
//! connection is serving, the test widens the seed file to `0644`. The process already has its
//! startup identity, but **every renewal reloads the seed from custody**, so the renewal at 6 s
//! must fail with the mode refusal. The assertions are:
//!
//! - no `operating-key certificate renewed` line ever appears (the failure is not silently
//!   retried into success once the mode was bad);
//! - the process is still alive 7 s after the first `host daemon starting` (past `renew_at`), so a
//!   failed renewal did not take the daemon down;
//! - the failure line names the `0o644` mode refusal;
//! - it exits non-zero by ~12 s — at `exp`, because the retry delay is `min(60, exp - now)`;
//! - the expiry path, not a connect failure, is what stops it.
//!
//! A [`HostGuard`] restores the seed file to `0600` and kills the child on every exit path,
//! including a panicking assertion, so a failed run cannot leave a world-readable seed or a
//! stray daemon behind.
//!
//! # Stack requirement — never skips
//!
//! This test is `#[ignore]`d, so `cargo test --workspace` reports it as ignored rather than
//! running it. When run it **requires** the live compose stack (`deploy/docker-compose.yml`);
//! an unreachable stack is a hard failure whose message includes the captured stderr, never a
//! skip. That is the repo's established policy (see `live_hostd.rs`'s module doc comment).
//!
//! Run with:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml up -d
//! cargo test -p spindle-hostd --test live_renewal_failsafe -- --ignored --nocapture
//! ```
//!
//! # Rebuild the helper image after any A7b wire-schema change
//!
//! Exactly as in `live_hostd.rs`.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Cargo sets this for every integration test in a package that has a `[[bin]]` target.
const BINARY: &str = env!("CARGO_BIN_EXE_spindle-hostd");
const STARTUP_MARKER: &str = "host daemon starting";
const RENEWAL_MARKER: &str = "operating-key certificate renewed";
const FAILURE_MARKER: &str = "operating-key certificate renewal failed";
const EXPIRY_MARKER: &str = "operating-key certificate has expired";
const MODE_REFUSAL: &str = "mode 0o644";
const OP_CERT_TTL_SECS: &str = "9";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
/// `renew_at` is 6 s; the process must still be serving past it.
const ALIVE_AFTER: Duration = Duration::from_secs(7);
/// `exp` is 9 s; the retry is clamped to it. Measured from the first startup, so 12 s is a
/// generous outer bound.
const EXIT_BY: Duration = Duration::from_secs(12);

/// A temp directory with the `0700` parent mode DESIGN.md A10.41 requires.
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

/// Kills the child (if it is still running) and restores the seed file's `0600` mode on every
/// exit path. Without the restore, a failed test would leave a widened seed behind; without the
/// kill, a panic while the daemon is alive could leave it running with a seed an operator has to
/// find and fix.
struct HostGuard {
    child: Child,
    seed_path: PathBuf,
}

impl Drop for HostGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::set_permissions(&self.seed_path, fs::Permissions::from_mode(0o600));
    }
}

/// Spawns the shipped binary for a first run against the live stack with a 9 s certificate
/// lifetime, so A10.45's renewal instant is 6 s.
fn spawn_host(dir: &TempDir) -> (Child, StderrCapture) {
    let mut child = Command::new(BINARY)
        .env("SPINDLE_HOST_SEED_FILE", dir.path().join("host.seed"))
        .env("SPINDLE_HOST_STORE", dir.path().join("host.db"))
        .env("SPINDLE_NATS_URL", spindle_test_fixtures::nats_url())
        .env("SPINDLE_HOST_BIND_IP", "127.0.0.1")
        .env("SPINDLE_HOST_INIT", "1")
        .env("SPINDLE_HOST_OP_CERT_TTL_SECS", OP_CERT_TTL_SECS)
        .env(
            "SPINDLE_HOST_RECOVERY_PHRASE_FILE",
            dir.path().join("recovery.phrase"),
        )
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the spindle-hostd binary");
    let stderr = StderrCapture::start(&mut child);
    (child, stderr)
}

/// Waits for a line containing `marker`, failing (never skipping) with the whole captured
/// transcript if `timeout` elapses or the child's stderr closes first.
fn wait_for_line(capture: &StderrCapture, marker: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
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
        timeout.as_secs(),
        capture.transcript()
    );
}

/// Consumes lines until `deadline`, returning them. Used to keep the stderr pipe drained while
/// the assertions inspect timing and content.
fn drain_until(capture: &StderrCapture, deadline: Instant) -> Vec<String> {
    let mut seen = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match capture.lines.recv_timeout(remaining) {
            Ok(line) => seen.push(line),
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    seen
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
                "the host binary did not exit within {}s of a failed renewal",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Reads the child's stdout after it has exited. Only the recovery phrase is ever written there
/// (and in this test it goes to a file instead); this keeps the pipe from filling.
fn drain_stdout(child: &mut Child) -> String {
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

#[test]
#[ignore = "live stack required: run `docker compose -f deploy/docker-compose.yml up -d` first, \
            then `cargo test -p spindle-hostd --test live_renewal_failsafe -- --ignored \
            --nocapture`. When run, an unreachable stack fails loudly with the captured stderr \
            — this test never skips."]
fn a_failed_renewal_keeps_serving_refuses_capabilities_and_stops_at_expiry() {
    let dir = private_tempdir();
    let seed_path = dir.path().join("host.seed");
    let (child, stderr) = spawn_host(&dir);
    let mut host = HostGuard {
        child,
        seed_path: seed_path.clone(),
    };

    // ---- first connection: startup identity is already resident -------------------------
    wait_for_line(&stderr, STARTUP_MARKER, STARTUP_TIMEOUT);
    let started_at = Instant::now();
    assert!(
        host.child
            .try_wait()
            .expect("try_wait on the first connect")
            .is_none(),
        "the host exited before its first connection could serve\ncaptured stderr:\n{}",
        stderr.transcript()
    );
    assert!(
        seed_path.exists(),
        "the first run must have persisted the seed before this test can widen it"
    );

    // ---- make the next renewal's seed reload impossible ----------------------------------
    // The startup identity is already in memory; only a renewal reloads the seed, so this
    // widens the file *after* start-up deliberately.
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644))
        .expect("widen the seed file to 0644");

    let lines = drain_until(&stderr, started_at + ALIVE_AFTER);
    assert!(
        !lines.iter().any(|line| line.contains(RENEWAL_MARKER)),
        "a renewal must not succeed after the seed file was widened to 0644\ncaptured stderr:\n{}",
        stderr.transcript()
    );
    assert!(
        lines.iter().any(|line| line.contains(FAILURE_MARKER)),
        "the failed renewal must be logged (the reason must not be swallowed)\ncaptured \
         stderr:\n{}",
        stderr.transcript()
    );
    assert!(
        host.child
            .try_wait()
            .expect("try_wait past renew_at")
            .is_none(),
        "a failed renewal must keep the process serving existing sessions, but it exited before \
         {}s\ncaptured stderr:\n{}",
        ALIVE_AFTER.as_secs(),
        stderr.transcript()
    );

    // ---- it must stop at `exp`, with the mode refusal named -----------------------------
    let remaining = (started_at + EXIT_BY).saturating_duration_since(Instant::now());
    let status = wait_for_exit(&mut host.child, remaining.max(Duration::from_secs(1)));
    assert!(
        !status.success(),
        "an expired operating certificate must stop the process with a failure exit, got \
         {status}\ncaptured stderr:\n{}",
        stderr.transcript()
    );

    // Let the reader thread append the last lines (stderr closes when the child exits).
    let _ = drain_until(&stderr, Instant::now() + Duration::from_secs(1));
    let transcript = stderr.transcript();
    assert!(
        !transcript.contains(RENEWAL_MARKER),
        "no renewal may ever succeed after the mode refusal\ncaptured stderr:\n{transcript}"
    );
    assert!(
        transcript.contains(FAILURE_MARKER),
        "the renewal-failure line must name the cause\ncaptured stderr:\n{transcript}"
    );
    assert!(
        transcript.contains(MODE_REFUSAL),
        "the renewal-failure line must carry the 0644 mode refusal\ncaptured stderr:\n{transcript}"
    );
    assert!(
        transcript.contains(EXPIRY_MARKER),
        "the process must stop because the certificate expired, not because a connect failed\
         \ncaptured stderr:\n{transcript}"
    );

    let stdout = drain_stdout(&mut host.child);
    assert!(
        stdout.is_empty(),
        "with stdout redirected, the recovery phrase must go to the configured phrase file, not \
         into the log stream; got:\n{stdout:?}"
    );
}
