#![cfg(unix)]
//! Live proof of td-6242d2: the shipped `spindle-hostd` binary survives a NATS outage **longer
//! than the `HostSessionAttestation` validity window** by reconnecting with fresh credentials,
//! while keeping this process's envelope `device_fp` stable.
//!
//! # What this proves
//!
//! The CONNECT token is a snapshot: a per-session nkey, an attestation valid for ±120 s, and a
//! token async-nats 0.35 replays unchanged on an automatic reconnect. Stopping the broker for
//! **130 s** makes that original token provably stale (the server is up again with a fresh clock
//! skew of zero against an attestation minted 130 s earlier), so a second `host daemon starting`
//! line can only come from the supervisor's `connect_host` call minting a new nkey, attestation,
//! and token. The assertions pin the two halves of A10.44/A10.45:
//!
//! - the redacted `host_fp` is unchanged (same persisted root), and
//! - the redacted `device_fp` is unchanged **within one process** — the envelope key is
//!   regenerated per process, never per reconnect.
//!
//! The process must also still be running throughout the outage (polled every second), and a
//! SIGINT afterwards must still exit 0. `connect_host` publishes and flushes the `HostDeviceCert`
//! before returning, so the second `host daemon starting` line also means a fresh certificate
//! publish succeeded; `live_devcert.rs` covers fetching a re-published certificate from the
//! helper with the same `device_fp` (the binary's op key is ephemeral and not available to this
//! test, so a member capability for its running identity cannot be minted here).
//!
//! # This test stops and starts the shared compose stack's `nats` service
//!
//! It runs `docker compose -f deploy/docker-compose.yml stop nats`, waits 130 s, then starts the
//! service again. It **must not run alongside any other live test** (`live_hostd.rs`,
//! `live_devcert.rs`, `live_host_binary.rs`, or a concurrently running binary): every one of them
//! needs the broker. Run this file last, and alone. A best-effort guard starts `nats` again on
//! every exit path, including a panic.
//!
//! # Gating
//!
//! `#[ignore]`d, so `cargo test --workspace` reports it as ignored rather than running it. When
//! run, an unreachable stack is a hard failure with the captured stderr, never a skip — the
//! repo's established policy (see `live_hostd.rs`'s module doc comment).
//!
//! Run with:
//!
//! ```text
//! docker compose -f deploy/docker-compose.yml up -d
//! cargo test -p spindle-hostd --test live_reconnect -- --ignored --nocapture
//! ```
//!
//! Takes over 2.5 minutes by construction (the outage alone is 130 s).

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// Cargo sets this for every integration test in a package that has a `[[bin]]` target.
const BINARY: &str = env!("CARGO_BIN_EXE_spindle-hostd");
const MINT_MARKER: &str = "host identity minted for this process";
const STARTUP_MARKER: &str = "host daemon starting";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
/// Longer than the ±120 s attestation window, so the original token cannot verify after it.
const OUTAGE: Duration = Duration::from_secs(130);
/// How long the host gets to reconnect once the broker is back. The outer loop's backoff is
/// capped at 30 s, so 60 s covers the worst phase plus the helper's own reconnect.
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn compose_file() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/docker-compose.yml")
        .canonicalize()
        .expect("locate deploy/docker-compose.yml from the crate manifest directory")
}

fn compose(compose_file: &Path, action: &str) -> std::process::Output {
    Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(compose_file)
        .arg(action)
        .arg("nats")
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "could not run `docker compose -f {} {action} nats`: {error}",
                compose_file.display()
            )
        })
}

fn compose_ok(compose_file: &Path, action: &str) {
    let output = compose(compose_file, action);
    assert!(
        output.status.success(),
        "`docker compose -f {} {action} nats` failed with {}\nstdout:\n{}\nstderr:\n{}",
        compose_file.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Best-effort: starts the shared stack's `nats` service again on every exit path, including a
/// panicking assertion. Never panics itself — a cleanup failure must not mask the test's own
/// failure.
struct NatsServiceGuard {
    compose_file: PathBuf,
}

impl NatsServiceGuard {
    fn new(compose_file: PathBuf) -> Self {
        // A previous failed run may have left the service stopped.
        let _ = compose(&compose_file, "start");
        Self { compose_file }
    }
}

impl Drop for NatsServiceGuard {
    fn drop(&mut self) {
        let _ = compose(&self.compose_file, "start");
    }
}

/// Kills and reaps the spawned host on every exit path, so a panicking assertion cannot leave the
/// daemon running against the shared broker.
struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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

/// Spawns the shipped binary for a first run (`--init` through the environment) against the live
/// stack, with the non-TTY recovery-phrase-file sink.
fn spawn_host(dir: &TempDir) -> (Child, StderrCapture) {
    let mut child = Command::new(BINARY)
        .env("SPINDLE_HOST_SEED_FILE", dir.path().join("host.seed"))
        .env("SPINDLE_HOST_STORE", dir.path().join("host.db"))
        .env("SPINDLE_NATS_URL", spindle_test_fixtures::nats_url())
        .env("SPINDLE_HOST_BIND_IP", "127.0.0.1")
        // stdout is piped, so the binary correctly refuses to put the phrase there; point it at
        // the non-TTY phrase-file sink instead.
        .env(
            "SPINDLE_HOST_RECOVERY_PHRASE_FILE",
            dir.path().join("recovery.phrase"),
        )
        // `info` is the binary's own default; setting it keeps this test independent of the
        // surrounding shell. `NO_COLOR` keeps the fingerprint fields free of ANSI escapes.
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env("SPINDLE_HOST_INIT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the spindle-hostd binary");
    let stderr = StderrCapture::start(&mut child);
    (child, stderr)
}

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

/// The redacted `field=value` token from a tracing line, e.g. `host_fp=abcdefgh…` or
/// `device_fp=abcdefgh…`.
fn redacted_field(line: &str, field: &str) -> String {
    let needle = format!("{field}=");
    let start = line
        .find(&needle)
        .unwrap_or_else(|| panic!("no `{needle}` field in line: {line:?}"))
        + needle.len();
    let rest = &line[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    assert!(!rest[..end].is_empty(), "empty `{field}` field in {line:?}");
    rest[..end].to_string()
}

/// Discards every line already buffered on the receiver. A startup marker read after this drain
/// must have been emitted by a line the child wrote *after* the drain — not by one that was
/// buffered while the broker was down.
fn drain_lines(capture: &StderrCapture) {
    while capture.lines.try_recv().is_ok() {}
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

#[test]
#[ignore = "live stack required (stops and restarts the shared `nats` service; run it alone, \
            after all other live tests): `docker compose -f deploy/docker-compose.yml up -d`, \
            then `cargo test -p spindle-hostd --test live_reconnect -- --ignored --nocapture`. \
            Takes >2.5 min. Never skips when run."]
fn host_reconnects_with_fresh_credentials_after_an_outage_longer_than_the_attestation_window() {
    let compose_file = compose_file();
    let _nats_guard = NatsServiceGuard::new(compose_file.clone());

    let dir = private_tempdir();
    let (child, stderr) = spawn_host(&dir);
    // Killing and reaping on Drop means a failed assertion cannot leave the daemon running.
    let mut host = ChildGuard::new(child);

    // ---- first connection ----------------------------------------------------------------
    let minted = wait_for_line(&stderr, MINT_MARKER, STARTUP_TIMEOUT);
    let first_host_fp = redacted_field(&minted, "host_fp");
    let first_device_fp = redacted_field(&minted, "device_fp");
    let first_startup = wait_for_line(&stderr, STARTUP_MARKER, STARTUP_TIMEOUT);

    // The mint line and the startup line describe the same process; cross-checking them makes a
    // later "unchanged device_fp" comparison meaningful rather than a comparison of two fields
    // that were never tied together.
    assert_eq!(
        redacted_field(&first_startup, "host_fp"),
        first_host_fp,
        "the minted and startup host_fp must agree"
    );
    assert_eq!(
        redacted_field(&first_startup, "device_fp"),
        first_device_fp,
        "the minted and startup device_fp must agree"
    );
    assert!(
        host.child
            .try_wait()
            .expect("try_wait on the host child")
            .is_none(),
        "the host exited before the outage began\ncaptured stderr:\n{}",
        stderr.transcript()
    );

    // ---- outage longer than the attestation window --------------------------------------
    println!(
        "[reconnect] stopping the compose stack's nats service for {}s (attestation window is \
         ±120 s)",
        OUTAGE.as_secs()
    );
    compose_ok(&compose_file, "stop");
    // Anything the child wrote before the broker went away is irrelevant; draining here means the
    // post-restart wait below cannot be satisfied by a line buffered before the outage.
    drain_lines(&stderr);

    let outage_deadline = Instant::now() + OUTAGE;
    while Instant::now() < outage_deadline {
        if let Some(status) = host
            .child
            .try_wait()
            .expect("try_wait on the host child during the outage")
        {
            panic!(
                "the host process exited during the NATS outage with {status}; it must stay \
                 alive and reconnect\ncaptured stderr:\n{}",
                stderr.transcript()
            );
        }
        thread::sleep(Duration::from_secs(1));
    }
    assert!(
        host.child
            .try_wait()
            .expect("try_wait on the host child after the outage")
            .is_none(),
        "the host process must still be running after the {}s outage\ncaptured stderr:\n{}",
        OUTAGE.as_secs(),
        stderr.transcript()
    );

    // ---- broker returns: a second, freshly-authenticated connection ----------------------
    // Discard everything emitted while the broker was down, so the marker read below must come
    // from the post-restart connection.
    drain_lines(&stderr);
    println!("[reconnect] starting the compose stack's nats service again");
    compose_ok(&compose_file, "start");
    let second_startup = wait_for_line(&stderr, STARTUP_MARKER, RECONNECT_TIMEOUT);

    assert_eq!(
        redacted_field(&second_startup, "host_fp"),
        first_host_fp,
        "host_fp must survive a reconnect (it is derived from the persisted root seed)"
    );
    assert_eq!(
        redacted_field(&second_startup, "device_fp"),
        first_device_fp,
        "device_fp must be stable across reconnects within one process (A10.44/A10.45): the \
         envelope DeviceKey is regenerated per process, never per reconnect. A different value \
         means the reconnect path re-minted the process identity"
    );
    println!(
        "[reconnect] daemon restarted with the same host_fp={} device_fp={}",
        first_host_fp, first_device_fp
    );

    // ---- SIGINT still exits 0 ------------------------------------------------------------
    assert!(
        host.child
            .try_wait()
            .expect("try_wait on the host child before SIGINT")
            .is_none(),
        "the host exited before SIGINT could be delivered\ncaptured stderr:\n{}",
        stderr.transcript()
    );
    send_sigint(&host.child);
    let status = wait_for_exit(&mut host.child, SHUTDOWN_TIMEOUT);
    assert_eq!(
        status.code(),
        Some(0),
        "SIGINT after a reconnect must exit 0, got {status}\ncaptured stderr:\n{}",
        stderr.transcript()
    );
}
