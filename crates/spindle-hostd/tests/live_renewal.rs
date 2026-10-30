#![cfg(unix)]
//! Live proof of td-81ef38 / A10.45: the shipped `spindle-hostd` binary renews its
//! operating-key certificate **mid-process**, reconnects with the new operating key, and keeps
//! both fingerprints stable.
//!
//! # What this proves
//!
//! The binary is started with `SPINDLE_HOST_OP_CERT_TTL_SECS=9`, so its first operating
//! certificate expires 9 s after minting and A10.45's renewal instant is two-thirds of that —
//! **6 s**. No connection loss or restart is induced: a second `host daemon starting` line is
//! therefore the planned reconnect that follows a successful renewal. It can only appear after
//! `identity::renew_operating_identity` minted a new operating key and a new op cert, and after
//! `connect_host` re-authenticated with them and re-published the `HostDeviceCert` under them.
//!
//! The assertions pin the two halves of A10.44/A10.45 across that renewal:
//!
//! - the redacted `host_fp` is unchanged (the root seed, and therefore the root, did not move),
//! - the redacted `device_fp` is unchanged (the envelope `DeviceKey` is **not** re-minted at a
//!   renewal; only the operating key and its certificate are), and
//! - the process never exited, and SIGINT afterwards still exits 0.
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
//! cargo test -p spindle-hostd --test live_renewal -- --ignored --nocapture
//! ```
//!
//! `NATS_URL` overrides the stack's TCP listener (default `nats://127.0.0.1:4222`); the binary
//! receives it through its own `SPINDLE_NATS_URL`.
//!
//! # Rebuild the helper image after any A7b wire-schema change
//!
//! Exactly as in `live_hostd.rs`: a changed A7b artifact or `spindle-helper` requires
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
const RENEWAL_MARKER: &str = "operating-key certificate renewed";
/// Emitted immediately before every `connect_host`, carrying `op_cert_ts`/`op_cert_exp`. This is
/// the non-secret discriminator that proves the post-renewal connection presented the **new**
/// certificate, not the old one.
const CONNECT_MARKER: &str = "connecting to NATS with the operating-key certificate";
/// Long enough for the first connect plus renewal at 6 s and the renewal-driven connect.
const RENEWAL_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// The 9 s lifetime exercises renewal at 6 s; it is set as a string because the binary parses
/// the environment spelling, and the test deliberately goes through the same operator surface.
const OP_CERT_TTL_SECS: &str = "9";

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

/// Spawns the shipped binary for a first run against the live stack, with the shortened
/// operating-certificate lifetime. stdout is piped, so the recovery phrase goes to the
/// configured `0600` file.
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
        // `info` is the binary's own default; setting it explicitly keeps this test independent
        // of whatever the surrounding shell exported. `NO_COLOR` keeps the fingerprint fields
        // free of ANSI escapes so they can be compared textually.
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

/// The redacted value of `<field>=...` on a log line, e.g. `host_fp=abcdef…`.
fn redacted_field(line: &str, field: &str) -> String {
    let marker = format!("{field}=");
    let start = line
        .find(&marker)
        .unwrap_or_else(|| panic!("no `{marker}` field in line: {line:?}"))
        + marker.len();
    let rest = &line[start..];
    let end = rest
        .find(|character: char| character.is_whitespace())
        .unwrap_or(rest.len());
    assert!(!rest[..end].is_empty(), "empty {field} field in {line:?}");
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
            then `cargo test -p spindle-hostd --test live_renewal -- --ignored --nocapture`. \
            When run, an unreachable stack fails loudly with the captured stderr — this test \
            never skips."]
fn renewal_reconnects_with_a_new_operating_key_and_keeps_both_fingerprints() {
    let dir = private_tempdir();
    let (mut host, stderr) = spawn_host(&dir);

    // ---- first connection: process start ------------------------------------------------
    let first_startup = wait_for_line(&stderr, STARTUP_MARKER, RENEWAL_TIMEOUT);
    let first_host_fp = redacted_field(&first_startup, "host_fp");
    let first_device_fp = redacted_field(&first_startup, "device_fp");
    assert!(
        host.try_wait()
            .expect("try_wait on the first connect")
            .is_none(),
        "the host exited before its first connection could serve\ncaptured stderr:\n{}",
        stderr.transcript()
    );

    // ---- renewal: two-thirds of the 9 s lifetime = 6 s ----------------------------------
    let renewal_line = wait_for_line(&stderr, RENEWAL_MARKER, RENEWAL_TIMEOUT);
    // The renewal marker is logged after `renew_operating_identity` succeeds and before the
    // planned reconnect's connect begins; the next startup line is that reconnect's daemon.
    let second_startup = wait_for_line(&stderr, STARTUP_MARKER, RENEWAL_TIMEOUT);
    let second_host_fp = redacted_field(&second_startup, "host_fp");
    let second_device_fp = redacted_field(&second_startup, "device_fp");

    assert!(
        host.try_wait()
            .expect("try_wait after the renewal reconnect")
            .is_none(),
        "the process must survive a renewal (a renewal is a planned reconnect, not a restart)\n\
         renewal line: {renewal_line}\ncaptured stderr:\n{}",
        stderr.transcript()
    );

    assert_eq!(
        first_host_fp, second_host_fp,
        "host_fp must not change across a renewal: the root seed reloaded from custody is the \
         same root"
    );
    assert_eq!(
        first_device_fp, second_device_fp,
        "device_fp must not change across a renewal: A10.45 renews the operating key and its \
         certificate, never the envelope DeviceKey"
    );

    // ---- the post-renewal connection presented the *new* certificate ---------------------
    //
    // Both `host daemon starting` lines have now been emitted, so every connect line is in the
    // transcript. The connect line after the renewal marker must carry a strictly later
    // `op_cert_ts` than the first connection, and that ts must be the renewed certificate's own
    // `ts` (cross-checked against the renewal marker's `exp`). A regression that reconnects with
    // the old certificate leaves the two `op_cert_ts` values equal and fails here.
    let transcript = stderr.transcript();
    let lines: Vec<&str> = transcript.lines().collect();
    let first_connect = *lines
        .iter()
        .find(|line| line.contains(CONNECT_MARKER))
        .unwrap_or_else(|| {
            panic!("no first-connect line in transcript:\n{transcript}");
        });
    let renewal_index = lines
        .iter()
        .position(|line| line.contains(RENEWAL_MARKER))
        .unwrap_or_else(|| {
            panic!("no renewal line in transcript:\n{transcript}");
        });
    let second_connect = *lines
        .iter()
        .skip(renewal_index)
        .find(|line| line.contains(CONNECT_MARKER))
        .unwrap_or_else(|| {
            panic!("no post-renewal connect line in transcript:\n{transcript}");
        });

    let first_ts: u64 = redacted_field(first_connect, "op_cert_ts")
        .parse()
        .expect("first connect's op_cert_ts is a whole second");
    let second_ts: u64 = redacted_field(second_connect, "op_cert_ts")
        .parse()
        .expect("second connect's op_cert_ts is a whole second");
    let renewal_ts: u64 = redacted_field(&renewal_line, "ts")
        .parse()
        .expect("the renewal marker logs the new certificate's ts");
    let renewal_exp: u64 = redacted_field(&renewal_line, "exp")
        .parse()
        .expect("the renewal marker logs the new certificate's exp");

    assert!(
        second_ts > first_ts,
        "the post-renewal connection must present a certificate minted after the first \
         connection's; got first_ts={first_ts} second_ts={second_ts}\ncaptured stderr:\n{transcript}"
    );
    assert_eq!(
        second_ts, renewal_ts,
        "the connection after the renewal marker must present the renewed certificate's ts, not \
         the process-start certificate's"
    );
    assert_eq!(
        renewal_exp,
        renewal_ts
            + OP_CERT_TTL_SECS
                .parse::<u64>()
                .expect("the test's TTL literal is a number"),
        "the renewed certificate must run for exactly the configured lifetime"
    );

    // ---- shutdown ------------------------------------------------------------------------
    send_sigint(&host);
    let status = wait_for_exit(&mut host, SHUTDOWN_TIMEOUT);
    assert!(
        status.success(),
        "SIGINT after a renewal must exit 0, got {status}\ncaptured stderr:\n{}",
        stderr.transcript()
    );
    wait_for_line(&stderr, "shutdown signal received", Duration::from_secs(5));

    let stdout = drain_stdout(&mut host);
    assert!(
        stdout.is_empty(),
        "with stdout redirected, the recovery phrase must go to the configured phrase file, not \
         into the log stream; got:\n{stdout:?}"
    );
}
