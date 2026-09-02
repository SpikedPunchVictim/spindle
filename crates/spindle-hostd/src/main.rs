//! `spindle-hostd`'s development entry point — **not** the production way to run a Spindle host.
//!
//! This binary exists only so `spindle-hostd`'s library wiring ([`spindle_hostd::HostDaemon`]) has
//! *some* caller during Stage 4/5 development, before `apps/host`'s Tauri shell (Stage 7) exists to
//! call it in-process instead (see this crate's `Cargo.toml` header comment and `src/lib.rs`'s
//! module doc comment for why the shell calls the library rather than shelling out to this binary).
//!
//! # Why this cannot yet source a real host identity
//!
//! [`spindle_hostd::HostDaemon::new`] needs this host's envelope [`DeviceKey`] and root
//! [`Fingerprint`] (`host_fp`) — see that module's "Two fingerprints, not one" doc comment. DESIGN.md
//! §A4 puts custody of a host's root key in the OS keystore ("*Host* = has a **host identity root**
//! (`host_fp = hash(host_root_pk)`, backed up with the share config / recovery phrase)"), the same
//! custody model §A4 states for a person's identity root key. That keystore integration is Stage 7
//! work and does not exist anywhere in this workspace yet — confirmed against
//! `crates/spindle-vfs/src/store/schema.rs`, which has no table for a host root key, an operating
//! key, or a device key of any kind.
//!
//! The only public way this workspace can produce a [`DeviceKey`] today is
//! [`DeviceKey::generate`] (a fresh, unpersisted random keypair — useless here, since a real host
//! needs the *same* identity across restarts) or [`DeviceKey::from_seeds`], whose own doc comment
//! reads "Deterministic construction from two 32-byte seeds — TEST-ONLY / crypto-vector use." Wiring
//! this binary to read raw seed bytes from the environment and hand them to `from_seeds` would
//! satisfy the type signature, but it would not be an honest implementation of host key custody: it
//! would be exactly the ad hoc key-file-adjacent format this crate's task brief says not to invent,
//! wearing an environment variable instead of a file. Rather than do that, this binary fails loudly
//! and immediately, naming the real gap, and does not start any part of the daemon.
//!
//! When Stage 7 lands OS-keystore-backed host identity, this binary either grows a real
//! `NATS_URL`/store-path/identity-source config path of its own, or (per this crate's own module
//! doc comment) is simply retired in favor of `apps/host` calling
//! [`spindle_hostd::HostDaemon`] directly — that decision is Stage 7's to make, not this one's.
use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "spindle-hostd: not yet wired: host key custody is unimplemented (DESIGN.md §A4, Stage 7).\n\
         \n\
         This binary cannot source a real host identity (envelope DeviceKey + root host_fp) because\n\
         DESIGN.md §A4's OS-keystore-backed host key custody has not been implemented anywhere in\n\
         this workspace yet, and the only available in-workspace DeviceKey constructor besides\n\
         DeviceKey::generate() (fresh, unpersisted, useless across restarts) is DeviceKey::from_seeds,\n\
         which is explicitly documented as TEST-ONLY / crypto-vector use — not a substitute for real\n\
         key custody. See spindle-hostd's src/main.rs module doc comment for the full explanation.\n\
         \n\
         Stage 7's apps/host Tauri shell will replace this entry point entirely by calling\n\
         spindle_hostd::HostDaemon directly, once it can supply a real host identity."
    );
    ExitCode::FAILURE
}
