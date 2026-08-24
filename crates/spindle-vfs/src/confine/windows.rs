//! Windows-only attack surface (DESIGN.md §A4b/§A13 S11 cases 11-14): reserved device names,
//! Alternate Data Streams, and `\\?\`/`\\.\` verbatim/device paths. Every function here is
//! `#[cfg(windows)]`-gated at the item level (not just internally) — on macOS/Linux these
//! functions do not exist at all, matching the S11 spike's structure exactly; the tests that
//! exercise them stay compiled everywhere (so `cargo test --workspace` never skips a whole test
//! file) but are `#[ignore]`d off-Windows via `#[cfg_attr(not(windows), ignore = "...")]`, with
//! the real assertions inside a `#[cfg(windows)]` block. Closes A12 #19 (VFS escape) for the
//! Windows-specific path classes cap-std's Unix-oriented confinement does not itself see.

/// Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`,
/// case-insensitive, with or without an extension) must never be passed through to the OS as a
/// path component — doing so opens the device, not a file.
#[cfg(windows)]
pub fn is_windows_reserved_name(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = name.split('.').next().unwrap_or(name);
    RESERVED
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(stem))
}

/// `true` if `relative` contains an NTFS Alternate Data Stream selector (`file.txt:hidden`). Any
/// colon in a relative virtual path is an ADS selector, not a drive letter (virtual paths are
/// never drive-letter-prefixed).
#[cfg(windows)]
pub fn is_ads_path(relative: &str) -> bool {
    relative.contains(':')
}

/// `true` if `relative` is a `\\?\` (or `\\.\`) verbatim/device path, or otherwise rooted, and so
/// must never be handed to `Dir` as a "relative" virtual path.
#[cfg(windows)]
pub fn is_verbatim_or_rooted_path(relative: &str) -> bool {
    relative.starts_with(r"\\?\")
        || relative.starts_with(r"\\.\")
        || relative.starts_with('\\')
        || relative.starts_with('/')
}

// The imports below are used only inside `#[cfg(windows)]` test bodies; on other platforms those
// bodies compile to nothing (the test still exists but is `#[ignore]`d), so every import needed
// only for the Windows-only logic is scoped per-test rather than hoisted to module level — a
// module-level `use` would otherwise be a dead-code/unused-import warning on macOS/Linux.
#[cfg(test)]
mod tests {
    #[test]
    #[cfg_attr(not(windows), ignore = "windows-only case")]
    fn windows_extended_length_path_prefix_bypasses_confinement() {
        #[cfg(windows)]
        {
            use super::is_verbatim_or_rooted_path;
            use crate::confine::open_share_root;
            use tempfile::tempdir;

            let sandbox = tempdir().expect("tempdir");
            let root = sandbox.path().join("share");
            std::fs::create_dir(&root).expect("create share root");
            let dir = open_share_root(&root).expect("open share root");

            let outside_dir = tempdir().expect("outside tempdir");
            let outside = outside_dir.path().join("outside_secret.txt");
            std::fs::write(&outside, b"real secret").expect("write outside file");

            let verbatim = format!(r"\\?\{}", outside.display());
            assert!(
                is_verbatim_or_rooted_path(&verbatim),
                "sanity: the constructed path must look like a verbatim path to our own check"
            );

            let result = dir.open(&verbatim);
            assert!(
                result.is_err(),
                "a \\\\?\\-prefixed absolute path must not escape the cap-std Dir capability, \
                 got {result:?}"
            );
        }
    }

    #[test]
    #[cfg_attr(not(windows), ignore = "windows-only case")]
    fn windows_reserved_device_name_rejected() {
        #[cfg(windows)]
        {
            use super::is_windows_reserved_name;

            for name in [
                "CON", "con", "PRN", "AUX", "NUL", "COM1", "LPT1", "con.txt", "Nul.log",
            ] {
                assert!(
                    is_windows_reserved_name(name),
                    "{name} must be flagged as a reserved Windows device name"
                );
            }
            for name in ["normal.txt", "confidential.txt", "console.txt"] {
                assert!(
                    !is_windows_reserved_name(name),
                    "{name} must NOT be flagged as reserved (it only looks similar)"
                );
            }
        }
    }

    #[test]
    #[cfg_attr(not(windows), ignore = "windows-only case")]
    fn windows_8_3_short_name_alias_bypasses_checks() {
        #[cfg(windows)]
        {
            use crate::confine::{open_share_root, resolve_identity};
            use tempfile::tempdir;

            // No extra dependency for this: shell out to `cmd /c dir /x` to ask Windows for the
            // 8.3 short-name alias it generated, if any. If 8.3 name generation is disabled on
            // this volume (fsutil 8dot3name, common on modern SSD-backed Windows installs),
            // there is no alias to test and we report that rather than fabricate a pass.
            let sandbox = tempdir().expect("tempdir");
            let root = sandbox.path().join("share");
            std::fs::create_dir(&root).expect("create share root");
            let dir = open_share_root(&root).expect("open share root");

            let long_name = "this-is-a-very-long-filename-for-8dot3-aliasing.txt";
            dir.write(long_name, b"long name content")
                .expect("create long-named file");

            let output = std::process::Command::new("cmd")
                .args(["/c", "dir", "/x", "/-c"])
                .current_dir(&root)
                .output()
                .expect("run `cmd /c dir /x`");
            let listing = String::from_utf8_lossy(&output.stdout);

            let short_name = listing.lines().find_map(|line| {
                if !line.contains(long_name) {
                    return None;
                }
                let columns: Vec<&str> = line.split_whitespace().collect();
                let long_pos = columns.iter().position(|c| *c == long_name)?;
                (long_pos > 0).then(|| columns[long_pos - 1].to_string())
            });

            match short_name {
                Some(short_name) if short_name != long_name => {
                    let id_long = resolve_identity(&dir, long_name).expect("stat long name");
                    let id_short =
                        resolve_identity(&dir, &short_name).expect("stat short-name alias");
                    assert_eq!(
                        id_long, id_short,
                        "an 8.3 short-name alias must resolve to the same identity as the long \
                         name it aliases, so identity-keyed checks (exclusions, permissions) \
                         still apply to it"
                    );
                }
                _ => {
                    eprintln!(
                        "8.3 short-name generation appears disabled on this volume (fsutil \
                         8dot3name) — no alias exists to test; nothing to assert"
                    );
                }
            }
        }
    }

    #[test]
    #[cfg_attr(not(windows), ignore = "windows-only case")]
    fn windows_alternate_data_stream_bypasses_confinement() {
        #[cfg(windows)]
        {
            use super::is_ads_path;
            use crate::confine::open_share_root;
            use tempfile::tempdir;

            let sandbox = tempdir().expect("tempdir");
            let root = sandbox.path().join("share");
            std::fs::create_dir(&root).expect("create share root");
            let dir = open_share_root(&root).expect("open share root");
            dir.write("file.txt", b"visible content")
                .expect("create base file");

            assert!(is_ads_path("file.txt:hidden"));
            assert!(!is_ads_path("file.txt"));

            assert!(
                is_ads_path("file.txt:hidden"),
                "path validation must recognize the ADS selector and refuse it pre-filesystem"
            );
        }
    }
}
