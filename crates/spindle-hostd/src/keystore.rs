//! Host root-seed custody: the [`HostKeyStore`] seam and its headless, seed-file implementation.
//!
//! DESIGN.md A10.41 puts custody of a host's Ed25519 identity root behind one trait, so the
//! desktop/Tauri and headless/server deployments can differ in *where* the 32-byte seed lives
//! without differing in what the host does with it. Only the seed is persisted — never the
//! derived keypair — and generation happens only through an explicit enrollment action, never as
//! a fallback from a failed read: an absent seed is a refusal to start, not a quiet first run.
//! The desktop half (an OS-keychain store) is still unshipped Stage 7 work; [`SeedFileStore`] is
//! the headless half.
//!
//! # Why the file contents are the raw seed
//!
//! A10.41 persists the 32-byte seed itself. Writing it with no encoding keeps the on-disk format
//! exactly as long as the secret and leaves no parser between the store and `RootKey::from_seed`.
//! The human-facing recovery phrase is a separate, display-only encoding (see
//! [`crate::identity::format_recovery_phrase`]); it is never the storage format.
//!
//! # Mode enforcement is a refusal, never a correction
//!
//! A10.41 makes the seed file's mode normative: the file is `0600` and its parent directory
//! `0700`. If either is found *wider* — any set permission bit outside that mask — the store
//! returns an error naming the path and the octal mode found. It never `chmod`s the entry on the
//! host's behalf, because a silent correction would conceal exactly the fact an operator needs to
//! know: the seed may already have been readable by someone else. A10.41(c) scopes this rule to
//! POSIX: where no meaningful mode bits exist the seed-file store is not a supported configuration
//! at all, and every operation on non-Unix targets returns [`KeyStoreError::UnsupportedPlatform`].

use std::path::PathBuf;

use thiserror::Error;

/// Length in bytes of a host root seed. DESIGN.md A10.41 persists this value verbatim; it is the
/// seed `spindle_core::RootKey::from_seed` accepts.
pub const ROOT_SEED_LEN: usize = 32;

/// The seed-custody seam DESIGN.md A10.41 specifies.
///
/// `Send + Sync` because a host process may load the seed during start-up and hand the store to
/// a background renewal path later; the trait itself carries no locking or caching behavior.
pub trait HostKeyStore: Send + Sync {
    /// Loads the persisted root seed.
    ///
    /// An absent entry is [`KeyStoreError::Absent`] — distinctly *not* a freshly generated seed.
    /// Implementations MUST NOT generate or fall back on a read failure (A10.41(b)).
    fn load_root_seed(&self) -> Result<[u8; ROOT_SEED_LEN], KeyStoreError>;

    /// Persists a seed obtained from the OS CSPRNG during explicit enrollment.
    ///
    /// Must never overwrite an existing entry; the `SeedFileStore` implementation enforces this
    /// with `create_new`.
    fn store_root_seed(&self, seed: &[u8; ROOT_SEED_LEN]) -> Result<(), KeyStoreError>;
}

/// Everything [`HostKeyStore`] operations can fail with.
///
/// Error messages name the path and, for mode failures, the octal mode found, because DESIGN.md
/// A10.41 requires a refusal to be diagnosable — an operator has to be able to see which entry is
/// wrong and why, rather than guess after a bare "permission denied".
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// No seed file exists. Deliberately distinct from every I/O failure: A10.41(b) forbids
    /// treating an unreadable or absent entry as first run.
    #[error(
        "host root seed file {} is absent; refusing to start (first-run generation must be an \
         explicit enrollment action, never a fallback from a failed read)",
        .path.display()
    )]
    Absent { path: PathBuf },

    /// The parent directory A10.41 requires does not exist (or is not a directory).
    #[error(
        "host seed directory {} does not exist or is not a directory; create it with mode 0o700 \
         before starting the host",
        .path.display()
    )]
    ParentMissing { path: PathBuf },

    /// The parent directory is wider than the required `0700`. Reused by [`check_parent_mode`]
    /// for the one-shot recovery-phrase files, whose directory is held to the same rule.
    #[error(
        "directory {} has mode 0o{:o}, wider than the required 0o700; refusing to use it rather \
         than silently correcting it, since the secret it holds may already have been read",
        .path.display(),
        mode
    )]
    ParentModeTooWide { path: PathBuf, mode: u32 },

    /// The secret file is wider than the required `0600`. Reused by [`check_file_mode`] for the
    /// one-shot recovery-phrase files, which are held to the same rule as the seed file.
    #[error(
        "file {} has mode 0o{:o}, wider than the required 0o600; refusing to read it rather than \
         silently correcting it, since the secret may already have been read",
        .path.display(),
        mode
    )]
    SeedFileModeTooWide { path: PathBuf, mode: u32 },

    /// The file exists but is not exactly [`ROOT_SEED_LEN`] bytes.
    #[error(
        "host seed file {} contains {len} bytes; a host root seed is exactly {expected} bytes",
        .path.display()
    )]
    WrongLength {
        path: PathBuf,
        len: usize,
        expected: usize,
    },

    /// [`HostKeyStore::store_root_seed`] found an existing entry. A seed is never rewritten:
    /// doing so would change `host_fp` and wall every member bound to it (A10.41).
    #[error(
        "host seed file {} already exists; refusing to overwrite an existing host root seed",
        .path.display()
    )]
    AlreadyExists { path: PathBuf },

    /// Reading or writing the secret file or its directory metadata failed.
    #[error("file I/O failed at {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `#[cfg(not(unix))]` only: A10.41(c) scopes the mode rule to POSIX and says the seed-file
    /// store is not a supported configuration where mode bits are not meaningful.
    #[error(
        "host seed-file custody is not supported on this platform: filesystem mode bits are not \
         meaningful here (DESIGN.md A10.41(c)); use an OS-keychain HostKeyStore instead"
    )]
    UnsupportedPlatform,
}

/// Headless host seed custody: the raw 32-byte seed in a file whose mode is `0600`, inside a
/// parent directory whose mode is at most `0700` (DESIGN.md A10.41).
///
/// Construction is infallible; the mode checks run on every load and store, so a directory whose
/// permissions get widened while the host is running is caught on the next read rather than
/// trusted from a check done once at start-up.
pub struct SeedFileStore {
    path: PathBuf,
}

impl SeedFileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The path this store reads and writes. Useful to a caller that has to name the same file in
    /// an operator-facing message of its own.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(unix)]
impl HostKeyStore for SeedFileStore {
    fn load_root_seed(&self) -> Result<[u8; ROOT_SEED_LEN], KeyStoreError> {
        self.ensure_parent_is_private()?;

        let metadata = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(KeyStoreError::Absent {
                    path: self.path.clone(),
                });
            }
            Err(source) => {
                return Err(KeyStoreError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };

        // Check the mode *before* reading the secret, so a seed that is already world-readable is
        // never copied into this process merely to discover that it should not have been read.
        // `metadata.mode()` carries file-type bits as well; mask them off before comparing.
        let mode = metadata.mode() & 0o7777;
        if mode & !0o600 != 0 {
            return Err(KeyStoreError::SeedFileModeTooWide {
                path: self.path.clone(),
                mode,
            });
        }

        let bytes = std::fs::read(&self.path).map_err(|source| KeyStoreError::Io {
            path: self.path.clone(),
            source,
        })?;
        let len = bytes.len();
        let seed: [u8; ROOT_SEED_LEN] =
            bytes.try_into().map_err(|_| KeyStoreError::WrongLength {
                path: self.path.clone(),
                len,
                expected: ROOT_SEED_LEN,
            })?;
        Ok(seed)
    }

    fn store_root_seed(&self, seed: &[u8; ROOT_SEED_LEN]) -> Result<(), KeyStoreError> {
        self.ensure_parent_is_private()?;

        // `create_new` is the enforcement of "never overwrite a seed": it is atomic in the
        // filesystem, so two concurrent first runs cannot both believe they won the race and
        // silently replace one another's `host_fp`. `mode(0o600)` is the requested permission;
        // the process umask may narrow it further, which is fine — narrower is never "wider".
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(KeyStoreError::AlreadyExists {
                    path: self.path.clone(),
                });
            }
            Err(source) => {
                return Err(KeyStoreError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };

        std::io::Write::write_all(&mut file, seed).map_err(|source| KeyStoreError::Io {
            path: self.path.clone(),
            source,
        })
    }
}

#[cfg(unix)]
impl SeedFileStore {
    /// A10.41's parent-directory half of the mode rule. Called before any read or write, so an
    /// over-wide directory is refused identically at load and store time.
    fn ensure_parent_is_private(&self) -> Result<(), KeyStoreError> {
        check_parent_mode(&self.path)
    }
}

/// The directory `path` lives in. A bare relative file name has an empty parent; treat that as
/// the current directory rather than statting an empty path.
#[cfg(unix)]
fn parent_dir(path: &std::path::Path) -> &std::path::Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
}

/// A10.41's parent-directory half of the mode rule, for a secret file at `path`.
///
/// Exposed so the binary can hold the one-shot recovery-phrase files (`--recovery-phrase-file`,
/// `--restore-seed-file`) to the seed file's `0700` directory rule without re-implementing it or
/// drifting from the diagnostics [`SeedFileStore`] already emits. The check is a refusal that
/// names the directory and the mode found; it never `chmod`s anything on the operator's behalf.
#[cfg(unix)]
pub fn check_parent_mode(path: &std::path::Path) -> Result<(), KeyStoreError> {
    let parent = parent_dir(path);
    let metadata = match std::fs::metadata(parent) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(KeyStoreError::ParentMissing {
                path: parent.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(KeyStoreError::Io {
                path: parent.to_path_buf(),
                source,
            });
        }
    };
    if !metadata.is_dir() {
        return Err(KeyStoreError::ParentMissing {
            path: parent.to_path_buf(),
        });
    }

    let mode = metadata.mode() & 0o7777;
    if mode & !0o700 != 0 {
        return Err(KeyStoreError::ParentModeTooWide {
            path: parent.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// A10.41's file half of the mode rule: `path` must carry no permission bit outside `0600`.
///
/// Exposed for the same reason as [`check_parent_mode`]. The mode is checked before any secret
/// is read, so a file that is already group/world-readable is never copied into the process
/// merely to discover that it should not have been read.
#[cfg(unix)]
pub fn check_file_mode(path: &std::path::Path) -> Result<(), KeyStoreError> {
    let metadata = std::fs::metadata(path).map_err(|source| KeyStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.mode() & 0o7777;
    if mode & !0o600 != 0 {
        return Err(KeyStoreError::SeedFileModeTooWide {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

/// `#[cfg(not(unix))]` only: A10.41(c) makes mode-bit checks meaningless here, and the seed-file
/// store itself is unsupported, so a caller reaching this function is already misconfigured.
#[cfg(not(unix))]
pub fn check_parent_mode(_path: &std::path::Path) -> Result<(), KeyStoreError> {
    Err(KeyStoreError::UnsupportedPlatform)
}

/// `#[cfg(not(unix))]` only: see [`check_parent_mode`].
#[cfg(not(unix))]
pub fn check_file_mode(_path: &std::path::Path) -> Result<(), KeyStoreError> {
    Err(KeyStoreError::UnsupportedPlatform)
}

#[cfg(not(unix))]
impl HostKeyStore for SeedFileStore {
    fn load_root_seed(&self) -> Result<[u8; ROOT_SEED_LEN], KeyStoreError> {
        Err(KeyStoreError::UnsupportedPlatform)
    }

    fn store_root_seed(&self, _seed: &[u8; ROOT_SEED_LEN]) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::UnsupportedPlatform)
    }
}

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::TempDir;

    use super::*;

    fn seed(byte: u8) -> [u8; ROOT_SEED_LEN] {
        [byte; ROOT_SEED_LEN]
    }

    /// A temp directory whose own mode is the `0700` A10.41 requires, so a test that means to
    /// test the *file* mode is not accidentally rejected because of `TempDir`'s mode instead.
    fn private_dir() -> TempDir {
        let dir = TempDir::new().expect("temp dir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        dir
    }

    fn set_mode(path: &std::path::Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn refuses_a_group_or_world_readable_seed_file() {
        let dir = private_dir();
        let path = dir.path().join("host.seed");
        fs::write(&path, seed(1)).expect("write seed");
        set_mode(&path, 0o644);

        match SeedFileStore::new(&path).load_root_seed() {
            Err(KeyStoreError::SeedFileModeTooWide { path: found, mode }) => {
                assert_eq!(found, path);
                assert_eq!(mode, 0o644);
            }
            other => panic!("expected SeedFileModeTooWide, got {other:?}"),
        }
    }

    #[test]
    fn refuses_a_group_or_world_accessible_parent_directory() {
        let dir = private_dir();
        set_mode(dir.path(), 0o755);
        let path = dir.path().join("host.seed");
        fs::write(&path, seed(2)).expect("write seed");
        set_mode(&path, 0o600);

        match SeedFileStore::new(&path).load_root_seed() {
            Err(KeyStoreError::ParentModeTooWide { path: found, mode }) => {
                // `TempDir` may canonicalize the path; compare components, not spelling.
                assert_eq!(
                    found.file_name(),
                    dir.path().file_name(),
                    "error must name the offending directory"
                );
                assert_eq!(mode, 0o755);
            }
            other => panic!("expected ParentModeTooWide, got {other:?}"),
        }
    }

    #[test]
    fn accepts_0700_parent_and_0600_seed() {
        let dir = private_dir();
        let path = dir.path().join("host.seed");
        let store = SeedFileStore::new(&path);

        store.store_root_seed(&seed(3)).expect("store seed");
        assert_eq!(store.load_root_seed().expect("load seed"), seed(3));
    }

    #[test]
    fn absent_seed_is_its_own_error_not_a_generated_fallback() {
        let dir = private_dir();
        let path = dir.path().join("missing.seed");

        match SeedFileStore::new(&path).load_root_seed() {
            Err(KeyStoreError::Absent { path: found }) => assert_eq!(found, path),
            other => panic!("expected Absent, got {other:?}"),
        }
        assert!(
            !path.exists(),
            "a failed load must not create a seed file as a fallback"
        );
    }

    #[test]
    fn seeded_file_round_trips_exactly() {
        let dir = private_dir();
        let path = dir.path().join("host.seed");
        let expected = seed(4);
        SeedFileStore::new(&path)
            .store_root_seed(&expected)
            .expect("store seed");

        assert_eq!(fs::read(&path).expect("read raw bytes"), expected.to_vec());
        assert_eq!(
            SeedFileStore::new(&path)
                .load_root_seed()
                .expect("load seed"),
            expected
        );
    }

    #[test]
    fn wrong_length_file_is_rejected() {
        let dir = private_dir();
        let path = dir.path().join("short.seed");
        fs::write(&path, [0u8; ROOT_SEED_LEN - 1]).expect("write short seed");
        set_mode(&path, 0o600);

        match SeedFileStore::new(&path).load_root_seed() {
            Err(KeyStoreError::WrongLength { len, expected, .. }) => {
                assert_eq!(len, ROOT_SEED_LEN - 1);
                assert_eq!(expected, ROOT_SEED_LEN);
            }
            other => panic!("expected WrongLength, got {other:?}"),
        }
    }

    #[test]
    fn a_second_store_refuses_to_overwrite_the_first_seed() {
        let dir = private_dir();
        let path = dir.path().join("host.seed");
        SeedFileStore::new(&path)
            .store_root_seed(&seed(5))
            .expect("first store");

        match SeedFileStore::new(&path).store_root_seed(&seed(6)) {
            Err(KeyStoreError::AlreadyExists { path: found }) => assert_eq!(found, path),
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        assert_eq!(
            SeedFileStore::new(&path)
                .load_root_seed()
                .expect("original seed survives"),
            seed(5)
        );
    }

    #[test]
    fn a_preexisting_0600_file_loads() {
        let dir = private_dir();
        let path = dir.path().join("host.seed");
        let expected = seed(7);
        fs::write(&path, expected).expect("write seed");
        set_mode(&path, 0o600);

        assert_eq!(
            SeedFileStore::new(&path)
                .load_root_seed()
                .expect("load seed"),
            expected
        );
    }

    #[test]
    fn a_missing_parent_directory_is_refused() {
        let dir = private_dir();
        let missing = dir.path().join("not-a-directory");
        let path = missing.join("host.seed");

        match SeedFileStore::new(&path).load_root_seed() {
            Err(KeyStoreError::ParentMissing { .. }) => {}
            other => panic!("expected ParentMissing, got {other:?}"),
        }
    }
}
