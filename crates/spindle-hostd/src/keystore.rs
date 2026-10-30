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
//!
//! # Descriptor-based checks close the substitution window
//!
//! A10.41's mode rule stays exactly as specified; this store enforces it on a descriptor rather
//! than on the path. Statting a path and then re-opening it for reading is two independent
//! resolutions of the same name, so the entry can be swapped between the check and the read. The
//! parent directory is opened once (`O_NOFOLLOW`), `fstat`ed, and the seed is opened *through that
//! descriptor* (`openat`); both the seed and its parent must also be owned by the calling effective
//! uid. Without the ownership half, an attacker with write access to a non-sticky, group-writable
//! ancestor could rename the `0700` directory and substitute their own `0700` directory holding a
//! `0600` seed of their choosing: the mode checks would pass and the host would load an
//! attacker-chosen root. Ownership is the fact such a substitution cannot forge, so a mismatched
//! uid is a refusal ([`KeyStoreError::NotOwned`]), never a correction.
//!
//! The same discipline backs the binary's one-shot recovery-phrase files through
//! [`open_secret_file`] and [`create_secret_file`]: a check followed by a separate
//! `read_to_string(path)`/`open(path)` would leave the identical window open.

use std::path::PathBuf;

use thiserror::Error;

#[cfg(unix)]
use rustix::fs::{fstat, openat, Mode, OFlags};
#[cfg(unix)]
use rustix::io::Errno;
#[cfg(unix)]
use std::io::{Read as _, Write as _};

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
/// Error messages name the path and, for mode failures, the octal mode found (or, for ownership
/// failures, the uid found), because DESIGN.md A10.41 requires a refusal to be diagnosable — an
/// operator has to be able to see which entry is wrong and why, rather than guess after a bare
/// "permission denied".
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

    /// The parent directory is wider than the required `0700`. Also returned for the one-shot
    /// recovery-phrase files ([`open_secret_file`]/[`create_secret_file`]), whose directory is
    /// held to the same rule.
    #[error(
        "directory {} has mode 0o{:o}, wider than the required 0o700; refusing to use it rather \
         than silently correcting it, since the secret it holds may already have been read",
        .path.display(),
        mode
    )]
    ParentModeTooWide { path: PathBuf, mode: u32 },

    /// The secret file is wider than the required `0600`. Also returned for the one-shot
    /// recovery-phrase files ([`open_secret_file`]/[`create_secret_file`]), which are held to the
    /// same rule as the seed file.
    #[error(
        "file {} has mode 0o{:o}, wider than the required 0o600; refusing to read it rather than \
         silently correcting it, since the secret may already have been read",
        .path.display(),
        mode
    )]
    SeedFileModeTooWide { path: PathBuf, mode: u32 },

    /// The seed file or its parent directory belongs to a uid other than this process's effective
    /// uid.
    ///
    /// A10.41's mode rule is the normative requirement; this ownership check is hardening around
    /// it, because a `0700` directory and a `0600` file say nothing about *who* owns them. An
    /// entry owned by another account is one this host cannot trust regardless of its mode — see
    /// this module's "substitution window" section.
    #[error(
        "{} is owned by uid {uid}, not the user running the host; refusing to use an entry \
         another account controls, whatever its mode says",
        .path.display()
    )]
    NotOwned { path: PathBuf, uid: u32 },

    /// A symbolic link was found where the seed file or its parent directory was expected.
    ///
    /// A dedicated variant rather than [`KeyStoreError::Io`] carrying `ELOOP`: "too many levels of
    /// symbolic links" names neither the entry nor the policy, and this is a refusal an operator
    /// may need to act on. Naming the path and the rule is the difference between a diagnosis and
    /// a puzzle. Some BSDs report `EMLINK` from `O_NOFOLLOW` instead of `ELOOP`, so both map here.
    #[error(
        "{} is a symbolic link; the host seed file and its parent directory must be real entries, \
         not links",
        .path.display()
    )]
    SymlinkRefused { path: PathBuf },

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
/// Construction is infallible; the mode, owner, and link checks run on every load and store, so a
/// directory whose permissions get widened while the host is running is caught on the next read
/// rather than trusted from a check done once at start-up.
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
        // One descriptor for the directory, and the seed opened relative to it: the directory
        // whose mode and owner were checked is the directory the seed is read from. Statting a
        // path and then re-opening it (the previous implementation) left a window in which the
        // name could be re-pointed at a different entry.
        let dir = open_private_dir(parent_dir(&self.path))?;
        let fd = match openat(
            &dir,
            secret_file_name(&self.path)?,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => {
                return Err(KeyStoreError::Absent {
                    path: self.path.clone(),
                });
            }
            Err(Errno::LOOP) | Err(Errno::MLINK) => {
                return Err(KeyStoreError::SymlinkRefused {
                    path: self.path.clone(),
                });
            }
            Err(errno) => {
                return Err(KeyStoreError::Io {
                    path: self.path.clone(),
                    source: errno.into(),
                });
            }
        };

        // Both checks read the descriptor the bytes will be read from, and both run before a
        // single seed byte is copied into this process.
        let stat = check_secret_fd(&self.path, &fd)?;

        // The length comes from the same descriptor, so it is the length the read below is
        // bounded by; `read_exact` refuses a file that shrank after the `fstat`.
        let len = usize::try_from(stat.st_size).unwrap_or(usize::MAX);
        if len != ROOT_SEED_LEN {
            return Err(KeyStoreError::WrongLength {
                path: self.path.clone(),
                len,
                expected: ROOT_SEED_LEN,
            });
        }
        let mut file = std::fs::File::from(fd);
        let mut seed = [0u8; ROOT_SEED_LEN];
        file.read_exact(&mut seed)
            .map_err(|source| KeyStoreError::Io {
                path: self.path.clone(),
                source,
            })?;
        Ok(seed)
    }

    fn store_root_seed(&self, seed: &[u8; ROOT_SEED_LEN]) -> Result<(), KeyStoreError> {
        let dir = open_private_dir(parent_dir(&self.path))?;

        // `O_EXCL` is the enforcement of "never overwrite a seed": it is atomic in the
        // filesystem, so two concurrent first runs cannot both believe they won the race and
        // silently replace one another's `host_fp`. POSIX `O_CREAT | O_EXCL` refuses a
        // pre-existing symbolic link as `EEXIST` — without following it — so that refusal
        // surfaces as `AlreadyExists`; `O_NOFOLLOW` guarantees no descriptor can ever name a
        // link's target. `Mode::from_bits_truncate(0o600)` is the requested permission; the
        // process umask may narrow it further, which is fine — narrower is never "wider".
        let fd = match openat(
            &dir,
            secret_file_name(&self.path)?,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(fd) => fd,
            Err(Errno::EXIST) => {
                return Err(KeyStoreError::AlreadyExists {
                    path: self.path.clone(),
                });
            }
            Err(Errno::LOOP) | Err(Errno::MLINK) => {
                return Err(KeyStoreError::SymlinkRefused {
                    path: self.path.clone(),
                });
            }
            Err(errno) => {
                return Err(KeyStoreError::Io {
                    path: self.path.clone(),
                    source: errno.into(),
                });
            }
        };

        // Confirm on the descriptor that the entry just created belongs to this process before
        // writing the secret into it. `O_EXCL` makes a foreign pre-existing entry impossible on a
        // well-behaved filesystem; the check is here so that a directory or file server that
        // reports a different owner is a refusal, not a write.
        let stat = fstat(&fd).map_err(|errno| KeyStoreError::Io {
            path: self.path.clone(),
            source: errno.into(),
        })?;
        check_owner(&self.path, stat.st_uid)?;

        let mut file = std::fs::File::from(fd);
        file.write_all(seed).map_err(|source| KeyStoreError::Io {
            path: self.path.clone(),
            source,
        })
    }
}

/// The directory `path` lives in. A bare relative file name has an empty parent; treat that as
/// the current directory rather than opening an empty path.
#[cfg(unix)]
fn parent_dir(path: &std::path::Path) -> &std::path::Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."))
}

/// Opens `dir` and applies A10.41's parent-directory half of the mode rule (at most `0700`) to
/// the descriptor it returns, together with this module's ownership hardening.
///
/// Returning the descriptor rather than dropping it lets callers open the secret *through* it
/// (`openat`): the directory that passed the check is the directory the secret is read from or
/// created in, with no window in which the path could be re-pointed. `NOFOLLOW` refuses a final
/// component that is a symbolic link. The mode and uid are read from the descriptor, never from
/// a separate path lookup.
#[cfg(unix)]
fn open_private_dir(dir: &std::path::Path) -> Result<rustix::fd::OwnedFd, KeyStoreError> {
    let fd = match rustix::fs::open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            return Err(KeyStoreError::ParentMissing {
                path: dir.to_path_buf(),
            });
        }
        Err(Errno::NOTDIR) => {
            // `O_DIRECTORY` reports a final component that is a link to a directory as `ENOTDIR`
            // on some kernels instead of `ELOOP`. The refusal is already decided; this read-only
            // `lstat` only picks the diagnostic, never the outcome.
            let is_link = std::fs::symlink_metadata(dir)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false);
            return Err(if is_link {
                KeyStoreError::SymlinkRefused {
                    path: dir.to_path_buf(),
                }
            } else {
                KeyStoreError::ParentMissing {
                    path: dir.to_path_buf(),
                }
            });
        }
        Err(Errno::LOOP) | Err(Errno::MLINK) => {
            return Err(KeyStoreError::SymlinkRefused {
                path: dir.to_path_buf(),
            });
        }
        Err(errno) => {
            return Err(KeyStoreError::Io {
                path: dir.to_path_buf(),
                source: errno.into(),
            });
        }
    };

    let stat = fstat(&fd).map_err(|errno| KeyStoreError::Io {
        path: dir.to_path_buf(),
        source: errno.into(),
    })?;
    // `st_mode` is `u16` on some targets and `u32` on others; the diagnostic field is `u32`.
    let mode = (stat.st_mode & 0o7777) as u32;
    if mode & !0o700 != 0 {
        return Err(KeyStoreError::ParentModeTooWide {
            path: dir.to_path_buf(),
            mode,
        });
    }
    check_owner(dir, stat.st_uid)?;
    Ok(fd)
}

/// The final component of `path`, i.e. the name `openat` resolves inside the checked parent
/// directory.
#[cfg(unix)]
fn secret_file_name(path: &std::path::Path) -> Result<&std::ffi::OsStr, KeyStoreError> {
    path.file_name().ok_or_else(|| KeyStoreError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "seed path has no final component to open",
        ),
    })
}

/// This module's ownership half of the hardening: the seed and the directory holding it must
/// belong to the calling effective uid.
///
/// `uid` is a parameter rather than read here so the refusal can be exercised without root; the
/// production call sites pass the `st_uid` of the descriptor they are about to use.
#[cfg(unix)]
fn check_owner(path: &std::path::Path, uid: u32) -> Result<(), KeyStoreError> {
    if uid != rustix::process::geteuid().as_raw() {
        return Err(KeyStoreError::NotOwned {
            path: path.to_path_buf(),
            uid,
        });
    }
    Ok(())
}

/// Applies A10.41's file half of the mode rule — no permission bit outside `0600` — and this
/// module's ownership rule to an already-open secret descriptor, returning its `fstat`.
///
/// Reading the checks off the descriptor is what makes them describe the object that will
/// actually be read. The mode check runs before any secret byte is copied into the process, so a
/// file that is already group/world-readable is never read merely to discover that it should not
/// have been. `st_mode` carries file-type bits as well; they are masked off before comparing.
#[cfg(unix)]
fn check_secret_fd(
    path: &std::path::Path,
    fd: &rustix::fd::OwnedFd,
) -> Result<rustix::fs::Stat, KeyStoreError> {
    let stat = fstat(fd).map_err(|errno| KeyStoreError::Io {
        path: path.to_path_buf(),
        source: errno.into(),
    })?;
    let mode = (stat.st_mode & 0o7777) as u32;
    if mode & !0o600 != 0 {
        return Err(KeyStoreError::SeedFileModeTooWide {
            path: path.to_path_buf(),
            mode,
        });
    }
    check_owner(path, stat.st_uid)?;
    Ok(stat)
}

/// Opens a one-shot secret file (the recovery-phrase and restore-phrase files) for reading under
/// the same descriptor discipline as the seed: the parent is opened and checked once
/// ([`open_private_dir`]), the entry is opened *through that descriptor* (`openat`, `O_NOFOLLOW`),
/// and [`check_secret_fd`] applies the `0600` mode and ownership rules to the descriptor the bytes
/// will come from.
///
/// This exists because the binary target is a separate crate from this library: its previous
/// `check_parent_mode` + `check_file_mode` + `read_to_string(path)` sequence resolved the name
/// three times, leaving the same substitution window `SeedFileStore` closes. The caller reads
/// through the returned handle (or converts it to text), never by path.
///
/// Errors keep the phrase path's existing variants: a missing parent is
/// [`KeyStoreError::ParentMissing`], a wide parent [`KeyStoreError::ParentModeTooWide`], a
/// symlinked entry [`KeyStoreError::SymlinkRefused`], a wide or foreign-owned file
/// [`KeyStoreError::SeedFileModeTooWide`]/[`KeyStoreError::NotOwned`], and every other failure
/// [`KeyStoreError::Io`].
#[cfg(unix)]
pub fn open_secret_file(path: &std::path::Path) -> Result<std::fs::File, KeyStoreError> {
    let dir = open_private_dir(parent_dir(path))?;
    let fd = match openat(
        &dir,
        secret_file_name(path)?,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::LOOP) | Err(Errno::MLINK) => {
            return Err(KeyStoreError::SymlinkRefused {
                path: path.to_path_buf(),
            });
        }
        Err(errno) => {
            return Err(KeyStoreError::Io {
                path: path.to_path_buf(),
                source: errno.into(),
            });
        }
    };
    check_secret_fd(path, &fd)?;
    Ok(std::fs::File::from(fd))
}

/// Creates a new one-shot secret file (the recovery-phrase and restore-phrase files) under the
/// same descriptor discipline as the seed: a checked parent descriptor, then
/// `openat(O_CREAT | O_EXCL | O_NOFOLLOW, 0600)` relative to it, then an ownership check on the
/// descriptor that will be written through.
///
/// `O_EXCL` preserves the existing "never overwrite an existing phrase file" behaviour; on a
/// well-behaved filesystem it also refuses a pre-existing symbolic link at the name without
/// following it. That refusal is reported as [`KeyStoreError::Io`] with `EEXIST` — the variant and
/// message the path-based `create_new` produced — because this helper is shared with the restore
/// phrase file, for which [`KeyStoreError::AlreadyExists`]'s "host seed file" wording would be
/// wrong.
#[cfg(unix)]
pub fn create_secret_file(path: &std::path::Path) -> Result<std::fs::File, KeyStoreError> {
    let dir = open_private_dir(parent_dir(path))?;
    let fd = match openat(
        &dir,
        secret_file_name(path)?,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    ) {
        Ok(fd) => fd,
        // `O_EXCL` reports a pre-existing entry, including a symlink, as `EEXIST`; the
        // `Io(AlreadyExists)` diagnostic is exactly what the path-based `create_new` produced.
        Err(errno) => {
            return Err(KeyStoreError::Io {
                path: path.to_path_buf(),
                source: errno.into(),
            });
        }
    };

    let stat = fstat(&fd).map_err(|errno| KeyStoreError::Io {
        path: path.to_path_buf(),
        source: errno.into(),
    })?;
    check_owner(path, stat.st_uid)?;
    Ok(std::fs::File::from(fd))
}

/// A10.41's parent-directory half of the mode rule, for a secret file at `path`.
///
/// Retained for callers that only need to *check* a directory; it is not used by the I/O paths.
/// The binary's one-shot recovery-phrase files (`--recovery-phrase-file`, `--restore-seed-file`)
/// go through [`open_secret_file`]/[`create_secret_file`], which open and check the directory once
/// and then open the entry relative to that descriptor — a `check` followed by a separate
/// `open(path)` would reintroduce the substitution window. The check is a refusal that names the
/// directory and the mode found; it never `chmod`s anything on the operator's behalf. It opens the
/// directory (refusing a symlinked final component) and reads the mode and owner from that
/// descriptor, so the answer describes the entry the kernel resolved.
#[cfg(unix)]
pub fn check_parent_mode(path: &std::path::Path) -> Result<(), KeyStoreError> {
    open_private_dir(parent_dir(path)).map(drop)
}

/// A10.41's file half of the mode rule: `path` must carry no permission bit outside `0600` and
/// must belong to the calling effective uid.
///
/// Retained for callers that only need to *check* a file, mirroring [`check_parent_mode`]; the
/// I/O paths use [`open_secret_file`]. The file is opened `O_NOFOLLOW` and the mode and owner are
/// read from that descriptor, before any secret is read, so a file that is already
/// group/world-readable is never copied into the process merely to discover that it should not
/// have been read.
#[cfg(unix)]
pub fn check_file_mode(path: &std::path::Path) -> Result<(), KeyStoreError> {
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::LOOP) | Err(Errno::MLINK) => {
            return Err(KeyStoreError::SymlinkRefused {
                path: path.to_path_buf(),
            });
        }
        Err(errno) => {
            return Err(KeyStoreError::Io {
                path: path.to_path_buf(),
                source: errno.into(),
            });
        }
    };
    check_secret_fd(path, &fd).map(drop)
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

    /// The seed file itself is a link. A `0600` link target (and a private parent) would pass
    /// every mode check, so `O_NOFOLLOW` is what refuses it — and the diagnostic names the link,
    /// not the target.
    #[test]
    fn refuses_a_symlinked_seed_file() {
        let dir = private_dir();
        let target = dir.path().join("elsewhere.seed");
        fs::write(&target, seed(8)).expect("write link target");
        set_mode(&target, 0o600);
        let link = dir.path().join("host.seed");
        std::os::unix::fs::symlink(&target, &link).expect("symlink seed file");

        match SeedFileStore::new(&link).load_root_seed() {
            Err(KeyStoreError::SymlinkRefused { path: found }) => assert_eq!(found, link),
            other => panic!("expected SymlinkRefused, got {other:?}"),
        }
    }

    /// The substitution attack: the seed's parent is a link to a directory that would pass the
    /// `0700` and ownership checks. Opening the parent with `O_NOFOLLOW` (rather than following
    /// it) refuses before the seed is ever named.
    #[test]
    fn refuses_a_symlinked_parent_directory() {
        let dir = private_dir();
        let real = dir.path().join("real");
        fs::create_dir(&real).expect("create real seed directory");
        set_mode(&real, 0o700);
        let path = real.join("host.seed");
        fs::write(&path, seed(9)).expect("write seed");
        set_mode(&path, 0o600);
        let link = dir.path().join("linked");
        std::os::unix::fs::symlink(&real, &link).expect("symlink parent");

        match SeedFileStore::new(link.join("host.seed")).load_root_seed() {
            Err(KeyStoreError::SymlinkRefused { path: found }) => assert_eq!(found, link),
            other => panic!("expected SymlinkRefused, got {other:?}"),
        }
    }

    /// A pre-existing symlink at the seed path must not be written through, and must not be
    /// replaced: `O_CREAT | O_EXCL` refuses it atomically as `EEXIST` (surfaced as
    /// `AlreadyExists`), and the target keeps its bytes.
    #[test]
    fn store_refuses_a_preexisting_symlink() {
        let dir = private_dir();
        let target = dir.path().join("target.seed");
        fs::write(&target, seed(10)).expect("write link target");
        set_mode(&target, 0o600);
        let link = dir.path().join("host.seed");
        std::os::unix::fs::symlink(&target, &link).expect("symlink seed file");

        match SeedFileStore::new(&link).store_root_seed(&seed(11)) {
            Err(KeyStoreError::AlreadyExists { path: found }) => assert_eq!(found, link),
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        assert_eq!(
            fs::read(&target).expect("link target is untouched"),
            seed(10).to_vec()
        );
        assert_eq!(
            fs::read_link(&link).expect("the link itself survives"),
            target
        );
    }

    /// Unit coverage for the ownership refusal at the helper boundary. The helper takes the uid
    /// as an argument precisely so this runs as an ordinary user; the live case — a real seed
    /// file whose `st_uid` differs from the caller's — needs `chown` and is the root-gated test
    /// below.
    #[test]
    fn ownership_check_names_the_foreign_uid() {
        let dir = private_dir();
        let path = dir.path().join("host.seed");
        fs::write(&path, seed(12)).expect("write seed");
        set_mode(&path, 0o600);

        let euid = rustix::process::geteuid().as_raw();
        check_owner(&path, euid).expect("the test process owns the file it just created");

        let foreign = euid.wrapping_add(1);
        match check_owner(&path, foreign) {
            Err(KeyStoreError::NotOwned { path: found, uid }) => {
                assert_eq!(found, path);
                assert_eq!(uid, foreign);
            }
            other => panic!("expected NotOwned, got {other:?}"),
        }
    }

    /// The live counterpart of [`ownership_check_names_the_foreign_uid`]: a real `0600` seed in a
    /// private, caller-owned directory whose `st_uid` is someone else's. Only root can `chown`
    /// a file to another uid, so this is gated on `TEST_RUN_AS_ROOT`; without that variable it
    /// returns immediately rather than pretending to have exercised the path. The descriptor
    /// plumbing that supplies `st_uid` is exercised by every other test here.
    #[test]
    fn refuses_a_seed_file_owned_by_another_uid_when_running_as_root() {
        if std::env::var_os("TEST_RUN_AS_ROOT").is_none() {
            return;
        }
        let dir = private_dir();
        let path = dir.path().join("host.seed");
        fs::write(&path, seed(13)).expect("write seed");
        set_mode(&path, 0o600);

        let foreign = rustix::process::geteuid().as_raw().wrapping_add(1);
        rustix::fs::chown(&path, Some(rustix::process::Uid::from_raw(foreign)), None)
            .expect("chown requires root");

        match SeedFileStore::new(&path).load_root_seed() {
            Err(KeyStoreError::NotOwned { path: found, uid }) => {
                assert_eq!(found, path);
                assert_eq!(uid, foreign);
            }
            other => panic!("expected NotOwned, got {other:?}"),
        }
    }
}
