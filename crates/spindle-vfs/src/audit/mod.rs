//! The tamper-evident, hash-chained audit log (DESIGN.md §A4b "Audit log", verbatim: "`{ts,
//! member, device, action, virtual_path, bytes, outcome}` for every VFS op and every admin
//! change; hash-chained append-only with a periodically signed head (tamper-evident). `list` is
//! cursor-paged with a max page.").
//!
//! [`Audit`] borrows the *same* `rusqlite::Connection` [`crate::store::Store`] uses (via
//! [`crate::store::Store::audit`]) rather than opening a second connection to the same file — see
//! "Transaction discipline" below for why that matters.
//!
//! # Not one of the eight A7b wire artifacts
//!
//! DESIGN.md §A7b catalogs eight signed wire artifacts (Envelope, Capability, AdmissionToken,
//! DeviceCertificate, RevocationRecord, AdminCommand, HostOpKeyCert, HostDeviceCert); the audit
//! chain's signed head is not one of them — it never crosses the wire, it is a host-local
//! durability artifact only ever read back by the same host that wrote it (via
//! `Store::open`/`Audit::verify_*`). This mirrors exactly how `spindle-core`'s pre-committed
//! root-rotation record is treated (see `spindle_core::identity`'s module doc comment: "not one
//! of spindle-proto's eight A7b-cataloged wire artifact types ... this module defines its own
//! minimal domain-separated signing input inside this crate rather than adding an unauthorized
//! type to spindle-proto"). Despite being
//! crate-local, it still follows A7b's *discipline* (a distinct, versioned domain-separation tag)
//! — see below.
//!
//! # Hash chain
//!
//! Row `N`'s stored `hash = SHA-256(domain_tag || prev_hash || deterministic_encoding(entry))`,
//! where `domain_tag = b"spindle-audit-v1"` (versioned, distinct from every other domain tag in
//! this codebase — A7b discipline) and `prev_hash` is row `N-1`'s `hash` (genesis: 32 zero
//! bytes, [`GENESIS_PREV_HASH`]). The SHA-256 itself is computed via
//! `spindle_core::Fingerprint::of_parts` rather than a direct `sha2` dependency — see the crate's
//! `Cargo.toml` comment for why (this crate's dependency budget for this slice is `rusqlite`
//! only).
//!
//! **Deterministic encoding choice**: a fixed-order, length-prefixed field encoding
//! (`crate::audit::encoding`), *not* `spindle-proto`'s canonical CBOR encoder. Two reasons: (1)
//! `spindle-vfs` must not gain a dependency beyond `rusqlite` this slice (DESIGN.md §A9c's crate
//! layering already puts `spindle-proto` two hops below this crate via `spindle-core`, but it is
//! not currently a *direct* dependency, and `spindle_core` does not re-export
//! `canonical_encode`/`CborValue` — taking a direct `spindle-proto` dependency just for this would
//! be a new, budget-violating dependency edge); (2) even setting the budget aside, this is exactly
//! the same call `spindle-core` already made for its own crate-local, non-wire artifact (the
//! root-rotation record, `spindle_core::identity`'s `ROOT_ROTATION_TAG` signing input) — a
//! host-local hash-chain input has no cross-implementation interop requirement (nothing outside
//! this one host's own re-verification ever parses these bytes), so canonical CBOR's real
//! benefit — byte-identical encoding across independent Rust/TS implementations — buys nothing
//! here, while a hand-rolled length-prefixed encoding is simpler to read and audit.
//!
//! # Signed heads (`HeadSigner`)
//!
//! [`HeadSigner::sign`] is written `Vec<u8>` rather than `ed25519_dalek::Signature` — the task
//! brief describes it as "`Signature`-shaped", but `spindle-vfs` cannot name that type without
//! taking a direct `ed25519-dalek` dependency (`spindle_core` re-exports `SigningKey`/
//! `VerifyingKey` but not `Signature`, and constructing one from raw bytes needs an associated
//! function on that unreachable type). [`sign_head`]/[`Audit::verify_head`] instead use
//! `spindle_core::{sign_bytes, verify_bytes}` (added to `spindle-core` alongside this slice — see
//! that crate's `lib.rs` module doc comment — expressly so a crate depending only on
//! `spindle-core` can still produce/verify raw Ed25519 signatures). [`Audit`] never signs the raw
//! chain head hash directly: [`sign_head`] first mixes it with its own domain tag
//! (`b"spindle-audit-head-v1"`, distinct from the entry-hash tag) via
//! `Fingerprint::of_parts(&[HEAD_DOMAIN_TAG, &head_hash])` and signs *that* digest — so
//! `HeadSigner` implementors need not know about domain separation themselves; they just sign
//! whatever 32 bytes they're given.
//!
//! The `signed_heads` table stores exactly DESIGN.md's stated tuple, `{seq, head_hash, ts, sig}`
//! — deliberately **no** signer public key column (see `crate::store::schema`'s doc comment on
//! that table): [`Audit::verify_head`] takes the expected `VerifyingKey` as a parameter from the
//! caller, who holds it independently of anything in this database, so an attacker who can edit
//! rows cannot also launder a forged signature by swapping in a matching keypair.
//!
//! # Transaction discipline (DESIGN.md §A4b: no gap/fork under concurrent appends)
//!
//! [`Audit::append`] wraps the chain-head read + insert in a single SQLite transaction
//! (`BEGIN IMMEDIATE` — acquires the write lock immediately rather than on first write, closing
//! the window between "read current head" and "insert the next row" that a deferred/optimistic
//! transaction would leave open). `rusqlite::Connection::transaction()` is not used here because
//! it requires `&mut Connection`, and [`Audit`] deliberately holds only a shared `&Connection`
//! (the same one [`crate::store::Store`]'s many `&self` methods use) — manual `BEGIN
//! IMMEDIATE`/`COMMIT`/`ROLLBACK` via `Connection::execute_batch` (which takes `&self`) gives the
//! identical atomicity guarantee without that borrow conflict. Because there is exactly one
//! `rusqlite::Connection` per open database in this crate (single-writer discipline, matching
//! SQLite's own single-writer model), and Rust's aliasing rules mean at most one `&Store`/`&Audit`
//! borrow chain can be actively running a statement against it at a time within one process,
//! there is no code path in this crate that could interleave two appends even without the
//! transaction — the transaction's real job is protecting against a *future* multi-connection or
//! multi-process caller (e.g. a WAL-mode multi-connection host-core, a later slice), and against
//! partial writes on crash (an interrupted `INSERT` before `COMMIT` is rolled back entirely, never
//! leaving a row with a `hash` but no matching next `prev_hash`, or vice versa).
//!
//! # Detecting tampering: why the signed head matters beyond `verify_chain`
//!
//! [`Audit::verify_chain`] alone (recomputing every row's hash from its stored fields and
//! comparing against the stored `hash` column) catches any tampering that leaves the chain
//! *internally* inconsistent — a bit-flipped field, a swapped/reordered pair of rows, anything
//! that doesn't come with a fully-recomputed set of downstream hashes. It does **not** catch
//! truncation of the tail: deleting the last row(s) leaves a shorter chain that is still perfectly
//! self-consistent (row `N-1` no longer has anything claiming `hash(row N-1)` as its `prev_hash`,
//! but nothing requires it to). Nor does it catch a *thorough* forgery that tampers with one
//! entry and then correctly recomputes every hash from that point forward. [`Audit::verify_head`]
//! catches both: it re-derives the chain hash at the signed `seq` independently (via the same
//! `verify_chain` machinery, bounded to that `seq`) and requires it to still exist and match the
//! hash that was actually signed — a truncated or thoroughly-reforged chain diverges from what was
//! signed at that historical point, even though it might now look internally consistent on its
//! own.

mod encoding;

use rusqlite::{params, Connection, OptionalExtension, Row};
use spindle_core::{Fingerprint, FingerprintError, IdentityError, VerifyingKey};
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

/// `SHA-256(domain_tag || prev_hash || deterministic_encoding(entry))`'s domain tag for entry
/// hashing (A7b discipline: distinct, versioned).
const ENTRY_DOMAIN_TAG: &[u8] = b"spindle-audit-v1";
/// Domain tag mixed into the head hash before signing (distinct from [`ENTRY_DOMAIN_TAG`], so a
/// signature over a signed head can never be confused with — or replayed as — a signature over a
/// raw chain-entry hash).
const HEAD_DOMAIN_TAG: &[u8] = b"spindle-audit-head-v1";

/// Genesis `prev_hash`: fixed, all-zero (DESIGN.md §A4b chain design).
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// DESIGN.md §A4b: "`list` is cursor-paged with a max page." A caller-requested `page_size`
/// larger than this is silently clamped (see [`Audit::list`]) rather than rejected — this default
/// (chosen by this implementation; DESIGN.md states the requirement but not a number) is generous
/// enough for an admin UI's audit view to rarely hit it, while still bounding one query's result
/// set and memory footprint.
pub const MAX_AUDIT_PAGE_SIZE: usize = 500;

/// One audit entry's caller-supplied fields (DESIGN.md §A4b, verbatim field list). `member`/
/// `device` are `None` for host-internal admin actions with no specific member/device attached
/// (e.g. the owner acting from the local host UI, DESIGN.md §A4b "Owner live operations" —
/// nothing in that surface requires presenting a device credential the way a VFS RPC session
/// does).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub ts: u64,
    pub member: Option<Fingerprint>,
    pub device: Option<Fingerprint>,
    pub action: String,
    pub virtual_path: Option<String>,
    pub bytes: Option<u64>,
    pub outcome: String,
}

/// One persisted, chain-linked audit row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub seq: u64,
    pub entry: AuditEntry,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

/// The result of a successful [`Audit::verify_chain`] (or the internal bounded walk
/// [`Audit::verify_head`] uses): the last verified row's position and hash, or the genesis values
/// for an empty chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub seq: u64,
    pub head_hash: [u8; 32],
}

/// A periodically-signed chain head (DESIGN.md §A4b), exactly the stated tuple `{seq, head_hash,
/// ts, sig}` — see the module doc comment for why no signer public key is stored alongside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHead {
    pub seq: u64,
    pub head_hash: [u8; 32],
    pub ts: u64,
    pub sig: Vec<u8>,
}

/// One page of [`Audit::list`] results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPage {
    pub records: Vec<AuditRecord>,
    /// `Some(seq)` to pass as the next call's `cursor` if more rows exist; `None` once the
    /// caller has reached the end of the chain.
    pub next_cursor: Option<u64>,
}

/// Signs a chain head hash without `spindle-vfs` (or its callers, via this trait object) needing
/// to hand key material into this crate — "so key custody stays out of spindle-vfs" (task brief).
/// See the module doc comment for why this returns raw signature bytes rather than a named
/// `Signature` type.
pub trait HeadSigner {
    fn public_key(&self) -> VerifyingKey;
    /// Signs exactly the 32 bytes given (already domain-tag-mixed by [`sign_head`] — see the
    /// module doc comment) and returns the raw Ed25519 signature bytes.
    fn sign(&self, digest: &[u8; 32]) -> Vec<u8>;
}

/// A [`HeadSigner`] built on `spindle-core`'s Ed25519 machinery, for tests (and any other
/// in-process signer that doesn't need OS-keystore custody). Production key custody
/// (`spindle-host-core`, a later slice) implements [`HeadSigner`] over whatever holds the host's
/// real operating key instead.
pub struct TestHeadSigner {
    signing_key: spindle_core::SigningKey,
}

impl TestHeadSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        TestHeadSigner {
            signing_key: spindle_core::SigningKey::from_bytes(&seed),
        }
    }
}

impl HeadSigner for TestHeadSigner {
    fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn sign(&self, digest: &[u8; 32]) -> Vec<u8> {
        spindle_core::sign_bytes(&self.signing_key, digest)
    }
}

/// Errors from [`Audit`] operations.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("corrupt fingerprint stored in audit row {seq}: {source}")]
    CorruptFingerprint { seq: u64, source: FingerprintError },

    #[error("audit row {seq} has a malformed {field} (expected 32 bytes, got {len})")]
    CorruptHashLength {
        seq: u64,
        field: &'static str,
        len: usize,
    },

    /// A bit-flip, or any content change not accompanied by a consistent chain re-hash from that
    /// point forward.
    #[error(
        "audit chain broken at seq {seq}: recomputed hash does not match the stored hash \
         (tampered entry, or the chain was reforged inconsistently from this point)"
    )]
    ChainBroken { seq: u64 },

    /// A missing `seq` in an otherwise-ascending scan — row deletion, or (if it appears mid-scan
    /// rather than at the end) a sign that seq values were never contiguous to begin with.
    #[error(
        "audit chain has a gap: expected seq {expected}, found {found} (a row was deleted, or \
         never existed)"
    )]
    SeqGap { expected: u64, found: u64 },

    #[error(
        "audit row {seq}'s stored prev_hash does not equal the previous row's hash — the chain \
         does not actually link at this point"
    )]
    PrevHashMismatch { seq: u64 },

    #[error("no signed head recorded for seq {0}")]
    NoSignedHead(u64),

    /// The chain no longer reaches the signed `seq` at all (tail truncation after signing).
    #[error(
        "audit chain does not reach seq {seq} anymore, but a head was signed at that seq \
         (tail truncated after signing)"
    )]
    TruncatedBeforeSignedHead { seq: u64 },

    /// The chain reaches `seq`, but its hash there no longer matches what was signed — either the
    /// tail was truncated and rebuilt differently, or an earlier entry was tampered with and the
    /// whole chain re-hashed consistently from that point (a "thorough" forgery `verify_chain`
    /// alone cannot see, since it only checks internal consistency).
    #[error("audit chain at seq {seq} no longer matches the hash that was signed")]
    HeadHashMismatch { seq: u64 },

    #[error("signed head at seq {seq} failed signature verification: {source}")]
    BadHeadSignature { seq: u64, source: IdentityError },

    #[error("cannot sign an empty audit chain (nothing has been appended yet)")]
    EmptyChain,

    #[error("page_size must be greater than zero")]
    ZeroPageSize,

    /// td-c9b9bd: mirrors [`crate::store::StoreError::ConnectionPoisoned`] — see that variant's
    /// doc comment for the full mechanism and recovery contract. `Audit` and `Store` share one
    /// `rusqlite::Connection` and therefore one poison flag ([`crate::store::Store::poisoned`]),
    /// so once either side poisons it, both refuse further writes. `Audit::append` checks this
    /// before even issuing `BEGIN IMMEDIATE`, so a caller sees this variant specifically rather
    /// than whatever raw SQLite error a doomed write would otherwise produce.
    #[error(
        "audit connection poisoned: a prior ROLLBACK/COMMIT failed to return this connection to \
         autocommit mode, so appends are refused rather than risking a silent, undurable write \
         into a stranded transaction; drop the owning Store and reopen a fresh one against the \
         same file to recover"
    )]
    ConnectionPoisoned,
}

/// A borrowed view over the audit chain, backed by the same `rusqlite::Connection` as
/// [`crate::store::Store`] — obtain one via [`crate::store::Store::audit`].
pub struct Audit<'a> {
    conn: &'a Connection,
    /// A borrow of [`crate::store::Store::poisoned`] — see that field's doc comment for the full
    /// mechanism and recovery contract, and [`Audit::append`] for the only place this crate ever
    /// sets it. `Audit<'a>` is a transient, freshly-constructed-per-call view (never held across
    /// calls, never itself owning any state — see the module doc comment's "Transaction
    /// discipline" section), so it cannot hold poison state itself; it can only borrow the flag
    /// that lives on `Store`, exactly as it already borrows `Store`'s `Connection`.
    poisoned: &'a AtomicBool,
}

impl<'a> Audit<'a> {
    pub(crate) fn new(conn: &'a Connection, poisoned: &'a AtomicBool) -> Self {
        Audit { conn, poisoned }
    }

    /// Appends one entry to the chain. See the module doc comment's "Transaction discipline"
    /// section for the `BEGIN IMMEDIATE` atomicity this provides.
    ///
    /// # Poisoning (td-c9b9bd)
    ///
    /// Refuses outright with [`AuditError::ConnectionPoisoned`] if a prior call already poisoned
    /// this connection (checked before `BEGIN IMMEDIATE` is even issued, so a poisoned connection
    /// never attempts another write at all). Otherwise, if the `ROLLBACK` that unwinds a failed
    /// append — or the `COMMIT` that durably lands a successful one — itself fails, this method
    /// does not just log and hope: it checks `Connection::is_autocommit()`, the direct observable
    /// of "is this connection actually stuck inside a transaction" (a `ROLLBACK`/`COMMIT`
    /// returning `Err` and the connection actually being stranded are NOT the same fact — one can
    /// fail while the transaction still ended, and vice versa). If still not in autocommit mode,
    /// it retries `ROLLBACK` exactly once (a single deterministic recovery attempt, since a
    /// transient error should not need to brick every future write on this host); if that also
    /// fails to restore autocommit mode, it poisons the shared `Store`/`Audit` connection
    /// ([`crate::store::Store`]'s `poisoned` field, set via the reference this `Audit` borrows) so
    /// every subsequent write — from this `Audit` or from any `Store` write method sharing the
    /// same connection — fails
    /// fast with [`AuditError::ConnectionPoisoned`]/[`crate::store::StoreError::ConnectionPoisoned`]
    /// instead of silently executing inside the stranded transaction. See
    /// [`crate::store::Store::poisoned`]'s doc comment for the recovery contract (drop and reopen
    /// the `Store`).
    ///
    pub fn append(&self, entry: AuditEntry) -> Result<AuditRecord, AuditError> {
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(AuditError::ConnectionPoisoned);
        }
        if let Err(begin_error) = self.conn.execute_batch("BEGIN IMMEDIATE") {
            // A failed `BEGIN` (e.g. "cannot start a transaction within a transaction") means
            // this connection was *already* stranded before this call — by an earlier failed
            // `ROLLBACK`/`COMMIT` this method's own recovery somehow didn't reach, or by a `Store`
            // write method sharing this connection. Until this fix, this branch didn't exist at
            // all: `?` returned immediately with no recovery attempt, so a connection that reached
            // `append` already stranded (but not yet poisoned) could sit that way indefinitely.
            self.recover_from_non_autocommit("a failed BEGIN");
            return Err(AuditError::Sqlite(begin_error));
        }
        match self.append_inner(entry) {
            Ok(record) => match self.conn.execute_batch("COMMIT") {
                Ok(()) => Ok(record),
                Err(commit_error) => {
                    // The append succeeded, but its COMMIT failed: the row is not (yet, or ever)
                    // durable, and the connection may still be sitting inside the transaction
                    // that was supposed to have ended. Until 5f0fa3a/td-c9b9bd this branch did not
                    // exist at all — a failed COMMIT returned early via `?` with no rollback
                    // attempt and no log line, the same stranding as a failed append's ROLLBACK
                    // but completely silent. See `recover_from_non_autocommit` for what happens
                    // next.
                    tracing::error!(
                        %commit_error,
                        "audit COMMIT failed after a successful append; the row is not durable, \
                         and the connection may be stuck mid-transaction, so subsequent writes on \
                         it are not guaranteed durable until this is resolved"
                    );
                    self.recover_from_non_autocommit("a failed COMMIT");
                    Err(AuditError::Sqlite(commit_error))
                }
            },
            Err(e) => {
                // The append itself already failed; if the ROLLBACK meant to undo its partial
                // work *also* fails, this connection is left sitting inside an open transaction
                // that neither committed nor rolled back. `Audit` and `Store` share this one
                // connection (see the module doc comment), so every subsequent write on it then
                // executes inside that stuck transaction instead of autocommitting as its caller
                // expects: it can look like it succeeded while remaining undurable until some
                // later operation happens to COMMIT, and a crash before that silently loses it —
                // exactly the kind of inconsistency this hash-chained, tamper-evident log exists
                // to make detectable, so a human needs to know immediately, not find it later via
                // `verify_chain`.
                if let Err(rollback_error) = self.conn.execute_batch("ROLLBACK") {
                    tracing::error!(
                        %rollback_error,
                        append_error = %e,
                        "audit ROLLBACK failed after a failed append; connection may be stuck \
                         mid-transaction, so subsequent writes on it are not guaranteed durable"
                    );
                }
                self.recover_from_non_autocommit("a failed append");
                Err(e)
            }
        }
    }

    /// Thin delegation to [`crate::store::recover_from_non_autocommit`] — see that free
    /// function's doc comment for the full mechanism and recovery contract (extracted there,
    /// rather than kept here, so `Store`'s own `&self` write methods can share the identical
    /// recovery logic via `Store::with_transaction` instead of duplicating it). `context` is a
    /// short human-readable description of which of [`Audit::append`]'s failure branches called
    /// this, for the log lines only.
    fn recover_from_non_autocommit(&self, context: &'static str) {
        crate::store::recover_from_non_autocommit(self.conn, self.poisoned, context);
    }

    fn append_inner(&self, entry: AuditEntry) -> Result<AuditRecord, AuditError> {
        let prev_hash: [u8; 32] = self
            .conn
            .query_row(
                "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|v| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&v);
                a
            })
            .unwrap_or(GENESIS_PREV_HASH);

        let hash = compute_entry_hash(&prev_hash, &entry);

        self.conn.execute(
            "INSERT INTO audit_log (ts, member, device, action, virtual_path, bytes, outcome, prev_hash, hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.ts as i64,
                entry.member.map(Fingerprint::to_vec),
                entry.device.map(Fingerprint::to_vec),
                entry.action,
                entry.virtual_path,
                entry.bytes.map(|b| b as i64),
                entry.outcome,
                prev_hash.to_vec(),
                hash.to_vec(),
            ],
        )?;
        let seq = self.conn.last_insert_rowid() as u64;
        Ok(AuditRecord {
            seq,
            entry,
            prev_hash,
            hash,
        })
    }

    /// Walks the full chain from genesis, recomputing and checking every row's hash and linkage.
    /// Returns the genesis [`ChainHead`] (`seq: 0`, `head_hash: GENESIS_PREV_HASH`) for an empty
    /// chain.
    pub fn verify_chain(&self) -> Result<ChainHead, AuditError> {
        Ok(self.walk_chain(None)?.unwrap_or(ChainHead {
            seq: 0,
            head_hash: GENESIS_PREV_HASH,
        }))
    }

    /// Signs the current chain head with `signer`, storing `{seq, head_hash, ts, sig}`.
    /// `ts` is caller-supplied (this crate has no wall-clock dependency — see `crate::model`/
    /// `crate::algebra`, which take timestamps as plain parameters throughout). Fails with
    /// [`AuditError::EmptyChain`] if nothing has been appended yet.
    pub fn sign_head(&self, signer: &dyn HeadSigner, ts: u64) -> Result<SignedHead, AuditError> {
        let head = self.verify_chain()?;
        if head.seq == 0 {
            return Err(AuditError::EmptyChain);
        }
        let digest = *Fingerprint::of_parts(&[HEAD_DOMAIN_TAG, &head.head_hash]).as_bytes();
        let sig = signer.sign(&digest);
        self.conn.execute(
            "INSERT INTO signed_heads (seq, head_hash, ts, sig) VALUES (?1, ?2, ?3, ?4)",
            params![
                head.seq as i64,
                head.head_hash.to_vec(),
                ts as i64,
                sig.clone()
            ],
        )?;
        Ok(SignedHead {
            seq: head.seq,
            head_hash: head.head_hash,
            ts,
            sig,
        })
    }

    /// Verifies the signed head at `seq` against `expected_pk` (supplied by the caller — see the
    /// module doc comment for why this database never stores the signer's public key itself):
    /// 1. The chain still reaches `seq` at all (catches tail truncation).
    /// 2. The chain's hash at `seq`, independently recomputed from genesis, still matches the
    ///    hash that was actually signed (catches truncation-and-rebuild or a thorough forgery).
    /// 3. The stored signature verifies under `expected_pk` over the same domain-tagged digest
    ///    [`sign_head`] produced.
    pub fn verify_head(&self, seq: u64, expected_pk: &VerifyingKey) -> Result<(), AuditError> {
        let (stored_head_hash, sig): (Vec<u8>, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT head_hash, sig FROM signed_heads WHERE seq = ?1",
                params![seq as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(AuditError::NoSignedHead(seq))?;
        if stored_head_hash.len() != 32 {
            return Err(AuditError::CorruptHashLength {
                seq,
                field: "signed_heads.head_hash",
                len: stored_head_hash.len(),
            });
        }
        let mut stored_head_hash_arr = [0u8; 32];
        stored_head_hash_arr.copy_from_slice(&stored_head_hash);

        let walked = self
            .walk_chain(Some(seq))?
            .filter(|h| h.seq == seq)
            .ok_or(AuditError::TruncatedBeforeSignedHead { seq })?;

        if walked.head_hash != stored_head_hash_arr {
            return Err(AuditError::HeadHashMismatch { seq });
        }

        let digest = *Fingerprint::of_parts(&[HEAD_DOMAIN_TAG, &stored_head_hash_arr]).as_bytes();
        spindle_core::verify_bytes(expected_pk, &digest, &sig)
            .map_err(|source| AuditError::BadHeadSignature { seq, source })?;
        Ok(())
    }

    /// Cursor-paged listing (DESIGN.md §A4b: "`list` is cursor-paged with a max page"). `cursor`
    /// is the last `seq` already seen (`None` for the first page); `page_size` is clamped to
    /// [`MAX_AUDIT_PAGE_SIZE`]. `next_cursor` is `Some` iff at least one more row exists beyond
    /// this page (determined by fetching one extra row, not by a same-size-page heuristic, so a
    /// page landing exactly on the last row correctly reports `next_cursor: None`).
    pub fn list(&self, cursor: Option<u64>, page_size: usize) -> Result<AuditPage, AuditError> {
        if page_size == 0 {
            return Err(AuditError::ZeroPageSize);
        }
        let effective = page_size.min(MAX_AUDIT_PAGE_SIZE);
        let after = cursor.unwrap_or(0) as i64;
        let fetch_limit = (effective + 1) as i64;

        let mut stmt = self.conn.prepare(
            "SELECT seq, ts, member, device, action, virtual_path, bytes, outcome, prev_hash, hash \
             FROM audit_log WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2",
        )?;
        let raw_rows: Vec<RawRow> = stmt
            .query_map(params![after, fetch_limit], row_to_raw)?
            .collect::<rusqlite::Result<_>>()?;

        let mut records: Vec<AuditRecord> = raw_rows
            .into_iter()
            .map(raw_to_record)
            .collect::<Result<_, _>>()?;

        let next_cursor = if records.len() > effective {
            records.truncate(effective);
            records.last().map(|r| r.seq)
        } else {
            None
        };
        Ok(AuditPage {
            records,
            next_cursor,
        })
    }

    /// Walks rows in ascending `seq` order (optionally bounded to `seq <= limit`), verifying
    /// linkage and hashes as it goes, returning the last verified row's [`ChainHead`] (`None` for
    /// an empty result set). Shared by [`Audit::verify_chain`] (unbounded) and
    /// [`Audit::verify_head`] (bounded to the signed `seq`, so a truncated tail is detected as
    /// "the walk never reaches `seq`" rather than by scanning the whole (possibly huge) chain).
    fn walk_chain(&self, limit: Option<u64>) -> Result<Option<ChainHead>, AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, ts, member, device, action, virtual_path, bytes, outcome, prev_hash, hash \
             FROM audit_log WHERE (?1 IS NULL OR seq <= ?1) ORDER BY seq ASC",
        )?;
        let limit_param = limit.map(|v| v as i64);
        let raw_rows: Vec<RawRow> = stmt
            .query_map(params![limit_param], row_to_raw)?
            .collect::<rusqlite::Result<_>>()?;

        let mut expected_prev = GENESIS_PREV_HASH;
        let mut head: Option<ChainHead> = None;
        for (expected_seq, raw) in (1u64..).zip(raw_rows) {
            let record = raw_to_record(raw)?;
            if record.seq != expected_seq {
                return Err(AuditError::SeqGap {
                    expected: expected_seq,
                    found: record.seq,
                });
            }
            if record.prev_hash != expected_prev {
                return Err(AuditError::PrevHashMismatch { seq: record.seq });
            }
            let recomputed = compute_entry_hash(&expected_prev, &record.entry);
            if recomputed != record.hash {
                return Err(AuditError::ChainBroken { seq: record.seq });
            }
            expected_prev = record.hash;
            head = Some(ChainHead {
                seq: record.seq,
                head_hash: record.hash,
            });
        }
        Ok(head)
    }
}

fn compute_entry_hash(prev_hash: &[u8; 32], entry: &AuditEntry) -> [u8; 32] {
    let encoded = encoding::encode_entry(entry);
    *Fingerprint::of_parts(&[ENTRY_DOMAIN_TAG, prev_hash, &encoded]).as_bytes()
}

/// Raw SQL-layer row, before fallible [`Fingerprint`]/hash-length parsing — kept separate from
/// [`AuditRecord`] so `rusqlite`'s row-mapping closure (which must return `rusqlite::Result`) never
/// needs to smuggle an [`AuditError`] through it; parsing happens in [`raw_to_record`] instead,
/// where the full `AuditError` type is available.
struct RawRow {
    seq: i64,
    ts: i64,
    member: Option<Vec<u8>>,
    device: Option<Vec<u8>>,
    action: String,
    virtual_path: Option<String>,
    bytes: Option<i64>,
    outcome: String,
    prev_hash: Vec<u8>,
    hash: Vec<u8>,
}

fn row_to_raw(row: &Row) -> rusqlite::Result<RawRow> {
    Ok(RawRow {
        seq: row.get(0)?,
        ts: row.get(1)?,
        member: row.get(2)?,
        device: row.get(3)?,
        action: row.get(4)?,
        virtual_path: row.get(5)?,
        bytes: row.get(6)?,
        outcome: row.get(7)?,
        prev_hash: row.get(8)?,
        hash: row.get(9)?,
    })
}

fn raw_to_record(raw: RawRow) -> Result<AuditRecord, AuditError> {
    let seq = raw.seq as u64;
    let member = raw
        .member
        .map(|b| Fingerprint::from_slice(&b))
        .transpose()
        .map_err(|source| AuditError::CorruptFingerprint { seq, source })?;
    let device = raw
        .device
        .map(|b| Fingerprint::from_slice(&b))
        .transpose()
        .map_err(|source| AuditError::CorruptFingerprint { seq, source })?;

    if raw.prev_hash.len() != 32 {
        return Err(AuditError::CorruptHashLength {
            seq,
            field: "prev_hash",
            len: raw.prev_hash.len(),
        });
    }
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&raw.prev_hash);

    if raw.hash.len() != 32 {
        return Err(AuditError::CorruptHashLength {
            seq,
            field: "hash",
            len: raw.hash.len(),
        });
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&raw.hash);

    Ok(AuditRecord {
        seq,
        entry: AuditEntry {
            ts: raw.ts as u64,
            member,
            device,
            action: raw.action,
            virtual_path: raw.virtual_path,
            bytes: raw.bytes.map(|b| b as u64),
            outcome: raw.outcome,
        },
        prev_hash,
        hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn entry(action: &str) -> AuditEntry {
        AuditEntry {
            ts: 1,
            member: Some(Fingerprint::of_parts(&[b"alex"])),
            device: Some(Fingerprint::of_parts(&[b"alex-laptop"])),
            action: action.to_string(),
            virtual_path: Some("Photos/img.jpg".to_string()),
            bytes: Some(1234),
            outcome: "ok".to_string(),
        }
    }

    // ---- Empty chain ----

    #[test]
    fn empty_chain_verifies_to_genesis() {
        let store = Store::open_in_memory().expect("open");
        let head = store.audit().verify_chain().expect("verify empty chain");
        assert_eq!(
            head,
            ChainHead {
                seq: 0,
                head_hash: GENESIS_PREV_HASH
            }
        );
    }

    #[test]
    fn cannot_sign_empty_chain() {
        let store = Store::open_in_memory().expect("open");
        let signer = TestHeadSigner::from_seed([1; 32]);
        let err = store.audit().sign_head(&signer, 100).unwrap_err();
        assert!(matches!(err, AuditError::EmptyChain));
    }

    // ---- Append + verify round trip ----

    #[test]
    fn append_and_verify_round_trip() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        let a = audit.append(entry("list")).expect("append a");
        let b = audit.append(entry("read")).expect("append b");
        let c = audit.append(entry("upload")).expect("append c");

        assert_eq!(a.seq, 1);
        assert_eq!(a.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(b.prev_hash, a.hash);
        assert_eq!(c.prev_hash, b.hash);

        let head = audit.verify_chain().expect("verify");
        assert_eq!(
            head,
            ChainHead {
                seq: 3,
                head_hash: c.hash
            }
        );
    }

    #[test]
    fn append_verify_round_trip_across_reopen() {
        let sandbox = tempfile::tempdir().expect("tempdir");
        let db_path = sandbox.path().join("audit.sqlite3");
        let signer = TestHeadSigner::from_seed([7; 32]);

        let (seq, signed) = {
            let store = Store::open(&db_path).expect("open");
            let audit = store.audit();
            audit.append(entry("list")).expect("append a");
            audit.append(entry("read")).expect("append b");
            let signed = audit.sign_head(&signer, 500).expect("sign_head");
            (signed.seq, signed)
        };

        let store = Store::open(&db_path).expect("reopen");
        let audit = store.audit();
        let head = audit.verify_chain().expect("verify after reopen");
        assert_eq!(head.seq, seq);
        assert_eq!(head.head_hash, signed.head_hash);
        audit
            .verify_head(seq, &signer.public_key())
            .expect("verify_head after reopen");
    }

    // ---- Paging ----

    #[test]
    fn list_pages_with_boundary_correctness() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        for i in 0..5 {
            audit.append(entry(&format!("op-{i}"))).expect("append");
        }

        let page1 = audit.list(None, 2).expect("page1");
        assert_eq!(
            page1.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(page1.next_cursor, Some(2));

        let page2 = audit.list(page1.next_cursor, 2).expect("page2");
        assert_eq!(
            page2.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(page2.next_cursor, Some(4));

        let page3 = audit.list(page2.next_cursor, 2).expect("page3");
        assert_eq!(
            page3.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![5]
        );
        assert_eq!(
            page3.next_cursor, None,
            "landing exactly on the last row must not claim more"
        );

        // `page3.next_cursor` is correctly `None` (nothing more to fetch) — querying again with
        // that would restart from the beginning (`None` means "first page"), not test "past the
        // end". Use the last real seq explicitly as the cursor to exercise that case.
        let page4 = audit.list(Some(5), 2).expect("page4 (explicitly past end)");
        assert!(page4.records.is_empty());
        assert_eq!(page4.next_cursor, None);
    }

    #[test]
    fn list_rejects_zero_page_size() {
        let store = Store::open_in_memory().expect("open");
        let err = store.audit().list(None, 0).unwrap_err();
        assert!(matches!(err, AuditError::ZeroPageSize));
    }

    #[test]
    fn list_clamps_page_size_to_max() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        for i in 0..3 {
            audit.append(entry(&format!("op-{i}"))).expect("append");
        }
        let page = audit
            .list(None, MAX_AUDIT_PAGE_SIZE + 1000)
            .expect("clamped page");
        assert_eq!(page.records.len(), 3);
        assert_eq!(page.next_cursor, None);
    }

    // ---- Tamper detection ----

    fn raw_conn(store: &Store) -> &Connection {
        store.connection()
    }

    #[test]
    fn tamper_bit_flip_in_entry_field_detected() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        audit.append(entry("list")).expect("append");
        audit.append(entry("read")).expect("append");

        raw_conn(&store)
            .execute("UPDATE audit_log SET action = 'TAMPERED' WHERE seq = 1", [])
            .expect("tamper");

        let err = audit.verify_chain().unwrap_err();
        assert!(matches!(err, AuditError::ChainBroken { seq: 1 }));
    }

    #[test]
    fn tamper_row_deletion_mid_chain_detected() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        audit.append(entry("a")).expect("append a");
        audit.append(entry("b")).expect("append b");
        audit.append(entry("c")).expect("append c");

        raw_conn(&store)
            .execute("DELETE FROM audit_log WHERE seq = 2", [])
            .expect("delete mid-chain");

        let err = audit.verify_chain().unwrap_err();
        assert!(matches!(
            err,
            AuditError::SeqGap {
                expected: 2,
                found: 3
            }
        ));
    }

    #[test]
    fn tamper_truncation_of_tail_detected_via_signed_head() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        audit.append(entry("a")).expect("append a");
        audit.append(entry("b")).expect("append b");
        audit.append(entry("c")).expect("append c");
        let signer = TestHeadSigner::from_seed([9; 32]);
        let signed = audit.sign_head(&signer, 1000).expect("sign at seq 3");

        raw_conn(&store)
            .execute("DELETE FROM audit_log WHERE seq = 3", [])
            .expect("truncate tail");

        // The now-shorter chain is internally consistent on its own...
        let head = audit
            .verify_chain()
            .expect("shortened chain still verifies alone");
        assert_eq!(head.seq, 2);

        // ...but the earlier-signed head at seq 3 can no longer be reached.
        let err = audit
            .verify_head(signed.seq, &signer.public_key())
            .unwrap_err();
        assert!(matches!(
            err,
            AuditError::TruncatedBeforeSignedHead { seq: 3 }
        ));
    }

    #[test]
    fn tamper_reordering_detected() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        audit.append(entry("a")).expect("append a");
        audit.append(entry("b")).expect("append b");

        // Swap the two rows' content fields (leaving hash/prev_hash untouched) to simulate
        // reordering the entries without regenerating the chain — content no longer matches the
        // hash computed at append time for either row.
        raw_conn(&store)
            .execute_batch(
                "UPDATE audit_log SET action = 'SWAPPED-B' WHERE seq = 1;
                 UPDATE audit_log SET action = 'SWAPPED-A' WHERE seq = 2;",
            )
            .expect("swap content");

        let err = audit.verify_chain().unwrap_err();
        assert!(matches!(err, AuditError::ChainBroken { seq: 1 }));
    }

    #[test]
    fn tamper_forged_head_signature_detected() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        audit.append(entry("a")).expect("append a");
        let signer = TestHeadSigner::from_seed([11; 32]);
        let signed = audit.sign_head(&signer, 42).expect("sign");

        raw_conn(&store)
            .execute(
                "UPDATE signed_heads SET sig = X'00' WHERE seq = ?1",
                params![signed.seq as i64],
            )
            .expect("forge signature to a value that can't even parse as one length-wise");

        let err = audit
            .verify_head(signed.seq, &signer.public_key())
            .unwrap_err();
        assert!(matches!(err, AuditError::BadHeadSignature { seq: 1, .. }));
    }

    #[test]
    fn tamper_forged_head_signature_wrong_bytes_same_length_detected() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        audit.append(entry("a")).expect("append a");
        let signer = TestHeadSigner::from_seed([12; 32]);
        let signed = audit.sign_head(&signer, 42).expect("sign");

        let mut forged = signed.sig.clone();
        forged[0] ^= 0xFF;
        raw_conn(&store)
            .execute(
                "UPDATE signed_heads SET sig = ?1 WHERE seq = ?2",
                params![forged, signed.seq as i64],
            )
            .expect("flip a byte of the real signature");

        let err = audit
            .verify_head(signed.seq, &signer.public_key())
            .unwrap_err();
        assert!(matches!(err, AuditError::BadHeadSignature { seq: 1, .. }));
    }

    #[test]
    fn no_signed_head_is_reported_distinctly() {
        let store = Store::open_in_memory().expect("open");
        let audit = store.audit();
        audit.append(entry("a")).expect("append");
        let signer = TestHeadSigner::from_seed([13; 32]);
        let err = audit.verify_head(1, &signer.public_key()).unwrap_err();
        assert!(matches!(err, AuditError::NoSignedHead(1)));
    }

    // ---- Poisoning (td-c9b9bd): a failed ROLLBACK/COMMIT must not strand this connection ----
    //
    // The seam: `Connection::authorizer` (rusqlite `hooks` feature, dev-dependency only — see
    // `Cargo.toml`'s comment) fires at statement *prepare* time and can `Deny` any statement,
    // including the bare `ROLLBACK`/`COMMIT` `Audit::append` issues via `execute_batch`. Verified
    // against the vendored sqlite3.c amalgamation (`sqlite3EndTransaction`): both `ROLLBACK` and
    // `COMMIT` route through the same `SQLITE_TRANSACTION` authorizer check, with the literal op
    // string `isRollback ? "ROLLBACK" : "COMMIT"`. rusqlite's `TransactionOperation::from_str`
    // only names `"BEGIN"`/`"RELEASE"`/`"ROLLBACK"`, so `"COMMIT"` surfaces as `Unknown` — every
    // test below that keys on `TransactionOperation::Unknown` relies on nothing else in that same
    // test issuing any other transaction-control statement, so `Unknown` is unambiguously "the
    // COMMIT" there. A denied statement never runs at all (SQLite never emits the `OP_AutoCommit`
    // VDBE op for it), so this is a genuine reproduction of "the connection never left its
    // transaction" — not a simulation of one.

    #[test]
    fn append_poisons_the_store_when_both_the_rollback_and_its_retry_are_denied() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

        let store = Store::open_in_memory().expect("open");
        // Deny the INSERT `append_inner` needs (forcing `append` into its failure/ROLLBACK
        // branch) and deny every ROLLBACK — the initial attempt AND the single retry — so the
        // connection can never leave the transaction `BEGIN IMMEDIATE` opened.
        store
            .connection()
            .authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert {
                    table_name: "audit_log",
                } => Authorization::Deny,
                AuthAction::Transaction {
                    operation: TransactionOperation::Rollback,
                } => Authorization::Deny,
                _ => Authorization::Allow,
            }));

        let audit = store.audit();
        let err = audit.append(entry("denied-insert")).unwrap_err();
        assert!(
            matches!(err, AuditError::Sqlite(_)),
            "the original append_inner failure (denied INSERT) must be what's returned, not a \
             poisoning-related error: {err:?}"
        );

        store
            .connection()
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

        assert!(
            !store.connection().is_autocommit(),
            "both ROLLBACK attempts were denied, so SQLite itself must still report this \
             connection as inside a transaction"
        );
        assert!(
            store.is_poisoned(),
            "both the initial ROLLBACK and its single retry were denied, so the connection never \
             left its transaction and must be poisoned"
        );

        // A poisoned connection refuses the very next append too — checked BEFORE it ever
        // attempts `BEGIN IMMEDIATE` again (which would otherwise fail with a confusing raw
        // "cannot start a transaction within a transaction" error instead of this named one).
        let err2 = audit.append(entry("after-poison")).unwrap_err();
        assert!(matches!(err2, AuditError::ConnectionPoisoned));
    }

    #[test]
    fn append_poisons_on_a_denied_commit_and_the_row_never_becomes_durable() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.sqlite3");
        let store = Store::open(&path).expect("open");

        // Until this ticket, a failed COMMIT (unlike a failed ROLLBACK) was handled by no code at
        // all — see `Audit::append`'s doc comment. Deny COMMIT itself, and deny the recovery
        // ROLLBACK that follows it, so the connection is left stuck and poisoned exactly the way
        // 5f0fa3a's `error!` line was added for the ROLLBACK side but never the COMMIT side.
        store
            .connection()
            .authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Transaction {
                    operation: TransactionOperation::Unknown,
                } => Authorization::Deny,
                AuthAction::Transaction {
                    operation: TransactionOperation::Rollback,
                } => Authorization::Deny,
                _ => Authorization::Allow,
            }));

        let audit = store.audit();
        let err = audit.append(entry("denied-commit")).unwrap_err();
        assert!(
            matches!(err, AuditError::Sqlite(_)),
            "a failed COMMIT must be surfaced to the caller as an error, not silently swallowed: \
             {err:?}"
        );

        store
            .connection()
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

        assert!(
            store.is_poisoned(),
            "COMMIT and the recovery ROLLBACK were both denied"
        );

        drop(store); // release the file lock before a second connection opens the same file

        // A second, independent connection to the same file proves the row never became
        // durable: the denied COMMIT means SQLite never applied it, regardless of what the first
        // (poisoned, doomed) connection's aborted transaction briefly held.
        let reopened = Store::open(&path).expect("reopen");
        let head = reopened
            .audit()
            .verify_chain()
            .expect("verify after reopen");
        assert_eq!(
            head.seq, 0,
            "the never-committed row must not be durable, and reopening must not be poisoned"
        );
        assert!(!reopened.is_poisoned());
    }

    #[test]
    fn append_recovers_and_is_not_poisoned_when_the_retried_rollback_succeeds() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
        use std::cell::Cell;

        let store = Store::open_in_memory().expect("open");
        let denied_once = Cell::new(false);
        store
            .connection()
            .authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert {
                    table_name: "audit_log",
                } => Authorization::Deny,
                AuthAction::Transaction {
                    operation: TransactionOperation::Rollback,
                } => {
                    if denied_once.get() {
                        // The retry: let it through.
                        Authorization::Allow
                    } else {
                        denied_once.set(true);
                        Authorization::Deny
                    }
                }
                _ => Authorization::Allow,
            }));

        let audit = store.audit();
        let err = audit
            .append(entry("denied-insert-then-recovered"))
            .unwrap_err();
        assert!(matches!(err, AuditError::Sqlite(_)));

        store
            .connection()
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

        assert!(
            store.connection().is_autocommit(),
            "the retried ROLLBACK was allowed and must have returned this connection to \
             autocommit mode"
        );
        assert!(
            !store.is_poisoned(),
            "the retried ROLLBACK succeeded, so this connection recovered and must not be \
             poisoned"
        );

        // Full recovery, not just "the flag is unset": a normal append afterward must actually
        // work, on a fresh, correctly-linked chain (the denied append never landed).
        let record = audit
            .append(entry("after-recovery"))
            .expect("append after recovery must succeed");
        assert_eq!(record.seq, 1);
        assert_eq!(record.prev_hash, GENESIS_PREV_HASH);
    }

    #[test]
    fn poisoned_connection_refuses_a_store_write_and_the_refused_write_does_not_land() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.sqlite3");
        let store = Store::open(&path).expect("open");

        store
            .connection()
            .authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                AuthAction::Insert {
                    table_name: "audit_log",
                } => Authorization::Deny,
                AuthAction::Transaction {
                    operation: TransactionOperation::Rollback,
                } => Authorization::Deny,
                _ => Authorization::Allow,
            }));

        let _ = store.audit().append(entry("poisoning-append")).unwrap_err();

        store
            .connection()
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        assert!(store.is_poisoned());

        // The poison flag lives on `Store`, not just `Audit` — a plain `Store` write method
        // sharing this connection must refuse too, not only `Audit::append`. `bump_cap_epoch` is
        // deliberately a leaf write (a single bare `UPDATE ... RETURNING`, no call into any other
        // guarded `Store` method) so this specifically exercises *its own*
        // `check_not_poisoned` call, not a downstream one — `add_member`, for contrast, would
        // still return `ConnectionPoisoned` even with its own top-level check removed, because it
        // internally calls `bump_grants_version` (separately guarded); that masking is itself a
        // useful defense-in-depth property, but it is not proof that any one call site matters,
        // which is what this test is for.
        let err = store.bump_cap_epoch().unwrap_err();
        assert!(matches!(err, crate::store::StoreError::ConnectionPoisoned));

        drop(store); // release the file lock

        let reopened = Store::open(&path).expect("reopen");
        assert_eq!(
            reopened.cap_epoch().expect("cap_epoch"),
            0,
            "the refused bump_cap_epoch call must not have written anything durable"
        );
        assert!(
            reopened.list_members().expect("list_members").is_empty(),
            "no member was ever added in this test; this just confirms the reopened store is \
             otherwise a normal, unpoisoned store"
        );
    }
}
