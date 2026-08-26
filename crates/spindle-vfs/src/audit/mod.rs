//! The tamper-evident, hash-chained audit log (DESIGN.md §A4b "Audit log", verbatim: "`{ts,
//! member, device, action, virtual_path, bytes, outcome}` for every VFS op and every admin
//! change; hash-chained append-only with a periodically signed head (tamper-evident). `list` is
//! cursor-paged with a max page.").
//!
//! [`Audit`] borrows the *same* `rusqlite::Connection` [`crate::store::Store`] uses (via
//! [`crate::store::Store::audit`]) rather than opening a second connection to the same file — see
//! "Transaction discipline" below for why that matters.
//!
//! # Not one of the seven A7b wire artifacts
//!
//! DESIGN.md §A7b catalogs seven signed wire artifacts (Envelope, Capability, AdmissionToken,
//! DeviceCertificate, RevocationRecord, AdminCommand, HostOpKeyCert); the audit chain's signed
//! head is not one of them — it never crosses the wire, it is a host-local durability artifact
//! only ever read back by the same host that wrote it (via `Store::open`/`Audit::verify_*`). This
//! mirrors exactly how `spindle-core`'s pre-committed root-rotation record is treated (see
//! `spindle_core::identity`'s module doc comment: "not one of spindle-proto's seven A7b-cataloged
//! wire artifacts ... this module defines its own minimal domain-separated signing input inside
//! this crate rather than adding an unauthorized type to spindle-proto"). Despite being
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
}

/// A borrowed view over the audit chain, backed by the same `rusqlite::Connection` as
/// [`crate::store::Store`] — obtain one via [`crate::store::Store::audit`].
pub struct Audit<'a> {
    conn: &'a Connection,
}

impl<'a> Audit<'a> {
    pub(crate) fn new(conn: &'a Connection) -> Self {
        Audit { conn }
    }

    /// Appends one entry to the chain. See the module doc comment's "Transaction discipline"
    /// section for the `BEGIN IMMEDIATE` atomicity this provides.
    pub fn append(&self, entry: AuditEntry) -> Result<AuditRecord, AuditError> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match self.append_inner(entry) {
            Ok(record) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(record)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
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
        Ok(self
            .walk_chain(None)?
            .unwrap_or(ChainHead {
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
            params![head.seq as i64, head.head_hash.to_vec(), ts as i64, sig.clone()],
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
        assert_eq!(head, ChainHead { seq: 0, head_hash: GENESIS_PREV_HASH });
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
        assert_eq!(head, ChainHead { seq: 3, head_hash: c.hash });
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
        assert_eq!(page1.records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(page1.next_cursor, Some(2));

        let page2 = audit.list(page1.next_cursor, 2).expect("page2");
        assert_eq!(page2.records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![3, 4]);
        assert_eq!(page2.next_cursor, Some(4));

        let page3 = audit.list(page2.next_cursor, 2).expect("page3");
        assert_eq!(page3.records.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![5]);
        assert_eq!(page3.next_cursor, None, "landing exactly on the last row must not claim more");

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
        let page = audit.list(None, MAX_AUDIT_PAGE_SIZE + 1000).expect("clamped page");
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
        assert!(matches!(err, AuditError::SeqGap { expected: 2, found: 3 }));
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
        let head = audit.verify_chain().expect("shortened chain still verifies alone");
        assert_eq!(head.seq, 2);

        // ...but the earlier-signed head at seq 3 can no longer be reached.
        let err = audit.verify_head(signed.seq, &signer.public_key()).unwrap_err();
        assert!(matches!(err, AuditError::TruncatedBeforeSignedHead { seq: 3 }));
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

        let err = audit.verify_head(signed.seq, &signer.public_key()).unwrap_err();
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

        let err = audit.verify_head(signed.seq, &signer.public_key()).unwrap_err();
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
}
