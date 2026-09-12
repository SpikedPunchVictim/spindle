//! DESIGN.md §A10.42 "Cold-clock diagnostics" leg (1) — the **always-on local bound check**
//! (td-7e3556).
//!
//! A client (or host) refused for clock skew today cannot tell that refusal from revocation or
//! from a stolen bundle: all three surface as the same uniform message (§A7 "Clock skew"). This
//! module closes that gap without putting a single new byte on the wire. It compares the caller's
//! notion of local time against bounds the caller has **already verified** — every
//! [`Capability`](spindle_proto::artifacts::Capability) embeds its `op_cert`, and
//! [`HostOpKeyCert`](spindle_proto::artifacts::HostOpKeyCert) carries `ts`, a *signed lower bound*
//! on true time, since a certificate cannot have been issued before it was signed.
//!
//! # This module reads no clock
//!
//! Every notion of "now" arrives as a caller-supplied `local_now: u64` (Unix seconds), exactly
//! like the rest of `spindle-core`. `tests/clock_source_guard.rs` scans this file — along with the
//! whole `src` tree — for ambient clock APIs and fails if one appears.
//!
//! # Resolution, stated honestly
//!
//! Per §A10.42 this check is only as tight as the age of the credentials on hand: it catches a
//! device with **no working notion of real time**, not one merely off by three minutes — which is
//! the case that actually trips the ±2 min `SessionAttestation` window. It costs nothing (no
//! network round trip, and it trusts nothing it did not already verify), which is why it runs
//! always rather than only when a connect has already failed.
//!
//! # Leg (2) — the OPTIONAL operator-configured HTTPS `Date` time source
//!
//! [`HttpsDateSource`], [`offset_from_date_header`], and [`diagnose_clock_from_https`] implement
//! §A10.42's second, optional leg: an operator may point a device or host at an HTTPS endpoint
//! and treat its `Date` response header as a second opinion on local time. **No HTTP client
//! dependency enters this workspace to do that.** The caller already owns a transport (for
//! whatever else it talks to over the network) and is trusted to make one more request with it;
//! `spindle-core` only needs the resulting header string, so [`HttpsDateSource`] asks the caller
//! for exactly that string and nothing about the caller's HTTP stack, TLS stack, or DNS resolution
//! is named anywhere in this module's public API. [`offset_from_date_header`] is the pure parser
//! and offset computation underneath it — no clock, no I/O, testable with plain string literals.
//!
//! Leg (2) can prove a direction leg (1) cannot: because the endpoint states its own notion of
//! now rather than a signed lower bound, a comparison against it can come out *either* ahead or
//! behind. That is the entire reason §A10.42 offers it as an option — see [`ClockOffset`]'s "Sign
//! convention" section for what that means for the sign of the result, and this module's leg-(2)
//! items' own doc comments for why the result stays diagnostic-only regardless.

use spindle_proto::artifacts::{Capability, HostOpKeyCert, ProtoError};
use thiserror::Error;

/// A **diagnostic-only** signed offset in seconds.
///
/// The entire point of this type is that it CANNOT be turned into a validity timestamp. It has
/// exactly one accessor — [`ClockOffset::diagnostic_seconds`] — named so that feeding it into a
/// signing time, an `exp` check, or a revocation check reads as obviously wrong at the call site.
///
/// **No conversions exist, deliberately**: no `From`/`Into`, no `Deref`, no `Add`/`Sub`, no
/// `as_timestamp`/`as_now`/`apply_to`. §A10.42: a time source is not an authenticated channel.
/// Folding one into a validity check would let anyone who shifts a client's perceived time turn a
/// safe refusal (wrong or compromised clock) into an **acceptance** of an expired or revoked
/// artifact. A refusal is a safe failure; an acceptance is not.
///
/// **This is a type-level speed bump, not a proof.** A caller can still call
/// `diagnostic_seconds()` and do arithmetic on the resulting `i64`; nothing in the type system
/// stops that. That residual hole is exactly why `tests/clock_source_guard.rs` *also* scans the
/// artifact validity paths for the literal symbol `ClockOffset` (and its siblings). The two
/// defences are layered on purpose: neither is sufficient alone.
///
/// # Sign convention
///
/// A [`ClockDiagnosis::ProvablyBehind`] offset is **positive seconds behind** — the number of
/// seconds the local clock must advance to reach the signed lower bound. See [`diagnose_clock`].
///
/// The same convention extends to leg (2): [`offset_from_date_header`] computes
/// `server_time - local_now`, so a local clock that is behind still yields a positive offset.
/// Unlike leg (1), though, leg (2) CAN prove the other direction — a local clock that is *ahead*
/// of the HTTPS source's `Date` header yields a **negative** offset. Leg (1) can never report
/// negative (it only ever compares local time against a lower bound it might be behind); leg (2)
/// can, because it compares against the source's own stated now rather than a one-sided bound.
/// That provable "ahead" direction is the whole reason §A10.42 offers leg (2) as an option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockOffset(i64);

impl ClockOffset {
    /// The offset in seconds, for **display and logging only**.
    ///
    /// §A10.42: this value MUST NOT be added to, subtracted from, or otherwise folded into any
    /// value used as `now` in an artifact validity check. It exists so a client can say "your
    /// clock is 41 days behind" instead of repeating the uniform refusal message.
    pub fn diagnostic_seconds(&self) -> i64 {
        self.0
    }
}

/// What the local bound check could prove about the caller's clock (DESIGN.md §A10.42 leg (1)).
///
/// This is a *diagnosis*, never a time value — see [`ClockOffset`] for why that distinction is
/// load-bearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockDiagnosis {
    /// Local time is earlier than a timestamp that was already signed, so the local clock is
    /// **provably** behind true time by at least `behind_by` seconds. A certificate cannot have
    /// been issued before it was signed, so `bound_ts` is a hard lower bound on true time and no
    /// honest clock can precede it.
    ///
    /// `behind_by` is positive seconds-behind; `bound_ts` is the `max(op_cert.ts)` that produced
    /// it, reported so a caller can show its basis rather than an unexplained number.
    ProvablyBehind {
        behind_by: ClockOffset,
        bound_ts: u64,
    },
    /// Local time is past `exp` for **every** capability held. §A10.42 requires this be reported
    /// honestly as ambiguous: the clock may be ahead, **or** every membership genuinely expired.
    ///
    /// **The "clock is ahead" direction is NOT provable and must not be claimed.**
    /// `spindle_proto::artifacts::Capability`'s fields are
    /// `{v, host_fp, host_root_pk, op_cert, kind, subject, cap_epoch, exp, nonce, sig}` — `exp`,
    /// never `ts`. Without an issue time there is nothing to compare local time *against* in that
    /// direction, so this variant states the two possibilities and resolves neither.
    ///
    /// `latest_cap_exp` is the largest `exp` held — the point local time is past.
    Ambiguous { latest_cap_exp: u64 },
    /// Nothing was proven. Either there was no signed lower bound to check against, or local time
    /// sits at or after the bound with at least one capability still unexpired.
    ///
    /// This is explicitly **not** a clean bill of health for the clock: §A10.42's check is only as
    /// tight as the age of the credentials on hand.
    NoEvidenceOfSkew,
}

/// Errors from [`diagnose_clock_from_capabilities`] (DESIGN.md §A10.42, td-7e3556).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClockDiagnosticError {
    /// A capability's embedded `op_cert` bytes did not decode as a
    /// [`HostOpKeyCert`](spindle_proto::artifacts::HostOpKeyCert). The index is reported because
    /// a bundle holds many capabilities and "one of them is malformed" is not an actionable
    /// message; this mirrors `ArtifactError::MalformedOpCert`, which fires on the same bytes in
    /// the verification path.
    #[error("capability at index {index} has an op_cert that does not decode: {source}")]
    MalformedOpCert { index: usize, source: ProtoError },
}

/// The core local bound check, pure over plain integers (DESIGN.md §A10.42 leg (1)).
///
/// `local_now` is the caller's Unix-seconds notion of now — this crate never reads a clock.
/// `op_cert_timestamps` are `HostOpKeyCert.ts` values the caller has **already verified**;
/// `capability_exps` are `Capability.exp` values from the same bundle.
///
/// Decision order, which is itself normative:
///
/// 1. **Provably-behind runs FIRST**, because it is the only direction that can be *proven*. If
///    both conditions hold at once, reporting the ambiguous one would throw away a fact in favour
///    of a maybe.
/// 2. Ambiguous second, reported honestly as ambiguous (see [`ClockDiagnosis::Ambiguous`]).
/// 3. Otherwise nothing was proven.
///
/// # Empty input proves nothing
///
/// An empty `op_cert_timestamps` slice means there is **no signed lower bound at all**, so the
/// provably-behind leg is skipped entirely and, with no expired capabilities either, the result is
/// [`ClockDiagnosis::NoEvidenceOfSkew`]. That is the absence of evidence, not evidence of a good
/// clock — an attacker who could strip the bundle would otherwise be handed a clean verdict for
/// free. Skipping that leg does **not** suppress the ambiguous case: per §A10.42 the ambiguous
/// case rests on `exp` alone, so expired capabilities with no op-cert bound on hand still report
/// [`ClockDiagnosis::Ambiguous`].
///
/// # Arithmetic
///
/// `bound` and `local_now` are both `u64`, and `bound - local_now` can exceed `i64::MAX` for an
/// absurd (corrupt or hostile) `ts`. The difference is computed in `u64` first — it is known
/// non-negative inside the provably-behind branch — and converted with `i64::try_from`,
/// **saturating at `i64::MAX`** rather than wrapping. Saturating rather than erroring is chosen
/// deliberately: the caller has already learned the one thing that matters ("your clock is
/// behind"), and an absurd magnitude is still absurd at `i64::MAX`, so turning a diagnostic into
/// a `Result` here would buy nothing. It must never silently wrap, because a wrapped value would
/// print as a *negative* offset and read as "your clock is ahead" — the exact direction §A10.42
/// says cannot be proven.
pub fn diagnose_clock(
    local_now: u64,
    op_cert_timestamps: &[u64],
    capability_exps: &[u64],
) -> ClockDiagnosis {
    // Checked first: this is the direction A10.42 can prove, so it wins over the ambiguous case.
    // An empty slice is no signed lower bound at all, so this leg is skipped rather than faked —
    // but the ambiguous leg below still runs, since it rests on `exp` alone.
    if let Some(&bound) = op_cert_timestamps.iter().max() {
        if local_now < bound {
            return ClockDiagnosis::ProvablyBehind {
                behind_by: ClockOffset(seconds_behind(bound, local_now)),
                bound_ts: bound,
            };
        }
    }

    // `all`, not `any`: one still-valid capability means expiry explains nothing about the clock.
    if !capability_exps.is_empty() && capability_exps.iter().all(|&exp| local_now > exp) {
        if let Some(&latest_cap_exp) = capability_exps.iter().max() {
            return ClockDiagnosis::Ambiguous { latest_cap_exp };
        }
    }

    ClockDiagnosis::NoEvidenceOfSkew
}

/// Runs [`diagnose_clock`] over a held bundle of verified artifacts (DESIGN.md §A10.42 leg (1),
/// td-7e3556).
///
/// Collects the `ts` of every capability's embedded `op_cert` (decoded from
/// `Capability.op_cert`'s opaque canonical bytes), plus the `ts` of every certificate in
/// `extra_op_certs`, plus every capability's `exp`, and delegates the decision.
///
/// `extra_op_certs` exists for the **host** path. td-7e3556 records the scope widening from
/// td-e8b79f: td-583db5 gave the host the same cold-bootstrap exposure the device has, and a host
/// holds its own [`HostOpKeyCert`] while it may hold no capabilities at all. Passing that
/// certificate here gives the host exactly the same check the device gets, through the same code.
///
/// # This function verifies NOTHING
///
/// It does **not** check a single signature. It reads `ts` out of bytes the caller must have
/// ALREADY verified — via [`crate::artifacts::verify_capability`] and
/// [`crate::artifacts::verify_host_op_key_cert`]. If a caller passes unverified input, the
/// "signed lower bound" property does not hold and the resulting diagnosis is
/// attacker-controlled.
///
/// The blast radius of a false diagnosis is bounded on purpose: this is a *diagnostic*, so the
/// worst outcome is a **wrong message**, never an acceptance of an expired or revoked artifact.
/// That is precisely why the return type is a [`ClockDiagnosis`] and not a time value — there is
/// no path from this output into any validity check (see [`ClockOffset`]).
pub fn diagnose_clock_from_capabilities(
    local_now: u64,
    capabilities: &[Capability],
    extra_op_certs: &[HostOpKeyCert],
) -> Result<ClockDiagnosis, ClockDiagnosticError> {
    let mut op_cert_timestamps = Vec::with_capacity(capabilities.len() + extra_op_certs.len());
    let mut capability_exps = Vec::with_capacity(capabilities.len());

    for (index, cap) in capabilities.iter().enumerate() {
        let op_cert = HostOpKeyCert::from_canonical_bytes(&cap.op_cert)
            .map_err(|source| ClockDiagnosticError::MalformedOpCert { index, source })?;
        op_cert_timestamps.push(op_cert.ts);
        capability_exps.push(cap.exp);
    }
    for cert in extra_op_certs {
        op_cert_timestamps.push(cert.ts);
    }

    Ok(diagnose_clock(
        local_now,
        &op_cert_timestamps,
        &capability_exps,
    ))
}

/// `bound - local_now` as a **positive** seconds-behind `i64`, saturating at `i64::MAX`.
///
/// Both inputs are `u64`; the subtraction happens in `u64` (where the caller has established
/// `bound >= local_now`) and the narrowing is explicit. See [`diagnose_clock`]'s "Arithmetic"
/// section for why wrapping here would be a correctness bug and not merely an odd number.
fn seconds_behind(bound: u64, local_now: u64) -> i64 {
    i64::try_from(bound.saturating_sub(local_now)).unwrap_or(i64::MAX)
}

/// A caller-supplied source of an operator-configured HTTPS endpoint's `Date` response header
/// (DESIGN.md §A10.42 leg (2), td-7e3556).
///
/// `spindle-core` takes no HTTP dependency to support this leg: the caller already owns a
/// transport (HTTP client, TLS stack, DNS resolution, endpoint configuration, retry policy) for
/// whatever else it talks to over the network, and is trusted to make one more request with it.
/// This trait asks for only the resulting raw header value, so the caller's transport error type
/// never has to be named in — or depend on — `spindle-core`'s public API.
pub trait HttpsDateSource {
    /// Fetches the raw `Date` response-header value from the configured HTTPS endpoint.
    ///
    /// Implementations own making the request, confirming the response actually carried a `Date`
    /// header, and folding any failure (DNS, TLS, timeout, non-2xx, missing header) into
    /// [`HttpsDateSourceError`]'s opaque message. This trait does not see or judge the request in
    /// any other way — it is not told the endpoint, and it does not retry.
    fn fetch_date_header(&self) -> Result<String, HttpsDateSourceError>;
}

/// An opaque transport failure from a [`HttpsDateSource`] (DESIGN.md §A10.42 leg (2), td-7e3556).
///
/// Deliberately just an owned message: the caller's transport type (an HTTP client's error enum,
/// a TLS error, a timeout type, ...) must not leak into `spindle-core`'s public API, the same way
/// [`ClockDiagnosticError::MalformedOpCert`] carries a [`ProtoError`] it already owns rather than
/// naming something from further up the stack. This carries enough for a log line and nothing
/// else.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct HttpsDateSourceError(pub String);

/// Errors from parsing a `Date` header value as strict IMF-fixdate (DESIGN.md §A10.42 leg (2),
/// RFC 9110 §5.6.7, td-7e3556).
///
/// This parser is deliberately stricter than RFC 9110 requires of a general HTTP *recipient*
/// (which must also accept the obsolete RFC 850 and asctime forms). It backs an
/// operator-configured diagnostic endpoint, not a general-purpose HTTP client: refusing an
/// unexpected form means no diagnostic is produced, which is a safe failure, never an unsafe one.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DateHeaderError {
    /// The header was not exactly 29 bytes — IMF-fixdate's fixed length. Checked against the raw
    /// byte length before anything is sliced, so a multi-byte UTF-8 input can never panic on a
    /// slice boundary below.
    #[error("Date header is {len} bytes, IMF-fixdate is always exactly 29")]
    InvalidLength { len: usize },
    /// One of the fixed-position separators (spaces, the comma, the colons, or the literal `GMT`)
    /// did not match IMF-fixdate's exact layout.
    #[error("Date header does not match IMF-fixdate's fixed layout")]
    InvalidFormat,
    /// The three-letter day-of-week name is not one of the seven English abbreviations.
    ///
    /// Note what this does NOT check: the day-of-week is never cross-checked against the computed
    /// date, even though it is present and well-formed. RFC 9110 makes that redundant, so a
    /// mismatch is a server bug, not a fact worth refusing a diagnostic over.
    #[error("Date header's day-of-week name is not a recognized three-letter abbreviation")]
    UnknownDayName,
    /// The three-letter month name is not one of the twelve English abbreviations.
    #[error("Date header's month name is not a recognized three-letter abbreviation")]
    UnknownMonth,
    /// A numeric field (day, year, hour, minute, or second) contained a non-digit byte.
    #[error("Date header contains a non-digit byte in a numeric field")]
    NonDigit,
    /// Hour, minute, or second was outside its valid range (`HH<=23`, `MM<=59`, `SS<=60`).
    #[error("Date header's time-of-day field is out of range")]
    FieldOutOfRange,
    /// The day-of-month exceeded the named month's real length, accounting for the full Gregorian
    /// leap rule (`y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)`).
    #[error("Date header's day-of-month does not exist in that month/year")]
    InvalidDayOfMonth,
    /// The year is before 1970. This parser produces Unix seconds, which cannot represent an
    /// instant before the epoch.
    #[error("Date header's year {year} is before the Unix epoch (1970)")]
    BeforeUnixEpoch { year: u32 },
    /// The header used one of the obsolete RFC 850 or asctime date forms instead of IMF-fixdate.
    ///
    /// RFC 9110 requires a general HTTP *recipient* to also accept obs-date, but this parser backs
    /// an operator-configured diagnostic endpoint, not a general HTTP client: a strict parser that
    /// refuses an obsolete form is a safe failure (no diagnostic produced), not an unsafe one, so
    /// this is rejected by name rather than tolerated.
    #[error("Date header uses the obsolete {form} form, not IMF-fixdate")]
    ObsoleteFormat { form: &'static str },
    /// The header contained a byte outside the ASCII range. IMF-fixdate (and both obsolete forms)
    /// are ASCII by definition, so this is checked before any of the obsolete-format pre-checks or
    /// the fixed-position layout checks below index into the bytes — a multi-byte UTF-8 sequence
    /// must never be misread as matching (or nearly matching) a fixed byte position.
    #[error("Date header contains a non-ASCII byte")]
    NonAscii,
}

/// Errors from [`diagnose_clock_from_https`] (DESIGN.md §A10.42 leg (2), td-7e3556).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpsDateError {
    /// The [`HttpsDateSource`] itself failed — DNS, TLS, timeout, or a response with no `Date`
    /// header. Propagated rather than swallowed: leg (2) is optional, but a caller that asked for
    /// it deserves to know its source failed rather than receiving an indistinguishable
    /// "nothing to report".
    #[error("fetching the configured HTTPS Date source failed: {0}")]
    Source(#[from] HttpsDateSourceError),
    /// The fetched `Date` header value did not parse as strict IMF-fixdate.
    #[error("the configured HTTPS Date source's Date header did not parse: {0}")]
    Parse(#[from] DateHeaderError),
}

/// The three-letter English day-of-week abbreviations IMF-fixdate requires, in no particular
/// order — see [`DateHeaderError::UnknownDayName`] for why a match here is required but never
/// cross-checked against the computed date.
const DAY_NAMES: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];

/// The seven FULL English day-of-week names RFC 850's obs-date form uses, in no particular order.
/// Distinguishing feature versus IMF-fixdate's three-letter [`DAY_NAMES`]: a full day name is
/// exactly what identifies obs-date's first token, so this is the basis for deciding whether a
/// misplaced comma actually indicates RFC 850 rather than arbitrary garbage — see
/// [`parse_imf_fixdate`].
const FULL_DAY_NAMES: [&[u8]; 7] = [
    b"Sunday",
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
];

/// The twelve three-letter English month abbreviations IMF-fixdate requires, in calendar order —
/// index `i` is month `i + 1`.
const MONTH_NAMES: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Parses an ASCII digit run into a `u32`, or `None` if any byte is not `0..=9`.
fn parse_digits(digits: &[u8]) -> Option<u32> {
    let mut value: u32 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(b - b'0');
    }
    Some(value)
}

/// The number of days in `month` (1-based) of Gregorian year `year`, with the full leap rule
/// (`y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)`) applied to February.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => unreachable!("month is 1..=12: produced from a validated MONTH_NAMES index"),
    }
}

/// Days since the Unix epoch (1970-01-01) for a Gregorian calendar date — Howard Hinnant's
/// days-from-civil algorithm, exact for every Gregorian date and needing no lookup table.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parses `date_header` as strict RFC 9110 §5.6.7 IMF-fixdate — `Www, DD Mon YYYY HH:MM:SS GMT`,
/// exactly 29 ASCII bytes — into Unix seconds.
///
/// Operates on `date_header.as_bytes()` throughout, with the ASCII check first and the length
/// check next, so a multi-byte UTF-8 input can never panic on a `str` slice boundary: every byte
/// index taken below is either bounds-checked immediately beforehand or follows from a length
/// that was already confirmed exact.
fn parse_imf_fixdate(date_header: &str) -> Result<u64, DateHeaderError> {
    let bytes = date_header.as_bytes();

    // IMF-fixdate (and both obsolete forms) are ASCII by definition. Gating on that here, before
    // any byte indexing at all, keeps a multi-byte UTF-8 sequence from ever being misread as
    // matching — or nearly matching — one of the fixed byte positions checked below.
    if !bytes.is_ascii() {
        return Err(DateHeaderError::NonAscii);
    }

    // Detect the two obsolete forms up front, before the length check below, so each is reported
    // by name rather than folded into a generic "wrong length" error. Both are structurally
    // distinguishable from IMF-fixdate:
    //   - RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`) uses a FULL day name, so this only fires when
    //     the bytes before the comma are actually one of the seven full English day names —
    //     otherwise an arbitrary misplaced comma would be misattributed to RFC 850 instead of
    //     falling through to the ordinary length/format errors below.
    //   - asctime (`Sun Nov  6 08:49:37 1994`) has no comma at all, and instead butts a
    //     three-letter day name directly against a three-letter month name across two spaces. The
    //     arm reads bytes[0..3], bytes[3], bytes[4..7], and bytes[7] — index 7 is the highest one
    //     read, so it requires `bytes.len() >= 8`, not 7.
    let comma_pos = bytes.iter().position(|&b| b == b',');
    match comma_pos {
        Some(pos) if FULL_DAY_NAMES.iter().any(|&name| name == &bytes[..pos]) => {
            return Err(DateHeaderError::ObsoleteFormat {
                form: "RFC 850 (obs-date), e.g. \"Sunday, 06-Nov-94 08:49:37 GMT\"",
            });
        }
        None if bytes.len() >= 8
            && bytes[3] == b' '
            && bytes[7] == b' '
            && DAY_NAMES.iter().any(|&name| name == &bytes[0..3])
            && MONTH_NAMES.iter().any(|&name| name == &bytes[4..7]) =>
        {
            return Err(DateHeaderError::ObsoleteFormat {
                form: "asctime, e.g. \"Sun Nov  6 08:49:37 1994\"",
            });
        }
        _ => {}
    }

    if bytes.len() != 29 {
        return Err(DateHeaderError::InvalidLength { len: bytes.len() });
    }

    if bytes[3] != b','
        || bytes[4] != b' '
        || bytes[7] != b' '
        || bytes[11] != b' '
        || bytes[16] != b' '
        || bytes[19] != b':'
        || bytes[22] != b':'
        || bytes[25] != b' '
        || &bytes[26..29] != b"GMT"
    {
        return Err(DateHeaderError::InvalidFormat);
    }

    if !DAY_NAMES.iter().any(|&name| name == &bytes[0..3]) {
        return Err(DateHeaderError::UnknownDayName);
    }

    let month_index = MONTH_NAMES
        .iter()
        .position(|&name| name == &bytes[8..11])
        .ok_or(DateHeaderError::UnknownMonth)?;
    let month = u32::try_from(month_index + 1).expect("month_index is in 0..12");

    let day = parse_digits(&bytes[5..7]).ok_or(DateHeaderError::NonDigit)?;
    let year = parse_digits(&bytes[12..16]).ok_or(DateHeaderError::NonDigit)?;
    let hour = parse_digits(&bytes[17..19]).ok_or(DateHeaderError::NonDigit)?;
    let minute = parse_digits(&bytes[20..22]).ok_or(DateHeaderError::NonDigit)?;
    let mut second = parse_digits(&bytes[23..25]).ok_or(DateHeaderError::NonDigit)?;

    if year < 1970 {
        return Err(DateHeaderError::BeforeUnixEpoch { year });
    }
    if hour > 23 || minute > 59 || second > 60 {
        return Err(DateHeaderError::FieldOutOfRange);
    }
    // Second 60 is a leap second. POSIX time has no representation for it, and a one-second error
    // in a diagnostic value is immaterial — refusing the whole header over it would be worse than
    // the second of slop this clamp introduces.
    if second == 60 {
        second = 59;
    }

    if day == 0 || day > days_in_month(year, month) {
        return Err(DateHeaderError::InvalidDayOfMonth);
    }

    let days_since_epoch = u64::try_from(days_from_civil(
        i64::from(year),
        i64::from(month),
        i64::from(day),
    ))
    .expect("year >= 1970, checked above, guarantees a non-negative days-since-epoch");
    Ok(days_since_epoch * 86_400
        + u64::from(hour) * 3600
        + u64::from(minute) * 60
        + u64::from(second))
}

/// The pure core of leg (2) (DESIGN.md §A10.42, td-7e3556): parses `date_header` as strict
/// IMF-fixdate and computes its offset against `local_now`. No clock, no I/O, no dependency —
/// testable with plain string literals.
///
/// # Sign convention
///
/// `offset = server_time - local_now`, matching leg (1) — see [`ClockOffset`]'s "Sign convention"
/// section for the full statement, including the negative (locally-ahead) case this leg can prove
/// and leg (1) cannot.
///
/// # Arithmetic
///
/// A 4-digit year keeps both `server_unix` and `local_now` comfortably inside `i64`, but the
/// subtraction is still done with explicit `i64::try_from` and `saturating_sub` rather than
/// relying on that headroom — exactly as [`seconds_behind`] does for leg (1), and for the same
/// reason: it must never silently wrap into a value that prints as the wrong sign.
pub fn offset_from_date_header(
    local_now: u64,
    date_header: &str,
) -> Result<ClockOffset, DateHeaderError> {
    let server_unix = parse_imf_fixdate(date_header)?;
    let server = i64::try_from(server_unix).unwrap_or(i64::MAX);
    let local = i64::try_from(local_now).unwrap_or(i64::MAX);
    Ok(ClockOffset(server.saturating_sub(local)))
}

/// Ties [`HttpsDateSource`] and [`offset_from_date_header`] together (DESIGN.md §A10.42 leg (2),
/// td-7e3556): fetches the `Date` header from `source` and computes its offset against
/// `local_now`.
///
/// # This is diagnostic only — TLS authenticates the server, not the time
///
/// An operator-configured HTTPS endpoint proves only that whoever holds that endpoint's TLS
/// certificate said what time it is, not that the time is correct. Folding this value into a
/// signing time, an `exp` check, or a revocation check would turn a safe refusal (a wrong or
/// compromised clock) into an **acceptance** of an expired or revoked artifact — precisely the
/// hazard [`ClockOffset`]'s doc comment describes for leg (1), and the reason this returns the
/// same non-convertible [`ClockOffset`] type leg (1) does.
pub fn diagnose_clock_from_https<S: HttpsDateSource + ?Sized>(
    local_now: u64,
    source: &S,
) -> Result<ClockOffset, HttpsDateError> {
    let date_header = source.fetch_date_header()?;
    Ok(offset_from_date_header(local_now, &date_header)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::{issue_capability, issue_host_op_key_cert};
    use crate::fingerprint::{Fingerprint, FINGERPRINT_LEN};
    use crate::identity::RootKey;
    use ed25519_dalek::SigningKey;
    use spindle_proto::artifacts::CapKind;

    /// Mints a real capability with a real embedded `op_cert` whose `ts` is `op_cert_ts`, the
    /// same way `artifacts::capability`'s own tests build one — so the extraction path under test
    /// reads production bytes, not a hand-assembled struct.
    fn real_capability(op_cert_ts: u64, cap_exp: u64) -> Capability {
        let root = RootKey::from_seed([0x21; 32]);
        let op_signer = SigningKey::from_bytes(&[0x22; 32]);
        let op_cert =
            issue_host_op_key_cert(&root, &op_signer.verifying_key(), op_cert_ts, u64::MAX);
        issue_capability(
            &root.public_key(),
            &op_cert,
            &op_signer,
            CapKind::Member,
            Fingerprint::of_parts(&[b"subject"]),
            1,
            cap_exp,
            vec![0xAA; FINGERPRINT_LEN],
        )
    }

    #[test]
    fn local_time_before_the_signed_bound_is_provably_behind() {
        let diagnosis = diagnose_clock(1_000, &[5_000], &[]);
        match diagnosis {
            ClockDiagnosis::ProvablyBehind {
                behind_by,
                bound_ts,
            } => {
                assert_eq!(behind_by.diagnostic_seconds(), 4_000);
                assert_eq!(bound_ts, 5_000);
            }
            other => panic!("expected ProvablyBehind, got {other:?}"),
        }
    }

    /// The bound is `max(op_cert.ts)` per A10.42. The max sits in the MIDDLE position, so a `[0]`
    /// or a `.min()` implementation picks a different value and this test fails.
    #[test]
    fn the_bound_is_the_max_op_cert_ts_not_the_first_or_the_min() {
        let diagnosis = diagnose_clock(1_000, &[2_000, 9_000, 3_000], &[]);
        match diagnosis {
            ClockDiagnosis::ProvablyBehind {
                behind_by,
                bound_ts,
            } => {
                assert_eq!(bound_ts, 9_000);
                assert_eq!(behind_by.diagnostic_seconds(), 8_000);
            }
            other => panic!("expected ProvablyBehind against the max ts, got {other:?}"),
        }
    }

    /// Boundary: "earlier than" is strict. A clock exactly at the bound is consistent with a
    /// certificate signed at that instant, so nothing is proven.
    #[test]
    fn local_time_exactly_at_the_bound_is_not_provably_behind() {
        assert_eq!(
            diagnose_clock(5_000, &[5_000], &[]),
            ClockDiagnosis::NoEvidenceOfSkew
        );
    }

    #[test]
    fn local_time_one_second_past_the_bound_is_not_provably_behind() {
        assert_eq!(
            diagnose_clock(5_001, &[5_000], &[]),
            ClockDiagnosis::NoEvidenceOfSkew
        );
    }

    #[test]
    fn every_capability_expired_is_ambiguous_with_the_latest_exp() {
        assert_eq!(
            diagnose_clock(9_000, &[1_000], &[4_000, 8_000, 6_000]),
            ClockDiagnosis::Ambiguous {
                latest_cap_exp: 8_000
            }
        );
    }

    /// Order is normative (A10.42): the provable direction wins over the ambiguous one when both
    /// conditions hold at once.
    #[test]
    fn provably_behind_wins_over_ambiguous_when_both_hold() {
        let diagnosis = diagnose_clock(500, &[5_000], &[100, 200]);
        match diagnosis {
            ClockDiagnosis::ProvablyBehind {
                behind_by,
                bound_ts,
            } => {
                assert_eq!(behind_by.diagnostic_seconds(), 4_500);
                assert_eq!(bound_ts, 5_000);
            }
            other => panic!("expected ProvablyBehind to win over Ambiguous, got {other:?}"),
        }
    }

    /// `all`, not `any`: one unexpired capability means expiry explains nothing about the clock.
    #[test]
    fn one_still_valid_capability_yields_no_evidence_not_ambiguous() {
        assert_eq!(
            diagnose_clock(5_000, &[1_000], &[100, 200, 9_999]),
            ClockDiagnosis::NoEvidenceOfSkew
        );
    }

    /// An empty op-cert slice is the absence of a lower bound, not a good clock — but it does not
    /// suppress the ambiguous case, which rests on `exp` alone.
    #[test]
    fn empty_op_cert_slice_with_expired_caps_is_ambiguous() {
        assert_eq!(
            diagnose_clock(9_000, &[], &[4_000, 8_000]),
            ClockDiagnosis::Ambiguous {
                latest_cap_exp: 8_000
            }
        );
    }

    #[test]
    fn empty_everything_proves_nothing() {
        assert_eq!(
            diagnose_clock(9_000, &[], &[]),
            ClockDiagnosis::NoEvidenceOfSkew
        );
    }

    /// The extraction path: a REAL capability's embedded `op_cert` bytes must yield the same
    /// diagnosis `diagnose_clock` gives for the same raw numbers.
    #[test]
    fn capability_path_extracts_ts_from_a_real_embedded_op_cert() {
        let cap = real_capability(7_000, 8_000);
        let diagnosis = diagnose_clock_from_capabilities(1_000, std::slice::from_ref(&cap), &[])
            .expect("a real capability's op_cert decodes");
        assert_eq!(diagnosis, diagnose_clock(1_000, &[7_000], &[8_000]));
        assert_eq!(
            diagnosis,
            ClockDiagnosis::ProvablyBehind {
                behind_by: ClockOffset(6_000),
                bound_ts: 7_000,
            }
        );
    }

    #[test]
    fn garbage_op_cert_bytes_report_the_offending_index() {
        let mut caps = vec![real_capability(7_000, 8_000), real_capability(7_000, 8_000)];
        caps[1].op_cert = vec![0xFF, 0xFF, 0xFF];
        let err = diagnose_clock_from_capabilities(1_000, &caps, &[])
            .expect_err("garbage op_cert bytes must not decode");
        match err {
            ClockDiagnosticError::MalformedOpCert { index, .. } => assert_eq!(index, 1),
        }
    }

    /// The host path (td-583db5 scope widening): a host holds its own `HostOpKeyCert` and may
    /// hold no capabilities at all, and must still get the check.
    #[test]
    fn extra_op_certs_alone_drive_the_host_path() {
        let root = RootKey::from_seed([0x31; 32]);
        let op_signer = SigningKey::from_bytes(&[0x32; 32]);
        let op_cert = issue_host_op_key_cert(&root, &op_signer.verifying_key(), 7_000, u64::MAX);
        let diagnosis = diagnose_clock_from_capabilities(1_000, &[], &[op_cert])
            .expect("no capabilities to decode");
        assert_eq!(
            diagnosis,
            ClockDiagnosis::ProvablyBehind {
                behind_by: ClockOffset(6_000),
                bound_ts: 7_000,
            }
        );
    }

    /// An absurd bound must saturate at `i64::MAX`, never wrap: a wrapped value would print as a
    /// negative offset and read as "your clock is ahead", the one direction A10.42 says cannot be
    /// proven.
    #[test]
    fn an_absurd_bound_saturates_instead_of_wrapping() {
        let diagnosis = diagnose_clock(0, &[u64::MAX], &[]);
        match diagnosis {
            ClockDiagnosis::ProvablyBehind {
                behind_by,
                bound_ts,
            } => {
                assert_eq!(behind_by.diagnostic_seconds(), i64::MAX);
                assert_eq!(bound_ts, u64::MAX);
            }
            other => panic!("expected a saturated ProvablyBehind, got {other:?}"),
        }
    }

    // ---- leg (2): offset_from_date_header ---------------------------------------------------

    /// Ground truth from Python's `email.utils.parsedate_to_datetime` (an independent
    /// implementation), pinned as literals. `local_now = 0` so the offset equals the parsed
    /// timestamp directly.
    #[test]
    fn ground_truth_vectors_from_an_independent_parser() {
        let vectors: &[(&str, i64)] = &[
            ("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777), // RFC 9110's own example
            ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
            ("Sat, 29 Feb 2020 12:00:00 GMT", 1_582_977_600),
            ("Tue, 29 Feb 2000 00:00:00 GMT", 951_782_400), // 2000 IS a leap year
            ("Fri, 31 Dec 2038 23:59:59 GMT", 2_177_452_799), // past the 32-bit cliff
            ("Wed, 01 Jan 2025 00:00:00 GMT", 1_735_689_600),
        ];
        for &(header, expected) in vectors {
            let offset = offset_from_date_header(0, header)
                .unwrap_or_else(|e| panic!("{header} must parse: {e}"));
            assert_eq!(offset.diagnostic_seconds(), expected, "header: {header}");
        }
    }

    #[test]
    fn local_clock_behind_the_https_source_yields_a_positive_offset() {
        let offset = offset_from_date_header(700_000_000, "Sun, 06 Nov 1994 08:49:37 GMT")
            .expect("valid IMF-fixdate");
        assert_eq!(offset.diagnostic_seconds(), 784_111_777 - 700_000_000);
        assert!(offset.diagnostic_seconds() > 0);
    }

    /// Unlike leg (1), leg (2) CAN prove this direction — the whole reason §A10.42 offers it.
    #[test]
    fn local_clock_ahead_of_the_https_source_yields_a_negative_offset() {
        let offset = offset_from_date_header(800_000_000, "Sun, 06 Nov 1994 08:49:37 GMT")
            .expect("valid IMF-fixdate");
        assert_eq!(offset.diagnostic_seconds(), 784_111_777 - 800_000_000);
        assert!(offset.diagnostic_seconds() < 0);
    }

    #[test]
    fn local_clock_exactly_matching_the_https_source_yields_zero() {
        let offset = offset_from_date_header(784_111_777, "Sun, 06 Nov 1994 08:49:37 GMT")
            .expect("valid IMF-fixdate");
        assert_eq!(offset.diagnostic_seconds(), 0);
    }

    #[test]
    fn feb_29_in_a_non_leap_year_is_rejected() {
        assert_eq!(
            offset_from_date_header(0, "Sun, 29 Feb 2021 12:00:00 GMT"),
            Err(DateHeaderError::InvalidDayOfMonth)
        );
    }

    /// The `%100` rule: 2100 is divisible by 4 but also by 100 and not by 400, so it is NOT a
    /// leap year.
    #[test]
    fn feb_29_in_a_century_non_leap_year_is_rejected() {
        assert_eq!(
            offset_from_date_header(0, "Mon, 29 Feb 2100 00:00:00 GMT"),
            Err(DateHeaderError::InvalidDayOfMonth)
        );
    }

    #[test]
    fn april_31st_is_rejected_april_has_thirty_days() {
        assert_eq!(
            offset_from_date_header(0, "Thu, 31 Apr 2025 00:00:00 GMT"),
            Err(DateHeaderError::InvalidDayOfMonth)
        );
    }

    /// A leap second is accepted and clamped to :59's value rather than refused outright — POSIX
    /// time has no leap second, and a one-second error in a diagnostic is immaterial.
    #[test]
    fn leap_second_sixty_is_accepted_and_clamped_to_fifty_nine() {
        let clamped = offset_from_date_header(0, "Thu, 01 Jan 1970 00:00:60 GMT")
            .expect("a leap second must be accepted, not refused");
        let fifty_nine = offset_from_date_header(0, "Thu, 01 Jan 1970 00:00:59 GMT")
            .expect("the :59 form parses");
        assert_eq!(
            clamped.diagnostic_seconds(),
            fifty_nine.diagnostic_seconds()
        );
    }

    #[test]
    fn rfc_850_obsolete_form_is_rejected_by_name() {
        match offset_from_date_header(0, "Sunday, 06-Nov-94 08:49:37 GMT") {
            Err(DateHeaderError::ObsoleteFormat { form }) => {
                assert!(form.contains("RFC 850"), "form was: {form}");
            }
            other => panic!("expected ObsoleteFormat naming RFC 850, got {other:?}"),
        }
    }

    /// The full-day-name check is not hard-coded to "Sunday": any of the seven full English day
    /// names must trigger the same RFC 850 attribution.
    #[test]
    fn rfc_850_full_day_name_check_is_not_hard_coded_to_one_name() {
        match offset_from_date_header(0, "Wednesday, 06-Nov-94 08:49:37 GMT") {
            Err(DateHeaderError::ObsoleteFormat { form }) => {
                assert!(form.contains("RFC 850"), "form was: {form}");
            }
            other => panic!("expected ObsoleteFormat naming RFC 850, got {other:?}"),
        }
    }

    /// DEFECT 2: a comma anywhere other than byte 3 used to be blamed on RFC 850 regardless of
    /// what preceded it. "garbage,x" has a misplaced comma but no full day name before it, so it
    /// must fall through to an ordinary error instead of a false RFC 850 attribution.
    #[test]
    fn a_misplaced_comma_without_a_full_day_name_is_not_blamed_on_rfc_850() {
        let err =
            offset_from_date_header(0, "garbage,x").expect_err("garbage input must be rejected");
        assert!(
            !matches!(err, DateHeaderError::ObsoleteFormat { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn asctime_obsolete_form_is_rejected_by_name() {
        match offset_from_date_header(0, "Sun Nov  6 08:49:37 1994") {
            Err(DateHeaderError::ObsoleteFormat { form }) => {
                assert!(form.contains("asctime"), "form was: {form}");
            }
            other => panic!("expected ObsoleteFormat naming asctime, got {other:?}"),
        }
    }

    #[test]
    fn plus_zero_offset_instead_of_gmt_is_rejected() {
        assert!(offset_from_date_header(0, "Sun, 06 Nov 1994 08:49:37 +0000").is_err());
    }

    #[test]
    fn unknown_month_name_is_rejected() {
        assert_eq!(
            offset_from_date_header(0, "Sun, 06 Xxx 1994 08:49:37 GMT"),
            Err(DateHeaderError::UnknownMonth)
        );
    }

    #[test]
    fn unknown_day_name_is_rejected() {
        assert_eq!(
            offset_from_date_header(0, "Xxx, 06 Nov 1994 08:49:37 GMT"),
            Err(DateHeaderError::UnknownDayName)
        );
    }

    /// RFC 9110 makes the day-of-week redundant with the computed date; this parser deliberately
    /// does NOT cross-check the two, so a disagreeing (but well-formed) day name is accepted.
    /// 1994-11-06 was actually a Sunday — "Mon" here is wrong and accepted anyway.
    #[test]
    fn a_day_name_that_disagrees_with_the_date_is_accepted() {
        let offset = offset_from_date_header(0, "Mon, 06 Nov 1994 08:49:37 GMT")
            .expect("day-of-week is never cross-checked against the computed date");
        assert_eq!(offset.diagnostic_seconds(), 784_111_777);
    }

    #[test]
    fn year_before_unix_epoch_is_rejected() {
        assert_eq!(
            offset_from_date_header(0, "Wed, 01 Jan 1969 00:00:00 GMT"),
            Err(DateHeaderError::BeforeUnixEpoch { year: 1969 })
        );
    }

    #[test]
    fn header_one_byte_too_short_is_rejected() {
        let short = "Sun, 06 Nov 1994 08:49:37 GM"; // 28 bytes
        assert_eq!(short.len(), 28);
        assert_eq!(
            offset_from_date_header(0, short),
            Err(DateHeaderError::InvalidLength { len: 28 })
        );
    }

    #[test]
    fn header_one_byte_too_long_is_rejected() {
        let long = "Sun, 06 Nov 1994 08:49:37 GMTT"; // 30 bytes
        assert_eq!(long.len(), 30);
        assert_eq!(
            offset_from_date_header(0, long),
            Err(DateHeaderError::InvalidLength { len: 30 })
        );
    }

    /// A multi-byte UTF-8 input must be rejected, never panic — the length check runs on raw
    /// bytes before anything is sliced.
    #[test]
    fn non_ascii_multibyte_input_is_rejected_without_panicking() {
        let result = offset_from_date_header(0, "Sün, 06 Nov 1994 08:49:37 GMT");
        assert!(result.is_err());
    }

    /// DEFECT 2: this input's comma lands at byte 4 (not 3, because 'ü' is a two-byte UTF-8
    /// sequence), which used to be misattributed to RFC 850 by the old `pos != 3` check even
    /// though the input is really an IMF-fixdate with one non-ASCII letter. It must be reported
    /// as non-ASCII, not as an obsolete format.
    #[test]
    fn non_ascii_input_is_reported_as_non_ascii_not_as_an_obsolete_format() {
        let err = offset_from_date_header(0, "Sün, 06 Nov 1994 08:49:37 GMT")
            .expect_err("non-ASCII input must be rejected");
        assert_eq!(err, DateHeaderError::NonAscii);
        assert!(!matches!(err, DateHeaderError::ObsoleteFormat { .. }));
    }

    /// DEFECT 1 regression: the asctime pre-check guarded `bytes.len() >= 7` but read `bytes[7]`,
    /// which needs `len >= 8`. This exact 7-byte input panicked with "index out of bounds: the
    /// len is 7 but the index is 7" before this fix. Pinned by name so the regression can never
    /// silently come back.
    #[test]
    fn a_seven_byte_header_is_rejected_without_panicking() {
        let result = offset_from_date_header(0, "Sun Nov");
        assert!(result.is_err());
    }

    /// Every truncation of a valid header, enumerated rather than sampled: a hand-picked probe
    /// over a few lengths cannot distinguish "this length is safe" from "this length was never
    /// tried" — length 7 was the only one that panicked (DEFECT 1), and nothing about it stood
    /// out as a length worth hand-picking. Looping over every truncated length 0..len (the full
    /// length is the valid header itself, not a truncation) is the only way to be sure none of
    /// them panics.
    ///
    /// Two fixtures are truncated, not one, and that second fixture is load-bearing rather than
    /// decorative. A neuter run proved it: reverting the asctime guard in `parse_imf_fixdate` from
    /// `bytes.len() >= 8` back to the buggy `>= 7` and re-running the suite left this test GREEN —
    /// `a_seven_byte_header_is_rejected_without_panicking` went red, but this one didn't notice —
    /// even though this is exactly the panic it claims to guard against. The reason: every prefix
    /// of the comma-bearing IMF-fixdate fixture that is 4 bytes or longer already has its comma at
    /// index 3, so `comma_pos` is `Some(3)` and control takes the RFC-850 branch, never the
    /// comma-less asctime arm that indexes `bytes[7]` — the only arm the reverted guard affects.
    /// An exhaustive loop over every length of the wrong alphabet still isn't exhaustive coverage
    /// of the code under test. Truncating the genuine comma-less asctime form
    /// `"Sun Nov  6 08:49:37 1994"` alongside it drives every prefix length through that
    /// comma-less arm instead, so this test can actually fail when the guard regresses.
    #[test]
    fn every_truncation_of_a_valid_header_is_rejected_without_panicking() {
        let fixtures = [
            "Sun, 06 Nov 1994 08:49:37 GMT", // comma-bearing: exercises the `Some(3)` branch
            "Sun Nov  6 08:49:37 1994",      // comma-less: exercises the asctime arm, bytes[7]
        ];
        for valid in fixtures {
            for len in 0..valid.len() {
                let prefix = &valid[..len];
                let result = offset_from_date_header(0, prefix);
                assert!(
                    result.is_err(),
                    "prefix of length {len} of {valid:?} must be rejected, not accepted or panic"
                );
            }
        }
    }

    #[test]
    fn non_digit_in_a_numeric_field_is_rejected() {
        assert_eq!(
            offset_from_date_header(0, "Sun, 0X Nov 1994 08:49:37 GMT"),
            Err(DateHeaderError::NonDigit)
        );
    }

    // ---- leg (2): HttpsDateSource -------------------------------------------------------------

    struct FakeGoodSource(&'static str);

    impl HttpsDateSource for FakeGoodSource {
        fn fetch_date_header(&self) -> Result<String, HttpsDateSourceError> {
            Ok(self.0.to_string())
        }
    }

    struct FakeFailingSource;

    impl HttpsDateSource for FakeFailingSource {
        fn fetch_date_header(&self) -> Result<String, HttpsDateSourceError> {
            Err(HttpsDateSourceError("connection reset by peer".to_string()))
        }
    }

    #[test]
    fn https_source_with_a_good_header_yields_a_computed_offset() {
        let source = FakeGoodSource("Sun, 06 Nov 1994 08:49:37 GMT");
        let offset =
            diagnose_clock_from_https(700_000_000, &source).expect("a good header must succeed");
        assert_eq!(offset.diagnostic_seconds(), 784_111_777 - 700_000_000);
    }

    /// A transport failure must propagate as an error, not be swallowed into some default offset.
    #[test]
    fn https_source_transport_error_propagates_not_swallowed() {
        let source = FakeFailingSource;
        match diagnose_clock_from_https(0, &source) {
            Err(HttpsDateError::Source(HttpsDateSourceError(msg))) => {
                assert_eq!(msg, "connection reset by peer");
            }
            other => panic!("expected the transport error to propagate, got {other:?}"),
        }
    }
}
