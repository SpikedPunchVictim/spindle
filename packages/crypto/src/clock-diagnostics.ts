// DESIGN.md §A10.42 "Cold-clock diagnostics" — the TypeScript twin of
// `crates/spindle-core/src/clock_diagnostics.rs` (both legs: leg (1) landed Rust-only in
// `67d89b6`, leg (2) in `390d1fb`; this file is the first TypeScript twin of either).
//
// A client (or host) refused for clock skew today cannot tell that refusal from revocation or
// from a stolen bundle: all three surface as the same uniform message (§A7 "Clock skew"). This
// module closes that gap without putting a single new byte on the wire, by comparing the caller's
// notion of local time against bounds the caller has ALREADY verified — every `Capability` embeds
// its `op_cert`, and `HostOpKeyCert` carries `ts`, a *signed lower bound* on true time, since a
// certificate cannot have been issued before it was signed.
//
// # This module reads no clock
//
// Every notion of "now" arrives as a caller-supplied `localNow: bigint` (Unix seconds), exactly
// like the rest of `@spindle/crypto` (see `artifacts.ts`'s `verifyCapability(cap, now: bigint,
// ...)`). `test/clock-source-guard.test.ts` scans this file — along with the whole `src` tree —
// for ambient clock APIs and fails if one appears.
//
// # Resolution, stated honestly
//
// Per §A10.42 this check is only as tight as the age of the credentials on hand: it catches a
// device with NO working notion of real time, not one merely off by three minutes — which is the
// case that actually trips the ±2 min `SessionAttestation` window. It costs nothing (no network
// round trip, and it trusts nothing it did not already verify), which is why it runs always
// rather than only when a connect has already failed.
//
// # Leg (2) — the OPTIONAL operator-configured HTTPS `Date` time source
//
// `HttpsDateSource`, `offsetFromDateHeader`, and `diagnoseClockFromHttps` implement §A10.42's
// second, optional leg: an operator may point a device or host at an HTTPS endpoint and treat its
// `Date` response header as a second opinion on local time. NO HTTP client dependency enters this
// package to do that. The caller already owns a transport (for whatever else it talks to over the
// network) and is trusted to make one more request with it; this module only needs the resulting
// header string, so `HttpsDateSource` asks the caller for exactly that string and nothing about
// the caller's HTTP stack, TLS stack, or DNS resolution is named anywhere in this module's public
// API. `offsetFromDateHeader` is the pure parser and offset computation underneath it — no clock,
// no I/O, testable with plain string literals.
//
// Leg (2) can prove a direction leg (1) cannot: because the endpoint states its own notion of now
// rather than a signed lower bound, a comparison against it can come out EITHER ahead or behind.
// That is the entire reason §A10.42 offers it as an option — see `ClockOffset`'s "Sign convention"
// section for what that means for the sign of the result, and this module's leg-(2) items' own
// doc comments for why the result stays diagnostic-only regardless.

import { Capability, HostOpKeyCert, ProtoError } from "@spindle/proto";

/**
 * A DIAGNOSTIC-ONLY signed offset in seconds.
 *
 * The entire point of this type is that it CANNOT be turned into a validity timestamp. It has
 * exactly one accessor — {@link ClockOffset.diagnosticSeconds} — named so that feeding it into a
 * signing time, an `exp` check, or a revocation check reads as obviously wrong at the call site.
 *
 * **No conversions exist, deliberately**: no `valueOf`, no `toString`, no `toJSON`, no numeric
 * coercion of any kind — those are TypeScript's equivalent of the `From`/`Into`/`Deref`/`Add`/`Sub`
 * conversions Rust's twin refuses. `+offset` or `` `${offset}` `` would be exactly the silent path
 * into a validity check that this type exists to block. §A10.42: a time source is not an
 * authenticated channel. Folding one into a validity check would let anyone who shifts a client's
 * perceived time turn a safe refusal (wrong or compromised clock) into an ACCEPTANCE of an expired
 * or revoked artifact. A refusal is a safe failure; an acceptance is not.
 *
 * **This is a type-level speed bump, not a proof.** A caller can still call
 * `diagnosticSeconds()` and do arithmetic on the resulting `bigint`; nothing in the type system
 * stops that. TypeScript cannot enforce the Rust twin's guarantee as hard, either: Rust's
 * `ClockOffset(i64)` has a module-private tuple field, so no code outside `clock_diagnostics.rs`
 * can construct one from a raw number at all, whereas this class's internal construction path
 * (see the `@internal` factory below) is technically reachable by any caller that imports this
 * class directly. That residual hole is exactly why `test/clock-source-guard.test.ts` ALSO scans
 * the artifact validity paths (`artifacts.ts`, `envelope.ts`) for the literal symbol
 * `ClockOffset` (and its siblings). The two defences are layered on purpose: neither is sufficient
 * alone.
 *
 * # Sign convention
 *
 * A `ClockDiagnosis` of kind `"ProvablyBehind"` carries an offset that is **positive seconds
 * behind** — the number of seconds the local clock must advance to reach the signed lower bound.
 * See {@link diagnoseClock}.
 *
 * The same convention extends to leg (2): {@link offsetFromDateHeader} computes
 * `serverTime - localNow`, so a local clock that is behind still yields a positive offset. Unlike
 * leg (1), though, leg (2) CAN prove the other direction — a local clock that is *ahead* of the
 * HTTPS source's `Date` header yields a **negative** offset. Leg (1) can never report negative (it
 * only ever compares local time against a lower bound it might be behind); leg (2) can, because it
 * compares against the source's own stated now rather than a one-sided bound. That provable
 * "ahead" direction is the whole reason §A10.42 offers leg (2) as an option.
 */
export class ClockOffset {
  readonly #seconds: bigint;

  private constructor(seconds: bigint) {
    this.#seconds = seconds;
  }

  /**
   * The offset in seconds, for DISPLAY AND LOGGING ONLY.
   *
   * §A10.42: this value MUST NOT be added to, subtracted from, or otherwise folded into any value
   * used as `now` in an artifact validity check. It exists so a client can say "your clock is 41
   * days behind" instead of repeating the uniform refusal message.
   */
  diagnosticSeconds(): bigint {
    return this.#seconds;
  }

  /**
   * @internal Constructs a `ClockOffset` from a raw signed-seconds value. Used only by
   * {@link diagnoseClock} and {@link offsetFromDateHeader} in this file — never call this
   * directly. Rust's twin makes external construction structurally impossible (a module-private
   * tuple field); TypeScript's `private` constructor only blocks `new ClockOffset(...)` from
   * outside this *class*, not from outside this *file*, so this factory is the closest this
   * language gets. See the class doc comment's "type-level speed bump, not a proof" section.
   */
  static internalFromSeconds(seconds: bigint): ClockOffset {
    return new ClockOffset(seconds);
  }
}

/**
 * What the local bound check could prove about the caller's clock (DESIGN.md §A10.42 leg (1)).
 *
 * This is a *diagnosis*, never a time value — see {@link ClockOffset} for why that distinction is
 * load-bearing.
 */
export type ClockDiagnosis =
  | {
      /**
       * Local time is earlier than a timestamp that was already signed, so the local clock is
       * PROVABLY behind true time by at least `behindBy` seconds. A certificate cannot have been
       * issued before it was signed, so `boundTs` is a hard lower bound on true time and no
       * honest clock can precede it.
       *
       * `behindBy` is positive seconds-behind; `boundTs` is the `max(op_cert.ts)` that produced
       * it, reported so a caller can show its basis rather than an unexplained number.
       */
      kind: "ProvablyBehind";
      behindBy: ClockOffset;
      boundTs: bigint;
    }
  | {
      /**
       * Local time is past `exp` for EVERY capability held. §A10.42 requires this be reported
       * honestly as ambiguous: the clock may be ahead, OR every membership genuinely expired.
       *
       * **The "clock is ahead" direction is NOT provable and must not be claimed.**
       * `@spindle/proto`'s `Capability` carries `exp`, never `ts` — without an issue time there is
       * nothing to compare local time *against* in that direction, so this variant states the two
       * possibilities and resolves neither.
       *
       * `latestCapExp` is the largest `exp` held — the point local time is past.
       */
      kind: "Ambiguous";
      latestCapExp: bigint;
    }
  | {
      /**
       * Nothing was proven. Either there was no signed lower bound to check against, or local
       * time sits at or after the bound with at least one capability still unexpired.
       *
       * This is explicitly NOT a clean bill of health for the clock: §A10.42's check is only as
       * tight as the age of the credentials on hand.
       */
      kind: "NoEvidenceOfSkew";
    };

/** `ClockDiagnosticError.kind` — mirrors Rust's `ClockDiagnosticError` enum, which has exactly
 * one variant today. */
export type ClockDiagnosticErrorKind = "MalformedOpCert";

/** Errors from {@link diagnoseClockFromCapabilities} (DESIGN.md §A10.42, td-7e3556). */
export class ClockDiagnosticError extends Error {
  readonly kind: ClockDiagnosticErrorKind;
  /** Set for `MalformedOpCert`: the index into `capabilities` whose embedded `op_cert` failed to
   * decode. Reported because a bundle holds many capabilities and "one of them is malformed" is
   * not an actionable message. */
  readonly index?: number;
  /** Set for `MalformedOpCert`: the underlying decode failure — mirrors `ArtifactError.malformedOpCert()`,
   * which fires on the same bytes in the verification path, except this variant keeps the
   * decode failure's own `ProtoError` around (Rust's `source: ProtoError` field) rather than
   * discarding it. */
  readonly source?: ProtoError;

  private constructor(kind: ClockDiagnosticErrorKind, message: string, extra?: { index?: number; source?: ProtoError }) {
    super(message);
    this.name = "ClockDiagnosticError";
    this.kind = kind;
    this.index = extra?.index;
    this.source = extra?.source;
  }

  static malformedOpCert(index: number, source: ProtoError): ClockDiagnosticError {
    return new ClockDiagnosticError(
      "MalformedOpCert",
      `capability at index ${index} has an op_cert that does not decode: ${source.message}`,
      { index, source },
    );
  }
}

function maxBigint(values: readonly bigint[]): bigint {
  let max = values[0];
  for (let i = 1; i < values.length; i++) {
    const v = values[i];
    if (v > max) max = v;
  }
  return max;
}

/**
 * The core local bound check, pure over plain integers (DESIGN.md §A10.42 leg (1)).
 *
 * `localNow` is the caller's Unix-seconds notion of now — this package never reads a clock.
 * `opCertTimestamps` are `HostOpKeyCert.ts` values the caller has ALREADY VERIFIED;
 * `capabilityExps` are `Capability.exp` values from the same bundle.
 *
 * Decision order, which is itself normative:
 *
 * 1. PROVABLY-BEHIND RUNS FIRST, because it is the only direction that can be proven. If both
 *    conditions hold at once, reporting the ambiguous one would throw away a fact in favour of a
 *    maybe.
 * 2. Ambiguous second, reported honestly as ambiguous (see the `"Ambiguous"` case above).
 * 3. Otherwise nothing was proven.
 *
 * # Empty input proves nothing
 *
 * An empty `opCertTimestamps` array means there is NO signed lower bound at all, so the
 * provably-behind leg is skipped entirely and, with no expired capabilities either, the result is
 * `"NoEvidenceOfSkew"`. That is the absence of evidence, not evidence of a good clock — an
 * attacker who could strip the bundle would otherwise be handed a clean verdict for free. Skipping
 * that leg does NOT suppress the ambiguous case: per §A10.42 the ambiguous case rests on `exp`
 * alone, so expired capabilities with no op-cert bound on hand still report `"Ambiguous"`.
 *
 * # Arithmetic — a deliberate divergence from the Rust twin
 *
 * Rust's `bound - local_now` is computed in `u64` and narrowed to `i64` with
 * `i64::try_from(..).unwrap_or(i64::MAX)` — SATURATING rather than wrapping, because a wrapped
 * value would print as a negative offset and read as "your clock is ahead", the one direction leg
 * (1) can never prove. `bigint` has no fixed width and never overflows or wraps, so there is
 * nothing here for a TypeScript twin to saturate: `bound - localNow` is always exact, for any
 * magnitude. This is a genuine, disclosed language-level divergence, not an oversight — the
 * *property* Rust's saturation protects (never silently flipping sign) holds here unconditionally
 * and by construction.
 */
export function diagnoseClock(
  localNow: bigint,
  opCertTimestamps: readonly bigint[],
  capabilityExps: readonly bigint[],
): ClockDiagnosis {
  // Checked first: this is the direction A10.42 can prove, so it wins over the ambiguous case. An
  // empty array is no signed lower bound at all, so this leg is skipped rather than faked — but
  // the ambiguous leg below still runs, since it rests on `exp` alone.
  if (opCertTimestamps.length > 0) {
    const bound = maxBigint(opCertTimestamps);
    if (localNow < bound) {
      return {
        kind: "ProvablyBehind",
        behindBy: ClockOffset.internalFromSeconds(bound - localNow),
        boundTs: bound,
      };
    }
  }

  // `every`, not `some`: one still-valid capability means expiry explains nothing about the clock.
  if (capabilityExps.length > 0 && capabilityExps.every((exp) => localNow > exp)) {
    return { kind: "Ambiguous", latestCapExp: maxBigint(capabilityExps) };
  }

  return { kind: "NoEvidenceOfSkew" };
}

/**
 * Runs {@link diagnoseClock} over a held bundle of verified artifacts (DESIGN.md §A10.42 leg (1),
 * td-7e3556).
 *
 * Collects the `ts` of every capability's embedded `op_cert` (decoded from `Capability.op_cert`'s
 * opaque canonical bytes), plus the `ts` of every certificate in `extraOpCerts`, plus every
 * capability's `exp`, and delegates the decision.
 *
 * `extraOpCerts` exists for the HOST path. td-7e3556 records the scope widening from td-e8b79f:
 * td-583db5 gave the host the same cold-bootstrap exposure the device has, and a host holds its
 * own `HostOpKeyCert` while it may hold no capabilities at all. Passing that certificate here
 * gives the host exactly the same check the device gets, through the same code.
 *
 * # This function verifies NOTHING
 *
 * It does NOT check a single signature. It reads `ts` out of bytes the caller must have ALREADY
 * VERIFIED — via `verifyCapability` and `verifyHostOpKeyCert` (`artifacts.ts`). If a caller passes
 * unverified input, the "signed lower bound" property does not hold and the resulting diagnosis is
 * attacker-controlled.
 *
 * The blast radius of a false diagnosis is bounded on purpose: this is a *diagnostic*, so the
 * worst outcome is a WRONG MESSAGE, never an acceptance of an expired or revoked artifact. That is
 * precisely why the return type is a `ClockDiagnosis` and not a time value — there is no path from
 * this output into any validity check (see {@link ClockOffset}).
 *
 * @throws {ClockDiagnosticError} if any capability's embedded `op_cert` fails to decode as a
 * `HostOpKeyCert` — the error names the offending index.
 */
export function diagnoseClockFromCapabilities(
  localNow: bigint,
  capabilities: readonly Capability[],
  extraOpCerts: readonly HostOpKeyCert[],
): ClockDiagnosis {
  const opCertTimestamps: bigint[] = [];
  const capabilityExps: bigint[] = [];

  for (let index = 0; index < capabilities.length; index++) {
    const cap = capabilities[index];
    let opCert: HostOpKeyCert;
    try {
      opCert = HostOpKeyCert.fromCanonicalBytes(cap.op_cert);
    } catch (e) {
      if (!(e instanceof ProtoError)) throw e;
      throw ClockDiagnosticError.malformedOpCert(index, e);
    }
    opCertTimestamps.push(opCert.ts);
    capabilityExps.push(cap.exp);
  }
  for (const cert of extraOpCerts) {
    opCertTimestamps.push(cert.ts);
  }

  return diagnoseClock(localNow, opCertTimestamps, capabilityExps);
}

/**
 * A caller-supplied source of an operator-configured HTTPS endpoint's `Date` response header
 * (DESIGN.md §A10.42 leg (2), td-7e3556).
 *
 * `@spindle/crypto` takes no HTTP dependency to support this leg: the caller already owns a
 * transport (HTTP client, TLS stack, DNS resolution, endpoint configuration, retry policy) for
 * whatever else it talks to over the network, and is trusted to make one more request with it.
 * This interface asks for only the resulting raw header value, so the caller's transport error
 * type never has to be named in — or depend on — this package's public API.
 */
export interface HttpsDateSource {
  /**
   * Fetches the raw `Date` response-header value from the configured HTTPS endpoint.
   *
   * Implementations own making the request, confirming the response actually carried a `Date`
   * header, and folding any failure (DNS, TLS, timeout, non-2xx, missing header) into an
   * {@link HttpsDateSourceError} rejection. This interface does not see or judge the request in
   * any other way — it is not told the endpoint, and it does not retry.
   *
   * *Raw* means raw: leading and trailing RFC 9110 `OWS` may be left on, because
   * {@link offsetFromDateHeader} trims it. An implementation that trims anyway is equally correct
   * — this is a promise that forgetting to cannot lose the diagnostic, not a request to forget.
   *
   * Returns a `Promise`, not a synchronous value: every I/O-shaped seam in this package is async
   * (see `verifyCapability` and friends in `artifacts.ts`), and a real fetch is async.
   */
  fetchDateHeader(): Promise<string>;
}

/**
 * An opaque transport failure from an {@link HttpsDateSource} (DESIGN.md §A10.42 leg (2),
 * td-7e3556).
 *
 * Deliberately just an owned message: the caller's transport type (an HTTP client's error class, a
 * TLS error, a timeout type, ...) must not leak into this package's public API, the same way
 * `ClockDiagnosticError.source` carries a `ProtoError` it already owns rather than naming
 * something from further up the stack. This carries enough for a log line and nothing else.
 */
export class HttpsDateSourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HttpsDateSourceError";
  }
}

/** `DateHeaderError.kind` — mirrors Rust's `DateHeaderError` enum, one variant per case. */
export type DateHeaderErrorKind =
  | "InvalidLength"
  | "InvalidFormat"
  | "UnknownDayName"
  | "UnknownMonth"
  | "NonDigit"
  | "FieldOutOfRange"
  | "InvalidDayOfMonth"
  | "BeforeUnixEpoch"
  | "ObsoleteFormat"
  | "NonAscii";

/**
 * Errors from parsing a `Date` header value as strict IMF-fixdate (DESIGN.md §A10.42 leg (2),
 * RFC 9110 §5.6.7, td-7e3556).
 *
 * This parser is deliberately stricter than RFC 9110 requires of a general HTTP RECIPIENT (which
 * must also accept the obsolete RFC 850 and asctime forms). It backs an operator-configured
 * diagnostic endpoint, not a general-purpose HTTP client: refusing an unexpected form means no
 * diagnostic is produced, which is a safe failure, never an unsafe one.
 */
export class DateHeaderError extends Error {
  readonly kind: DateHeaderErrorKind;
  /** Set for `InvalidLength`. */
  readonly len?: number;
  /** Set for `BeforeUnixEpoch`. */
  readonly year?: number;
  /** Set for `ObsoleteFormat`. */
  readonly form?: string;

  private constructor(
    kind: DateHeaderErrorKind,
    message: string,
    extra?: { len?: number; year?: number; form?: string },
  ) {
    super(message);
    this.name = "DateHeaderError";
    this.kind = kind;
    this.len = extra?.len;
    this.year = extra?.year;
    this.form = extra?.form;
  }

  /** The header was not exactly 29 code units — IMF-fixdate's fixed length. Checked (after the
   * ASCII gate) before anything is sliced. */
  static invalidLength(len: number): DateHeaderError {
    return new DateHeaderError("InvalidLength", `Date header is ${len} bytes, IMF-fixdate is always exactly 29`, {
      len,
    });
  }
  /** One of the fixed-position separators (spaces, the comma, the colons, or the literal `GMT`)
   * did not match IMF-fixdate's exact layout. */
  static invalidFormat(): DateHeaderError {
    return new DateHeaderError("InvalidFormat", "Date header does not match IMF-fixdate's fixed layout");
  }
  /** The three-letter day-of-week name is not one of the seven English abbreviations.
   *
   * Note what this does NOT check: the day-of-week is never cross-checked against the computed
   * date, even though it is present and well-formed. RFC 9110 makes that redundant, so a mismatch
   * is a server bug, not a fact worth refusing a diagnostic over. */
  static unknownDayName(): DateHeaderError {
    return new DateHeaderError(
      "UnknownDayName",
      "Date header's day-of-week name is not a recognized three-letter abbreviation",
    );
  }
  /** The three-letter month name is not one of the twelve English abbreviations. */
  static unknownMonth(): DateHeaderError {
    return new DateHeaderError(
      "UnknownMonth",
      "Date header's month name is not a recognized three-letter abbreviation",
    );
  }
  /** A numeric field (day, year, hour, minute, or second) contained a non-digit character. */
  static nonDigit(): DateHeaderError {
    return new DateHeaderError("NonDigit", "Date header contains a non-digit byte in a numeric field");
  }
  /** Hour, minute, or second was outside its valid range (`HH<=23`, `MM<=59`, `SS<=60`). */
  static fieldOutOfRange(): DateHeaderError {
    return new DateHeaderError("FieldOutOfRange", "Date header's time-of-day field is out of range");
  }
  /** The day-of-month exceeded the named month's real length, accounting for the full Gregorian
   * leap rule (`y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0)`). */
  static invalidDayOfMonth(): DateHeaderError {
    return new DateHeaderError("InvalidDayOfMonth", "Date header's day-of-month does not exist in that month/year");
  }
  /** The year is before 1970. This parser produces Unix seconds, which cannot represent an instant
   * before the epoch. */
  static beforeUnixEpoch(year: number): DateHeaderError {
    return new DateHeaderError("BeforeUnixEpoch", `Date header's year ${year} is before the Unix epoch (1970)`, {
      year,
    });
  }
  /** The header used one of the obsolete RFC 850 or asctime date forms instead of IMF-fixdate.
   *
   * RFC 9110 requires a general HTTP recipient to also accept obs-date, but this parser backs an
   * operator-configured diagnostic endpoint, not a general HTTP client: a strict parser that
   * refuses an obsolete form is a safe failure (no diagnostic produced), not an unsafe one, so this
   * is rejected by name rather than tolerated. */
  static obsoleteFormat(form: string): DateHeaderError {
    return new DateHeaderError("ObsoleteFormat", `Date header uses the obsolete ${form} form, not IMF-fixdate`, {
      form,
    });
  }
  /** The header contained a character outside the ASCII range. IMF-fixdate (and both obsolete
   * forms) are ASCII by definition, so this is checked before any of the obsolete-format
   * pre-checks or the fixed-position layout checks below index into the string — a multi-code-unit
   * character must never be misread as matching (or nearly matching) a fixed position. */
  static nonAscii(): DateHeaderError {
    return new DateHeaderError("NonAscii", "Date header contains a non-ASCII byte");
  }
}

/** `HttpsDateError.kind` — mirrors Rust's `HttpsDateError` enum. */
export type HttpsDateErrorKind = "Source" | "Parse";

/** Errors from {@link diagnoseClockFromHttps} (DESIGN.md §A10.42 leg (2), td-7e3556). */
export class HttpsDateError extends Error {
  readonly kind: HttpsDateErrorKind;
  /** Set for `Source`: the {@link HttpsDateSource} itself failed — DNS, TLS, timeout, or a
   * response with no `Date` header. Propagated rather than swallowed: leg (2) is optional, but a
   * caller that asked for it deserves to know its source failed rather than receiving an
   * indistinguishable "nothing to report". */
  readonly source?: HttpsDateSourceError;
  /** Set for `Parse`: the fetched `Date` header value did not parse as strict IMF-fixdate. */
  readonly parseError?: DateHeaderError;

  private constructor(
    kind: HttpsDateErrorKind,
    message: string,
    extra?: { source?: HttpsDateSourceError; parseError?: DateHeaderError },
  ) {
    super(message);
    this.name = "HttpsDateError";
    this.kind = kind;
    this.source = extra?.source;
    this.parseError = extra?.parseError;
  }

  static source(source: HttpsDateSourceError): HttpsDateError {
    return new HttpsDateError("Source", `fetching the configured HTTPS Date source failed: ${source.message}`, {
      source,
    });
  }
  static parse(parseError: DateHeaderError): HttpsDateError {
    return new HttpsDateError(
      "Parse",
      `the configured HTTPS Date source's Date header did not parse: ${parseError.message}`,
      { parseError },
    );
  }
}

/** The three-letter English day-of-week abbreviations IMF-fixdate requires, in no particular
 * order — see {@link DateHeaderError.unknownDayName} for why a match here is required but never
 * cross-checked against the computed date. */
const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/** The seven FULL English day-of-week names RFC 850's obs-date form uses, in no particular order.
 * Distinguishing feature versus IMF-fixdate's three-letter {@link DAY_NAMES}: a full day name is
 * exactly what identifies obs-date's first token, so this is the basis for deciding whether a
 * misplaced comma actually indicates RFC 850 rather than arbitrary garbage — see
 * `parseImfFixdate`. */
const FULL_DAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** The twelve three-letter English month abbreviations IMF-fixdate requires, in calendar order —
 * index `i` is month `i + 1`. */
const MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const RFC_850_FORM = 'RFC 850 (obs-date), e.g. "Sunday, 06-Nov-94 08:49:37 GMT"';
const ASCTIME_FORM = 'asctime, e.g. "Sun Nov  6 08:49:37 1994"';

/** Parses an ASCII digit run into a `number`, or `undefined` if any character is not `0`-`9`. */
function parseDigits(digits: string): number | undefined {
  let value = 0;
  for (let i = 0; i < digits.length; i++) {
    const code = digits.charCodeAt(i);
    if (code < 0x30 || code > 0x39) return undefined;
    value = value * 10 + (code - 0x30);
  }
  return value;
}

/** The number of days in `month` (1-based) of Gregorian year `year`, with the full leap rule
 * (`y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0)`) applied to February. */
function daysInMonth(year: number, month: number): number {
  switch (month) {
    case 1:
    case 3:
    case 5:
    case 7:
    case 8:
    case 10:
    case 12:
      return 31;
    case 4:
    case 6:
    case 9:
    case 11:
      return 30;
    case 2:
      return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
    default:
      // Unreachable: month is always produced from a validated MONTH_NAMES index (1..=12).
      throw new Error("daysInMonth: month must be 1..=12");
  }
}

/** Days since the Unix epoch (1970-01-01) for a Gregorian calendar date — Howard Hinnant's
 * days-from-civil algorithm, exact for every Gregorian date and needing no lookup table. Ported
 * directly from `spindle-core`'s `days_from_civil`; the `y < 0` branch is dead code here exactly
 * as it is there, since `parseImfFixdate` already rejects `year < 1970` before this is called —
 * kept for fidelity with the Rust twin rather than trimmed as unreachable. */
function daysFromCivil(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor((yy >= 0 ? yy : yy - 399) / 400);
  const yoe = yy - era * 400; // [0, 399]
  const doy = Math.floor((153 * (m > 2 ? m - 3 : m + 9) + 2) / 5) + d - 1; // [0, 365]
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy; // [0, 146096]
  return era * 146097 + doe - 719468;
}

/**
 * Parses `dateHeader` as strict RFC 9110 §5.6.7 IMF-fixdate — `Www, DD Mon YYYY HH:MM:SS GMT`,
 * exactly 29 ASCII characters — into Unix seconds.
 *
 * Operates on UTF-16 code units throughout (JavaScript's native string-indexing unit), with the
 * ASCII check first, so a multi-code-unit / non-ASCII input can never produce a wrong length or
 * mis-index a fixed position: every index taken below is either checked immediately beforehand or
 * follows from a length that was already confirmed exact. Rust's twin operates on UTF-8 bytes and
 * had a real out-of-bounds panic here (a 7-byte header, fixed by requiring `bytes.len() >= 8`
 * before reading `bytes[7]` in the asctime pre-check) — the same `length >= 8` guard is carried
 * over below for the equivalent reason, even though JavaScript indexing past the end of a string
 * returns `undefined` rather than throwing: an unguarded comparison against `undefined` would
 * silently fail to match rather than panic, which is a *quieter* bug, not a safer one, so the
 * explicit length guard stays.
 */
function parseImfFixdate(dateHeader: string): bigint {
  // ASCII gate first, before any length check or indexing at all. IMF-fixdate (and both obsolete
  // forms) are ASCII by definition; gating here keeps a non-ASCII character from ever being
  // misread as matching — or nearly matching — one of the fixed positions checked below.
  for (let i = 0; i < dateHeader.length; i++) {
    if (dateHeader.charCodeAt(i) > 0x7f) throw DateHeaderError.nonAscii();
  }

  // Detect the two obsolete forms up front, before the length check below, so each is reported by
  // name rather than folded into a generic "wrong length" error. Both are structurally
  // distinguishable from IMF-fixdate:
  //   - RFC 850 ("Sunday, 06-Nov-94 08:49:37 GMT") uses a FULL day name, so this only fires when
  //     the text before the comma is actually one of the seven full English day names — otherwise
  //     an arbitrary misplaced comma would be misattributed to RFC 850 instead of falling through
  //     to the ordinary length/format errors below.
  //   - asctime ("Sun Nov  6 08:49:37 1994") has no comma at all, and instead butts a three-letter
  //     day name directly against a three-letter month name across two spaces. The guard reads
  //     index 7 (the highest one it needs), so it requires `length >= 8`, not 7.
  const commaPos = dateHeader.indexOf(",");
  if (commaPos !== -1) {
    if (FULL_DAY_NAMES.includes(dateHeader.slice(0, commaPos))) {
      throw DateHeaderError.obsoleteFormat(RFC_850_FORM);
    }
  } else if (
    dateHeader.length >= 8 &&
    dateHeader[3] === " " &&
    dateHeader[7] === " " &&
    DAY_NAMES.includes(dateHeader.slice(0, 3)) &&
    MONTH_NAMES.includes(dateHeader.slice(4, 7))
  ) {
    throw DateHeaderError.obsoleteFormat(ASCTIME_FORM);
  }

  if (dateHeader.length !== 29) throw DateHeaderError.invalidLength(dateHeader.length);

  if (
    dateHeader[3] !== "," ||
    dateHeader[4] !== " " ||
    dateHeader[7] !== " " ||
    dateHeader[11] !== " " ||
    dateHeader[16] !== " " ||
    dateHeader[19] !== ":" ||
    dateHeader[22] !== ":" ||
    dateHeader[25] !== " " ||
    dateHeader.slice(26, 29) !== "GMT"
  ) {
    throw DateHeaderError.invalidFormat();
  }

  if (!DAY_NAMES.includes(dateHeader.slice(0, 3))) throw DateHeaderError.unknownDayName();

  const monthIndex = MONTH_NAMES.indexOf(dateHeader.slice(8, 11));
  if (monthIndex === -1) throw DateHeaderError.unknownMonth();
  const month = monthIndex + 1;

  const day = parseDigits(dateHeader.slice(5, 7));
  const year = parseDigits(dateHeader.slice(12, 16));
  const hour = parseDigits(dateHeader.slice(17, 19));
  const minute = parseDigits(dateHeader.slice(20, 22));
  let second = parseDigits(dateHeader.slice(23, 25));
  if (day === undefined || year === undefined || hour === undefined || minute === undefined || second === undefined) {
    throw DateHeaderError.nonDigit();
  }

  if (year < 1970) throw DateHeaderError.beforeUnixEpoch(year);
  if (hour > 23 || minute > 59 || second > 60) throw DateHeaderError.fieldOutOfRange();
  // Second 60 is a leap second. POSIX time has no representation for it, and a one-second error in
  // a diagnostic value is immaterial — refusing the whole header over it would be worse than the
  // second of slop this clamp introduces.
  if (second === 60) second = 59;

  if (day === 0 || day > daysInMonth(year, month)) throw DateHeaderError.invalidDayOfMonth();

  const daysSinceEpoch = daysFromCivil(year, month, day);
  return BigInt(daysSinceEpoch) * 86_400n + BigInt(hour) * 3600n + BigInt(minute) * 60n + BigInt(second);
}

/**
 * Strips leading and trailing RFC 9110 `OWS` (`OWS = *( SP / HTAB )`) and nothing else.
 *
 * Deliberately not `String.prototype.trim`, which also strips `\n`, `\r`, `\f`, `\v`, U+00A0,
 * and the rest of Unicode's whitespace: those are not `OWS`, and silently accepting them would
 * widen what counts as a well-formed `Date` header past what RFC 9110 says it is.
 */
function trimOws(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && (value[start] === " " || value[start] === "\t")) start += 1;
  while (end > start && (value[end - 1] === " " || value[end - 1] === "\t")) end -= 1;
  return value.slice(start, end);
}

/**
 * The pure core of leg (2) (DESIGN.md §A10.42, td-7e3556): parses `dateHeader` as strict
 * IMF-fixdate and computes its offset against `localNow`. No clock, no I/O, no dependency —
 * testable with plain string literals.
 *
 * # Sign convention
 *
 * `offset = serverTime - localNow`, matching leg (1) — see {@link ClockOffset}'s "Sign convention"
 * section for the full statement, including the negative (locally-ahead) case this leg can prove
 * and leg (1) cannot.
 *
 * # Leading and trailing OWS is trimmed here, not by the caller
 *
 * RFC 9110 permits optional whitespace (`SP` / `HTAB`) around a field value, and an HTTP client
 * may hand it over untrimmed. {@link HttpsDateSource} asks for the *raw* header value, so this
 * function owns the trim rather than making every implementer remember it. Only ASCII `SP` and
 * `HTAB` are trimmed — not `String.prototype.trim`'s full Unicode whitespace set, since a
 * non-ASCII character in this header is a malformed header and must reach
 * {@link DateHeaderError} as such, not be quietly stripped.
 *
 * The failure this prevents is silent: an untrimmed header fails the fixed-length check, yields no
 * offset, and an absent diagnostic looks exactly like a healthy clock. Rust's twin trims
 * identically (`clock_diagnostics.rs`, `offset_from_date_header`).
 *
 * # Arithmetic — see {@link diagnoseClock}'s "Arithmetic" section
 *
 * Rust's twin narrows both `serverUnix` and `localNow` into `i64` with explicit
 * `i64::try_from`/`saturating_sub`, even though a 4-digit year keeps both comfortably inside `i64`
 * range, "exactly as it does for leg (1), and for the same reason". `bigint` has no fixed width,
 * so `serverUnix - localNow` is always exact here — the same disclosed divergence as leg (1)'s,
 * not a separate one.
 */
export function offsetFromDateHeader(localNow: bigint, dateHeader: string): ClockOffset {
  const serverUnix = parseImfFixdate(trimOws(dateHeader));
  return ClockOffset.internalFromSeconds(serverUnix - localNow);
}

/**
 * Ties {@link HttpsDateSource} and {@link offsetFromDateHeader} together (DESIGN.md §A10.42
 * leg (2), td-7e3556): fetches the `Date` header from `source` and computes its offset against
 * `localNow`.
 *
 * # This is diagnostic only — TLS authenticates the server, not the time
 *
 * An operator-configured HTTPS endpoint proves only that whoever holds that endpoint's TLS
 * certificate said what time it is, not that the time is correct. Folding this value into a
 * signing time, an `exp` check, or a revocation check would turn a safe refusal (a wrong or
 * compromised clock) into an ACCEPTANCE of an expired or revoked artifact — precisely the hazard
 * {@link ClockOffset}'s doc comment describes for leg (1), and the reason this returns the same
 * non-convertible `ClockOffset` type leg (1) does.
 *
 * @throws {HttpsDateError} of kind `"Source"` if `source.fetchDateHeader()` rejects, or kind
 * `"Parse"` if the fetched header does not parse as strict IMF-fixdate. The transport failure is
 * always propagated as an error — never swallowed into a default offset.
 */
export async function diagnoseClockFromHttps(localNow: bigint, source: HttpsDateSource): Promise<ClockOffset> {
  let dateHeader: string;
  try {
    dateHeader = await source.fetchDateHeader();
  } catch (e) {
    const sourceError = e instanceof HttpsDateSourceError ? e : new HttpsDateSourceError(String(e));
    throw HttpsDateError.source(sourceError);
  }

  try {
    return offsetFromDateHeader(localNow, dateHeader);
  } catch (e) {
    if (!(e instanceof DateHeaderError)) throw e;
    throw HttpsDateError.parse(e);
  }
}
