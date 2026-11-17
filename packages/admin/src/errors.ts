// Errors raised by @spindle/admin. One class with a `kind` discriminant, matching the idiom of
// `@spindle/proto`'s `ProtoError` and `@spindle/crypto`'s `ArtifactError`.
//
// REDACTION: no message produced here ever interpolates peer-supplied content, key material, a
// nonce, a signature, or command payload bytes. Specifically:
//   - `Refused` carries the helper's `code`/`detail` as *fields*, never in `.message`; a helper
//     that echoed a secret in its refusal detail therefore cannot get it into a log line that
//     records `String(err)`.
//   - `Transport` carries the underlying error as `cause` (which `Error.prototype.toString`
//     does not include) and a fixed `.message`.
//   - every length/value diagnostic reports field names and lengths only.
// This package has no logging call sites (same as @spindle/proto and @spindle/crypto), so there is
// no separate redaction guard to mirror yet.

/** Every failure mode this library can surface. */
export type AdminErrorKind =
  /** `buildAdminCommand` was called with an empty (or whitespace-only) command name. */
  | "EmptyCommand"
  /** An admin command name outside the documented A3b/ADR-007 surface. */
  | "UnknownCommand"
  /** A subject outside `registry.admin.<documented-command>`. */
  | "InvalidSubject"
  /** A fixed-length field was the wrong size (signer_fp, nonce, signatures, keys). */
  | "WrongLength"
  /** A structurally invalid value (non-integer/out-of-range `v`, `seq`, or `ts`). */
  | "InvalidValue"
  /** `v` below `ADMIN_COMMAND_MIN_V`. */
  | "VersionTooLow"
  /** `v` above `ADMIN_COMMAND_CURRENT_V`. */
  | "VersionTooHigh"
  /** `signer_fp` does not name the identity the configured `Signer` signs as. */
  | "SignerFingerprintMismatch"
  /** A reply was not the documented canonical-CBOR reply envelope. */
  | "MalformedReply"
  /** The helper answered `ok: false`; `code`/`detail` carry its refusal. */
  | "Refused"
  /** The transport itself failed; `cause` carries the original error. */
  | "Transport";

/** Errors from this package. See the module comment for the redaction rule every `.message`
 * obeys. */
export class AdminError extends Error {
  readonly kind: AdminErrorKind;
  /** Set for `WrongLength`, `InvalidValue`. */
  readonly field?: string;
  /** Set for `WrongLength`. */
  readonly expected?: number;
  /** Set for `WrongLength`. */
  readonly actual?: number;
  /** Set for `VersionTooLow`/`VersionTooHigh`. */
  readonly found?: number;
  /** Set for `VersionTooLow`. */
  readonly minimum?: number;
  /** Set for `VersionTooHigh`. */
  readonly maximum?: number;
  /** Set for `Refused`: the helper's refusal code, verbatim (peer-supplied; never in `.message`). */
  readonly code?: string;
  /** Set for `Refused`: the helper's refusal detail, verbatim (peer-supplied; never in
   * `.message` — do not log this field unredacted). */
  readonly detail?: string;
  /** Set for `Transport`: the subject the request was published on. */
  readonly subject?: string;

  private constructor(
    kind: AdminErrorKind,
    message: string,
    extra?: {
      field?: string;
      expected?: number;
      actual?: number;
      found?: number;
      minimum?: number;
      maximum?: number;
      code?: string;
      detail?: string;
      subject?: string;
      cause?: unknown;
    },
  ) {
    super(message);
    this.name = "AdminError";
    this.kind = kind;
    this.field = extra?.field;
    this.expected = extra?.expected;
    this.actual = extra?.actual;
    this.found = extra?.found;
    this.minimum = extra?.minimum;
    this.maximum = extra?.maximum;
    this.code = extra?.code;
    this.detail = extra?.detail;
    this.subject = extra?.subject;
    if (extra?.cause !== undefined) this.cause = extra.cause;
  }

  static emptyCommand(): AdminError {
    return new AdminError("EmptyCommand", "admin command name must not be empty");
  }

  static unknownCommand(): AdminError {
    return new AdminError("UnknownCommand", "admin command is not part of the documented A3b surface");
  }

  static invalidSubject(): AdminError {
    return new AdminError(
      "InvalidSubject",
      "subject is not one of the documented registry.admin.<command> subjects",
    );
  }

  static wrongLength(field: string, expected: number, actual: number): AdminError {
    return new AdminError(
      "WrongLength",
      `field \`${field}\` must be exactly ${expected} bytes (got ${actual})`,
      { field, expected, actual },
    );
  }

  static invalidValue(field: string): AdminError {
    return new AdminError("InvalidValue", `field \`${field}\` is structurally invalid`, { field });
  }

  static versionTooLow(found: number, minimum: number): AdminError {
    return new AdminError(
      "VersionTooLow",
      `admin command version ${found} is below the minimum ${minimum}`,
      { found, minimum },
    );
  }

  static versionTooHigh(found: number, maximum: number): AdminError {
    return new AdminError(
      "VersionTooHigh",
      `admin command version ${found} is above the known maximum ${maximum}`,
      { found, maximum },
    );
  }

  static signerFingerprintMismatch(): AdminError {
    return new AdminError(
      "SignerFingerprintMismatch",
      "signer_fp does not name the identity the configured signer signs as",
    );
  }

  static malformedReply(): AdminError {
    return new AdminError("MalformedReply", "malformed admin reply");
  }

  /** A helper refusal. `code`/`detail` are stored verbatim as fields but deliberately omitted
   * from `.message` — see the module's redaction rule. */
  static refused(code: string, detail?: string): AdminError {
    return new AdminError("Refused", "admin command refused by helper", { code, detail });
  }

  /** A transport failure. The original error is preserved as `cause`, not folded into the
   * message, so a transport that includes payload bytes in its own error text cannot leak them
   * through `String(err)`. */
  static transport(subject: string, cause: unknown): AdminError {
    return new AdminError("Transport", "admin transport request failed", { subject, cause });
  }
}
