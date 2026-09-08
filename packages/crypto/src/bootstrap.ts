// Build and verify the device bootstrap state bundle (DESIGN.md §A4 "Adding a device (device
// bootstrap)", :317-330; see also `@spindle/proto`'s `bootstrap.ts` module doc for why this bundle
// is unsigned and NOT one of A7b's eight signed artifacts) — the TypeScript twin of
// `crates/spindle-core/src/artifacts/bootstrap.rs`. `@spindle/proto` carries the wire shape only
// (A9c boundary rule 3: it has zero crypto dependencies); everything that touches a key or a
// hash — building a real bundle, verifying one, and deriving `hostFp` and each host's
// `hostDeviceFp` — lives here.
//
// Neither derived value is ever present on the wire (DESIGN.md :320-322: "derived, never
// carried ... so no field of an entry can disagree with another"):
// - `hostFp = SHA-256(memberCap.host_root_pk)` — the same check `verifyCapability`'s step 1
//   already performs.
// - `hostDeviceFp = deviceFpOf(ALG_ID_V1, sign_pk, agree_pk)`.
//
// Unlike its Rust twin (which is synchronous throughout), every exported function here is
// `async`: deriving a fingerprint goes through this package's promise-based crypto backend
// (WebCrypto with a `@noble/curves`/`@noble/hashes` fallback — see `backend.ts`), the same reason
// `verifyCapability` and friends in `artifacts.ts` are `async`.

import {
  BUNDLE_CURRENT_V,
  BUNDLE_MIN_V,
  BundleEntry,
  Capability,
  DeviceBootstrapBundle,
  MAX_BUNDLE_ENTRIES,
  QR_V40_L_CAPACITY_BYTES,
  QR_V40_M_CAPACITY_BYTES,
} from "@spindle/proto";

import { ArtifactError, verifyCapability } from "./artifacts.js";
import { deviceFpOf, rootFpOf } from "./fingerprint.js";

/** The `alg_id` suite version byte (DESIGN.md §A4): `1` = Ed25519 / X25519 / AES-256-GCM. Mirrors
 * `spindle-core::identity::ALG_ID_V1` and `artifacts.ts`'s own (unexported) constant of the same
 * name and value — duplicated here rather than imported because `artifacts.ts` does not export
 * it. */
const ALG_ID_V1 = 1;

/** `pk.length === 32`, thrown as `ArtifactError.invalidPublicKey()` on mismatch — the same
 * length-only check `artifacts.ts`'s `verifyHostDeviceCert` applies to `sign_pk`/`agree_pk` (see
 * that function's doc comment: this package does not separately validate Ed25519/X25519
 * curve-point well-formedness beyond length, leaving malformed-but-right-length bytes to fail
 * whichever signature or key-agreement operation actually uses them). Duplicated here rather than
 * imported because `artifacts.ts` does not export its own copy. */
function requirePublicKeyLen(pk: Uint8Array): void {
  if (pk.length !== 32) throw ArtifactError.invalidPublicKey();
}

// ================================================================================================
// QrEcLevel
// ================================================================================================

/** Which ISO/IEC 18004 version-40 QR error-correction level a bundle is being sized for — mirrors
 * Rust's `QrEcLevel` enum. Both byte-mode data capacities are spec constants re-exported from
 * `@spindle/proto` (`QR_V40_L_CAPACITY_BYTES`/`QR_V40_M_CAPACITY_BYTES`), not measurements of this
 * package's own output — see `buildBootstrapBundle`'s doc comment for how the real encoding is
 * checked against them. */
export type QrEcLevel = "L" | "M";

/** `QrEcLevel`'s companion namespace. TypeScript has no way to attach an instance method
 * (`ecLevel.budgetBytes()`) to a string-literal union the way Rust attaches one to its `enum`, so
 * `budgetBytes` is a static function here instead — the same "impl namespace" convention
 * `@spindle/proto`'s `BundleEntry`/`DeviceBootstrapBundle` already use for their own methods. */
export const QrEcLevel = {
  L: "L" as QrEcLevel,
  M: "M" as QrEcLevel,

  /** The byte-mode data capacity for this EC level, at QR version 40 (the largest QR version). */
  budgetBytes(level: QrEcLevel): number {
    switch (level) {
      case "L":
        return QR_V40_L_CAPACITY_BYTES;
      case "M":
        return QR_V40_M_CAPACITY_BYTES;
    }
  },
};

// ================================================================================================
// BundleError
// ================================================================================================

/** Errors from building or verifying a `DeviceBootstrapBundle`. Unlike `ArtifactError` (the A7b
 * signed-artifact catalog's error type), this one also covers the QR fit check, which has no
 * equivalent among the signed artifacts. Mirrors Rust's `BundleError` enum. */
export type BundleErrorKind = "VersionTooLow" | "TooManyEntries" | "Entry" | "TooLargeForQr";

export class BundleError extends Error {
  readonly kind: BundleErrorKind;
  /** Set for `VersionTooLow`. */
  readonly found?: number;
  /** Set for `VersionTooLow`. */
  readonly minimum?: number;
  /** Set for `TooManyEntries`. */
  readonly max?: number;
  /** Set for `Entry`. */
  readonly index?: number;
  /** Set for `Entry`. */
  readonly source?: ArtifactError;
  /** Set for `TooLargeForQr`. */
  readonly ecLevel?: QrEcLevel;
  /** Set for `TooLargeForQr`. */
  readonly budgetBytes?: number;
  /** Set for `TooLargeForQr`. */
  readonly encodedBytes?: number;
  /** Set for `TooLargeForQr`. */
  readonly fits?: number;
  /** Set for `TooLargeForQr` — the `hostFp` of every entry beyond the fitting prefix, in order.
   * See {@link BundleError.tooLargeForQr}'s doc comment for the redaction discipline governing
   * this field vs. this error's own `message`. */
  readonly dropped?: Uint8Array[];

  private constructor(
    kind: BundleErrorKind,
    message: string,
    extra?: {
      found?: number;
      minimum?: number;
      max?: number;
      index?: number;
      source?: ArtifactError;
      ecLevel?: QrEcLevel;
      budgetBytes?: number;
      encodedBytes?: number;
      fits?: number;
      dropped?: Uint8Array[];
    },
  ) {
    super(message);
    this.name = "BundleError";
    this.kind = kind;
    this.found = extra?.found;
    this.minimum = extra?.minimum;
    this.max = extra?.max;
    this.index = extra?.index;
    this.source = extra?.source;
    this.ecLevel = extra?.ecLevel;
    this.budgetBytes = extra?.budgetBytes;
    this.encodedBytes = extra?.encodedBytes;
    this.fits = extra?.fits;
    this.dropped = extra?.dropped;
  }

  /** `verifyBootstrapBundle`: the bundle's own `v` is below `BUNDLE_MIN_V` — checked once, before
   * touching any entry (mirrors `verifyCapability`'s "cheapest rejection first" ordering). A
   * distinct kind from `ArtifactErrorKind`'s `"VersionTooLow"` rather than a reuse of it: the
   * bundle is not an A7b signed artifact (see `bootstrap.ts`'s module doc comment), so its version
   * floor is not an `ArtifactError` concern. */
  static versionTooLow(found: number, minimum: number): BundleError {
    return new BundleError(
      "VersionTooLow",
      `bundle version ${found} is below the minimum ${minimum}`,
      { found, minimum },
    );
  }

  /** `buildBootstrapBundle` / `verifyBootstrapBundle`: `entries.length` exceeds
   * `MAX_BUNDLE_ENTRIES` (DESIGN.md :329's 32-host presentation cap). Checked before any
   * per-entry or QR-fit work in both directions. */
  static tooManyEntries(found: number, max: number): BundleError {
    return new BundleError(
      "TooManyEntries",
      `bundle has ${found} entries, exceeding the ${max}-entry cap`,
      { found, max },
    );
  }

  /** `verifyBootstrapBundle`: entry `index` failed verification. `source` is whichever
   * `ArtifactError` the per-entry checks produced — bad key encoding, a failed
   * `verifyCapability`, or a `hostFp` derivation failure. */
  static entry(index: number, source: ArtifactError): BundleError {
    const message = `bundle entry ${index} failed verification: ${source.message}`;
    return new BundleError("Entry", message, { index, source });
  }

  /** `buildBootstrapBundle`: the bundle's real canonical encoding exceeds `ecLevel`'s budget even
   * after every candidate prefix length was tried. `fits` is the largest number of leading entries
   * that DOES fit; `dropped` names every host beyond that prefix, in order.
   *
   * REDACTION DISCIPLINE (this repo fixed three fingerprint-display leaks like this one
   * recently — see the Rust twin's `BundleError::TooLargeForQr` doc comment and
   * `fingerprint.ts`'s `base32EncodeNoPad`): a fingerprint's base32 form is display-only and is
   * exactly what would reach a log line if this error's `message` ever echoed it. This factory's
   * `message` therefore reports only `dropped.length` — a COUNT — and NEVER a dropped
   * fingerprint's bytes or their base32 rendering. `dropped` still carries the actual fingerprint
   * bytes on the error object itself, for the UI to render to the person doing the enrollment
   * ("Alex, Office NAS, and 2 more didn't fit — re-invite from Settings"); it must never be
   * interpolated into `message`. */
  static tooLargeForQr(params: {
    ecLevel: QrEcLevel;
    budgetBytes: number;
    encodedBytes: number;
    fits: number;
    dropped: Uint8Array[];
  }): BundleError {
    const { ecLevel, budgetBytes, encodedBytes, fits, dropped } = params;
    const message =
      `bundle encodes to ${encodedBytes} bytes, exceeding the ${budgetBytes}-byte QR budget ` +
      `at EC level ${ecLevel}; kept ${fits} entries, dropped ${dropped.length} host(s) to fit`;
    return new BundleError("TooLargeForQr", message, {
      ecLevel,
      budgetBytes,
      encodedBytes,
      fits,
      dropped,
    });
  }
}

// ================================================================================================
// buildBootstrapBundle
// ================================================================================================

/** Builds a `DeviceBootstrapBundle` at `BUNDLE_CURRENT_V` and checks it against the printed QR's
 * real byte budget.
 *
 * **The fit check measures the REAL canonical encoding, never
 * `@spindle/proto`'s `MEASURED_ENTRY_BYTES`.** That constant is documentation for DESIGN.md
 * :328-329's "4 hosts at EC level M, 5 at level L" figures only — it is not a lower bound this
 * function is allowed to trust. A future artifact (e.g. a larger op-cert chain, or a second cap
 * embedded per entry) could grow a single entry's encoding well past 530 B; measuring the real
 * bytes here means such a change is caught by this check automatically, rather than silently
 * producing a bundle that fails to scan once printed.
 *
 * On overflow, this function finds the largest prefix of `entries` that DOES fit by encoding
 * candidate bundles for `n` descending from `entries.length - 1` down to `0` — at most
 * `MAX_BUNDLE_ENTRIES` (32) candidates, each a re-encode of at most 32 entries, so the O(n²) cost
 * is free in practice. It throws `BundleError.tooLargeForQr` naming the largest fitting prefix
 * (`fits`) and the `hostFp` of every entry beyond it (`dropped`), so the caller can tell the
 * person doing the enrollment exactly which hosts didn't make it in and let them re-invite the new
 * device to the remainder later (DESIGN.md :329: "fails loudly ... naming the hosts left out").
 *
 * **This function does NOT run `verifyCapability` on any entry.** The primary device already
 * holds these capabilities — that's what makes it the primary for these hosts — and an expired
 * one is still useful to hand to the new device: the new device only needs to *connect* to learn
 * it should refresh, not present a live capability up front (DESIGN.md :286, :289-290). Rejecting
 * an expired-but-otherwise-valid capability here would make bundle construction less useful than
 * doing nothing at all. Verification is entirely a decode-side duty — see
 * `verifyBootstrapBundle`. Do not add a `verifyCapability` call here. */
export async function buildBootstrapBundle(
  registry: string,
  entries: BundleEntry[],
  ecLevel: QrEcLevel,
): Promise<DeviceBootstrapBundle> {
  if (entries.length > MAX_BUNDLE_ENTRIES) {
    throw BundleError.tooManyEntries(entries.length, MAX_BUNDLE_ENTRIES);
  }

  const bundle: DeviceBootstrapBundle = { v: BUNDLE_CURRENT_V, registry, entries };

  const budgetBytes = QrEcLevel.budgetBytes(ecLevel);
  const encodedBytes = DeviceBootstrapBundle.toCanonicalBytes(bundle).length;
  if (encodedBytes <= budgetBytes) return bundle;

  // Overflow: find the largest fitting prefix by trying n descending from len - 1 to 0. The
  // full-length bundle (n === entries.length) already failed above, so it is not retried.
  let fits = 0;
  for (let n = entries.length - 1; n >= 0; n--) {
    const candidateEntries = entries.slice(0, n);
    const candidate: DeviceBootstrapBundle = { v: bundle.v, registry, entries: candidateEntries };
    if (DeviceBootstrapBundle.toCanonicalBytes(candidate).length <= budgetBytes) {
      fits = n;
      break;
    }
  }

  // hostFp is derived from each dropped entry's own host_root_pk (SHA-256 of the raw key bytes),
  // never trusted from the nested capability's carried host_fp field — the same
  // derived-not-carried discipline this module's doc comment describes for the bundle as a
  // whole, applied here even though the builder does not otherwise verify these capabilities.
  const dropped = await Promise.all(
    entries.slice(fits).map((entry) => rootFpOf(entry.member_cap.host_root_pk)),
  );

  throw BundleError.tooLargeForQr({ ecLevel, budgetBytes, encodedBytes, fits, dropped });
}

// ================================================================================================
// verifyBootstrapBundle
// ================================================================================================

/** One `BundleEntry` after verification: the two derived fingerprints, the host's keys, and the
 * verified capability. `signPk`/`agreePk` are the **host's** envelope keys (see `BundleEntry`'s
 * own doc comment in `@spindle/proto`), not the new device's. */
export interface VerifiedBundleEntry {
  /** `SHA-256(memberCap.host_root_pk)` — derived, and only reachable after `verifyCapability` has
   * already confirmed this equals `memberCap.host_fp`. */
  hostFp: Uint8Array;
  /** `deviceFpOf(ALG_ID_V1, signPk, agreePk)` — this host's envelope identity. */
  hostDeviceFp: Uint8Array;
  /** The host's envelope Ed25519 verifying key. */
  signPk: Uint8Array;
  /** The host's envelope X25519 public key. */
  agreePk: Uint8Array;
  /** The verified membership capability for this host. */
  memberCap: Capability;
}

/** A `DeviceBootstrapBundle` after every entry has been verified. */
export interface VerifiedBundle {
  registry: string;
  entries: VerifiedBundleEntry[];
}

/** Verifies every entry of a `DeviceBootstrapBundle` and derives each entry's `hostFp` and
 * `hostDeviceFp`. Order (cheapest rejection first, mirroring `verifyCapability`'s own ordering):
 *
 * 0. `BUNDLE_MIN_V` floor on `bundle.v` — once, before touching any entry.
 * 1. `bundle.entries.length <= MAX_BUNDLE_ENTRIES`.
 * 2. Per entry, in order:
 *    - a. `sign_pk`/`agree_pk` are each exactly 32 bytes (the same length-only idiom
 *      `verifyHostDeviceCert` in `artifacts.ts` uses for the same two fields).
 *    - b. `hostDeviceFp = deviceFpOf(ALG_ID_V1, sign_pk, agree_pk)`.
 *    - c. `verifyCapability` — this is the step this bundle's acceptance criterion names; it
 *      already enforces `host_fp === SHA-256(host_root_pk)`.
 *    - d. `hostFp = member_cap.host_fp` — safe only after (c) has already proven
 *      `member_cap.host_fp` is exactly 32 bytes and self-consistent (a successful
 *      `verifyCapability` call cannot return unless the two already compared byte-equal).
 *
 *    Any per-entry failure surfaces as `BundleError.entry`, carrying that entry's index.
 *
 * **`ALG_ID_V1` is assumed, not read from the wire**: `deviceFpOf` takes an `algId` parameter, but
 * `BundleEntry` carries no `alg_id` field for the host's envelope keys. This is the same
 * assumption `crates/spindle-host-core/src/authorize.rs:652` already makes for the devices
 * table's own `device_fp_of` call — tracked for both call sites by open ticket td-6c01e3. */
export async function verifyBootstrapBundle(
  bundle: DeviceBootstrapBundle,
  now: bigint,
): Promise<VerifiedBundle> {
  // 0. Version floor — cheapest possible rejection, before any per-entry work.
  if (bundle.v < BUNDLE_MIN_V) {
    throw BundleError.versionTooLow(bundle.v, BUNDLE_MIN_V);
  }

  // 1. Entry count cap.
  if (bundle.entries.length > MAX_BUNDLE_ENTRIES) {
    throw BundleError.tooManyEntries(bundle.entries.length, MAX_BUNDLE_ENTRIES);
  }

  // 2. Per entry, in order.
  const entries: VerifiedBundleEntry[] = [];
  for (let index = 0; index < bundle.entries.length; index++) {
    try {
      entries.push(await verifyBundleEntry(bundle.entries[index], now));
    } catch (e) {
      if (e instanceof ArtifactError) throw BundleError.entry(index, e);
      throw e;
    }
  }

  return { registry: bundle.registry, entries };
}

/** One entry's worth of step 2 in `verifyBootstrapBundle`'s doc comment — pulled out so the loop
 * above can attach the entry's index to whichever `ArtifactError` this produces. */
async function verifyBundleEntry(entry: BundleEntry, now: bigint): Promise<VerifiedBundleEntry> {
  // a. sign_pk (Ed25519) / agree_pk (X25519) length checks — same idiom as
  // `verifyHostDeviceCert`.
  requirePublicKeyLen(entry.sign_pk);
  requirePublicKeyLen(entry.agree_pk);

  // b. Derive this host's device fingerprint.
  const hostDeviceFp = await deviceFpOf(ALG_ID_V1, entry.sign_pk, entry.agree_pk);

  // c. Verify the nested capability — already enforces host_fp === SHA-256(host_root_pk).
  await verifyCapability(entry.member_cap, now);

  // d. hostFp — safe only now that (c) has proven member_cap.host_fp is exactly 32 bytes and
  // self-consistent with host_root_pk.
  const hostFp = entry.member_cap.host_fp;

  return {
    hostFp,
    hostDeviceFp,
    signPk: entry.sign_pk,
    agreePk: entry.agree_pk,
    memberCap: entry.member_cap,
  };
}
