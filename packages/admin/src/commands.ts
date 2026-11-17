// Admin-command construction and signing (DESIGN.md §A3b/§A7b).
//
// The wire struct and the signature preimage are owned by `@spindle/proto`'s `AdminCommand`
// (`spindle-adm-cmd-v1 || canonical(self minus sig)`); this module only fills it in, enforces the
// producer-side invariants, and asks the configured `Signer` for the Ed25519 signature. It does
// not re-encode the struct, so `toCanonicalBytes`/`signingInput` are byte-identical to the Rust
// encoder by construction and are pinned against `vectors/admin-command.json` in the tests.
//
// Verification is deliberately not duplicated here: `@spindle/crypto`'s `verifyAdminCommand`
// remains the single verifier (version floor/ceiling, signer_fp binding, signature, ±120 s skew).

import {
  AdminCommand,
  ADMIN_COMMAND_CURRENT_V,
  ADMIN_COMMAND_MIN_V,
  canonicalDecode,
  canonicalEncode,
  type CborValue,
} from "@spindle/proto";

import { AdminError } from "./errors.js";
import type { Signer } from "./signer.js";

/** Ed25519 signature length (RFC 8032). */
const SIGNATURE_LEN = 64;
/** Ed25519 public key / Spindle fingerprint length. */
const KEY_LEN = 32;
/** `AdminCommand.nonce` length fixed by ADR-007's replay rule and the golden vectors. */
const ADMIN_NONCE_LEN = 16;
/** CBOR uint64 ceiling. */
const U64_MAX = 0xffffffffffffffffn;

/** Parameters for {@link buildAdminCommand}. */
export interface BuildAdminCommandParams {
  /** Documented command name (`evict_host`, `set_mode`, …). Non-empty; this low-level builder
   * does not require it to be in the documented surface (see `AdminClient` for that check). */
  cmd: string;
  /** Command arguments, canonical CBOR. An empty argument list is CBOR `null`, matching the
   * `rotate_admission_key` golden vector — not an omitted field. */
  args: CborValue;
  /** The operator identity this command must claim, 32 bytes. Must equal
   * `signer.fingerprint()`; a mismatch is rejected before signing. */
  signerFp: Uint8Array;
  /** Per-signer monotonic sequence number (u64). Persistence is caller-owned. */
  seq: bigint | number;
  /** 16-byte anti-replay nonce. */
  nonce: Uint8Array;
  /** Unix seconds (u64). */
  ts: bigint | number;
  /** Wire version. Defaults to `ADMIN_COMMAND_CURRENT_V`; must lie within
   * `[ADMIN_COMMAND_MIN_V, ADMIN_COMMAND_CURRENT_V]`. */
  v?: number;
  /** Signs the canonical preimage. */
  signer: Signer;
}

function requireU64(value: bigint | number, field: string): bigint {
  let out: bigint;
  try {
    out = BigInt(value);
  } catch {
    throw AdminError.invalidValue(field);
  }
  if (out < 0n || out > U64_MAX) throw AdminError.invalidValue(field);
  return out;
}

function requireVersion(v: number): number {
  if (!Number.isInteger(v) || v < 0 || v > 0xff) throw AdminError.invalidValue("v");
  if (v < ADMIN_COMMAND_MIN_V) throw AdminError.versionTooLow(v, ADMIN_COMMAND_MIN_V);
  if (v > ADMIN_COMMAND_CURRENT_V) throw AdminError.versionTooHigh(v, ADMIN_COMMAND_CURRENT_V);
  return v;
}

function requireLength(bytes: Uint8Array, expected: number, field: string): void {
  if (bytes.length !== expected) throw AdminError.wrongLength(field, expected, bytes.length);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Builds and signs an `AdminCommand`.
 *
 * Checks run cheapest-first, mirroring `verify_admin_command`'s ordering where the producer has
 * the equivalent information:
 * 1. non-empty `cmd`;
 * 2. `v` integer, bounded by `[ADMIN_COMMAND_MIN_V, ADMIN_COMMAND_CURRENT_V]`;
 * 3. `seq`/`ts` valid u64 values;
 * 4. `signer_fp` (32) and `nonce` (16) lengths;
 * 5. the signer's public key (32) and fingerprint (32), and `signerFp === signer.fingerprint()`;
 * 6. signature length (64) after signing.
 *
 * No private-key bytes are read or retained by this function; it only invokes `signer.sign`. */
export async function buildAdminCommand(params: BuildAdminCommandParams): Promise<AdminCommand> {
  const { cmd, args, signerFp, nonce, signer } = params;

  if (cmd.length === 0 || cmd.trim().length === 0) throw AdminError.emptyCommand();

  const v = requireVersion(params.v ?? ADMIN_COMMAND_CURRENT_V);
  const seq = requireU64(params.seq, "seq");
  const ts = requireU64(params.ts, "ts");

  requireLength(signerFp, KEY_LEN, "signer_fp");
  requireLength(nonce, ADMIN_NONCE_LEN, "nonce");

  const publicKey = await signer.publicKey();
  requireLength(publicKey, KEY_LEN, "public_key");
  const fingerprint = await signer.fingerprint();
  requireLength(fingerprint, KEY_LEN, "signer_fingerprint");
  if (!bytesEqual(signerFp, fingerprint)) throw AdminError.signerFingerprintMismatch();

  // Canonical round-trip: rejects duplicate map keys, excessive nesting, and non-CborValue
  // shapes, and guarantees the command we sign decodes under the same rules the helper applies.
  try {
    canonicalDecode(canonicalEncode(args));
  } catch {
    throw AdminError.invalidValue("args");
  }

  const unsigned: AdminCommand = {
    v,
    cmd,
    args,
    signer_fp: signerFp,
    seq,
    nonce,
    ts,
    sig: new Uint8Array(0),
  };

  // `AdminCommand.signingInput` already carries the `spindle-adm-cmd-v1` domain tag.
  let signingInput: Uint8Array;
  try {
    signingInput = AdminCommand.signingInput(unsigned);
  } catch {
    throw AdminError.invalidValue("command");
  }
  const signature = await signer.sign(signingInput);
  requireLength(signature, SIGNATURE_LEN, "sig");

  return { ...unsigned, sig: signature };
}
