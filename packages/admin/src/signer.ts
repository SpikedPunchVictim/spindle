// The pluggable operator-key seam (DESIGN.md §A3b, decision A10.19). A `Signer` owns its private
// key: callers can ask it to sign and to identify itself, but there is no accessor that returns
// secret bytes. File-custody is implemented here; OS-keychain, hardware-token, and WebCrypto
// signers implement the same interface without changing this module.
//
// `fingerprint()` is the operator identity written to `AdminCommand.signer_fp`. A3b does not say
// how that 32-byte value is derived from the operator key — `spindle-core`'s verifier treats it as
// a caller-supplied `Fingerprint` (`verify_admin_command`'s `expected_signer_fp`), and the signed
// golden vector uses a synthetic identity that is not SHA-256 of the signing key. The interface
// therefore makes the identity explicit rather than guessing: a `Signer` reports the fingerprint
// it signs as, and `buildAdminCommand` refuses to attach a different one. `FileKeySigner` defaults
// to `SHA-256(public_key)` — the same construction `@spindle/crypto`'s `rootFpOf` uses for every
// other principal fingerprint — and accepts an override for deployments whose helper expects an
// operator-assigned identity.

import {
  ed25519PublicKeyFromSeed,
  ed25519Sign,
  FINGERPRINT_LEN,
  rootFpOf,
  type BackendOption,
} from "@spindle/crypto";

/** A signer that never exposes its private key.
 *
 * Implementations must:
 * - return a 64-byte Ed25519 signature from `sign`;
 * - return a 32-byte Ed25519 public key from `publicKey` (the key that verifies `sign`);
 * - return a 32-byte operator identity from `fingerprint` (written to `signer_fp`).
 *
 * The admin library accepts commands only by signing them here — it has no API that takes an
 * externally produced signature. */
export interface Signer {
  /** Signs `message` with the operator admission key. */
  sign(message: Uint8Array): Promise<Uint8Array>;
  /** The Ed25519 public key corresponding to the signing key (32 bytes). */
  publicKey(): Promise<Uint8Array>;
  /** The operator identity this signer signs as, written to `AdminCommand.signer_fp` (32 bytes). */
  fingerprint(): Promise<Uint8Array>;
}

/** Options for {@link FileKeySigner.open}. */
export interface FileKeySignerOptions {
  /** Force one crypto backend (mirrors `@spindle/crypto`'s `BackendOption`). Omitted = WebCrypto
   * with the `@noble/curves` fallback. */
  backend?: BackendOption["backend"];
  /** Override the operator fingerprint. Omitted = `SHA-256(public_key)`. */
  signerFp?: Uint8Array;
}

/** A `Signer` backed by a 32-byte raw Ed25519 seed held in a file.
 *
 * Custody rule: the file must be a regular file with no group/other permission bits on POSIX
 * (`0600`; wider permissions are refused rather than silently corrected, matching
 * `spindle-hostd`'s keystore behaviour). The seed is kept in an ECMAScript private field, copied
 * once from the read buffer, and never returned by any method. */
export class FileKeySigner implements Signer {
  readonly #seed: Uint8Array;
  readonly #publicKey: Uint8Array;
  readonly #fingerprint: Uint8Array;
  readonly #backend: BackendOption["backend"] | undefined;

  private constructor(
    seed: Uint8Array,
    publicKey: Uint8Array,
    fingerprint: Uint8Array,
    backend: BackendOption["backend"] | undefined,
  ) {
    this.#seed = seed;
    this.#publicKey = publicKey;
    this.#fingerprint = fingerprint;
    this.#backend = backend;
  }

  /** Loads a raw 32-byte Ed25519 seed from `path`.
   *
   * `node:fs/promises` is imported dynamically so this module stays importable in a browser
   * bundle; only code that actually opens a file needs Node. */
  static async open(path: string, opts: FileKeySignerOptions = {}): Promise<FileKeySigner> {
    const { readFile, stat } = await import("node:fs/promises");

    const info = await stat(path);
    if (!info.isFile()) {
      throw new Error(`refusing to load key file \`${path}\`: not a regular file`);
    }
    // Windows has no POSIX mode bits to enforce. On every other platform, a key file readable by
    // anyone else is refused rather than chmod'ed — a silent fix would conceal that the seed may
    // already have been read.
    if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
      const mode = (info.mode & 0o777).toString(8).padStart(3, "0");
      throw new Error(
        `refusing to load key file \`${path}\`: mode ${mode} grants group/other access (expected 0600)`,
      );
    }

    const raw = new Uint8Array(await readFile(path));
    try {
      if (raw.length !== 32) {
        throw new Error(`refusing to load key file \`${path}\`: expected a 32-byte seed`);
      }
      const seed = raw.slice();
      const publicKey = await ed25519PublicKeyFromSeed(seed, { backend: opts.backend });
      if (publicKey.length !== FINGERPRINT_LEN) {
        throw new Error("Ed25519 public key has an unexpected length");
      }
      const fingerprint = opts.signerFp ?? (await rootFpOf(publicKey));
      if (fingerprint.length !== FINGERPRINT_LEN) {
        throw new Error("operator fingerprint has an unexpected length");
      }
      return new FileKeySigner(seed, publicKey, fingerprint, opts.backend);
    } finally {
      raw.fill(0);
    }
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return ed25519Sign(this.#seed, message, { backend: this.#backend });
  }

  async publicKey(): Promise<Uint8Array> {
    return this.#publicKey.slice();
  }

  async fingerprint(): Promise<Uint8Array> {
    return this.#fingerprint.slice();
  }
}
