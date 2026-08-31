// @spindle/crypto — the TypeScript twin of Spindle's `spindle-core` crypto layer: Ed25519/X25519
// (WebCrypto with `@noble/curves` fallback), HKDF-SHA256/AES-256-GCM/SHA-256 (WebCrypto), A4
// fingerprints, the A7 end-to-end envelope (`seal`/`open`), and A7b signed-artifact verification.
// Builds on `@spindle/proto` for canonical CBOR encoding and domain-separation tags; never
// re-encodes wire structs by hand. Verified byte-identical to `spindle-core`'s real-signature
// golden vectors (`vectors/signed/*.json`) — see `test/vectors.test.ts`.

export type { AsymmetricBackend, BackendOption } from "./backend.js";
export {
  ed25519PublicKeyFromSeed,
  ed25519Sign,
  ed25519Verify,
  probeWebCryptoSupport,
  x25519PublicKeyFromSeed,
  x25519SharedSecret,
} from "./backend.js";

export { aesGcmOpen, aesGcmSeal, hkdfSha256, sha256 } from "./primitives.js";

export { FINGERPRINT_LEN, base32EncodeNoPad, deviceFpOf, rootFpOf } from "./fingerprint.js";

export type { EnvelopeErrorKind, OpenParams, SealParams, SessionKey } from "./envelope.js";
export {
  BOOT_KEY_INFO_DOMAIN,
  CLOCK_SKEW_SECS,
  EnvelopeError,
  SESSION_KEY_INFO_DOMAIN,
  deriveBootstrapKey,
  deriveSessionKey,
  directionByte,
  open,
  seal,
} from "./envelope.js";

export type { ArtifactErrorKind } from "./artifacts.js";
export {
  ADMIN_COMMAND_CLOCK_SKEW_SECS,
  ArtifactError,
  isNewerEpoch,
  verifyAdminCommand,
  verifyAdmissionToken,
  verifyCapability,
  verifyDeviceCertificate,
  verifyHostDeviceCert,
  verifyHostOpKeyCert,
  verifyRevocationRecord,
} from "./artifacts.js";
