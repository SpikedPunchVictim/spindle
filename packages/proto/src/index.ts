// @spindle/proto — the TypeScript twin of the Rust `spindle-proto` crate: wire types plus a
// small, hand-written canonical CBOR encoder/decoder (RFC 8949 §4.2.1) and the A7b
// signed-artifact domain-separation tags. Third-party CBOR libraries are not used here because
// they are not guaranteed byte-canonical; this package's output is verified byte-identical to
// the Rust encoder's via the golden vectors in /vectors, in CI.

export {
  CborValue,
  CborError,
  canonicalEncode,
  canonicalDecode,
  cborValueEquals,
} from "./canonical.js";
export type { CborErrorKind } from "./canonical.js";

export { hexToBytes, bytesToHex } from "./hex.js";

export * as tags from "./tags.js";

export {
  ProtoError,
  CapKind,
  Envelope,
  Capability,
  AdmissionToken,
  DeviceCertificate,
  RevocationRecord,
  AdminCommand,
  HostOpKeyCert,
} from "./artifacts.js";
export type { ProtoErrorKind } from "./artifacts.js";

export {
  MIN_PROTOCOL_VERSION,
  CURRENT_PROTOCOL_VERSION,
  MAX_LIST_PAGE,
  MAX_READ_CHUNK,
  MAX_UPLOAD_CHUNK,
  UPLOAD_SESSION_TTL_SECS,
  EntryKind,
  VfsPerms,
  vfsPermsUnion,
  vfsPermsContains,
  VfsErrorCode,
  DirEntry,
  VfsRequestEnvelope,
  VfsReply,
} from "./vfsRpc.js";
export type { VfsRequest } from "./vfsRpc.js";

export {
  CERT_FP_LEN,
  MAX_UFRAG_LEN,
  MAX_PWD_LEN,
  MAX_CANDIDATE_LEN,
  MAX_INBOX_LEN,
  KIND_OFFER,
  KIND_ANSWER,
  KIND_ICE,
  SignalingError,
  Transport,
  OfferPayload,
  AnswerPayload,
  IcePayload,
} from "./signaling.js";
export type { SignalingErrorKind } from "./signaling.js";
