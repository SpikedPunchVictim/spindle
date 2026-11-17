// @spindle/admin — the A3b registry control-plane protocol library (DESIGN.md §A3b, decision
// A10.19; ADR-007).
//
// Scope (A10.19): this package owns admin-command signing with the same envelope discipline as A7
// (nonce, `ts`, canonical CBOR), a pluggable `Signer`, and the connection logic for
// `registry.admin.>`. It owns no CLI and no UI — `packages/admin-cli` is the v1 client over it, and
// any future interface builds on it and owns its own transport security.
//
// What is implemented here:
// - `Signer` (and a file-custody `FileKeySigner`) — no private key is ever exposed;
// - `buildAdminCommand` — fills `@spindle/proto`'s `AdminCommand`, enforces producer invariants,
//   and signs `AdminCommand.signingInput` via the signer. Wire encoding and the signature preimage
//   are `@spindle/proto`'s, so they are byte-identical to the Rust encoder (pinned against
//   `vectors/admin-command.json`);
// - `AdminTransport` — the only transport seam; the embedding application owns NATS/mTLS;
// - `AdminClient` — validates/documents the command→subject mapping, signs, sends, and decodes a
//   typed reply or refusal.
//
// What is deliberately NOT implemented (reported, not guessed):
// - a live NATS adapter, operator credentials, or the mTLS profile (A10.19 keeps transport out of
//   this package; `registry.admin.>` has no helper handler yet — DESIGN.md §A5 status column / §A9 divergence list);
// - admission-invite *minting* (`AdmissionToken` signing) — a sibling A3b slice, not part of this
//   ticket's command client;
// - verification — `@spindle/crypto`'s `verifyAdminCommand` is the single verifier and is used by
//   these tests to cross-check the producer;
// - response/connection handling for anything other than one request/reply per command.
//
// Provisional contracts pending the helper's admin handler:
// - the per-command subject mapping `registry.admin.<cmd>` (`subjects.ts`);
// - the reply envelope (`reply.ts`);
// - `Signer.fingerprint()`'s value for a file key (`SHA-256(public_key)` by default) — DESIGN.md
//   does not define `signer_fp`'s derivation and the signed vector uses a synthetic identity.

export {
  AdminError,
  type AdminErrorKind,
} from "./errors.js";

export {
  FileKeySigner,
  type FileKeySignerOptions,
  type Signer,
} from "./signer.js";

export {
  ADMIN_COMMAND_NAMES,
  ADMIN_SUBJECT_PREFIX,
  adminSubjectFor,
  assertAdminSubject,
  commandForSubject,
  isAdminCommandName,
  isAdminSubject,
  type AdminCommandName,
} from "./subjects.js";

export {
  buildAdminCommand,
  type BuildAdminCommandParams,
} from "./commands.js";

export {
  ADMIN_REPLY_CURRENT_V,
  ADMIN_REPLY_MIN_V,
  decodeAdminReply,
  encodeAdminReply,
  type AdminRefusal,
  type AdminReply,
} from "./reply.js";

export type { AdminTransport } from "./transport.js";

export {
  AdminClient,
  type AdminClientOptions,
  type AdminSendOptions,
  type AdminSendResult,
} from "./client.js";
