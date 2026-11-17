// `AdminClient` — the A3b protocol client over an {@link AdminTransport} seam.
//
// Responsibilities, all protocol-level (A10.19: the library owns signing and connection logic;
// no CLI/UI lives here):
//   1. map a documented command name to its `registry.admin.<command>` subject;
//   2. build and sign the command (never accept a pre-signed command);
//   3. publish exactly that subject/payload through the injected transport;
//   4. decode the reply into a typed result, or raise a typed refusal/transport error.
//
// Sequence numbers: A7b requires a per-signer monotonic `seq` and the helper enforces it durably.
// This client cannot supply durability by itself. Pass a function backed by the operator's durable
// store; the convenience overload (a fixed number/bigint) increments process-locally and is meant
// for tests or single-use tooling.
//
// Clock: `ts` defaults to the local wall clock. That is correct for *producing* a command (the
// helper checks ±120 s); unlike verification, signing has no caller-supplied trusted time to use.

import { AdminCommand, type CborValue } from "@spindle/proto";

import { buildAdminCommand } from "./commands.js";
import { AdminError } from "./errors.js";
import { decodeAdminReply, type AdminReply } from "./reply.js";
import type { Signer } from "./signer.js";
import { adminSubjectFor, type AdminCommandName } from "./subjects.js";
import type { AdminTransport } from "./transport.js";

/** Per-send overrides, mainly for deterministic tests and sequenced tooling. */
export interface AdminSendOptions {
  /** Explicit `seq`. Defaults to the client's sequence source. */
  seq?: bigint | number;
  /** Explicit 16-byte nonce. Defaults to 16 CSPRNG bytes. */
  nonce?: Uint8Array;
  /** Explicit `ts` (Unix seconds). Defaults to `now()`. */
  ts?: bigint | number;
  /** Explicit wire version. Defaults to the client's `v`. */
  v?: number;
}

/** Result of a successful command: the exact signed command sent, plus the decoded reply. */
export interface AdminSendResult {
  /** The subject the command was published on. */
  subject: string;
  /** The signed `AdminCommand` (useful for audit correlation with the helper's log). */
  command: AdminCommand;
  /** The decoded reply envelope. `ok` is always true on a resolved promise. */
  reply: AdminReply;
  /** Convenience alias for `reply.result`. Absent for commands with no result. */
  result: CborValue | undefined;
}

/** Construction options for {@link AdminClient}. */
export interface AdminClientOptions {
  /** The caller-owned transport adapter (`registry.admin.>` over mTLS in production). */
  transport: AdminTransport;
  /** The operator admission-key signer. The client never sees key bytes. */
  signer: Signer;
  /** Monotonic sequence source. A function is awaited on every send; a fixed number/bigint is
   * incremented process-locally. Durable persistence is the caller's responsibility. */
  seq: bigint | number | (() => bigint | number | Promise<bigint | number>);
  /** Clock override returning Unix seconds. Defaults to `Math.floor(Date.now() / 1000)`. */
  now?: () => bigint | number;
  /** Nonce source. Defaults to 16 bytes from `crypto.getRandomValues`. */
  nonce?: () => Uint8Array;
  /** Command wire version. Defaults to `ADMIN_COMMAND_CURRENT_V` via `buildAdminCommand`. */
  v?: number;
}

function defaultNonce(): Uint8Array {
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);
  return nonce;
}

function defaultNow(): bigint {
  return BigInt(Math.floor(Date.now() / 1000));
}

export class AdminClient {
  readonly #transport: AdminTransport;
  readonly #signer: Signer;
  readonly #seqSource: AdminClientOptions["seq"];
  readonly #now: () => bigint | number;
  readonly #nonce: () => Uint8Array;
  readonly #v: number | undefined;
  /** Only used when `seqSource` is a fixed number/bigint. */
  #nextSeq: bigint | undefined;

  constructor(options: AdminClientOptions) {
    this.#transport = options.transport;
    this.#signer = options.signer;
    this.#seqSource = options.seq;
    this.#now = options.now ?? defaultNow;
    this.#nonce = options.nonce ?? defaultNonce;
    this.#v = options.v;
    if (typeof options.seq !== "function") {
      try {
        this.#nextSeq = BigInt(options.seq);
      } catch {
        throw AdminError.invalidValue("seq");
      }
    }
  }

  async #takeSeq(override: bigint | number | undefined): Promise<bigint | number> {
    if (override !== undefined) return override;
    if (typeof this.#seqSource === "function") return this.#seqSource();
    const seq = this.#nextSeq;
    if (seq === undefined) throw AdminError.invalidValue("seq");
    this.#nextSeq = seq + 1n;
    return seq;
  }

  /** Signs and sends one documented admin command.
   *
   * Rejects with {@link AdminError}:
   * - `UnknownCommand` if `cmd` is not in the documented surface;
   * - the same builder errors `buildAdminCommand` raises (empty command, lengths, version,
   *   signer_fp binding);
   * - `Transport` if the transport rejects;
   * - `MalformedReply` if the reply is not the documented envelope;
   * - `Refused` (carrying `code`/`detail`) if the helper answers `ok: false`.
   *
   * Never logs or embeds key material, nonces, signatures, or payload bytes in error messages. */
  async send(
    cmd: AdminCommandName,
    args: CborValue,
    options: AdminSendOptions = {},
  ): Promise<AdminSendResult> {
    const subject = adminSubjectFor(cmd);
    const signerFp = await this.#signer.fingerprint();
    const seq = await this.#takeSeq(options.seq);
    const nonce = options.nonce ?? this.#nonce();
    const ts = options.ts ?? this.#now();

    const command = await buildAdminCommand({
      cmd,
      args,
      signerFp,
      seq,
      nonce,
      ts,
      v: options.v ?? this.#v,
      signer: this.#signer,
    });

    let payload: Uint8Array;
    try {
      payload = AdminCommand.toCanonicalBytes(command);
    } catch {
      throw AdminError.invalidValue("command");
    }

    let raw: Uint8Array;
    try {
      raw = await this.#transport.request(subject, payload);
    } catch (cause) {
      throw AdminError.transport(subject, cause);
    }
    if (!(raw instanceof Uint8Array)) throw AdminError.malformedReply();

    const reply = decodeAdminReply(raw);
    if (!reply.ok) {
      const refusal = reply.error;
      // `decodeAdminReply` guarantees `error` is present when `ok` is false.
      throw AdminError.refused(refusal?.code ?? "", refusal?.message);
    }

    return { subject, command, reply, result: reply.result };
  }
}
