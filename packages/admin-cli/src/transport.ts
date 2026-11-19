// NATS transport for the admin CLI. The contract is @spindle/admin's AdminTransport: publish
// exactly the given subject/payload and return the raw reply bytes.

import { connect, nkeyAuthenticator, type NatsConnection } from "nats";

import type { AdminTransport } from "@spindle/admin";

export interface NatsTransportOptions {
  url: string;
  /** Raw nkey user seed (for the operator's NATS identity), as UTF-8 bytes. */
  nkeySeed: Uint8Array;
  timeoutMs?: number;
}

export class NatsAdminTransport implements AdminTransport {
  readonly #nc: NatsConnection;
  readonly #timeoutMs: number;

  private constructor(nc: NatsConnection, timeoutMs: number) {
    this.#nc = nc;
    this.#timeoutMs = timeoutMs;
  }

  static async connect(options: NatsTransportOptions): Promise<NatsAdminTransport> {
    const nc = await connect({
      servers: options.url,
      authenticator: nkeyAuthenticator(options.nkeySeed),
    });
    return new NatsAdminTransport(nc, options.timeoutMs ?? 5_000);
  }

  async request(subject: string, payload: Uint8Array): Promise<Uint8Array> {
    const reply = await this.#nc.request(subject, payload, { timeout: this.#timeoutMs });
    return reply.data;
  }

  async close(): Promise<void> {
    await this.#nc.drain();
  }
}
