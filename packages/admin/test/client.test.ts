// `AdminClient` over a recording transport: subject mapping, signing/serialization, typed
// refusal/transport/malformed-reply errors, and the redaction guarantee that no key material or
// nonce byte reaches an error message.

import { describe, expect, it } from "vitest";

import { AdminCommand, bytesToHex, CborValue, hexToBytes } from "@spindle/proto";

import { AdminClient } from "../src/client.js";
import { AdminError } from "../src/errors.js";
import { encodeAdminReply } from "../src/reply.js";
import {
  ADMIN_SUBJECT_PREFIX,
  adminSubjectFor,
  assertAdminSubject,
  isAdminSubject,
} from "../src/subjects.js";
import type { AdminTransport } from "../src/transport.js";
import { fixedSigner } from "./helpers.js";

const SIGNER_FP = new Uint8Array(32).fill(0x21);
const NONCE = new Uint8Array(16).fill(0x33);

interface Request {
  subject: string;
  payload: Uint8Array;
}

class RecordingTransport implements AdminTransport {
  readonly requests: Request[] = [];
  constructor(private readonly handler: () => Promise<Uint8Array>) {}

  async request(subject: string, payload: Uint8Array): Promise<Uint8Array> {
    this.requests.push({ subject, payload });
    return this.handler();
  }
}

function signer() {
  return fixedSigner({ fingerprint: SIGNER_FP, signature: new Uint8Array(64).fill(0x44) });
}

function clientWith(
  handler: () => Promise<Uint8Array>,
  overrides: Partial<ConstructorParameters<typeof AdminClient>[0]> = {},
) {
  const transport = new RecordingTransport(handler);
  const client = new AdminClient({
    transport,
    signer: signer(),
    seq: 7n,
    now: () => 1_755_907_200n,
    nonce: () => NONCE,
    ...overrides,
  });
  return { client, transport };
}

const ARGS = CborValue.map([
  ["host_fp", CborValue.bytes(new Uint8Array(32).fill(0x91))],
]);

describe("command surface and subjects", () => {
  it("maps every documented command to registry.admin.<cmd>", () => {
    for (const cmd of [
      "set_mode",
      "mint_invite",
      "revoke_invite",
      "pre_register_host",
      "list_hosts",
      "suspend_host",
      "evict_host",
      "set_quota_profile",
      "rotate_admission_key",
      "read_audit_log",
    ] as const) {
      expect(adminSubjectFor(cmd)).toBe(`${ADMIN_SUBJECT_PREFIX}${cmd}`);
      expect(assertAdminSubject(`${ADMIN_SUBJECT_PREFIX}${cmd}`)).toBe(cmd);
      expect(isAdminSubject(`${ADMIN_SUBJECT_PREFIX}${cmd}`)).toBe(true);
    }
  });

  it("rejects a subject outside the documented surface", () => {
    expect(() => assertAdminSubject("registry.admin.not_a_command")).toThrow(AdminError);
    expect(() => assertAdminSubject("host.deadbeef.connect")).toThrow(AdminError);
    expect(() => assertAdminSubject("registry.admin.")).toThrow(AdminError);
    expect(isAdminSubject("registry.admin.not_a_command")).toBe(false);
  });

  it("rejects an unknown command name", () => {
    expect(() => adminSubjectFor("not_a_command")).toThrow(AdminError);
    expect(() => adminSubjectFor("")).toThrow(AdminError);
  });
});

describe("AdminClient.send", () => {
  it("publishes exactly the documented subject and a signed command", async () => {
    const reply = encodeAdminReply({
      v: 1,
      ok: true,
      result: CborValue.map([["evicted", CborValue.text("host-1")]]),
    });
    const { client, transport } = clientWith(async () => reply);

    const sent = await client.send("evict_host", ARGS);

    expect(transport.requests).toHaveLength(1);
    expect(transport.requests[0].subject).toBe("registry.admin.evict_host");

    const decoded = AdminCommand.fromCanonicalBytes(transport.requests[0].payload);
    expect(decoded.cmd).toBe("evict_host");
    expect(bytesToHex(decoded.signer_fp)).toBe(bytesToHex(SIGNER_FP));
    expect(bytesToHex(decoded.nonce)).toBe(bytesToHex(NONCE));
    expect(decoded.seq).toBe(7n);
    expect(decoded.ts).toBe(1_755_907_200n);
    expect(decoded.sig).toHaveLength(64);
    expect(sent.subject).toBe("registry.admin.evict_host");
    expect(sent.command).toEqual(decoded);
    expect(sent.result).toEqual(CborValue.map([["evicted", CborValue.text("host-1")]]));
  });

  it("omits result for a null-argument command and still succeeds", async () => {
    const { client } = clientWith(async () => encodeAdminReply({ v: 1, ok: true }));
    const sent = await client.send("rotate_admission_key", CborValue.null());
    expect(sent.result).toBeUndefined();
    expect(sent.reply.ok).toBe(true);
  });

  it("increments a fixed seq process-locally", async () => {
    const { client, transport } = clientWith(async () => encodeAdminReply({ v: 1, ok: true }));
    await client.send("list_hosts", CborValue.null());
    await client.send("list_hosts", CborValue.null());
    expect(AdminCommand.fromCanonicalBytes(transport.requests[0].payload).seq).toBe(7n);
    expect(AdminCommand.fromCanonicalBytes(transport.requests[1].payload).seq).toBe(8n);
  });

  it("uses a caller-supplied seq function on every send", async () => {
    let seq = 100n;
    const { client, transport } = clientWith(async () => encodeAdminReply({ v: 1, ok: true }), {
      seq: () => seq++,
    });
    await client.send("list_hosts", CborValue.null());
    await client.send("list_hosts", CborValue.null());
    expect(AdminCommand.fromCanonicalBytes(transport.requests[0].payload).seq).toBe(100n);
    expect(AdminCommand.fromCanonicalBytes(transport.requests[1].payload).seq).toBe(101n);
  });

  it("honours per-send nonce/ts/seq/v overrides", async () => {
    const { client, transport } = clientWith(async () => encodeAdminReply({ v: 1, ok: true }));
    const nonce = new Uint8Array(16).fill(0x77);
    await client.send("set_mode", CborValue.null(), { seq: 9n, nonce, ts: 1_755_907_260n, v: 1 });
    const decoded = AdminCommand.fromCanonicalBytes(transport.requests[0].payload);
    expect(decoded.seq).toBe(9n);
    expect(bytesToHex(decoded.nonce)).toBe(bytesToHex(nonce));
    expect(decoded.ts).toBe(1_755_907_260n);
  });

  it("maps a helper refusal to a typed error without leaking peer detail into the message", async () => {
    const nonceHex = bytesToHex(NONCE);
    const reply = encodeAdminReply({
      v: 1,
      ok: false,
      error: { code: "mode_locked", message: `refused while handling nonce ${nonceHex}` },
    });
    const { client } = clientWith(async () => reply);

    try {
      await client.send("evict_host", ARGS);
      throw new Error("expected AdminClient.send to reject");
    } catch (err) {
      expect(err).toBeInstanceOf(AdminError);
      const e = err as AdminError;
      expect(e.kind).toBe("Refused");
      expect(e.code).toBe("mode_locked");
      // Peer-supplied detail is available as a field, but never interpolated into `.message`.
      expect(e.detail).toContain(nonceHex);
      expect(e.message).not.toContain(nonceHex);
      expect(e.message).not.toContain("mode_locked");
    }
  });

  it("wraps a transport failure as a typed Transport error without leaking its message", async () => {
    const nonceHex = bytesToHex(NONCE);
    const { client } = clientWith(async () => {
      throw new Error(`publish failed for payload ${nonceHex}`);
    });

    try {
      await client.send("evict_host", ARGS);
      throw new Error("expected AdminClient.send to reject");
    } catch (err) {
      expect(err).toBeInstanceOf(AdminError);
      const e = err as AdminError;
      expect(e.kind).toBe("Transport");
      expect(e.subject).toBe("registry.admin.evict_host");
      expect(e.message).not.toContain(nonceHex);
      expect((e.cause as Error).message).toContain(nonceHex);
    }
  });

  it("rejects malformed replies", async () => {
    const malformed: Uint8Array[] = [
      new Uint8Array(0),
      Uint8Array.from([0xff]),
      Uint8Array.from([0x61, 0x61]), // text "a"
      // map {v:1} — missing `ok`
      Uint8Array.from([0xa1, 0x61, 0x76, 0x01]),
      // map {v:1, ok:false} — missing `error`
      Uint8Array.from([0xa2, 0x61, 0x76, 0x01, 0x62, 0x6f, 0x6b, 0xf4]),
      // map {v:1, ok:true, error:{code:"x"}} — error with ok:true
      Uint8Array.from([
        0xa3, 0x61, 0x76, 0x01, 0x62, 0x6f, 0x6b, 0xf5, 0x65, 0x65, 0x72, 0x72, 0x6f, 0x72,
        0xa1, 0x64, 0x63, 0x6f, 0x64, 0x65, 0x61, 0x78,
      ]),
      // map {v:99, ok:true} — version above the ceiling
      Uint8Array.from([0xa2, 0x61, 0x76, 0x18, 0x63, 0x62, 0x6f, 0x6b, 0xf5]),
    ];

    for (const bytes of malformed) {
      const { client } = clientWith(async () => bytes);
      await expect(client.send("evict_host", ARGS)).rejects.toMatchObject({
        kind: "MalformedReply",
      });
    }
  });

  it("rejects a reply that is not a Uint8Array", async () => {
    const { client } = clientWith(async () => "not bytes" as unknown as Uint8Array);
    await expect(client.send("evict_host", ARGS)).rejects.toMatchObject({
      kind: "MalformedReply",
    });
  });

  it("rejects an unknown command before touching the transport", async () => {
    const transport = new RecordingTransport(async () => encodeAdminReply({ v: 1, ok: true }));
    const client = new AdminClient({
      transport,
      signer: signer(),
      seq: 1n,
      nonce: () => NONCE,
      now: () => 1n,
    });
    await expect(
      client.send("not_a_command" as unknown as "evict_host", ARGS),
    ).rejects.toMatchObject({ kind: "UnknownCommand" });
    expect(transport.requests).toHaveLength(0);
  });

  it("rejects an out-of-range version through the builder", async () => {
    const { client } = clientWith(async () => encodeAdminReply({ v: 1, ok: true }));
    await expect(client.send("evict_host", ARGS, { v: 2 })).rejects.toMatchObject({
      kind: "VersionTooHigh",
    });
  });
});
