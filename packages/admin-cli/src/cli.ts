#!/usr/bin/env node
// spindle-admin — the v1 operator CLI over @spindle/admin (A3b/A10.19). All signing and protocol
// logic lives in the library; this file only parses flags, supplies the NATS transport, persists
// the per-signer sequence, and renders results.

import process from "node:process";

import { Command, Option } from "commander";

import {
  AdminClient,
  AdminError,
  FileKeySigner,
  type AdminCommandName,
  type AdminTransport,
} from "@spindle/admin";
import { CborValue, hexToBytes } from "@spindle/proto";

import { defaultSeqPath, SeqFile } from "./seq.js";
import { NatsAdminTransport } from "./transport.js";

interface GlobalOptions {
  seedFile: string;
  natsUrl: string;
  natsSeed?: string;
  seqFile?: string;
  signerFp?: string;
  seqStart?: string;
}

const HOST_FP_LEN = 32;

function hostFingerprint(hex: string): CborValue {
  const bytes = hexToBytes(hex.replace(/^0x/, ""));
  if (bytes.length !== HOST_FP_LEN) {
    throw new Error(`--host-fp must be ${HOST_FP_LEN} bytes (${HOST_FP_LEN * 2} hex chars)`);
  }
  return CborValue.bytes(bytes);
}

/** A JSON-ish rendering of the opaque admin result, for terminal output only. */
export function renderCbor(value: CborValue): unknown {
  switch (value.kind) {
    case "uint":
    case "negint":
      return value.value.toString();
    case "bytes":
      return `0x${Array.from(value.value as Uint8Array, (b) => b.toString(16).padStart(2, "0")).join("")}`;
    case "text":
      return value.value;
    case "bool":
      return value.value;
    case "null":
      return null;
    case "array":
      return (value.value as CborValue[]).map(renderCbor);
    case "map": {
      const out: Record<string, unknown> = {};
      for (const [k, v] of value.value as Array<[CborValue, CborValue]>) {
        out[String(renderCbor(k))] = renderCbor(v);
      }
      return out;
    }
  }
}

const program = new Command();
program
  .name("spindle-admin")
  .description("Operator CLI for the Spindle registry admin plane (registry.admin.>)")
  .requiredOption("--seed-file <path>", "32-byte operator Ed25519 seed file (mode 0600)")
  .option("--nats-url <url>", "NATS URL", process.env.SPINDLE_NATS_URL ?? "nats://127.0.0.1:4222")
  .option(
    "--nats-seed <seed>",
    "operator NATS nkey seed (or SPINDLE_ADMIN_NATS_SEED)",
    process.env.SPINDLE_ADMIN_NATS_SEED,
  )
  .option("--seq-file <path>", "sequence file (default: <seed-file>.seq)")
  .option("--signer-fp <hex>", "operator fingerprint override (32 bytes hex)")
  .option("--seq-start <n>", "minimum sequence number (default: from the seq file)");

function withMode(command: Command): Command {
  return command.addOption(
    new Option("--mode <mode>", "admission mode").choices(["open", "invite", "closed"]).makeOptionMandatory(),
  );
}

withMode(program.command("set-mode")).action(async (opts, command) => {
  await send(command, "set_mode", CborValue.map([["mode", CborValue.text(opts.mode)]]));
});

program
  .command("pre-register-host")
  .requiredOption("--host-fp <hex>", "host root fingerprint (32 bytes hex)")
  .requiredOption("--label <text>", "human label")
  .requiredOption("--quota-profile <name>", "quota profile")
  .action(async (opts, command) => {
    await send(
      command,
      "pre_register_host",
      CborValue.map([
        ["host_fp", hostFingerprint(opts.hostFp)],
        ["label", CborValue.text(opts.label)],
        ["quota_profile", CborValue.text(opts.quotaProfile)],
      ]),
    );
  });

program.command("list-hosts").action(async (_opts, command) => {
  await send(command, "list_hosts", CborValue.null());
});

program
  .command("suspend-host")
  .requiredOption("--host-fp <hex>", "host root fingerprint (32 bytes hex)")
  .action(async (opts, command) => {
    await send(
      command,
      "suspend_host",
      CborValue.map([["host_fp", hostFingerprint(opts.hostFp)]]),
    );
  });

program
  .command("evict-host")
  .requiredOption("--host-fp <hex>", "host root fingerprint (32 bytes hex)")
  .action(async (opts, command) => {
    await send(
      command,
      "evict_host",
      CborValue.map([["host_fp", hostFingerprint(opts.hostFp)]]),
    );
  });

program
  .command("set-quota-profile")
  .requiredOption("--host-fp <hex>", "host root fingerprint (32 bytes hex)")
  .requiredOption("--quota-profile <name>", "quota profile")
  .action(async (opts, command) => {
    await send(
      command,
      "set_quota_profile",
      CborValue.map([
        ["host_fp", hostFingerprint(opts.hostFp)],
        ["quota_profile", CborValue.text(opts.quotaProfile)],
      ]),
    );
  });

program
  .command("read-audit-log")
  .description("read the hash-chained admin audit log")
  .action(async (_opts, command) => {
    await send(command, "read_audit_log", CborValue.null());
  });

program
  .command("mint-invite")
  .requiredOption("--label <text>", "host label")
  .requiredOption("--quota-profile <name>", "quota profile")
  .requiredOption("--ttl-secs <n>", "token lifetime in seconds", Number)
  .action(async (opts, command) => {
    await send(
      command,
      "mint_invite",
      CborValue.map([
        ["label", CborValue.text(opts.label)],
        ["quota_profile", CborValue.text(opts.quotaProfile)],
        ["ttl_secs", CborValue.uint(BigInt(opts.ttlSecs))],
      ]),
    );
  });

program
  .command("revoke-invite")
  .requiredOption("--nonce <hex>", "admission-token nonce")
  .action(async (opts, command) => {
    await send(
      command,
      "revoke_invite",
      CborValue.map([["nonce", CborValue.bytes(hexToBytes(opts.nonce.replace(/^0x/, "")))]]),
    );
  });

program.command("rotate-admission-key").action(async (_opts, command) => {
  await send(command, "rotate_admission_key", CborValue.null());
});

/** Extracts the global options from whichever command node invoked `send`. */
function globals(command: Command): GlobalOptions {
  return command.optsWithGlobals<GlobalOptions>();
}

async function send(command: Command, cmd: AdminCommandName, args: CborValue): Promise<void> {
  const options = globals(command);
  let transport: NatsAdminTransport | undefined;
  try {
    if (!options.natsSeed || options.natsSeed.length === 0) {
      throw new Error(
        "operator NATS nkey seed is required: set SPINDLE_ADMIN_NATS_SEED or pass --nats-seed",
      );
    }
    const signer = await FileKeySigner.open(options.seedFile, {
      signerFp: options.signerFp ? hexToBytes(options.signerFp.replace(/^0x/, "")) : undefined,
    });
    const seq = SeqFile.open(
      options.seqFile ?? defaultSeqPath(options.seedFile),
      options.seqStart ? BigInt(options.seqStart) : 0n,
    );
    transport = await NatsAdminTransport.connect({
      url: options.natsUrl,
      nkeySeed: new TextEncoder().encode(options.natsSeed),
    });
    const client = new AdminClient({ transport, signer, seq: () => seq.next() });
    const result = await client.send(cmd, args);
    if (result.result !== undefined) {
      console.log(JSON.stringify(renderCbor(result.result), null, 2));
    } else {
      console.log("ok");
    }
  } catch (error) {
    if (error instanceof AdminError) {
      console.error(`refused: ${error.kind}${error.detail ? ": " + error.detail : ""}`);
    } else {
      console.error(error instanceof Error ? error.message : String(error));
    }
    process.exitCode = 1;
  } finally {
    await transport?.close().catch(() => undefined);
  }
}

/** Parses `argv` and runs one command. Exported for tests; `index.ts` calls it in production. */
export async function main(argv: string[] = process.argv): Promise<void> {
  try {
    await program.parseAsync(argv);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
