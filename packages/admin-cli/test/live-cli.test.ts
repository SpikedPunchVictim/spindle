// Live CLI integration test (td-6c9b85). Gated by SPINDLE_ADMIN_LIVE=1 so CI does not need a
// registry; run with the compose stack and the dev operator/app seeds:
//
//   SPINDLE_ADMIN_LIVE=1 pnpm --filter spindle-admin test

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { hexToBytes } from "@spindle/proto";

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.resolve(here, "..", "dist", "index.js");
const OPERATOR_SEED_HEX =
  "e595e1797f66bac7093f959c5692e73fa3a33c41cadc47d139c87ef0bfc1b273";
const APP_CONN_SEED =
  "SUAFWWQRCTGQTS6DKVAJKMMFMIJKFZ3MRFGFQ4WCRZ5RVZ5WFRB4CXPYBY";

describe.skipIf(process.env.SPINDLE_ADMIN_LIVE !== "1")("spindle-admin live", () => {
  it("sets the mode and lists hosts through the real registry", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "spindle-admin-live-"));
    const seedFile = path.join(dir, "operator.seed");
    fs.writeFileSync(seedFile, hexToBytes(OPERATOR_SEED_HEX), { mode: 0o600 });
    const seqStart = (Date.now() * 1_000).toString();

    const run = (...args: string[]) =>
      execFileSync(process.execPath, [cli, "--seed-file", seedFile, "--nats-seed", APP_CONN_SEED, "--seq-start", seqStart, ...args], {
        encoding: "utf8",
        env: { ...process.env, SPINDLE_NATS_URL: "nats://127.0.0.1:4222" },
      });

    expect(run("set-mode", "--mode", "open").trim()).toBe("ok");
    expect(run("list-hosts").trim().startsWith("[")).toBe(true);
  }, 20_000);
});
