import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { CborValue } from "@spindle/proto";

import { renderCbor } from "../src/cli.js";
import { SeqFile } from "../src/seq.js";

describe("spindle-admin helpers", () => {
  it("renders results without losing bytes or map keys", () => {
    expect(renderCbor(CborValue.text("ready"))).toBe("ready");
    expect(renderCbor(CborValue.bytes(new Uint8Array([0x01, 0xab])))).toBe("0x01ab");
    expect(
      renderCbor(
        CborValue.map([
          ["label", CborValue.text("host")],
          ["count", CborValue.uint(2)],
        ]),
      ),
    ).toEqual({ label: "host", count: "2" });
  });

  it("persists a monotonic sequence across reopen", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "spindle-admin-seq-"));
    const file = path.join(dir, "op.seed.seq");
    const first = SeqFile.open(file);
    expect(first.next()).toBe(1n);
    expect(first.next()).toBe(2n);
    const reopened = SeqFile.open(file);
    expect(reopened.next()).toBe(3n);
    expect(fs.statSync(file).mode & 0o077).toBe(0);
  });
});
