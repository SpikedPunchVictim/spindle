// Per-operator monotonic sequence persistence for the admin CLI. The helper refuses a reused seq,
// so the CLI must advance this before every command. One file per operator seed keeps two
// operators on one machine independent.

import fs from "node:fs";
import path from "node:path";

export class SeqFile {
  readonly #path: string;
  #last: bigint;

  private constructor(file: string, last: bigint) {
    this.#path = file;
    this.#last = last;
  }

  /** Default location: `<seed file>.seq` next to the operator seed. */
  static open(file: string, startAt = 0n): SeqFile {
    let last = 0n;
    try {
      const text = fs.readFileSync(file, "utf8");
      const parsed = JSON.parse(text) as { last?: string };
      if (parsed.last !== undefined) last = BigInt(parsed.last);
    } catch {
      // Missing/unreadable file is a fresh sequence; the helper's durable replay guard is the
      // authority and will refuse a lower seq loudly rather than silently reusing one.
    }
    return new SeqFile(file, last > startAt ? last : startAt);
  }

  next(): bigint {
    this.#last += 1n;
    fs.writeFileSync(this.#path, JSON.stringify({ last: this.#last.toString() }) + "\n", {
      mode: 0o600,
    });
    return this.#last;
  }

  get path(): string {
    return this.#path;
  }
}

/** `<seed>.seq`, alongside the seed file. */
export function defaultSeqPath(seedFile: string): string {
  return path.join(path.dirname(seedFile), `${path.basename(seedFile)}.seq`);
}
