// Golden-vector conformance for td-b8c68a's Ed25519 canonicality fix and the deliberate
// non-validation of X25519 keys — the cross-language contract lives in `vectors/key-validity.json`
// (see DESIGN.md :1117 on `vectors/` as the cross-language contract, and this file's Rust twin,
// `crates/spindle-core/tests/vectors.rs`'s `key_validity_vectors_agree_with_checked_verifying_key`).
//
// Each `"ed25519"` case is driven directly through `artifacts.ts`'s real, exported
// `requireEd25519PublicKey` — not a reimplementation of its logic against the raw
// `ed25519.Point.fromBytes` primitive — so this test actually exercises production code, the same
// way the Rust twin calls the exported `checked_verifying_key` rather than re-deriving canonicality
// itself.
//
// Each `"x25519"` case only asserts `expected === "accept"` and the key's length: X25519 public
// keys are unvalidated by design on both sides of the Rust/TS boundary (mirrors
// `x25519_dalek::PublicKey::from`'s infallibility — see `spindle_core::checked_verifying_key`'s
// doc comment). A future case setting `expected: "reject"` for an X25519 key would mean the vector
// itself has drifted from that deliberate agreement, not that this test needs updating.

import { hexToBytes } from "@spindle/proto";
import { describe, expect, it } from "vitest";

import { ArtifactError, requireEd25519PublicKey } from "../src/artifacts.js";
import { loadTopVectorFile } from "./helpers.js";

interface KeyValidityCase {
  name: string;
  description: string;
  curve: "ed25519" | "x25519";
  key_hex: string;
  expected: "accept" | "reject";
}

describe("key-validity.json", () => {
  const doc = loadTopVectorFile("key-validity.json") as { cases: KeyValidityCase[] };

  for (const c of doc.cases) {
    it(`${c.name}: ${c.curve} must ${c.expected}`, () => {
      const key = hexToBytes(c.key_hex);
      expect(key.length).toBe(32);

      if (c.curve === "ed25519") {
        let accepted: boolean;
        try {
          requireEd25519PublicKey(key);
          accepted = true;
        } catch (e) {
          expect(e).toBeInstanceOf(ArtifactError);
          expect((e as ArtifactError).kind).toBe("InvalidPublicKey");
          accepted = false;
        }
        expect(accepted).toBe(c.expected === "accept");
      } else if (c.curve === "x25519") {
        expect(c.expected).toBe("accept");
      } else {
        throw new Error(`case ${c.name}: unknown curve ${c.curve as string}`);
      }
    });
  }
});
