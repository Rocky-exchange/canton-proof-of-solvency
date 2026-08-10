import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verifyFromText } from "./offline";
import { parseAmount18dp } from "./verify";

/**
 * The browser verifier must fail visibly, never throw.
 *
 * Every file it reads was supplied by the party being checked, and it runs in
 * a page whose error console nobody is watching. A thrown exception leaves the
 * reader looking at a screen that says nothing — worse than a clear "this did
 * not verify", because it is indistinguishable from the page being broken.
 *
 * The Rust suite asserts the same property for the CLI. This is its mirror:
 * every input must resolve to a ViewModel, and a malformed one must resolve to
 * `status: "error"` rather than reject.
 */
const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url)), "utf8");

const KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

const report = fixture("report.golden.json");
const proof = fixture("proof.golden.json");

describe("the browser verifier on malformed input", () => {
  it("accepts the golden pair, so the harness is wired to something real", async () => {
    const view = await verifyFromText(report, proof, KEY);
    expect(view.status).toBe("verified");
  });

  it("reports rather than throws on truncation at any offset", async () => {
    // Every 7th offset: broad coverage without hundreds of crypto round trips.
    for (let cut = 0; cut < report.length; cut += 7) {
      const view = await verifyFromText(report.slice(0, cut), proof, KEY);
      expect(view.status, `report truncated at ${cut}`).toBe("error");
    }
    for (let cut = 0; cut < proof.length; cut += 7) {
      const view = await verifyFromText(report, proof.slice(0, cut), KEY);
      expect(view.status, `proof truncated at ${cut}`).toBe("error");
    }
  });

  it("says so plainly when the two files are swapped", async () => {
    const view = await verifyFromText(proof, report, KEY);
    expect(view.status).toBe("error");
    // A reader needs to know what to do, not merely that something is wrong.
    expect(view.detail).toMatch(/swapped/i);
  });

  it("reports rather than throws on a wrong type in any field", async () => {
    const substitutes = [null, 0, -1, "", "zz", "0x00", [], {}, "a".repeat(65)];
    const paths = [
      "root_hash",
      "leaf_count",
      "format_version",
      "profile",
      "publisher",
      "snapshot_time",
      "ledger_offset",
      "root_sums",
    ];
    for (const path of paths) {
      for (const value of substitutes) {
        const doc = JSON.parse(report);
        doc.report[path] = value;
        const view = await verifyFromText(JSON.stringify(doc), proof, KEY);
        expect(view.status, `report.${path} = ${JSON.stringify(value)}`).not.toBe("verified");
      }
    }
  });

  it("reports rather than throws on a malformed trusted key", async () => {
    for (const key of ["", "not hex", "0x", "a".repeat(63), "a".repeat(65), " ", "ZZ".repeat(32)]) {
      const view = await verifyFromText(report, proof, key);
      expect(view.status, `key ${JSON.stringify(key)}`).toBe("error");
    }
  });

  it("reports rather than throws on deeply nested JSON", async () => {
    for (const depth of [64, 1000, 20000]) {
      const nested = "[".repeat(depth) + "]".repeat(depth);
      const view = await verifyFromText(nested, proof, KEY);
      expect(view.status, `nesting depth ${depth}`).toBe("error");
    }
  });

  it("agrees with the producer about the largest representable amount", () => {
    // SPEC §1 bounds the scaled value at 2^128 - 1. Rust parses into u128 and
    // rejects anything above it with checked arithmetic; BigInt has no such
    // limit, so this is the boundary at which the two could disagree.
    const max = (1n << 128n) - 1n;
    const asDecimal = (v: bigint) => `${v / 10n ** 18n}.${(v % 10n ** 18n).toString().padStart(18, "0")}`;

    expect(parseAmount18dp(asDecimal(max))).toBe(max);
    expect(() => parseAmount18dp(asDecimal(max + 1n))).toThrow(/representable range/);
    expect(() => parseAmount18dp("9".repeat(60))).toThrow(/representable range/);
  });

  it("rejects adversarial amounts with a real error", () => {
    // parseAmount18dp throws by design. The contract under test is that it
    // throws rather than returning NaN or a silently truncated bigint.
    const bad = [
      "",
      ".",
      "-",
      "+1",
      "1.",
      ".1",
      "1.2.3",
      "1e18",
      "０", // fullwidth zero
      "١", // Arabic-Indic one
      "9".repeat(100),
      `1.${"0".repeat(19)}`,
    ];
    for (const amount of bad) {
      expect(() => parseAmount18dp(amount), `amount ${JSON.stringify(amount)}`).toThrow();
    }
  });
});
