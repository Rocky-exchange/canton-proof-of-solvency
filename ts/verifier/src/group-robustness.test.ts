import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verifyMembership } from "./group";
import { verifyReport } from "./report";

/**
 * Group verification takes documents from the party being checked, like every
 * other entry point here, and must return a failure rather than throw one.
 *
 * `verifyReport` already does: a malformed amount comes back as
 * `{ ok: false, failure: { kind: "malformed" } }`, which is what lets the
 * offline verifier render a sentence instead of a blank page. The question is
 * whether the group path, added later, does the same.
 */
const fixture = (name: string): any =>
  JSON.parse(
    readFileSync(fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url)), "utf8")
  );

const KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

const BAD = ["", "zz", "-1", "1.", "1e18", "9".repeat(60)];

describe("group verification on malformed input", () => {
  it("accepts the golden pair, so the harness is wired to something real", async () => {
    const result = await verifyMembership(
      fixture("group-report.golden.json"),
      fixture("group-membership.golden.json"),
      KEY
    );
    expect(result.ok).toBe(true);
  });

  it("returns a failure rather than throwing on a malformed amount", async () => {
    for (const amount of BAD) {
      const report = fixture("group-report.golden.json");
      report.report.root_sums = { USDA: amount };
      await expect(
        verifyMembership(report, fixture("group-membership.golden.json"), KEY),
        `group root_sums USDA = ${JSON.stringify(amount)}`
      ).resolves.toHaveProperty("ok", false);
    }
  });

  it("returns a failure rather than throwing on a malformed membership", async () => {
    for (const amount of BAD) {
      const membership = fixture("group-membership.golden.json");
      membership.entity.root_sums = { USDA: amount };
      await expect(
        verifyMembership(fixture("group-report.golden.json"), membership, KEY),
        `entity.root_sums USDA = ${JSON.stringify(amount)}`
      ).resolves.toHaveProperty("ok", false);
    }
  });

  it("returns a failure rather than throwing when sums are not a map", async () => {
    for (const sums of [null, "zz", [], 0]) {
      const report = fixture("group-report.golden.json");
      report.report.root_sums = sums;
      await expect(
        verifyMembership(report, fixture("group-membership.golden.json"), KEY),
        `root_sums = ${JSON.stringify(sums)}`
      ).resolves.toHaveProperty("ok", false);
    }
  });
});

/**
 * The same fault reached the main entry point, and was invisible because the
 * offline verifier catches at its own boundary. `verifyReport` returns a
 * `VerificationResult`; a caller reading that signature is entitled to assume
 * it does not throw.
 */
describe("verifyReport on aggregates that are not maps", () => {
  it("returns a failure rather than throwing", async () => {
    for (const sums of [null, "zz", [], 0, undefined]) {
      const report = fixture("report.golden.json");
      report.report.root_sums = sums;
      await expect(
        verifyReport(report, fixture("proof.golden.json"), KEY),
        `root_sums = ${JSON.stringify(sums)}`
      ).resolves.toHaveProperty("ok", false);
    }
  });

  it("returns a failure when mark_prices is not a map", async () => {
    for (const prices of [null, "zz", []]) {
      const report = fixture("report.golden.json");
      report.report.mark_prices = prices;
      await expect(
        verifyReport(report, fixture("proof.golden.json"), KEY),
        `mark_prices = ${JSON.stringify(prices)}`
      ).resolves.toHaveProperty("ok", false);
    }
  });
});
