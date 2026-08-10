import { describe, expect, it } from "vitest";

import { coverageRows, flowOf } from "./console";

/**
 * The console renders documents supplied by the party being checked, exactly
 * as the offline verifier does, and the offline verifier turned out to throw
 * on a malformed amount rather than report one. These are the same paths in
 * the console: a coverage table and a data-flow view, both of which format
 * amounts for display.
 *
 * A display path should not be able to take down the page. Whether the figure
 * is shown as "(malformed)" or the row is dropped is a design choice; throwing
 * out of the render is not.
 */
const report = (rootSums: Record<string, string>): any => ({
  format_version: "canton-solvency-report-v1",
  profile: "solvency.liabilities",
  publisher: "venue::test",
  snapshot_time: "2026-01-01T00:00:00Z",
  ledger_offset: "000000000000000042",
  root_hash: "aa".repeat(32),
  leaf_count: 2,
  root_sums: rootSums,
  mark_prices: {},
  disclosures: { bad_debt: {}, excluded_house_accounts: 0, excluded_house_totals: {} },
});

const BAD_AMOUNTS = ["", "zz", "-1", "1.", ".1", "1e18", "9".repeat(60), "１"];

describe("the console on malformed amounts", () => {
  it("renders a well-formed report, so the harness is wired to something real", () => {
    const nodes = flowOf(report({ USDA: "1.000000000000000000" }));
    expect(nodes.length).toBeGreaterThan(1);
  });

  it("does not throw out of the data-flow view", () => {
    for (const amount of BAD_AMOUNTS) {
      expect(() => flowOf(report({ USDA: amount })), `root_sums USDA = ${JSON.stringify(amount)}`)
        .not.toThrow();
    }
  });

  it("does not throw out of the coverage table", () => {
    for (const amount of BAD_AMOUNTS) {
      const custody = report({ "held/USDA": amount });
      const liabilities = report({ USDA: "1.000000000000000000" });
      expect(
        () => coverageRows(custody, liabilities),
        `custody held/USDA = ${JSON.stringify(amount)}`
      ).not.toThrow();

      const owed = report({ USDA: amount });
      expect(
        () => coverageRows(report({ "held/USDA": "1.000000000000000000" }), owed),
        `liabilities USDA = ${JSON.stringify(amount)}`
      ).not.toThrow();
    }
  });

  it("does not throw when root_sums is not an amount map at all", () => {
    for (const sums of [null, "zz", [], 0]) {
      expect(() => flowOf(report(sums as any)), `root_sums = ${JSON.stringify(sums)}`).not.toThrow();
    }
  });
});
