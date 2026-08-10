import { describe, expect, it } from "vitest";

import { buildDesigner, carriesData, changeRows, designerRows, previewFor } from "./publisher";

/**
 * The disclosure designer renders a report and a manifest, both supplied by
 * whoever is operating it — which in practice means whatever a compliance team
 * exported, not necessarily what this code expects.
 *
 * Same contract as the console and the offline verifier: a render must not
 * throw. This is the last browser surface that had no such test, and the three
 * before it each had a real defect.
 */
const report = (over: Record<string, unknown> = {}): any => ({
  format_version: "canton-solvency-report-v1",
  profile: "solvency.liabilities",
  publisher: "venue::test",
  snapshot_time: "2026-01-01T00:00:00Z",
  ledger_offset: "000000000000000042",
  root_hash: "aa".repeat(32),
  leaf_count: 2,
  root_sums: { USDA: "1.000000000000000000" },
  mark_prices: {},
  disclosures: { bad_debt: {}, excluded_house_accounts: 0, excluded_house_totals: {} },
  ...over,
});

const manifest = (fields: Record<string, string> = { root_sums: "published" }): any => ({
  audience: "public",
  fields,
});

/** The shapes a hand-edited or foreign document actually arrives in. */
const NOT_A_MAP = [null, undefined, "zz", 0, [], true];

describe("the disclosure designer on malformed input", () => {
  it("renders a well-formed pair, so the harness is wired to something real", () => {
    expect(designerRows(report(), manifest()).length).toBeGreaterThan(0);
  });

  it("does not throw when an aggregate is not a map", () => {
    for (const value of NOT_A_MAP) {
      for (const field of ["root_sums", "mark_prices", "disclosures"]) {
        const doc = report({ [field]: value });
        expect(
          () => designerRows(doc, manifest()),
          `${field} = ${JSON.stringify(value)}`
        ).not.toThrow();
        expect(
          () => carriesData(doc, "root_sums"),
          `carriesData with ${field} = ${JSON.stringify(value)}`
        ).not.toThrow();
      }
    }
  });

  it("does not throw when the manifest is malformed", () => {
    for (const fields of NOT_A_MAP) {
      const m = { audience: "public", fields } as any;
      expect(() => designerRows(report(), m), `fields = ${JSON.stringify(fields)}`).not.toThrow();
      expect(() => previewFor(m), `previewFor ${JSON.stringify(fields)}`).not.toThrow();
      expect(() => changeRows(null, m), `changeRows ${JSON.stringify(fields)}`).not.toThrow();
      expect(() => changeRows(m, manifest()), `changeRows prev ${JSON.stringify(fields)}`).not.toThrow();
    }
  });

  it("does not throw on an unknown disclosure state", () => {
    const m = manifest({ root_sums: "sideways", customer_balances: "" });
    expect(() => designerRows(report(), m)).not.toThrow();
    expect(() => previewFor(m)).not.toThrow();
    expect(() => changeRows(manifest(), m)).not.toThrow();
  });

  it("does not throw when building the whole designer view", () => {
    // Including a manifest with no audience, which the designer reads with
    // .trim() when deciding whether to complain about it.
    expect(() => buildDesigner(report(), { fields: {} } as any, null)).not.toThrow();
    for (const value of NOT_A_MAP) {
      expect(() =>
        buildDesigner(report({ root_sums: value }) as any, manifest(), null)
      ).not.toThrow();
    }
  });
});
