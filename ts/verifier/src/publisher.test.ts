import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { buildDesigner, carriesData, changeRows, previewFor } from "./publisher";
import type { Manifest, Report, SignedReport } from "./report";

const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url)), "utf8");

const report = (): Report => (JSON.parse(fixture("report-v2.golden.json")) as SignedReport).report;
const goldenManifest = (): Manifest => report().manifest!;

const manifest = (fields: Record<string, string>, audience = "public"): Manifest =>
  ({ audience, fields }) as Manifest;

describe("disclosure designer", () => {
  it("reports what the draft actually carries, field by field", () => {
    const rows = buildDesigner(report(), goldenManifest(), null).fields;
    const bySum = rows.find((r) => r.path === "root_sums")!;
    expect(bySum.carriesData).toBe(true);
    expect(bySum.state).toBe("published");
    expect(bySum.problem).toBeNull();
  });

  /// The designer must catch what verification would reject, before publishing
  /// rather than after.
  it("flags a field declared published that the report does not carry", () => {
    const draft = report();
    draft.mark_prices = {};
    const model = buildDesigner(draft, goldenManifest(), null);
    expect(model.problems.some((p) => p.includes("mark_prices"))).toBe(true);
  });

  it("flags a field declared withheld that the report publishes anyway", () => {
    const model = buildDesigner(
      report(),
      manifest({ root_sums: "withheld" }),
      null
    );
    expect(model.problems.some((p) => p.includes("publishes it anyway"))).toBe(true);
  });

  it("requires an audience, since a packaging is for someone in particular", () => {
    const model = buildDesigner(report(), manifest({ root_sums: "published" }, "  "), null);
    expect(model.problems.some((p) => p.includes("no audience"))).toBe(true);
  });

  /// Fields attested through the commitment are not in the body, so the body
  /// check must not fire on them.
  it("does not flag fields proven through the commitment", () => {
    const model = buildDesigner(report(), goldenManifest(), null);
    expect(model.problems).toEqual([]);
    expect(carriesData(report(), "customer_balances")).toBe(false);
  });
});

describe("pre-publication diff", () => {
  const before = manifest({ root_sums: "published", mark_prices: "published" });

  it("reports nothing when nothing changed", () => {
    expect(changeRows(before, before)).toEqual([]);
  });

  /// The reason the screen exists: disclosure shrinking is never accidental.
  it("marks a field moving away from published as a reduction", () => {
    const rows = changeRows(before, manifest({ root_sums: "published", mark_prices: "withheld" }));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ path: "mark_prices", reduction: true });
  });

  it("marks a published field dropped entirely as a reduction", () => {
    const rows = changeRows(before, manifest({ root_sums: "published" }));
    expect(rows[0]).toMatchObject({ path: "mark_prices", to: null, reduction: true });
  });

  it("does not mark an expansion as a reduction", () => {
    const rows = changeRows(
      manifest({ mark_prices: "withheld" }),
      manifest({ mark_prices: "published" })
    );
    expect(rows[0].reduction).toBe(false);
  });

  it("surfaces reductions as warnings on the model", () => {
    const draft = report();
    draft.mark_prices = {};
    const model = buildDesigner(draft, manifest({ root_sums: "published" }), before);
    expect(model.warnings.some((w) => w.includes("mark_prices"))).toBe(true);
  });

  it("has nothing to diff against on a first publication", () => {
    expect(buildDesigner(report(), goldenManifest(), null).changes).toEqual([]);
  });
});

describe("audience preview", () => {
  it("splits fields into shown, proven-only, and withheld", () => {
    const preview = previewFor(goldenManifest());
    expect(preview.audience).toBe("public");
    expect(preview.shown).toContain("root_sums");
    expect(preview.provenOnly).toContain("customer_balances");
    expect(preview.withheld).toContain("customer_identities");
  });

  /// What one audience sees must not depend on what another was shown.
  it("describes only the packaging it was given", () => {
    const auditor = previewFor(
      manifest({ root_sums: "published", customer_identities: "published" }, "auditor")
    );
    expect(auditor.audience).toBe("auditor");
    expect(auditor.shown).toEqual(["customer_identities", "root_sums"]);
    expect(auditor.withheld).toEqual([]);
  });
});
