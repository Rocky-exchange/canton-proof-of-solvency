import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyReportV2 } from "./report";

const fixture = (n: string): any =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../../fixtures/${n}`, import.meta.url)), "utf8"));
const KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

/**
 * The v2 verification path reads the manifest and the disclosures block, both
 * of which come from the report under examination. Neither was guarded: a
 * manifest whose `fields` is not a map, or a report with no `disclosures` at
 * all, threw a TypeError out of `verifyReportV2` rather than failing it.
 *
 * This is the same defect as the four browser surfaces, in the verification
 * path rather than a render, which is why the guard now has one name in
 * `verify.ts` instead of a copy per module.
 */
describe("v2 verification on malformed metadata", () => {
  it("fails rather than throws when manifest.fields is not a map", async () => {
    for (const fields of [null, "zz", [], 0]) {
      const report = fixture("report-v2.golden.json");
      report.report.manifest = { audience: "public", fields };
      await expect(
        verifyReportV2(report, fixture("proof-for-report-v2.golden.json"), KEY),
        `manifest.fields = ${JSON.stringify(fields)}`
      ).resolves.toHaveProperty("ok", false);
    }
  });
  it("fails rather than throws when the disclosures block is missing", async () => {
    const report = fixture("report-v2.golden.json");
    delete report.report.disclosures;
    await expect(verifyReportV2(report, fixture("proof-for-report-v2.golden.json"), KEY)).resolves.toHaveProperty("ok", false);
  });
});
