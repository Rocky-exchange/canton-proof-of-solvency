import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020";
import { describe, expect, it } from "vitest";

/**
 * The published JSON Schemas are what third-party tooling parses against, so
 * they have to stay in step with what the producer actually emits. These tests
 * fail if the schemas drift from the golden fixtures in either direction.
 */
const repoFile = (path: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url)), "utf8");

const json = (path: string): unknown => JSON.parse(repoFile(path));

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateReport = ajv.compile(json("schemas/report-v1.schema.json") as object);
const validateProof = ajv.compile(json("schemas/proof-v1.schema.json") as object);
const validateReportV2 = ajv.compile(json("schemas/report-v2.schema.json") as object);

describe("report schema", () => {
  it("accepts the golden report", () => {
    expect(validateReport(json("fixtures/report.golden.json"))).toBe(true);
  });

  it("rejects an unknown field, matching the strict Rust parser", () => {
    const doc = json("fixtures/report.golden.json") as Record<string, any>;
    doc.report.surprise = 1;
    expect(validateReport(doc)).toBe(false);
  });

  it("rejects a non-canonical snapshot time", () => {
    const doc = json("fixtures/report.golden.json") as Record<string, any>;
    doc.report.snapshot_time = "2026-01-01 00:00:00";
    expect(validateReport(doc)).toBe(false);
  });

  it("rejects a negative amount", () => {
    const doc = json("fixtures/report.golden.json") as Record<string, any>;
    doc.report.root_sums.USDA = "-1";
    expect(validateReport(doc)).toBe(false);
  });

  it("rejects a truncated root hash", () => {
    const doc = json("fixtures/report.golden.json") as Record<string, any>;
    doc.report.root_hash = "abcd";
    expect(validateReport(doc)).toBe(false);
  });
});

describe("proof schema", () => {
  it("accepts the golden proof", () => {
    expect(validateProof(json("fixtures/proof.golden.json"))).toBe(true);
  });

  it("requires the report binding", () => {
    const doc = json("fixtures/proof.golden.json") as Record<string, any>;
    delete doc.report_digest;
    expect(validateProof(doc)).toBe(false);
  });

  it("rejects a step missing its orientation", () => {
    const doc = json("fixtures/proof.golden.json") as Record<string, any>;
    delete doc.steps[0].sibling_on_left;
    expect(validateProof(doc)).toBe(false);
  });
});

describe("report v2 schema", () => {
  it("accepts the golden v2 report", () => {
    expect(validateReportV2(json("fixtures/report-v2.golden.json"))).toBe(true);
  });

  it("requires the manifest", () => {
    const doc = json("fixtures/report-v2.golden.json") as Record<string, any>;
    delete doc.report.manifest;
    expect(validateReportV2(doc)).toBe(false);
  });

  it("rejects a manifest key outside the defined vocabulary", () => {
    const doc = json("fixtures/report-v2.golden.json") as Record<string, any>;
    doc.report.manifest.fields.secret_sauce = "withheld";
    expect(validateReportV2(doc)).toBe(false);
  });

  it("rejects an undefined disclosure state", () => {
    const doc = json("fixtures/report-v2.golden.json") as Record<string, any>;
    doc.report.manifest.fields.root_sums = "maybe";
    expect(validateReportV2(doc)).toBe(false);
  });

  /// The two versions must not validate against each other's schema.
  it("rejects a v1 report, and the v1 schema rejects a v2 one", () => {
    expect(validateReportV2(json("fixtures/report.golden.json"))).toBe(false);
    expect(validateReport(json("fixtures/report-v2.golden.json"))).toBe(false);
  });
});
