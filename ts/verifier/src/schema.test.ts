import { readFileSync, readdirSync } from "node:fs";
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
const validateProofV2 = ajv.compile(json("schemas/proof-v2.schema.json") as object);
const validateCustody = ajv.compile(json("schemas/custody-report-v1.schema.json") as object);
const validateCoverageStatement = ajv.compile(
  json("schemas/coverage-statement-v1.schema.json") as object
);
const validateAnchor = ajv.compile(json("schemas/anchor-v1.schema.json") as object);
const validatePack = ajv.compile(json("schemas/pack-v1.schema.json") as object);
const validateMembership = ajv.compile(
  json("schemas/group-membership-v1.schema.json") as object
);

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

describe("proof v2 schema", () => {
  it("accepts the golden repo proof", () => {
    expect(validateProofV2(json("fixtures/repo-proof.golden.json"))).toBe(true);
  });

  it("requires at least one named map", () => {
    const doc = json("fixtures/repo-proof.golden.json") as Record<string, any>;
    doc.leaf.maps = {};
    expect(validateProofV2(doc)).toBe(false);
  });

  /// The restriction that stops a qualified key forging a node boundary.
  it("rejects a map or asset name outside the safe character set", () => {
    const withBadAsset = json("fixtures/repo-proof.golden.json") as Record<string, any>;
    withBadAsset.leaf.maps.collateral = { "x|exposure/USDA": "1" };
    expect(validateProofV2(withBadAsset)).toBe(false);

    const withBadMap = json("fixtures/repo-proof.golden.json") as Record<string, any>;
    withBadMap.leaf.maps["a/b"] = { USDA: "1" };
    expect(validateProofV2(withBadMap)).toBe(false);
  });

  it("does not accept a v1 proof, and the v1 schema does not accept a v2 one", () => {
    expect(validateProofV2(json("fixtures/proof.golden.json"))).toBe(false);
    expect(validateProof(json("fixtures/repo-proof.golden.json"))).toBe(false);
  });
});

describe("group membership schema", () => {
  it("accepts the golden membership", () => {
    expect(validateMembership(json("fixtures/group-membership.golden.json"))).toBe(true);
  });

  it("requires the entity identity that binds the leaf", () => {
    const doc = json("fixtures/group-membership.golden.json") as Record<string, any>;
    delete doc.entity.entity_id;
    expect(validateMembership(doc)).toBe(false);
  });

  it("requires the group report binding", () => {
    const doc = json("fixtures/group-membership.golden.json") as Record<string, any>;
    delete doc.group_report_digest;
    expect(validateMembership(doc)).toBe(false);
  });

  it("rejects an inclusion proof, which is a different document", () => {
    expect(validateMembership(json("fixtures/proof.golden.json"))).toBe(false);
  });
});

/**
 * Every checked-in fixture should have a schema that accepts it. Without this
 * a new document format can ship with no schema and nothing notices.
 */
describe("schema coverage", () => {
  const validators: Record<string, (d: unknown) => boolean> = {
    "report.golden.json": validateReport,
    "report-v2.golden.json": validateReportV2,
    "proof.golden.json": validateProof,
    // A v1-format proof that happens to belong to a v2 report; the name
    // says so, because "proof-v2" read as a v2 proof and was not one.
    "proof-for-report-v2.golden.json": validateProof,
    "repo-report.golden.json": validateReport,
    "repo-proof.golden.json": validateProofV2,
    "group-report.golden.json": validateReport,
    "group-membership.golden.json": validateMembership,
    "custody-report.golden.json": validateCustody,
    "coverage-statement.golden.json": validateCoverageStatement,
    "anchor.golden.json": validateAnchor,
  };

  /**
   * A schema nobody exercises can be wrong for as long as it likes, and the
   * one thing third-party tooling parses against is the schema. The fixture
   * list above has had this guard from the start; the schema directory did
   * not, so adding a schema and forgetting its test would have gone unnoticed.
   *
   * Every schema here is genuinely exercised, not merely compiled — checked by
   * replacing each in turn with `{}`, which accepts everything, and confirming
   * at least one test fails each time.
   */
  it("exercises every schema in the repository", () => {
    const dir = fileURLToPath(new URL("../../../schemas", import.meta.url));
    const present = readdirSync(dir)
      .filter((f) => f.endsWith(".schema.json"))
      .sort();
    const exercised = [
      "anchor-v1.schema.json",
      "coverage-statement-v1.schema.json",
      "custody-report-v1.schema.json",
      "group-membership-v1.schema.json",
      "pack-v1.schema.json",
      "proof-v1.schema.json",
      "proof-v2.schema.json",
      "report-v1.schema.json",
      "report-v2.schema.json",
    ].sort();
    expect(present, "a schema was added or removed without updating its tests").toEqual(
      exercised
    );
  });

  it("covers every fixture in the repository", () => {
    const dir = fileURLToPath(new URL("../../../fixtures", import.meta.url));
    const present = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
    expect(present).toEqual(Object.keys(validators).sort());
  });

  it("validates each fixture against its schema", () => {
    for (const [name, validate] of Object.entries(validators)) {
      expect(validate(json(`fixtures/${name}`)), `${name} failed its schema`).toBe(true);
    }
  });
});

describe("coverage documents", () => {
  it("accepts the golden custody report and statement", () => {
    expect(validateCustody(json("fixtures/custody-report.golden.json"))).toBe(true);
    expect(validateCoverageStatement(json("fixtures/coverage-statement.golden.json"))).toBe(true);
  });

  it("pins the custody profile, so a liabilities report cannot pose as custody", () => {
    expect(validateCustody(json("fixtures/report.golden.json"))).toBe(false);
  });

  it("requires both report bindings on a statement", () => {
    for (const field of ["custody_report_digest", "liabilities_report_digest"]) {
      const doc = json("fixtures/coverage-statement.golden.json") as Record<string, unknown>;
      delete doc[field];
      expect(validateCoverageStatement(doc), `${field} was optional`).toBe(false);
    }
  });
});

describe("anchor schema", () => {
  it("accepts the golden genesis anchor", () => {
    expect(validateAnchor(json("fixtures/anchor.golden.json"))).toBe(true);
  });

  it("accepts an anchor naming a predecessor", () => {
    const doc = json("fixtures/anchor.golden.json") as Record<string, unknown>;
    doc.prev_anchor = "ab".repeat(32);
    expect(validateAnchor(doc)).toBe(true);
  });

  /// Anchors carry digests and offsets only. An amount here would be
  /// disclosed to every observer of the ledger contract.
  it("rejects an anchor carrying balances", () => {
    const doc = json("fixtures/anchor.golden.json") as Record<string, unknown>;
    doc.root_sums = { USDA: "1" };
    expect(validateAnchor(doc)).toBe(false);
  });

  it("requires the report binding and the publisher", () => {
    for (const field of ["report_digest", "publisher", "ledger_offset"]) {
      const doc = json("fixtures/anchor.golden.json") as Record<string, unknown>;
      delete doc[field];
      expect(validateAnchor(doc), `${field} was optional`).toBe(false);
    }
  });
});

describe("evidence pack schema", () => {
  const pack = (): any => json("conformance/pack-valid/pack.json");

  it("accepts the conformance pack index", () => {
    expect(validatePack(pack())).toBe(true);
  });

  it("rejects a member name that is a path", () => {
    const doc = pack();
    doc.pack.entries[0].name = "../escape.json";
    expect(validatePack(doc)).toBe(false);
  });

  it("rejects an unknown field, matching the strict Rust parser", () => {
    const doc = pack();
    doc.pack.surprise = 1;
    expect(validatePack(doc)).toBe(false);
  });

  it("rejects a member digest that is not a hash", () => {
    const doc = pack();
    doc.pack.entries[0].sha256 = "nope";
    expect(validatePack(doc)).toBe(false);
  });
});
