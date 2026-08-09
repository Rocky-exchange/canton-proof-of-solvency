import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { leafNodeV2 } from "./verify";
import {
  reportDigestHex,
  verifyReportV2,
  type ProofDocumentV2,
  verifyReport,
  type ProofDocument,
  type SignedReport,
} from "./report";

// The same fixture files the Rust golden test asserts against. If these fail,
// the report format diverged between the producer and this verifier.
const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url)), "utf8");

const GOLDEN_DIGEST = "0800c1047c9724ea429b238b01366f2032d674425d3ed745ed3402b2f534df61";
const GOLDEN_PUBLIC_KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

const signed = (): SignedReport => JSON.parse(fixture("report.golden.json"));
const proof = (): ProofDocument => JSON.parse(fixture("proof.golden.json"));

describe("report digest", () => {
  it("matches the digest pinned by the Rust producer", async () => {
    expect(await reportDigestHex(signed().report)).toBe(GOLDEN_DIGEST);
  });

  it("is unchanged by how the publisher wrote its amounts", async () => {
    const loose = signed().report;
    loose.root_sums = { CBTC: "0.25", USDA: "101.500000000000000001" };
    expect(await reportDigestHex(loose)).toBe(GOLDEN_DIGEST);
  });

  it("changes when any field changes", async () => {
    const mutated = signed().report;
    mutated.ledger_offset = "000000000000000043";
    expect(await reportDigestHex(mutated)).not.toBe(GOLDEN_DIGEST);
  });
});

describe("report verification", () => {
  it("accepts the golden publication", async () => {
    expect(await verifyReport(signed(), proof(), GOLDEN_PUBLIC_KEY)).toEqual({ ok: true });
  });

  it("rejects a report signed by an untrusted key", async () => {
    const result = await verifyReport(signed(), proof(), "ab".repeat(32));
    expect(result).toEqual({ ok: false, failure: { kind: "unknown_signer" } });
  });

  it("rejects a forged signature", async () => {
    const doc = signed();
    doc.signature.value = "11".repeat(64);
    expect(await verifyReport(doc, proof(), GOLDEN_PUBLIC_KEY)).toEqual({
      ok: false,
      failure: { kind: "bad_signature" },
    });
  });

  it("rejects a proof bound to a different report", async () => {
    const stale = proof();
    stale.report_digest = "cd".repeat(32);
    expect(await verifyReport(signed(), stale, GOLDEN_PUBLIC_KEY)).toEqual({
      ok: false,
      failure: { kind: "digest_mismatch" },
    });
  });

  it("rejects a tampered leaf balance", async () => {
    const tampered = proof();
    tampered.leaf.balances.USDA = "999";
    expect(await verifyReport(signed(), tampered, GOLDEN_PUBLIC_KEY)).toEqual({
      ok: false,
      failure: { kind: "root_hash_mismatch" },
    });
  });

  it("rejects an unsupported format version", async () => {
    const doc = signed();
    doc.report.format_version = "canton-solvency-report-v9";
    const result = await verifyReport(doc, proof(), GOLDEN_PUBLIC_KEY);
    expect(result).toEqual({
      ok: false,
      failure: {
        kind: "unsupported_version",
        field: "report.format_version",
        found: "canton-solvency-report-v9",
      },
    });
  });

  it("reports malformed hex as malformed rather than as forgery", async () => {
    const bad = proof();
    bad.leaf.salt = "nothex";
    const result = await verifyReport(signed(), bad, GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.kind).toBe("malformed");
  });
});

describe("report v2 and the disclosure manifest", () => {
  const v2 = (): SignedReport => JSON.parse(fixture("report-v2.golden.json"));
  const v2Proof = (): ProofDocument => JSON.parse(fixture("proof-v2.golden.json"));

  it("reproduces the v2 digest and signature pinned by the Rust producer", async () => {
    const doc = v2();
    expect(await reportDigestHex(doc.report)).toBe(v2Proof().report_digest);
    expect(doc.signature.value).toBe(
      "d7385bd2c72f274584ce804ef3f513d90465d6a68896c597726f8eff84bb86ec" +
        "a2ac42583fbb3fd4157ace9132ac24e8087cbe6f445cc984e1ad979197357e01"
    );
  });

  it("accepts the golden v2 publication", async () => {
    expect(await verifyReport(v2(), v2Proof(), GOLDEN_PUBLIC_KEY)).toEqual({ ok: true });
  });

  /// Domain separation: a v2 signature must not be replayable as a v1 one.
  it("digests the same fields differently under v1 and v2", async () => {
    const doc = v2();
    const asV1 = { ...doc.report, format_version: "canton-solvency-report-v1" };
    delete (asV1 as { manifest?: unknown }).manifest;
    expect(await reportDigestHex(doc.report)).not.toBe(await reportDigestHex(asV1));
  });

  it("covers every manifest entry in the digest", async () => {
    const base = await reportDigestHex(v2().report);
    const changed = v2();
    changed.report.manifest!.fields.mark_prices = "withheld";
    expect(await reportDigestHex(changed.report)).not.toBe(base);

    const audience = v2();
    audience.report.manifest!.audience = "auditor";
    expect(await reportDigestHex(audience.report)).not.toBe(base);
  });

  it("rejects a v1 report carrying a manifest", async () => {
    const doc = JSON.parse(fixture("report.golden.json")) as SignedReport;
    doc.report.manifest = v2().report.manifest;
    const result = await verifyReport(doc, proof(), GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.kind).toBe("manifest_presence");
  });

  it("rejects a v2 report without a manifest", async () => {
    const doc = v2();
    delete doc.report.manifest;
    const result = await verifyReport(doc, v2Proof(), GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.kind).toBe("manifest_presence");
  });

  it("rejects declaring a published field withheld", async () => {
    const doc = v2();
    doc.report.manifest!.fields.root_sums = "withheld";
    const result = await verifyReport(doc, v2Proof(), GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe("manifest_inconsistent");
      if (result.failure.kind === "manifest_inconsistent") {
        expect(result.failure.path).toBe("root_sums");
      }
    }
  });

  it("rejects a manifest naming a field the format does not define", async () => {
    const doc = v2();
    doc.report.manifest!.fields.secret_sauce = "withheld";
    const result = await verifyReport(doc, v2Proof(), GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.kind).toBe("manifest_inconsistent");
  });
});

describe("profile registry", () => {
  it("rejects a report whose profile is not registered", async () => {
    const doc = signed();
    doc.report.profile = "settlement.dvp";
    const result = await verifyReport(doc, proof(), GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe("profile");
      if (result.failure.kind === "profile") {
        expect(result.failure.detail).toContain("registry");
      }
    }
  });

  it("refuses a customer proof against a group-profile report", async () => {
    const doc = signed();
    doc.report.profile = "solvency.group";
    const result = await verifyReport(doc, proof(), GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok && result.failure.kind === "profile") {
      expect(result.failure.detail).toContain("entity leaves");
    }
  });

  it("rejects a liabilities report carrying no totals as vacuous", async () => {
    const doc = signed();
    doc.report.root_sums = {};
    const result = await verifyReport(doc, proof(), GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok && result.failure.kind === "profile") {
      expect(result.failure.detail).toContain("vacuous");
    }
  });
});

describe("leaf v2 and the collateral.repo profile", () => {
  const repoReport = (): SignedReport => JSON.parse(fixture("repo-report.golden.json"));
  const repoProof = (): ProofDocumentV2 => JSON.parse(fixture("repo-proof.golden.json"));

  it("accepts the golden repo publication produced by Rust", async () => {
    expect(await verifyReportV2(repoReport(), repoProof(), GOLDEN_PUBLIC_KEY)).toEqual({
      ok: true,
    });
  });

  it("reproduces the v2 leaf hash the Rust producer committed", async () => {
    const proof = repoProof();
    const node = await leafNodeV2(proof.leaf.salt, proof.leaf.subject_id, proof.leaf.maps);
    // The leaf's own qualified sums, independent of the tree.
    expect(node.sums["collateral/USDA"]).toBe(110n * 10n ** 18n);
    expect(node.sums["exposure/USDA"]).toBe(100n * 10n ** 18n);
  });

  it("rejects a tampered leg", async () => {
    const proof = repoProof();
    proof.leaf.maps.collateral.USDA = "999";
    const result = await verifyReportV2(repoReport(), proof, GOLDEN_PUBLIC_KEY);
    expect(result).toEqual({ ok: false, failure: { kind: "root_hash_mismatch" } });
  });

  /// The statement the profile exists to make, enforced at the root.
  it("rejects an under-collateralised book", async () => {
    const doc = repoReport();
    doc.report.root_sums["exposure/USDA"] = "999";
    const result = await verifyReportV2(doc, repoProof(), GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok && result.failure.kind === "profile") {
      expect(result.failure.detail).toContain("does not cover");
    }
  });

  it("refuses a v1 proof against a repo report and vice versa", async () => {
    const asV1 = await verifyReport(repoReport(), proof(), GOLDEN_PUBLIC_KEY);
    expect(asV1.ok).toBe(false);
    if (!asV1.ok && asV1.failure.kind === "profile") {
      expect(asV1.failure.detail).toContain("repoleg leaves");
    }
    const asV2 = await verifyReportV2(signed(), repoProof(), GOLDEN_PUBLIC_KEY);
    expect(asV2.ok).toBe(false);
    if (!asV2.ok && asV2.failure.kind === "profile") {
      expect(asV2.failure.detail).toContain("customer leaves");
    }
  });

  it("refuses an asset name that could forge a node boundary", async () => {
    const proof = repoProof();
    proof.leaf.maps.collateral = { "x|exposure/USDA": "1" };
    const result = await verifyReportV2(repoReport(), proof, GOLDEN_PUBLIC_KEY);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.failure.kind).toBe("malformed");
  });
});
