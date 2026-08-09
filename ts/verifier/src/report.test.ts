import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  reportDigestHex,
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
