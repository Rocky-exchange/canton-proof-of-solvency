import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verifyChain, verifyMembership, type GroupMembershipDocument } from "./group";
import type { ProofDocument, SignedReport } from "./report";

const fixture = (name: string): unknown =>
  JSON.parse(
    readFileSync(fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url)), "utf8")
  );

const KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

const groupReport = () => fixture("group-report.golden.json") as SignedReport;
const membership = () => fixture("group-membership.golden.json") as GroupMembershipDocument;
const entityReport = () => fixture("report.golden.json") as SignedReport;
const entityProof = () => fixture("proof.golden.json") as ProofDocument;

describe("group membership", () => {
  it("accepts the golden group fixture produced by the Rust implementation", async () => {
    expect(await verifyMembership(groupReport(), membership(), KEY)).toEqual({ ok: true });
  });

  it("rejects a forged signature on the group report", async () => {
    const doc = groupReport();
    doc.signature.value = "11".repeat(64);
    expect(await verifyMembership(doc, membership(), KEY)).toEqual({
      ok: false,
      failure: { kind: "bad_signature" },
    });
  });

  it("rejects a group report signed by an untrusted key", async () => {
    expect(await verifyMembership(groupReport(), membership(), "ab".repeat(32))).toEqual({
      ok: false,
      failure: { kind: "unknown_signer" },
    });
  });

  it("rejects a relabelled entity", async () => {
    const m = membership();
    m.entity.entity_id = "golden-entity-b";
    expect(await verifyMembership(groupReport(), m, KEY)).toEqual({
      ok: false,
      failure: { kind: "root_hash_mismatch" },
    });
  });

  it("rejects an entity overstating its totals", async () => {
    const m = membership();
    m.entity.root_sums.USDA = "999";
    expect(await verifyMembership(groupReport(), m, KEY)).toEqual({
      ok: false,
      failure: { kind: "root_hash_mismatch" },
    });
  });

  it("rejects a membership bound to another group report", async () => {
    const m = membership();
    m.group_report_digest = "cd".repeat(32);
    expect(await verifyMembership(groupReport(), m, KEY)).toEqual({
      ok: false,
      failure: { kind: "digest_mismatch" },
    });
  });
});

describe("full chain", () => {
  it("verifies a customer up to the consolidated group total", async () => {
    const result = await verifyChain(
      groupReport(),
      membership(),
      entityReport(),
      entityProof(),
      KEY,
      KEY
    );
    expect(result).toEqual({ ok: true });
  });

  it("rejects a membership paired with a different entity's report", async () => {
    const other = entityReport();
    other.report.root_hash = "ab".repeat(32);
    const result = await verifyChain(
      groupReport(),
      membership(),
      other,
      entityProof(),
      KEY,
      KEY
    );
    // The customer's proof no longer folds to the altered entity report, so
    // the chain fails before the entity comparison — either way, not ok.
    expect(result.ok).toBe(false);
  });

  it("rejects a tampered customer proof", async () => {
    const proof = entityProof();
    proof.leaf.balances.USDA = "999";
    const result = await verifyChain(
      groupReport(),
      membership(),
      entityReport(),
      proof,
      KEY,
      KEY
    );
    expect(result).toEqual({ ok: false, failure: { kind: "root_hash_mismatch" } });
  });
});
