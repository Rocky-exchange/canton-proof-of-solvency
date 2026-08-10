import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verifyChain as verifyGroupChain, verifyMembership } from "./group";
import { verifyReport, verifyReportV2 } from "./report";

/**
 * The conformance corpus (SPEC §14.3) exists so a second implementation can
 * claim compatibility. This *is* the second implementation: if TypeScript and
 * Rust disagree about any case, the format is not pinned, whatever the golden
 * vectors say.
 */
const root = (path: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url)), "utf8");

const json = (path: string): any => JSON.parse(root(path));

type Case = {
  id: string;
  kind: string;
  description: string;
  expect: "accept" | "reject";
};

const manifest = json("conformance/manifest.json");
const cases: Case[] = manifest.cases;
const KEY: string = manifest.trusted_key;

/** Mirrors the anchor chain rules in SPEC §12.1. */
async function checkAnchors(history: any[]): Promise<boolean> {
  const { anchorDigestHex } = await import("./anchor");
  for (const [i, anchor] of history.entries()) {
    if (anchor.format_version !== "canton-solvency-anchor-v1") return false;
    if (i === 0) {
      if (anchor.prev_anchor !== undefined) return false;
      continue;
    }
    const previous = history[i - 1];
    if (anchor.prev_anchor !== (await anchorDigestHex(previous))) return false;
    if (anchor.publisher !== previous.publisher) return false;
    if (anchor.snapshot_time <= previous.snapshot_time) return false;
    if (anchor.ledger_offset < previous.ledger_offset) return false;
  }
  return true;
}

async function runCase(c: Case): Promise<boolean> {
  const f = (name: string) => json(`conformance/${c.id}/${name}`);
  switch (c.kind) {
    case "proof":
      return (await verifyReport(f("report.json"), f("proof.json"), KEY)).ok;
    case "proof-v2":
      return (await verifyReportV2(f("report.json"), f("proof.json"), KEY)).ok;
    case "membership":
      return (await verifyMembership(f("group-report.json"), f("membership.json"), KEY)).ok;
    case "coverage": {
      // Coverage is a pairing rule; the browser verifier checks the two
      // reports and the binding, then compares held against owed.
      const custody = f("custody.json");
      const liabilities = f("liabilities.json");
      const statement = f("statement.json");
      const { reportDigestHex } = await import("./report");
      if (custody.report.profile !== "coverage.custody") return false;
      if (liabilities.report.profile !== "solvency.liabilities") return false;
      if ((await reportDigestHex(custody.report)) !== statement.custody_report_digest) return false;
      if ((await reportDigestHex(liabilities.report)) !== statement.liabilities_report_digest) {
        return false;
      }
      const { parseAmount18dp } = await import("./verify");
      for (const [asset, owed] of Object.entries<string>(liabilities.report.root_sums)) {
        const held = custody.report.root_sums[`held/${asset}`] ?? "0";
        if (parseAmount18dp(held) < parseAmount18dp(owed)) return false;
      }
      return true;
    }
    case "pack": {
      // The delivery is whatever is in the directory, minus the index. Reading
      // it from disk rather than from the manifest is deliberate: a runner
      // that trusted the manifest's file list could not detect a file the
      // index does not name.
      const { verifyPack } = await import("./pack");
      const { verifyEd25519 } = await import("./report");
      const { packDigestHex } = await import("./pack");
      const dir = fileURLToPath(new URL(`../../../conformance/${c.id}`, import.meta.url));
      const signed = f("pack.json");
      const members = new Map<string, Uint8Array>();
      for (const name of readdirSync(dir)) {
        if (name === "pack.json") continue;
        members.set(
          name,
          new Uint8Array(
            readFileSync(fileURLToPath(new URL(`../../../conformance/${c.id}/${name}`, import.meta.url)))
          )
        );
      }
      // Signature first: it is what forces this implementation's pack digest
      // to agree with the Rust one byte for byte. Without it the cases would
      // only prove the two agree about SHA-256 of a file.
      const signatureValid = await verifyEd25519(
        KEY,
        await packDigestHex(signed.pack),
        signed.signature.value
      );
      if (!signatureValid) return false;
      return (await verifyPack(signed, members)).ok;
    }
    case "anchors":
      return checkAnchors(f("history.json"));
    default:
      throw new Error(`unknown case kind ${c.kind}`);
  }
}

describe("conformance corpus", () => {
  it("is substantive and balanced", () => {
    expect(cases.length).toBeGreaterThanOrEqual(15);
    expect(cases.filter((c) => c.expect === "accept").length).toBeGreaterThanOrEqual(5);
    expect(cases.filter((c) => c.expect === "reject").length).toBeGreaterThanOrEqual(8);
  });

  it("lists every case directory on disk", () => {
    const dir = fileURLToPath(new URL("../../../conformance", import.meta.url));
    const present = readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
    expect(present).toEqual(cases.map((c) => c.id).sort());
  });

  for (const c of cases) {
    it(`${c.expect}s: ${c.id} — ${c.description}`, async () => {
      expect(await runCase(c)).toBe(c.expect === "accept");
    });
  }
});
