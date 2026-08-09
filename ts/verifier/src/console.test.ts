import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { buildConsole, coverageRows, flowOf, historyRows } from "./console";
import type { Anchor } from "./anchor";
import type { SignedReport } from "./report";

const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url)), "utf8");

const KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const report = () => fixture("report.golden.json");
const proof = () => fixture("proof.golden.json");
const custody = () => fixture("custody-report.golden.json");

describe("coverage rows", () => {
  const reportOf = (text: string) => (JSON.parse(text) as SignedReport).report;

  it("shows every owed asset against what is held", () => {
    const rows = coverageRows(reportOf(custody()), reportOf(report()));
    expect(rows.map((r) => r.asset)).toEqual(["CBTC", "USDA"]);
    expect(rows.every((r) => r.covered)).toBe(true);
  });

  /// An asset owed and held nowhere must read as a shortfall, not as silence.
  it("treats an asset with no custody entry as uncovered", () => {
    const liabilities = reportOf(report());
    liabilities.root_sums = { CETH: "1" };
    const rows = coverageRows(reportOf(custody()), liabilities);
    expect(rows).toHaveLength(1);
    expect(rows[0].covered).toBe(false);
    expect(rows[0].held).toBe("0.000000000000000000");
  });

  it("ignores an asset held but not owed", () => {
    const liabilities = reportOf(report());
    liabilities.root_sums = { USDA: "1" };
    expect(coverageRows(reportOf(custody()), liabilities)).toHaveLength(1);
  });
});

describe("anchor history rows", () => {
  const genesis = (): Anchor => JSON.parse(fixture("anchor.golden.json"));

  it("marks a genesis anchor as linked", async () => {
    const rows = await historyRows([genesis()]);
    expect(rows[0].linked).toBe(true);
  });

  /// A break must be visible in the row itself, not inferred from a summary.
  it("marks an anchor that does not link to its predecessor", async () => {
    const broken: Anchor = { ...genesis(), prev_anchor: "ab".repeat(32) };
    const rows = await historyRows([genesis(), broken]);
    expect(rows[0].linked).toBe(true);
    expect(rows[1].linked).toBe(false);
  });

  it("marks a first anchor that claims a predecessor", async () => {
    const notGenesis: Anchor = { ...genesis(), prev_anchor: "cd".repeat(32) };
    const rows = await historyRows([notGenesis]);
    expect(rows[0].linked).toBe(false);
  });
});

describe("data-flow view", () => {
  const reportOf = (text: string) => (JSON.parse(text) as SignedReport).report;

  it("shows the root, each total, the entries, and the ledger offset", () => {
    const flow = flowOf(reportOf(report()));
    expect(flow[0].depth).toBe(0);
    expect(flow.map((n) => n.id)).toContain("total:USDA");
    expect(flow.map((n) => n.id)).toContain("leaf");
    expect(flow.map((n) => n.id)).toContain("snapshot");
  });

  /// The point of the view for a reader new to Canton: a published total is
  /// an aggregate of committed things, not a figure someone typed.
  it("says a total was summed rather than stated", () => {
    const flow = flowOf(reportOf(report()));
    const total = flow.find((n) => n.id === "total:USDA");
    expect(total?.detail).toContain("summed from every committed entry");
  });

  it("names the leaf kind the profile commits to", () => {
    const flow = flowOf(reportOf(fixture("repo-report.golden.json")));
    expect(flow.find((n) => n.id === "leaf")?.label).toContain("repoleg");
  });
});

describe("console model", () => {
  it("verifies and carries the flow for a plain report", async () => {
    const model = await buildConsole({
      reportText: report(),
      proofText: proof(),
      trustedKeyHex: KEY,
    });
    expect(model.verification.status).toBe("verified");
    expect(model.flow.length).toBeGreaterThan(3);
    expect(model.coverage).toBeNull();
    expect(model.history).toBeNull();
  });

  it("adds coverage when a custody report is supplied", async () => {
    const model = await buildConsole({
      reportText: report(),
      proofText: proof(),
      trustedKeyHex: KEY,
      custodyText: custody(),
    });
    expect(model.coverage?.every((r) => r.covered)).toBe(true);
  });

  it("adds history when an anchor chain is supplied", async () => {
    const model = await buildConsole({
      reportText: report(),
      proofText: proof(),
      trustedKeyHex: KEY,
      historyText: `[${fixture("anchor.golden.json")}]`,
    });
    expect(model.history).toHaveLength(1);
  });

  /// A malformed extra document must not take down the verification the
  /// reader actually came for.
  it("still verifies when an optional document is malformed", async () => {
    const model = await buildConsole({
      reportText: report(),
      proofText: proof(),
      trustedKeyHex: KEY,
      custodyText: "{ not json",
      historyText: "also not json",
    });
    expect(model.verification.status).toBe("verified");
    expect(model.coverage).toBeNull();
    expect(model.history).toBeNull();
  });
});
