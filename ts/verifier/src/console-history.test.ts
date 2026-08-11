import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { historyRows } from "./console";
import { verifyAnchorChain } from "./coverage";

/**
 * The history view and the verifier must agree.
 *
 * They did not: the view checked only that each anchor named its predecessor,
 * so a history that changed publisher, restated a snapshot time or rewound a
 * ledger offset rendered every row as linked while `verifyAnchorChain` refused
 * the chain. A reader saw green for precisely the rewriting anchoring exists
 * to expose.
 */
const history = (id: string): any =>
  JSON.parse(
    readFileSync(
      fileURLToPath(new URL(`../../../conformance/${id}/history.json`, import.meta.url)),
      "utf8"
    )
  );

const REJECTED = [
  "anchors-publisher-changed",
  "anchors-restated-instant",
  "anchors-rewound-offset",
  "anchors-broken-link",
  "anchors-suffix",
];

describe("the console history view", () => {
  it("shows an intact history as linked", async () => {
    const rows = await historyRows(history("anchors-intact"));
    expect(rows.every((r) => r.linked)).toBe(true);
    expect(rows.every((r) => r.problem === null)).toBe(true);
  });

  it("agrees with the verifier on every history the corpus rejects", async () => {
    for (const id of REJECTED) {
      const chain = history(id);
      const verdict = await verifyAnchorChain(chain);
      expect(verdict.ok, `${id} should be refused by the verifier`).toBe(false);

      const rows = await historyRows(chain);
      expect(rows.some((r) => !r.linked), `${id} renders as fully linked`).toBe(true);
    }
  });

  it("says what is wrong, not merely that something is", async () => {
    const rows = await historyRows(history("anchors-publisher-changed"));
    const broken = rows.find((r) => !r.linked);
    expect(broken?.problem).toMatch(/publisher changed/);
  });
});
