import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { provenanceView } from "./console";

/**
 * The console has made this exact mistake before: anchor histories were shown
 * as linked while verification would have rejected them, because the display
 * path reimplemented the rules rather than calling them.
 *
 * So the question here is not whether a good graph renders. It is whether a
 * graph the verifier refuses can reach the screen.
 */
const fixture = (id: string, name: string): any =>
  JSON.parse(
    readFileSync(
      fileURLToPath(new URL(`../../../conformance/${id}/${name}`, import.meta.url)),
      "utf8"
    )
  );

const KEY: string = JSON.parse(
  readFileSync(fileURLToPath(new URL(`../../../conformance/manifest.json`, import.meta.url)), "utf8")
).trusted_key;

describe("the console's provenance view", () => {
  it("renders a verified graph, so the harness is wired to something real", async () => {
    const view = await provenanceView(
      fixture("provenance-well-formed", "report.json"),
      fixture("provenance-well-formed", "provenance.json"),
      KEY
    );
    expect(view.ok).toBe(true);
    if (!view.ok) return;
    const root = view.fields.find((f) => f.field === "root_sums");
    expect(root?.sources.every((s) => s.onLedger)).toBe(true);
    const prices = view.fields.find((f) => f.field === "mark_prices");
    expect(prices?.sources[0].onLedger).toBe(false);
    expect(prices?.sources[0].basis).toBeTruthy();
  });

  it("names the fields the graph says nothing about", async () => {
    const view = await provenanceView(
      fixture("provenance-well-formed", "report.json"),
      fixture("provenance-well-formed", "provenance.json"),
      KEY
    );
    expect(view.ok).toBe(true);
    if (!view.ok) return;
    expect(view.undeclared).toContain("disclosures.bad_debt");
  });

  it("shows nothing at all for a graph with a dangling edge", async () => {
    const view = await provenanceView(
      fixture("provenance-dangling-source", "report.json"),
      fixture("provenance-dangling-source", "provenance.json"),
      KEY
    );
    expect(view.ok).toBe(false);
    if (view.ok) return;
    expect(view.problem).toContain("root_sums");
  });

  it("shows nothing for an off-ledger source with no stated basis", async () => {
    const view = await provenanceView(
      fixture("provenance-off-ledger-without-basis", "report.json"),
      fixture("provenance-off-ledger-without-basis", "provenance.json"),
      KEY
    );
    expect(view.ok).toBe(false);
  });

  /// §17.4: the contradiction is only visible when the statement is supplied,
  /// so the view must actually run that check rather than render the graph and
  /// leave the reader to notice.
  it("refuses a graph that contradicts the declared assurance levels", async () => {
    const id = "provenance-ledger-derived-contradiction";
    const view = await provenanceView(
      fixture(id, "report.json"),
      fixture(id, "provenance.json"),
      KEY,
      fixture(id, "assurance.json")
    );
    expect(view.ok).toBe(false);
    if (view.ok) return;
    expect(view.problem).toContain("mark_prices");
  });

  it("accepts the same graph when the honest field is the one declared", async () => {
    const id = "provenance-ledger-derived-honest";
    const view = await provenanceView(
      fixture(id, "report.json"),
      fixture(id, "provenance.json"),
      KEY,
      fixture(id, "assurance.json")
    );
    expect(view.ok).toBe(true);
    if (!view.ok) return;
    expect(view.checkedLevels).toBe(true);
  });

  it("refuses a graph signed by a key the reader did not supply", async () => {
    const view = await provenanceView(
      fixture("provenance-well-formed", "report.json"),
      fixture("provenance-well-formed", "provenance.json"),
      "11".repeat(32)
    );
    expect(view.ok).toBe(false);
    if (view.ok) return;
    expect(view.problem).toContain("trusted key");
  });
});
