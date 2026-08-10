import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { buildStatement, runCase, type Case } from "./corpus";

/**
 * The conformance corpus (SPEC §14.3) exists so a second implementation can
 * claim compatibility. This *is* the second implementation: if TypeScript and
 * Rust disagree about any case, the format is not pinned, whatever the golden
 * vectors say.
 */
const root = (path: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url)), "utf8");

const json = (path: string): any => JSON.parse(root(path));

const manifest = json("conformance/manifest.json");
const cases: Case[] = manifest.cases;
const KEY: string = manifest.trusted_key;

describe("conformance corpus", () => {
  it("is substantive and balanced", () => {
    expect(cases.length).toBeGreaterThanOrEqual(15);
    expect(cases.filter((c) => c.expect === "accept").length).toBeGreaterThanOrEqual(5);
    expect(cases.filter((c) => c.expect === "reject").length).toBeGreaterThanOrEqual(8);
  });

  it("declares what every case requires, so a partial implementation can filter", () => {
    // Without this a verifier supporting only report v1 does not merely fail
    // the v2 cases -- it *passes* `report-v2-manifest-lies` by rejecting a
    // version it never implemented, and a case meant to test the manifest
    // tests nothing.
    for (const c of cases as any[]) {
      expect(Array.isArray(c.requires), `${c.id} declares no requires`).toBe(true);
      expect(c.requires.length, `${c.id} declares an empty requires`).toBeGreaterThan(0);
    }
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
      expect(await runCase(c, KEY)).toBe(c.expect === "accept");
    });
  }
});
