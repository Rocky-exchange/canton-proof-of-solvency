import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { PAGES, renderPage } from "../scripts/build-offline.mjs";

/**
 * Both pages are checked in so a user can download one file and run it with
 * their connection off. These tests keep that promise true: each must stay in
 * step with its source, and must not reach the network.
 */
for (const page of PAGES) {
  const checkedIn = readFileSync(
    fileURLToPath(new URL(`../${page.out.replace("../../../", "../../")}`, import.meta.url)),
    "utf8"
  );

  describe(`${page.name} artifact`, () => {
    it("is in step with the source", async () => {
      expect(
        checkedIn,
        `${page.out} is stale — rebuild with \`npm run build:offline\``
      ).toBe(await renderPage(page));
    });

    it("references no external origin", () => {
      const urls = checkedIn.match(/\bhttps?:\/\/[^\s"'`)]+/g) ?? [];
      expect(urls, `page must be self-contained, found: ${urls.join(", ")}`).toHaveLength(0);
      expect(checkedIn).not.toMatch(/\ssrc\s*=\s*["'](?!data:)[^"']+["']/);
      expect(checkedIn).not.toMatch(/<link\b/i);
    });

    it("uses no network API", () => {
      for (const api of ["fetch(", "XMLHttpRequest", "WebSocket", "importScripts"]) {
        expect(checkedIn, `found ${api}`).not.toContain(api);
      }
    });

    it("embeds the verification logic rather than reimplementing it", () => {
      expect(checkedIn).toContain("rocky-solvency-leaf-v1");
      expect(checkedIn).toContain("rocky-solvency-node-v1");
      expect(checkedIn).toContain("rocky-solvency-report-v1");
    });

    it("keeps the provenance vocabulary the pages are built around", () => {
      expect(checkedIn).toContain("recomputed here");
      expect(checkedIn).toContain("publisher says");
    });

    /**
     * The one failure the node tests cannot see: the script asks for an
     * element the markup does not define, and the page dies on load.
     */
    it("only addresses element ids that the markup defines", () => {
      const entry = readFileSync(
        fileURLToPath(new URL(`../${page.entry.replace("../", "")}`, import.meta.url)),
        "utf8"
      );
      const referenced = [...entry.matchAll(/\$\("([^"]+)"\)/g)].map((m) => m[1]);
      expect(referenced.length).toBeGreaterThan(0);
      for (const id of referenced) {
        expect(checkedIn, `script uses #${id} but the page has no such element`).toMatch(
          new RegExp(`id="${id}"`)
        );
      }
    });

    it("embeds a script that parses", () => {
      const script = checkedIn.slice(
        checkedIn.lastIndexOf("<script>") + "<script>".length,
        checkedIn.lastIndexOf("</script>")
      );
      expect(script.trim().length).toBeGreaterThan(1000);
      expect(() => new Function(script)).not.toThrow();
    });
  });
}
