/**
 * Bundles the verifier into a single self-contained HTML file.
 *
 * The page must never reimplement verification: it embeds the same modules the
 * test suite exercises, so the two cannot drift. The output is checked in so a
 * user can download one file from the repository and run it offline; CI fails
 * if the checked-in copy is stale.
 */
import { build } from "esbuild";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** Each page: an entry point, a template, and where it is checked in. */
export const PAGES = [
  {
    name: "offline verifier",
    entry: "../src/offline-entry.ts",
    template: "../offline-template.html",
    out: "../../../offline/verifier.html",
  },
  {
    name: "disclosure console",
    entry: "../src/console-entry.ts",
    template: "../console-template.html",
    out: "../../../console/viewer.html",
  },
];

export async function renderPage(page) {
  const result = await build({
    entryPoints: [resolve(here, page.entry)],
    bundle: true,
    format: "iife",
    target: "es2022",
    platform: "browser",
    minify: false, // a verifier people are asked to trust should stay readable
    write: false,
    legalComments: "none",
  });

  const js = result.outputFiles[0].text;
  if (/\b(fetch|XMLHttpRequest|WebSocket|importScripts)\b/.test(js)) {
    throw new Error("bundle references a network API; the page must be fully offline");
  }

  const template = readFileSync(resolve(here, page.template), "utf8");
  const marker = "<script>/*BUNDLE*/</script>";
  if (!template.includes(marker)) throw new Error(`template is missing ${marker}`);
  // `</script>` inside the bundle would close the tag early.
  return template.replace(marker, `<script>\n${js.replaceAll("</script", "<\\/script")}\n</script>`);
}

/** Back-compat for callers that only wanted the offline verifier. */
export async function renderOfflineVerifier() {
  return renderPage(PAGES[0]);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  for (const page of PAGES) {
    const html = await renderPage(page);
    const outPath = resolve(here, page.out);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, html);
    console.log(`wrote ${outPath} (${(html.length / 1024).toFixed(1)} KiB)`);
  }
}
