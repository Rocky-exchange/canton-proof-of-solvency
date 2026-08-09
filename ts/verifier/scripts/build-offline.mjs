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
const templatePath = resolve(here, "../offline-template.html");
const outPath = resolve(here, "../../../offline/verifier.html");

export async function renderOfflineVerifier() {
  const result = await build({
    entryPoints: [resolve(here, "../src/offline-entry.ts")],
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

  const template = readFileSync(templatePath, "utf8");
  const marker = "<script>/*BUNDLE*/</script>";
  if (!template.includes(marker)) throw new Error(`template is missing ${marker}`);
  // `</script>` inside the bundle would close the tag early.
  return template.replace(marker, `<script>\n${js.replaceAll("</script", "<\\/script")}\n</script>`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const html = await renderOfflineVerifier();
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, html);
  console.log(`wrote ${outPath} (${(html.length / 1024).toFixed(1)} KiB)`);
}
