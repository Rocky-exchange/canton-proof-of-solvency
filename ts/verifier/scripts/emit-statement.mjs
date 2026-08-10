// Emits this implementation's §14.5 compatibility statement to
// statements/typescript.json.
//
//   npm run emit:statement
//
// Bundled through esbuild rather than imported directly, matching
// build-offline.mjs: the source is TypeScript with extensionless imports,
// which Node's type stripping does not resolve.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { build } from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, "../../../statements/typescript.json");

const result = await build({
  entryPoints: [resolve(here, "../src/corpus.ts")],
  bundle: true,
  format: "esm",
  target: "es2022",
  platform: "node",
  write: false,
  external: ["node:*"],
});

// Written beside the source: the bundle inherits corpus.ts's relative paths
// to the repository root, so it has to sit at the same depth.
const tmp = resolve(here, "../src/.corpus.bundle.mjs");
writeFileSync(tmp, result.outputFiles[0].text);
try {
  const { buildStatement } = await import(pathToFileURL(tmp).href);
  const statement = await buildStatement();
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(statement, null, 2)}\n`);
  console.log(`wrote ${out} (${statement.results.length} cases)`);
} finally {
  const { rmSync } = await import("node:fs");
  rmSync(tmp, { force: true });
}
