import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

/**
 * `Object.keys` and `Object.entries` must not be applied directly to a field
 * of a document this library did not create.
 *
 * Seven times now, one mistake: the browser verifier, the console, the
 * disclosure designer, the group path, v2 verification twice, and the offline
 * manifest display. Each was a field that should have been a map arriving as
 * `null`, a string or an array, and each turned a verification failure into a
 * thrown TypeError. `keysOf` in verify.ts returns no keys for a value that is
 * not a map, which is what every one of those callers meant.
 *
 * Fixing seven instances does not stop the eighth; this does. The rule is
 * crude on purpose — it bans a syntactic pattern rather than reasoning about
 * reachability, because two of the seven were sites I had convinced myself
 * were unreachable.
 */
const SRC = fileURLToPath(new URL(".", import.meta.url));

/**
 * Fields that only ever arrive from a document.
 *
 * Deliberately narrower than "anything map-shaped". `current.sums` is a node
 * this code just computed and `parseSums(sums)` has already guarded its
 * argument; flagging those taught nothing and would have been silenced with an
 * allow-list, which is how a rule stops being read. These five are only ever
 * read off a report, a manifest or a membership.
 */
const DOCUMENT_FIELDS = [
  "root_sums",
  "mark_prices",
  "fields",
  "bad_debt",
  "excluded_house_totals",
];

describe("untrusted map access", () => {
  it("never calls Object.keys or Object.entries on a document field", () => {
    const offenders: string[] = [];
    for (const file of readdirSync(SRC).filter((f) => f.endsWith(".ts") && !f.includes(".test."))) {
      const text = readFileSync(`${SRC}/${file}`, "utf8");
      text.split("\n").forEach((line, i) => {
        const m = line.match(/Object\.(keys|entries)\(\s*([A-Za-z_$][\w$.]*)\s*\)/);
        if (!m) return;
        const target = m[2];
        // Only a qualified access: `report.root_sums`, not a local already
        // guarded by its caller.
        if (!target.includes(".")) return;
        const last = target.split(".").pop() ?? "";
        if (DOCUMENT_FIELDS.includes(last)) {
          offenders.push(`${file}:${i + 1}: Object.${m[1]}(${target}) — use keysOf()`);
        }
      });
    }
    expect(offenders, "reach for keysOf() from verify.ts instead").toEqual([]);
  });

  it("checks a meaningful number of files, so a broken matcher fails loudly", () => {
    const files = readdirSync(SRC).filter((f) => f.endsWith(".ts") && !f.includes(".test."));
    expect(files.length).toBeGreaterThanOrEqual(8);
  });
});
