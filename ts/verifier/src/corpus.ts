/**
 * Running the §14.3 corpus, and this implementation's §14.5 compatibility
 * statement.
 *
 * Extracted from the test so the emitter and the test share one runner: a
 * statement that could report an outcome the test would not produce is worse
 * than no statement at all.
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { verifyChain as verifyGroupChain, verifyMembership } from "./group";
import { verifyReport, verifyReportV2 } from "./report";
import { bytewiseCompare } from "./verify";

export const root = (path: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../${path}`, import.meta.url)), "utf8");

export const json = (path: string): any => JSON.parse(root(path));

export type Case = {
  id: string;
  kind: string;
  requires: string[];
  description: string;
  expect: "accept" | "reject";
};

/** Everything this implementation verifies. */
export const SUPPORTED = [
  "anchor-v1",
  "coverage-v1",
  "group-v1",
  "leaf-v2",
  "manifest",
  "pack-v1",
  "proof-v1",
  "proof-v2",
  "report-v1",
  "report-v2",
];

const CORPUS_DIGEST_DOMAIN = "rocky-solvency-corpus-v1";
const encoder = new TextEncoder();

function u64le(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}

function lp(s: string): Uint8Array {
  const bytes = encoder.encode(s);
  const out = new Uint8Array(8 + bytes.length);
  out.set(u64le(bytes.length));
  out.set(bytes, 8);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** SPEC §14.5 — binds a statement to the exact corpus it ran against. */
export async function corpusDigestHex(cases: Case[]): Promise<string> {
  const parts: Uint8Array[] = [encoder.encode(CORPUS_DIGEST_DOMAIN), u64le(cases.length)];
  for (const c of cases) {
    parts.push(lp(c.id), lp(c.expect), u64le(c.requires.length));
    for (const name of c.requires) parts.push(lp(name));
  }
  const digest = await crypto.subtle.digest("SHA-256", concat(parts) as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Mirrors the anchor chain rules in SPEC §12.1. */
export async function checkAnchors(history: any[]): Promise<boolean> {
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

/**
 * The failure kind a rejecting case produced, where this runner can name it.
 *
 * A case can exercise the check it names and a different check in fact: the
 * corpus carries `proof-understated-totals`, which reads as a test of the §9.1
 * sums comparison and is rejected a step earlier by the digest binding. Only
 * comparing against the declared `failure` catches that.
 */
export async function failureKind(c: Case, KEY: string): Promise<string | undefined> {
  const f = (name: string) => json(`conformance/${c.id}/${name}`);
  let result;
  if (c.kind === "proof") result = await verifyReport(f("report.json"), f("proof.json"), KEY);
  else if (c.kind === "proof-v2")
    result = await verifyReportV2(f("report.json"), f("proof.json"), KEY);
  else if (c.kind === "chain")
    result = await verifyGroupChain(
      f("group-report.json"),
      f("membership.json"),
      f("entity-report.json"),
      f("proof.json"),
      KEY,
      KEY
    );
  else return undefined; // the other kinds are checked structurally, not by kind
  return result.ok ? undefined : result.failure.kind;
}

export async function runCase(c: Case, KEY: string): Promise<boolean> {
  const f = (name: string) => json(`conformance/${c.id}/${name}`);
  switch (c.kind) {
    case "proof":
      return (await verifyReport(f("report.json"), f("proof.json"), KEY)).ok;
    case "proof-v2":
      return (await verifyReportV2(f("report.json"), f("proof.json"), KEY)).ok;
    case "chain":
      // §13.4 step 3 is the whole point: steps 1 and 2 pass independently for
      // a membership belonging to a different entity than the report.
      return (
        await verifyGroupChain(
          f("group-report.json"),
          f("membership.json"),
          f("entity-report.json"),
          f("proof.json"),
          KEY,
          KEY
        )
      ).ok;
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


export async function buildStatement(): Promise<any> {
  const manifest = json("conformance/manifest.json");
  const cases: Case[] = manifest.cases;
  const supports = new Set(SUPPORTED);
  const results = [];
  for (const c of cases) {
    let outcome: string;
    if (!c.requires.every((r) => supports.has(r))) {
      outcome = "skip";
    } else {
      try {
        outcome = (await runCase(c, manifest.trusted_key)) ? "accept" : "reject";
      } catch {
        outcome = "reject";
      }
    }
    results.push({ id: c.id, expected: c.expect, outcome });
  }
  return {
    format_version: "canton-solvency-compat-v1",
    implementation: "ts/verifier (TypeScript)",
    version: "0.1.0",
    supports: [...SUPPORTED].sort(bytewiseCompare),
    corpus_digest: await corpusDigestHex(cases),
    results,
  };
}
