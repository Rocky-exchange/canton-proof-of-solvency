/**
 * Client-side verifier for signed solvency reports (SPEC §8, §9).
 *
 * Byte-for-byte mirror of the Rust `canton-solvency-report` crate; the shared
 * format is pinned by the golden fixtures in `fixtures/` and asserted on both
 * sides. Any change here that breaks them is a format version bump, not a
 * refactor.
 */

import {
  combineNodes,
  formatAmount18dp,
  leafHashHex,
  parseAmount18dp,
  type SolvencyNode,
} from "./verify";

export const REPORT_FORMAT_VERSION = "canton-solvency-report-v1";
export const REPORT_FORMAT_VERSION_V2 = "canton-solvency-report-v2";
export const PROOF_FORMAT_VERSION = "canton-solvency-proof-v1";
export const SIGNATURE_ALGORITHM = "ed25519";
const REPORT_DIGEST_DOMAIN = "rocky-solvency-report-v1";
const REPORT_DIGEST_DOMAIN_V2 = "rocky-solvency-report-v2";

/** How a field was handled in this report (SPEC §8.5). */
export type Disclosure = "published" | "committed" | "withheld";
export type Manifest = { audience: string; fields: Record<string, Disclosure> };

/** SPEC §14: what a leaf of the committed tree stands for. */
export type LeafKind = "customer" | "entity";
export type ProfileRules = { name: string; leaf: LeafKind; requiredAggregates: string[] };

export const PROFILE_REGISTRY: ProfileRules[] = [
  { name: "solvency.liabilities", leaf: "customer", requiredAggregates: ["root_sums"] },
  { name: "solvency.group", leaf: "entity", requiredAggregates: ["root_sums"] },
];

export function lookupProfile(name: string): ProfileRules | undefined {
  return PROFILE_REGISTRY.find((p) => p.name === name);
}

const KNOWN_FIELDS = [
  "root_sums",
  "mark_prices",
  "disclosures.bad_debt",
  "disclosures.excluded_house_accounts",
  "disclosures.excluded_house_totals",
  "customer_balances",
  "customer_identities",
];
const REPORT_RESIDENT_FIELDS = KNOWN_FIELDS.slice(0, 5);

/** Amounts arrive as decimal strings and are canonicalised before hashing. */
export type AmountMap = Record<string, string>;

export type Report = {
  format_version: string;
  profile: string;
  publisher: string;
  snapshot_time: string;
  ledger_offset: string;
  root_hash: string;
  leaf_count: number;
  root_sums: AmountMap;
  mark_prices: AmountMap;
  disclosures: {
    bad_debt: AmountMap;
    excluded_house_accounts: number;
    excluded_house_totals: AmountMap;
  };
  /** v2 only. */
  manifest?: Manifest;
};

export type SignedReport = {
  report: Report;
  signature: { algorithm: string; public_key: string; value: string };
};

export type ProofDocument = {
  format_version: string;
  report_digest: string;
  leaf: { salt: string; user_id: string; balances: AmountMap };
  steps: { sibling_hash: string; sibling_sums: AmountMap; sibling_on_left: boolean }[];
};

export type VerificationFailure =
  | { kind: "unsupported_version"; field: string; found: string }
  | { kind: "digest_mismatch" }
  | { kind: "unknown_signer" }
  | { kind: "bad_signature" }
  | { kind: "root_hash_mismatch" }
  | { kind: "root_sums_mismatch"; asset: string }
  | { kind: "entity_root_mismatch" }
  | { kind: "entity_sums_mismatch"; asset: string }
  | { kind: "profile"; detail: string }
  | { kind: "manifest_presence"; detail: string }
  | { kind: "manifest_inconsistent"; path: string; detail: string }
  | { kind: "malformed"; detail: string };

export type VerificationResult = { ok: true } | { ok: false; failure: VerificationFailure };

const encoder = new TextEncoder();

function concat(parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u64le(n: number | bigint) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}

/** `u64le(len) ‖ utf8(s)` — length prefixes keep the preimage unambiguous. */
export function lp(s: string) {
  const bytes = encoder.encode(s);
  return concat([u64le(bytes.length), bytes]);
}

/** `u64le(count) ‖ (lp(asset) ‖ lp(canonical amount))*`, assets bytewise. */
export function lpmap(m: AmountMap) {
  const assets = Object.keys(m).sort();
  const parts = [u64le(assets.length)];
  for (const asset of assets) {
    parts.push(lp(asset), lp(formatAmount18dp(parseAmount18dp(m[asset]))));
  }
  return concat(parts);
}

function hexToBytes(hex: string) {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function reportDigestHex(report: Report): Promise<string> {
  const v2 = report.format_version === REPORT_FORMAT_VERSION_V2;
  const manifestParts: Uint8Array[] = [];
  if (v2 && report.manifest) {
    manifestParts.push(lp(report.manifest.audience));
    const paths = Object.keys(report.manifest.fields).sort();
    manifestParts.push(u64le(paths.length));
    for (const path of paths) {
      manifestParts.push(lp(path), lp(report.manifest.fields[path]));
    }
  }
  const preimage = concat([
    encoder.encode(v2 ? REPORT_DIGEST_DOMAIN_V2 : REPORT_DIGEST_DOMAIN),
    lp(report.format_version),
    lp(report.profile),
    lp(report.publisher),
    lp(report.snapshot_time),
    lp(report.ledger_offset),
    lp(report.root_hash),
    u64le(report.leaf_count),
    lpmap(report.root_sums),
    lpmap(report.mark_prices),
    lpmap(report.disclosures.bad_debt),
    u64le(report.disclosures.excluded_house_accounts),
    lpmap(report.disclosures.excluded_house_totals),
    ...manifestParts,
  ]);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", preimage)));
}

/**
 * Ed25519 landed in WebCrypto relatively recently. Fail with a message that
 * names the requirement rather than surfacing an opaque DOMException.
 */
export async function verifyEd25519(
  publicKeyHex: string,
  messageHex: string,
  signatureHex: string
): Promise<boolean> {
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(publicKeyHex),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
  } catch (cause) {
    throw new Error(
      "Ed25519 is unavailable in this WebCrypto implementation; " +
        "report verification needs Chrome 137+, Safari 17+, Firefox 129+, or Node 18.4+",
      { cause }
    );
  }
  return crypto.subtle.verify("Ed25519", key, hexToBytes(signatureHex), hexToBytes(messageHex));
}

function parseSums(sums: AmountMap): Record<string, bigint> {
  return Object.fromEntries(Object.entries(sums).map(([a, v]) => [a, parseAmount18dp(v)]));
}

function fail(failure: VerificationFailure): VerificationResult {
  return { ok: false, failure };
}

function checkVersion(field: string, found: string, want: string): VerificationResult | null {
  return found === want ? null : fail({ kind: "unsupported_version", field, found });
}

/**
 * v1 and v2 differ only in the manifest and the digest domain. A manifest that
 * merely asserted things would be decoration, so every claim it makes about a
 * field living in the report body is checked against the body.
 */
export function checkReportVersionAndManifest(report: Report): VerificationResult | null {
  if (report.format_version === REPORT_FORMAT_VERSION) {
    return report.manifest
      ? fail({
          kind: "manifest_presence",
          detail: "a v1 report cannot carry a manifest; the v1 digest does not cover it",
        })
      : null;
  }
  if (report.format_version !== REPORT_FORMAT_VERSION_V2) {
    return fail({
      kind: "unsupported_version",
      field: "report.format_version",
      found: report.format_version,
    });
  }
  const manifest = report.manifest;
  if (!manifest) {
    return fail({
      kind: "manifest_presence",
      detail: "a v2 report must carry a disclosure manifest",
    });
  }

  const carriesData: Record<string, boolean> = {
    root_sums: Object.keys(report.root_sums).length > 0,
    mark_prices: Object.keys(report.mark_prices).length > 0,
    "disclosures.bad_debt": Object.keys(report.disclosures.bad_debt).length > 0,
    "disclosures.excluded_house_accounts": report.disclosures.excluded_house_accounts > 0,
    "disclosures.excluded_house_totals":
      Object.keys(report.disclosures.excluded_house_totals).length > 0,
  };

  for (const path of Object.keys(manifest.fields).sort()) {
    const state = manifest.fields[path];
    if (!KNOWN_FIELDS.includes(path)) {
      return fail({
        kind: "manifest_inconsistent",
        path,
        detail: "not a field this format defines",
      });
    }
    if (!REPORT_RESIDENT_FIELDS.includes(path)) continue;
    if (state === "published" && !carriesData[path]) {
      return fail({
        kind: "manifest_inconsistent",
        path,
        detail: "declared published but the report carries no data for it",
      });
    }
    if (state !== "published" && carriesData[path]) {
      return fail({
        kind: "manifest_inconsistent",
        path,
        detail: `declared ${state} but the report publishes it anyway`,
      });
    }
  }
  return null;
}

/**
 * Validates the declared profile and requires the tree's leaves to be what the
 * caller is about to present a proof for. Without this a customer proof
 * against a group report would fail later as an opaque hash mismatch.
 */
export function expectLeafKind(report: Report, wanted: LeafKind): VerificationResult | null {
  const rules = lookupProfile(report.profile);
  if (!rules) {
    return fail({ kind: "profile", detail: `profile "${report.profile}" is not in the registry` });
  }
  for (const aggregate of rules.requiredAggregates) {
    const present =
      aggregate === "root_sums"
        ? Object.keys(report.root_sums).length > 0
        : Object.keys(report.mark_prices).length > 0;
    if (!present) {
      return fail({
        kind: "profile",
        detail: `profile ${rules.name}: ${aggregate} is required by this profile but the report carries none, so the statement would be vacuous`,
      });
    }
  }
  if (rules.leaf !== wanted) {
    return fail({
      kind: "profile",
      detail: `profile ${rules.name} commits to ${rules.leaf} leaves; this proof is for ${wanted} leaves`,
    });
  }
  return null;
}

/** Recompute the leaf, fold the path, compare hash *and* per-asset totals. */
export async function verifyReport(
  signed: SignedReport,
  proof: ProofDocument,
  trustedPublicKeyHex: string
): Promise<VerificationResult> {
  const { report } = signed;
  const versionFailure =
    checkReportVersionAndManifest(report) ??
    expectLeafKind(report, "customer") ??
    checkVersion("proof.format_version", proof.format_version, PROOF_FORMAT_VERSION) ??
    checkVersion("signature.algorithm", signed.signature.algorithm, SIGNATURE_ALGORITHM);
  if (versionFailure) return versionFailure;

  let digest: string;
  try {
    digest = await reportDigestHex(report);
  } catch (e) {
    return fail({ kind: "malformed", detail: String(e) });
  }
  if (digest !== proof.report_digest) return fail({ kind: "digest_mismatch" });

  // The embedded public key is display metadata; trust comes from the caller.
  if (signed.signature.public_key !== trustedPublicKeyHex) return fail({ kind: "unknown_signer" });

  let signatureValid: boolean;
  try {
    signatureValid = await verifyEd25519(trustedPublicKeyHex, digest, signed.signature.value);
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("Ed25519 is unavailable")) throw e;
    return fail({ kind: "malformed", detail: String(e) });
  }
  if (!signatureValid) return fail({ kind: "bad_signature" });

  let current: SolvencyNode;
  try {
    current = {
      hashHex: await leafHashHex(proof.leaf.salt, proof.leaf.user_id, proof.leaf.balances),
      sums: parseSums(proof.leaf.balances),
    };
    for (const step of proof.steps) {
      const sibling: SolvencyNode = {
        // Rejects a malformed sibling hash before it reaches the hasher.
        hashHex: bytesToHex(hexToBytes(step.sibling_hash)),
        sums: parseSums(step.sibling_sums),
      };
      current = step.sibling_on_left
        ? await combineNodes(sibling, current)
        : await combineNodes(current, sibling);
    }
  } catch (e) {
    return fail({ kind: "malformed", detail: String(e) });
  }

  if (current.hashHex !== report.root_hash) return fail({ kind: "root_hash_mismatch" });

  const published = parseSums(report.root_sums);
  for (const asset of new Set([...Object.keys(current.sums), ...Object.keys(published)])) {
    if ((current.sums[asset] ?? 0n) !== (published[asset] ?? 0n)) {
      return fail({ kind: "root_sums_mismatch", asset });
    }
  }
  return { ok: true };
}
