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
export const PROOF_FORMAT_VERSION = "canton-solvency-proof-v1";
export const SIGNATURE_ALGORITHM = "ed25519";
const REPORT_DIGEST_DOMAIN = "rocky-solvency-report-v1";

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
  const preimage = concat([
    encoder.encode(REPORT_DIGEST_DOMAIN),
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
  ]);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", preimage)));
}

/**
 * Ed25519 landed in WebCrypto relatively recently. Fail with a message that
 * names the requirement rather than surfacing an opaque DOMException.
 */
async function verifyEd25519(
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

/** Recompute the leaf, fold the path, compare hash *and* per-asset totals. */
export async function verifyReport(
  signed: SignedReport,
  proof: ProofDocument,
  trustedPublicKeyHex: string
): Promise<VerificationResult> {
  const { report } = signed;
  const versionFailure =
    checkVersion("report.format_version", report.format_version, REPORT_FORMAT_VERSION) ??
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
