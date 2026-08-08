/**
 * Client-side verifier for Rocky proof-of-solvency commitments.
 *
 * Byte-for-byte mirror of rocky-backend's `crates/solvency-merkle`; the
 * shared wire format is pinned by golden vectors on both sides (Rust:
 * `golden_vectors_pin_the_wire_format`, TS: verify.test.ts). Any change
 * here that breaks those vectors is a format version bump, not a refactor.
 */

const LEAF_DOMAIN = "rocky-solvency-leaf-v1";
const NODE_DOMAIN = "rocky-solvency-node-v1";
const SCALE = 10n ** 18n;
const FRACTION_DIGITS = 18;

export type SolvencyNode = {
  hashHex: string;
  /** Per-asset totals this node commits to, as 18dp fixed-point bigints. */
  sums: Record<string, bigint>;
};

export type ProofStep = { sibling: SolvencyNode; siblingOnLeft: boolean };

/** Non-negative decimal string -> 18dp fixed point. Mirrors Rust parse_amount_18dp. */
export function parseAmount18dp(s: string): bigint {
  const dot = s.indexOf(".");
  const intPart = dot === -1 ? s : s.slice(0, dot);
  const fracPart = dot === -1 ? "" : s.slice(dot + 1);
  if (intPart === "" || (dot !== -1 && fracPart === "")) {
    throw new Error(`malformed amount: ${s}`);
  }
  if (fracPart.length > FRACTION_DIGITS) {
    throw new Error(`amount exceeds 18 decimal places: ${s}`);
  }
  if (!/^[0-9]+$/.test(intPart) || (fracPart !== "" && !/^[0-9]+$/.test(fracPart))) {
    throw new Error(`amount is not a non-negative decimal: ${s}`);
  }
  return BigInt(intPart) * SCALE + BigInt(fracPart.padEnd(FRACTION_DIGITS, "0") || "0");
}

/** 18dp fixed point -> canonical "int.<18 digits>" string. */
export function formatAmount18dp(v: bigint): string {
  if (v < 0n) throw new Error("negative amount");
  return `${v / SCALE}.${(v % SCALE).toString().padStart(FRACTION_DIGITS, "0")}`;
}

/** {asset: bigint} from an API balances object of decimal strings. */
export function sumBalances(balances: Record<string, string>): Record<string, bigint> {
  return Object.fromEntries(
    Object.entries(balances).map(([asset, v]) => [asset, parseAmount18dp(v)])
  );
}

/** Assets sorted bytewise, `ASSET:int.<18 digits>` joined by `|`. */
export function canonicalBalances(balances: Record<string, string>): string {
  return canonicalSums(sumBalances(balances));
}

function canonicalSums(sums: Record<string, bigint>): string {
  return Object.keys(sums)
    .sort()
    .map((asset) => `${asset}:${formatAmount18dp(sums[asset])}`)
    .join("|");
}

const encoder = new TextEncoder();

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

/** H(domain ‖ salt ‖ H(user_id) ‖ canonical(balances)), hex. */
export async function leafHashHex(
  saltHex: string,
  userId: string,
  balances: Record<string, string>
): Promise<string> {
  const userIdHash = await sha256(encoder.encode(userId));
  const digest = await sha256(
    encoder.encode(LEAF_DOMAIN),
    hexToBytes(saltHex),
    userIdHash,
    encoder.encode(canonicalBalances(balances))
  );
  return bytesToHex(digest);
}

function addSums(a: Record<string, bigint>, b: Record<string, bigint>): Record<string, bigint> {
  const out: Record<string, bigint> = { ...a };
  for (const [asset, v] of Object.entries(b)) {
    out[asset] = (out[asset] ?? 0n) + v;
  }
  return out;
}

/** (H(domain ‖ left ‖ right ‖ canonical(sums)), summed vectors). */
export async function combineNodes(
  left: SolvencyNode,
  right: SolvencyNode
): Promise<SolvencyNode> {
  const sums = addSums(left.sums, right.sums);
  const digest = await sha256(
    encoder.encode(NODE_DOMAIN),
    hexToBytes(left.hashHex),
    hexToBytes(right.hashHex),
    encoder.encode(canonicalSums(sums))
  );
  return { hashHex: bytesToHex(digest), sums };
}

function nodesEqual(a: SolvencyNode, b: SolvencyNode): boolean {
  if (a.hashHex !== b.hashHex) return false;
  const assets = new Set([...Object.keys(a.sums), ...Object.keys(b.sums)]);
  for (const asset of assets) {
    if ((a.sums[asset] ?? 0n) !== (b.sums[asset] ?? 0n)) return false;
  }
  return true;
}

/** Recompute the path from `leaf` and compare hash AND sums against `root`. */
export async function verifyProof(
  leaf: SolvencyNode,
  path: ProofStep[],
  root: SolvencyNode
): Promise<boolean> {
  let current = leaf;
  try {
    for (const step of path) {
      current = step.siblingOnLeft
        ? await combineNodes(step.sibling, current)
        : await combineNodes(current, step.sibling);
    }
  } catch {
    return false;
  }
  return nodesEqual(current, root);
}
