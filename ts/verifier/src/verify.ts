/**
 * Client-side verifier for Rocky proof-of-solvency commitments.
 *
 * Byte-for-byte mirror of rocky-backend's `crates/solvency-merkle`; the
 * shared wire format is pinned by golden vectors on both sides (Rust:
 * `golden_vectors_pin_the_wire_format`, TS: verify.test.ts). Any change
 * here that breaks those vectors is a format version bump, not a refactor.
 */

const LEAF_DOMAIN = "rocky-solvency-leaf-v1";
const LEAF_DOMAIN_V2 = "rocky-solvency-leaf-v2";
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
    .sort(bytewiseCompare)
    .map((asset) => `${asset}:${formatAmount18dp(sums[asset])}`)
    .join("|");
}

const encoder = new TextEncoder();

/**
 * SPEC §2 and §8.1 order keys **bytewise** over UTF-8. JavaScript's default
 * `Array.sort()` compares UTF-16 code units, which disagrees for any codepoint
 * above U+FFFF: a surrogate (0xD800) sorts before U+E000..U+FFFF, while the
 * UTF-8 encoding of the same character (0xF0…) sorts after. Rust's
 * `String::cmp` is bytewise, so the default sort would give the two
 * implementations different leaf hashes for an asset named outside the BMP —
 * a report the producer signed honestly, rejected in the browser.
 *
 * Every ASCII name agrees under both orders, which is why the golden vectors
 * never caught this.
 */
export function bytewiseCompare(a: string, b: string): number {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

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

/**
 * v2 leaves carry several named amount maps, so a statement can compare them
 * (SPEC §3.1). Names are restricted because the §4 node hash still joins sums
 * with `:` and `|`, and an unconstrained qualified key could forge a boundary.
 */
const SAFE_NAME = /^[A-Za-z0-9._-]+$/;

function u64le(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}

function lpBytes(s: string): Uint8Array {
  const bytes = encoder.encode(s);
  const out = new Uint8Array(8 + bytes.length);
  out.set(u64le(bytes.length));
  out.set(bytes, 8);
  return out;
}

function lpmapBytes(m: Record<string, string>): Uint8Array {
  const assets = Object.keys(m).sort(bytewiseCompare);
  const parts: Uint8Array[] = [u64le(assets.length)];
  for (const asset of assets) {
    parts.push(lpBytes(asset), lpBytes(formatAmount18dp(parseAmount18dp(m[asset]))));
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function qualified(mapName: string, asset: string): string {
  return `${mapName}/${asset}`;
}

/** H(domain ‖ salt ‖ H(subject) ‖ count ‖ (lp(map) ‖ lpmap(amounts))*) */
export async function leafHashV2Hex(
  saltHex: string,
  subjectId: string,
  maps: Record<string, Record<string, string>>
): Promise<string> {
  const names = Object.keys(maps).sort(bytewiseCompare);
  for (const name of names) {
    if (!SAFE_NAME.test(name)) throw new Error(`unsafe map name: ${name}`);
    for (const asset of Object.keys(maps[name])) {
      if (!SAFE_NAME.test(asset)) throw new Error(`unsafe asset name: ${asset}`);
    }
  }
  const parts: Uint8Array[] = [
    encoder.encode(LEAF_DOMAIN_V2),
    hexToBytes(saltHex),
    await sha256(encoder.encode(subjectId)),
    u64le(names.length),
  ];
  for (const name of names) {
    parts.push(lpBytes(name), lpmapBytes(maps[name]));
  }
  return bytesToHex(await sha256(...parts));
}

/** A v2 leaf node: every map flattened under `<map>/<asset>` keys. */
export async function leafNodeV2(
  saltHex: string,
  subjectId: string,
  maps: Record<string, Record<string, string>>
): Promise<SolvencyNode> {
  const sums: Record<string, bigint> = {};
  for (const [name, amounts] of Object.entries(maps)) {
    for (const [asset, v] of Object.entries(amounts)) {
      sums[qualified(name, asset)] = parseAmount18dp(v);
    }
  }
  return { hashHex: await leafHashV2Hex(saltHex, subjectId, maps), sums };
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
