/**
 * Anchor digests (SPEC §12), mirroring the Rust `anchor` module.
 */

const ANCHOR_DIGEST_DOMAIN = "rocky-solvency-anchor-v1";

export type Anchor = {
  format_version: string;
  report_digest: string;
  root_hash: string;
  snapshot_time: string;
  ledger_offset: string;
  publisher: string;
  /** The Ed25519 key that signed the anchored report (SPEC §8.4). */
  publisher_key: string;
  prev_anchor?: string;
};

const encoder = new TextEncoder();

function u64le(n: number) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}

function lp(s: string) {
  const bytes = encoder.encode(s);
  const out = new Uint8Array(8 + bytes.length);
  out.set(u64le(bytes.length));
  out.set(bytes, 8);
  return out;
}

function concat(parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export async function anchorDigestHex(anchor: Anchor): Promise<string> {
  const parts: Uint8Array[] = [
    encoder.encode(ANCHOR_DIGEST_DOMAIN),
    lp(anchor.format_version),
    lp(anchor.report_digest),
    lp(anchor.root_hash),
    lp(anchor.snapshot_time),
    lp(anchor.ledger_offset),
    lp(anchor.publisher),
    lp(anchor.publisher_key),
  ];
  // A presence byte, not an empty string: otherwise a genesis anchor and one
  // naming an empty predecessor hash identically, and a mid-history anchor
  // could pose as the start of a history.
  parts.push(
    anchor.prev_anchor === undefined
      ? new Uint8Array([0])
      : concat([new Uint8Array([1]), lp(anchor.prev_anchor)])
  );
  const digest = await crypto.subtle.digest("SHA-256", concat(parts));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}
