/**
 * Evidence packs (SPEC §15), mirroring the Rust `pack` module.
 *
 * A proof says nothing about what else was delivered alongside it, so a
 * folder with a customer's proof removed verifies exactly as cleanly as the
 * complete one. The signed index is what makes the *set* part of the claim.
 *
 * This checks the index against the bytes actually delivered. The signature
 * over the index is the caller's to verify with a trusted key — the same rule
 * as everywhere else here: a document checked against a key it carries proves
 * only internal consistency.
 */

const PACK_DIGEST_DOMAIN = "rocky-solvency-pack-v1";
export const PACK_FORMAT_VERSION = "canton-solvency-pack-v1";

export type PackEntry = { name: string; sha256: string };

export type Pack = {
  format_version: string;
  publisher: string;
  snapshot_time: string;
  report_digest: string;
  entries: PackEntry[];
};

export type SignedPack = {
  pack: Pack;
  signature: { algorithm: string; public_key: string; value: string };
};

export type PackResult =
  | { ok: true }
  | { ok: false; failure: "version"; found: string }
  | { ok: false; failure: "missing" | "altered" | "unlisted" | "unsafe-name"; name: string };

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

const hex = (bytes: ArrayBuffer): string =>
  [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

export async function memberDigestHex(bytes: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

export async function packDigestHex(pack: Pack): Promise<string> {
  const parts: Uint8Array[] = [
    encoder.encode(PACK_DIGEST_DOMAIN),
    lp(pack.format_version),
    lp(pack.publisher),
    lp(pack.snapshot_time),
    lp(pack.report_digest),
    // The count, so a pack over two members cannot be made to agree with one
    // over a single longer member.
    u64le(pack.entries.length),
  ];
  for (const entry of pack.entries) {
    parts.push(lp(entry.name), lp(entry.sha256));
  }
  return hex(await crypto.subtle.digest("SHA-256", concat(parts) as BufferSource));
}

/**
 * Check a delivery against its index: the members present are exactly the
 * members named, byte for byte.
 *
 * Named-but-absent is reported before present-but-unnamed, because a dropped
 * proof is the failure this exists to catch.
 */
export async function verifyPack(
  signed: SignedPack,
  members: Map<string, Uint8Array>
): Promise<PackResult> {
  if (signed.pack.format_version !== PACK_FORMAT_VERSION) {
    return { ok: false, failure: "version", found: signed.pack.format_version };
  }
  for (const entry of signed.pack.entries) {
    // A member name is a file name, never a path. Checked on the reading side
    // because a pack is not always built by the tool that reads it.
    if (
      entry.name === "" ||
      entry.name.includes("/") ||
      entry.name.includes("\\") ||
      entry.name === "." ||
      entry.name === ".."
    ) {
      return { ok: false, failure: "unsafe-name", name: entry.name };
    }
    const bytes = members.get(entry.name);
    if (bytes === undefined) {
      return { ok: false, failure: "missing", name: entry.name };
    }
    if ((await memberDigestHex(bytes)).toLowerCase() !== entry.sha256.toLowerCase()) {
      return { ok: false, failure: "altered", name: entry.name };
    }
  }
  for (const name of members.keys()) {
    if (!signed.pack.entries.some((e) => e.name === name)) {
      return { ok: false, failure: "unlisted", name };
    }
  }
  return { ok: true };
}
