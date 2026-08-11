/**
 * Evidence provenance (SPEC §17), mirroring the Rust `provenance` module.
 *
 * A graph nobody checks is a drawing of the system as someone hoped it
 * worked. What makes this load-bearing is §17.4: a figure declared
 * `ledger-derived` whose only named sources are off-ledger APIs is a
 * contradiction, and the verifier refuses it.
 */

import { KNOWN_FIELDS, type AssuranceLevel } from "./assurance";
import { lp, verifyEd25519, reportDigestHex, type SignedReport } from "./report";

export const PROVENANCE_FORMAT_VERSION = "canton-solvency-provenance-v1";
const PROVENANCE_DIGEST_DOMAIN = "rocky-solvency-provenance-v1";

export type SourceKind = "participant" | "synchronizer" | "party" | "template" | "off-ledger";

/** Whether Canton itself can be asked about this source. */
export const onLedger = (kind: SourceKind): boolean => kind !== "off-ledger";

export type Source = {
  id: string;
  kind: SourceKind;
  name: string;
  basis?: string;
};

export type Derivation = {
  field: string;
  sources: string[];
  method: string;
};

export type Provenance = {
  format_version: string;
  report_digest: string;
  sources: Source[];
  derivations: Derivation[];
};

export type SignedProvenance = {
  provenance: Provenance;
  signature: { algorithm: string; public_key: string; value: string };
};

export type ProvenanceFailure =
  | { kind: "unsupported_version"; field: string; found: string }
  | { kind: "digest_mismatch" }
  | { kind: "unknown_signer" }
  | { kind: "bad_signature" }
  | { kind: "provenance_inconsistent"; field: string; detail: string }
  | { kind: "malformed"; detail: string };

export type ProvenanceResult = { ok: true } | { ok: false; failure: ProvenanceFailure };

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

function u64le(n: number) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}

export async function provenanceDigestHex(p: Provenance): Promise<string> {
  const parts: Uint8Array[] = [
    encoder.encode(PROVENANCE_DIGEST_DOMAIN),
    lp(p.format_version),
    lp(p.report_digest),
    u64le(p.sources.length),
  ];
  for (const s of p.sources) {
    parts.push(lp(s.id), lp(s.kind), lp(s.name));
    // A presence byte, not an empty string: a source with no basis and one
    // with an empty basis are different claims.
    if (s.basis === undefined || s.basis === null) {
      parts.push(new Uint8Array([0]));
    } else {
      parts.push(new Uint8Array([1]), lp(s.basis));
    }
  }
  parts.push(u64le(p.derivations.length));
  for (const d of p.derivations) {
    parts.push(lp(d.field), u64le(d.sources.length));
    for (const id of d.sources) parts.push(lp(id));
    parts.push(lp(d.method));
  }
  const digest = await crypto.subtle.digest("SHA-256", concat(parts));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

const bad = (failure: ProvenanceFailure): ProvenanceResult => ({ ok: false, failure });

const inconsistent = (field: string, detail: string): ProvenanceResult =>
  bad({ kind: "provenance_inconsistent", field, detail });

/** SPEC §17.3, in order. */
export async function verifyProvenance(
  signedReport: SignedReport,
  signed: SignedProvenance,
  trustedKeyHex: string
): Promise<ProvenanceResult> {
  try {
    const p = signed?.provenance;
    if (p?.format_version !== PROVENANCE_FORMAT_VERSION) {
      return bad({
        kind: "unsupported_version",
        field: "provenance.format_version",
        found: String(p?.format_version),
      });
    }
    if (p.report_digest !== (await reportDigestHex(signedReport.report))) {
      return bad({ kind: "digest_mismatch" });
    }
    if (signed.signature.public_key.toLowerCase() !== trustedKeyHex.trim().toLowerCase()) {
      return bad({ kind: "unknown_signer" });
    }
    if (signed.signature.algorithm !== "ed25519") {
      return bad({
        kind: "unsupported_version",
        field: "signature.algorithm",
        found: signed.signature.algorithm,
      });
    }
    const valid = await verifyEd25519(
      trustedKeyHex.trim(),
      await provenanceDigestHex(p),
      signed.signature.value
    );
    if (!valid) return bad({ kind: "bad_signature" });

    if (!Array.isArray(p.sources) || !Array.isArray(p.derivations)) {
      return bad({ kind: "malformed", detail: "sources and derivations must be arrays" });
    }

    const ids = new Set<string>();
    for (const source of p.sources) {
      if (ids.has(source?.id)) {
        return inconsistent("", `two sources share the id ${JSON.stringify(source.id)}`);
      }
      ids.add(source.id);
      if (source.kind === "off-ledger" && !(source.basis ?? "").trim()) {
        return inconsistent(
          "",
          `off-ledger source ${JSON.stringify(source.id)} declares no basis; nothing else here says how that figure arrives`
        );
      }
    }

    const seen = new Set<string>();
    for (const d of p.derivations) {
      if (!KNOWN_FIELDS.includes(d?.field)) {
        return inconsistent(String(d?.field), "not a field this format defines");
      }
      if (seen.has(d.field)) {
        return inconsistent(d.field, "declared twice; a field has one derivation");
      }
      seen.add(d.field);
      if (!Array.isArray(d.sources) || d.sources.length === 0) {
        return inconsistent(
          d.field,
          "names no sources, so it says nothing about where the figure came from"
        );
      }
      for (const id of d.sources) {
        if (!ids.has(id)) {
          return inconsistent(
            d.field,
            `names source ${JSON.stringify(id)}, which the graph does not declare`
          );
        }
      }
    }
    return { ok: true };
  } catch (e) {
    return bad({ kind: "malformed", detail: String(e) });
  }
}

/** Whether the graph names at least one on-ledger source for a field (§17.4). */
export function derivesFromLedger(p: Provenance, field: string): boolean {
  const derivation = p.derivations?.find((d) => d.field === field);
  if (!derivation) return false;
  return derivation.sources.some((id) =>
    p.sources.some((s) => s.id === id && onLedger(s.kind))
  );
}

/** SPEC §17.4: the graph against the declared assurance levels. */
export function checkAgainstAssurance(
  p: Provenance,
  levels: Record<string, AssuranceLevel>
): ProvenanceResult {
  for (const [field, level] of Object.entries(levels ?? {})) {
    if (level !== "ledger-derived") continue;
    const derivation = p.derivations?.find((d) => d.field === field);
    if (!derivation) {
      return inconsistent(
        field,
        "declared ledger-derived, and the provenance graph does not say where it came from"
      );
    }
    if (!derivesFromLedger(p, field)) {
      return inconsistent(
        field,
        "declared ledger-derived, but every source the graph names for it is off-ledger"
      );
    }
  }
  return { ok: true };
}
