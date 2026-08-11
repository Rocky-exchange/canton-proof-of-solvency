/**
 * Assurance levels (SPEC §16), mirroring the Rust `assurance` module.
 *
 * The distinction this draws is not cryptographic and cannot be made
 * cryptographically. `verifyReport` establishes that a published total equals
 * the sum of the leaves the publisher committed to. Whether those leaves
 * describe anything real is outside what a commitment scheme reaches — a
 * custody report over invented positions recomputes perfectly.
 *
 * So a statement declares what kind of evidence each figure rests on, and this
 * establishes independently what it can substantiate. A declaration outside
 * what was established is a failure. A level the publisher could assert into
 * being would document the over-claim rather than prevent it.
 */

import { type Anchor } from "./anchor";
import { derivesFromLedger, type Provenance } from "./provenance";
import {
  lp,
  reportDigestHex,
  verifyEd25519,
  verifyReport,
  type ProofDocument,
  type Report,
  type SignedReport,
} from "./report";

export const ASSURANCE_FORMAT_VERSION = "canton-solvency-assurance-v1";
export const ATTESTATION_FORMAT_VERSION = "canton-solvency-attestation-v1";
const ATTESTATION_DIGEST_DOMAIN = "rocky-solvency-attestation-v1";

export type AssuranceLevel =
  | "not-disclosed"
  | "claimed-only"
  | "issuer-attested"
  | "third-party-attested"
  | "ledger-derived"
  | "cryptographically-verified";

/**
 * For display ordering only. `issuer-attested` sorts below
 * `third-party-attested` because the issuer is the party whose solvency is in
 * question; self-attestation is the weaker of the two (§16.1).
 */
export const STRENGTH: Record<AssuranceLevel, number> = {
  "not-disclosed": 0,
  "claimed-only": 1,
  "issuer-attested": 2,
  "third-party-attested": 3,
  "ledger-derived": 4,
  "cryptographically-verified": 5,
};

export type AttestorRole = "issuer" | "third-party";

export type Attestation = {
  format_version: string;
  report_digest: string;
  field: string;
  role: AttestorRole;
  attestor: string;
  basis: string;
};

export type SignedAttestation = {
  attestation: Attestation;
  signature: { algorithm: string; public_key: string; value: string };
};

export type AssuranceStatement = {
  format_version: string;
  report_digest: string;
  levels: Record<string, AssuranceLevel>;
};

export type Evidence = {
  proof?: ProofDocument;
  anchor?: Anchor;
  attestations?: SignedAttestation[];
  /**
   * The §17 graph. Required for `ledger-derived`: an anchor shows a report was
   * pinned to ledger state at an offset and says nothing about whether the
   * figure was derived from ledger state, which is what the level claims. A
   * report whose totals arrive from a custody API and is anchored on schedule
   * satisfies the anchor half completely.
   */
  provenance?: Provenance;
};

export type TrustedKeys = {
  publisher: string;
  /** Attestor key hex to the role that key is trusted for (§16.4). */
  attestors: Record<string, AttestorRole>;
};

export type AssuranceFailure =
  | { kind: "unsupported_version"; field: string; found: string }
  | { kind: "digest_mismatch" }
  | { kind: "unknown_signer" }
  | { kind: "bad_signature" }
  | { kind: "unknown_field"; field: string }
  | { kind: "over_claimed"; field: string; declared: AssuranceLevel; established: AssuranceLevel[] }
  | { kind: "malformed"; detail: string };

export type AssuranceResult =
  | { ok: true; levels: Record<string, AssuranceLevel> }
  | { ok: false; failure: AssuranceFailure };

/** The §8.5 report-resident vocabulary, and no other paths (§16.2). */
export const KNOWN_FIELDS = [
  "root_sums",
  "mark_prices",
  "disclosures.bad_debt",
  "disclosures.excluded_house_accounts",
  "disclosures.excluded_house_totals",
];

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

export async function attestationDigestHex(a: Attestation): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    concat([
      encoder.encode(ATTESTATION_DIGEST_DOMAIN),
      lp(a.format_version),
      lp(a.report_digest),
      lp(a.field),
      lp(a.role),
      lp(a.attestor),
      lp(a.basis),
    ])
  );
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Whether the report body publishes data for a resident field.
 *
 * The same rule §8.5 uses. A field can be withheld only if the manifest says
 * so *and* the body carries nothing for it — otherwise a report could declare
 * a published figure `not-disclosed` and escape standing behind it.
 */
function carriesData(report: Report, path: string): boolean {
  const size = (v: unknown): number =>
    v !== null && typeof v === "object" && !Array.isArray(v) ? Object.keys(v as object).length : 0;
  switch (path) {
    case "root_sums":
      return size(report.root_sums) > 0;
    case "mark_prices":
      return size(report.mark_prices) > 0;
    case "disclosures.bad_debt":
      return size(report.disclosures?.bad_debt) > 0;
    case "disclosures.excluded_house_accounts":
      return Number(report.disclosures?.excluded_house_accounts ?? 0) > 0;
    case "disclosures.excluded_house_totals":
      return size(report.disclosures?.excluded_house_totals) > 0;
    default:
      return false;
  }
}

function withheld(report: Report, field: string): boolean {
  const declared = report.manifest?.fields?.[field] === "withheld";
  return declared && !carriesData(report, field);
}

/**
 * Partial agreement is not evidence: the digest already covers the report, so
 * a disagreement anywhere else means one of the two documents was edited after
 * the fact.
 */
function anchors(report: Report, anchor: Anchor, digest: string): boolean {
  return (
    anchor.format_version === "canton-solvency-anchor-v1" &&
    anchor.report_digest === digest &&
    anchor.root_hash === report.root_hash &&
    anchor.snapshot_time === report.snapshot_time &&
    anchor.ledger_offset === report.ledger_offset &&
    anchor.publisher === report.publisher
  );
}

/** What the evidence supports for each field (§16.4 step 5). */
export async function establish(
  signed: SignedReport,
  evidence: Evidence,
  trusted: TrustedKeys
): Promise<Record<string, Set<AssuranceLevel>>> {
  const report = signed.report;
  const digest = await reportDigestHex(report);
  const out: Record<string, Set<AssuranceLevel>> = {};

  for (const field of KNOWN_FIELDS) {
    const levels = new Set<AssuranceLevel>();
    if (withheld(report, field)) {
      levels.add("not-disclosed");
      out[field] = levels;
      continue;
    }
    levels.add("claimed-only");

    // Only root_sums is bound into the tree. mark_prices and the disclosures
    // enter the report digest and are therefore signed, but nothing
    // recomputes them.
    if (field === "root_sums" && evidence.proof) {
      const verified = await verifyReport(signed, evidence.proof, trusted.publisher);
      if (verified.ok) levels.add("cryptographically-verified");
    }

    // The anchor covers the whole report; the graph is what says this
    // particular figure came from ledger state, so it is checked per field.
    if (
      evidence.anchor &&
      anchors(report, evidence.anchor, digest) &&
      evidence.provenance &&
      derivesFromLedger(evidence.provenance, field)
    ) {
      levels.add("ledger-derived");
    }

    for (const signedAttestation of evidence.attestations ?? []) {
      const a = signedAttestation.attestation;
      if (
        a?.format_version !== ATTESTATION_FORMAT_VERSION ||
        a.field !== field ||
        a.report_digest !== digest
      ) {
        continue;
      }
      // Trust is by key *and* by role, decided before the document was opened.
      // A custodian key must not be able to vouch as an issuer.
      if (trusted.attestors[signedAttestation.signature?.public_key] !== a.role) continue;
      if (signedAttestation.signature.algorithm !== "ed25519") continue;
      const valid = await verifyEd25519(
        signedAttestation.signature.public_key,
        await attestationDigestHex(a),
        signedAttestation.signature.value
      );
      if (valid) levels.add(a.role === "issuer" ? "issuer-attested" : "third-party-attested");
    }

    out[field] = levels;
  }
  return out;
}

/** Check declarations against what the evidence supports (SPEC §16.4). */
export async function verifyAssurance(
  signed: SignedReport,
  statement: AssuranceStatement,
  evidence: Evidence,
  trusted: TrustedKeys
): Promise<AssuranceResult> {
  try {
    if (statement?.format_version !== ASSURANCE_FORMAT_VERSION) {
      return {
        ok: false,
        failure: {
          kind: "unsupported_version",
          field: "assurance.format_version",
          found: String(statement?.format_version),
        },
      };
    }

    const digest = await reportDigestHex(signed.report);
    if (statement.report_digest !== digest) {
      return { ok: false, failure: { kind: "digest_mismatch" } };
    }

    // A statement about a report nobody vouched for must not be graded.
    if (signed.signature.public_key.toLowerCase() !== trusted.publisher.trim().toLowerCase()) {
      return { ok: false, failure: { kind: "unknown_signer" } };
    }
    if (!(await verifyEd25519(trusted.publisher.trim(), digest, signed.signature.value))) {
      return { ok: false, failure: { kind: "bad_signature" } };
    }

    const levels = statement.levels;
    if (levels === null || typeof levels !== "object" || Array.isArray(levels)) {
      return { ok: false, failure: { kind: "malformed", detail: "levels is not a map" } };
    }
    for (const field of Object.keys(levels)) {
      if (!KNOWN_FIELDS.includes(field)) {
        return { ok: false, failure: { kind: "unknown_field", field } };
      }
    }

    const established = await establish(signed, evidence, trusted);
    const accepted: Record<string, AssuranceLevel> = {};
    for (const [field, declared] of Object.entries(levels)) {
      const supported = established[field] ?? new Set<AssuranceLevel>();
      if (!supported.has(declared)) {
        return {
          ok: false,
          failure: {
            kind: "over_claimed",
            field,
            declared,
            established: [...supported].sort((a, b) => STRENGTH[a] - STRENGTH[b]),
          },
        };
      }
      accepted[field] = declared;
    }
    return { ok: true, levels: accepted };
  } catch (e) {
    return { ok: false, failure: { kind: "malformed", detail: String(e) } };
  }
}
