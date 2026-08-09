/**
 * View logic for the standalone offline verifier.
 *
 * Kept as a pure function over text so it can be tested against real
 * WebCrypto and the real golden fixtures; the HTML page is a thin DOM shell
 * over this. Nothing here touches the network.
 */

/**
 * How a displayed value is known. `verified` means this browser recomputed it
 * from the commitment; `disclosed` means the publisher asserted it and signed
 * it, but one inclusion proof cannot prove it. Never render a value without
 * one of these.
 */
export type Provenance = "verified" | "disclosed";

export type Fact = { label: string; value: string; provenance: Provenance };

export type ViewModel = {
  status: "verified" | "failed" | "error";
  headline: string;
  detail: string;
  facts: Fact[];
};

import { formatAmount18dp, parseAmount18dp } from "./verify";
import { verifyReport, type ProofDocument, type SignedReport } from "./report";

const FAILURE_TEXT: Record<string, string> = {
  digest_mismatch:
    "This proof belongs to a different report. It may be from another day — ask for the proof issued with this report.",
  unknown_signer:
    "This report is not signed by the trusted key you supplied. Either the key is wrong, or this report did not come from who you think.",
  bad_signature: "The signature on this report does not verify. The report has been altered.",
  root_hash_mismatch:
    "Your entry does not fold to the published root. The balance shown to you is not the one that was committed.",
  root_sums_mismatch:
    "The published totals disagree with what the committed entries actually add up to.",
};

function amountList(amounts: Record<string, string>): string {
  const entries = Object.entries(amounts);
  if (entries.length === 0) return "(none)";
  return entries
    .map(([asset, v]) => `${asset} ${formatAmount18dp(parseAmount18dp(v))}`)
    .join(", ");
}

function error(detail: string): ViewModel {
  return {
    status: "error",
    headline: "Could not check this",
    detail,
    facts: [],
  };
}

export async function verifyFromText(
  reportText: string,
  proofText: string,
  trustedKeyHex: string
): Promise<ViewModel> {
  const key = trustedKeyHex.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(key)) {
    return error("The publisher key must be 64 hex characters (32 bytes).");
  }

  let signed: SignedReport;
  let proof: ProofDocument;
  try {
    signed = JSON.parse(reportText);
    proof = JSON.parse(proofText);
  } catch {
    return error("One of these files is not valid JSON.");
  }
  if (!signed?.report || !proof?.leaf) {
    return error("Expected one report file and one proof file — they may be swapped.");
  }

  let result;
  try {
    result = await verifyReport(signed, proof, key);
  } catch (e) {
    return error(e instanceof Error ? e.message : String(e));
  }

  const { report } = signed;
  // Values this browser recomputed, versus values the publisher merely
  // asserted. One inclusion proof cannot attest to the metadata.
  const facts: Fact[] = [
    { label: "Your balance", value: amountList(proof.leaf.balances), provenance: "verified" },
    { label: "Published totals", value: amountList(report.root_sums), provenance: "verified" },
    { label: "Root", value: report.root_hash, provenance: "verified" },
    { label: "Publisher", value: report.publisher, provenance: "disclosed" },
    { label: "Snapshot time", value: report.snapshot_time, provenance: "disclosed" },
    { label: "Ledger offset", value: report.ledger_offset, provenance: "disclosed" },
    { label: "Entries committed", value: String(report.leaf_count), provenance: "disclosed" },
    {
      label: "Bad debt disclosed",
      value: amountList(report.disclosures.bad_debt),
      provenance: "disclosed",
    },
    {
      label: "House accounts excluded",
      value: String(report.disclosures.excluded_house_accounts),
      provenance: "disclosed",
    },
  ];

  if (result.ok) {
    return {
      status: "verified",
      headline: "Verified — your balance is in the published totals",
      detail:
        "Your entry was recomputed in this browser and folds to the root this report publishes, " +
        "and the totals match what the committed entries add up to.",
      facts,
    };
  }

  const { failure } = result;
  const detail =
    FAILURE_TEXT[failure.kind] ??
    (failure.kind === "unsupported_version"
      ? `This file uses an unsupported format version (${failure.found}).`
      : failure.kind === "malformed"
        ? `The document is malformed: ${failure.detail}`
        : failure.kind);

  return {
    status: "failed",
    headline: "Not verified",
    detail:
      failure.kind === "root_sums_mismatch"
        ? `${detail} (asset ${failure.asset})`
        : detail,
    facts,
  };
}
