/**
 * View logic for the disclosure console's viewer half.
 *
 * The console's job is not to say "verified". It is to show *what* was
 * verified, *what* was merely asserted, and where each number came from —
 * for a reader who did not write the format.
 *
 * Publisher-side workflows (connecting a participant node, designing a
 * disclosure, publishing) are not here: they need a live ledger connection,
 * which a page loaded from a file cannot have.
 */

import { anchorDigestHex, type Anchor } from "./anchor";
import { verifyFromText, type Fact, type ViewModel } from "./offline";
import { lookupProfile, type Report, type SignedReport } from "./report";
import { formatAmount18dp, parseAmount18dp } from "./verify";

export type CoverageRow = {
  asset: string;
  held: string;
  owed: string;
  covered: boolean;
};

export type HistoryRow = {
  index: number;
  snapshotTime: string;
  reportDigest: string;
  linked: boolean;
  /** Why not, when `linked` is false. Null when the row follows correctly. */
  problem: string | null;
};

/** A node in the data-flow view: where a published figure came from. */
export type FlowNode = {
  id: string;
  label: string;
  detail: string;
  /** Depth from the published root, so the view can lay it out. */
  depth: number;
};

export type ConsoleModel = {
  verification: ViewModel;
  /** What the report's profile asserts, in the format's own words. */
  statement: string | null;
  coverage: CoverageRow[] | null;
  history: HistoryRow[] | null;
  flow: FlowNode[];
};

/**
 * Format an amount for display, or say it is malformed.
 *
 * These figures come from a document supplied by the party being checked, and
 * this renders in a page whose error console nobody is watching. A throw out
 * of a display path leaves a blank screen, which a reader cannot tell from a
 * broken console — strictly worse than a row that says the figure is wrong.
 * The offline verifier had the same defect and the same fix.
 */
function display(amount: string): string {
  try {
    return formatAmount18dp(parseAmount18dp(amount));
  } catch {
    return "(malformed)";
  }
}

/** Comparable only when both sides parse; an unreadable figure is not covered. */
function coveredBy(held: string, owed: string): boolean {
  try {
    return parseAmount18dp(held) >= parseAmount18dp(owed);
  } catch {
    return false;
  }
}

function amountRow(asset: string, held: string, owed: string): CoverageRow {
  return {
    asset,
    held: display(held),
    owed: display(owed),
    covered: coveredBy(held, owed),
  };
}

/** A map of amounts, or nothing renderable. Untrusted input is not a map. */
function amountEntries(sums: unknown): [string, string][] {
  if (sums === null || typeof sums !== "object" || Array.isArray(sums)) return [];
  return Object.entries(sums as Record<string, string>);
}

/**
 * Coverage is driven by what is owed. An asset held but not owed is not a
 * coverage question; an asset owed and held nowhere is the worst case.
 */
export function coverageRows(custody: Report, liabilities: Report): CoverageRow[] {
  const held = new Map(amountEntries(custody.root_sums));
  return amountEntries(liabilities.root_sums)
    .map(([asset, owed]) => amountRow(asset, held.get(`held/${asset}`) ?? "0", owed))
    .sort((a, b) => a.asset.localeCompare(b.asset));
}

/** Each row says whether it links to the one before it, so a break is visible. */
export async function historyRows(anchors: Anchor[]): Promise<HistoryRow[]> {
  const rows: HistoryRow[] = [];
  for (const [index, anchor] of anchors.entries()) {
    // §12.1 is more than the digest link. This view used to check only that
    // each anchor named its predecessor, so a history that changed publisher,
    // restated a snapshot time or rewound a ledger offset rendered as fully
    // linked while `verifyAnchorChain` refused it — the reader saw green for
    // exactly the rewriting anchoring exists to expose.
    const problem = await chainProblem(anchors, index);
    rows.push({
      index,
      snapshotTime: anchor.snapshot_time,
      reportDigest: anchor.report_digest,
      linked: problem === null,
      problem,
    });
  }
  return rows;
}

/** What stops this anchor following the one before it, if anything. */
async function chainProblem(anchors: Anchor[], index: number): Promise<string | null> {
  const anchor = anchors[index];
  if (anchor.format_version !== "canton-solvency-anchor-v1") {
    return `unrecognised anchor format ${anchor.format_version}`;
  }
  if (index === 0) {
    return anchor.prev_anchor === undefined
      ? null
      : "the first anchor names a predecessor, so this history does not start at its beginning";
  }
  const previous = anchors[index - 1];
  if (anchor.prev_anchor !== (await anchorDigestHex(previous))) {
    return "does not name the anchor before it";
  }
  if (anchor.publisher !== previous.publisher) {
    return `publisher changed from ${previous.publisher}`;
  }
  if (anchor.snapshot_time <= previous.snapshot_time) {
    return "snapshot time does not advance, so an instant has been restated";
  }
  if (anchor.ledger_offset < previous.ledger_offset) {
    return "ledger offset moves backwards";
  }
  return null;
}

/**
 * Where a published figure came from, as a shallow tree. Aimed at readers new
 * to Canton who need to see that a number is an aggregate of things, not a
 * figure someone typed.
 */
export function flowOf(report: Report): FlowNode[] {
  const profile = lookupProfile(report.profile);
  const nodes: FlowNode[] = [
    {
      id: "root",
      label: `${report.profile} root`,
      detail: `${report.root_hash.slice(0, 16)}… over ${report.leaf_count} committed entries`,
      depth: 0,
    },
  ];

  for (const [key, total] of amountEntries(report.root_sums).sort()) {
    nodes.push({
      id: `total:${key}`,
      label: key,
      detail: `${display(total)} — summed from every committed entry`,
      depth: 1,
    });
  }

  nodes.push({
    id: "leaf",
    label: profile ? `${profile.leaf} entries` : "entries",
    detail:
      `${report.leaf_count} of them, committed but not published. ` +
      "Each holder can prove their own without revealing the others.",
    depth: 2,
  });

  nodes.push({
    id: "snapshot",
    label: "ledger offset",
    detail: `${report.ledger_offset} — the point in the publisher's event history this is "as of"`,
    depth: 3,
  });

  return nodes;
}

export type ConsoleInput = {
  reportText: string;
  proofText: string;
  trustedKeyHex: string;
  group?: { reportText: string; membershipText: string; keyHex?: string };
  custodyText?: string;
  historyText?: string;
};

export async function buildConsole(input: ConsoleInput): Promise<ConsoleModel> {
  const verification = await verifyFromText(
    input.reportText,
    input.proofText,
    input.trustedKeyHex,
    input.group
  );

  let report: Report | null = null;
  try {
    report = (JSON.parse(input.reportText) as SignedReport).report;
  } catch {
    report = null;
  }

  let coverage: CoverageRow[] | null = null;
  if (report && input.custodyText) {
    try {
      const custody = (JSON.parse(input.custodyText) as SignedReport).report;
      coverage = coverageRows(custody, report);
    } catch {
      coverage = null;
    }
  }

  let history: HistoryRow[] | null = null;
  if (input.historyText) {
    try {
      history = await historyRows(JSON.parse(input.historyText) as Anchor[]);
    } catch {
      history = null;
    }
  }

  return {
    verification,
    statement: report ? (lookupProfile(report.profile)?.name ?? null) : null,
    coverage,
    history,
    flow: report ? flowOf(report) : [],
  };
}

/** Re-exported so the page can render provenance without importing two modules. */
export type { Fact };
