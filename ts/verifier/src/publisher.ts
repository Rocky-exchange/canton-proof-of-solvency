/**
 * The disclosure designer and pre-publication diff (M4, publisher half).
 *
 * What an institution decides to disclose is a decision it should be able to
 * see before it makes it, and see again next quarter when it changes. These
 * are the two parts of that which need no ledger connection: designing a
 * manifest against a draft report, and diffing it against what was published
 * last time.
 *
 * Connecting a participant, reading live data and publishing are not here.
 * They need a ledger connection a page loaded from a file cannot have.
 */

import { KNOWN_MANIFEST_FIELDS, type Disclosure, type Manifest, type Report } from "./report";

export type FieldRow = {
  path: string;
  state: Disclosure;
  /** Whether the draft report actually carries data for this field. */
  carriesData: boolean;
  /** Set when the declared state contradicts the report body. */
  problem: string | null;
};

export type ChangeRow = {
  path: string;
  from: Disclosure | null;
  to: Disclosure | null;
  /** A move away from published, or a published field dropped. */
  reduction: boolean;
};

export type AudiencePreview = {
  audience: string;
  shown: string[];
  provenOnly: string[];
  withheld: string[];
};

export type DesignerModel = {
  fields: FieldRow[];
  changes: ChangeRow[];
  preview: AudiencePreview;
  /** Blocking problems: publishing with any of these would be rejected. */
  problems: string[];
  /** Non-blocking, but the reason the diff exists. */
  warnings: string[];
};

/** Whether the report body carries data for a manifest field. */
export function carriesData(report: Report, path: string): boolean {
  switch (path) {
    case "root_sums":
      return Object.keys(report.root_sums).length > 0;
    case "mark_prices":
      return Object.keys(report.mark_prices).length > 0;
    case "disclosures.bad_debt":
      return Object.keys(report.disclosures.bad_debt).length > 0;
    case "disclosures.excluded_house_accounts":
      return report.disclosures.excluded_house_accounts > 0;
    case "disclosures.excluded_house_totals":
      return Object.keys(report.disclosures.excluded_house_totals).length > 0;
    default:
      // Fields attested through the commitment rather than the body.
      return false;
  }
}

const BODY_FIELDS = [
  "root_sums",
  "mark_prices",
  "disclosures.bad_debt",
  "disclosures.excluded_house_accounts",
  "disclosures.excluded_house_totals",
];

export function designerRows(report: Report, manifest: Manifest): FieldRow[] {
  return [...KNOWN_MANIFEST_FIELDS].sort().map((path) => {
    const state = manifest.fields[path] ?? "withheld";
    const has = carriesData(report, path);
    let problem: string | null = null;
    if (BODY_FIELDS.includes(path)) {
      if (state === "published" && !has) {
        problem = "declared published but the report carries no data for it";
      } else if (state !== "published" && has) {
        problem = `declared ${state} but the report publishes it anyway`;
      }
    }
    return { path, state, carriesData: has, problem };
  });
}

export function changeRows(previous: Manifest | null, next: Manifest): ChangeRow[] {
  if (!previous) return [];
  const paths = [...new Set([...Object.keys(previous.fields), ...Object.keys(next.fields)])].sort();
  const rows: ChangeRow[] = [];
  for (const path of paths) {
    const from = previous.fields[path] ?? null;
    const to = next.fields[path] ?? null;
    if (from === to) continue;
    rows.push({ path, from, to, reduction: from === "published" && to !== "published" });
  }
  return rows;
}

/** Exactly what this audience will and will not be shown. */
export function previewFor(manifest: Manifest): AudiencePreview {
  const byState = (want: Disclosure) =>
    Object.keys(manifest.fields)
      .filter((path) => manifest.fields[path] === want)
      .sort();
  return {
    audience: manifest.audience,
    shown: byState("published"),
    provenOnly: byState("committed"),
    withheld: byState("withheld"),
  };
}

export function buildDesigner(
  report: Report,
  manifest: Manifest,
  previous: Manifest | null
): DesignerModel {
  const fields = designerRows(report, manifest);
  const changes = changeRows(previous, manifest);

  const problems = fields.filter((f) => f.problem).map((f) => `${f.path}: ${f.problem}`);
  if (!manifest.audience.trim()) {
    problems.push("no audience named: a packaging is for someone in particular");
  }

  // Reductions are the reason this screen exists. They are warnings, not
  // errors: reducing disclosure can be legitimate, but never accidental.
  const warnings = changes
    .filter((c) => c.reduction)
    .map((c) => `${c.path} was published and is now ${c.to ?? "not declared at all"}`);

  return { fields, changes, preview: previewFor(manifest), problems, warnings };
}
