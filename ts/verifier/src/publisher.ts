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

/**
 * Keys of a value that should be a map, or none.
 *
 * The designer renders whatever a compliance team exported, which is not
 * always the shape this code expects. `Object.keys(null)` throws, and a throw
 * out of a render leaves the operator looking at a blank screen rather than at
 * a report that says what is wrong with their document.
 */
function keysOf(value: unknown): string[] {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value as Record<string, unknown>)
    : [];
}

/** Whether the report body carries data for a manifest field. */
export function carriesData(report: Report, path: string): boolean {
  const disclosures = (report.disclosures ?? {}) as Record<string, unknown>;
  switch (path) {
    case "root_sums":
      return keysOf(report.root_sums).length > 0;
    case "mark_prices":
      return keysOf(report.mark_prices).length > 0;
    case "disclosures.bad_debt":
      return keysOf(disclosures.bad_debt).length > 0;
    case "disclosures.excluded_house_accounts":
      return Number(disclosures.excluded_house_accounts ?? 0) > 0;
    case "disclosures.excluded_house_totals":
      return keysOf(disclosures.excluded_house_totals).length > 0;
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
    const state = fieldsOf(manifest)[path] ?? "withheld";
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

/** A manifest's field map, or an empty one if it is not a map. */
function fieldsOf(manifest: Manifest | null): Record<string, Disclosure> {
  const fields = manifest?.fields as unknown;
  return fields !== null && typeof fields === "object" && !Array.isArray(fields)
    ? (fields as Record<string, Disclosure>)
    : {};
}

export function changeRows(previous: Manifest | null, next: Manifest): ChangeRow[] {
  if (!previous) return [];
  const before = fieldsOf(previous);
  const after = fieldsOf(next);
  const paths = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  const rows: ChangeRow[] = [];
  for (const path of paths) {
    const from = before[path] ?? null;
    const to = after[path] ?? null;
    if (from === to) continue;
    rows.push({ path, from, to, reduction: from === "published" && to !== "published" });
  }
  return rows;
}

/** Exactly what this audience will and will not be shown. */
export function previewFor(manifest: Manifest): AudiencePreview {
  const fields = fieldsOf(manifest);
  const byState = (want: Disclosure) =>
    Object.keys(fields)
      .filter((path) => fields[path] === want)
      .sort();
  return {
    audience: manifest?.audience,
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
  // A manifest still being written has no audience yet, and that is the state
  // this screen exists to be looked at in. Reading .trim() off it turned the
  // most ordinary half-finished document into a blank page.
  if (typeof manifest?.audience !== "string" || !manifest.audience.trim()) {
    problems.push("no audience named: a packaging is for someone in particular");
  }

  // Reductions are the reason this screen exists. They are warnings, not
  // errors: reducing disclosure can be legitimate, but never accidental.
  const warnings = changes
    .filter((c) => c.reduction)
    .map((c) => `${c.path} was published and is now ${c.to ?? "not declared at all"}`);

  return { fields, changes, preview: previewFor(manifest), problems, warnings };
}
