/**
 * DOM shell for the disclosure designer. All decisions live in
 * `publisher.ts`; this moves text between the DOM and `buildDesigner`.
 */

import { buildDesigner, type DesignerModel } from "./publisher";
import { KNOWN_MANIFEST_FIELDS, type Disclosure, type Manifest, type SignedReport } from "./report";

const $ = (id: string): HTMLElement => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el;
};

const STATES: Disclosure[] = ["published", "committed", "withheld"];

let draft: SignedReport | null = null;
let previous: Manifest | null = null;

/** The manifest currently drawn on screen. */
function currentManifest(): Manifest {
  const fields: Record<string, Disclosure> = {};
  for (const path of KNOWN_MANIFEST_FIELDS) {
    const select = document.getElementById(`state:${path}`) as HTMLSelectElement | null;
    if (select) fields[path] = select.value as Disclosure;
  }
  return { audience: ($("audience") as HTMLInputElement).value, fields };
}

function drawFieldTable(): void {
  const rows = $("fields");
  if (rows.childElementCount > 0) return;
  for (const path of [...KNOWN_MANIFEST_FIELDS].sort()) {
    const tr = document.createElement("tr");
    const name = document.createElement("th");
    name.scope = "row";
    name.textContent = path;

    const control = document.createElement("td");
    const select = document.createElement("select");
    select.id = `state:${path}`;
    for (const state of STATES) {
      const option = document.createElement("option");
      option.value = state;
      option.textContent = state;
      select.appendChild(option);
    }
    select.value = "withheld";
    select.addEventListener("change", refresh);
    control.appendChild(select);

    const note = document.createElement("td");
    note.id = `note:${path}`;
    note.className = "hint";

    tr.append(name, control, note);
    rows.appendChild(tr);
  }
}

function render(model: DesignerModel): void {
  for (const field of model.fields) {
    const note = document.getElementById(`note:${field.path}`);
    if (!note) continue;
    note.textContent = field.problem
      ? field.problem
      : field.carriesData
        ? "the draft carries data for this"
        : "not in the report body";
    note.className = field.problem ? "hint problem" : "hint";
  }

  const list = (id: string, items: string[], empty: string) => {
    const el = $(id);
    el.innerHTML = "";
    if (items.length === 0) {
      const li = document.createElement("li");
      li.className = "hint";
      li.textContent = empty;
      el.appendChild(li);
      return;
    }
    for (const item of items) {
      const li = document.createElement("li");
      li.textContent = item;
      el.appendChild(li);
    }
  };

  list("problems", model.problems, "none — this manifest is consistent with the draft");
  list("warnings", model.warnings, "no disclosure was reduced");
  list(
    "changes",
    model.changes.map((c) => `${c.path}: ${c.from ?? "not declared"} → ${c.to ?? "not declared"}`),
    previous ? "nothing changed since the previous report" : "no previous report loaded"
  );
  list("shown", model.preview.shown, "nothing");
  list("proven", model.preview.provenOnly, "nothing");
  list("hidden", model.preview.withheld, "nothing");

  ($("export") as HTMLButtonElement).disabled = model.problems.length > 0;
  $("manifest-json").textContent = JSON.stringify(currentManifest(), null, 2);
}

function refresh(): void {
  if (!draft) return;
  $("designer").hidden = false;
  render(buildDesigner(draft.report, currentManifest(), previous));
}

async function loadDraft(input: HTMLInputElement): Promise<void> {
  const file = input.files?.[0];
  if (!file) return;
  draft = JSON.parse(await file.text()) as SignedReport;
  drawFieldTable();
  refresh();
}

async function loadPrevious(input: HTMLInputElement): Promise<void> {
  const file = input.files?.[0];
  if (!file) return;
  previous = (JSON.parse(await file.text()) as SignedReport).report.manifest ?? null;
  refresh();
}

$("draft").addEventListener("change", (e) => {
  void loadDraft(e.target as HTMLInputElement);
});
$("previous").addEventListener("change", (e) => {
  void loadPrevious(e.target as HTMLInputElement);
});
$("audience").addEventListener("input", refresh);
$("export").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(currentManifest(), null, 2)], {
    type: "application/json",
  });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "manifest.json";
  link.click();
  URL.revokeObjectURL(link.href);
});
