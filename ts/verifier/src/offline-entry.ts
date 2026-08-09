/**
 * DOM shell for the standalone offline verifier. All decision logic lives in
 * `offline.ts` and is tested there; this file only moves text between the DOM
 * and `verifyFromText`.
 */

import { verifyFromText, type ViewModel } from "./offline";

const $ = (id: string): HTMLElement => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el;
};

async function readFile(input: HTMLInputElement): Promise<string> {
  const file = input.files?.[0];
  if (!file) throw new Error(`Choose a ${input.dataset.what ?? "file"} first.`);
  return file.text();
}

function render(vm: ViewModel): void {
  const result = $("result");
  result.hidden = false;
  result.className = `result ${vm.status}`;
  $("headline").textContent = vm.headline;
  $("detail").textContent = vm.detail;

  const rows = $("facts");
  rows.innerHTML = "";
  for (const f of vm.facts) {
    const row = document.createElement("tr");

    const label = document.createElement("th");
    label.scope = "row";
    label.textContent = f.label;

    const value = document.createElement("td");
    value.className = "value";
    value.textContent = f.value;

    const provenance = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${f.provenance}`;
    badge.textContent = f.provenance === "verified" ? "recomputed here" : "publisher says";
    badge.title =
      f.provenance === "verified"
        ? "This browser recomputed this value from the commitment."
        : "Signed by the publisher, but one inclusion proof cannot prove it.";
    provenance.appendChild(badge);

    row.append(label, value, provenance);
    rows.appendChild(row);
  }
  $("facts-table").hidden = vm.facts.length === 0;
}

async function onVerify(): Promise<void> {
  try {
    const [reportText, proofText] = await Promise.all([
      readFile($("report") as HTMLInputElement),
      readFile($("proof") as HTMLInputElement),
    ]);
    const key = ($("key") as HTMLInputElement).value;
    render(await verifyFromText(reportText, proofText, key));
  } catch (e) {
    render({
      status: "error",
      headline: "Could not check this",
      detail: e instanceof Error ? e.message : String(e),
      facts: [],
    });
  }
}

$("verify").addEventListener("click", () => {
  void onVerify();
});
