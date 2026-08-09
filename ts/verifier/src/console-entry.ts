/**
 * DOM shell for the disclosure console (viewer half). All decisions live in
 * `console.ts`; this only moves text between the DOM and `buildConsole`.
 */

import { buildConsole, type ConsoleModel } from "./console";

const $ = (id: string): HTMLElement => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el;
};

async function required(input: HTMLInputElement): Promise<string> {
  const file = input.files?.[0];
  if (!file) throw new Error(`Choose a ${input.dataset.what ?? "file"} first.`);
  return file.text();
}

async function optional(input: HTMLInputElement): Promise<string | undefined> {
  return input.files?.[0] ? input.files[0].text() : undefined;
}

function section(id: string, show: boolean): HTMLElement {
  const el = $(id);
  el.hidden = !show;
  return el;
}

function render(model: ConsoleModel): void {
  const { verification } = model;
  const result = section("result", true);
  result.className = `result ${verification.status}`;
  $("headline").textContent = verification.headline;
  $("detail").textContent = verification.detail;

  const facts = $("facts");
  facts.innerHTML = "";
  for (const f of verification.facts) {
    const row = document.createElement("tr");
    const label = document.createElement("th");
    label.scope = "row";
    label.textContent = f.label;
    const value = document.createElement("td");
    value.className = "value";
    value.textContent = f.value;
    const badge = document.createElement("span");
    badge.className = `badge ${f.provenance}`;
    badge.textContent = f.provenance === "verified" ? "recomputed here" : "publisher says";
    const prov = document.createElement("td");
    prov.appendChild(badge);
    row.append(label, value, prov);
    facts.appendChild(row);
  }

  // Where each published figure comes from.
  const flow = section("flow-section", model.flow.length > 0);
  const flowList = $("flow");
  flowList.innerHTML = "";
  for (const node of model.flow) {
    const li = document.createElement("li");
    li.style.marginLeft = `${node.depth * 1.4}rem`;
    const name = document.createElement("strong");
    name.textContent = node.label;
    const detail = document.createElement("span");
    detail.className = "hint";
    detail.textContent = ` — ${node.detail}`;
    li.append(name, detail);
    flowList.appendChild(li);
  }
  flow.hidden = model.flow.length === 0;

  section("coverage-section", model.coverage !== null);
  const coverage = $("coverage");
  coverage.innerHTML = "";
  for (const row of model.coverage ?? []) {
    const tr = document.createElement("tr");
    for (const [text, cls] of [
      [row.asset, ""],
      [row.held, "value"],
      [row.owed, "value"],
    ] as const) {
      const td = document.createElement("td");
      td.className = cls;
      td.textContent = text;
      tr.appendChild(td);
    }
    const verdict = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${row.covered ? "verified" : "short"}`;
    badge.textContent = row.covered ? "covered" : "SHORT";
    verdict.appendChild(badge);
    tr.appendChild(verdict);
    coverage.appendChild(tr);
  }

  section("history-section", model.history !== null);
  const history = $("history");
  history.innerHTML = "";
  for (const row of model.history ?? []) {
    const tr = document.createElement("tr");
    for (const text of [String(row.index), row.snapshotTime, `${row.reportDigest.slice(0, 16)}…`]) {
      const td = document.createElement("td");
      td.textContent = text;
      tr.appendChild(td);
    }
    const verdict = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${row.linked ? "verified" : "short"}`;
    badge.textContent = row.linked ? "linked" : "BREAK";
    verdict.appendChild(badge);
    tr.appendChild(verdict);
    history.appendChild(tr);
  }
}

async function onCheck(): Promise<void> {
  try {
    const [reportText, proofText, custodyText, historyText] = await Promise.all([
      required($("report") as HTMLInputElement),
      required($("proof") as HTMLInputElement),
      optional($("custody") as HTMLInputElement),
      optional($("history") as HTMLInputElement),
    ]);
    render(
      await buildConsole({
        reportText,
        proofText,
        trustedKeyHex: ($("key") as HTMLInputElement).value,
        custodyText,
        historyText,
      })
    );
  } catch (e) {
    render({
      verification: {
        status: "error",
        headline: "Could not check this",
        detail: e instanceof Error ? e.message : String(e),
        facts: [],
      },
      statement: null,
      coverage: null,
      history: null,
      flow: [],
    });
  }
}

$("check").addEventListener("click", () => {
  void onCheck();
});
