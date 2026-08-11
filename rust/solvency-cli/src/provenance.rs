//! The `provenance` verb: where a published figure came from (SPEC §17).
//!
//! The rendering groups by field rather than by source, because the question
//! a reader arrives with is "where did *this number* come from" and not "what
//! is this participant used for". On-ledger and off-ledger sources are marked
//! differently for the same reason §17.4 exists: the distinction between a
//! figure Canton can be asked about and one that arrives by API is the one
//! that changes what may be claimed about it.

use crate::args::Command;
use anyhow::{Context, Result};
use canton_solvency_report::assurance::AssuranceStatement;
use canton_solvency_report::document::SignedReport;
use canton_solvency_report::provenance::{
    check_against_assurance, verify_provenance, SignedProvenance, SourceKind,
};

fn load<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub struct ProvenanceOutcome {
    pub graph: SignedProvenance,
    /// Present when an assurance statement was supplied and §17.4 was checked.
    pub checked_against_levels: bool,
    pub failure: Option<String>,
}

impl ProvenanceOutcome {
    pub fn ok(&self) -> bool {
        self.failure.is_none()
    }
}

pub fn run_provenance(command: &Command) -> Result<ProvenanceOutcome> {
    let Command::Provenance {
        report,
        provenance,
        assurance,
        trusted_key,
        ..
    } = command
    else {
        anyhow::bail!("run_provenance called with a non-provenance command");
    };

    let signed_report: SignedReport = load(report)?;
    let graph: SignedProvenance = load(provenance)?;
    let statement: Option<AssuranceStatement> = assurance.as_deref().map(load).transpose()?;

    let mut failure = verify_provenance(&signed_report, &graph, trusted_key)
        .err()
        .map(|e| e.to_string());

    // §17.4 only means anything beside a statement, and running it on a graph
    // that already failed its own rules would report the second problem for a
    // document that never got past the first.
    if failure.is_none() {
        if let Some(statement) = &statement {
            failure = check_against_assurance(&graph.provenance, &statement.levels)
                .err()
                .map(|e| e.to_string());
        }
    }

    Ok(ProvenanceOutcome {
        graph,
        checked_against_levels: statement.is_some(),
        failure,
    })
}

/// The graph as a tree, one block per field.
pub fn render_provenance_text(outcome: &ProvenanceOutcome) -> String {
    let p = &outcome.graph.provenance;
    let by_id: std::collections::BTreeMap<&str, _> =
        p.sources.iter().map(|s| (s.id.as_str(), s)).collect();

    let mut out = String::new();
    for derivation in &p.derivations {
        out.push_str(&format!("{}\n", derivation.field));
        out.push_str(&format!("  method: {}\n", derivation.method));
        let last = derivation.sources.len().saturating_sub(1);
        for (i, id) in derivation.sources.iter().enumerate() {
            let branch = if i == last { "└─" } else { "├─" };
            match by_id.get(id.as_str()) {
                Some(source) => {
                    // The marker is the §17.4 distinction, not decoration: it
                    // is what decides whether ledger-derived may be claimed.
                    let marker = if source.kind.on_ledger() {
                        "on-ledger "
                    } else {
                        "OFF-LEDGER"
                    };
                    out.push_str(&format!(
                        "  {branch} [{marker}] {:<14} {}\n",
                        source.kind.to_string(),
                        source.name
                    ));
                    if let Some(basis) = &source.basis {
                        let indent = if i == last { "     " } else { "  │  " };
                        out.push_str(&format!("{indent}    {basis}\n"));
                    }
                }
                // verify_provenance refuses this, so it can only appear when
                // rendering a graph that already failed.
                None => out.push_str(&format!("  {branch} [UNDECLARED] {id}\n")),
            }
        }
        out.push('\n');
    }

    let unnamed: Vec<&str> = canton_solvency_report::assurance::KNOWN_FIELDS
        .iter()
        .copied()
        .filter(|f| !p.derivations.iter().any(|d| d.field == *f))
        .collect();
    if !unnamed.is_empty() {
        // Honest rather than alarming: §17.1 allows a partial graph, and a
        // reader still needs to know which figures it says nothing about.
        out.push_str(&format!(
            "no provenance declared for: {}\n",
            unnamed.join(", ")
        ));
    }

    match &outcome.failure {
        Some(reason) => out.push_str(&format!("REFUSED: {reason}\n")),
        None if outcome.checked_against_levels => {
            out.push_str("graph verified, and consistent with the declared assurance levels\n")
        }
        None => out.push_str(
            "graph verified — supply --assurance to check it against declared levels (§17.4)\n",
        ),
    }
    out
}

pub fn render_provenance_json(outcome: &ProvenanceOutcome) -> String {
    let p = &outcome.graph.provenance;
    let sources: Vec<serde_json::Value> = p
        .sources
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "kind": s.kind.as_str(),
                "on_ledger": s.kind.on_ledger(),
                "name": s.name,
                "basis": s.basis,
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "ok": outcome.ok(),
        "report_digest": p.report_digest,
        "sources": sources,
        "derivations": p.derivations,
        "checked_against_levels": outcome.checked_against_levels,
        "failure": outcome.failure,
    }))
    .unwrap_or_else(|e| format!("{{\"error\":{:?}}}", e.to_string()))
}

/// Whether any off-ledger source appears in the graph at all.
pub fn has_off_ledger(outcome: &ProvenanceOutcome) -> bool {
    outcome
        .graph
        .provenance
        .sources
        .iter()
        .any(|s| s.kind == SourceKind::OffLedger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_solvency_report::golden;
    use std::path::PathBuf;

    /// Per-test file names. Tests run in parallel, and sharing one path meant
    /// one test reading a file another was still writing.
    fn scratch(case: &str, name: &str, value: &serde_json::Value) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("canton-provenance-cli-tests")
            .join(case);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
        path
    }

    fn command(case: &str, assurance: Option<PathBuf>) -> Command {
        let (report, graph) = golden::provenance_fixture();
        Command::Provenance {
            report: scratch(case, "report.json", &serde_json::to_value(&report).unwrap()),
            provenance: scratch(
                case,
                "provenance.json",
                &serde_json::to_value(&graph).unwrap(),
            ),
            assurance,
            trusted_key: golden::signer().public_key_hex(),
            json: false,
        }
    }

    #[test]
    fn renders_each_field_with_its_sources() {
        const CASE: &str = "renders_each_field_with_its_sources";
        let outcome = run_provenance(&command(CASE, None)).unwrap();
        assert!(outcome.ok(), "{:?}", outcome.failure);
        let text = render_provenance_text(&outcome);
        assert!(text.contains("root_sums"), "{text}");
        assert!(text.contains("participant::venue-one"), "{text}");
        assert!(text.contains("acme-pricing"), "{text}");
    }

    /// The distinction §17.4 turns on has to be visible, or a reader cannot
    /// see why one figure may be called ledger-derived and another may not.
    #[test]
    fn marks_off_ledger_sources_differently_from_on_ledger_ones() {
        const CASE: &str = "marks_off_ledger_sources_differently_from_on_ledger_ones";
        let text = render_provenance_text(&run_provenance(&command(CASE, None)).unwrap());
        assert!(text.contains("OFF-LEDGER"), "{text}");
        assert!(text.contains("on-ledger"), "{text}");
    }

    /// A partial graph is allowed, and a reader needs to know which figures it
    /// says nothing about — silence there reads as "everything is accounted
    /// for".
    #[test]
    fn names_the_fields_the_graph_says_nothing_about() {
        const CASE: &str = "names_the_fields_the_graph_says_nothing_about";
        let text = render_provenance_text(&run_provenance(&command(CASE, None)).unwrap());
        assert!(
            text.contains("no provenance declared for") && text.contains("disclosures.bad_debt"),
            "{text}"
        );
    }

    #[test]
    fn refuses_a_contradiction_with_the_declared_levels() {
        const CASE: &str = "refuses_a_contradiction_with_the_declared_levels";
        let (report, _) = golden::provenance_fixture();
        let statement = serde_json::json!({
            "format_version": "canton-solvency-assurance-v1",
            "report_digest": canton_solvency_report::digest::report_digest_hex(&report.report),
            "levels": { "mark_prices": "ledger-derived" },
        });
        let path = scratch(CASE, "assurance.json", &statement);
        let outcome = run_provenance(&command(CASE, Some(path))).unwrap();
        assert!(!outcome.ok());
        let text = render_provenance_text(&outcome);
        assert!(
            text.contains("REFUSED") && text.contains("mark_prices"),
            "{text}"
        );
    }
}
