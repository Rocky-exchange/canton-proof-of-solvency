//! Rendering a [`Summary`] for humans and for pipelines.

use crate::diff::DiffSummary;
use crate::run::Summary;
use canton_solvency_report::manifest::ManifestChange;

fn describe(change: &ManifestChange) -> String {
    match change {
        ManifestChange::Added { path, state } => {
            format!("+ {path}: now {}", state.as_str())
        }
        ManifestChange::Removed { path, was } => {
            format!("- {path}: was {}, no longer declared", was.as_str())
        }
        ManifestChange::Changed { path, from, to } => {
            format!("~ {path}: {} -> {}", from.as_str(), to.as_str())
        }
    }
}

/// Reductions are called out separately: an expansion of disclosure is not
/// the thing anyone is scanning this output for.
pub fn render_diff_text(summary: &DiffSummary) -> String {
    if summary.changes.is_empty() {
        return "no change to the disclosure manifest\n".to_string();
    }
    let mut out = String::new();
    for change in &summary.changes {
        let marker = if change.is_reduction() {
            "  REDUCED "
        } else {
            "          "
        };
        out.push_str(&format!("{marker}{}\n", describe(change)));
    }
    let reductions = summary.reductions().len();
    out.push_str(&format!(
        "{} change(s), {reductions} reducing disclosure\n",
        summary.changes.len()
    ));
    out
}

/// Shortfalls are named with their size; a covered asset needs only a count.
pub fn render_coverage_text(outcome: &canton_solvency_report::coverage::CoverageOutcome) -> String {
    use canton_solvency_merkle::format_amount_18dp;
    let mut out = String::new();
    for asset in outcome.shortfalls() {
        out.push_str(&format!(
            "SHORT {}: holds {} against {} owed, {} missing\n",
            asset.asset,
            format_amount_18dp(asset.held),
            format_amount_18dp(asset.owed),
            format_amount_18dp(asset.shortfall())
        ));
    }
    out.push_str(&format!(
        "{} of {} assets covered{}\n",
        outcome.assets.len() - outcome.shortfalls().len(),
        outcome.assets.len(),
        if outcome.fully_covered() {
            ""
        } else {
            " — NOT COVERED"
        }
    ));
    out
}

pub fn render_recompute_text(outcome: &crate::recompute::RecomputeOutcome) -> String {
    let mut out = format!(
        "leaves rebuilt: {}\npublished root: {}\nrecomputed    : {}\n",
        outcome.leaves, outcome.published_root, outcome.recomputed_root
    );
    for asset in &outcome.disagreeing_assets {
        out.push_str(&format!("DISAGREES     : {asset}\n"));
    }
    out.push_str(if outcome.matches() {
        "the dump reproduces the published commitment\n"
    } else {
        "the dump does NOT reproduce the published commitment\n"
    });
    out
}

pub fn render_recompute_json(outcome: &crate::recompute::RecomputeOutcome) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "ok": outcome.matches(),
        "leaves": outcome.leaves,
        "published_root": outcome.published_root,
        "recomputed_root": outcome.recomputed_root,
        "disagreeing_assets": outcome.disagreeing_assets,
    }))
    .expect("outcome is always serializable")
}

pub fn render_chain_text(summary: &crate::anchors::ChainSummary) -> String {
    let mut out = format!(
        "publisher     : {}\nhistory       : {} anchors, {} to {}\n",
        summary.publisher, summary.anchors, summary.first, summary.last
    );
    match &summary.failure {
        Some(failure) => out.push_str(&format!("BROKEN        : {failure}\n")),
        None => out.push_str("history intact\n"),
    }
    out
}

pub fn render_chain_json(summary: &crate::anchors::ChainSummary) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "ok": summary.intact(),
        "publisher": summary.publisher,
        "anchors": summary.anchors,
        "first": summary.first,
        "last": summary.last,
        "failure": summary.failure,
    }))
    .expect("summary is always serializable")
}

pub fn render_coverage_json(outcome: &canton_solvency_report::coverage::CoverageOutcome) -> String {
    use canton_solvency_merkle::format_amount_18dp;
    let assets: Vec<serde_json::Value> = outcome
        .assets
        .iter()
        .map(|a| {
            serde_json::json!({
                "asset": a.asset,
                "held": format_amount_18dp(a.held),
                "owed": format_amount_18dp(a.owed),
                "covered": a.covered(),
                "shortfall": format_amount_18dp(a.shortfall()),
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "ok": outcome.fully_covered(),
        "assets": assets,
    }))
    .expect("outcome is always serializable")
}

pub fn render_diff_json(summary: &DiffSummary) -> String {
    let changes: Vec<serde_json::Value> = summary
        .changes
        .iter()
        .map(|c| {
            serde_json::json!({
                "path": c.path(),
                "description": describe(c),
                "reduction": c.is_reduction(),
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "ok": !summary.has_reductions(),
        "changes": changes,
        "reductions": summary.reductions().len(),
    }))
    .expect("summary is always serializable")
}

/// Failures are listed individually; successes are counted. Someone sweeping
/// ten thousand proofs needs the one that broke, not ten thousand OK lines.
pub fn render_text(summary: &Summary) -> String {
    let mut out = format!("report digest : {}\n", summary.report_digest);
    if let Some(statement) = &summary.statement {
        out.push_str(&format!("asserts       : {statement}\n"));
    }

    if summary.outcomes.is_empty() {
        return out;
    }

    for outcome in summary.outcomes.iter().filter(|o| o.failure.is_some()) {
        out.push_str(&format!(
            "FAILED {} ({}): {}\n",
            outcome.path.display(),
            outcome.subject,
            outcome.failure.as_deref().unwrap_or_default()
        ));
    }

    let (passed, total) = (summary.passed(), summary.outcomes.len());
    out.push_str(&format!(
        "{} of {} proofs verified{}\n",
        passed,
        total,
        if summary.all_passed() {
            ""
        } else {
            " — FAILED"
        }
    ));
    out
}

pub fn render_json(summary: &Summary) -> String {
    let proofs: Vec<serde_json::Value> = summary
        .outcomes
        .iter()
        .map(|o| {
            serde_json::json!({
                "path": o.path.display().to_string(),
                "subject": o.subject,
                "ok": o.failure.is_none(),
                "failure": o.failure,
            })
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "ok": summary.all_passed(),
        "report_digest": summary.report_digest,
        "statement": summary.statement,
        "checked": summary.outcomes.len(),
        "passed": summary.passed(),
        "proofs": proofs,
    }))
    .expect("summary is always serializable")
}

pub fn render_pack_text(summary: &crate::pack::PackSummary) -> String {
    let mut out = format!(
        "publisher     : {}\nsnapshot      : {}\nreport digest : {}\npack members  : {}\n",
        summary.publisher, summary.snapshot_time, summary.report_digest, summary.members
    );
    match &summary.index_failure {
        Some(failure) => {
            out.push_str(&format!("DELIVERY      : {failure}\n"));
            // Saying this out loud matters: the files that did arrive may all
            // be perfectly valid, and a reader should not take that as
            // reassurance when the delivery itself is wrong.
            out.push_str("contents were not verified: the delivery is not the one signed\n");
        }
        None => {
            out.push_str("delivery      : complete and unaltered\n");
            if let Some(contents) = &summary.contents {
                out.push_str(&render_text(contents));
            }
        }
    }
    out
}

pub fn render_pack_json(summary: &crate::pack::PackSummary) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "ok": summary.all_passed(),
        "publisher": summary.publisher,
        "snapshot_time": summary.snapshot_time,
        "report_digest": summary.report_digest,
        "members": summary.members,
        "delivery_failure": summary.index_failure.as_ref().map(|f| f.to_string()),
        "contents": summary.contents.as_ref().map(|c| {
            serde_json::from_str::<serde_json::Value>(&render_json(c))
                .expect("render_json emits JSON")
        }),
    }))
    .expect("summary is always serializable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::ProofOutcome;
    use std::path::PathBuf;

    fn summary(outcomes: Vec<ProofOutcome>) -> Summary {
        Summary {
            report_digest: "0800c104".to_string() + &"0".repeat(56),
            statement: Some(
                "solvency.liabilities: every customer balance is committed".to_string(),
            ),
            outcomes,
        }
    }

    fn ok_outcome(name: &str) -> ProofOutcome {
        ProofOutcome {
            path: PathBuf::from(name),
            subject: "user-1".to_string(),
            failure: None,
        }
    }

    fn bad_outcome(name: &str) -> ProofOutcome {
        ProofOutcome {
            path: PathBuf::from(name),
            subject: "user-2".to_string(),
            failure: Some("proof does not fold to the published root".to_string()),
        }
    }

    #[test]
    fn text_output_states_the_digest_and_a_pass_count() {
        let text = render_text(&summary(vec![ok_outcome("a.json"), ok_outcome("b.json")]));
        assert!(text.contains("0800c104"), "digest missing from {text}");
        assert!(text.contains("2 of 2"), "counts missing from {text}");
        assert!(text.to_lowercase().contains("verified"), "got {text}");
    }

    /// "Verified" is not much use to a reader who does not know what was
    /// verified, so the profile's statement is part of the output.
    #[test]
    fn text_output_says_what_the_report_asserts() {
        let text = render_text(&summary(vec![ok_outcome("a.json")]));
        assert!(text.contains("solvency.liabilities"), "got {text}");
        assert!(text.contains("every customer balance"), "got {text}");
    }

    #[test]
    fn json_output_carries_the_statement_for_pipelines() {
        let json = render_json(&summary(vec![ok_outcome("a.json")]));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["statement"]
            .as_str()
            .unwrap()
            .contains("solvency.liabilities"));
    }

    #[test]
    fn text_output_names_every_failing_file_and_its_reason() {
        let text = render_text(&summary(vec![ok_outcome("a.json"), bad_outcome("b.json")]));
        assert!(text.contains("b.json"), "failing file missing from {text}");
        assert!(
            text.contains("does not fold"),
            "failure reason missing from {text}"
        );
        assert!(text.contains("1 of 2"), "got {text}");
    }

    /// An auditor sweeping thousands of proofs should not have to read
    /// thousands of success lines to find the one that broke.
    #[test]
    fn text_output_does_not_list_passing_files_individually() {
        let many: Vec<ProofOutcome> = (0..50).map(|i| ok_outcome(&format!("p{i}.json"))).collect();
        let text = render_text(&summary(many));
        assert!(!text.contains("p37.json"), "passing files listed in {text}");
        assert!(text.lines().count() < 10, "too verbose: {text}");
    }

    #[test]
    fn json_output_is_machine_readable_and_carries_per_proof_outcomes() {
        let json = render_json(&summary(vec![ok_outcome("a.json"), bad_outcome("b.json")]));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["checked"], 2);
        assert_eq!(parsed["passed"], 1);
        assert_eq!(parsed["report_digest"], summary(vec![]).report_digest);
        assert_eq!(parsed["proofs"][1]["path"], "b.json");
        assert_eq!(parsed["proofs"][1]["ok"], false);
        assert_eq!(
            parsed["proofs"][1]["failure"],
            "proof does not fold to the published root"
        );
        assert_eq!(parsed["proofs"][0]["failure"], serde_json::Value::Null);
    }

    mod manifest_diff {
        use super::*;
        use canton_solvency_report::manifest::Disclosure;

        fn changed(from: Disclosure, to: Disclosure) -> ManifestChange {
            ManifestChange::Changed {
                path: "mark_prices".to_string(),
                from,
                to,
            }
        }

        #[test]
        fn no_changes_says_so_plainly() {
            let text = render_diff_text(&DiffSummary { changes: vec![] });
            assert!(text.contains("no change"), "got {text}");
        }

        #[test]
        fn a_reduction_is_marked_in_the_text_output() {
            let text = render_diff_text(&DiffSummary {
                changes: vec![changed(Disclosure::Published, Disclosure::Withheld)],
            });
            assert!(text.contains("REDUCED"), "got {text}");
            assert!(text.contains("published -> withheld"), "got {text}");
            assert!(text.contains("1 reducing"), "got {text}");
        }

        #[test]
        fn an_expansion_is_listed_but_not_marked_as_a_reduction() {
            let text = render_diff_text(&DiffSummary {
                changes: vec![changed(Disclosure::Withheld, Disclosure::Published)],
            });
            assert!(!text.contains("REDUCED"), "got {text}");
            assert!(text.contains("0 reducing"), "got {text}");
        }

        #[test]
        fn json_output_flags_each_change_and_the_overall_verdict() {
            let json = render_diff_json(&DiffSummary {
                changes: vec![
                    changed(Disclosure::Published, Disclosure::Withheld),
                    ManifestChange::Added {
                        path: "root_sums".to_string(),
                        state: Disclosure::Published,
                    },
                ],
            });
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed["ok"], false);
            assert_eq!(parsed["reductions"], 1);
            assert_eq!(parsed["changes"][0]["reduction"], true);
            assert_eq!(parsed["changes"][1]["reduction"], false);
        }

        #[test]
        fn json_output_is_ok_when_nothing_was_reduced() {
            let json = render_diff_json(&DiffSummary {
                changes: vec![changed(Disclosure::Withheld, Disclosure::Published)],
            });
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed["ok"], true);
        }
    }

    #[test]
    fn json_output_reports_ok_for_a_fully_passing_run() {
        let json = render_json(&summary(vec![ok_outcome("a.json")]));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ok"], true);
    }
}
