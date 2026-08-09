//! Rendering a [`Summary`] for humans and for pipelines.

use crate::run::Summary;

/// Failures are listed individually; successes are counted. Someone sweeping
/// ten thousand proofs needs the one that broke, not ten thousand OK lines.
pub fn render_text(summary: &Summary) -> String {
    let mut out = format!("report digest : {}\n", summary.report_digest);

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
        "checked": summary.outcomes.len(),
        "passed": summary.passed(),
        "proofs": proofs,
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

    #[test]
    fn json_output_reports_ok_for_a_fully_passing_run() {
        let json = render_json(&summary(vec![ok_outcome("a.json")]));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ok"], true);
    }
}
