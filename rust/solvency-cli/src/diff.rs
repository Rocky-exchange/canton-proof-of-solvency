//! Comparing the disclosure manifests of two reports (SPEC §8.5).
//!
//! Separate from `run`: this reads no commitments and verifies nothing, so it
//! neither takes a trusted key nor produces proof outcomes. Demanding a key
//! for an operation that checks no signature would be theatre.

use crate::args::Command;
use anyhow::{Context, Result};
use canton_solvency_report::document::SignedReport;
use canton_solvency_report::manifest::{diff, Manifest, ManifestChange};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffSummary {
    pub changes: Vec<ManifestChange>,
}

impl DiffSummary {
    pub fn reductions(&self) -> Vec<&ManifestChange> {
        self.changes.iter().filter(|c| c.is_reduction()).collect()
    }

    /// A reduction is the finding this command exists to surface, so it is
    /// what the exit code reports.
    pub fn has_reductions(&self) -> bool {
        self.changes.iter().any(|c| c.is_reduction())
    }
}

/// A report with no manifest is compared as an empty one, so dropping from v2
/// back to v1 shows up as every field being removed rather than as nothing.
fn manifest_of(path: &std::path::Path) -> Result<Manifest> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let signed: SignedReport =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(signed.report.manifest.unwrap_or(Manifest {
        audience: String::new(),
        fields: Default::default(),
    }))
}

pub fn run_diff(command: &Command) -> Result<DiffSummary> {
    let Command::ManifestDiff {
        previous, current, ..
    } = command
    else {
        anyhow::bail!("run_diff called with a non-diff command");
    };
    Ok(DiffSummary {
        changes: diff(&manifest_of(previous)?, &manifest_of(current)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_solvency_report::manifest::Disclosure;
    use std::path::PathBuf;

    fn fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        std::fs::read_to_string(path).unwrap()
    }

    /// Writes two reports and diffs them. `edit` mutates the second's
    /// manifest JSON.
    fn diff_of(edit: impl Fn(&str) -> String) -> DiffSummary {
        let dir = tempfile::tempdir().unwrap();
        let previous = dir.path().join("prev.json");
        let current = dir.path().join("curr.json");
        let base = fixture("report-v2.golden.json");
        std::fs::write(&previous, &base).unwrap();
        std::fs::write(&current, edit(&base)).unwrap();
        run_diff(&Command::ManifestDiff {
            previous,
            current,
            json: false,
        })
        .unwrap()
    }

    #[test]
    fn identical_reports_have_no_changes() {
        let summary = diff_of(|base| base.to_string());
        assert!(summary.changes.is_empty());
        assert!(!summary.has_reductions());
    }

    #[test]
    fn a_field_moving_away_from_published_is_a_reduction() {
        let summary = diff_of(|base| {
            base.replace(
                r#""mark_prices": "published""#,
                r#""mark_prices": "withheld""#,
            )
        });
        assert_eq!(
            summary.changes,
            vec![ManifestChange::Changed {
                path: "mark_prices".to_string(),
                from: Disclosure::Published,
                to: Disclosure::Withheld,
            }]
        );
        assert!(summary.has_reductions());
    }

    #[test]
    fn a_field_becoming_published_is_not_a_reduction() {
        let summary = diff_of(|base| {
            base.replace(
                r#""customer_identities": "withheld""#,
                r#""customer_identities": "published""#,
            )
        });
        assert_eq!(summary.changes.len(), 1);
        assert!(!summary.has_reductions());
    }

    /// Dropping back to v1 loses the manifest entirely. That is the largest
    /// possible reduction and must not read as "no changes".
    #[test]
    fn dropping_the_manifest_altogether_is_a_reduction() {
        let dir = tempfile::tempdir().unwrap();
        let previous = dir.path().join("prev.json");
        let current = dir.path().join("curr.json");
        std::fs::write(&previous, fixture("report-v2.golden.json")).unwrap();
        std::fs::write(&current, fixture("report.golden.json")).unwrap();

        let summary = run_diff(&Command::ManifestDiff {
            previous,
            current,
            json: false,
        })
        .unwrap();
        assert!(summary.has_reductions(), "changes: {:?}", summary.changes);
        assert!(summary
            .changes
            .iter()
            .all(|c| matches!(c, ManifestChange::Removed { .. })));
        assert_eq!(summary.reductions().len(), 5, "the five published fields");
    }

    #[test]
    fn adopting_a_manifest_is_not_a_reduction() {
        let dir = tempfile::tempdir().unwrap();
        let previous = dir.path().join("prev.json");
        let current = dir.path().join("curr.json");
        std::fs::write(&previous, fixture("report.golden.json")).unwrap();
        std::fs::write(&current, fixture("report-v2.golden.json")).unwrap();

        let summary = run_diff(&Command::ManifestDiff {
            previous,
            current,
            json: false,
        })
        .unwrap();
        assert!(!summary.changes.is_empty());
        assert!(!summary.has_reductions());
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let err = run_diff(&Command::ManifestDiff {
            previous: PathBuf::from("/nope/a.json"),
            current: PathBuf::from("/nope/b.json"),
            json: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("reading"), "got {err}");
    }
}
