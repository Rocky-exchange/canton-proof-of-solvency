//! The `coverage` verb: custody assets against liabilities (SPEC §11).

use crate::args::Command;
use anyhow::{Context, Result};
use canton_solvency_report::coverage::{verify_coverage, CoverageOutcome, CoverageStatement};
use canton_solvency_report::document::SignedReport;

fn load<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn run_coverage(command: &Command) -> Result<CoverageOutcome> {
    let Command::Coverage {
        custody,
        liabilities,
        statement,
        trusted_key,
        custody_key,
        max_skew_seconds,
        ..
    } = command
    else {
        anyhow::bail!("run_coverage called with a non-coverage command");
    };

    let custody_report: SignedReport = load(custody)?;
    let liabilities_report: SignedReport = load(liabilities)?;
    let statement_doc: CoverageStatement = load(statement)?;

    verify_coverage(
        &custody_report,
        &liabilities_report,
        &statement_doc,
        custody_key,
        trusted_key,
        *max_skew_seconds,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        std::fs::read_to_string(path).unwrap()
    }

    fn command(dir: &std::path::Path) -> Command {
        Command::Coverage {
            custody: dir.join("custody.json"),
            liabilities: dir.join("liabilities.json"),
            statement: dir.join("statement.json"),
            trusted_key: KEY.to_string(),
            custody_key: KEY.to_string(),
            max_skew_seconds: canton_solvency_report::coverage::SAME_RUN,
            json: false,
        }
    }

    const KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

    fn write_fixtures() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, fixture_name) in [
            ("custody.json", "custody-report.golden.json"),
            ("liabilities.json", "report.golden.json"),
            ("statement.json", "coverage-statement.golden.json"),
        ] {
            std::fs::write(dir.path().join(name), fixture(fixture_name)).unwrap();
        }
        dir
    }

    #[test]
    fn the_golden_coverage_pair_is_fully_covered() {
        let dir = write_fixtures();
        let outcome = run_coverage(&command(dir.path())).unwrap();
        assert!(outcome.fully_covered(), "{:?}", outcome.assets);
    }

    #[test]
    fn a_missing_document_is_an_error_not_a_shortfall() {
        let dir = write_fixtures();
        std::fs::remove_file(dir.path().join("statement.json")).unwrap();
        let err = run_coverage(&command(dir.path())).unwrap_err();
        assert!(err.to_string().contains("reading"), "got {err}");
    }

    #[test]
    fn a_statement_naming_other_reports_is_rejected() {
        let dir = write_fixtures();
        std::fs::write(
            dir.path().join("statement.json"),
            fixture("coverage-statement.golden.json").replace(
                "\"custody_report_digest\": \"",
                "\"custody_report_digest\": \"0",
            ),
        )
        .unwrap();
        assert!(run_coverage(&command(dir.path())).is_err());
    }
}
