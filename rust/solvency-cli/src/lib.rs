//! Offline verification of Canton solvency reports (SPEC §8, §9).
//!
//! All behaviour lives here so it can be tested without spawning processes;
//! `main` only maps a [`run::Summary`] onto stdout and an exit code.

pub mod args;
pub mod diff;
pub mod output;
pub mod run;

use anyhow::Result;
use run::Summary;

pub const EXIT_OK: i32 = 0;
pub const EXIT_VERIFICATION_FAILED: i32 = 1;
pub const EXIT_USAGE_OR_IO: i32 = 2;

/// A failed verification and a missing file are different events: in CI, a
/// typo in a path must never be reported as evidence of insolvency.
pub fn exit_code(result: &Result<Summary>) -> i32 {
    match result {
        Ok(summary) if summary.all_passed() => EXIT_OK,
        Ok(_) => EXIT_VERIFICATION_FAILED,
        Err(_) => EXIT_USAGE_OR_IO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use run::ProofOutcome;
    use std::path::PathBuf;

    fn summary(failure: Option<&str>) -> Summary {
        Summary {
            report_digest: "aa".repeat(32),
            outcomes: vec![ProofOutcome {
                path: PathBuf::from("p.json"),
                subject: "u".to_string(),
                failure: failure.map(String::from),
            }],
        }
    }

    #[test]
    fn a_fully_verified_run_exits_zero() {
        assert_eq!(exit_code(&Ok(summary(None))), EXIT_OK);
    }

    #[test]
    fn a_verification_failure_exits_one() {
        assert_eq!(
            exit_code(&Ok(summary(Some("root hash mismatch")))),
            EXIT_VERIFICATION_FAILED
        );
    }

    #[test]
    fn an_io_or_usage_error_exits_two_not_one() {
        assert_eq!(
            exit_code(&Err(anyhow::anyhow!("reading nope.json"))),
            EXIT_USAGE_OR_IO
        );
    }

    /// `digest` checks nothing, so it must not claim a verification passed by
    /// virtue of having checked nothing.
    #[test]
    fn a_run_with_no_proofs_exits_zero_only_because_nothing_was_asked() {
        let empty = Summary {
            report_digest: "aa".repeat(32),
            outcomes: Vec::new(),
        };
        assert_eq!(exit_code(&Ok(empty)), EXIT_OK);
    }
}
