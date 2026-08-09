//! Load documents from disk and verify them.

use crate::args::{Command, ProofSource};
use anyhow::{Context, Result};
use canton_solvency_report::document::{ProofDocument, SignedReport};
use canton_solvency_report::group::{verify_chain, verify_membership, GroupMembershipDocument};
use canton_solvency_report::verify::verify;
use std::path::{Path, PathBuf};

/// One proof's outcome. `failure` is the typed verification failure rendered
/// as a stable string, so `--json` consumers can match on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofOutcome {
    pub path: PathBuf,
    /// Customer id, or entity id when checking a group membership.
    pub subject: String,
    pub failure: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    pub report_digest: String,
    pub outcomes: Vec<ProofOutcome>,
}

impl Summary {
    pub fn passed(&self) -> usize {
        self.outcomes.iter().filter(|o| o.failure.is_none()).count()
    }

    pub fn all_passed(&self) -> bool {
        self.outcomes.iter().all(|o| o.failure.is_none())
    }
}

fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// `*.json` in the directory, sorted so output is stable across filesystems.
fn proof_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    anyhow::ensure!(
        !paths.is_empty(),
        "no *.json proofs in {} — refusing to report a vacuous pass",
        dir.display()
    );
    Ok(paths)
}

pub fn run(command: &Command) -> Result<Summary> {
    match command {
        Command::Digest { report } => {
            let signed: SignedReport = load(report)?;
            Ok(Summary {
                report_digest: hex_digest(&signed),
                outcomes: Vec::new(),
            })
        }
        Command::Verify {
            report,
            proofs,
            trusted_key,
            ..
        } => {
            let signed: SignedReport = load(report)?;
            let paths = match proofs {
                ProofSource::File(p) => vec![p.clone()],
                ProofSource::Dir(d) => proof_paths(d)?,
            };

            let sweeping = matches!(proofs, ProofSource::Dir(_));
            let mut outcomes = Vec::new();
            for path in paths {
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let proof: ProofDocument = match serde_json::from_str(&text) {
                    Ok(proof) => proof,
                    // Publishers put report.json next to the proofs. Skip a
                    // report while sweeping; anything else is a real error,
                    // and an explicitly named file must always parse.
                    Err(e) => {
                        if sweeping && serde_json::from_str::<SignedReport>(&text).is_ok() {
                            continue;
                        }
                        return Err(
                            anyhow::Error::new(e).context(format!("parsing {}", path.display()))
                        );
                    }
                };
                outcomes.push(ProofOutcome {
                    subject: proof.leaf.user_id.clone(),
                    failure: verify(&signed, &proof, trusted_key)
                        .err()
                        .map(|f| f.to_string()),
                    path,
                });
            }

            Ok(Summary {
                report_digest: hex_digest(&signed),
                outcomes,
            })
        }
        Command::VerifyGroup {
            report,
            memberships,
            trusted_key,
            ..
        } => {
            let signed: SignedReport = load(report)?;
            let paths = match memberships {
                ProofSource::File(p) => vec![p.clone()],
                ProofSource::Dir(d) => proof_paths(d)?,
            };
            let sweeping = matches!(memberships, ProofSource::Dir(_));

            let mut outcomes = Vec::new();
            for path in paths {
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let membership: GroupMembershipDocument = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    // Publishers put the group report beside the memberships.
                    Err(e) => {
                        if sweeping && serde_json::from_str::<SignedReport>(&text).is_ok() {
                            continue;
                        }
                        return Err(
                            anyhow::Error::new(e).context(format!("parsing {}", path.display()))
                        );
                    }
                };
                outcomes.push(ProofOutcome {
                    subject: membership.entity.entity_id.clone(),
                    failure: verify_membership(&signed, &membership, trusted_key)
                        .err()
                        .map(|f| f.to_string()),
                    path,
                });
            }

            Ok(Summary {
                report_digest: hex_digest(&signed),
                outcomes,
            })
        }

        Command::VerifyChain {
            group_report,
            membership,
            report,
            proof,
            trusted_key,
            group_key,
            ..
        } => {
            let group_signed: SignedReport = load(group_report)?;
            let membership_doc: GroupMembershipDocument = load(membership)?;
            let entity_signed: SignedReport = load(report)?;
            let proof_doc: ProofDocument = load(proof)?;

            let failure = verify_chain(
                &group_signed,
                &membership_doc,
                &entity_signed,
                &proof_doc,
                group_key,
                trusted_key,
            )
            .err()
            .map(|f| f.to_string());

            Ok(Summary {
                report_digest: hex_digest(&group_signed),
                outcomes: vec![ProofOutcome {
                    path: proof.clone(),
                    subject: format!(
                        "{} in {}",
                        proof_doc.leaf.user_id, membership_doc.entity.entity_id
                    ),
                    failure,
                }],
            })
        }
        Command::ManifestDiff { .. } => anyhow::bail!("handled by run_diff"),
        Command::Help | Command::Version => Ok(Summary {
            report_digest: String::new(),
            outcomes: Vec::new(),
        }),
    }
}

fn hex_digest(signed: &SignedReport) -> String {
    canton_solvency_report::digest::report_digest_hex(&signed.report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const GOLDEN_DIGEST: &str = "0800c1047c9724ea429b238b01366f2032d674425d3ed745ed3402b2f534df61";

    fn fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        std::fs::read_to_string(path).unwrap()
    }

    /// Writes the golden pair into a temp dir and returns (dir, report path).
    fn golden_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        std::fs::write(&report, fixture("report.golden.json")).unwrap();
        std::fs::write(
            dir.path().join("proof-u2.json"),
            fixture("proof.golden.json"),
        )
        .unwrap();
        (dir, report)
    }

    fn verify_cmd(report: PathBuf, proofs: ProofSource) -> Command {
        Command::Verify {
            report,
            proofs,
            trusted_key: KEY.to_string(),
            json: false,
        }
    }

    #[test]
    fn a_valid_report_and_proof_verify() {
        let (dir, report) = golden_dir();
        let summary = run(&verify_cmd(
            report,
            ProofSource::File(dir.path().join("proof-u2.json")),
        ))
        .unwrap();
        assert!(summary.all_passed());
        assert_eq!(summary.report_digest, GOLDEN_DIGEST);
        assert_eq!(
            summary.outcomes[0].subject,
            "22222222-2222-7222-8222-222222222222"
        );
    }

    #[test]
    fn a_tampered_balance_fails_and_names_the_file() {
        let (dir, report) = golden_dir();
        let bad = dir.path().join("bad.json");
        std::fs::write(
            &bad,
            fixture("proof.golden.json").replace("0.250000000000000000", "9.250000000000000000"),
        )
        .unwrap();

        let summary = run(&verify_cmd(report, ProofSource::File(bad.clone()))).unwrap();
        assert!(!summary.all_passed());
        assert_eq!(summary.outcomes[0].path, bad);
        assert!(
            summary.outcomes[0]
                .failure
                .as_deref()
                .unwrap()
                .contains("root"),
            "got {:?}",
            summary.outcomes[0].failure
        );
    }

    #[test]
    fn the_wrong_trusted_key_fails_verification() {
        let (dir, report) = golden_dir();
        let summary = run(&Command::Verify {
            report,
            proofs: ProofSource::File(dir.path().join("proof-u2.json")),
            trusted_key: "ab".repeat(32),
            json: false,
        })
        .unwrap();
        assert!(!summary.all_passed());
        assert!(summary.outcomes[0]
            .failure
            .as_deref()
            .unwrap()
            .contains("trusted key"));
    }

    #[test]
    fn a_directory_verifies_every_proof_in_it() {
        let (dir, report) = golden_dir();
        for n in 0..3 {
            std::fs::write(
                dir.path().join(format!("copy-{n}.json")),
                fixture("proof.golden.json"),
            )
            .unwrap();
        }
        let summary = run(&verify_cmd(report, ProofSource::Dir(dir.path().into()))).unwrap();
        // 4 proofs; report.json is skipped because it is not a proof document.
        assert_eq!(summary.outcomes.len(), 4);
        assert_eq!(summary.passed(), 4);
    }

    #[test]
    fn one_bad_proof_among_many_fails_the_run_and_is_identified() {
        let (dir, report) = golden_dir();
        std::fs::write(dir.path().join("copy.json"), fixture("proof.golden.json")).unwrap();
        let bad = dir.path().join("zz-bad.json");
        std::fs::write(
            &bad,
            fixture("proof.golden.json").replace("0.250000000000000000", "9.250000000000000000"),
        )
        .unwrap();

        let summary = run(&verify_cmd(report, ProofSource::Dir(dir.path().into()))).unwrap();
        assert!(!summary.all_passed());
        assert_eq!(summary.passed(), 2);
        let failed: Vec<&PathBuf> = summary
            .outcomes
            .iter()
            .filter(|o| o.failure.is_some())
            .map(|o| &o.path)
            .collect();
        assert_eq!(failed, vec![&bad]);
    }

    #[test]
    fn an_empty_directory_is_an_error_not_a_vacuous_pass() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        std::fs::write(&report, fixture("report.golden.json")).unwrap();
        let empty = dir.path().join("proofs");
        std::fs::create_dir(&empty).unwrap();

        let err = run(&verify_cmd(report, ProofSource::Dir(empty))).unwrap_err();
        assert!(err.to_string().contains("no *.json"), "got {err}");
    }

    #[test]
    fn a_missing_file_is_an_error_distinct_from_a_verification_failure() {
        let (dir, _) = golden_dir();
        let err = run(&verify_cmd(
            dir.path().join("nope.json"),
            ProofSource::File(dir.path().join("proof-u2.json")),
        ))
        .unwrap_err();
        assert!(err.to_string().contains("reading"), "got {err}");
    }

    #[test]
    fn a_malformed_document_is_an_error_not_a_verification_failure() {
        let (dir, report) = golden_dir();
        let junk = dir.path().join("junk.json");
        std::fs::write(&junk, "{ not json").unwrap();
        let err = run(&verify_cmd(report, ProofSource::File(junk))).unwrap_err();
        assert!(err.to_string().contains("parsing"), "got {err}");
    }

    fn group_dir() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let group = dir.path().join("group-report.json");
        let membership = dir.path().join("membership.json");
        std::fs::write(&group, fixture("group-report.golden.json")).unwrap();
        std::fs::write(&membership, fixture("group-membership.golden.json")).unwrap();
        (dir, group, membership)
    }

    #[test]
    fn a_group_membership_verifies_against_its_group_report() {
        let (_d, group, membership) = group_dir();
        let summary = run(&Command::VerifyGroup {
            report: group,
            memberships: ProofSource::File(membership),
            trusted_key: KEY.to_string(),
            json: false,
        })
        .unwrap();
        assert!(summary.all_passed());
        assert_eq!(summary.outcomes[0].subject, "golden-entity-a");
    }

    #[test]
    fn a_relabelled_entity_fails_group_verification() {
        let (dir, group, _) = group_dir();
        let bad = dir.path().join("bad.json");
        std::fs::write(
            &bad,
            fixture("group-membership.golden.json").replace("golden-entity-a", "golden-entity-z"),
        )
        .unwrap();
        let summary = run(&Command::VerifyGroup {
            report: group,
            memberships: ProofSource::File(bad),
            trusted_key: KEY.to_string(),
            json: false,
        })
        .unwrap();
        assert!(!summary.all_passed());
    }

    #[test]
    fn a_group_directory_skips_the_group_report_beside_the_memberships() {
        let (dir, group, _) = group_dir();
        let summary = run(&Command::VerifyGroup {
            report: group,
            memberships: ProofSource::Dir(dir.path().into()),
            trusted_key: KEY.to_string(),
            json: false,
        })
        .unwrap();
        assert_eq!(summary.outcomes.len(), 1);
        assert!(summary.all_passed());
    }

    #[test]
    fn a_full_chain_verifies_a_customer_up_to_the_group_total() {
        let (dir, group, membership) = group_dir();
        let report = dir.path().join("report.json");
        let proof = dir.path().join("proof.json");
        std::fs::write(&report, fixture("report.golden.json")).unwrap();
        std::fs::write(&proof, fixture("proof.golden.json")).unwrap();

        let summary = run(&Command::VerifyChain {
            group_report: group,
            membership,
            report,
            proof,
            trusted_key: KEY.to_string(),
            group_key: KEY.to_string(),
            json: false,
        })
        .unwrap();
        assert!(summary.all_passed());
        assert_eq!(summary.outcomes.len(), 1);
    }

    #[test]
    fn a_chain_with_a_tampered_customer_proof_fails() {
        let (dir, group, membership) = group_dir();
        let report = dir.path().join("report.json");
        let proof = dir.path().join("proof.json");
        std::fs::write(&report, fixture("report.golden.json")).unwrap();
        std::fs::write(
            &proof,
            fixture("proof.golden.json").replace("0.250000000000000000", "9.250000000000000000"),
        )
        .unwrap();

        let summary = run(&Command::VerifyChain {
            group_report: group,
            membership,
            report,
            proof,
            trusted_key: KEY.to_string(),
            group_key: KEY.to_string(),
            json: false,
        })
        .unwrap();
        assert!(!summary.all_passed());
        assert!(summary.outcomes[0]
            .failure
            .as_deref()
            .unwrap()
            .contains("root"));
    }

    #[test]
    fn digest_prints_the_golden_digest_without_needing_a_proof() {
        let (_dir, report) = golden_dir();
        let summary = run(&Command::Digest { report }).unwrap();
        assert_eq!(summary.report_digest, GOLDEN_DIGEST);
        assert!(summary.outcomes.is_empty());
    }
}
