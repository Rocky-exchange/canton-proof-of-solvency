//! Runs the checked-in conformance corpus (SPEC §14.3).
//!
//! The corpus is the artefact a second implementation runs to claim
//! compatibility. Running it here too is what keeps it honest: a case the
//! reference implementation cannot itself satisfy is not a conformance test,
//! it is a bug report.

use canton_solvency_report::anchor::{verify_chain, Anchor};
use canton_solvency_report::coverage::{verify_coverage, CoverageStatement};
use canton_solvency_report::document::{ProofDocument, ProofDocumentV2, SignedReport};
use canton_solvency_report::group::{verify_membership, GroupMembershipDocument};
use canton_solvency_report::verify::{verify, verify_v2};
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

/// Ok(()) when the case's documents verify, Err(reason) otherwise.
fn run_case(dir: &Path, kind: &str, key: &str) -> Result<(), String> {
    match kind {
        "proof" => {
            let report: SignedReport = load(&dir.join("report.json"))?;
            let proof: ProofDocument = load(&dir.join("proof.json"))?;
            verify(&report, &proof, key).map_err(|e| e.to_string())
        }
        "proof-v2" => {
            let report: SignedReport = load(&dir.join("report.json"))?;
            let proof: ProofDocumentV2 = load(&dir.join("proof.json"))?;
            verify_v2(&report, &proof, key).map_err(|e| e.to_string())
        }
        "membership" => {
            let report: SignedReport = load(&dir.join("group-report.json"))?;
            let membership: GroupMembershipDocument = load(&dir.join("membership.json"))?;
            verify_membership(&report, &membership, key).map_err(|e| e.to_string())
        }
        "coverage" => {
            let custody: SignedReport = load(&dir.join("custody.json"))?;
            let liabilities: SignedReport = load(&dir.join("liabilities.json"))?;
            let statement: CoverageStatement = load(&dir.join("statement.json"))?;
            let outcome = verify_coverage(&custody, &liabilities, &statement, key, key)
                .map_err(|e| e.to_string())?;
            if outcome.fully_covered() {
                Ok(())
            } else {
                Err("shortfall".to_string())
            }
        }
        "anchors" => {
            let history: Vec<Anchor> = load(&dir.join("history.json"))?;
            verify_chain(&history).map_err(|e| e.to_string())
        }
        other => panic!("unknown case kind {other}"),
    }
}

#[test]
fn every_conformance_case_behaves_as_the_manifest_says() {
    let dir = corpus_dir();
    let manifest: serde_json::Value =
        load(&dir.join("manifest.json")).expect("the corpus is checked in");
    let key = manifest["trusted_key"].as_str().unwrap();
    let cases = manifest["cases"].as_array().unwrap();
    assert!(cases.len() >= 15, "the corpus should be substantive");

    let (mut accepted, mut rejected) = (0, 0);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let expect = case["expect"].as_str().unwrap();
        let outcome = run_case(&dir.join(id), kind, key);

        match expect {
            "accept" => {
                assert_eq!(outcome, Ok(()), "case {id} should be accepted");
                accepted += 1;
            }
            "reject" => {
                assert!(outcome.is_err(), "case {id} should be rejected but passed");
                rejected += 1;
            }
            other => panic!("case {id} has unknown expectation {other}"),
        }
    }

    // A corpus of only-accepts would pass against an implementation that
    // accepts everything, and a corpus of only-rejects against one that
    // rejects everything.
    assert!(accepted >= 5, "too few accepting cases: {accepted}");
    assert!(rejected >= 8, "too few rejecting cases: {rejected}");
}

#[test]
fn every_case_directory_is_listed_in_the_manifest() {
    let dir = corpus_dir();
    let manifest: serde_json::Value = load(&dir.join("manifest.json")).unwrap();
    let mut listed: Vec<String> = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap().to_string())
        .collect();
    listed.sort();

    let mut present: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    present.sort();

    assert_eq!(
        present, listed,
        "a case on disk the manifest does not list would never be run"
    );
}
