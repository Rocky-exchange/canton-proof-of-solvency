//! Runs the checked-in conformance corpus (SPEC §14.3).
//!
//! The corpus is the artefact a second implementation runs to claim
//! compatibility. Running it here too is what keeps it honest: a case the
//! reference implementation cannot itself satisfy is not a conformance test,
//! it is a bug report.

use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

/// Delegates to the library runner, which the §14.5 statement builder also
/// uses: a statement must not be able to report an outcome this test would
/// not have produced.
use canton_solvency_report::compat::run_case;

/// A phrase that only the declared failure produces. Deliberately a fragment
/// of the real message rather than a code: a message reworded into something
/// less specific should fail here, because the message is what an operator
/// reads.
fn expected_text(failure: &str) -> &'static str {
    match failure {
        "root_hash_mismatch" => "does not fold to the published root",
        "root_sums_mismatch" => "totals",
        "digest_mismatch" => "belongs to a different report",
        "bad_signature" => "signature does not verify",
        "unknown_signer" => "trusted key",
        "manifest_inconsistent" => "manifest disagrees",
        "profile" => "profile ",
        "not_genesis" => "names a predecessor",
        "broken" => "does not name the one before it",
        "pack_missing" => "which is not present",
        "pack_altered" => "does not match the digest",
        "pack_unlisted" => "does not name it",
        other => panic!("no expected text for declared failure {other:?}"),
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
                let error = outcome
                    .as_ref()
                    .err()
                    .unwrap_or_else(|| panic!("case {id} should be rejected but passed"));
                // Rejected is not enough: a case can exercise the check it
                // names and a different check in fact. `proof-understated-totals`
                // looked like a test of the §9.1 sums comparison and was
                // rejected one step earlier by the digest binding, which left
                // the sums comparison untested entirely.
                if let Some(declared) = case["failure"].as_str() {
                    let expected = expected_text(declared);
                    assert!(
                        error.contains(expected),
                        "case {id} declares {declared:?}, so its rejection should \
                         mention {expected:?}; it said {error:?}"
                    );
                }
                rejected += 1;
            }
            other => panic!("case {id} has unknown expectation {other}"),
        }
    }

    // Every case must declare what it needs. An implementation supporting a
    // subset of the format can then skip by declaration instead of by
    // accident: a report-v1-only verifier that merely rejects the v2 cases
    // "passes" `report-v2-manifest-lies` without ever testing a manifest.
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let requires = case["requires"]
            .as_array()
            .unwrap_or_else(|| panic!("case {id} declares no `requires`"));
        assert!(
            !requires.is_empty(),
            "case {id} declares an empty `requires`, so nothing can filter it"
        );
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
