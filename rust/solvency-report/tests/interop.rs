//! Verifies third-party submissions in `interop/` with this toolkit.
//!
//! Milestone 6 asks for interop shown in both directions. The §14.5
//! compatibility statements cover one direction — another implementation
//! verifying our corpus. This is the other: *their* reports verified by *our*
//! toolkit, on our CI, reproducibly.
//!
//! Without it, "send us your reports and we will check" is a promise rather
//! than a procedure, and a producer has no way to know whether their output is
//! acceptable before asking.
//!
//! An empty `interop/` is not a failure — nobody has submitted yet, and
//! pretending otherwise would be the dishonest reading. What *is* a failure is
//! a submission that does not verify, or a harness that would not notice.

use canton_solvency_report::document::{ProofDocument, ProofDocumentV2, SignedReport};
use canton_solvency_report::verify::{verify, verify_v2};
use serde::Deserialize;
use std::path::{Path, PathBuf};

fn interop_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../interop")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    format_version: String,
    organisation: String,
    /// Where to reach whoever produced this, so a failure has an addressee.
    contact: String,
    implementation: String,
    /// Obtained out of band, exactly as §8.4 requires — never read from the
    /// report it is meant to authenticate.
    trusted_key: String,
    documents: Vec<Document>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    /// `proof` or `proof-v2`.
    kind: String,
    report: String,
    proof: String,
}

fn load<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

fn submissions() -> Vec<(String, Submission)> {
    let dir = interop_dir();
    if !dir.exists() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("interop/ is readable") {
        let path = entry.unwrap().path();
        if !path.is_dir() {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let manifest = path.join("submission.json");
        assert!(
            manifest.exists(),
            "interop/{name} has no submission.json, so nothing describes what \
             it claims — see interop/README.md"
        );
        out.push((name, load::<Submission>(&manifest)));
    }
    out
}

/// Verify one submission, returning the failures rather than panicking, so a
/// broken submission reports every problem at once instead of the first.
fn check(name: &str, submission: &Submission) -> Vec<String> {
    let dir = interop_dir().join(name);
    let mut failures = Vec::new();

    if submission.format_version != "canton-solvency-interop-v1" {
        failures.push(format!(
            "{name}: unknown submission format {:?}",
            submission.format_version
        ));
        return failures;
    }
    if submission.documents.is_empty() {
        failures.push(format!("{name}: submits no documents"));
    }

    for document in &submission.documents {
        let report: SignedReport = load(&dir.join(&document.report));
        let outcome = match document.kind.as_str() {
            "proof" => {
                let proof: ProofDocument = load(&dir.join(&document.proof));
                verify(&report, &proof, &submission.trusted_key).map_err(|e| e.to_string())
            }
            "proof-v2" => {
                let proof: ProofDocumentV2 = load(&dir.join(&document.proof));
                verify_v2(&report, &proof, &submission.trusted_key).map_err(|e| e.to_string())
            }
            other => Err(format!("unknown document kind {other:?}")),
        };
        if let Err(reason) = outcome {
            failures.push(format!(
                "{name} ({}, {}): {} failed — {reason}",
                submission.organisation, submission.implementation, document.proof
            ));
        }
    }
    failures
}

#[test]
fn every_third_party_submission_verifies_under_this_toolkit() {
    let mut failures = Vec::new();
    for (name, submission) in submissions() {
        failures.extend(check(&name, &submission));
    }
    assert!(
        failures.is_empty(),
        "third-party interop failures:\n  {}",
        failures.join("\n  ")
    );
}

/// The harness has to be able to fail, or a green CI means nothing. A
/// submission carrying a report the declared key did not sign must be caught.
#[test]
fn the_harness_rejects_a_submission_it_should() {
    let (name, submission) = submissions()
        .into_iter()
        .find(|(n, _)| n == "_example")
        .expect("the worked example is checked in");

    let mut wrong_key = submission;
    // A syntactically valid key that signed nothing here.
    wrong_key.trusted_key = "ab".repeat(32);
    let failures = check(&name, &wrong_key);
    assert!(
        !failures.is_empty(),
        "a submission signed by another key must not pass"
    );
}

#[test]
fn every_submission_names_someone_to_contact() {
    for (name, submission) in submissions() {
        assert!(
            !submission.contact.trim().is_empty(),
            "interop/{name} names no contact, so a verification failure has \
             nobody to report to"
        );
    }
}
