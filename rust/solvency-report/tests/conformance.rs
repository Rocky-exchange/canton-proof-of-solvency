//! Runs the checked-in conformance corpus (SPEC §14.3).
//!
//! The corpus is the artefact a second implementation runs to claim
//! compatibility. Running it here too is what keeps it honest: a case the
//! reference implementation cannot itself satisfy is not a conformance test,
//! it is a bug report.

use std::collections::{BTreeMap, BTreeSet};
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
        "entity_root_mismatch" => "describe different roots",
        "root_sums_mismatch" => "disagrees with the committed leaves",
        "digest_mismatch" => "belongs to a different report",
        "bad_signature" => "signature does not verify",
        "unknown_signer" => "trusted key",
        "entity_sums_mismatch" => "disagree",
        "manifest_inconsistent" => "manifest disagrees",
        "manifest_presence" => "manifest",
        "profile" => "profile ",
        "not_genesis" => "names a predecessor",
        "unsupported_version" => "unsupported",
        "broken" => "does not name the one before it",
        "publisher_changed" => "publisher",
        "went_backwards" => "backwards",
        "pack_missing" => "which is not present",
        "pack_altered" => "does not match the digest",
        "pack_unlisted" => "does not name it",
        "unsafe_name" => "not a plain file name",
        "shortfall" => "shortfall",
        "over_claimed" => "but the evidence supplied supports",
        "unknown_field" => "has no way to substantiate",
        "provenance_inconsistent" => "provenance graph",
        "temporal_mismatch" => "apart, beyond",
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

/// The checked-in corpus must be what its generator currently produces.
///
/// Without this, editing `corpus_gen` without regenerating leaves every
/// implementation testing cases the generator no longer describes, and a
/// reader of the generator believing in cases that are not on disk. The same
/// drift guard the offline verifier pages already have.
#[test]
fn the_checked_in_corpus_matches_its_generator() {
    let fresh = tempfile::tempdir().expect("a temporary directory");
    canton_solvency_report::corpus_gen::emit(fresh.path()).expect("generation succeeds");

    let checked_in = corpus_dir();
    let listing = |root: &Path| -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let rel = path
                        .strip_prefix(root)
                        .expect("under root")
                        .to_string_lossy()
                        .into_owned();
                    // The differential vectors sit beside the corpus but come
                    // from a different generator, and have their own drift
                    // guard in tests/cross_vectors.rs.
                    if rel == "cross-vectors.json" {
                        continue;
                    }
                    out.insert(rel, std::fs::read(&path).expect("readable"));
                }
            }
        }
        out
    };

    let generated = listing(fresh.path());
    let on_disk = listing(&checked_in);

    // Compare names first: a missing or extra case is the clearer message.
    let generated_names: Vec<&String> = generated.keys().collect();
    let on_disk_names: Vec<&String> = on_disk.keys().collect();
    assert_eq!(
        generated_names, on_disk_names,
        "the corpus on disk has different files from the generator — \
         regenerate with `cargo run --example emit_conformance -- ./conformance`"
    );

    for (name, bytes) in &generated {
        assert_eq!(
            on_disk.get(name),
            Some(bytes),
            "{name} differs from what the generator produces — regenerate with \
             `cargo run --example emit_conformance -- ./conformance`"
        );
    }
}

/// Every registered profile must have at least one case.
///
/// The registry is where a profile becomes real, and §14 calls the profiles
/// the point of the format. Four of the seven had no case at all until now —
/// fund.nav, settlement.dvp and eligibility.holder were declared, implemented
/// and never exercised, which is the same shape as a check nobody runs.
#[test]
fn every_registered_profile_has_a_conformance_case() {
    let dir = corpus_dir();
    let mut covered = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("corpus is checked in") {
        let path = entry.expect("entry").path();
        if !path.is_dir() {
            continue;
        }
        for name in ["report.json", "group-report.json", "custody.json"] {
            let file = path.join(name);
            if !file.exists() {
                continue;
            }
            let text = std::fs::read_to_string(&file).expect("readable");
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(profile) = doc["report"]["profile"].as_str() {
                    covered.insert(profile.to_string());
                }
            }
        }
    }

    let registered: Vec<&str> = canton_solvency_report::profile::REGISTRY
        .iter()
        .map(|rules| rules.name)
        .collect();
    let missing: Vec<&&str> = registered
        .iter()
        .filter(|name| !covered.contains(**name))
        .collect();
    assert!(
        missing.is_empty(),
        "registered profiles with no conformance case: {missing:?}"
    );
}
