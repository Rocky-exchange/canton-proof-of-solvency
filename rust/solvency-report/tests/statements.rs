//! Cross-implementation agreement over the §14.5 compatibility statements.
//!
//! This is the mechanism the sort bug should have tripped. Rust and
//! TypeScript disagreed about key ordering for months; nothing compared their
//! results, so nothing said so. A checked-in statement per implementation,
//! compared here, turns "we both run the corpus" into an assertion that fails
//! at a *named case* when they diverge.
//!
//! Regenerate with:
//!   cargo run --example emit_statement -- statements/rust.json
//!   cd ts/verifier && npm run emit:statement
//!   python3 -c "..."  (see spec-audit/README.md)

use canton_solvency_report::compat::{corpus_digest, defects, read_cases, Statement};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn statements() -> BTreeMap<String, Statement> {
    let dir = repo().join("statements");
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).expect("statements are checked in") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        out.insert(
            name.clone(),
            serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{name}.json is not a §14.5 statement: {e}")),
        );
    }
    assert!(out.len() >= 3, "expected a statement per implementation");
    out
}

#[test]
fn every_statement_is_over_this_corpus() {
    let cases = read_cases(&repo().join("conformance")).unwrap();
    let expected = corpus_digest(&cases);
    for (name, statement) in statements() {
        assert_eq!(
            statement.corpus_digest, expected,
            "{name} was produced against a different corpus, so its results are \
             not comparable -- regenerate it"
        );
    }
}

#[test]
fn no_statement_claims_a_feature_and_skips_its_cases() {
    let cases = read_cases(&repo().join("conformance")).unwrap();
    for (name, statement) in statements() {
        let found = defects(&statement, &cases);
        assert!(found.is_empty(), "{name}: {found:?}");
    }
}

/// The one that would have caught the UTF-16 sort: two implementations
/// claiming the same feature must agree about every case that needs it.
#[test]
fn implementations_agree_wherever_they_both_claim_support() {
    let all = statements();
    let names: Vec<&String> = all.keys().collect();
    let mut compared = 0;

    for (i, a_name) in names.iter().enumerate() {
        for b_name in &names[i + 1..] {
            let (a, b) = (&all[*a_name], &all[*b_name]);
            let b_by_id: BTreeMap<&str, &str> = b
                .results
                .iter()
                .map(|r| (r.id.as_str(), r.outcome.as_str()))
                .collect();
            for result in &a.results {
                let Some(other) = b_by_id.get(result.id.as_str()) else {
                    panic!("{b_name} reports nothing for {}", result.id);
                };
                // Only where both actually ran it. A skip is a declaration of
                // scope, not a result, so comparing against one proves nothing.
                if result.outcome == "skip" || *other == "skip" {
                    continue;
                }
                assert_eq!(
                    &result.outcome, other,
                    "{a_name} and {b_name} disagree on {}: {} vs {}. One of them \
                     is wrong, or the specification does not determine the answer.",
                    result.id, result.outcome, other
                );
                compared += 1;
            }
        }
    }
    assert!(
        compared >= 20,
        "only {compared} case comparisons across implementations -- too few to \
         mean anything"
    );
}

#[test]
fn every_result_matches_what_the_manifest_expects() {
    let cases = read_cases(&repo().join("conformance")).unwrap();
    let expected: BTreeMap<&str, &str> = cases
        .iter()
        .map(|c| (c.id.as_str(), c.expect.as_str()))
        .collect();
    for (name, statement) in statements() {
        for result in &statement.results {
            if result.outcome == "skip" {
                continue;
            }
            assert_eq!(
                result.outcome,
                expected[result.id.as_str()],
                "{name} fails conformance case {}",
                result.id
            );
        }
    }
}
