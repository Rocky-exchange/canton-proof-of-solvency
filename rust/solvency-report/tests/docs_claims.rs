//! Checks that the counts stated in the documentation match the repository.
//!
//! This exists because both had already drifted. The README advertised sixteen
//! conformance cases when there were twenty-one, and the changelog claimed 291
//! differential vectors when there were 311 — an arithmetic slip in a figure
//! nobody could verify without adding up five arrays by hand.
//!
//! A number in a README is a claim like any other. This project asks readers
//! to check its arithmetic rather than trust it, so the documentation should
//! hold to the same standard.

use std::path::PathBuf;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo().join(relative))
        .unwrap_or_else(|e| panic!("reading {relative}: {e}"))
}

fn json(relative: &str) -> serde_json::Value {
    serde_json::from_str(&read(relative)).expect("valid JSON")
}

/// Every `<n> cases` / `<n> 个用例` in the docs must be the real case count.
#[test]
fn the_documented_conformance_case_count_is_the_real_one() {
    let actual = json("conformance/manifest.json")["cases"]
        .as_array()
        .unwrap()
        .len();

    let mut checked = 0;
    for doc in [
        "README.md",
        "README.zh-CN.md",
        "docs/SECURITY-REVIEW-BRIEF.md",
    ] {
        let text = read(doc);
        for (pattern, label) in [(" cases", "en"), (" 个用例", "zh")] {
            for (i, _) in text.match_indices(pattern) {
                // The digits immediately preceding the phrase.
                let head = &text[..i];
                let digits: String = head
                    .chars()
                    .rev()
                    .take_while(char::is_ascii_digit)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                if digits.is_empty() {
                    continue; // prose like "the cases", not a count
                }
                assert_eq!(
                    digits.parse::<usize>().unwrap(),
                    actual,
                    "{doc} ({label}) claims {digits} conformance cases; there are {actual}"
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 2,
        "found only {checked} case-count claims to check — the phrasing changed \
         and this test stopped looking at anything"
    );
}

/// Same for the differential corpus, which is five arrays nobody adds up.
#[test]
fn the_documented_differential_vector_count_is_the_real_one() {
    let corpus = json("conformance/cross-vectors.json");
    let actual: usize = ["vectors", "reports", "trees", "packs", "anchors"]
        .iter()
        .map(|k| corpus[k].as_array().expect(k).len())
        .sum();

    let text = read("CHANGELOG.md");
    let needle = " cross-implementation differential vectors";
    let at = text
        .find(needle)
        .expect("the changelog should state the corpus size");
    let digits: String = text[..at]
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    assert_eq!(
        digits.parse::<usize>().unwrap(),
        actual,
        "CHANGELOG claims {digits} differential vectors; the corpus holds {actual}"
    );
}

/// The registry is the authority on how many profiles exist; the changelog
/// names them, so the two must not diverge.
#[test]
fn every_profile_the_changelog_names_is_registered() {
    let registry = read("rust/solvency-report/src/profile.rs");
    let changelog = read("CHANGELOG.md");
    for profile in [
        "solvency.liabilities",
        "solvency.group",
        "collateral.repo",
        "fund.nav",
        "settlement.dvp",
        "eligibility.holder",
        "coverage.custody",
    ] {
        assert!(
            registry.contains(&format!("name: \"{profile}\"")),
            "{profile} is named in the changelog but not registered"
        );
        assert!(
            changelog.contains(profile),
            "{profile} is registered but the changelog does not name it"
        );
    }
}
