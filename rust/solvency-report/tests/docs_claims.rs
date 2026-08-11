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

/// Every relative link in the documentation must resolve.
///
/// A link into the repository is a claim that a file is there, and this sweep
/// moved or added enough of them — `scripts/`, `statements/`, `interop/`,
/// `spec-audit/`, `UPGRADING.md` — that one going stale was a matter of time.
/// One already had: SPEC §8.5 pointed at `fixtures/proof-v2.golden.json`,
/// which has never existed. I then used that name in a test of my own and
/// spent a run debugging an ENOENT, which is what a wrong reference in a
/// specification costs a reader.
#[test]
fn every_relative_link_in_the_documentation_resolves() {
    fn markdown(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        let skip = ["node_modules", "target", "Xushi", ".git"];
        for entry in std::fs::read_dir(dir).expect("readable") {
            let path = entry.expect("entry").path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if skip.contains(&name.as_str()) {
                continue;
            }
            if path.is_dir() {
                markdown(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
                out.push(path);
            }
        }
    }

    let mut docs = Vec::new();
    markdown(&repo(), &mut docs);
    assert!(
        docs.len() >= 10,
        "expected the documentation set, found {}",
        docs.len()
    );

    let mut broken = Vec::new();
    let mut checked = 0usize;
    for doc in &docs {
        let text = std::fs::read_to_string(doc).expect("readable");
        // [label](target), ignoring anchors and absolute URLs.
        let mut rest = text.as_str();
        while let Some(open) = rest.find("](") {
            let after = &rest[open + 2..];
            let Some(close) = after.find(')') else { break };
            let target = &after[..close];
            rest = &after[close..];
            if target.starts_with("http") || target.starts_with("mailto:") || target.is_empty() {
                continue;
            }
            let path = target.split('#').next().unwrap();
            if path.is_empty() {
                continue;
            }
            checked += 1;
            if !doc.parent().unwrap().join(path).exists() {
                broken.push(format!("{}: {path}", doc.display()));
            }
        }
    }
    assert!(
        checked >= 100,
        "only {checked} links checked; the parser stopped seeing them"
    );
    assert!(
        broken.is_empty(),
        "broken documentation links:\n  {}",
        broken.join("\n  ")
    );
}

/// The Daml SDK version in CI must match the one the package declares.
///
/// They are pinned in two files, and a mismatch does not fail loudly: CI
/// installs one SDK and `daml build` asks for another, which surfaces as a
/// download error rather than as "these two numbers disagree".
#[test]
fn the_daml_sdk_version_is_pinned_consistently() {
    let workflow = read(".github/workflows/ci.yml");
    let project = read("daml/solvency-anchor/daml.yaml");

    let from_workflow = workflow
        .split("version=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("ci.yml pins a Daml SDK version");
    let from_project = project
        .lines()
        .find_map(|line| line.strip_prefix("sdk-version:"))
        .map(str::trim)
        .expect("daml.yaml declares an sdk-version");

    assert_eq!(
        from_workflow, from_project,
        "ci.yml installs Daml {from_workflow} and daml.yaml asks for {from_project}"
    );
}
