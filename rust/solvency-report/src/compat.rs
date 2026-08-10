//! Compatibility statements (SPEC §14.5).
//!
//! The corpus establishes what an implementation does. A statement is how it
//! says so, in a form another party can check rather than take on trust.
//!
//! The rule that matters is the second one in [`defects`]: a case outside the
//! claimed feature set must be reported as `skip`, never as a pass. A verifier
//! that rejects a document because it does not implement that document's
//! version has tested nothing, and at this level of detail a rejection for the
//! wrong reason is indistinguishable from a correct one. That is not
//! hypothetical -- the Python audit implementation in `spec-audit/` did exactly
//! this, "passing" a manifest case without ever reading a manifest.

use crate::digest::lp;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const COMPAT_FORMAT_VERSION: &str = "canton-solvency-compat-v1";
pub const CORPUS_DIGEST_DOMAIN: &[u8] = b"rocky-solvency-corpus-v1";

/// Everything this implementation verifies.
pub const SUPPORTED: &[&str] = &[
    "anchor-v1",
    "coverage-v1",
    "group-v1",
    "leaf-v2",
    "manifest",
    "pack-v1",
    "proof-v1",
    "proof-v2",
    "report-v1",
    "report-v2",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseResult {
    pub id: String,
    pub expected: String,
    /// `accept`, `reject`, or `skip`.
    pub outcome: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub format_version: String,
    pub implementation: String,
    pub version: String,
    pub supports: Vec<String>,
    pub corpus_digest: String,
    pub results: Vec<CaseResult>,
}

/// One case as the manifest describes it.
pub struct CaseSpec {
    pub id: String,
    pub expect: String,
    pub requires: Vec<String>,
}

/// §14.5. Two statements over different corpora are not comparable, and
/// without this binding that would not be visible.
pub fn corpus_digest(cases: &[CaseSpec]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(CORPUS_DIGEST_DOMAIN);
    h.update((cases.len() as u64).to_le_bytes());
    for case in cases {
        h.update(lp(&case.id));
        h.update(lp(&case.expect));
        h.update((case.requires.len() as u64).to_le_bytes());
        for name in &case.requires {
            h.update(lp(name));
        }
    }
    hex::encode(h.finalize())
}

pub fn read_cases(corpus: &Path) -> anyhow::Result<Vec<CaseSpec>> {
    let text = std::fs::read_to_string(corpus.join("manifest.json"))?;
    let manifest: serde_json::Value = serde_json::from_str(&text)?;
    Ok(manifest["cases"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("the manifest has no cases"))?
        .iter()
        .map(|c| CaseSpec {
            id: c["id"].as_str().unwrap_or_default().to_string(),
            expect: c["expect"].as_str().unwrap_or_default().to_string(),
            requires: c["requires"]
                .as_array()
                .map(|r| {
                    r.iter()
                        .map(|v| v.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect())
}

/// The three §14.5 rules, checked rather than assumed — the point of the
/// format is that a *reader* can hold a statement to account.
pub fn defects(statement: &Statement, cases: &[CaseSpec]) -> Vec<String> {
    let supports: std::collections::BTreeSet<&str> =
        statement.supports.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    for case in cases {
        let Some(result) = statement.results.iter().find(|r| r.id == case.id) else {
            out.push(format!("{}: no result reported", case.id));
            continue;
        };
        let claimed = case.requires.iter().all(|r| supports.contains(r.as_str()));
        let skipped = result.outcome == "skip";
        if claimed && skipped {
            out.push(format!(
                "{}: claims {} but skipped the case",
                case.id,
                case.requires.join(", ")
            ));
        }
        if !claimed && !skipped {
            let missing: Vec<&str> = case
                .requires
                .iter()
                .map(String::as_str)
                .filter(|r| !supports.contains(r))
                .collect();
            out.push(format!(
                "{}: reported {} but does not claim {}",
                case.id,
                result.outcome,
                missing.join(", ")
            ));
        }
    }
    out
}

/// Run one corpus case. `Ok(())` on accept, `Err(reason)` on reject.
///
/// Shared by `tests/conformance.rs` and [`build_statement`], so a statement
/// can never report an outcome the conformance test would not have produced.
pub fn run_case(dir: &Path, kind: &str, key: &str) -> Result<(), String> {
    fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| e.to_string())
    }
    match kind {
        "proof" => {
            let report: crate::document::SignedReport = load(&dir.join("report.json"))?;
            let proof: crate::document::ProofDocument = load(&dir.join("proof.json"))?;
            crate::verify::verify(&report, &proof, key).map_err(|e| e.to_string())
        }
        "proof-v2" => {
            let report: crate::document::SignedReport = load(&dir.join("report.json"))?;
            let proof: crate::document::ProofDocumentV2 = load(&dir.join("proof.json"))?;
            crate::verify::verify_v2(&report, &proof, key).map_err(|e| e.to_string())
        }
        "chain" => {
            let group: crate::document::SignedReport = load(&dir.join("group-report.json"))?;
            let membership: crate::group::GroupMembershipDocument =
                load(&dir.join("membership.json"))?;
            let entity: crate::document::SignedReport = load(&dir.join("entity-report.json"))?;
            let proof: crate::document::ProofDocument = load(&dir.join("proof.json"))?;
            crate::group::verify_chain(&group, &membership, &entity, &proof, key, key)
                .map_err(|e| e.to_string())
        }
        "membership" => {
            let report: crate::document::SignedReport = load(&dir.join("group-report.json"))?;
            let membership: crate::group::GroupMembershipDocument =
                load(&dir.join("membership.json"))?;
            crate::group::verify_membership(&report, &membership, key).map_err(|e| e.to_string())
        }
        "coverage" => {
            let custody: crate::document::SignedReport = load(&dir.join("custody.json"))?;
            let liabilities: crate::document::SignedReport = load(&dir.join("liabilities.json"))?;
            let statement: crate::coverage::CoverageStatement = load(&dir.join("statement.json"))?;
            let outcome =
                crate::coverage::verify_coverage(&custody, &liabilities, &statement, key, key)
                    .map_err(|e| e.to_string())?;
            if outcome.fully_covered() {
                Ok(())
            } else {
                Err("shortfall".to_string())
            }
        }
        "anchors" => {
            let history: Vec<crate::anchor::Anchor> = load(&dir.join("history.json"))?;
            crate::anchor::verify_chain(&history).map_err(|e| e.to_string())
        }
        "pack" => {
            let signed: crate::pack::SignedPack = load(&dir.join("pack.json"))?;
            let mut members = std::collections::BTreeMap::new();
            for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?.path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if !path.is_file() || name == "pack.json" {
                    continue;
                }
                members.insert(name, std::fs::read(&path).map_err(|e| e.to_string())?);
            }
            crate::pack::verify_pack(&signed, key, &members).map_err(|e| e.to_string())
        }
        other => Err(format!("unknown case kind {other}")),
    }
}

/// Run the corpus and describe the outcome.
pub fn build_statement(
    implementation: &str,
    supported: &[&str],
    corpus: &Path,
) -> anyhow::Result<Statement> {
    let cases = read_cases(corpus)?;
    let text = std::fs::read_to_string(corpus.join("manifest.json"))?;
    let manifest: serde_json::Value = serde_json::from_str(&text)?;
    let key = manifest["trusted_key"].as_str().unwrap_or_default();
    let kinds: std::collections::BTreeMap<String, String> = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["id"].as_str().unwrap_or_default().to_string(),
                c["kind"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();

    let supports: std::collections::BTreeSet<&str> = supported.iter().copied().collect();
    let mut results = Vec::new();
    for case in &cases {
        let outcome = if !case.requires.iter().all(|r| supports.contains(r.as_str())) {
            "skip".to_string()
        } else {
            let kind = kinds.get(&case.id).map(String::as_str).unwrap_or("");
            match run_case(&corpus.join(&case.id), kind, key) {
                Ok(()) => "accept".to_string(),
                Err(_) => "reject".to_string(),
            }
        };
        results.push(CaseResult {
            id: case.id.clone(),
            expected: case.expect.clone(),
            outcome,
        });
    }

    Ok(Statement {
        format_version: COMPAT_FORMAT_VERSION.to_string(),
        implementation: implementation.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        supports: supported.iter().map(|s| s.to_string()).collect(),
        corpus_digest: corpus_digest(&cases),
        results,
    })
}
