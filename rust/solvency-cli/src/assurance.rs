//! The `assurance` verb: declared evidence levels against established ones
//! (SPEC §16).
//!
//! The interesting input is the one that is absent. Every piece of evidence
//! here is optional, and withholding the proof is not an error — it lowers
//! what can be established, which is exactly the distinction the verb exists
//! to draw. A run that reports `cryptographically-verified` without having
//! been given a proof would be the bug.

use crate::args::Command;
use anyhow::{Context, Result};
use canton_solvency_report::assurance::{
    establish, verify_assurance, AssuranceLevel, AssuranceStatement, AttestorRole, Evidence,
    SignedAttestation, TrustedKeys,
};
use canton_solvency_report::document::{ProofDocument, SignedReport};
use std::collections::BTreeMap;

fn load<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub struct AssuranceOutcome {
    /// What the publisher declared and the verifier accepted, per field.
    pub accepted: BTreeMap<String, AssuranceLevel>,
    /// Everything the evidence supports, whether declared or not — so a reader
    /// can see that a figure is only claimed even when nothing was declared
    /// about it.
    pub established: BTreeMap<String, Vec<AssuranceLevel>>,
    pub failure: Option<String>,
}

impl AssuranceOutcome {
    pub fn ok(&self) -> bool {
        self.failure.is_none()
    }
}

pub fn run_assurance(command: &Command) -> Result<AssuranceOutcome> {
    let Command::Assurance {
        report,
        assurance,
        proof,
        anchor,
        attestations,
        provenance,
        attestors,
        trusted_key,
        ..
    } = command
    else {
        anyhow::bail!("run_assurance called with a non-assurance command");
    };

    let signed: SignedReport = load(report)?;
    let statement: AssuranceStatement = load(assurance)?;
    let proof_doc: Option<ProofDocument> = proof.as_deref().map(load).transpose()?;
    let anchor_doc: Option<canton_solvency_report::anchor::Anchor> =
        anchor.as_deref().map(load).transpose()?;
    let attestation_docs: Vec<SignedAttestation> = match attestations.as_deref() {
        Some(path) => load(path)?,
        None => Vec::new(),
    };

    // §16.4: an anchor shows the report was pinned at an offset; the graph is
    // what says the figure came from ledger state. ledger-derived needs both.
    let graph: Option<canton_solvency_report::provenance::SignedProvenance> =
        provenance.as_deref().map(load).transpose()?;

    let mut roles = BTreeMap::new();
    for (hex, role) in attestors {
        roles.insert(
            hex.clone(),
            match role.as_str() {
                "issuer" => AttestorRole::Issuer,
                _ => AttestorRole::ThirdParty,
            },
        );
    }
    let trusted = TrustedKeys {
        publisher: trusted_key.clone(),
        attestors: roles,
    };
    let evidence = Evidence {
        proof: proof_doc.as_ref(),
        anchor: anchor_doc.as_ref(),
        attestations: &attestation_docs,
        provenance: graph.as_ref().map(|g| &g.provenance),
    };

    let established = establish(&signed, &evidence, &trusted)
        .into_iter()
        .map(|(field, levels)| (field, levels.into_iter().collect::<Vec<_>>()))
        .collect();

    match verify_assurance(&signed, &statement, &evidence, &trusted) {
        Ok(accepted) => Ok(AssuranceOutcome {
            accepted,
            established,
            failure: None,
        }),
        Err(e) => Ok(AssuranceOutcome {
            accepted: BTreeMap::new(),
            established,
            failure: Some(e.to_string()),
        }),
    }
}

/// The strongest level established for a field, for one-line summaries.
///
/// §16.1 is explicit that the levels are not a total order; `strength` orders
/// only what can be ordered without lying, and this is a display path.
pub fn strongest(levels: &[AssuranceLevel]) -> Option<AssuranceLevel> {
    levels.iter().copied().max_by_key(|l| l.strength())
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_solvency_report::golden;
    use std::path::PathBuf;

    /// Per-test directories. Tests run in parallel, and sharing one path meant
    /// one test reading a file another was still writing — a flake that would
    /// have surfaced in CI rather than here.
    fn scratch(case: &str, name: &str, value: &serde_json::Value) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("canton-assurance-cli-tests")
            .join(case);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
        path
    }

    fn statement_for(report: &SignedReport, field: &str, level: &str) -> serde_json::Value {
        serde_json::json!({
            "format_version": "canton-solvency-assurance-v1",
            "report_digest": canton_solvency_report::digest::report_digest_hex(&report.report),
            "levels": { field: level },
        })
    }

    fn command(report: PathBuf, assurance: PathBuf, proof: Option<PathBuf>) -> Command {
        Command::Assurance {
            report,
            assurance,
            proof,
            anchor: None,
            attestations: None,
            provenance: None,
            attestors: BTreeMap::new(),
            trusted_key: golden::signer().public_key_hex(),
            json: false,
        }
    }

    #[test]
    fn accepts_a_declaration_the_supplied_evidence_supports() {
        const CASE: &str = "accepts_a_declaration_the_supplied_evidence_supports";
        let (report, proof) = golden::fixture();
        let r = scratch(CASE, "report.json", &serde_json::to_value(&report).unwrap());
        let p = scratch(CASE, "proof.json", &serde_json::to_value(&proof).unwrap());
        let a = scratch(
            CASE,
            "assurance-ok.json",
            &statement_for(&report, "root_sums", "cryptographically-verified"),
        );
        let outcome = run_assurance(&command(r, a, Some(p))).unwrap();
        assert!(outcome.ok(), "{:?}", outcome.failure);
    }

    /// Same documents, proof withheld. The verb must not report a
    /// recomputation it never performed.
    #[test]
    fn refuses_the_same_declaration_when_the_proof_is_withheld() {
        const CASE: &str = "refuses_the_same_declaration_when_the_proof_is_withheld";
        let (report, _proof) = golden::fixture();
        let r = scratch(CASE, "report.json", &serde_json::to_value(&report).unwrap());
        let a = scratch(
            CASE,
            "assurance-ok.json",
            &statement_for(&report, "root_sums", "cryptographically-verified"),
        );
        let outcome = run_assurance(&command(r, a, None)).unwrap();
        assert!(!outcome.ok());
        let failure = outcome.failure.unwrap();
        assert!(
            failure.contains("root_sums") && failure.contains("claimed-only"),
            "the failure should name the field and what was actually supported: {failure}"
        );
    }

    /// The established map is reported whether or not the check passed: a
    /// reader who has just been told a declaration failed needs to see what
    /// the evidence did support.
    #[test]
    fn reports_what_was_established_even_on_failure() {
        const CASE: &str = "reports_what_was_established_even_on_failure";
        let (report, _proof) = golden::fixture();
        let r = scratch(CASE, "report.json", &serde_json::to_value(&report).unwrap());
        let a = scratch(
            CASE,
            "assurance-ok.json",
            &statement_for(&report, "root_sums", "cryptographically-verified"),
        );
        let outcome = run_assurance(&command(r, a, None)).unwrap();
        assert_eq!(
            strongest(&outcome.established["root_sums"]),
            Some(AssuranceLevel::ClaimedOnly)
        );
    }
}
