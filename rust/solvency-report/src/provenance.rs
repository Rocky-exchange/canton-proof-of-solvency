//! Evidence provenance: which parties, contracts and systems a published
//! figure was computed from (SPEC §17).
//!
//! Institutional data does not sit in one place. A single NAV or coverage
//! ratio can draw on several participants, several synchronizers, a handful of
//! Daml templates, and off-ledger custody, pricing and core banking systems.
//! Node dashboards answer "is the participant healthy", which is a different
//! question from "where did this number come from", and no amount of the first
//! adds up to the second.
//!
//! What makes this more than a diagram is that it is signed, bound to one
//! report by digest, and **checked against the assurance levels** (§16). A
//! figure declared `ledger-derived` whose only declared sources are off-ledger
//! APIs is a contradiction, and the verifier says so. A graph nobody checks
//! is a drawing of the system as someone hoped it worked.
//!
//! What it does not do is establish that the graph is complete. A publisher
//! can sign a partial one — the same honest limitation evidence packs carry in
//! §15.4. What it removes is the ability to leave the question unanswered.

use crate::assurance::AssuranceLevel;
use crate::digest::{lp, report_digest_hex};
use crate::document::SignedReport;
use crate::sign::verify_signature;
use crate::verify::VerificationFailure as F;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PROVENANCE_FORMAT_VERSION: &str = "canton-solvency-provenance-v1";
pub const PROVENANCE_DIGEST_DOMAIN: &[u8] = b"rocky-solvency-provenance-v1";

/// Where a figure can come from.
///
/// The split that carries weight is on-ledger versus off: everything Canton
/// can be asked about, against everything that arrives by API and can only be
/// attested. `Party` and `Template` are on-ledger because they name things a
/// reader with the right visibility can go and look at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Participant,
    Synchronizer,
    Party,
    Template,
    /// Custody statements, price feeds, core banking, risk systems.
    OffLedger,
}

impl SourceKind {
    /// Whether Canton itself can be asked about this source.
    pub fn on_ledger(self) -> bool {
        !matches!(self, Self::OffLedger)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Participant => "participant",
            Self::Synchronizer => "synchronizer",
            Self::Party => "party",
            Self::Template => "template",
            Self::OffLedger => "off-ledger",
        }
    }
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Referenced by derivations. Unique within one graph.
    pub id: String,
    pub kind: SourceKind,
    /// The participant id, synchronizer id, party id, template id, or the name
    /// of the outside system.
    pub name: String,
    /// How the figure is obtained from it. Required for off-ledger sources,
    /// where nothing else in the document says how the number arrived — the
    /// same honest limitation `custody_basis` carries in §11.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derivation {
    /// The §16.2 field path this describes.
    pub field: String,
    /// Source ids, in the order a reader should follow them.
    pub sources: Vec<String>,
    /// What was done with them: "sum of active Holding contracts", "NAV
    /// divided by units outstanding". Signed, and proven by nothing here.
    pub method: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub format_version: String,
    pub report_digest: String,
    pub sources: Vec<Source>,
    pub derivations: Vec<Derivation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProvenance {
    pub provenance: Provenance,
    pub signature: crate::document::SignatureBlock,
}

/// SHA-256 over the graph, length-prefixed, under its own domain (SPEC §17.2).
pub fn provenance_digest(p: &Provenance) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(PROVENANCE_DIGEST_DOMAIN);
    h.update(lp(&p.format_version));
    h.update(lp(&p.report_digest));
    // Counts before contents, for the same reason §15.2 commits the entry
    // count: without it a graph over two sources and one over a single
    // longer-named source could be made to agree.
    h.update((p.sources.len() as u64).to_le_bytes());
    for s in &p.sources {
        h.update(lp(&s.id));
        h.update(lp(s.kind.as_str()));
        h.update(lp(&s.name));
        // A presence byte, not an empty string: a source with no basis and one
        // with an empty basis are different claims.
        match &s.basis {
            None => h.update([0u8]),
            Some(basis) => {
                h.update([1u8]);
                h.update(lp(basis));
            }
        }
    }
    h.update((p.derivations.len() as u64).to_le_bytes());
    for d in &p.derivations {
        h.update(lp(&d.field));
        h.update((d.sources.len() as u64).to_le_bytes());
        for id in &d.sources {
            h.update(lp(id));
        }
        h.update(lp(&d.method));
    }
    h.finalize().into()
}

pub fn provenance_digest_hex(p: &Provenance) -> String {
    hex::encode(provenance_digest(p))
}

fn inconsistent(field: &str, detail: impl Into<String>) -> F {
    F::ProvenanceInconsistent {
        field: field.to_string(),
        detail: detail.into(),
    }
}

/// The graph's own rules (SPEC §17.3), independent of any assurance statement.
pub fn verify_provenance(
    signed_report: &SignedReport,
    signed: &SignedProvenance,
    trusted_public_key_hex: &str,
) -> Result<(), F> {
    let p = &signed.provenance;
    if p.format_version != PROVENANCE_FORMAT_VERSION {
        return Err(F::UnsupportedVersion {
            field: "provenance.format_version",
            found: p.format_version.clone(),
        });
    }
    if p.report_digest != report_digest_hex(&signed_report.report) {
        return Err(F::DigestMismatch);
    }
    if signed.signature.public_key != trusted_public_key_hex {
        return Err(F::UnknownSigner);
    }
    if signed.signature.algorithm != crate::document::SIGNATURE_ALGORITHM {
        return Err(F::UnsupportedVersion {
            field: "signature.algorithm",
            found: signed.signature.algorithm.clone(),
        });
    }
    verify_signature(
        trusted_public_key_hex,
        &provenance_digest(p),
        &signed.signature.value,
    )
    .map_err(|_| F::BadSignature)?;

    let mut ids = BTreeSet::new();
    for source in &p.sources {
        if !ids.insert(source.id.as_str()) {
            return Err(inconsistent(
                "",
                format!("two sources share the id {:?}", source.id),
            ));
        }
        // Without this an off-ledger figure could be named and left
        // unexplained, which is the state the graph exists to end.
        if source.kind == SourceKind::OffLedger
            && !source
                .basis
                .as_deref()
                .is_some_and(|b| !b.trim().is_empty())
        {
            return Err(inconsistent(
                "",
                format!(
                    "off-ledger source {:?} declares no basis; nothing else here \
                     says how that figure arrives",
                    source.id
                ),
            ));
        }
    }

    let mut seen_fields = BTreeSet::new();
    for d in &p.derivations {
        if !crate::assurance::KNOWN_FIELDS.contains(&d.field.as_str()) {
            return Err(inconsistent(&d.field, "not a field this format defines"));
        }
        if !seen_fields.insert(d.field.as_str()) {
            return Err(inconsistent(
                &d.field,
                "declared twice; a field has one derivation",
            ));
        }
        if d.sources.is_empty() {
            return Err(inconsistent(
                &d.field,
                "names no sources, so it says nothing about where the figure came from",
            ));
        }
        for id in &d.sources {
            if !ids.contains(id.as_str()) {
                return Err(inconsistent(
                    &d.field,
                    format!("names source {id:?}, which the graph does not declare"),
                ));
            }
        }
    }
    Ok(())
}

/// The graph against the declared assurance levels (SPEC §17.4).
///
/// This is the check that makes the graph load-bearing rather than
/// decorative, and it is also what makes `ledger-derived` mean what §16 says
/// it means. An anchor establishes that a report was pinned to ledger state at
/// an offset; on its own it says nothing about whether the *figure* was
/// derived from ledger state. The graph is where that is claimed, so the level
/// requires both.
pub fn check_against_assurance(
    p: &Provenance,
    levels: &BTreeMap<String, AssuranceLevel>,
) -> Result<(), F> {
    let by_id: BTreeMap<&str, &Source> = p.sources.iter().map(|s| (s.id.as_str(), s)).collect();
    for (field, level) in levels {
        if *level != AssuranceLevel::LedgerDerived {
            continue;
        }
        let Some(derivation) = p.derivations.iter().find(|d| &d.field == field) else {
            return Err(inconsistent(
                field,
                "declared ledger-derived, and the provenance graph does not say \
                 where it came from",
            ));
        };
        let on_ledger = derivation
            .sources
            .iter()
            .filter_map(|id| by_id.get(id.as_str()))
            .any(|s| s.kind.on_ledger());
        if !on_ledger {
            return Err(inconsistent(
                field,
                "declared ledger-derived, but every source the graph names for \
                 it is off-ledger",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden;
    use crate::sign::ReportSigner;

    fn source(id: &str, kind: SourceKind, basis: Option<&str>) -> Source {
        Source {
            id: id.to_string(),
            kind,
            name: format!("{id}-name"),
            basis: basis.map(str::to_string),
        }
    }

    fn graph(
        report: &SignedReport,
        sources: Vec<Source>,
        derivations: Vec<Derivation>,
    ) -> Provenance {
        Provenance {
            format_version: PROVENANCE_FORMAT_VERSION.to_string(),
            report_digest: report_digest_hex(&report.report),
            sources,
            derivations,
        }
    }

    fn sign(p: Provenance) -> SignedProvenance {
        let signer = golden::signer();
        SignedProvenance {
            signature: crate::document::SignatureBlock {
                algorithm: crate::document::SIGNATURE_ALGORITHM.to_string(),
                public_key: signer.public_key_hex(),
                value: signer.sign_digest(&provenance_digest(&p)),
            },
            provenance: p,
        }
    }

    fn derivation(field: &str, sources: &[&str]) -> Derivation {
        Derivation {
            field: field.to_string(),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            method: "sum of active Holding contracts".to_string(),
        }
    }

    fn well_formed(report: &SignedReport) -> Provenance {
        graph(
            report,
            vec![
                source("p1", SourceKind::Participant, None),
                source("tpl", SourceKind::Template, None),
                source("px", SourceKind::OffLedger, Some("vendor close price")),
            ],
            vec![
                derivation("root_sums", &["p1", "tpl"]),
                derivation("mark_prices", &["px"]),
            ],
        )
    }

    fn key() -> String {
        golden::signer().public_key_hex()
    }

    #[test]
    fn a_well_formed_graph_verifies() {
        let (report, _) = golden::fixture();
        verify_provenance(&report, &sign(well_formed(&report)), &key()).expect("well formed");
    }

    #[test]
    fn a_derivation_naming_an_undeclared_source_is_refused() {
        let (report, _) = golden::fixture();
        let mut p = well_formed(&report);
        p.derivations[0].sources.push("ghost".to_string());
        let failure = verify_provenance(&report, &sign(p), &key()).expect_err("dangling edge");
        assert!(
            matches!(&failure, F::ProvenanceInconsistent { field, detail }
                if field == "root_sums" && detail.contains("ghost")),
            "got {failure}"
        );
    }

    #[test]
    fn two_sources_sharing_an_id_are_refused() {
        let (report, _) = golden::fixture();
        let mut p = well_formed(&report);
        p.sources.push(source("p1", SourceKind::Party, None));
        assert!(verify_provenance(&report, &sign(p), &key()).is_err());
    }

    /// An off-ledger figure with no stated basis is exactly the gap the graph
    /// exists to close: a number from somewhere, and nothing saying where.
    #[test]
    fn an_off_ledger_source_without_a_basis_is_refused() {
        let (report, _) = golden::fixture();
        let mut p = well_formed(&report);
        p.sources[2].basis = None;
        let failure = verify_provenance(&report, &sign(p), &key()).expect_err("no basis");
        assert!(format!("{failure}").contains("basis"), "got {failure}");

        let mut blank = well_formed(&report);
        blank.sources[2].basis = Some("   ".to_string());
        assert!(
            verify_provenance(&report, &sign(blank), &key()).is_err(),
            "whitespace is not a basis"
        );
    }

    #[test]
    fn a_derivation_with_no_sources_is_refused() {
        let (report, _) = golden::fixture();
        let mut p = well_formed(&report);
        p.derivations[0].sources.clear();
        assert!(verify_provenance(&report, &sign(p), &key()).is_err());
    }

    /// Two derivations for one field leave the document ambiguous: the
    /// consistency check reads the first, and a renderer showing the second
    /// would give two readers of the same signed graph different answers.
    #[test]
    fn a_field_with_two_derivations_is_refused() {
        let (report, _) = golden::fixture();
        let mut p = well_formed(&report);
        p.derivations.push(Derivation {
            field: "root_sums".to_string(),
            sources: vec!["px".to_string()],
            method: "actually we used the vendor feed".to_string(),
        });
        let failure = verify_provenance(&report, &sign(p), &key()).expect_err("ambiguous");
        assert!(
            matches!(&failure, F::ProvenanceInconsistent { field, detail }
                if field == "root_sums" && detail.contains("twice")),
            "got {failure}"
        );
    }

    #[test]
    fn a_field_the_format_does_not_define_is_refused() {
        let (report, _) = golden::fixture();
        let mut p = well_formed(&report);
        p.derivations[0].field = "solvency_vibes".to_string();
        assert!(verify_provenance(&report, &sign(p), &key()).is_err());
    }

    #[test]
    fn a_graph_bound_to_another_report_is_refused() {
        let (report, _) = golden::fixture();
        let (other, _) = golden::withheld_fixture();
        let p = well_formed(&other);
        assert!(matches!(
            verify_provenance(&report, &sign(p), &key()),
            Err(F::DigestMismatch)
        ));
    }

    #[test]
    fn a_graph_signed_by_a_stranger_is_refused() {
        let (report, _) = golden::fixture();
        let stranger = ReportSigner::from_seed(&[77u8; 32]);
        let p = well_formed(&report);
        let signed = SignedProvenance {
            signature: crate::document::SignatureBlock {
                algorithm: crate::document::SIGNATURE_ALGORITHM.to_string(),
                public_key: stranger.public_key_hex(),
                value: stranger.sign_digest(&provenance_digest(&p)),
            },
            provenance: p,
        };
        assert!(matches!(
            verify_provenance(&report, &signed, &key()),
            Err(F::UnknownSigner)
        ));
    }

    #[test]
    fn an_edited_graph_fails_its_signature() {
        let (report, _) = golden::fixture();
        let mut signed = sign(well_formed(&report));
        signed.provenance.derivations[0].method = "we asked around".to_string();
        assert!(matches!(
            verify_provenance(&report, &signed, &key()),
            Err(F::BadSignature)
        ));
    }

    // --- §17.4: the graph against the assurance levels ---

    #[test]
    fn ledger_derived_is_satisfied_by_an_on_ledger_source() {
        let (report, _) = golden::fixture();
        let levels = [("root_sums".to_string(), AssuranceLevel::LedgerDerived)]
            .into_iter()
            .collect();
        check_against_assurance(&well_formed(&report), &levels).expect("p1 is a participant");
    }

    /// The contradiction the whole section exists to catch: a figure declared
    /// to come from ledger state, whose graph says it came from a vendor API.
    #[test]
    fn ledger_derived_over_only_off_ledger_sources_is_a_contradiction() {
        let (report, _) = golden::fixture();
        let levels = [("mark_prices".to_string(), AssuranceLevel::LedgerDerived)]
            .into_iter()
            .collect();
        let failure = check_against_assurance(&well_formed(&report), &levels)
            .expect_err("mark_prices comes from a price vendor");
        assert!(
            matches!(&failure, F::ProvenanceInconsistent { field, .. } if field == "mark_prices"),
            "got {failure}"
        );
    }

    #[test]
    fn ledger_derived_with_no_derivation_at_all_is_refused() {
        let (report, _) = golden::fixture();
        let levels = [(
            "disclosures.bad_debt".to_string(),
            AssuranceLevel::LedgerDerived,
        )]
        .into_iter()
        .collect();
        assert!(check_against_assurance(&well_formed(&report), &levels).is_err());
    }

    /// Levels other than ledger-derived make no claim about sources, so the
    /// graph must not second-guess them.
    #[test]
    fn other_levels_are_not_constrained_by_the_graph() {
        let (report, _) = golden::fixture();
        for level in [
            AssuranceLevel::ClaimedOnly,
            AssuranceLevel::ThirdPartyAttested,
            AssuranceLevel::CryptographicallyVerified,
        ] {
            let levels = [("disclosures.bad_debt".to_string(), level)]
                .into_iter()
                .collect();
            check_against_assurance(&well_formed(&report), &levels)
                .unwrap_or_else(|e| panic!("{level} should not need a derivation: {e}"));
        }
    }
}
