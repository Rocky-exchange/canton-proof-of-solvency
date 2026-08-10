//! Coverage: pairing custody assets against liabilities (SPEC §11).
//!
//! A custody report says what is held. A liabilities report says what is
//! owed. Neither, alone, is a solvency claim. A coverage statement binds the
//! two by digest and asserts that the assets cover the liabilities, per asset.
//!
//! Binding by digest is what makes the claim non-transferable: without it, a
//! venue could present today's custody totals beside last quarter's smaller
//! liabilities and the arithmetic would check out.

use crate::digest::report_digest_hex;
use crate::document::SignedReport;
use crate::verify::VerificationFailure;
use serde::{Deserialize, Serialize};

pub const COVERAGE_FORMAT_VERSION: &str = "canton-solvency-coverage-v1";

/// Names the two reports being compared. The comparison itself is derived
/// from them rather than restated here: a figure restated in a third document
/// is a figure that can disagree with its sources.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageStatement {
    pub format_version: String,
    pub custody_report_digest: String,
    pub liabilities_report_digest: String,
    /// Free text recording how custody was established — which parties, which
    /// contract types. Signed, but not proven by anything here.
    pub custody_basis: String,
}

/// Per-asset outcome of a coverage comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetCoverage {
    pub asset: String,
    pub held: u128,
    pub owed: u128,
}

impl AssetCoverage {
    pub fn covered(&self) -> bool {
        self.held >= self.owed
    }

    /// Shortfall, or zero when covered.
    pub fn shortfall(&self) -> u128 {
        self.owed.saturating_sub(self.held)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageOutcome {
    pub assets: Vec<AssetCoverage>,
}

impl CoverageOutcome {
    pub fn fully_covered(&self) -> bool {
        self.assets.iter().all(|a| a.covered())
    }

    pub fn shortfalls(&self) -> Vec<&AssetCoverage> {
        self.assets.iter().filter(|a| !a.covered()).collect()
    }
}

/// Compares a custody report against a liabilities report.
///
/// Both reports must already verify in their own right; this checks that the
/// statement names *these* two reports and that the assets cover the
/// liabilities asset by asset.
pub fn verify_coverage(
    custody: &SignedReport,
    liabilities: &SignedReport,
    statement: &CoverageStatement,
    custody_trusted_key: &str,
    liabilities_trusted_key: &str,
) -> Result<CoverageOutcome, VerificationFailure> {
    use VerificationFailure as F;

    crate::verify::expect_version(
        "coverage.format_version",
        &statement.format_version,
        COVERAGE_FORMAT_VERSION,
    )?;

    // Each side must be the kind of report it is being used as. Without this
    // a liabilities report could stand in for custody and "cover" itself.
    expect_profile(custody, "coverage.custody")?;
    expect_profile(liabilities, "solvency.liabilities")?;

    // The statement must name these two reports, or the comparison is between
    // documents nobody agreed to compare.
    if report_digest_hex(&custody.report) != statement.custody_report_digest {
        return Err(F::DigestMismatch);
    }
    if report_digest_hex(&liabilities.report) != statement.liabilities_report_digest {
        return Err(F::DigestMismatch);
    }

    check_signature(custody, custody_trusted_key)?;
    check_signature(liabilities, liabilities_trusted_key)?;

    // Driven by what is owed: an asset held but not owed is not a coverage
    // question, while an asset owed and not held is the worst case and must
    // not read as "nothing required".
    let mut assets: Vec<AssetCoverage> = Vec::new();
    for (asset, owed) in &liabilities.report.root_sums {
        let held = custody
            .report
            .root_sums
            .get(&canton_solvency_merkle::qualified("held", asset))
            .copied()
            .unwrap_or(0);
        assets.push(AssetCoverage {
            asset: asset.clone(),
            held,
            owed: *owed,
        });
    }
    Ok(CoverageOutcome { assets })
}

fn expect_profile(signed: &SignedReport, wanted: &str) -> Result<(), VerificationFailure> {
    if signed.report.profile == wanted {
        Ok(())
    } else {
        Err(VerificationFailure::Profile {
            detail: format!(
                "expected a {wanted} report here, got {:?}",
                signed.report.profile
            ),
        })
    }
}

fn check_signature(signed: &SignedReport, trusted_key: &str) -> Result<(), VerificationFailure> {
    use VerificationFailure as F;
    if signed.signature.public_key != trusted_key {
        return Err(F::UnknownSigner);
    }
    let digest = crate::digest::report_digest(&signed.report);
    crate::sign::verify_signature(trusted_key, &digest, &signed.signature.value).map_err(
        |e| match e {
            crate::sign::SignatureError::BadSignature => F::BadSignature,
            other => F::Malformed(other.to_string()),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::produce::{publish, publish_v2, LeafInputV2, ReportMetadata};
    use crate::sign::ReportSigner;
    use canton_solvency_merkle::leaf_salt;
    use std::collections::BTreeMap;

    fn signer() -> ReportSigner {
        ReportSigner::from_seed(&[11u8; 32])
    }

    fn key() -> String {
        signer().public_key_hex()
    }

    fn meta(profile: &str) -> ReportMetadata {
        ReportMetadata {
            profile: profile.to_string(),
            publisher: "venue::one".to_string(),
            snapshot_time: "2026-08-09T00:00:00Z".to_string(),
            ledger_offset: "000000000000000007".to_string(),
            mark_prices: BTreeMap::new(),
            disclosures: Default::default(),
            manifest: None,
        }
    }

    fn custody_report(positions: &[(&str, u128)]) -> SignedReport {
        let leaves: Vec<LeafInputV2> = positions
            .iter()
            .enumerate()
            .map(|(i, (asset, amount))| LeafInputV2 {
                salt: [i as u8; 32],
                subject_id: format!("position-{i}"),
                maps: [(
                    "held".to_string(),
                    [(asset.to_string(), *amount)].into_iter().collect(),
                )]
                .into_iter()
                .collect(),
            })
            .collect();
        publish_v2(&leaves, &meta("coverage.custody"), &signer())
            .unwrap()
            .signed_report
    }

    fn liabilities_report(balances: &[(&str, u128)]) -> SignedReport {
        let leaves: Vec<crate::produce::LeafInput> = balances
            .iter()
            .enumerate()
            .map(|(i, (asset, amount))| {
                let user_id = format!("user-{i}");
                crate::produce::LeafInput {
                    salt: leaf_salt(b"m", &user_id),
                    balances: [(asset.to_string(), *amount)].into_iter().collect(),
                    user_id,
                }
            })
            .collect();
        publish(&leaves, &meta("solvency.liabilities"), &signer())
            .unwrap()
            .signed_report
    }

    fn statement_for(custody: &SignedReport, liabilities: &SignedReport) -> CoverageStatement {
        CoverageStatement {
            format_version: COVERAGE_FORMAT_VERSION.to_string(),
            custody_report_digest: report_digest_hex(&custody.report),
            liabilities_report_digest: report_digest_hex(&liabilities.report),
            custody_basis: "omnibus custody party venue::custody".to_string(),
        }
    }

    fn check(
        custody: &SignedReport,
        liabilities: &SignedReport,
        statement: &CoverageStatement,
    ) -> Result<CoverageOutcome, VerificationFailure> {
        verify_coverage(custody, liabilities, statement, &key(), &key())
    }

    #[test]
    fn assets_covering_liabilities_verify() {
        let custody = custody_report(&[("USDA", 150), ("CBTC", 5)]);
        let liabilities = liabilities_report(&[("USDA", 100), ("CBTC", 5)]);
        let outcome = check(
            &custody,
            &liabilities,
            &statement_for(&custody, &liabilities),
        )
        .unwrap();
        assert!(outcome.fully_covered());
        assert_eq!(outcome.assets.len(), 2);
    }

    #[test]
    fn a_shortfall_is_reported_per_asset_with_its_size() {
        let custody = custody_report(&[("USDA", 90)]);
        let liabilities = liabilities_report(&[("USDA", 100)]);
        let outcome = check(
            &custody,
            &liabilities,
            &statement_for(&custody, &liabilities),
        )
        .unwrap();
        assert!(!outcome.fully_covered());
        let short = outcome.shortfalls();
        assert_eq!(short.len(), 1);
        assert_eq!(short[0].asset, "USDA");
        assert_eq!(short[0].shortfall(), 10);
    }

    /// A surplus in one asset must not excuse a shortfall in another.
    #[test]
    fn coverage_is_per_asset_not_aggregate() {
        let custody = custody_report(&[("USDA", 1_000), ("CBTC", 1)]);
        let liabilities = liabilities_report(&[("USDA", 1), ("CBTC", 500)]);
        let outcome = check(
            &custody,
            &liabilities,
            &statement_for(&custody, &liabilities),
        )
        .unwrap();
        assert!(!outcome.fully_covered());
        assert_eq!(outcome.shortfalls()[0].asset, "CBTC");
    }

    /// A liability in an asset held nowhere is the worst case, and an absent
    /// custody entry must not read as "nothing required".
    #[test]
    fn a_liability_with_no_custody_at_all_is_a_shortfall() {
        let custody = custody_report(&[("USDA", 100)]);
        let liabilities = liabilities_report(&[("CETH", 1)]);
        let outcome = check(
            &custody,
            &liabilities,
            &statement_for(&custody, &liabilities),
        )
        .unwrap();
        assert!(!outcome.fully_covered());
        assert_eq!(outcome.shortfalls()[0].asset, "CETH");
    }

    /// The binding that stops today's assets being shown against last
    /// quarter's smaller liabilities.
    #[test]
    fn a_statement_naming_a_different_report_is_rejected() {
        let custody = custody_report(&[("USDA", 150)]);
        let liabilities = liabilities_report(&[("USDA", 100)]);
        let other = liabilities_report(&[("USDA", 1)]);

        let mut statement = statement_for(&custody, &other);
        statement.custody_report_digest = report_digest_hex(&custody.report);
        assert!(
            check(&custody, &liabilities, &statement).is_err(),
            "a statement about another report was accepted"
        );
    }

    #[test]
    fn the_custody_side_must_declare_the_custody_profile() {
        let custody = liabilities_report(&[("USDA", 150)]);
        let liabilities = liabilities_report(&[("USDA", 100)]);
        assert!(check(
            &custody,
            &liabilities,
            &statement_for(&custody, &liabilities)
        )
        .is_err());
    }

    #[test]
    fn the_liabilities_side_must_declare_a_liabilities_profile() {
        let custody = custody_report(&[("USDA", 150)]);
        let other_custody = custody_report(&[("USDA", 100)]);
        assert!(check(
            &custody,
            &other_custody,
            &statement_for(&custody, &other_custody)
        )
        .is_err());
    }

    #[test]
    fn an_unsigned_or_wrongly_signed_report_is_rejected() {
        let custody = custody_report(&[("USDA", 150)]);
        let liabilities = liabilities_report(&[("USDA", 100)]);
        let statement = statement_for(&custody, &liabilities);
        assert!(
            verify_coverage(&custody, &liabilities, &statement, &"ab".repeat(32), &key()).is_err()
        );
    }

    #[test]
    fn coverage_statements_round_trip_through_json() {
        let custody = custody_report(&[("USDA", 1)]);
        let liabilities = liabilities_report(&[("USDA", 1)]);
        let statement = statement_for(&custody, &liabilities);
        let back: CoverageStatement =
            serde_json::from_str(&serde_json::to_string(&statement).unwrap()).unwrap();
        assert_eq!(back, statement);
    }
}
