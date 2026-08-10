//! Turning custody positions into a signed `coverage.custody` report.

use crate::CustodyPosition;
use anyhow::{ensure, Result};
use canton_solvency_report::document::SignedReport;
use canton_solvency_report::produce::{publish_v2, LeafInputV2, ReportMetadata};
use canton_solvency_report::sign::ReportSigner;
use std::collections::BTreeMap;

/// Builds the custody side of a coverage claim.
///
/// `snapshot_offset` must be the offset the liabilities snapshot was taken
/// at, in the report's opaque string form (see `HoldingsQuery::offset_string`). The two halves of a coverage claim describe one instant or they
/// describe nothing, so this refuses to publish against a different one
/// rather than leaving the mismatch for a reader to notice.
pub fn build_custody_report(
    positions: &[CustodyPosition],
    meta: &ReportMetadata,
    snapshot_offset: &str,
    master_salt: &[u8],
    signer: &ReportSigner,
) -> Result<SignedReport> {
    ensure!(
        !positions.is_empty(),
        "no custody positions: an empty book is not a coverage claim"
    );
    ensure!(
        meta.ledger_offset == snapshot_offset,
        "custody read is pinned to offset {} but the liabilities snapshot is at {}; \
         a coverage claim across two instants compares different days",
        meta.ledger_offset,
        snapshot_offset
    );
    ensure!(
        meta.profile == "coverage.custody",
        "a custody report must declare coverage.custody, got {:?}",
        meta.profile
    );

    // Leaves in contract-id order, so the tree is reproducible from the same
    // snapshot regardless of the order the participant returned rows in.
    let mut sorted: Vec<&CustodyPosition> = positions.iter().collect();
    sorted.sort_by(|a, b| a.contract_id.cmp(&b.contract_id));

    let leaves: Vec<LeafInputV2> = sorted
        .iter()
        .map(|position| {
            let mut held = BTreeMap::new();
            held.insert(position.asset.clone(), position.amount);
            LeafInputV2 {
                salt: canton_solvency_merkle::leaf_salt(master_salt, &position.contract_id),
                subject_id: position.contract_id.clone(),
                maps: [("held".to_string(), held)].into_iter().collect(),
            }
        })
        .collect();

    Ok(publish_v2(&leaves, meta, signer)?.signed_report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_solvency_report::coverage::{
        verify_coverage, CoverageStatement, COVERAGE_FORMAT_VERSION,
    };
    use canton_solvency_report::digest::report_digest_hex;
    use canton_solvency_report::produce::{publish, LeafInput};

    const OFFSET: &str = "000000000000000042";

    fn signer() -> ReportSigner {
        ReportSigner::from_seed(&[13u8; 32])
    }

    fn meta(profile: &str, offset: &str) -> ReportMetadata {
        ReportMetadata {
            profile: profile.to_string(),
            publisher: "venue::one".to_string(),
            snapshot_time: "2026-08-09T00:00:00Z".to_string(),
            ledger_offset: offset.to_string(),
            mark_prices: BTreeMap::new(),
            disclosures: Default::default(),
            manifest: None,
        }
    }

    fn positions(entries: &[(&str, &str, u128)]) -> Vec<CustodyPosition> {
        entries
            .iter()
            .map(|(id, asset, amount)| CustodyPosition {
                contract_id: id.to_string(),
                asset: asset.to_string(),
                amount: *amount,
            })
            .collect()
    }

    fn custody(entries: &[(&str, &str, u128)]) -> SignedReport {
        build_custody_report(
            &positions(entries),
            &meta("coverage.custody", OFFSET),
            OFFSET,
            b"master",
            &signer(),
        )
        .unwrap()
    }

    #[test]
    fn positions_become_qualified_held_totals() {
        let report = custody(&[("c1", "USDA", 100), ("c2", "USDA", 50), ("c3", "CBTC", 7)]);
        assert_eq!(report.report.root_sums["held/USDA"], 150);
        assert_eq!(report.report.root_sums["held/CBTC"], 7);
        assert_eq!(report.report.leaf_count, 3);
    }

    /// The participant may return rows in any order; the commitment must not
    /// depend on it, or two honest reads of one snapshot would disagree.
    #[test]
    fn the_root_does_not_depend_on_the_order_rows_came_back_in() {
        let forwards = custody(&[("c1", "USDA", 100), ("c2", "CBTC", 7)]);
        let backwards = custody(&[("c2", "CBTC", 7), ("c1", "USDA", 100)]);
        assert_eq!(forwards.report.root_hash, backwards.report.root_hash);
    }

    /// The check that stops a coverage claim spanning two instants.
    #[test]
    fn a_custody_read_at_another_offset_is_refused() {
        let err = build_custody_report(
            &positions(&[("c1", "USDA", 1)]),
            &meta("coverage.custody", "000000000000000099"),
            OFFSET,
            b"master",
            &signer(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("two instants"), "got {err}");
    }

    #[test]
    fn a_report_declaring_another_profile_is_refused() {
        let err = build_custody_report(
            &positions(&[("c1", "USDA", 1)]),
            &meta("solvency.liabilities", OFFSET),
            OFFSET,
            b"master",
            &signer(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("coverage.custody"), "got {err}");
    }

    #[test]
    fn an_empty_book_is_refused() {
        assert!(build_custody_report(
            &[],
            &meta("coverage.custody", OFFSET),
            OFFSET,
            b"m",
            &signer()
        )
        .is_err());
    }

    /// End to end: what this crate produces is what §11 consumes.
    #[test]
    fn the_report_it_builds_pairs_with_a_liabilities_report() {
        let custody_report = custody(&[("c1", "USDA", 150), ("c2", "CBTC", 10)]);

        let liabilities = publish(
            &[LeafInput {
                salt: [1u8; 32],
                user_id: "u1".to_string(),
                balances: [("USDA".to_string(), 100u128), ("CBTC".to_string(), 5)]
                    .into_iter()
                    .collect(),
            }],
            &meta("solvency.liabilities", OFFSET),
            &signer(),
        )
        .unwrap()
        .signed_report;

        let statement = CoverageStatement {
            format_version: COVERAGE_FORMAT_VERSION.to_string(),
            custody_report_digest: report_digest_hex(&custody_report.report),
            liabilities_report_digest: report_digest_hex(&liabilities.report),
            custody_basis: "read from participant at offset 42".to_string(),
        };

        let key = signer().public_key_hex();
        let outcome =
            verify_coverage(&custody_report, &liabilities, &statement, &key, &key).unwrap();
        assert!(outcome.fully_covered(), "{:?}", outcome.assets);
    }

    /// And each position is individually provable, so a custodian can show one
    /// holder their position without publishing the book.
    #[test]
    fn each_position_can_be_proven_on_its_own() {
        let positions = positions(&[("c1", "USDA", 100), ("c2", "USDA", 50), ("c3", "CBTC", 7)]);
        let mut sorted = positions.clone();
        sorted.sort_by(|a, b| a.contract_id.cmp(&b.contract_id));
        let leaves: Vec<LeafInputV2> = sorted
            .iter()
            .map(|p| LeafInputV2 {
                salt: canton_solvency_merkle::leaf_salt(b"master", &p.contract_id),
                subject_id: p.contract_id.clone(),
                maps: [(
                    "held".to_string(),
                    [(p.asset.clone(), p.amount)].into_iter().collect(),
                )]
                .into_iter()
                .collect(),
            })
            .collect();
        let published = publish_v2(&leaves, &meta("coverage.custody", OFFSET), &signer()).unwrap();
        let key = signer().public_key_hex();
        for proof in &published.proofs {
            assert_eq!(
                canton_solvency_report::verify::verify_v2(&published.signed_report, proof, &key),
                Ok(())
            );
        }
    }
}
