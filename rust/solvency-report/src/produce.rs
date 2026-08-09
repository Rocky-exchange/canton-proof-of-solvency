//! Producer side: turn committed leaves into a signed report plus one proof
//! document per user.

use crate::digest::report_digest;
use crate::document::{
    Disclosures, LeafPreimage, ProofDocument, ProofStepDocument, Report, SignatureBlock,
    SignedReport, PROOF_FORMAT_VERSION, REPORT_FORMAT_VERSION, SIGNATURE_ALGORITHM,
};
use crate::sign::ReportSigner;
use anyhow::Result;
use canton_solvency_merkle::{leaf_node, Node, SumTree};
use std::collections::BTreeMap;

/// One user's committed position, in the producer's stable ordering.
#[derive(Clone, Debug)]
pub struct LeafInput {
    pub salt: [u8; 32],
    pub user_id: String,
    pub balances: BTreeMap<String, u128>,
}

/// Everything about a report that the tree does not determine.
#[derive(Clone, Debug)]
pub struct ReportMetadata {
    pub profile: String,
    pub publisher: String,
    pub snapshot_time: String,
    pub ledger_offset: String,
    pub mark_prices: BTreeMap<String, u128>,
    pub disclosures: Disclosures,
}

/// A signed report and the per-user proofs that reduce to it.
#[derive(Clone, Debug)]
pub struct Publication {
    pub signed_report: SignedReport,
    /// One per input leaf, in the same order.
    pub proofs: Vec<ProofDocument>,
}

pub fn publish(
    leaves: &[LeafInput],
    meta: &ReportMetadata,
    signer: &ReportSigner,
) -> Result<Publication> {
    anyhow::ensure!(!leaves.is_empty(), "cannot publish a report with no leaves");

    let nodes: Vec<Node> = leaves
        .iter()
        .map(|l| {
            let balances: Vec<(String, u128)> = l.balances.clone().into_iter().collect();
            leaf_node(&l.salt, &l.user_id, &balances)
        })
        .collect::<Result<_>>()?;
    let tree = SumTree::build(nodes)?;

    let report = Report {
        format_version: REPORT_FORMAT_VERSION.to_string(),
        profile: meta.profile.clone(),
        publisher: meta.publisher.clone(),
        snapshot_time: meta.snapshot_time.clone(),
        ledger_offset: meta.ledger_offset.clone(),
        root_hash: hex::encode(tree.root().hash),
        leaf_count: leaves.len() as u64,
        root_sums: tree.root().sums.clone(),
        mark_prices: meta.mark_prices.clone(),
        disclosures: meta.disclosures.clone(),
    };

    let digest = report_digest(&report);
    let digest_hex = hex::encode(digest);

    let proofs = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| {
            let proof = tree.prove(i)?;
            Ok(ProofDocument {
                format_version: PROOF_FORMAT_VERSION.to_string(),
                report_digest: digest_hex.clone(),
                leaf: LeafPreimage {
                    salt: hex::encode(leaf.salt),
                    user_id: leaf.user_id.clone(),
                    balances: leaf.balances.clone(),
                },
                steps: proof
                    .steps
                    .iter()
                    .map(|step| ProofStepDocument {
                        sibling_hash: hex::encode(step.sibling.hash),
                        sibling_sums: step.sibling.sums.clone(),
                        sibling_on_left: step.sibling_on_left,
                    })
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Publication {
        signed_report: SignedReport {
            signature: SignatureBlock {
                algorithm: SIGNATURE_ALGORITHM.to_string(),
                public_key: signer.public_key_hex(),
                value: signer.sign_digest(&digest),
            },
            report,
        },
        proofs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_solvency_merkle::leaf_salt;

    pub(crate) fn leaves(n: usize) -> Vec<LeafInput> {
        (1..=n)
            .map(|i| {
                let user_id = format!("user-{i}");
                LeafInput {
                    salt: leaf_salt(b"master", &user_id),
                    balances: [("USDA".to_string(), i as u128 * 1_000_000_000_000_000_000)]
                        .into_iter()
                        .collect(),
                    user_id,
                }
            })
            .collect()
    }

    pub(crate) fn metadata() -> ReportMetadata {
        ReportMetadata {
            profile: "solvency.liabilities".to_string(),
            publisher: "rocky::122099".to_string(),
            snapshot_time: "2026-08-09T00:00:00Z".to_string(),
            ledger_offset: "000000000000012345".to_string(),
            mark_prices: BTreeMap::new(),
            disclosures: Disclosures::default(),
        }
    }

    fn publication(n: usize) -> Publication {
        publish(
            &leaves(n),
            &metadata(),
            &ReportSigner::from_seed(&[7u8; 32]),
        )
        .unwrap()
    }

    #[test]
    fn report_root_matches_the_tree_built_from_the_same_leaves() {
        let pubn = publication(5);
        let nodes: Vec<Node> = leaves(5)
            .iter()
            .map(|l| {
                let balances: Vec<(String, u128)> = l.balances.clone().into_iter().collect();
                leaf_node(&l.salt, &l.user_id, &balances).unwrap()
            })
            .collect();
        let tree = SumTree::build(nodes).unwrap();

        assert_eq!(
            pubn.signed_report.report.root_hash,
            hex::encode(tree.root().hash)
        );
        assert_eq!(pubn.signed_report.report.root_sums, tree.root().sums);
        assert_eq!(pubn.signed_report.report.leaf_count, 5);
    }

    #[test]
    fn one_proof_is_produced_per_leaf_bound_to_the_report_digest() {
        let pubn = publication(5);
        let expected = hex::encode(report_digest(&pubn.signed_report.report));
        assert_eq!(pubn.proofs.len(), 5);
        for (i, proof) in pubn.proofs.iter().enumerate() {
            assert_eq!(proof.report_digest, expected, "proof {i}");
            assert_eq!(proof.leaf.user_id, format!("user-{}", i + 1));
        }
    }

    #[test]
    fn the_signature_is_over_the_report_digest() {
        let pubn = publication(3);
        let signer = ReportSigner::from_seed(&[7u8; 32]);
        assert_eq!(
            crate::sign::verify_signature(
                &signer.public_key_hex(),
                &report_digest(&pubn.signed_report.report),
                &pubn.signed_report.signature.value,
            ),
            Ok(())
        );
    }

    #[test]
    fn publishing_no_leaves_is_an_error() {
        assert!(publish(&[], &metadata(), &ReportSigner::from_seed(&[7u8; 32])).is_err());
    }
}
