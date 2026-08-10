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

/// One subject's committed position under a v2 leaf (SPEC §3.1).
#[derive(Clone, Debug)]
pub struct LeafInputV2 {
    pub salt: [u8; 32],
    pub subject_id: String,
    pub maps: BTreeMap<String, BTreeMap<String, u128>>,
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
    /// Supplying one publishes a v2 report (SPEC §8.5); omitting it publishes
    /// v1, whose bytes are unchanged by v2's existence.
    pub manifest: Option<crate::manifest::Manifest>,
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
        format_version: if meta.manifest.is_some() {
            crate::document::REPORT_FORMAT_VERSION_V2.to_string()
        } else {
            REPORT_FORMAT_VERSION.to_string()
        },
        profile: meta.profile.clone(),
        publisher: meta.publisher.clone(),
        snapshot_time: meta.snapshot_time.clone(),
        ledger_offset: meta.ledger_offset.clone(),
        root_hash: hex::encode(tree.root().hash),
        leaf_count: leaves.len() as u64,
        root_sums: tree.root().sums.clone(),
        mark_prices: meta.mark_prices.clone(),
        disclosures: meta.disclosures.clone(),
        manifest: meta.manifest.clone(),
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

/// A signed report over v2 leaves, and the per-subject proofs.
#[derive(Clone, Debug)]
pub struct PublicationV2 {
    pub signed_report: SignedReport,
    pub proofs: Vec<crate::document::ProofDocumentV2>,
}

pub fn publish_v2(
    leaves: &[LeafInputV2],
    meta: &ReportMetadata,
    signer: &ReportSigner,
) -> Result<PublicationV2> {
    use crate::document::{LeafPreimageV2, ProofDocumentV2, PROOF_FORMAT_VERSION_V2};
    anyhow::ensure!(!leaves.is_empty(), "cannot publish a report with no leaves");

    let nodes: Vec<Node> = leaves
        .iter()
        .map(|l| canton_solvency_merkle::leaf_node_v2(&l.salt, &l.subject_id, &l.maps))
        .collect::<Result<_>>()?;
    let tree = SumTree::build(nodes)?;

    let report = Report {
        format_version: if meta.manifest.is_some() {
            crate::document::REPORT_FORMAT_VERSION_V2.to_string()
        } else {
            REPORT_FORMAT_VERSION.to_string()
        },
        profile: meta.profile.clone(),
        publisher: meta.publisher.clone(),
        snapshot_time: meta.snapshot_time.clone(),
        ledger_offset: meta.ledger_offset.clone(),
        root_hash: hex::encode(tree.root().hash),
        leaf_count: leaves.len() as u64,
        root_sums: tree.root().sums.clone(),
        mark_prices: meta.mark_prices.clone(),
        disclosures: meta.disclosures.clone(),
        manifest: meta.manifest.clone(),
    };

    let digest = report_digest(&report);
    let digest_hex = hex::encode(digest);

    let proofs = leaves
        .iter()
        .enumerate()
        .map(|(i, leaf)| {
            let proof = tree.prove(i)?;
            Ok(ProofDocumentV2 {
                format_version: PROOF_FORMAT_VERSION_V2.to_string(),
                report_digest: digest_hex.clone(),
                leaf: LeafPreimageV2 {
                    salt: hex::encode(leaf.salt),
                    subject_id: leaf.subject_id.clone(),
                    maps: leaf.maps.clone(),
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

    Ok(PublicationV2 {
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

/// One commitment, packaged for several audiences (SPEC §14.4).
///
/// Every packaging commits to the same leaves, so every root hash and every
/// total is identical; only the manifest — what each audience is told was
/// published, committed or withheld — differs. Two packagings therefore have
/// different digests and different signatures, which is correct: they are
/// different statements about the same commitment.
pub fn publish_for_audiences(
    leaves: &[LeafInput],
    meta: &ReportMetadata,
    manifests: &[crate::manifest::Manifest],
    signer: &ReportSigner,
) -> Result<Vec<Publication>> {
    anyhow::ensure!(
        !manifests.is_empty(),
        "publishing for no audience is not a packaging"
    );
    let mut audiences: Vec<&str> = manifests.iter().map(|m| m.audience.as_str()).collect();
    audiences.sort_unstable();
    let distinct = {
        let mut seen = audiences.clone();
        seen.dedup();
        seen.len()
    };
    anyhow::ensure!(
        distinct == manifests.len(),
        "two packagings name the same audience, so one would silently replace the other"
    );

    manifests
        .iter()
        .map(|manifest| {
            publish(
                leaves,
                &ReportMetadata {
                    manifest: Some(manifest.clone()),
                    ..meta.clone()
                },
                signer,
            )
        })
        .collect()
}

/// Checks two reports are packagings of the same commitment: identical root
/// and totals, differing only in what each audience was told.
///
/// Without this a venue could hand two audiences genuinely different books
/// and each would verify in isolation.
pub fn same_commitment(a: &Report, b: &Report) -> bool {
    a.root_hash == b.root_hash && a.root_sums == b.root_sums && a.leaf_count == b.leaf_count
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
            manifest: None,
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

    /// Scale exercises the promotion path at many levels: 10_000 is not a
    /// power of two, so odd nodes are promoted repeatedly on the way up.
    /// No timing assertion — that belongs in `examples/bench_scale.rs`, since
    /// a wall-clock threshold in CI is a flake waiting to happen.
    #[test]
    fn every_proof_verifies_at_ten_thousand_leaves() {
        assert_scale(10_000);
    }

    #[test]
    #[ignore = "slow in a debug build; run with --release --ignored"]
    fn every_proof_verifies_at_one_hundred_thousand_leaves() {
        assert_scale(100_000);
    }

    fn assert_scale(n: usize) {
        let master = b"scale-master";
        let leaves: Vec<LeafInput> = (0..n)
            .map(|i| {
                let user_id = format!("user-{i:07}");
                LeafInput {
                    salt: leaf_salt(master, &user_id),
                    balances: [("USDA".to_string(), i as u128 + 1)].into_iter().collect(),
                    user_id,
                }
            })
            .collect();
        let signer = ReportSigner::from_seed(&[7u8; 32]);
        let published = publish(&leaves, &metadata(), &signer).unwrap();
        let trusted = signer.public_key_hex();

        assert_eq!(published.signed_report.report.leaf_count, n as u64);
        // The totals must survive aggregation over every level.
        let expected: u128 = (1..=n as u128).sum();
        assert_eq!(published.signed_report.report.root_sums["USDA"], expected);

        // Sample across the tree: path lengths differ, and a prefix is not
        // representative of the promotion cases.
        let stride = (n / 200).max(1);
        for proof in published.proofs.iter().step_by(stride) {
            assert_eq!(
                crate::verify::verify(&published.signed_report, proof, &trusted),
                Ok(()),
                "proof for {} failed",
                proof.leaf.user_id
            );
        }
    }

    /// One commitment, several audiences (SPEC §14.4).
    mod audiences {
        use super::*;
        use crate::manifest::{Disclosure, Manifest};

        fn manifest(audience: &str, mark_prices: Disclosure) -> Manifest {
            Manifest {
                audience: audience.to_string(),
                fields: [
                    ("root_sums".to_string(), Disclosure::Published),
                    ("mark_prices".to_string(), mark_prices),
                    ("customer_balances".to_string(), Disclosure::Committed),
                ]
                .into_iter()
                .collect(),
            }
        }

        fn packagings() -> Vec<Publication> {
            publish_for_audiences(
                &leaves(5),
                &metadata(),
                &[
                    manifest("public", Disclosure::Withheld),
                    manifest("auditor", Disclosure::Withheld),
                ],
                &ReportSigner::from_seed(&[7u8; 32]),
            )
            .unwrap()
        }

        /// The property that makes packaging safe: every audience is looking
        /// at the same commitment, whatever each was told.
        #[test]
        fn every_packaging_commits_to_the_same_leaves() {
            let packs = packagings();
            assert_eq!(packs.len(), 2);
            assert!(same_commitment(
                &packs[0].signed_report.report,
                &packs[1].signed_report.report
            ));
            assert_eq!(
                packs[0].signed_report.report.root_hash,
                packs[1].signed_report.report.root_hash
            );
        }

        /// And they are different statements, so they must not share a digest.
        #[test]
        fn packagings_for_different_audiences_have_different_digests() {
            let packs = packagings();
            assert_ne!(
                crate::digest::report_digest(&packs[0].signed_report.report),
                crate::digest::report_digest(&packs[1].signed_report.report)
            );
            assert_ne!(
                packs[0].signed_report.signature.value,
                packs[1].signed_report.signature.value
            );
        }

        #[test]
        fn every_packaging_verifies_on_its_own_terms() {
            let key = ReportSigner::from_seed(&[7u8; 32]).public_key_hex();
            for pack in packagings() {
                for proof in &pack.proofs {
                    assert_eq!(
                        crate::verify::verify(&pack.signed_report, proof, &key),
                        Ok(())
                    );
                }
            }
        }

        /// Two audiences handed genuinely different books would each verify in
        /// isolation, which is exactly what same_commitment exists to catch.
        #[test]
        fn two_different_books_are_not_packagings_of_one_commitment() {
            let signer = ReportSigner::from_seed(&[7u8; 32]);
            let a = publish(&leaves(5), &metadata(), &signer).unwrap();
            let b = publish(&leaves(4), &metadata(), &signer).unwrap();
            assert!(!same_commitment(
                &a.signed_report.report,
                &b.signed_report.report
            ));
        }

        #[test]
        fn two_packagings_naming_the_same_audience_are_refused() {
            let err = publish_for_audiences(
                &leaves(3),
                &metadata(),
                &[
                    manifest("public", Disclosure::Withheld),
                    manifest("public", Disclosure::Published),
                ],
                &ReportSigner::from_seed(&[7u8; 32]),
            )
            .unwrap_err();
            assert!(err.to_string().contains("same audience"), "got {err}");
        }

        #[test]
        fn publishing_for_no_audience_is_an_error() {
            assert!(publish_for_audiences(
                &leaves(3),
                &metadata(),
                &[],
                &ReportSigner::from_seed(&[7u8; 32])
            )
            .is_err());
        }
    }

    #[test]
    fn publishing_no_leaves_is_an_error() {
        assert!(publish(&[], &metadata(), &ReportSigner::from_seed(&[7u8; 32])).is_err());
    }
}
