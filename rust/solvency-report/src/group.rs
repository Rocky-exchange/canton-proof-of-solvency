//! Group-level commitments over entity roots (SPEC §13).
//!
//! A group tree is an ordinary Merkle sum tree whose leaves are entities
//! rather than customers, so a subsidiary can prove its position to its own
//! regulator without exposing its siblings, while the group root still sums
//! to the consolidated total.

use crate::digest::{lp, lpmap, report_digest};
use crate::document::{ProofStepDocument, Report, SignatureBlock, SignedReport};
use crate::produce::ReportMetadata;
use crate::sign::ReportSigner;
use crate::verify::VerificationFailure;
use anyhow::Result;
use canton_solvency_merkle::{Node, SumTree};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const ENTITY_DOMAIN: &[u8] = b"rocky-solvency-entity-v1";

/// One subsidiary's published position, as it enters the group tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityInput {
    pub entity_id: String,
    pub root_hash: [u8; 32],
    pub root_sums: BTreeMap<String, u128>,
}

/// `H(domain ‖ lp(entity_id) ‖ root_hash ‖ lpmap(sums))`.
///
/// The identity is bound into the hash deliberately: without it a group could
/// swap one subsidiary's subtree for another of equal total undetected.
pub fn entity_leaf_node(entity: &EntityInput) -> Node {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ENTITY_DOMAIN);
    h.update(lp(&entity.entity_id));
    h.update(entity.root_hash);
    h.update(lpmap(&entity.root_sums));
    Node {
        hash: h.finalize().into(),
        sums: entity.root_sums.clone(),
    }
}

pub const GROUP_MEMBERSHIP_FORMAT_VERSION: &str = "canton-solvency-group-membership-v1";
pub const GROUP_PROFILE: &str = "solvency.group";

/// The entity fields as published, mirroring [`EntityInput`] on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityRecord {
    pub entity_id: String,
    pub root_hash: String,
    #[serde(with = "crate::document::amount_map")]
    pub root_sums: BTreeMap<String, u128>,
}

/// Proves one entity is committed in a group's consolidated total.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMembershipDocument {
    pub format_version: String,
    pub group_report_digest: String,
    pub entity: EntityRecord,
    pub steps: Vec<ProofStepDocument>,
}

#[derive(Clone, Debug)]
pub struct GroupPublication {
    pub signed_report: SignedReport,
    /// One per input entity, in the same order.
    pub memberships: Vec<GroupMembershipDocument>,
}

/// Builds a group report over entity roots. `meta.profile` is ignored and
/// replaced with [`GROUP_PROFILE`]: a group report states a different thing
/// from a customer-level one and must not be mistaken for it.
pub fn publish_group(
    entities: &[EntityInput],
    meta: &ReportMetadata,
    signer: &ReportSigner,
) -> Result<GroupPublication> {
    anyhow::ensure!(
        !entities.is_empty(),
        "cannot publish a group with no entities"
    );

    let leaves: Vec<Node> = entities.iter().map(entity_leaf_node).collect();
    let tree = SumTree::build(leaves)?;

    let report = Report {
        format_version: if meta.manifest.is_some() {
            crate::document::REPORT_FORMAT_VERSION_V2.to_string()
        } else {
            crate::document::REPORT_FORMAT_VERSION.to_string()
        },
        profile: GROUP_PROFILE.to_string(),
        publisher: meta.publisher.clone(),
        snapshot_time: meta.snapshot_time.clone(),
        ledger_offset: meta.ledger_offset.clone(),
        root_hash: hex::encode(tree.root().hash),
        leaf_count: entities.len() as u64,
        root_sums: tree.root().sums.clone(),
        mark_prices: meta.mark_prices.clone(),
        disclosures: meta.disclosures.clone(),
        manifest: meta.manifest.clone(),
    };

    let digest = report_digest(&report);
    let digest_hex = hex::encode(digest);

    let memberships = entities
        .iter()
        .enumerate()
        .map(|(i, entity)| {
            let proof = tree.prove(i)?;
            Ok(GroupMembershipDocument {
                format_version: GROUP_MEMBERSHIP_FORMAT_VERSION.to_string(),
                group_report_digest: digest_hex.clone(),
                entity: EntityRecord {
                    entity_id: entity.entity_id.clone(),
                    root_hash: hex::encode(entity.root_hash),
                    root_sums: entity.root_sums.clone(),
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

    Ok(GroupPublication {
        signed_report: SignedReport {
            signature: SignatureBlock {
                algorithm: crate::document::SIGNATURE_ALGORITHM.to_string(),
                public_key: signer.public_key_hex(),
                value: signer.sign_digest(&digest),
            },
            report,
        },
        memberships,
    })
}

/// Checks an entity is committed in the group's published consolidated total.
pub fn verify_membership(
    signed: &SignedReport,
    membership: &GroupMembershipDocument,
    trusted_public_key_hex: &str,
) -> Result<(), VerificationFailure> {
    crate::verify::expect_version(
        "membership.format_version",
        &membership.format_version,
        GROUP_MEMBERSHIP_FORMAT_VERSION,
    )?;

    let root_hash = crate::verify::hash32(&membership.entity.root_hash, "entity root hash")?;
    let leaf = entity_leaf_node(&EntityInput {
        entity_id: membership.entity.entity_id.clone(),
        root_hash,
        root_sums: membership.entity.root_sums.clone(),
    });

    crate::verify::verify_against_report(
        signed,
        leaf,
        &membership.steps,
        &membership.group_report_digest,
        trusted_public_key_hex,
    )
}

/// Verifies a customer all the way to a group's consolidated total: their
/// proof against the entity's report, the entity's membership against the
/// group, and — critically — that those two documents describe the same book.
///
/// Without the last check the two halves would be independently valid and
/// jointly meaningless: a group could present entity A's membership beside
/// entity B's report.
pub fn verify_chain(
    group_signed: &SignedReport,
    membership: &GroupMembershipDocument,
    entity_signed: &SignedReport,
    proof: &crate::document::ProofDocument,
    group_trusted_key: &str,
    entity_trusted_key: &str,
) -> Result<(), VerificationFailure> {
    crate::verify::verify(entity_signed, proof, entity_trusted_key)?;
    verify_membership(group_signed, membership, group_trusted_key)?;

    let entity_report = &entity_signed.report;
    if membership.entity.root_hash != entity_report.root_hash {
        return Err(VerificationFailure::EntityRootMismatch);
    }
    for asset in membership
        .entity
        .root_sums
        .keys()
        .chain(entity_report.root_sums.keys())
    {
        let claimed = membership.entity.root_sums.get(asset).copied().unwrap_or(0);
        let published = entity_report.root_sums.get(asset).copied().unwrap_or(0);
        if claimed != published {
            return Err(VerificationFailure::EntitySumsMismatch {
                asset: asset.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sums(entries: &[(&str, u128)]) -> BTreeMap<String, u128> {
        entries.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn entity(id: &str, root: u8, amounts: &[(&str, u128)]) -> EntityInput {
        EntityInput {
            entity_id: id.to_string(),
            root_hash: [root; 32],
            root_sums: sums(amounts),
        }
    }

    #[test]
    fn an_entity_leaf_carries_the_entitys_totals_as_its_sums() {
        let e = entity("sub-a", 1, &[("USDA", 100), ("CBTC", 2)]);
        assert_eq!(
            entity_leaf_node(&e).sums,
            sums(&[("USDA", 100), ("CBTC", 2)])
        );
    }

    #[test]
    fn the_leaf_hash_is_deterministic() {
        let e = entity("sub-a", 1, &[("USDA", 100)]);
        assert_eq!(entity_leaf_node(&e).hash, entity_leaf_node(&e).hash);
    }

    /// The property that justifies binding the identity: two subsidiaries
    /// with identical books must not produce interchangeable leaves.
    #[test]
    fn two_entities_with_equal_books_have_different_leaves() {
        let a = entity("sub-a", 1, &[("USDA", 100)]);
        let b = entity("sub-b", 1, &[("USDA", 100)]);
        assert_ne!(entity_leaf_node(&a).hash, entity_leaf_node(&b).hash);
    }

    #[test]
    fn the_leaf_hash_changes_with_the_root_or_the_totals() {
        let base = entity_leaf_node(&entity("sub-a", 1, &[("USDA", 100)])).hash;
        assert_ne!(
            base,
            entity_leaf_node(&entity("sub-a", 2, &[("USDA", 100)])).hash
        );
        assert_ne!(
            base,
            entity_leaf_node(&entity("sub-a", 1, &[("USDA", 101)])).hash
        );
    }

    #[test]
    fn an_entity_id_cannot_impersonate_a_field_boundary() {
        let a = entity("sub-a", 1, &[("USDA", 100)]);
        let b = entity("sub", 1, &[("USDA", 100)]);
        assert_ne!(entity_leaf_node(&a).hash, entity_leaf_node(&b).hash);
    }

    const SEED: [u8; 32] = [5u8; 32];

    fn signer() -> ReportSigner {
        ReportSigner::from_seed(&SEED)
    }

    fn metadata() -> ReportMetadata {
        ReportMetadata {
            profile: "ignored".to_string(),
            publisher: "group::holdings".to_string(),
            snapshot_time: "2026-08-09T00:00:00Z".to_string(),
            ledger_offset: "000000000000000900".to_string(),
            mark_prices: BTreeMap::new(),
            disclosures: Default::default(),
            manifest: None,
        }
    }

    /// Entities with ragged asset sets, so consolidation is not trivially
    /// a single-asset addition.
    fn entities() -> Vec<EntityInput> {
        vec![
            entity("sub-a", 1, &[("USDA", 100), ("CBTC", 2)]),
            entity("sub-b", 2, &[("USDA", 50)]),
            entity("sub-c", 3, &[("CETH", 7)]),
        ]
    }

    fn group() -> GroupPublication {
        publish_group(&entities(), &metadata(), &signer()).unwrap()
    }

    fn check(g: &GroupPublication, i: usize) -> Result<(), VerificationFailure> {
        verify_membership(
            &g.signed_report,
            &g.memberships[i],
            &signer().public_key_hex(),
        )
    }

    #[test]
    fn the_group_root_consolidates_every_entitys_totals() {
        let report = &group().signed_report.report;
        assert_eq!(
            report.root_sums,
            sums(&[("USDA", 150), ("CBTC", 2), ("CETH", 7)])
        );
        assert_eq!(report.leaf_count, 3);
    }

    #[test]
    fn a_group_report_declares_the_group_profile_whatever_the_caller_passed() {
        assert_eq!(group().signed_report.report.profile, GROUP_PROFILE);
    }

    #[test]
    fn every_entity_membership_verifies_against_the_group() {
        let g = group();
        assert_eq!(g.memberships.len(), 3);
        for i in 0..3 {
            assert_eq!(check(&g, i), Ok(()), "entity {i}");
        }
    }

    #[test]
    fn a_single_entity_group_verifies_with_an_empty_path() {
        let g = publish_group(&entities()[..1], &metadata(), &signer()).unwrap();
        assert!(g.memberships[0].steps.is_empty());
        assert_eq!(check(&g, 0), Ok(()));
    }

    #[test]
    fn odd_entity_counts_verify_at_every_index() {
        for n in [2usize, 3, 5] {
            let list: Vec<EntityInput> = (0..n)
                .map(|i| {
                    entity(
                        &format!("sub-{i}"),
                        i as u8,
                        &[("USDA", 10 * i as u128 + 1)],
                    )
                })
                .collect();
            let g = publish_group(&list, &metadata(), &signer()).unwrap();
            for i in 0..n {
                assert_eq!(check(&g, i), Ok(()), "n={n} i={i}");
            }
        }
    }

    /// Binding the identity is what makes this fail; with a bare root node as
    /// the leaf, two entities of equal total would be interchangeable.
    #[test]
    fn relabelling_an_entity_breaks_its_membership() {
        let mut g = group();
        g.memberships[0].entity.entity_id = "sub-b".to_string();
        assert_eq!(check(&g, 0), Err(VerificationFailure::RootHashMismatch));
    }

    #[test]
    fn overstating_an_entitys_totals_breaks_its_membership() {
        let mut g = group();
        g.memberships[0].entity.root_sums.insert("USDA".into(), 999);
        assert_eq!(check(&g, 0), Err(VerificationFailure::RootHashMismatch));
    }

    #[test]
    fn a_membership_for_another_group_report_is_rejected() {
        let g = group();
        let other = publish_group(
            &entities(),
            &ReportMetadata {
                snapshot_time: "2026-08-08T00:00:00Z".to_string(),
                ..metadata()
            },
            &signer(),
        )
        .unwrap();
        assert_eq!(
            verify_membership(
                &g.signed_report,
                &other.memberships[0],
                &signer().public_key_hex()
            ),
            Err(VerificationFailure::DigestMismatch)
        );
    }

    #[test]
    fn a_group_report_signed_by_an_untrusted_key_is_rejected() {
        let g = group();
        assert_eq!(
            verify_membership(&g.signed_report, &g.memberships[0], &"ab".repeat(32)),
            Err(VerificationFailure::UnknownSigner)
        );
    }

    #[test]
    fn publishing_a_group_with_no_entities_is_an_error() {
        assert!(publish_group(&[], &metadata(), &signer()).is_err());
    }

    /// A customer of a subsidiary, verifying all the way up to the group's
    /// consolidated liabilities without ever seeing a sibling entity's book.
    mod chain {
        use super::*;
        use crate::produce::{publish, LeafInput, Publication};
        use canton_solvency_merkle::leaf_salt;

        fn entity_publication(name: &str, amount: u128) -> Publication {
            let leaves: Vec<LeafInput> = (1..=3)
                .map(|i| {
                    let user_id = format!("{name}-user-{i}");
                    LeafInput {
                        salt: leaf_salt(name.as_bytes(), &user_id),
                        balances: sums(&[("USDA", amount * i as u128)]),
                        user_id,
                    }
                })
                .collect();
            publish(
                &leaves,
                &ReportMetadata {
                    profile: "solvency.liabilities".to_string(),
                    publisher: format!("group::{name}"),
                    ..metadata()
                },
                &signer(),
            )
            .unwrap()
        }

        fn entity_of(p: &Publication, id: &str) -> EntityInput {
            EntityInput {
                entity_id: id.to_string(),
                root_hash: crate::verify::hash32(&p.signed_report.report.root_hash, "root")
                    .unwrap(),
                root_sums: p.signed_report.report.root_sums.clone(),
            }
        }

        fn scenario() -> (GroupPublication, Publication, Publication) {
            let a = entity_publication("sub-a", 10);
            let b = entity_publication("sub-b", 100);
            let group = publish_group(
                &[entity_of(&a, "sub-a"), entity_of(&b, "sub-b")],
                &metadata(),
                &signer(),
            )
            .unwrap();
            (group, a, b)
        }

        fn key() -> String {
            signer().public_key_hex()
        }

        #[test]
        fn a_customer_verifies_up_to_the_consolidated_group_total() {
            let (group, a, _) = scenario();
            for proof in &a.proofs {
                assert_eq!(
                    verify_chain(
                        &group.signed_report,
                        &group.memberships[0],
                        &a.signed_report,
                        proof,
                        &key(),
                        &key()
                    ),
                    Ok(())
                );
            }
        }

        #[test]
        fn the_group_total_is_the_sum_of_its_entities() {
            let (group, a, b) = scenario();
            let total =
                a.signed_report.report.root_sums["USDA"] + b.signed_report.report.root_sums["USDA"];
            assert_eq!(group.signed_report.report.root_sums["USDA"], total);
        }

        /// The check that stops the two halves being jointly meaningless.
        #[test]
        fn one_entitys_membership_beside_another_entitys_report_is_rejected() {
            let (group, _a, b) = scenario();
            assert_eq!(
                verify_chain(
                    &group.signed_report,
                    &group.memberships[0], // sub-a
                    &b.signed_report,      // sub-b's book
                    &b.proofs[0],
                    &key(),
                    &key()
                ),
                Err(VerificationFailure::EntityRootMismatch)
            );
        }

        #[test]
        fn a_membership_restating_the_entitys_totals_is_rejected() {
            let (mut group, a, _) = scenario();
            let root = group.memberships[0].entity.root_hash.clone();
            group.memberships[0]
                .entity
                .root_sums
                .insert("USDA".into(), 1);
            group.memberships[0].entity.root_hash = root;
            let err = verify_chain(
                &group.signed_report,
                &group.memberships[0],
                &a.signed_report,
                &a.proofs[0],
                &key(),
                &key(),
            );
            // The membership no longer folds, so this fails before the
            // entity-comparison step; either way it must not verify.
            assert!(err.is_err(), "restated totals verified: {err:?}");
        }

        #[test]
        fn a_tampered_customer_proof_fails_the_whole_chain() {
            let (group, mut a, _) = scenario();
            a.proofs[0].leaf.balances.insert("USDA".into(), 999);
            assert_eq!(
                verify_chain(
                    &group.signed_report,
                    &group.memberships[0],
                    &a.signed_report,
                    &a.proofs[0],
                    &key(),
                    &key()
                ),
                Err(VerificationFailure::RootHashMismatch)
            );
        }

        #[test]
        fn an_entity_absent_from_the_group_has_no_chain() {
            let (group, _, _) = scenario();
            let outsider = entity_publication("sub-c", 7);
            // The outsider's own report verifies, but no membership in this
            // group describes it.
            for membership in &group.memberships {
                assert!(verify_chain(
                    &group.signed_report,
                    membership,
                    &outsider.signed_report,
                    &outsider.proofs[0],
                    &key(),
                    &key()
                )
                .is_err());
            }
        }
    }

    #[test]
    fn membership_documents_round_trip_through_json() {
        let g = group();
        let text = serde_json::to_string(&g.memberships[0]).unwrap();
        let back: GroupMembershipDocument = serde_json::from_str(&text).unwrap();
        assert_eq!(back, g.memberships[0]);
    }
}
