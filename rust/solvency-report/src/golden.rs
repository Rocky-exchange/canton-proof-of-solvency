//! The SPEC §10 golden fixture, shared by the Rust golden test, the vector
//! regenerator, and the TypeScript conformance data.
//!
//! It extends the §6 leaf fixture — the same three users and master salt
//! `golden-v1` — with report metadata and a fixed signing seed, so the two
//! implementations pin the same bytes end to end.

use crate::document::{Disclosures, ProofDocument, SignedReport};
use crate::produce::{publish, LeafInput, ReportMetadata};
use crate::sign::ReportSigner;
use canton_solvency_merkle::leaf_salt;
use std::collections::BTreeMap;

pub const MASTER_SALT: &[u8] = b"golden-v1";
/// 32 bytes of 0x01.
pub const SIGNING_SEED: [u8; 32] = [1u8; 32];

fn amounts(entries: &[(&str, u128)]) -> BTreeMap<String, u128> {
    entries.iter().map(|(a, v)| (a.to_string(), *v)).collect()
}

pub fn signer() -> ReportSigner {
    ReportSigner::from_seed(&SIGNING_SEED)
}

pub fn leaves() -> Vec<LeafInput> {
    [
        (
            "11111111-1111-7111-8111-111111111111",
            amounts(&[("USDA", 100_500_000_000_000_000_000)]),
        ),
        (
            "22222222-2222-7222-8222-222222222222",
            amounts(&[
                ("CBTC", 250_000_000_000_000_000),
                ("USDA", 1_000_000_000_000_000_001),
            ]),
        ),
        ("33333333-3333-7333-8333-333333333333", BTreeMap::new()),
    ]
    .into_iter()
    .map(|(user_id, balances)| LeafInput {
        salt: leaf_salt(MASTER_SALT, user_id),
        user_id: user_id.to_string(),
        balances,
    })
    .collect()
}

pub fn metadata() -> ReportMetadata {
    ReportMetadata {
        profile: "solvency.liabilities".to_string(),
        publisher: "golden::publisher".to_string(),
        snapshot_time: "2026-01-01T00:00:00Z".to_string(),
        ledger_offset: "000000000000000042".to_string(),
        mark_prices: amounts(&[("CBTC", 50_000_000_000_000_000_000_000)]),
        disclosures: Disclosures {
            bad_debt: amounts(&[("USDA", 2_500_000_000_000_000_000)]),
            excluded_house_accounts: 1,
            excluded_house_totals: amounts(&[("USDA", 1_000_000_000_000_000_000_000)]),
        },
    }
}

/// The signed report and the proof for the second user (the §6 vector that
/// exercises a two-step path with the sibling on the left).
pub fn fixture() -> (SignedReport, ProofDocument) {
    let published = publish(&leaves(), &metadata(), &signer()).unwrap();
    let proof = published.proofs[1].clone();
    (published.signed_report, proof)
}

/// The SPEC §13 group fixture: the §10 report as one entity, plus a second
/// entity with fixed values, consolidated under one group report.
pub fn group_fixture() -> (SignedReport, crate::group::GroupMembershipDocument) {
    use crate::group::{publish_group, EntityInput};
    let (entity_report, _) = fixture();
    let entities = vec![
        EntityInput {
            entity_id: "golden-entity-a".to_string(),
            root_hash: crate::verify::hash32(&entity_report.report.root_hash, "root").unwrap(),
            root_sums: entity_report.report.root_sums.clone(),
        },
        EntityInput {
            entity_id: "golden-entity-b".to_string(),
            root_hash: [0x11; 32],
            root_sums: amounts(&[("USDA", 42_000_000_000_000_000_000)]),
        },
    ];
    let published = publish_group(&entities, &metadata(), &signer()).unwrap();
    let membership = published.memberships[0].clone();
    (published.signed_report, membership)
}

/// Cross-implementation wire-format pin (SPEC §10). The TypeScript verifier
/// asserts these same bytes against the same fixture files. Changing any value
/// here is a format version bump, not a refactor.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::report_digest;
    use crate::verify::verify;

    const REPORT_JSON: &str = include_str!("../../../fixtures/report.golden.json");
    const PROOF_JSON: &str = include_str!("../../../fixtures/proof.golden.json");

    #[test]
    fn golden_vectors_pin_the_report_format() {
        let (signed, proof) = fixture();

        assert_eq!(
            signed.signature.public_key,
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        assert_eq!(
            hex::encode(report_digest(&signed.report)),
            "0800c1047c9724ea429b238b01366f2032d674425d3ed745ed3402b2f534df61"
        );
        assert_eq!(
            signed.signature.value,
            "b1bf2a1fc11476610e385e5017cf7a568b13a0c84088b66ecf58ffa04b78499a\
             da7ff8ebf3c2ee7ec0d10d7130cdc868a8074ff51725252631c67f61ce575a07"
        );
        // Unchanged from the §6 leaf fixture: the envelope composes on top of
        // wire format v1 rather than altering it.
        assert_eq!(
            signed.report.root_hash,
            "02885b0fc65c3d8992899c8acba1917cb838b18b7054b6675e3d89f2bf8f0970"
        );
        assert_eq!(
            proof.report_digest,
            hex::encode(report_digest(&signed.report))
        );
        assert_eq!(proof.steps.len(), 2);
        assert!(proof.steps[0].sibling_on_left);
    }

    #[test]
    fn golden_fixture_files_match_what_the_producer_emits() {
        let (signed, proof) = fixture();
        assert_eq!(
            serde_json::to_string_pretty(&signed).unwrap(),
            REPORT_JSON.trim_end(),
            "fixtures/report.golden.json is stale; regenerate with `cargo run --example print_golden`"
        );
        assert_eq!(
            serde_json::to_string_pretty(&proof).unwrap(),
            PROOF_JSON.trim_end(),
            "fixtures/proof.golden.json is stale"
        );
    }

    const GROUP_REPORT_JSON: &str = include_str!("../../../fixtures/group-report.golden.json");
    const GROUP_MEMBERSHIP_JSON: &str =
        include_str!("../../../fixtures/group-membership.golden.json");

    #[test]
    fn golden_vectors_pin_the_group_format() {
        let (group, membership) = group_fixture();
        assert_eq!(
            group.report.root_hash,
            "f672eceb0b675040260bbc6062362c7701bddf8daaba128cae1bcaef80c5fb66"
        );
        assert_eq!(
            hex::encode(report_digest(&group.report)),
            "e2eb5175a25f845acf0059ec85a8594e2e5587d412ed3498a872c83057a93fc8"
        );
        // The consolidated total is the sum of the entity totals.
        assert_eq!(
            crate::document::REPORT_FORMAT_VERSION,
            group.report.format_version
        );
        assert_eq!(
            canton_solvency_merkle::format_amount_18dp(group.report.root_sums["USDA"]),
            "143.500000000000000001"
        );
        assert_eq!(membership.entity.entity_id, "golden-entity-a");
    }

    #[test]
    fn group_fixture_files_match_what_the_producer_emits() {
        let (group, membership) = group_fixture();
        assert_eq!(
            serde_json::to_string_pretty(&group).unwrap(),
            GROUP_REPORT_JSON.trim_end(),
            "fixtures/group-report.golden.json is stale"
        );
        assert_eq!(
            serde_json::to_string_pretty(&membership).unwrap(),
            GROUP_MEMBERSHIP_JSON.trim_end(),
            "fixtures/group-membership.golden.json is stale"
        );
    }

    #[test]
    fn the_group_fixture_verifies_when_read_back_from_disk() {
        let group: SignedReport = serde_json::from_str(GROUP_REPORT_JSON).unwrap();
        let membership: crate::group::GroupMembershipDocument =
            serde_json::from_str(GROUP_MEMBERSHIP_JSON).unwrap();
        assert_eq!(
            crate::group::verify_membership(&group, &membership, &signer().public_key_hex()),
            Ok(())
        );
    }

    #[test]
    fn the_golden_fixture_files_verify_when_read_back_from_disk() {
        let signed: SignedReport = serde_json::from_str(REPORT_JSON).unwrap();
        let proof: ProofDocument = serde_json::from_str(PROOF_JSON).unwrap();
        assert_eq!(verify(&signed, &proof, &signer().public_key_hex()), Ok(()));
    }
}
