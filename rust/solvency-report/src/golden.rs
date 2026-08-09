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

    #[test]
    fn the_golden_fixture_files_verify_when_read_back_from_disk() {
        let signed: SignedReport = serde_json::from_str(REPORT_JSON).unwrap();
        let proof: ProofDocument = serde_json::from_str(PROOF_JSON).unwrap();
        assert_eq!(verify(&signed, &proof, &signer().public_key_hex()), Ok(()));
    }
}
