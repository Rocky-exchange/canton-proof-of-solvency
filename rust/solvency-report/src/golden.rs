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
        manifest: None,
    }
}

/// The signed report and the proof for the second user (the §6 vector that
/// exercises a two-step path with the sibling on the left).
pub fn fixture() -> (SignedReport, ProofDocument) {
    let published = publish(&leaves(), &metadata(), &signer()).unwrap();
    let proof = published.proofs[1].clone();
    (published.signed_report, proof)
}

/// The SPEC §8.5 v2 fixture: the §10 report plus a disclosure manifest,
/// consistent with what that report actually carries.
pub fn manifest() -> crate::manifest::Manifest {
    use crate::manifest::{Disclosure, Manifest};
    Manifest {
        audience: "public".to_string(),
        fields: [
            ("root_sums", Disclosure::Published),
            ("mark_prices", Disclosure::Published),
            ("disclosures.bad_debt", Disclosure::Published),
            ("disclosures.excluded_house_accounts", Disclosure::Published),
            ("disclosures.excluded_house_totals", Disclosure::Published),
            ("customer_balances", Disclosure::Committed),
            ("customer_identities", Disclosure::Withheld),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
    }
}

/// The three §8.5 manifest rules the corpus did not reach.
///
/// Returns, in order: a report declaring a field published that it does not
/// carry, with its proof; a v1 report carrying a manifest; and a v2 report
/// carrying none.
///
/// The corpus had one manifest case, and it covered the opposite direction —
/// a field declared withheld that the report publishes anyway. Consistency is
/// checked both ways, and only one way was checked.
pub fn manifest_edge_fixtures() -> (SignedReport, ProofDocument, SignedReport, SignedReport) {
    use crate::manifest::{Disclosure, Manifest};

    // Declares mark_prices published, and publishes none. A manifest is a
    // claim about what the report shows, so promising a figure and omitting it
    // is as inconsistent as printing one you called withheld.
    let mut fields = manifest().fields.clone();
    fields.insert("mark_prices".to_string(), Disclosure::Published);
    let published_but_absent = publish(
        &leaves(),
        &ReportMetadata {
            mark_prices: BTreeMap::new(),
            manifest: Some(Manifest {
                audience: "public".to_string(),
                fields,
            }),
            ..metadata()
        },
        &signer(),
    )
    .unwrap();

    // A v1 report carrying a manifest. The v1 digest does not cover the
    // manifest, so the signature and the proof binding both still hold — which
    // is exactly why the presence rule has to exist as its own check rather
    // than falling out of the digest.
    let (mut v1_with_manifest, _) = fixture();
    v1_with_manifest.report.manifest = Some(manifest());

    // A v2 report with the manifest removed. Here the digest *would* catch it,
    // but only after §9.1 has already refused it on presence — the earlier and
    // clearer answer.
    let (mut v2_without_manifest, _) = fixture_v2();
    v2_without_manifest.report.manifest = None;

    (
        published_but_absent.signed_report.clone(),
        published_but_absent.proofs[1].clone(),
        v1_with_manifest,
        v2_without_manifest,
    )
}

pub fn fixture_v2() -> (SignedReport, ProofDocument) {
    let published = publish(
        &leaves(),
        &ReportMetadata {
            manifest: Some(manifest()),
            ..metadata()
        },
        &signer(),
    )
    .unwrap();
    let proof = published.proofs[1].clone();
    (published.signed_report, proof)
}

/// The SPEC §3.1 repo fixture: three legs under leaf v2, each collateralised
/// above its exposure.
pub fn repo_fixture() -> (SignedReport, crate::document::ProofDocumentV2) {
    use crate::produce::{publish_v2, LeafInputV2};
    let leaves: Vec<LeafInputV2> = [
        ("repo-leg-1", 110u128, 100u128),
        ("repo-leg-2", 55, 50),
        ("repo-leg-3", 22, 20),
    ]
    .into_iter()
    .map(|(id, collateral, exposure)| LeafInputV2 {
        salt: leaf_salt(MASTER_SALT, id),
        subject_id: id.to_string(),
        maps: [("collateral", collateral), ("exposure", exposure)]
            .into_iter()
            .map(|(name, v)| {
                (
                    name.to_string(),
                    amounts(&[("USDA", v * 1_000_000_000_000_000_000)]),
                )
            })
            .collect(),
    })
    .collect();

    let published = publish_v2(
        &leaves,
        &ReportMetadata {
            profile: "collateral.repo".to_string(),
            mark_prices: BTreeMap::new(),
            disclosures: Default::default(),
            ..metadata()
        },
        &signer(),
    )
    .unwrap();
    let proof = published.proofs[0].clone();
    (published.signed_report, proof)
}

/// The SPEC §11 coverage fixture: a custody report covering the §10
/// liabilities, and the statement binding the two.
pub fn coverage_fixture() -> (SignedReport, crate::coverage::CoverageStatement) {
    use crate::coverage::{CoverageStatement, COVERAGE_FORMAT_VERSION};
    use crate::digest::report_digest_hex;
    use crate::produce::{publish_v2, LeafInputV2};

    // Held comfortably above the §10 totals of CBTC 0.25 and USDA 101.5…001.
    let leaves: Vec<LeafInputV2> = [
        (
            "custody-position-1",
            "USDA",
            120_000_000_000_000_000_000u128,
        ),
        ("custody-position-2", "CBTC", 300_000_000_000_000_000),
    ]
    .into_iter()
    .map(|(id, asset, amount)| LeafInputV2 {
        salt: leaf_salt(MASTER_SALT, id),
        subject_id: id.to_string(),
        maps: [("held".to_string(), amounts(&[(asset, amount)]))]
            .into_iter()
            .collect(),
    })
    .collect();

    let custody = publish_v2(
        &leaves,
        &ReportMetadata {
            profile: "coverage.custody".to_string(),
            mark_prices: BTreeMap::new(),
            disclosures: Default::default(),
            ..metadata()
        },
        &signer(),
    )
    .unwrap()
    .signed_report;

    let (liabilities, _) = fixture();
    let statement = CoverageStatement {
        format_version: COVERAGE_FORMAT_VERSION.to_string(),
        custody_report_digest: report_digest_hex(&custody.report),
        liabilities_report_digest: report_digest_hex(&liabilities.report),
        custody_basis: "omnibus custody party golden::custodian".to_string(),
    };
    (custody, statement)
}

/// The SPEC §12 anchor fixture: the genesis anchor of the §10 report.
pub fn anchor_fixture() -> crate::anchor::Anchor {
    let (signed, _) = fixture();
    crate::anchor::anchor_report(&signed, None)
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
/// A publisher that commits an honest tree and signs understated totals.
///
/// SPEC §9.1 names this as the reason step 5 compares sums as well as hashes:
/// "a publisher can commit a truthful tree and still print understated totals
/// in the report". Nothing in the corpus exercised it — the existing
/// `proof-understated-totals` case edits the report *after* signing, so the
/// digest binding catches it first and the sums comparison never runs.
///
/// Here the publisher signs the lie. The digest is computed over the false
/// totals, so the proof binds correctly and the signature verifies; the root
/// hash is the real one, because the tree is real. Only comparing the folded
/// sums against the published ones detects it.
pub fn understated_fixture() -> (SignedReport, ProofDocument) {
    let (mut signed, mut proof) = fixture();

    // Understate one asset. The tree is untouched.
    let understated = signed.report.root_sums["USDA"] / 2;
    signed
        .report
        .root_sums
        .insert("USDA".to_string(), understated);

    // Sign the report as it now reads, and rebind the proof to it.
    let digest = crate::digest::report_digest(&signed.report);
    signed.signature.value = signer().sign_digest(&digest);
    proof.report_digest = hex::encode(digest);

    (signed, proof)
}

/// The golden report and proof packaged as an evidence pack (SPEC §15),
/// signed by the same key, so a conformance runner can check a whole delivery.
///
/// The member bytes are the pretty-printed documents a publisher writes, since
/// the index pins bytes on disk rather than any re-serialisation of them.
/// An `eligibility.holder` report, and one where a holder did not comply.
///
/// §14's unanimity rule: each attested rule carries `1` in every leaf, so the
/// total equalling `leaf_count` is consistent with every holder having
/// satisfied it. The second report has three holders and one that did not,
/// so the total falls a whole unit short of the count.
///
/// §14 already qualifies what this proves — `leaf_count` is signed but never
/// recomputed, so a publisher who understates it satisfies the arithmetic. The
/// case pins what the check does catch, which is a publisher who reports the
/// count honestly and the indicator honestly.
pub fn eligibility_fixture() -> (
    SignedReport,
    crate::document::ProofDocumentV2,
    SignedReport,
    crate::document::ProofDocumentV2,
) {
    use crate::produce::{publish_v2, LeafInputV2};
    let one = 1_000_000_000_000_000_000u128;

    let holder = |id: &str, complies: bool| LeafInputV2 {
        salt: leaf_salt(MASTER_SALT, id),
        subject_id: id.to_string(),
        maps: [(
            "attested".to_string(),
            amounts(&[("accredited", if complies { one } else { 0 })]),
        )]
        .into_iter()
        .collect(),
    };
    let meta = || ReportMetadata {
        profile: "eligibility.holder".to_string(),
        ..metadata()
    };

    let all_comply = publish_v2(
        &[
            holder("holder-1", true),
            holder("holder-2", true),
            holder("holder-3", true),
        ],
        &meta(),
        &signer(),
    )
    .unwrap();
    let one_does_not = publish_v2(
        &[
            holder("holder-1", true),
            holder("holder-2", true),
            holder("holder-3", false),
        ],
        &meta(),
        &signer(),
    )
    .unwrap();

    // The rejecting pair gets its own proof, so the digest binding passes and
    // the unanimity total is the only thing left to fail. Pairing it with the
    // other report's proof rejects on the binding instead, which is a
    // different check and would have made the case worthless.
    (
        all_comply.signed_report,
        all_comply.proofs[0].clone(),
        one_does_not.signed_report,
        one_does_not.proofs[0].clone(),
    )
}

/// A `fund.nav` report: units outstanding and total entitlement, per holder.
///
/// The profile requires both `units/*` and `entitlement/*` aggregates, so a
/// report publishing only one of them asserts half its statement and is
/// refused as vacuous.
pub fn fund_fixture() -> (
    SignedReport,
    crate::document::ProofDocumentV2,
    SignedReport,
    crate::document::ProofDocumentV2,
) {
    use crate::produce::{publish_v2, LeafInputV2};
    let one = 1_000_000_000_000_000_000u128;
    let leaves: Vec<LeafInputV2> = [("holder-a", 1_000u128, 2_500u128), ("holder-b", 400, 1_000)]
        .into_iter()
        .map(|(id, units, entitlement)| LeafInputV2 {
            salt: leaf_salt(MASTER_SALT, id),
            subject_id: id.to_string(),
            maps: [
                ("units".to_string(), amounts(&[("CLASS_A", units * one)])),
                (
                    "entitlement".to_string(),
                    amounts(&[("USDA", entitlement * one)]),
                ),
            ]
            .into_iter()
            .collect(),
        })
        .collect();

    let published = publish_v2(
        &leaves,
        &ReportMetadata {
            profile: "fund.nav".to_string(),
            ..metadata()
        },
        &signer(),
    )
    .unwrap();

    // The same holders with the entitlement map dropped: units outstanding
    // published, entitlement not. That is half the statement the profile
    // makes, and §14 refuses a report omitting an aggregate its profile
    // requires rather than accepting a partial one.
    let units_only: Vec<LeafInputV2> = leaves
        .iter()
        .map(|l| LeafInputV2 {
            salt: l.salt,
            subject_id: l.subject_id.clone(),
            maps: l
                .maps
                .iter()
                .filter(|(name, _)| name.as_str() == "units")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
        .collect();
    let partial = publish_v2(
        &units_only,
        &ReportMetadata {
            profile: "fund.nav".to_string(),
            ..metadata()
        },
        &signer(),
    )
    .unwrap();

    (
        published.signed_report,
        published.proofs[0].clone(),
        partial.signed_report,
        partial.proofs[0].clone(),
    )
}

/// A `settlement.dvp` report, and the trade that is missing a leg.
///
/// §14 states the case in as many words: "a committed trade missing a leg is
/// rejected when its own proof is checked". The profile requires every leaf to
/// carry both `delivered` and `paid`, which is what makes delivery-versus-
/// payment structural rather than a policy someone remembers to apply.
///
/// Returns the report, a proof for a complete trade, and a proof for one that
/// carries only the delivered leg. Both proofs are genuine — the incomplete
/// trade really is committed in the tree — so nothing but the per-leaf rule
/// separates them.
pub fn dvp_fixture() -> (
    SignedReport,
    crate::document::ProofDocumentV2,
    crate::document::ProofDocumentV2,
) {
    use crate::produce::{publish_v2, LeafInputV2};

    let one = 1_000_000_000_000_000_000u128;
    let complete = LeafInputV2 {
        salt: leaf_salt(MASTER_SALT, "trade-1"),
        subject_id: "trade-1".to_string(),
        maps: [
            ("delivered".to_string(), amounts(&[("BOND", 100 * one)])),
            ("paid".to_string(), amounts(&[("USDA", 99 * one)])),
        ]
        .into_iter()
        .collect(),
    };
    // Delivered but never paid for. The leaf is committed exactly like any
    // other; only its own proof reveals the missing leg.
    let half_settled = LeafInputV2 {
        salt: leaf_salt(MASTER_SALT, "trade-2"),
        subject_id: "trade-2".to_string(),
        maps: [("delivered".to_string(), amounts(&[("BOND", 200 * one)]))]
            .into_iter()
            .collect(),
    };

    let published = publish_v2(
        &[complete, half_settled],
        &ReportMetadata {
            profile: "settlement.dvp".to_string(),
            ..metadata()
        },
        &signer(),
    )
    .unwrap();
    (
        published.signed_report,
        published.proofs[0].clone(),
        published.proofs[1].clone(),
    )
}

/// A custody report that does not cover the liabilities, for the case §11
/// exists to catch.
///
/// Holds plenty of USDA and no CBTC at all. §11 is driven by what is owed, so
/// an asset owed and held nowhere must read as a shortfall rather than as
/// silence — the failure mode where a missing row looks like nothing required.
pub fn shortfall_fixture() -> (SignedReport, crate::coverage::CoverageStatement) {
    use crate::coverage::{CoverageStatement, COVERAGE_FORMAT_VERSION};
    use crate::digest::report_digest_hex;
    use crate::produce::{publish_v2, LeafInputV2};

    let leaves: Vec<LeafInputV2> = [(
        "custody-position-1",
        "USDA",
        120_000_000_000_000_000_000u128,
    )]
    .into_iter()
    .map(|(id, asset, amount)| LeafInputV2 {
        salt: leaf_salt(MASTER_SALT, id),
        subject_id: id.to_string(),
        maps: [("held".to_string(), amounts(&[(asset, amount)]))]
            .into_iter()
            .collect(),
    })
    .collect();

    let meta = ReportMetadata {
        profile: "coverage.custody".to_string(),
        ..metadata()
    };
    let published = publish_v2(&leaves, &meta, &signer()).unwrap();
    let (liabilities, _) = fixture();
    let statement = CoverageStatement {
        format_version: COVERAGE_FORMAT_VERSION.to_string(),
        custody_report_digest: report_digest_hex(&published.signed_report.report),
        liabilities_report_digest: report_digest_hex(&liabilities.report),
        custody_basis: "omnibus custody party golden::custodian".to_string(),
    };
    (published.signed_report, statement)
}

/// The §13.4 chain, and the substitution it exists to refuse.
///
/// Returns the group report, entity A's membership, entity B's membership,
/// entity A's own report, and a customer proof against it.
///
/// Pairing A's membership with A's report is the honest chain. Pairing **B's**
/// membership with A's report is the attack §13.4 names in as many words: "a
/// group could present entity A's membership beside entity B's report". Both
/// halves verify on their own — the proof against A's report, the membership
/// against the group report — and only step 3, comparing the membership's
/// claimed entity root against the report's actual one, connects them.
pub fn chain_fixture() -> (
    SignedReport,
    crate::group::GroupMembershipDocument,
    crate::group::GroupMembershipDocument,
    SignedReport,
    ProofDocument,
) {
    use crate::group::{publish_group, EntityInput};
    let (entity_report, proof) = fixture();
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
    (
        published.signed_report,
        published.memberships[0].clone(),
        published.memberships[1].clone(),
        entity_report,
        proof,
    )
}

/// A fixture whose asset names sort differently under UTF-8 bytes than under
/// UTF-16 code units (SPEC §2).
///
/// `U+FF01` encodes as `ef bc 81` and `U+10000` as `f0 90 80 80`, so bytewise
/// order puts `U+FF01` first. JavaScript's default `Array.sort()` compares
/// UTF-16 code units, where `U+10000` is the surrogate pair `d800 dc00` and
/// therefore sorts *first* — the opposite order, a different canonical string,
/// and a different leaf hash.
///
/// Every asset name in the §6 vectors is ASCII, where the two orders agree,
/// which is why nothing caught this until a third implementation was written
/// from the specification text. A conformance case makes it permanent: an
/// implementation that sorts by UTF-16 fails here rather than in production
/// against the first venue to list a non-ASCII asset.
pub fn astral_fixture() -> (SignedReport, ProofDocument) {
    let balances = amounts(&[
        ("\u{FF01}", 1_000_000_000_000_000_000),
        ("\u{10000}", 2_000_000_000_000_000_000),
    ]);
    let leaves: Vec<LeafInput> = ["astral-a", "astral-b"]
        .into_iter()
        .map(|user_id| LeafInput {
            salt: leaf_salt(MASTER_SALT, user_id),
            user_id: user_id.to_string(),
            balances: balances.clone(),
        })
        .collect();
    let published = publish(&leaves, &metadata(), &signer()).unwrap();
    let proof = published.proofs[0].clone();
    (published.signed_report, proof)
}

pub fn pack_fixture() -> (crate::pack::SignedPack, Vec<(String, Vec<u8>)>) {
    let (report, proof) = fixture();
    let members = vec![
        (
            "report.json".to_string(),
            format!("{}\n", serde_json::to_string_pretty(&report).unwrap()).into_bytes(),
        ),
        (
            "proof.json".to_string(),
            format!("{}\n", serde_json::to_string_pretty(&proof).unwrap()).into_bytes(),
        ),
    ];
    let signed = crate::pack::build_pack(
        &report.report.publisher,
        &report.report.snapshot_time,
        &crate::digest::report_digest_hex(&report.report),
        &members,
        &signer(),
    )
    .expect("the golden members are distinct");
    (signed, members)
}

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

    const REPORT_V2_JSON: &str = include_str!("../../../fixtures/report-v2.golden.json");
    const PROOF_FOR_REPORT_V2_JSON: &str =
        include_str!("../../../fixtures/proof-for-report-v2.golden.json");

    #[test]
    fn golden_vectors_pin_the_v2_report_format() {
        let (signed, proof) = fixture_v2();
        assert_eq!(
            signed.report.format_version,
            crate::document::REPORT_FORMAT_VERSION_V2
        );
        assert_eq!(
            signed.signature.value,
            "d7385bd2c72f274584ce804ef3f513d90465d6a68896c597726f8eff84bb86ec\
             a2ac42583fbb3fd4157ace9132ac24e8087cbe6f445cc984e1ad979197357e01"
        );
        // Same tree as §10: v2 changes the envelope, not the commitment.
        assert_eq!(signed.report.root_hash, fixture().0.report.root_hash);
        // ...but a different digest, because the domain differs.
        assert_ne!(
            report_digest(&signed.report),
            report_digest(&fixture().0.report)
        );
        assert_eq!(
            proof.report_digest,
            hex::encode(report_digest(&signed.report))
        );
    }

    #[test]
    fn v2_fixture_files_match_what_the_producer_emits() {
        let (signed, proof) = fixture_v2();
        assert_eq!(
            serde_json::to_string_pretty(&signed).unwrap(),
            REPORT_V2_JSON.trim_end(),
            "fixtures/report-v2.golden.json is stale"
        );
        assert_eq!(
            serde_json::to_string_pretty(&proof).unwrap(),
            PROOF_FOR_REPORT_V2_JSON.trim_end(),
            "fixtures/proof-for-report-v2.golden.json is stale"
        );
    }

    #[test]
    fn the_v2_fixture_verifies_when_read_back_from_disk() {
        let signed: SignedReport = serde_json::from_str(REPORT_V2_JSON).unwrap();
        let proof: ProofDocument = serde_json::from_str(PROOF_FOR_REPORT_V2_JSON).unwrap();
        assert_eq!(verify(&signed, &proof, &signer().public_key_hex()), Ok(()));
    }

    const REPO_REPORT_JSON: &str = include_str!("../../../fixtures/repo-report.golden.json");
    const REPO_PROOF_JSON: &str = include_str!("../../../fixtures/repo-proof.golden.json");

    #[test]
    fn golden_vectors_pin_the_repo_profile() {
        let (signed, proof) = repo_fixture();
        assert_eq!(signed.report.profile, "collateral.repo");
        assert_eq!(
            signed.report.root_hash,
            "5c018ba640db02fdd645b6a1318d2fa71ed083813bb366dddd28e683d3b8d458"
        );
        assert_eq!(
            proof.report_digest,
            "210c70446f6a5eae020fcabfce19f733b60b9d5fa804fa0323e5d855591b4501"
        );
        // Coverage holds at the root, checkable by hand: 110+55+22 vs 100+50+20.
        assert_eq!(
            canton_solvency_merkle::format_amount_18dp(signed.report.root_sums["collateral/USDA"]),
            "187.000000000000000000"
        );
        assert_eq!(
            canton_solvency_merkle::format_amount_18dp(signed.report.root_sums["exposure/USDA"]),
            "170.000000000000000000"
        );
    }

    #[test]
    fn repo_fixture_files_match_what_the_producer_emits() {
        let (signed, proof) = repo_fixture();
        assert_eq!(
            serde_json::to_string_pretty(&signed).unwrap(),
            REPO_REPORT_JSON.trim_end(),
            "fixtures/repo-report.golden.json is stale"
        );
        assert_eq!(
            serde_json::to_string_pretty(&proof).unwrap(),
            REPO_PROOF_JSON.trim_end(),
            "fixtures/repo-proof.golden.json is stale"
        );
    }

    #[test]
    fn the_repo_fixture_verifies_when_read_back_from_disk() {
        let signed: SignedReport = serde_json::from_str(REPO_REPORT_JSON).unwrap();
        let proof: crate::document::ProofDocumentV2 =
            serde_json::from_str(REPO_PROOF_JSON).unwrap();
        assert_eq!(
            crate::verify::verify_v2(&signed, &proof, &signer().public_key_hex()),
            Ok(())
        );
    }

    const CUSTODY_REPORT_JSON: &str = include_str!("../../../fixtures/custody-report.golden.json");
    const COVERAGE_STATEMENT_JSON: &str =
        include_str!("../../../fixtures/coverage-statement.golden.json");

    #[test]
    fn coverage_fixture_files_match_what_the_producer_emits() {
        let (custody, statement) = coverage_fixture();
        assert_eq!(
            serde_json::to_string_pretty(&custody).unwrap(),
            CUSTODY_REPORT_JSON.trim_end(),
            "fixtures/custody-report.golden.json is stale"
        );
        assert_eq!(
            serde_json::to_string_pretty(&statement).unwrap(),
            COVERAGE_STATEMENT_JSON.trim_end(),
            "fixtures/coverage-statement.golden.json is stale"
        );
    }

    /// The statement names the §10 report, so a reader can check the pairing
    /// against a vector they already have.
    #[test]
    fn the_coverage_statement_binds_the_golden_liabilities_report() {
        let (_, statement) = coverage_fixture();
        assert_eq!(
            statement.liabilities_report_digest,
            "0800c1047c9724ea429b238b01366f2032d674425d3ed745ed3402b2f534df61"
        );
    }

    #[test]
    fn the_coverage_fixture_verifies_when_read_back_from_disk() {
        let custody: SignedReport = serde_json::from_str(CUSTODY_REPORT_JSON).unwrap();
        let statement: crate::coverage::CoverageStatement =
            serde_json::from_str(COVERAGE_STATEMENT_JSON).unwrap();
        let liabilities: SignedReport = serde_json::from_str(REPORT_JSON).unwrap();
        let key = signer().public_key_hex();
        let outcome =
            crate::coverage::verify_coverage(&custody, &liabilities, &statement, &key, &key)
                .unwrap();
        assert!(outcome.fully_covered(), "{:?}", outcome.assets);
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
