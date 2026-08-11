//! Generates the conformance corpus (SPEC §14.3): a set of cases any
//! implementation runs to claim compatibility.
//!
//! The generator lives here rather than in the example so a test can call
//! it: a checked-in corpus that has drifted from its generator would have
//! every implementation testing cases the generator no longer describes, and
//! a reader of the generator believing in cases that are not on disk.
//!
//! Cases are derived from the golden fixtures, so the corpus cannot drift
//! from the vectors both implementations already assert.
use crate::golden;
use serde_json::json;
use std::path::Path;

fn write(dir: &Path, name: &str, value: &serde_json::Value) -> anyhow::Result<()> {
    std::fs::write(
        dir.join(name),
        format!("{}\n", serde_json::to_string_pretty(value)?),
    )?;
    Ok(())
}

/// Replaces the first occurrence of `from` with `to` inside a document, used
/// to build the rejection cases.
fn tweak(value: &serde_json::Value, from: &str, to: &str) -> serde_json::Value {
    let text = serde_json::to_string(value).unwrap();
    assert!(
        text.contains(from),
        "conformance mutation {from:?} matched nothing; a case whose mutation \
         silently no-ops tests that the implementation accepts a valid document"
    );
    serde_json::from_str(&text.replacen(from, to, 1)).unwrap()
}

pub fn emit(out: &Path) -> anyhow::Result<usize> {
    std::fs::create_dir_all(out)?;

    let (report, proof) = golden::fixture();
    let (report_v2, proof_v2) = golden::fixture_v2();
    let (repo_report, repo_proof) = golden::repo_fixture();
    let (group_report, membership) = golden::group_fixture();
    let (custody, statement) = golden::coverage_fixture();
    let (shortfall_custody, shortfall_statement) = golden::shortfall_fixture();
    let (dvp_report, dvp_complete, dvp_missing_leg) = golden::dvp_fixture();
    let (eligibility_report, eligibility_proof, eligibility_broken, eligibility_broken_proof) =
        golden::eligibility_fixture();
    let (fund_report, fund_proof, fund_partial, fund_partial_proof) = golden::fund_fixture();
    let (manifest_absent, manifest_absent_proof, v1_with_manifest, v2_without_manifest) =
        golden::manifest_edge_fixtures();
    let (foreign_report, foreign_proof) = golden::foreign_signer_fixture();
    let (sums_group, sums_membership, sums_entity, sums_proof) = golden::entity_sums_fixture();
    let anchor = golden::anchor_fixture();
    let (pack, pack_members) = golden::pack_fixture();
    let (astral_report, astral_proof) = golden::astral_fixture();
    let (understated_report, understated_proof) = golden::understated_fixture();
    let (chain_group, chain_membership_a, chain_membership_b, chain_entity, chain_proof) =
        golden::chain_fixture();
    let key = golden::signer().public_key_hex();

    let report_j = serde_json::to_value(&report)?;
    let proof_j = serde_json::to_value(&proof)?;
    let report_v2_j = serde_json::to_value(&report_v2)?;
    let proof_v2_j = serde_json::to_value(&proof_v2)?;
    let repo_report_j = serde_json::to_value(&repo_report)?;
    let repo_proof_j = serde_json::to_value(&repo_proof)?;
    let group_report_j = serde_json::to_value(&group_report)?;
    let membership_j = serde_json::to_value(&membership)?;
    let custody_j = serde_json::to_value(&custody)?;
    let statement_j = serde_json::to_value(&statement)?;
    let anchor_j = serde_json::to_value(&anchor)?;

    let mut cases: Vec<serde_json::Value> = Vec::new();
    // `requires` is what lets an implementation run the corpus partially and
    // honestly. Without it a verifier that supports only report v1 rejects the
    // v2 cases: it fails `report-v2-valid`, and — worse — *passes*
    // `report-v2-manifest-lies` by rejecting a version it does not implement,
    // so a case meant to test the manifest tests nothing at all.
    let mut add = |id: &str,
                   kind: &str,
                   requires: &[&str],
                   description: &str,
                   expect: &str,
                   failure: Option<&str>,
                   files: Vec<(&str, serde_json::Value)>|
     -> anyhow::Result<()> {
        let dir = out.join(id);
        std::fs::create_dir_all(&dir)?;
        for (name, value) in &files {
            write(&dir, name, value)?;
        }
        cases.push(json!({
            "id": id,
            "kind": kind,
            "requires": requires,
            "description": description,
            "expect": expect,
            "failure": failure,
            "files": files.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        }));
        Ok(())
    };

    // --- proof v1 ---
    add(
        "proof-valid",
        "proof",
        &["report-v1", "proof-v1"],
        "a valid customer proof",
        "accept",
        None,
        vec![
            ("report.json", report_j.clone()),
            ("proof.json", proof_j.clone()),
        ],
    )?;
    add(
        "proof-tampered-balance",
        "proof",
        &["report-v1", "proof-v1"],
        "a balance edited after commitment",
        "reject",
        Some("root_hash_mismatch"),
        vec![
            ("report.json", report_j.clone()),
            (
                "proof.json",
                tweak(&proof_j, "0.250000000000000000", "9.250000000000000000"),
            ),
        ],
    )?;
    add(
        "proof-understated-totals",
        "proof",
        &["report-v1", "proof-v1"],
        "an honest root beside understated published totals",
        "reject",
        Some("digest_mismatch"),
        vec![
            (
                "report.json",
                tweak(&report_j, "101.500000000000000001", "1.500000000000000001"),
            ),
            ("proof.json", proof_j.clone()),
        ],
    )?;
    add(
        "proof-forged-signature",
        "proof",
        &["report-v1", "proof-v1"],
        "a signature that does not verify",
        "reject",
        Some("bad_signature"),
        vec![
            (
                "report.json",
                tweak(
                    &report_j,
                    &serde_json::to_value(&report)?["signature"]["value"]
                        .as_str()
                        .unwrap()[..16],
                    "1111111111111111",
                ),
            ),
            ("proof.json", proof_j.clone()),
        ],
    )?;
    add(
        "proof-stale",
        "proof",
        &["report-v1", "proof-v1"],
        "a proof bound to a different report",
        "reject",
        Some("digest_mismatch"),
        vec![
            ("report.json", report_j.clone()),
            (
                "proof.json",
                tweak(&proof_j, &proof.report_digest[..16], "cdcdcdcdcdcdcdcd"),
            ),
        ],
    )?;

    // --- report v2 and the manifest ---
    add(
        "report-v2-valid",
        "proof",
        &["report-v2", "proof-v1", "manifest"],
        "a v2 report with a consistent manifest",
        "accept",
        None,
        vec![
            ("report.json", report_v2_j.clone()),
            ("proof.json", proof_v2_j.clone()),
        ],
    )?;
    add(
        "report-v2-manifest-lies",
        "proof",
        &["report-v2", "proof-v1", "manifest"],
        "a field declared withheld that the report publishes",
        "reject",
        Some("manifest_inconsistent"),
        vec![
            (
                "report.json",
                tweak(
                    &report_v2_j,
                    "\"root_sums\":\"published\"",
                    "\"root_sums\":\"withheld\"",
                ),
            ),
            ("proof.json", proof_v2_j.clone()),
        ],
    )?;

    // --- leaf v2 profiles ---
    add(
        "repo-valid",
        "proof-v2",
        &["report-v1", "proof-v2", "leaf-v2"],
        "a collateralised repo book",
        "accept",
        None,
        vec![
            ("report.json", repo_report_j.clone()),
            ("proof.json", repo_proof_j.clone()),
        ],
    )?;
    add(
        "repo-under-collateralised",
        "proof-v2",
        &["report-v1", "proof-v2", "leaf-v2"],
        "exposure exceeding collateral for an asset",
        "reject",
        Some("profile"),
        vec![
            (
                "report.json",
                tweak(
                    &repo_report_j,
                    "\"exposure/USDA\":\"170.000000000000000000\"",
                    "\"exposure/USDA\":\"999.000000000000000000\"",
                ),
            ),
            ("proof.json", repo_proof_j.clone()),
        ],
    )?;

    // --- group ---
    add(
        "group-valid",
        "membership",
        &["report-v1", "group-v1"],
        "an entity committed in a group",
        "accept",
        None,
        vec![
            ("group-report.json", group_report_j.clone()),
            ("membership.json", membership_j.clone()),
        ],
    )?;
    add(
        "group-relabelled-entity",
        "membership",
        &["report-v1", "group-v1"],
        "an entity renamed after commitment",
        "reject",
        Some("root_hash_mismatch"),
        vec![
            ("group-report.json", group_report_j.clone()),
            (
                "membership.json",
                tweak(&membership_j, "golden-entity-a", "golden-entity-z"),
            ),
        ],
    )?;

    // --- coverage ---
    add(
        "coverage-valid",
        "coverage",
        &["report-v1", "coverage-v1"],
        "assets covering liabilities",
        "accept",
        None,
        vec![
            ("custody.json", custody_j.clone()),
            ("liabilities.json", report_j.clone()),
            ("statement.json", statement_j.clone()),
        ],
    )?;
    add(
        "coverage-unbound-statement",
        "coverage",
        &["report-v1", "coverage-v1"],
        "a statement naming a different custody report",
        "reject",
        Some("digest_mismatch"),
        vec![
            ("custody.json", custody_j.clone()),
            ("liabilities.json", report_j.clone()),
            (
                "statement.json",
                tweak(
                    &statement_j,
                    &statement.custody_report_digest[..16],
                    "0000000000000000",
                ),
            ),
        ],
    )?;

    // A custody report signed by a key the verifier was not told to trust.
    // The TypeScript coverage path did not verify signatures at all until this
    // case existed, and nothing noticed, because no case required it to.
    {
        let mut untrusted = custody.clone();
        untrusted.signature.public_key = "ab".repeat(32);
        add(
            "coverage-untrusted-signer",
            "coverage",
            &["report-v1", "coverage-v1"],
            "a custody report claiming a key the verifier does not trust",
            "reject",
            Some("unknown_signer"),
            vec![
                ("custody.json", serde_json::to_value(&untrusted)?),
                ("liabilities.json", report_j.clone()),
                ("statement.json", statement_j.clone()),
            ],
        )?;
    }

    // --- §8.4 trust comes from the caller ---
    // A verifier that only asked "does this signature verify against the key
    // in the document" passed every case in the corpus. That is the check the
    // whole signature scheme rests on: the embedded key is display metadata,
    // and a document that certifies itself proves only internal consistency.
    add(
        "proof-signed-by-another-key",
        "proof",
        &["report-v1", "proof-v1"],
        "a valid signature by a key the verifier was not told to trust",
        "reject",
        Some("unknown_signer"),
        vec![
            ("report.json", serde_json::to_value(&foreign_report)?),
            ("proof.json", serde_json::to_value(&foreign_proof)?),
        ],
    )?;

    // --- §13.4 step 3, the sums half ---
    add(
        "chain-entity-sums-disagree",
        "chain",
        &["report-v1", "proof-v1", "group-v1"],
        "a group committing an entity at the right root and the wrong totals",
        "reject",
        Some("entity_sums_mismatch"),
        vec![
            ("group-report.json", serde_json::to_value(&sums_group)?),
            ("membership.json", serde_json::to_value(&sums_membership)?),
            ("entity-report.json", serde_json::to_value(&sums_entity)?),
            ("proof.json", serde_json::to_value(&sums_proof)?),
        ],
    )?;

    // --- §8.5 manifest consistency, both directions ---
    // The corpus checked a field declared withheld that the report publishes.
    // Consistency is checked both ways and only one way was exercised, and the
    // presence rule — a v1 report carrying a manifest, or a v2 carrying none —
    // was not exercised at all.
    add(
        "report-v2-published-but-absent",
        "proof",
        &["report-v2", "proof-v1", "manifest"],
        "a field declared published that the report does not carry",
        "reject",
        Some("manifest_inconsistent"),
        vec![
            ("report.json", serde_json::to_value(&manifest_absent)?),
            ("proof.json", serde_json::to_value(&manifest_absent_proof)?),
        ],
    )?;
    add(
        "report-v1-carrying-a-manifest",
        "proof",
        &["report-v1", "proof-v1", "manifest"],
        "a v1 report carrying a manifest it has no envelope for",
        "reject",
        Some("manifest_presence"),
        vec![
            ("report.json", serde_json::to_value(&v1_with_manifest)?),
            ("proof.json", proof_j.clone()),
        ],
    )?;
    add(
        "report-v2-without-a-manifest",
        "proof",
        &["report-v2", "proof-v1", "manifest"],
        "a v2 report with no manifest at all",
        "reject",
        Some("manifest_presence"),
        vec![
            ("report.json", serde_json::to_value(&v2_without_manifest)?),
            ("proof.json", proof_v2_j.clone()),
        ],
    )?;

    // --- §14 per-leaf rules ---
    // required_leaf_maps is checked when a proof is verified, and nothing
    // exercised it: neutralising the check left every case passing. Three
    // profiles declare per-leaf rules and none had a case at all. §14 names
    // this exact scenario — "a committed trade missing a leg is rejected when
    // its own proof is checked".
    add(
        "dvp-valid",
        "proof-v2",
        &["report-v1", "proof-v2", "leaf-v2"],
        "a settled trade carrying both of its legs",
        "accept",
        None,
        vec![
            ("report.json", serde_json::to_value(&dvp_report)?),
            ("proof.json", serde_json::to_value(&dvp_complete)?),
        ],
    )?;
    add(
        "dvp-missing-leg",
        "proof-v2",
        &["report-v1", "proof-v2", "leaf-v2"],
        "a committed trade delivered but never paid for",
        "reject",
        Some("profile"),
        vec![
            ("report.json", serde_json::to_value(&dvp_report)?),
            ("proof.json", serde_json::to_value(&dvp_missing_leg)?),
        ],
    )?;

    // fund.nav and eligibility.holder were the last two profiles with no case
    // at all. Between them they exercise the two aggregate forms: a profile
    // requiring several prefixed families, and a profile whose statement is
    // about every subject rather than about the totals.
    add(
        "fund-valid",
        "proof-v2",
        &["report-v1", "proof-v2", "leaf-v2"],
        "a tokenised fund publishing units outstanding and total entitlement",
        "accept",
        None,
        vec![
            ("report.json", serde_json::to_value(&fund_report)?),
            ("proof.json", serde_json::to_value(&fund_proof)?),
        ],
    )?;
    add(
        "eligibility-valid",
        "proof-v2",
        &["report-v1", "proof-v2", "leaf-v2"],
        "every committed holder satisfied the attested rule",
        "accept",
        None,
        vec![
            ("report.json", serde_json::to_value(&eligibility_report)?),
            ("proof.json", serde_json::to_value(&eligibility_proof)?),
        ],
    )?;
    add(
        "eligibility-not-unanimous",
        "proof-v2",
        &["report-v1", "proof-v2", "leaf-v2"],
        "a holder who did not satisfy the rule the report asserts of everyone",
        "reject",
        Some("profile"),
        vec![
            ("report.json", serde_json::to_value(&eligibility_broken)?),
            (
                "proof.json",
                serde_json::to_value(&eligibility_broken_proof)?,
            ),
        ],
    )?;
    add(
        "fund-missing-aggregate",
        "proof-v2",
        &["report-v1", "proof-v2", "leaf-v2"],
        "a fund publishing units outstanding but not entitlement",
        "reject",
        Some("profile"),
        vec![
            ("report.json", serde_json::to_value(&fund_partial)?),
            ("proof.json", serde_json::to_value(&fund_partial_proof)?),
        ],
    )?;

    // --- §11 shortfall ---
    // The corpus paired custody with liabilities and checked the binding, and
    // never once checked the comparison the pairing exists for. §11 is driven
    // by what is owed precisely so an asset owed and held nowhere reads as a
    // shortfall rather than as silence; this custody report holds no CBTC at
    // all.
    add(
        "coverage-shortfall",
        "coverage",
        &["report-v1", "coverage-v1"],
        "an asset owed and held nowhere",
        "reject",
        Some("shortfall"),
        vec![
            ("custody.json", serde_json::to_value(&shortfall_custody)?),
            ("liabilities.json", report_j.clone()),
            (
                "statement.json",
                serde_json::to_value(&shortfall_statement)?,
            ),
        ],
    )?;

    // --- the version gate (SPEC §9.1 step 1, §12, §15.3) ---
    // Nothing exercised it. An implementation ignoring format_version
    // altogether passed every other case, which would defeat the whole
    // additive-versioning strategy: v1 stays untouched only because a verifier
    // refuses to read a v2 document under v1 rules.
    add(
        "proof-unknown-report-version",
        "proof",
        &["report-v1", "proof-v1"],
        "a report claiming a format version this verifier does not know",
        "reject",
        Some("unsupported_version"),
        vec![
            (
                "report.json",
                tweak(
                    &report_j,
                    "canton-solvency-report-v1",
                    "canton-solvency-report-v9",
                ),
            ),
            ("proof.json", proof_j.clone()),
        ],
    )?;
    add(
        "proof-unknown-proof-version",
        "proof",
        &["report-v1", "proof-v1"],
        "a proof claiming a format version this verifier does not know",
        "reject",
        Some("unsupported_version"),
        vec![
            ("report.json", report_j.clone()),
            (
                "proof.json",
                tweak(
                    &proof_j,
                    "canton-solvency-proof-v1",
                    "canton-solvency-proof-v9",
                ),
            ),
        ],
    )?;
    add(
        "proof-unknown-signature-algorithm",
        "proof",
        &["report-v1", "proof-v1"],
        "a signature naming an algorithm this verifier does not implement",
        "reject",
        Some("unsupported_version"),
        vec![
            ("report.json", tweak(&report_j, "\"ed25519\"", "\"ed448\"")),
            ("proof.json", proof_j.clone()),
        ],
    )?;

    // --- anchors ---
    let second = {
        let mut a = anchor.clone();
        a.snapshot_time = "2026-01-02T00:00:00Z".into();
        a.ledger_offset = "000000000000000043".into();
        a.prev_anchor = Some(crate::anchor::anchor_digest_hex(&anchor));
        serde_json::to_value(&a)?
    };
    add(
        "anchors-intact",
        "anchors",
        &["anchor-v1"],
        "a two-anchor history",
        "accept",
        None,
        vec![("history.json", json!([anchor_j.clone(), second.clone()]))],
    )?;
    add(
        "anchors-suffix",
        "anchors",
        &["anchor-v1"],
        "a history that does not start at genesis",
        "reject",
        Some("not_genesis"),
        vec![("history.json", json!([second.clone()]))],
    )?;
    // The README lists a rewound offset, a restated instant and a changed
    // publisher among the things a chain refuses. Nothing exercised any of
    // them: neutralising either guard in verify_chain left every case passing.
    let successor =
        |mutate: &dyn Fn(&mut crate::anchor::Anchor)| -> anyhow::Result<serde_json::Value> {
            let mut a = anchor.clone();
            a.snapshot_time = "2026-01-02T00:00:00Z".into();
            a.ledger_offset = "000000000000000043".into();
            a.prev_anchor = Some(crate::anchor::anchor_digest_hex(&anchor));
            mutate(&mut a);
            Ok(serde_json::to_value(&a)?)
        };

    let changed_publisher = successor(&|a| a.publisher = "venue::somebody-else".to_string())?;
    add(
        "anchors-publisher-changed",
        "anchors",
        &["anchor-v1"],
        "a history that changes publisher part-way through",
        "reject",
        Some("publisher_changed"),
        vec![("history.json", json!([anchor_j.clone(), changed_publisher]))],
    )?;

    // A restated instant: the successor claims a snapshot no later than its
    // predecessor's, which is how a republished day would look.
    let restated = successor(&|a| a.snapshot_time = anchor.snapshot_time.clone())?;
    add(
        "anchors-restated-instant",
        "anchors",
        &["anchor-v1"],
        "a successor whose snapshot time does not advance",
        "reject",
        Some("went_backwards"),
        vec![("history.json", json!([anchor_j.clone(), restated]))],
    )?;

    // A rewound offset: the ledger position moves backwards, which cannot
    // happen in an append-only event history.
    let rewound = successor(&|a| a.ledger_offset = "000000000000000001".to_string())?;
    add(
        "anchors-rewound-offset",
        "anchors",
        &["anchor-v1"],
        "a successor whose ledger offset moves backwards",
        "reject",
        Some("went_backwards"),
        vec![("history.json", json!([anchor_j.clone(), rewound]))],
    )?;

    add(
        "anchors-broken-link",
        "anchors",
        &["anchor-v1"],
        "an anchor not naming its predecessor",
        "reject",
        Some("broken"),
        vec![(
            "history.json",
            json!([
                anchor_j.clone(),
                // Tampering with prev_anchor is what breaks a link; editing an
                // anchor's own fields only breaks the link of the one after it.
                tweak(
                    &second,
                    &crate::anchor::anchor_digest_hex(&anchor)[..16],
                    "0000000000000000"
                )
            ]),
        )],
    )?;

    // --- §13.4 chain verification ---
    // Step 3 binds the membership to the entity report. Nothing else in the
    // corpus exercises it: steps 1 and 2 are each covered, and §13.4 says in
    // as many words that they are "independently valid and jointly
    // meaningless" without step 3.
    add(
        "chain-valid",
        "chain",
        &["report-v1", "proof-v1", "group-v1"],
        "a customer proved all the way to a group's consolidated total",
        "accept",
        None,
        vec![
            ("group-report.json", serde_json::to_value(&chain_group)?),
            (
                "membership.json",
                serde_json::to_value(&chain_membership_a)?,
            ),
            ("entity-report.json", serde_json::to_value(&chain_entity)?),
            ("proof.json", serde_json::to_value(&chain_proof)?),
        ],
    )?;
    add(
        "chain-substituted-entity",
        "chain",
        &["report-v1", "proof-v1", "group-v1"],
        "one entity's membership presented beside another entity's report",
        "reject",
        Some("entity_root_mismatch"),
        vec![
            ("group-report.json", serde_json::to_value(&chain_group)?),
            (
                "membership.json",
                serde_json::to_value(&chain_membership_b)?,
            ),
            ("entity-report.json", serde_json::to_value(&chain_entity)?),
            ("proof.json", serde_json::to_value(&chain_proof)?),
        ],
    )?;

    // --- the sums comparison (SPEC §9.1 step 5) ---
    add(
        "proof-signed-understated-totals",
        "proof",
        &["report-v1", "proof-v1"],
        "an honest tree beside understated totals the publisher signed",
        "reject",
        Some("root_sums_mismatch"),
        vec![
            ("report.json", serde_json::to_value(&understated_report)?),
            ("proof.json", serde_json::to_value(&understated_proof)?),
        ],
    )?;

    // --- key ordering (SPEC §2) ---
    add(
        "proof-astral-assets",
        "proof",
        &["report-v1", "proof-v1"],
        "asset names that sort differently under UTF-16 than under UTF-8 bytes",
        "accept",
        None,
        vec![
            ("report.json", serde_json::to_value(&astral_report)?),
            ("proof.json", serde_json::to_value(&astral_proof)?),
        ],
    )?;

    // --- assurance levels (§16) ---
    //
    // The cases that matter here are the over-claims. An implementation that
    // reads the statement and reports it back has implemented nothing: the
    // question is always whether it refused a declaration the evidence did not
    // support.
    {
        use crate::assurance::{AssuranceLevel, ASSURANCE_FORMAT_VERSION};
        let (a_report, a_proof, attestation, custodian_key) = golden::assurance_fixture();
        let a_report_j = serde_json::to_value(&a_report)?;
        let a_proof_j = serde_json::to_value(&a_proof)?;
        let attestations_j = serde_json::to_value(vec![&attestation])?;
        let digest = crate::digest::report_digest_hex(&a_report.report);

        let statement = |field: &str, level: AssuranceLevel| -> serde_json::Value {
            json!({
                "format_version": ASSURANCE_FORMAT_VERSION,
                "report_digest": digest,
                "levels": { field: level.as_str() },
            })
        };
        let trusting_custodian = json!({ custodian_key.clone(): "third-party" });

        add(
            "assurance-verified-with-proof",
            "assurance",
            &["report-v1", "proof-v1", "assurance-v1"],
            "root_sums declared recomputed, with the proof that recomputes it",
            "accept",
            None,
            vec![
                ("report.json", a_report_j.clone()),
                ("proof.json", a_proof_j.clone()),
                (
                    "assurance.json",
                    statement("root_sums", AssuranceLevel::CryptographicallyVerified),
                ),
            ],
        )?;

        // The mechanism, in one case: identical documents, proof withheld.
        add(
            "assurance-verified-without-proof",
            "assurance",
            &["report-v1", "assurance-v1"],
            "root_sums declared recomputed when nothing was recomputed",
            "reject",
            Some("over_claimed"),
            vec![
                ("report.json", a_report_j.clone()),
                (
                    "assurance.json",
                    statement("root_sums", AssuranceLevel::CryptographicallyVerified),
                ),
            ],
        )?;

        // Mark prices are signed and uncommitted. This is the level most
        // likely to be claimed by mistake, because the report it sits in does
        // contain recomputed figures.
        add(
            "assurance-uncommitted-field-declared-verified",
            "assurance",
            &["report-v1", "proof-v1", "assurance-v1"],
            "mark_prices declared recomputed, though nothing in the tree commits to it",
            "reject",
            Some("over_claimed"),
            vec![
                ("report.json", a_report_j.clone()),
                ("proof.json", a_proof_j.clone()),
                (
                    "assurance.json",
                    statement("mark_prices", AssuranceLevel::CryptographicallyVerified),
                ),
            ],
        )?;

        add(
            "assurance-attested-by-trusted-custodian",
            "assurance",
            &["report-v1", "assurance-v1"],
            "root_sums declared third-party attested, with an attestation from a trusted key",
            "accept",
            None,
            vec![
                ("report.json", a_report_j.clone()),
                ("attestations.json", attestations_j.clone()),
                ("attestors.json", trusting_custodian.clone()),
                (
                    "assurance.json",
                    statement("root_sums", AssuranceLevel::ThirdPartyAttested),
                ),
            ],
        )?;

        // Same attestation, same signature, no prior decision to believe the
        // signer. §8.4 applied to attestors.
        add(
            "assurance-attested-by-untrusted-key",
            "assurance",
            &["report-v1", "assurance-v1"],
            "an attestation that verifies, from a key the verifier was never given",
            "reject",
            Some("over_claimed"),
            vec![
                ("report.json", a_report_j.clone()),
                ("attestations.json", attestations_j.clone()),
                (
                    "assurance.json",
                    statement("root_sums", AssuranceLevel::ThirdPartyAttested),
                ),
            ],
        )?;

        // A custodian key vouching as an issuer. The signature is good and the
        // role is not the one it was trusted for.
        add(
            "assurance-attestor-role-mismatch",
            "assurance",
            &["report-v1", "assurance-v1"],
            "a key trusted as a custodian used to establish issuer attestation",
            "reject",
            Some("over_claimed"),
            vec![
                ("report.json", a_report_j.clone()),
                ("attestations.json", attestations_j.clone()),
                ("attestors.json", trusting_custodian.clone()),
                (
                    "assurance.json",
                    statement("root_sums", AssuranceLevel::IssuerAttested),
                ),
            ],
        )?;

        add(
            "assurance-statement-for-another-report",
            "assurance",
            &["report-v1", "proof-v1", "assurance-v1"],
            "a statement naming a different report",
            "reject",
            Some("digest_mismatch"),
            vec![
                ("report.json", a_report_j.clone()),
                ("proof.json", a_proof_j.clone()),
                (
                    "assurance.json",
                    tweak(
                        &statement("root_sums", AssuranceLevel::CryptographicallyVerified),
                        &digest,
                        &"0".repeat(64),
                    ),
                ),
            ],
        )?;

        add(
            "assurance-unknown-field",
            "assurance",
            &["report-v1", "proof-v1", "assurance-v1"],
            "a level declared for a field the format does not define",
            "reject",
            Some("unknown_field"),
            vec![
                ("report.json", a_report_j.clone()),
                ("proof.json", a_proof_j.clone()),
                (
                    "assurance.json",
                    statement("solvency_vibes", AssuranceLevel::ClaimedOnly),
                ),
            ],
        )?;
    }

    // --- temporal comparability (§18.4) ---
    {
        let (stale_custody, stale_liabilities, stale_statement) = golden::stale_pairing_fixture();
        add(
            "coverage-stale-pairing",
            "coverage",
            &["report-v1", "report-v2", "coverage-v1", "leaf-v2"],
            "custody and liabilities three months apart, presented as one solvency claim",
            "reject",
            Some("temporal_mismatch"),
            vec![
                ("custody.json", serde_json::to_value(&stale_custody)?),
                (
                    "liabilities.json",
                    serde_json::to_value(&stale_liabilities)?,
                ),
                ("statement.json", serde_json::to_value(&stale_statement)?),
            ],
        )?;
    }

    // --- evidence provenance (§17) ---
    //
    // The pair that carries the section: one graph in which `root_sums` may
    // honestly be ledger-derived and `mark_prices` may not, because the graph
    // says the prices came from a vendor. §16 alone could not tell them apart,
    // since the anchor covers the whole report.
    {
        use crate::assurance::{AssuranceLevel, ASSURANCE_FORMAT_VERSION};
        let (pr_report, pr_graph) = golden::provenance_fixture();
        let pr_report_j = serde_json::to_value(&pr_report)?;
        let pr_graph_j = serde_json::to_value(&pr_graph)?;
        let pr_digest = crate::digest::report_digest_hex(&pr_report.report);
        let pr_anchor = crate::anchor::Anchor {
            format_version: crate::anchor::ANCHOR_FORMAT_VERSION.to_string(),
            report_digest: pr_digest.clone(),
            root_hash: pr_report.report.root_hash.clone(),
            snapshot_time: pr_report.report.snapshot_time.clone(),
            ledger_offset: pr_report.report.ledger_offset.clone(),
            publisher: pr_report.report.publisher.clone(),
            publisher_key: pr_report.signature.public_key.clone(),
            prev_anchor: None,
        };
        let pr_anchor_j = serde_json::to_value(&pr_anchor)?;
        let level_for = |field: &str, level: AssuranceLevel| -> serde_json::Value {
            json!({
                "format_version": ASSURANCE_FORMAT_VERSION,
                "report_digest": pr_digest,
                "levels": { field: level.as_str() },
            })
        };

        add(
            "provenance-well-formed",
            "provenance",
            &["report-v1", "provenance-v1"],
            "a signed graph naming participants, a template and a price vendor",
            "accept",
            None,
            vec![
                ("report.json", pr_report_j.clone()),
                ("provenance.json", pr_graph_j.clone()),
            ],
        )?;

        add(
            "provenance-dangling-source",
            "provenance",
            &["report-v1", "provenance-v1"],
            "a derivation naming a source the graph does not declare",
            "reject",
            Some("provenance_inconsistent"),
            vec![
                ("report.json", pr_report_j.clone()),
                ("provenance.json", {
                    let mut g = pr_graph.provenance.clone();
                    g.derivations[0].sources[1] = "ghost-template".to_string();
                    serde_json::to_value(golden::sign_provenance(g))?
                }),
            ],
        )?;

        add(
            "provenance-off-ledger-without-basis",
            "provenance",
            &["report-v1", "provenance-v1"],
            "an off-ledger source with nothing saying how the figure arrives",
            "reject",
            Some("provenance_inconsistent"),
            vec![
                ("report.json", pr_report_j.clone()),
                ("provenance.json", {
                    let mut g = pr_graph.provenance.clone();
                    g.sources[2].basis = None;
                    serde_json::to_value(golden::sign_provenance(g))?
                }),
            ],
        )?;

        // §17.4. Identical graph, identical anchor; the only difference is
        // which field is declared ledger-derived.
        add(
            "provenance-ledger-derived-honest",
            "provenance",
            &["report-v1", "provenance-v1", "assurance-v1"],
            "root_sums declared ledger-derived, and the graph names a participant",
            "accept",
            None,
            vec![
                ("report.json", pr_report_j.clone()),
                ("provenance.json", pr_graph_j.clone()),
                (
                    "assurance.json",
                    level_for("root_sums", AssuranceLevel::LedgerDerived),
                ),
            ],
        )?;

        add(
            "provenance-ledger-derived-contradiction",
            "provenance",
            &["report-v1", "provenance-v1", "assurance-v1"],
            "mark_prices declared ledger-derived, and the graph says a price vendor",
            "reject",
            Some("provenance_inconsistent"),
            vec![
                ("report.json", pr_report_j.clone()),
                ("provenance.json", pr_graph_j.clone()),
                (
                    "assurance.json",
                    level_for("mark_prices", AssuranceLevel::LedgerDerived),
                ),
            ],
        )?;

        // §16.4: the anchor half alone is not enough, which is the rule the
        // section gained because of §17.
        add(
            "assurance-ledger-derived-with-graph",
            "assurance",
            &["report-v1", "assurance-v1", "anchor-v1", "provenance-v1"],
            "ledger-derived with both an anchor and an on-ledger derivation",
            "accept",
            None,
            vec![
                ("report.json", pr_report_j.clone()),
                ("anchor.json", pr_anchor_j.clone()),
                ("provenance.json", pr_graph_j.clone()),
                (
                    "assurance.json",
                    level_for("root_sums", AssuranceLevel::LedgerDerived),
                ),
            ],
        )?;

        add(
            "assurance-ledger-derived-anchor-only",
            "assurance",
            &["report-v1", "assurance-v1", "anchor-v1"],
            "ledger-derived on an anchor alone, with no graph saying where the figure came from",
            "reject",
            Some("over_claimed"),
            vec![
                ("report.json", pr_report_j.clone()),
                ("anchor.json", pr_anchor_j.clone()),
                (
                    "assurance.json",
                    level_for("root_sums", AssuranceLevel::LedgerDerived),
                ),
            ],
        )?;
    }

    // §15.1 requires a member name to be a plain file name. An index naming a
    // path is a delivery instruction rather than an integrity claim, and
    // nothing exercised the rule.
    {
        // Signed with the bad name, not edited afterwards: §15.3 checks the
        // signature before the names, so an index tampered with in transit is
        // caught as a forgery and never reaches the name rule. The rule exists
        // for a publisher who meant it.
        let mut escaping_pack = pack.pack.clone();
        escaping_pack.entries[0].name = "../escape.json".to_string();
        let escaping = crate::pack::SignedPack {
            signature: crate::document::SignatureBlock {
                algorithm: "ed25519".to_string(),
                public_key: golden::signer().public_key_hex(),
                value: golden::signer().sign_digest(&crate::pack::pack_digest(&escaping_pack)),
            },
            pack: escaping_pack,
        };
        let dir = out.join("pack-unsafe-name");
        std::fs::create_dir_all(&dir)?;
        write(&dir, "pack.json", &serde_json::to_value(&escaping)?)?;
        let mut names = vec!["pack.json".to_string()];
        for (name, bytes) in &pack_members {
            std::fs::write(dir.join(name), bytes)?;
            names.push(name.clone());
        }
        cases.push(json!({
            "id": "pack-unsafe-name", "kind": "pack",
            "requires": ["pack-v1"],
            "description": "an index naming a path rather than a file",
            "expect": "reject", "failure": "unsafe_name", "files": names,
        }));
    }

    // The pack index carries its own version, and §15.3 checks it first.
    {
        let mut wrong = pack.clone();
        wrong.pack.format_version = "canton-solvency-pack-v9".to_string();
        let dir = out.join("pack-unknown-version");
        std::fs::create_dir_all(&dir)?;
        write(&dir, "pack.json", &serde_json::to_value(&wrong)?)?;
        let mut names = vec!["pack.json".to_string()];
        for (name, bytes) in &pack_members {
            std::fs::write(dir.join(name), bytes)?;
            names.push(name.clone());
        }
        cases.push(json!({
            "id": "pack-unknown-version", "kind": "pack",
            "requires": ["pack-v1"],
            "description": "a pack index claiming a format version this verifier does not know",
            "expect": "reject", "failure": "unsupported_version", "files": names,
        }));
    }

    // --- evidence packs (SPEC §15) ---
    // A pack case is a directory of raw member files plus the signed index.
    // The runner reads the directory itself, because what is under test is
    // whether the delivery matches the index — not whether a named file parses.
    {
        let pack_j = serde_json::to_value(&pack)?;
        let write_pack = |id: &str,
                          drop: Option<&str>,
                          alter: Option<&str>,
                          extra: bool|
         -> anyhow::Result<Vec<String>> {
            let dir = out.join(id);
            std::fs::create_dir_all(&dir)?;
            let mut names = vec!["pack.json".to_string()];
            std::fs::write(
                dir.join("pack.json"),
                format!("{}\n", serde_json::to_string_pretty(&pack_j)?),
            )?;
            for (name, bytes) in &pack_members {
                if drop == Some(name.as_str()) {
                    continue;
                }
                let bytes = if alter == Some(name.as_str()) {
                    // One trailing newline. The document still parses and
                    // still verifies on its own — which is exactly the point:
                    // only the index notices.
                    let mut altered = bytes.clone();
                    altered.push(b'\n');
                    altered
                } else {
                    bytes.clone()
                };
                std::fs::write(dir.join(name), &bytes)?;
                names.push(name.clone());
            }
            if extra {
                std::fs::write(dir.join("proof-mallory.json"), b"{}\n")?;
                names.push("proof-mallory.json".to_string());
            }
            Ok(names)
        };

        let files = write_pack("pack-valid", None, None, false)?;
        cases.push(json!({
            "id": "pack-valid", "kind": "pack",
            "requires": ["pack-v1"],
            "description": "a complete, unaltered delivery",
            "expect": "accept", "failure": null, "files": files,
        }));

        let files = write_pack("pack-dropped-proof", Some("proof.json"), None, false)?;
        cases.push(json!({
            "id": "pack-dropped-proof", "kind": "pack",
            "requires": ["pack-v1"],
            "description": "a delivery with a customer's proof removed",
            "expect": "reject", "failure": "pack_missing", "files": files,
        }));

        let files = write_pack("pack-altered-member", None, Some("proof.json"), false)?;
        cases.push(json!({
            "id": "pack-altered-member", "kind": "pack",
            "requires": ["pack-v1"],
            "description": "a member whose bytes differ from the index",
            "expect": "reject", "failure": "pack_altered", "files": files,
        }));

        let files = write_pack("pack-unlisted-member", None, None, true)?;
        cases.push(json!({
            "id": "pack-unlisted-member", "kind": "pack",
            "requires": ["pack-v1"],
            "description": "a file the index does not name",
            "expect": "reject", "failure": "pack_unlisted", "files": files,
        }));
    }

    write(
        out,
        "manifest.json",
        &json!({
            "format_version": "canton-solvency-conformance-v1",
            "description": "Cases any implementation must agree on to claim compatibility with this format.",
            "trusted_key": key,
            "cases": cases,
        }),
    )?;
    Ok(cases.len())
}
