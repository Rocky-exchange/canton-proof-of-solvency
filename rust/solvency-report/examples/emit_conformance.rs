//! Emits the conformance corpus (SPEC §14.3): a set of cases any
//! implementation runs to claim compatibility.
//!
//! Usage: cargo run --example emit_conformance -- ./conformance
//!
//! Cases are derived from the golden fixtures, so the corpus cannot drift
//! from the vectors both implementations already assert.
use canton_solvency_report::golden;
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

fn main() -> anyhow::Result<()> {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "conformance".into());
    let out = Path::new(&out);
    std::fs::create_dir_all(out)?;

    let (report, proof) = golden::fixture();
    let (report_v2, proof_v2) = golden::fixture_v2();
    let (repo_report, repo_proof) = golden::repo_fixture();
    let (group_report, membership) = golden::group_fixture();
    let (custody, statement) = golden::coverage_fixture();
    let anchor = golden::anchor_fixture();
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
    let mut add = |id: &str,
                   kind: &str,
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

    // --- anchors ---
    let second = {
        let mut a = anchor.clone();
        a.snapshot_time = "2026-01-02T00:00:00Z".into();
        a.ledger_offset = "000000000000000043".into();
        a.prev_anchor = Some(canton_solvency_report::anchor::anchor_digest_hex(&anchor));
        serde_json::to_value(&a)?
    };
    add(
        "anchors-intact",
        "anchors",
        "a two-anchor history",
        "accept",
        None,
        vec![("history.json", json!([anchor_j.clone(), second.clone()]))],
    )?;
    add(
        "anchors-suffix",
        "anchors",
        "a history that does not start at genesis",
        "reject",
        Some("not_genesis"),
        vec![("history.json", json!([second.clone()]))],
    )?;
    add(
        "anchors-broken-link",
        "anchors",
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
                    &canton_solvency_report::anchor::anchor_digest_hex(&anchor)[..16],
                    "0000000000000000"
                )
            ]),
        )],
    )?;

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

    println!("wrote {} cases to {}", cases.len(), out.display());
    Ok(())
}
