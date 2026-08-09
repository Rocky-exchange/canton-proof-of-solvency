//! Build a signed solvency report from a CSV of balances and write the
//! publishable documents to disk.
//!
//! Usage:
//!   cargo run --example publish_report -- balances.csv my-master-salt ./out
//!
//! CSV format (no header): user_id,asset,amount
//!   alice,USDA,100.5
//!   alice,CBTC,0.25
//!   bob,USDA,7
//!
//! Writes `report.json` plus one `proof-<user_id>.json` per user, then
//! verifies every proof back against the report exactly as a recipient would.
use canton_solvency_merkle::{leaf_salt, parse_amount_18dp};
use canton_solvency_report::document::Disclosures;
use canton_solvency_report::produce::{publish, LeafInput, ReportMetadata};
use canton_solvency_report::sign::ReportSigner;
use canton_solvency_report::verify::verify;
use std::collections::BTreeMap;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (csv_path, master_salt, out_dir) = match (args.next(), args.next(), args.next()) {
        (Some(c), Some(m), Some(o)) => (c, m, o),
        _ => {
            eprintln!("usage: publish_report <balances.csv> <master-salt> <out-dir>");
            std::process::exit(2);
        }
    };

    let mut users: BTreeMap<String, BTreeMap<String, u128>> = BTreeMap::new();
    for (i, line) in std::fs::read_to_string(&csv_path)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split(',');
        let (user, asset, amount) = (
            cols.next().unwrap_or_default().trim(),
            cols.next().unwrap_or_default().trim(),
            cols.next().unwrap_or_default().trim(),
        );
        anyhow::ensure!(!user.is_empty() && !asset.is_empty(), "bad row {}", i + 1);
        if users
            .entry(user.to_string())
            .or_default()
            .insert(asset.to_string(), parse_amount_18dp(amount)?)
            .is_some()
        {
            anyhow::bail!("row {}: duplicate asset {asset:?} for {user:?}", i + 1);
        }
    }
    anyhow::ensure!(!users.is_empty(), "no balances in {csv_path}");

    // Leaves in a stable order (ascending user_id), as SPEC §4 requires.
    let leaves: Vec<LeafInput> = users
        .into_iter()
        .map(|(user_id, balances)| LeafInput {
            salt: leaf_salt(master_salt.as_bytes(), &user_id),
            user_id,
            balances,
        })
        .collect();

    // A demo key. A real publisher holds this in an HSM or KMS and publishes
    // the public half out of band — see SPEC §8 on key distribution.
    let signer = ReportSigner::from_seed(&[1u8; 32]);

    let metadata = ReportMetadata {
        profile: "solvency.liabilities".to_string(),
        publisher: "example::publisher".to_string(),
        snapshot_time: "2026-01-01T00:00:00Z".to_string(),
        ledger_offset: "000000000000000042".to_string(),
        mark_prices: BTreeMap::new(),
        disclosures: Disclosures::default(),
        manifest: None,
    };

    let published = publish(&leaves, &metadata, &signer)?;

    std::fs::create_dir_all(&out_dir)?;
    let report_path = format!("{out_dir}/report.json");
    std::fs::write(
        &report_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&published.signed_report)?
        ),
    )?;

    for proof in &published.proofs {
        let safe: String = proof
            .leaf
            .user_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        std::fs::write(
            format!("{out_dir}/proof-{safe}.json"),
            format!("{}\n", serde_json::to_string_pretty(proof)?),
        )?;
    }

    let trusted = signer.public_key_hex();
    for proof in &published.proofs {
        verify(&published.signed_report, proof, &trusted)
            .map_err(|e| anyhow::anyhow!("proof for {} failed: {e}", proof.leaf.user_id))?;
    }

    println!("users committed : {}", published.proofs.len());
    println!(
        "merkle root     : {}",
        published.signed_report.report.root_hash
    );
    println!("report digest   : {}", published.proofs[0].report_digest);
    println!("signing key     : {trusted}");
    for (asset, total) in &published.signed_report.report.root_sums {
        println!(
            "total {asset:<8}: {}",
            canton_solvency_merkle::format_amount_18dp(*total)
        );
    }
    println!(
        "wrote {} + {} proofs to {out_dir}/ ; all verified",
        report_path,
        published.proofs.len()
    );
    Ok(())
}
