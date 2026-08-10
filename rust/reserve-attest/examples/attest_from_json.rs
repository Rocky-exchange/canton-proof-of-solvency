//! Builds a signed custody report from a saved active-contracts response.
//!
//! Usage:
//!   attest_from_json <response.json> <offset> <asset-field> <amount-field>
//!                    <publisher> <snapshot-time>
//!
//! Separating the read from the commitment lets an operator capture a snapshot
//! with whatever tooling their participant needs, and commit it with this —
//! and it lets the whole pipeline be exercised against a real response without
//! this crate ever holding a ledger credential.
use canton_reserve_attest::{build::build_custody_report, parse_holdings, totals, HoldingFields};
use canton_solvency_report::produce::ReportMetadata;
use canton_solvency_report::sign::ReportSigner;
use std::collections::BTreeMap;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 6 {
        eprintln!(
            "usage: attest_from_json <response.json> <offset> <asset-field> \
             <amount-field> <publisher> <snapshot-time>"
        );
        std::process::exit(2);
    }

    let body = std::fs::read_to_string(&a[0])?;
    let fields = HoldingFields {
        asset: a[2].clone(),
        amount: a[3].clone(),
    };
    let positions = parse_holdings(&body, &fields)?;
    anyhow::ensure!(!positions.is_empty(), "the snapshot holds no positions");

    let meta = ReportMetadata {
        profile: "coverage.custody".to_string(),
        publisher: a[4].clone(),
        snapshot_time: a[5].clone(),
        ledger_offset: a[1].clone(),
        mark_prices: BTreeMap::new(),
        disclosures: Default::default(),
        manifest: None,
    };
    // A demo key. A real deployment signs with a key held in an HSM or KMS.
    let signer = ReportSigner::from_seed(&[5u8; 32]);
    let report = build_custody_report(&positions, &meta, &a[1], b"attest-demo-salt", &signer)?;

    println!("positions      : {}", positions.len());
    for (asset, total) in totals(&positions)? {
        println!(
            "  held {asset:<10}: {}",
            canton_solvency_merkle::format_amount_18dp(total)
        );
    }
    println!("root           : {}", report.report.root_hash);
    println!("offset         : {}", report.report.ledger_offset);
    println!("profile        : {}", report.report.profile);
    println!("signing key    : {}", signer.public_key_hex());
    Ok(())
}
