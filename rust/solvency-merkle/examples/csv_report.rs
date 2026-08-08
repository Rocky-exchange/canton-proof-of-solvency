//! Build a solvency commitment from a CSV of balances and verify one proof.
//!
//! Usage:
//!   cargo run --example csv_report -- balances.csv my-master-salt
//!
//! CSV format (no header): user_id,asset,amount
//!   alice,USDA,100.5
//!   alice,CBTC,0.25
//!   bob,USDA,7
use canton_solvency_merkle::{
    format_amount_18dp, leaf_node, leaf_salt, parse_amount_18dp, verify_proof, Node, SumTree,
};
use std::collections::BTreeMap;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (csv_path, master_salt) = match (args.next(), args.next()) {
        (Some(p), Some(s)) => (p, s),
        _ => {
            eprintln!("usage: csv_report <balances.csv> <master-salt>");
            std::process::exit(2);
        }
    };

    let mut users: BTreeMap<String, Vec<(String, u128)>> = BTreeMap::new();
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
        users
            .entry(user.to_string())
            .or_default()
            .push((asset.to_string(), parse_amount_18dp(amount)?));
    }

    let mut leaves: Vec<Node> = Vec::new();
    let ids: Vec<&String> = users.keys().collect();
    for (user, balances) in &users {
        let salt = leaf_salt(master_salt.as_bytes(), user);
        leaves.push(leaf_node(&salt, user, balances)?);
    }
    let tree = SumTree::build(leaves.clone())?;

    println!("users committed : {}", ids.len());
    println!("merkle root     : {}", hex::encode(tree.root().hash));
    for (asset, total) in &tree.root().sums {
        println!("total {asset:<8}: {}", format_amount_18dp(*total));
    }

    // Prove and verify the first user, end to end.
    let proof = tree.prove(0)?;
    let ok = verify_proof(&leaves[0], &proof, tree.root());
    println!(
        "proof for {:<8}: {} ({} siblings)",
        ids[0],
        if ok { "VERIFIED" } else { "FAILED" },
        proof.steps.len()
    );
    Ok(())
}
