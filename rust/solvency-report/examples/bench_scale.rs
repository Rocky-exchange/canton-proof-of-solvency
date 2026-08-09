//! Measures publication and verification at production scale.
//!
//! Usage:
//!   cargo run --release --example bench_scale -- [leaf_count] [proofs_to_verify]
//!
//! Prints wall-clock timings. Run with `--release`: a debug build is roughly
//! an order of magnitude slower and would give a misleading figure.
use canton_solvency_merkle::leaf_salt;
use canton_solvency_report::document::Disclosures;
use canton_solvency_report::produce::{publish, LeafInput, ReportMetadata};
use canton_solvency_report::sign::ReportSigner;
use canton_solvency_report::verify::verify;
use std::collections::BTreeMap;
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let leaf_count: usize = args
        .next()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(100_000);
    let sample: usize = args.next().map(|s| s.parse()).transpose()?.unwrap_or(1_000);

    if cfg!(debug_assertions) {
        eprintln!("warning: debug build — rerun with --release for a meaningful figure");
    }

    let started = Instant::now();
    let master = b"bench-master-salt";
    let leaves: Vec<LeafInput> = (0..leaf_count)
        .map(|i| {
            let user_id = format!("user-{i:08}");
            LeafInput {
                salt: leaf_salt(master, &user_id),
                balances: [
                    ("USDA".to_string(), (i as u128 + 1) * 1_000_000_000_000_000),
                    ("CBTC".to_string(), (i as u128 % 7) * 1_000_000_000_000),
                ]
                .into_iter()
                .collect(),
                user_id,
            }
        })
        .collect();
    let built = started.elapsed();

    let signer = ReportSigner::from_seed(&[3u8; 32]);
    let meta = ReportMetadata {
        profile: "solvency.liabilities".to_string(),
        publisher: "bench::publisher".to_string(),
        snapshot_time: "2026-08-09T00:00:00Z".to_string(),
        ledger_offset: "000000000000000001".to_string(),
        mark_prices: BTreeMap::new(),
        disclosures: Disclosures::default(),
    };

    let t = Instant::now();
    let published = publish(&leaves, &meta, &signer)?;
    let publish_time = t.elapsed();

    let trusted = signer.public_key_hex();
    // Spread the sample across the tree rather than taking a prefix: path
    // lengths differ, and the first leaves are not representative.
    let stride = (published.proofs.len() / sample.max(1)).max(1);
    let sampled: Vec<_> = published
        .proofs
        .iter()
        .step_by(stride)
        .take(sample)
        .collect();

    let t = Instant::now();
    for proof in &sampled {
        verify(&published.signed_report, proof, &trusted)
            .map_err(|e| anyhow::anyhow!("proof for {} failed: {e}", proof.leaf.user_id))?;
    }
    let verify_time = t.elapsed();

    let per_proof = verify_time.as_secs_f64() / sampled.len() as f64;
    let deepest = published
        .proofs
        .iter()
        .map(|p| p.steps.len())
        .max()
        .unwrap();

    println!("leaves              : {leaf_count}");
    println!("  build inputs      : {built:.2?}");
    println!("  publish (tree +");
    println!("   sign + proofs)   : {publish_time:.2?}");
    println!("  deepest path      : {deepest} steps");
    println!("verified            : {} proofs", sampled.len());
    println!("  total             : {verify_time:.2?}");
    println!("  per proof         : {:.3} ms", per_proof * 1000.0);
    println!(
        "  all {leaf_count} would be : {:.1?}",
        std::time::Duration::from_secs_f64(per_proof * leaf_count as f64)
    );
    Ok(())
}
