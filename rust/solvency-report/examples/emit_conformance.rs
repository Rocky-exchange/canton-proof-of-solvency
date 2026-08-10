//! Emits the conformance corpus (SPEC §14.3).
//!
//! Usage: cargo run --example emit_conformance -- ./conformance
//!
//! The generation itself lives in `canton_solvency_report::corpus_gen` so that
//! a test can regenerate into a temporary directory and compare, which is what
//! keeps the checked-in corpus honest about its own generator.
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "conformance".into())
        .into();
    let count = canton_solvency_report::corpus_gen::emit(&out)?;
    println!("wrote {count} cases to {}", out.display());
    Ok(())
}
