//! Emits this implementation's §14.5 compatibility statement.
//!
//! Usage: cargo run --example emit_statement -- statements/rust.json
//!
//! A statement nobody can diff against is decoration. The value appears when
//! two implementations publish one over the same corpus: they then disagree at
//! a *named case* rather than in a prose report that "we tested it". The
//! cross-implementation check in tests/statements.rs is what turns these files
//! into an assertion.
use canton_solvency_report::compat::{build_statement, SUPPORTED};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "statements/rust.json".into())
        .into();
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
    let statement = build_statement("canton-solvency-report (Rust)", SUPPORTED, &corpus)?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &out,
        format!("{}\n", serde_json::to_string_pretty(&statement)?),
    )?;
    println!(
        "wrote {} ({} cases, {} claimed features)",
        out.display(),
        statement.results.len(),
        statement.supports.len()
    );
    Ok(())
}
