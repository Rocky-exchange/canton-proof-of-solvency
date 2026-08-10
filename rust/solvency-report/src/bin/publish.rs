//! `canton-solvency-publish` — produce a signed report from a balance file.
//!
//! The counterpart to `canton-solvency-verify`. An institution that can export
//! balances as CSV can publish a conforming report without writing code, which
//! is what M4's publishing path is for: the console designs the manifest, this
//! consumes it.
//!
//! The signing seed is read from a file, never from an argument, because a
//! command line is readable by every other process on the host.

use anyhow::{bail, Context, Result};
use canton_solvency_report::anchor::{anchor_report, Anchor};
use canton_solvency_report::document::Disclosures;
use canton_solvency_report::manifest::Manifest;
use canton_solvency_report::produce::{publish, LeafInput, ReportMetadata};
use canton_solvency_report::sign::ReportSigner;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const USAGE: &str = "\
canton-solvency-publish — produce a signed solvency report

USAGE:
  canton-solvency-publish --balances <csv> --key-file <path> --publisher <party>
                          --snapshot-time <rfc3339> --ledger-offset <offset>
                          --out <dir> [--manifest <json>] [--prev-anchor <json>]

  --balances       CSV of user_id,asset,amount (no header)
  --key-file       32-byte signing seed as hex. Never passed as an argument.
  --manifest       a manifest from the disclosure designer; publishes format v2
  --prev-anchor    the previous anchor, so the new one links to it

Writes report.json, anchor.json, and one proof per user.";

struct Args {
    balances: PathBuf,
    key_file: PathBuf,
    publisher: String,
    snapshot_time: String,
    ledger_offset: String,
    out: PathBuf,
    manifest: Option<PathBuf>,
    prev_anchor: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut flags: BTreeMap<String, String> = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--help" || flag == "-h" {
            println!("{USAGE}");
            std::process::exit(0);
        }
        let value = args
            .next()
            .with_context(|| format!("{flag} needs a value"))?;
        flags.insert(flag, value);
    }
    let need = |name: &str| -> Result<String> {
        flags
            .get(name)
            .cloned()
            .with_context(|| format!("{name} is required\n\n{USAGE}"))
    };
    Ok(Args {
        balances: need("--balances")?.into(),
        key_file: need("--key-file")?.into(),
        publisher: need("--publisher")?,
        snapshot_time: need("--snapshot-time")?,
        ledger_offset: need("--ledger-offset")?,
        out: need("--out")?.into(),
        manifest: flags.get("--manifest").map(PathBuf::from),
        prev_anchor: flags.get("--prev-anchor").map(PathBuf::from),
    })
}

/// Read from a file so the seed never appears in the process table.
fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes = hex::decode(text.trim()).context("the key file is not hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("the signing seed must be exactly 32 bytes"))
}

fn read_balances(path: &Path, master_salt: &str) -> Result<Vec<LeafInput>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut users: BTreeMap<String, BTreeMap<String, u128>> = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split(',').map(str::trim).collect();
        if cols.len() < 3 || cols[0].is_empty() || cols[1].is_empty() {
            bail!("row {}: expected user_id,asset,amount", i + 1);
        }
        let amount = canton_solvency_merkle::parse_amount_18dp(cols[2])
            .with_context(|| format!("row {}", i + 1))?;
        if users
            .entry(cols[0].to_string())
            .or_default()
            .insert(cols[1].to_string(), amount)
            .is_some()
        {
            bail!("row {}: {} appears twice for {}", i + 1, cols[1], cols[0]);
        }
    }
    anyhow::ensure!(!users.is_empty(), "no balances in the file");

    // Ascending user id: the stable order SPEC §4 requires.
    Ok(users
        .into_iter()
        .map(|(user_id, balances)| LeafInput {
            salt: canton_solvency_merkle::leaf_salt(master_salt.as_bytes(), &user_id),
            user_id,
            balances,
        })
        .collect())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn main() -> Result<()> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    };

    let seed = read_seed(&args.key_file)?;
    let signer = ReportSigner::from_seed(&seed);
    // Derived from the seed and the snapshot, so it rotates per report without
    // the operator managing a second secret, and two snapshots never share
    // leaf salts (SPEC §3).
    let master_salt = format!("{}-{}", hex::encode(seed), args.snapshot_time);
    let leaves = read_balances(&args.balances, &master_salt)?;

    let manifest: Option<Manifest> = args.manifest.as_deref().map(read_json).transpose()?;

    let meta = ReportMetadata {
        profile: "solvency.liabilities".to_string(),
        publisher: args.publisher,
        snapshot_time: args.snapshot_time,
        ledger_offset: args.ledger_offset,
        mark_prices: BTreeMap::new(),
        disclosures: Disclosures::default(),
        manifest,
    };
    let published = publish(&leaves, &meta, &signer)?;

    let previous: Option<Anchor> = args.prev_anchor.as_deref().map(read_json).transpose()?;
    let anchor = anchor_report(&published.signed_report, previous.as_ref());

    std::fs::create_dir_all(&args.out)?;
    let write = |name: &str, value: serde_json::Value| -> Result<()> {
        std::fs::write(
            args.out.join(name),
            format!("{}\n", serde_json::to_string_pretty(&value)?),
        )?;
        Ok(())
    };
    write(
        "report.json",
        serde_json::to_value(&published.signed_report)?,
    )?;
    write("anchor.json", serde_json::to_value(&anchor)?)?;
    for proof in &published.proofs {
        let safe: String = proof
            .leaf
            .user_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        write(&format!("proof-{safe}.json"), serde_json::to_value(proof)?)?;
    }

    println!("users        : {}", published.proofs.len());
    println!(
        "root         : {}",
        published.signed_report.report.root_hash
    );
    println!(
        "format       : {}",
        published.signed_report.report.format_version
    );
    println!("public key   : {}", signer.public_key_hex());
    println!(
        "anchor       : {}",
        if anchor.prev_anchor.is_some() {
            "links to the previous report"
        } else {
            "genesis"
        }
    );
    println!(
        "wrote {} files to {}",
        published.proofs.len() + 2,
        args.out.display()
    );
    Ok(())
}
