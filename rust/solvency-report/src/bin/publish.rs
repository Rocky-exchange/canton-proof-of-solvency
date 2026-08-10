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
use canton_solvency_report::pack::build_pack;
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

    // Ordered by the derived salt, not by the identifier.
    //
    // §4 lets the producer pick any stable order, and ascending `user_id` is
    // the obvious one. It is also attackable. A proof discloses its sibling's
    // sums, and at leaf level the sibling is one other customer, so whoever
    // lands as your pair learns your exact balances. Under identifier order,
    // an attacker who can influence their own identifier chooses where they
    // land: register two accounts around a target — one to fix the parity of
    // the target's index, one to occupy the pair position — and the second
    // account's own proof discloses the target's balances. Two accounts and no
    // special access.
    //
    // The salt is `HMAC(master_salt, user_id)`, and the master salt is a
    // per-snapshot secret. Ordering by it is just as stable and deterministic
    // for the producer, and unpredictable to everyone else: an attacker cannot
    // aim at a chosen victim because they cannot predict where any identifier
    // lands.
    //
    // The trade is worth stating. A fixed order leaks the same neighbour every
    // snapshot; a rotating one leaks a different random neighbour each time.
    // Neither dominates — what this removes is *targeting*, which is the part
    // an attacker controls.
    let mut leaves: Vec<LeafInput> = users
        .into_iter()
        .map(|(user_id, balances)| LeafInput {
            salt: canton_solvency_merkle::leaf_salt(master_salt.as_bytes(), &user_id),
            user_id,
            balances,
        })
        .collect();
    leaves.sort_by(|a, b| a.salt.cmp(&b.salt).then_with(|| a.user_id.cmp(&b.user_id)));
    Ok(leaves)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// A filename for one customer's proof that is distinct for every distinct
/// customer.
///
/// Replacing every non-alphanumeric character with `_` is not enough on its
/// own: `alice-1`, `alice_1` and `alice 1` are three different customers and
/// one filename, so two of the three proofs were silently overwritten by the
/// third. The pack index caught the duplicate afterwards, but only after the
/// files were written and with a message about the pack rather than about the
/// customers.
///
/// When sanitising loses nothing, the readable name is kept. When it loses
/// something, a digest of the *full* identifier is appended, which restores
/// what the sanitising threw away. The two forms cannot collide with each
/// other either: a lossless name is alphanumeric throughout and a suffixed one
/// always contains a `-`.
fn proof_filename(user_id: &str) -> String {
    let safe: String = user_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if safe == user_id {
        return format!("proof-{safe}.json");
    }
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(user_id.as_bytes()));
    format!("proof-{safe}-{}.json", &digest[..8])
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
    // Every file is remembered as it is written, so the pack index commits to
    // exactly the bytes that landed on disk rather than to a re-serialisation
    // of them.
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    let mut write = |name: &str, value: serde_json::Value| -> Result<()> {
        let bytes = format!("{}\n", serde_json::to_string_pretty(&value)?).into_bytes();
        std::fs::write(args.out.join(name), &bytes)?;
        members.push((name.to_string(), bytes));
        Ok(())
    };
    write(
        "report.json",
        serde_json::to_value(&published.signed_report)?,
    )?;
    write("anchor.json", serde_json::to_value(&anchor)?)?;
    for proof in &published.proofs {
        write(
            &proof_filename(&proof.leaf.user_id),
            serde_json::to_value(proof)?,
        )?;
    }

    // The evidence pack (SPEC §15). Without it an auditor cannot tell a
    // complete delivery from one with a customer's proof quietly removed:
    // every file that did arrive verifies either way.
    let pack = build_pack(
        &published.signed_report.report.publisher,
        &published.signed_report.report.snapshot_time,
        &canton_solvency_report::digest::report_digest_hex(&published.signed_report.report),
        &members,
        &signer,
    )?;
    std::fs::write(
        args.out.join("pack.json"),
        format!("{}\n", serde_json::to_string_pretty(&pack)?),
    )?;

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
    println!("pack         : {} members, signed", pack.pack.entries.len());
    println!(
        "wrote {} files to {}",
        published.proofs.len() + 3,
        args.out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{proof_filename, read_balances};

    /// Leaves must not be ordered by identifier.
    ///
    /// A proof discloses its sibling's sums, and at leaf level the sibling is
    /// one other customer. Under identifier order an attacker who can
    /// influence their own identifier picks who that is: two accounts, one to
    /// fix the parity of the target's index and one to occupy the pair
    /// position, and the second account's proof carries the target's exact
    /// balances. Ordering by the per-snapshot derived salt removes the
    /// targeting, because nobody without the master salt can predict where an
    /// identifier lands.
    #[test]
    fn leaves_are_ordered_unpredictably_not_by_identifier() {
        let dir = std::env::temp_dir().join("cps-order-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("balances.csv");
        std::fs::write(
            &path,
            "aaa,USDA,1\naab,USDA,1\nvictim,USDA,9\nvictin,USDA,1\nzzz,USDA,1\n",
        )
        .unwrap();

        let leaves = read_balances(&path, "a-master-salt").unwrap();
        let ids: Vec<&str> = leaves.iter().map(|l| l.user_id.as_str()).collect();

        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_ne!(
            ids, sorted,
            "leaves came out in identifier order, which lets an attacker choose \
             whose balance their own proof discloses"
        );

        // Still a total order over the same set: nothing is lost or duplicated.
        let mut round_trip = ids.clone();
        round_trip.sort_unstable();
        assert_eq!(round_trip, sorted);
    }

    /// The order must be stable for a given snapshot, or two runs over the
    /// same input would publish different roots.
    #[test]
    fn the_order_is_deterministic_for_one_snapshot() {
        let dir = std::env::temp_dir().join("cps-order-stable");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("balances.csv");
        std::fs::write(&path, "a,USDA,1\nb,USDA,2\nc,USDA,3\nd,USDA,4\n").unwrap();

        let first: Vec<String> = read_balances(&path, "salt-one")
            .unwrap()
            .iter()
            .map(|l| l.user_id.clone())
            .collect();
        let again: Vec<String> = read_balances(&path, "salt-one")
            .unwrap()
            .iter()
            .map(|l| l.user_id.clone())
            .collect();
        assert_eq!(first, again, "the same snapshot must order identically");

        // A different snapshot salt reorders, so a pairing does not persist.
        let other: Vec<String> = read_balances(&path, "salt-two")
            .unwrap()
            .iter()
            .map(|l| l.user_id.clone())
            .collect();
        assert_ne!(first, other, "a new snapshot should reshuffle the pairing");
    }

    /// The bug this guards: `alice-1`, `alice_1` and `alice 1` are three
    /// customers and used to be one filename, so two proofs were overwritten
    /// by the third before anything noticed.
    #[test]
    fn customers_that_sanitise_alike_still_get_distinct_files() {
        let names: Vec<String> = ["alice-1", "alice_1", "alice 1", "alice.1", "alice/1"]
            .iter()
            .map(|u| proof_filename(u))
            .collect();
        let unique: std::collections::BTreeSet<&String> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "collision among {names:?}");
    }

    /// An identifier that needs no sanitising keeps the readable name, so the
    /// ordinary case is unchanged.
    #[test]
    fn an_ordinary_identifier_keeps_its_readable_name() {
        assert_eq!(proof_filename("alice"), "proof-alice.json");
        assert_eq!(proof_filename("u2"), "proof-u2.json");
    }

    /// A sanitised name always carries a `-`, and a clean one never can, so the
    /// two forms cannot meet in the middle.
    #[test]
    fn a_sanitised_name_cannot_collide_with_a_clean_one() {
        let clean = proof_filename("aliceX1");
        let dirty = proof_filename("alice X1");
        assert_ne!(clean, dirty);
        assert!(!clean.trim_start_matches("proof-").contains('-'));
        assert!(dirty.contains('-'));
    }

    /// Distinct identifiers that sanitise identically must differ in the
    /// digest, which is taken over the full identifier rather than the
    /// sanitised form.
    #[test]
    fn the_digest_is_over_the_identifier_not_the_sanitised_name() {
        assert_ne!(proof_filename("a b"), proof_filename("a\tb"));
    }
}
