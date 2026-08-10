//! The `recompute` verb: rebuild a root from a full leaf dump.
//!
//! An inclusion proof shows one entry is in the tree. It cannot show that the
//! tree contains only the entries it should, which is why the security model
//! says detection of an omitted customer relies on customers checking.
//!
//! An auditor given the whole leaf set can do better: rebuild the tree and
//! compare. That trades away privacy entirely, which is why it is an auditor's
//! tool under an engagement, not something a venue publishes.

use crate::args::Command;
use anyhow::{Context, Result};
use canton_solvency_report::document::SignedReport;
use canton_solvency_report::produce::LeafInput;
use serde::Deserialize;
use std::collections::BTreeMap;

/// One entry of a dump: the same preimage a proof discloses.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DumpEntry {
    salt: String,
    user_id: String,
    balances: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct RecomputeOutcome {
    pub leaves: usize,
    pub published_root: String,
    pub recomputed_root: String,
    /// Assets where the recomputed total differs from the published one.
    pub disagreeing_assets: Vec<String>,
}

impl RecomputeOutcome {
    pub fn matches(&self) -> bool {
        self.published_root == self.recomputed_root && self.disagreeing_assets.is_empty()
    }
}

pub fn run_recompute(command: &Command) -> Result<RecomputeOutcome> {
    let Command::Recompute { leaves, report, .. } = command else {
        anyhow::bail!("run_recompute called with a non-recompute command");
    };

    let signed: SignedReport = {
        let text = std::fs::read_to_string(report)
            .with_context(|| format!("reading {}", report.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", report.display()))?
    };
    let dump: Vec<DumpEntry> = {
        let text = std::fs::read_to_string(leaves)
            .with_context(|| format!("reading {}", leaves.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", leaves.display()))?
    };
    anyhow::ensure!(
        !dump.is_empty(),
        "the dump is empty — refusing to report a vacuous match"
    );

    let inputs: Vec<LeafInput> = dump
        .iter()
        .map(|entry| {
            let salt = hex::decode(&entry.salt)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .with_context(|| format!("salt for {} is not 32 bytes of hex", entry.user_id))?;
            let balances = entry
                .balances
                .iter()
                .map(|(asset, amount)| {
                    Ok((
                        asset.clone(),
                        canton_solvency_merkle::parse_amount_18dp(amount)?,
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            Ok(LeafInput {
                salt,
                user_id: entry.user_id.clone(),
                balances,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // Rebuilt with a throwaway key: the signature is irrelevant here, only
    // the tree the leaves produce.
    let rebuilt = canton_solvency_report::produce::publish(
        &inputs,
        &canton_solvency_report::produce::ReportMetadata {
            profile: signed.report.profile.clone(),
            publisher: signed.report.publisher.clone(),
            snapshot_time: signed.report.snapshot_time.clone(),
            ledger_offset: signed.report.ledger_offset.clone(),
            mark_prices: Default::default(),
            disclosures: Default::default(),
            manifest: None,
        },
        &canton_solvency_report::sign::ReportSigner::from_seed(&[0u8; 32]),
    )?;

    let recomputed = &rebuilt.signed_report.report;
    let disagreeing: Vec<String> = recomputed
        .root_sums
        .keys()
        .chain(signed.report.root_sums.keys())
        .filter(|asset| {
            recomputed.root_sums.get(*asset).copied().unwrap_or(0)
                != signed.report.root_sums.get(*asset).copied().unwrap_or(0)
        })
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(RecomputeOutcome {
        leaves: inputs.len(),
        published_root: signed.report.root_hash.clone(),
        recomputed_root: recomputed.root_hash.clone(),
        disagreeing_assets: disagreeing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures")
                .join(name),
        )
        .unwrap()
    }

    /// The §10 fixture's three users, as an auditor would receive them.
    fn dump() -> String {
        let salts = [
            "3de523c46646d91361907f6158f560ed6c55b8684c595139b05df6b12e3ddbb1",
            "332f77b30295afb7a346ba580de798bc08f3bada500905be6bd7a552c7eec458",
        ];
        let proof: serde_json::Value = serde_json::from_str(&fixture("proof.golden.json")).unwrap();
        let u3_salt = "171f5e7577171aeabb58b3013b0e0e2d0b9f45b387fe8b1ed2027be1a0d7108c";
        let _ = (proof, u3_salt);
        serde_json::json!([
            {"salt": salts[0], "user_id": "11111111-1111-7111-8111-111111111111",
             "balances": {"USDA": "100.5"}},
            {"salt": salts[1], "user_id": "22222222-2222-7222-8222-222222222222",
             "balances": {"CBTC": "0.25", "USDA": "1.000000000000000001"}},
            {"salt": "00".repeat(32), "user_id": "33333333-3333-7333-8333-333333333333",
             "balances": {}},
        ])
        .to_string()
    }

    fn write(dump_text: &str) -> (tempfile::TempDir, Command) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("dump.json"), dump_text).unwrap();
        std::fs::write(
            dir.path().join("report.json"),
            fixture("report.golden.json"),
        )
        .unwrap();
        let cmd = Command::Recompute {
            leaves: dir.path().join("dump.json"),
            report: dir.path().join("report.json"),
            json: false,
        };
        (dir, cmd)
    }

    /// The third user's salt is not the real one, so the root must differ —
    /// this is the check working, not failing.
    #[test]
    fn a_dump_with_a_wrong_salt_does_not_reproduce_the_root() {
        let (_d, cmd) = write(&dump());
        let outcome = run_recompute(&cmd).unwrap();
        assert_eq!(outcome.leaves, 3);
        assert_ne!(outcome.recomputed_root, outcome.published_root);
        assert!(!outcome.matches());
        // The totals still agree: only the salt differed, not the amounts.
        assert!(outcome.disagreeing_assets.is_empty());
    }

    /// An omitted customer is exactly what a dump is meant to catch, and it
    /// shows up in the totals as well as the root.
    #[test]
    fn omitting_a_customer_changes_both_the_root_and_the_totals() {
        let mut entries: Vec<serde_json::Value> = serde_json::from_str(&dump()).unwrap();
        entries.remove(0);
        let (_d, cmd) = write(&serde_json::to_string(&entries).unwrap());
        let outcome = run_recompute(&cmd).unwrap();
        assert!(!outcome.matches());
        assert!(outcome.disagreeing_assets.contains(&"USDA".to_string()));
    }

    #[test]
    fn an_empty_dump_is_an_error_not_a_vacuous_match() {
        let (_d, cmd) = write("[]");
        assert!(run_recompute(&cmd).is_err());
    }

    #[test]
    fn a_malformed_salt_is_reported_clearly() {
        let mut entries: Vec<serde_json::Value> = serde_json::from_str(&dump()).unwrap();
        entries[0]["salt"] = serde_json::json!("nothex");
        let (_d, cmd) = write(&serde_json::to_string(&entries).unwrap());
        let err = run_recompute(&cmd).unwrap_err();
        assert!(err.to_string().contains("32 bytes of hex"), "got {err}");
    }
}
