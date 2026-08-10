//! `verify-pack` — check a whole delivery, not just its parts (SPEC §15).
//!
//! `verify` answers "does this proof belong to this report?". It cannot
//! answer "is this all of them?", because nothing in a proof says what else
//! was sent. A pack's signed index does, so this runs both checks in order:
//! the delivery is complete and unaltered, and then everything in it verifies.
//!
//! The index is checked first deliberately. If a proof is missing, saying so
//! is more useful than reporting that the 999 proofs which did arrive all
//! passed — which is true, and beside the point.

use crate::args::{Command, ProofSource};
use crate::run::{run, Summary};
use anyhow::{Context, Result};
use canton_solvency_report::pack::{verify_pack, PackFailure, SignedPack};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The name a pack index is always delivered under, so an auditor does not
/// have to be told which file is the index.
pub const PACK_FILE: &str = "pack.json";

pub struct PackSummary {
    pub publisher: String,
    pub snapshot_time: String,
    pub report_digest: String,
    pub members: usize,
    /// `None` when the delivery matches its index.
    pub index_failure: Option<PackFailure>,
    /// Content verification, run only once the delivery is known to be whole.
    pub contents: Option<Summary>,
}

impl PackSummary {
    pub fn all_passed(&self) -> bool {
        self.index_failure.is_none() && self.contents.as_ref().is_some_and(Summary::all_passed)
    }
}

/// Read every file in `dir` except the index itself.
fn delivered(dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut members = BTreeMap::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };
        if name == PACK_FILE {
            continue;
        }
        members.insert(
            name,
            std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
        );
    }
    Ok(members)
}

pub fn run_pack(command: &Command) -> Result<PackSummary> {
    let (pack_dir, trusted_key) = match command {
        Command::VerifyPack {
            pack_dir,
            trusted_key,
            ..
        } => (pack_dir, trusted_key),
        _ => anyhow::bail!("run_pack expects verify-pack"),
    };

    let index_path = pack_dir.join(PACK_FILE);
    let text = std::fs::read_to_string(&index_path)
        .with_context(|| format!("reading {}", index_path.display()))?;
    let signed: SignedPack =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", index_path.display()))?;

    let members = delivered(pack_dir)?;
    let index_failure = verify_pack(&signed, trusted_key, &members).err();

    // Only verify contents once the delivery is known to be the intended one.
    // Verifying what arrived after establishing that something did not is how
    // an incomplete delivery gets reported as a clean run.
    let contents = if index_failure.is_none() {
        Some(run(&Command::Verify {
            report: pack_dir.join("report.json"),
            proofs: ProofSource::Dir(PathBuf::from(pack_dir)),
            trusted_key: trusted_key.clone(),
            json: false,
        })?)
    } else {
        None
    };

    Ok(PackSummary {
        publisher: signed.pack.publisher.clone(),
        snapshot_time: signed.pack.snapshot_time.clone(),
        report_digest: signed.pack.report_digest.clone(),
        members: signed.pack.entries.len(),
        index_failure,
        contents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_solvency_report::pack::build_pack;
    use canton_solvency_report::sign::ReportSigner;

    const KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

    fn fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        std::fs::read(path).expect("fixture is checked in")
    }

    /// The golden report and proof, packed under the golden signing key so the
    /// content verification inside `run_pack` has something real to check.
    fn packed_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let members = vec![
            ("report.json".to_string(), fixture("report.golden.json")),
            ("proof-u2.json".to_string(), fixture("proof.golden.json")),
        ];
        for (name, bytes) in &members {
            std::fs::write(dir.path().join(name), bytes).unwrap();
        }
        // The golden signing seed, so one --key verifies the index and the
        // report both -- which is the ordinary case: a publisher signs its own
        // delivery.
        let signer = ReportSigner::from_seed(&[1u8; 32]);
        let signed = build_pack(
            "venue::rocky",
            "2026-01-01T00:00:00Z",
            "aa11",
            &members,
            &signer,
        )
        .unwrap();
        std::fs::write(
            dir.path().join(PACK_FILE),
            serde_json::to_string_pretty(&signed).unwrap(),
        )
        .unwrap();
        dir
    }

    fn command(dir: &Path, key: &str) -> Command {
        Command::VerifyPack {
            pack_dir: dir.to_path_buf(),
            trusted_key: key.to_string(),
            json: false,
        }
    }

    #[test]
    fn a_complete_delivery_passes_the_index_check() {
        let dir = packed_dir();
        let summary = run_pack(&command(dir.path(), KEY)).unwrap();
        assert_eq!(summary.index_failure, None);
        assert_eq!(summary.members, 2);
    }

    #[test]
    fn a_dropped_proof_fails_even_though_every_remaining_file_verifies() {
        let dir = packed_dir();
        std::fs::remove_file(dir.path().join("proof-u2.json")).unwrap();
        let summary = run_pack(&command(dir.path(), KEY)).unwrap();
        assert_eq!(
            summary.index_failure,
            Some(PackFailure::Missing {
                name: "proof-u2.json".to_string()
            })
        );
        assert!(!summary.all_passed());
    }

    /// Content verification must not run on a delivery already known to be
    /// wrong, or a partial delivery reads as a clean run with fewer proofs.
    #[test]
    fn contents_are_not_verified_once_the_index_has_failed() {
        let dir = packed_dir();
        std::fs::remove_file(dir.path().join("proof-u2.json")).unwrap();
        let summary = run_pack(&command(dir.path(), KEY)).unwrap();
        assert!(summary.contents.is_none());
    }

    #[test]
    fn a_file_slipped_into_the_delivery_fails() {
        let dir = packed_dir();
        std::fs::write(dir.path().join("proof-mallory.json"), b"{}").unwrap();
        let summary = run_pack(&command(dir.path(), KEY)).unwrap();
        assert_eq!(
            summary.index_failure,
            Some(PackFailure::Unlisted {
                name: "proof-mallory.json".to_string()
            })
        );
    }

    #[test]
    fn an_intact_delivery_also_verifies_its_contents() {
        let dir = packed_dir();
        let summary = run_pack(&command(dir.path(), KEY)).unwrap();
        let contents = summary
            .contents
            .as_ref()
            .expect("contents run on an intact index");
        assert_eq!(contents.outcomes.len(), 1);
        assert!(summary.all_passed(), "{:?}", contents.outcomes);
    }

    /// A pack signed by someone other than the trusted key is refused before
    /// any member is looked at.
    #[test]
    fn a_pack_from_an_untrusted_signer_is_refused() {
        let dir = packed_dir();
        let other = ReportSigner::from_seed(&[7u8; 32]).public_key_hex();
        let summary = run_pack(&command(dir.path(), &other)).unwrap();
        assert_eq!(summary.index_failure, Some(PackFailure::UnknownSigner));
    }

    #[test]
    fn a_missing_index_is_an_io_error_not_a_verification_failure() {
        let dir = tempfile::tempdir().unwrap();
        assert!(run_pack(&command(dir.path(), KEY)).is_err());
    }
}
