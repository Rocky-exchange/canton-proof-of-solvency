//! The `anchors` verb: walk a publisher's history (SPEC §12).
//!
//! Takes no key. An anchor is a public fact about a moment that has passed;
//! the chain rules are arithmetic over the documents, and demanding a key
//! would imply an assurance this check does not provide.

use crate::args::Command;
use anyhow::{Context, Result};
use canton_solvency_report::anchor::{verify_chain, Anchor};
use std::path::Path;

/// A directory of anchors is read in filename order, which is why a publisher
/// should name them so they sort chronologically. A single file may hold the
/// whole history as an array.
fn load_chain(path: &Path) -> Result<Vec<Anchor>> {
    if path.is_dir() {
        let mut files: Vec<_> = std::fs::read_dir(path)
            .with_context(|| format!("reading directory {}", path.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        anyhow::ensure!(
            !files.is_empty(),
            "no *.json anchors in {} — refusing to report a vacuous pass",
            path.display()
        );
        files
            .iter()
            .map(|p| {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?;
                serde_json::from_str(&text).with_context(|| format!("parsing {}", p.display()))
            })
            .collect()
    } else {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }
}

pub struct ChainSummary {
    pub anchors: usize,
    pub publisher: String,
    pub first: String,
    pub last: String,
    pub failure: Option<String>,
}

impl ChainSummary {
    pub fn intact(&self) -> bool {
        self.failure.is_none()
    }
}

pub fn run_anchors(command: &Command) -> Result<ChainSummary> {
    let Command::Anchors { chain, .. } = command else {
        anyhow::bail!("run_anchors called with a non-anchor command");
    };
    let anchors = load_chain(chain)?;
    anyhow::ensure!(!anchors.is_empty(), "the history is empty");

    Ok(ChainSummary {
        anchors: anchors.len(),
        publisher: anchors[0].publisher.clone(),
        first: anchors[0].snapshot_time.clone(),
        last: anchors[anchors.len() - 1].snapshot_time.clone(),
        failure: verify_chain(&anchors).err().map(|f| f.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use canton_solvency_report::anchor::{anchor_digest_hex, ANCHOR_FORMAT_VERSION};

    fn anchor(i: usize, prev: Option<&Anchor>) -> Anchor {
        Anchor {
            format_version: ANCHOR_FORMAT_VERSION.to_string(),
            report_digest: format!("{:02x}", i).repeat(32),
            root_hash: format!("{:02x}", i + 50).repeat(32),
            snapshot_time: format!("2026-01-{:02}T00:00:00Z", i + 1),
            ledger_offset: format!("{:018}", i * 10),
            publisher: "venue::one".to_string(),
            publisher_key: "ab".repeat(32),
            prev_anchor: prev.map(anchor_digest_hex),
        }
    }

    fn write_chain(n: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut chain: Vec<Anchor> = Vec::new();
        for i in 0..n {
            let next = anchor(i, chain.last());
            std::fs::write(
                dir.path().join(format!("{i:03}.json")),
                serde_json::to_string_pretty(&next).unwrap(),
            )
            .unwrap();
            chain.push(next);
        }
        dir
    }

    fn walk(dir: &Path) -> Result<ChainSummary> {
        run_anchors(&Command::Anchors {
            chain: dir.to_path_buf(),
            json: false,
        })
    }

    #[test]
    fn an_intact_history_walks_cleanly() {
        let dir = write_chain(4);
        let summary = walk(dir.path()).unwrap();
        assert!(summary.intact());
        assert_eq!(summary.anchors, 4);
        assert_eq!(summary.publisher, "venue::one");
        assert_eq!(summary.first, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn a_removed_day_is_reported_as_a_break() {
        let dir = write_chain(4);
        std::fs::remove_file(dir.path().join("002.json")).unwrap();
        let summary = walk(dir.path()).unwrap();
        assert!(!summary.intact());
        assert!(summary.failure.unwrap().contains("does not name"));
    }

    #[test]
    fn an_empty_directory_is_an_error_not_a_vacuous_pass() {
        let dir = tempfile::tempdir().unwrap();
        assert!(walk(dir.path()).is_err());
    }

    #[test]
    fn a_history_in_one_file_walks_too() {
        let dir = write_chain(3);
        let mut chain: Vec<Anchor> = Vec::new();
        for i in 0..3 {
            let next = anchor(i, chain.last());
            chain.push(next);
        }
        let path = dir.path().join("history.jsonl");
        std::fs::write(&path, serde_json::to_string(&chain).unwrap()).unwrap();

        let summary = run_anchors(&Command::Anchors {
            chain: path,
            json: false,
        })
        .unwrap();
        assert!(summary.intact());
        assert_eq!(summary.anchors, 3);
    }
}
