//! Guards the checked-in differential vectors against drift.
//!
//! The TypeScript suite recomputes `fixtures/cross-vectors.json` and compares.
//! That only means something if the file still reflects what this
//! implementation produces — a stale file would let both sides agree about a
//! value neither one computes any more.

use canton_solvency_merkle::*;
use canton_solvency_report::digest::report_digest;
use canton_solvency_report::document::Report;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn the_checked_in_vectors_match_what_this_implementation_computes() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cross-vectors.json");
    let text = std::fs::read_to_string(&path).expect("the vectors are checked in");
    let doc: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(doc["format_version"], "canton-solvency-cross-vectors-v1");

    let master_salt = doc["master_salt"].as_str().unwrap().as_bytes();
    let vectors = doc["vectors"].as_array().expect("an array of vectors");
    assert!(vectors.len() >= 100, "the corpus should be substantive");

    for vector in vectors {
        let user_id = vector["user_id"].as_str().unwrap();
        let balances: BTreeMap<String, u128> = vector["balances"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(asset, amount)| {
                (
                    asset.clone(),
                    parse_amount_18dp(amount.as_str().unwrap()).unwrap(),
                )
            })
            .collect();
        let pairs: Vec<(String, u128)> = balances.clone().into_iter().collect();

        let salt = leaf_salt(master_salt, user_id);
        assert_eq!(
            hex::encode(salt),
            vector["salt"].as_str().unwrap(),
            "salt drifted for {user_id}"
        );
        assert_eq!(
            canonical_balances(&pairs).unwrap(),
            vector["canonical"].as_str().unwrap(),
            "canonical serialization drifted for {user_id}"
        );
        assert_eq!(
            hex::encode(leaf_hash(&salt, user_id, &pairs).unwrap()),
            vector["leaf_hash"].as_str().unwrap(),
            "leaf hash drifted for {user_id}"
        );
        assert_eq!(
            hex::encode(lpmap(&balances)),
            vector["lpmap"].as_str().unwrap(),
            "lpmap drifted for {user_id}"
        );
    }
}

/// The §8.2 preimage is what the signature covers, so a drift here would
/// invalidate every signature rather than one leaf.
#[test]
fn the_checked_in_report_digests_match() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cross-vectors.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let reports = doc["reports"].as_array().expect("report vectors");
    assert!(reports.len() >= 40, "too few report vectors");

    for entry in reports {
        let report: Report =
            serde_json::from_value(entry["report"].clone()).expect("a well-formed report");
        assert_eq!(
            hex::encode(report_digest(&report)),
            entry["report_digest"].as_str().unwrap(),
            "report digest drifted for publisher {}",
            report.publisher
        );
    }
}

/// The corpus exists to cover what the §6 vectors cannot. If it drifted to
/// ASCII-only names it would still pass while testing nothing new.
#[test]
fn the_corpus_actually_exercises_non_ascii_names() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cross-vectors.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

    let mut astral = 0;
    let mut delimiters = 0;
    for vector in doc["vectors"].as_array().unwrap() {
        for asset in vector["balances"].as_object().unwrap().keys() {
            if asset.chars().any(|c| c as u32 > 0xFFFF) {
                astral += 1;
            }
            if asset.contains('|') || asset.contains(':') {
                delimiters += 1;
            }
        }
    }
    assert!(
        astral >= 20,
        "only {astral} assets above the BMP — too few to catch a UTF-16 sort"
    );
    assert!(
        delimiters >= 20,
        "only {delimiters} assets containing §2 delimiters"
    );
}
