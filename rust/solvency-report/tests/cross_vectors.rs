//! Guards the checked-in differential vectors against drift.
//!
//! The TypeScript suite recomputes `conformance/cross-vectors.json` and
//! compares.
//! That only means something if the file still reflects what this
//! implementation produces — a stale file would let both sides agree about a
//! value neither one computes any more.

use canton_solvency_merkle::*;
use canton_solvency_report::anchor::{anchor_digest, Anchor};
use canton_solvency_report::digest::report_digest;
use canton_solvency_report::document::Report;
use canton_solvency_report::pack::{pack_digest, Pack};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn corpus() -> serde_json::Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cross-vectors.json");
    let text = std::fs::read_to_string(&path).expect("the vectors are checked in");
    serde_json::from_str(&text).expect("valid JSON")
}

#[test]
fn the_checked_in_vectors_match_what_this_implementation_computes() {
    let doc = corpus();
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
    let doc = corpus();
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

/// Every remaining hash preimage in the format: §4 roots, §15.2 packs, §12
/// anchors. A drift here would let both implementations agree about a value
/// neither one still computes.
#[test]
fn the_checked_in_trees_packs_and_anchors_match() {
    let doc = corpus();

    for tree in doc["trees"].as_array().expect("tree vectors") {
        let nodes: Vec<Node> = tree["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                let balances: Vec<(String, u128)> = l["balances"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(a, v)| (a.clone(), parse_amount_18dp(v.as_str().unwrap()).unwrap()))
                    .collect();
                let salt: [u8; 32] = hex::decode(l["salt"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                leaf_node(&salt, l["user_id"].as_str().unwrap(), &balances).unwrap()
            })
            .collect();
        let size = nodes.len();
        let built = SumTree::build(nodes).unwrap();
        assert_eq!(
            hex::encode(built.root().hash),
            tree["root_hash"].as_str().unwrap(),
            "root drifted for a {size}-leaf tree"
        );
    }

    for entry in doc["packs"].as_array().expect("pack vectors") {
        let pack: Pack = serde_json::from_value(entry["pack"].clone()).unwrap();
        assert_eq!(
            hex::encode(pack_digest(&pack)),
            entry["pack_digest"].as_str().unwrap(),
            "pack digest drifted for {}",
            pack.publisher
        );
    }

    for entry in doc["anchors"].as_array().expect("anchor vectors") {
        let anchor: Anchor = serde_json::from_value(entry["anchor"].clone()).unwrap();
        assert_eq!(
            hex::encode(anchor_digest(&anchor)),
            entry["anchor_digest"].as_str().unwrap(),
            "anchor digest drifted for {}",
            anchor.publisher
        );
    }
}

/// Half the anchors must be genesis and half linked, or the presence byte that
/// distinguishes them goes untested.
#[test]
fn the_anchor_vectors_cover_both_genesis_and_linked() {
    let doc = corpus();
    let anchors = doc["anchors"].as_array().unwrap();
    let genesis = anchors
        .iter()
        .filter(|a| a["anchor"]["prev_anchor"].is_null())
        .count();
    assert!(
        genesis > 0 && genesis < anchors.len(),
        "anchors must include both genesis and linked, got {genesis} of {}",
        anchors.len()
    );
}

/// The corpus exists to cover what the §6 vectors cannot. If it drifted to
/// ASCII-only names it would still pass while testing nothing new.
#[test]
fn the_corpus_actually_exercises_non_ascii_names() {
    let doc = corpus();

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
