//! `canton-solvency-publish` must refuse bad input, not crash on it.
//!
//! This is the binary an operator runs to produce a report, usually against a
//! balance export they did not hand-check. A panic mid-publish leaves them
//! guessing whether anything was written, and the output directory in an
//! unknown state.
//!
//! Nothing here asserts the message. The contract is that a bad input is
//! refused with a non-zero, non-panic exit, and that a good one still works.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_canton-solvency-publish");

struct Case {
    label: &'static str,
    balances: String,
    key: String,
}

fn good_key() -> String {
    "11".repeat(32)
}

fn cases() -> Vec<Case> {
    let case = |label, balances: &str, key: String| Case {
        label,
        balances: balances.to_string(),
        key,
    };
    vec![
        case("empty balance file", "", good_key()),
        case("row with no amount", "alice,USDA\n", good_key()),
        case("amount is not a number", "alice,USDA,twelve\n", good_key()),
        case("negative amount", "alice,USDA,-1\n", good_key()),
        case("bare decimal point", "alice,USDA,1.\n", good_key()),
        case(
            "nineteen decimal places",
            "alice,USDA,1.0000000000000000001\n",
            good_key(),
        ),
        case(
            "amount past u128",
            &format!("alice,USDA,{}\n", "9".repeat(60)),
            good_key(),
        ),
        case(
            "same asset twice for one user",
            "alice,USDA,1\nalice,USDA,2\n",
            good_key(),
        ),
        case("empty user id", ",USDA,1\n", good_key()),
        case("empty asset", "alice,,1\n", good_key()),
        case("only separators", ",,\n", good_key()),
        case("key file is not hex", "alice,USDA,1\n", "zz".to_string()),
        case("key file is empty", "alice,USDA,1\n", String::new()),
        case("key file is too short", "alice,USDA,1\n", "11".repeat(31)),
        case("key file is too long", "alice,USDA,1\n", "11".repeat(33)),
    ]
}

fn publish(dir: &std::path::Path, balances: &str, key: &str) -> i32 {
    let balances_path = dir.join("balances.csv");
    let key_path = dir.join("key.hex");
    std::fs::write(&balances_path, balances).unwrap();
    std::fs::write(&key_path, key).unwrap();

    let output = Command::new(BIN)
        .args([
            "--balances",
            balances_path.to_str().unwrap(),
            "--key-file",
            key_path.to_str().unwrap(),
            "--publisher",
            "venue::test",
            "--snapshot-time",
            "2026-01-01T00:00:00Z",
            "--ledger-offset",
            "000000000000000042",
            "--out",
            dir.join("out").to_str().unwrap(),
        ])
        .output()
        .expect("binary runs");
    output.status.code().unwrap_or(-1)
}

#[test]
fn bad_input_is_refused_without_panicking() {
    for case in cases() {
        let dir = tempfile::tempdir().unwrap();
        let code = publish(dir.path(), &case.balances, &case.key);
        assert_ne!(code, 0, "{}: should not have succeeded", case.label);
        assert_ne!(
            code, 101,
            "{}: panicked — bad input must be refused, not fatal",
            case.label
        );
    }
}

/// The harness has to be able to tell success from refusal, or the assertions
/// above are satisfied by a binary that fails at everything.
#[test]
fn a_well_formed_balance_file_still_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let code = publish(
        dir.path(),
        "alice,USDA,100.5\nalice,CBTC,0.25\nbob,USDA,1\n",
        &good_key(),
    );
    assert_eq!(code, 0, "the good path should publish");

    let out = dir.path().join("out");
    for name in ["report.json", "anchor.json", "pack.json"] {
        assert!(out.join(name).exists(), "{name} was not written");
    }
    // One proof per user, and the pack indexes everything.
    let files: Vec<PathBuf> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(
        files.len(),
        5,
        "expected report, anchor, pack and two proofs"
    );
}

/// Three customers, one sanitised filename. Each proof used to overwrite the
/// last, and only the pack index noticed — after the files were written, and
/// with a message about the pack rather than about the customers.
#[test]
fn customers_whose_ids_sanitise_alike_all_get_their_proof() {
    let dir = tempfile::tempdir().unwrap();
    let code = publish(
        dir.path(),
        "alice-1,USDA,100\nalice_1,USDA,7\nalice 1,USDA,3\nbob,USDA,1\n",
        &good_key(),
    );
    assert_eq!(code, 0, "four distinct customers should publish");

    let out = dir.path().join("out");
    let proofs: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("proof-"))
        .collect();
    assert_eq!(proofs.len(), 4, "one proof per customer, got {proofs:?}");
}

/// An identifier that is unusual but valid — SPEC §3 places no restriction on
/// the UTF-8 identity string — must publish and round-trip, not be refused.
#[test]
fn an_unusual_but_valid_identifier_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let code = publish(dir.path(), "a\u{0}b,USDA,1\n", &good_key());
    assert_eq!(code, 0, "a NUL is valid UTF-8 and §3 does not exclude it");

    let out = dir.path().join("out");
    let proof = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("proof-")
        })
        .expect("a proof was written");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(proof).unwrap()).unwrap();
    assert_eq!(
        doc["leaf"]["user_id"].as_str().unwrap(),
        "a\u{0}b",
        "the identifier must survive the round trip intact"
    );
}

/// A refusal must not leave a half-written publication behind. An operator
/// re-running after a rejected file should not find yesterday's proofs mixed
/// with today's.
#[test]
fn a_refusal_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let code = publish(dir.path(), "alice,USDA,twelve\n", &good_key());
    assert_ne!(code, 0);

    let out = dir.path().join("out");
    let written = if out.exists() {
        std::fs::read_dir(&out).unwrap().count()
    } else {
        0
    };
    assert_eq!(written, 0, "a rejected publish left {written} files behind");
}
