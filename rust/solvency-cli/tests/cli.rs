//! End-to-end tests against the real binary. The unit tests cover behaviour;
//! these prove `main` is wired to it — exit codes especially, since that is
//! what a CI pipeline actually consumes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_canton-solvency-verify");
const KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const GOLDEN_DIGEST: &str = "0800c1047c9724ea429b238b01366f2032d674425d3ed745ed3402b2f534df61";

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    std::fs::read_to_string(path).expect("fixture is checked in")
}

fn golden_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("report.json"),
        fixture("report.golden.json"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("proof-u2.json"),
        fixture("proof.golden.json"),
    )
    .unwrap();
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("binary runs")
}

fn path(dir: &Path, name: &str) -> String {
    dir.join(name).to_str().unwrap().to_string()
}

#[test]
fn a_valid_publication_exits_zero_and_reports_the_digest() {
    let dir = golden_dir();
    let out = run(&[
        "verify",
        "--report",
        &path(dir.path(), "report.json"),
        "--proof",
        &path(dir.path(), "proof-u2.json"),
        "--key",
        KEY,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains(GOLDEN_DIGEST), "got {stdout}");
    assert!(stdout.contains("1 of 1"), "got {stdout}");
    assert!(
        stdout.contains("solvency.liabilities"),
        "a passing check should say what it verified; got {stdout}"
    );
}

#[test]
fn a_tampered_proof_exits_one() {
    let dir = golden_dir();
    std::fs::write(
        dir.path().join("bad.json"),
        fixture("proof.golden.json").replace("0.250000000000000000", "9.250000000000000000"),
    )
    .unwrap();

    let out = run(&[
        "verify",
        "--report",
        &path(dir.path(), "report.json"),
        "--proof",
        &path(dir.path(), "bad.json"),
        "--key",
        KEY,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("FAILED"), "got {stdout}");
}

#[test]
fn a_missing_file_exits_two_not_one() {
    let dir = golden_dir();
    let out = run(&[
        "verify",
        "--report",
        &path(dir.path(), "nope.json"),
        "--proof",
        &path(dir.path(), "proof-u2.json"),
        "--key",
        KEY,
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("reading"));
}

#[test]
fn a_directory_sweep_skips_the_report_and_verifies_the_proofs() {
    let dir = golden_dir();
    let out = run(&[
        "verify",
        "--report",
        &path(dir.path(), "report.json"),
        "--proof-dir",
        dir.path().to_str().unwrap(),
        "--key",
        KEY,
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--json emits valid JSON");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["checked"], 1);
    assert_eq!(parsed["report_digest"], GOLDEN_DIGEST);
}

#[test]
fn digest_prints_the_report_digest() {
    let dir = golden_dir();
    let out = run(&["digest", "--report", &path(dir.path(), "report.json")]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains(GOLDEN_DIGEST));
}

#[test]
fn verifying_without_a_key_exits_two_and_explains_why() {
    let dir = golden_dir();
    let out = run(&[
        "verify",
        "--report",
        &path(dir.path(), "report.json"),
        "--proof",
        &path(dir.path(), "proof-u2.json"),
    ]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--key"), "got {stderr}");
    assert!(stderr.contains("internal consistency"), "got {stderr}");
}

fn group_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, fixture_name) in [
        ("group-report.json", "group-report.golden.json"),
        ("membership.json", "group-membership.golden.json"),
        ("report.json", "report.golden.json"),
        ("proof.json", "proof.golden.json"),
    ] {
        std::fs::write(dir.path().join(name), fixture(fixture_name)).unwrap();
    }
    dir
}

#[test]
fn verify_group_exits_zero_for_a_valid_membership() {
    let dir = group_dir();
    let out = run(&[
        "verify-group",
        "--report",
        &path(dir.path(), "group-report.json"),
        "--membership",
        &path(dir.path(), "membership.json"),
        "--key",
        KEY,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("1 of 1"), "got {stdout}");
}

#[test]
fn verify_chain_exits_zero_and_names_the_customer_and_entity() {
    let dir = group_dir();
    let out = run(&[
        "verify-chain",
        "--group-report",
        &path(dir.path(), "group-report.json"),
        "--membership",
        &path(dir.path(), "membership.json"),
        "--report",
        &path(dir.path(), "report.json"),
        "--proof",
        &path(dir.path(), "proof.json"),
        "--key",
        KEY,
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(
        parsed["proofs"][0]["subject"],
        "22222222-2222-7222-8222-222222222222 in golden-entity-a"
    );
}

#[test]
fn verify_chain_exits_one_when_the_customer_proof_is_tampered() {
    let dir = group_dir();
    std::fs::write(
        dir.path().join("proof.json"),
        fixture("proof.golden.json").replace("0.250000000000000000", "9.250000000000000000"),
    )
    .unwrap();
    let out = run(&[
        "verify-chain",
        "--group-report",
        &path(dir.path(), "group-report.json"),
        "--membership",
        &path(dir.path(), "membership.json"),
        "--report",
        &path(dir.path(), "report.json"),
        "--proof",
        &path(dir.path(), "proof.json"),
        "--key",
        KEY,
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("FAILED"));
}

#[test]
fn manifest_diff_exits_one_when_disclosure_was_reduced() {
    let dir = tempfile::tempdir().unwrap();
    let prev = dir.path().join("prev.json");
    let curr = dir.path().join("curr.json");
    let base = fixture("report-v2.golden.json");
    std::fs::write(&prev, &base).unwrap();
    std::fs::write(
        &curr,
        base.replace(
            r#""mark_prices": "published""#,
            r#""mark_prices": "withheld""#,
        ),
    )
    .unwrap();

    let out = run(&[
        "manifest-diff",
        "--previous",
        prev.to_str().unwrap(),
        "--current",
        curr.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("REDUCED"), "got {stdout}");
}

#[test]
fn manifest_diff_exits_zero_when_nothing_was_reduced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r.json");
    std::fs::write(&path, fixture("report-v2.golden.json")).unwrap();
    let out = run(&[
        "manifest-diff",
        "--previous",
        path.to_str().unwrap(),
        "--current",
        path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["reductions"], 0);
}

#[test]
fn help_exits_zero_and_documents_the_exit_codes() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("EXIT CODES"), "got {stdout}");
}
