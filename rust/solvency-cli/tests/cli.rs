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

/// The golden signing seed is 32 bytes of 0x01, so a pack built here is
/// signed by the same key as the golden report and one `--key` covers both.
fn packed_golden_dir() -> tempfile::TempDir {
    use canton_solvency_report::pack::build_pack;
    use canton_solvency_report::sign::ReportSigner;

    let dir = tempfile::tempdir().unwrap();
    let members = vec![
        (
            "report.json".to_string(),
            fixture("report.golden.json").into_bytes(),
        ),
        (
            "proof-u2.json".to_string(),
            fixture("proof.golden.json").into_bytes(),
        ),
    ];
    for (name, bytes) in &members {
        std::fs::write(dir.path().join(name), bytes).unwrap();
    }
    let signed = build_pack(
        "venue::golden",
        "2026-01-01T00:00:00Z",
        GOLDEN_DIGEST,
        &members,
        &ReportSigner::from_seed(&[1u8; 32]),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("pack.json"),
        serde_json::to_string_pretty(&signed).unwrap(),
    )
    .unwrap();
    dir
}

#[test]
fn an_intact_pack_exits_zero() {
    let dir = packed_golden_dir();
    let out = run(&[
        "verify-pack",
        "--pack-dir",
        dir.path().to_str().unwrap(),
        "--key",
        KEY,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("complete and unaltered"), "got {stdout}");
    assert!(stdout.contains("1 of 1"), "got {stdout}");
}

/// The reason `verify-pack` exists. `verify` over the same folder is content
/// with what remains and exits 0; only the pack index knows a proof is gone.
#[test]
fn a_delivery_missing_a_proof_fails_the_pack_but_passes_plain_verify() {
    let dir = packed_golden_dir();
    std::fs::remove_file(dir.path().join("proof-u2.json")).unwrap();

    let packed = run(&[
        "verify-pack",
        "--pack-dir",
        dir.path().to_str().unwrap(),
        "--key",
        KEY,
    ]);
    let stdout = String::from_utf8_lossy(&packed.stdout);
    assert_eq!(packed.status.code(), Some(1), "stdout: {stdout}");
    assert!(stdout.contains("proof-u2.json"), "got {stdout}");

    let plain = run(&[
        "verify",
        "--report",
        &path(dir.path(), "report.json"),
        "--proof-dir",
        dir.path().to_str().unwrap(),
        "--key",
        KEY,
    ]);
    assert_eq!(
        plain.status.code(),
        Some(0),
        "plain verify cannot see an absent proof -- that is what packs are for"
    );
}

#[test]
fn a_pack_directory_that_has_no_index_exits_two_not_one() {
    let dir = golden_dir();
    let out = run(&[
        "verify-pack",
        "--pack-dir",
        dir.path().to_str().unwrap(),
        "--key",
        KEY,
    ]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn pack_json_output_is_machine_readable() {
    let dir = packed_golden_dir();
    let out = run(&[
        "verify-pack",
        "--pack-dir",
        dir.path().to_str().unwrap(),
        "--key",
        KEY,
        "--json",
    ]);
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(parsed["ok"], serde_json::Value::Bool(true));
    assert_eq!(parsed["members"], serde_json::json!(2));
}

/// The exit-code contract, for every verb that verifies something.
///
/// `1` means a verification failed. `2` means the run could not happen —
/// usage, I/O, a parse error. A pipeline reading these treats them very
/// differently: a wrapper that alerts on 1 and retries on 2 will retry a
/// forged document forever and never alert, so a verification failure
/// reported as 2 is worse than one reported as 0 would be loud.
///
/// `coverage` reported *every* verification failure as 2 — an untrusted
/// signer, a statement bound to another report, and later a stale pairing —
/// while its shortfall path correctly used 1. Present in 0.1.0 onwards; found
/// by exercising the published binary rather than the library.
mod exit_codes {
    use super::*;

    fn corpus(case: &str, file: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance")
            .join(case)
            .join(file)
            .to_str()
            .unwrap()
            .to_string()
    }

    fn corpus_key() -> String {
        let text = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/manifest.json"),
        )
        .unwrap();
        let manifest: serde_json::Value = serde_json::from_str(&text).unwrap();
        manifest["trusted_key"].as_str().unwrap().to_string()
    }

    fn coverage(case: &str) -> Output {
        let key = corpus_key();
        run(&[
            "coverage",
            "--custody",
            &corpus(case, "custody.json"),
            "--liabilities",
            &corpus(case, "liabilities.json"),
            "--statement",
            &corpus(case, "statement.json"),
            "--key",
            &key,
        ])
    }

    #[test]
    fn a_valid_coverage_pairing_exits_zero() {
        let out = coverage("coverage-valid");
        assert_eq!(
            out.status.code(),
            Some(0),
            "stdout: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn every_coverage_verification_failure_exits_one() {
        for case in [
            "coverage-untrusted-signer",
            "coverage-unbound-statement",
            "coverage-shortfall",
            "coverage-stale-pairing",
        ] {
            let out = coverage(case);
            assert_eq!(
                out.status.code(),
                Some(1),
                "{case}: exit 2 says the run could not happen; this run happened and refused.\n\
                 stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// The distinction is only meaningful if a genuine I/O problem still
    /// reports 2, so this pins the other side of it.
    #[test]
    fn a_coverage_run_over_a_missing_file_still_exits_two() {
        let key = corpus_key();
        let out = run(&[
            "coverage",
            "--custody",
            "/nonexistent/custody.json",
            "--liabilities",
            &corpus("coverage-valid", "liabilities.json"),
            "--statement",
            &corpus("coverage-valid", "statement.json"),
            "--key",
            &key,
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("reading"));
    }
}
