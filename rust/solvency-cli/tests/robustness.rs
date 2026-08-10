//! Malformed input must exit 2, never panic.
//!
//! The exit codes are this tool's contract with a CI pipeline: `0` verified,
//! `1` a verification failed, `2` usage or I/O. A panic exits `101`, which is
//! none of those — and worse, a pipeline treating "not 0" as failure would
//! report a corrupt file as evidence of insolvency, which is exactly the
//! confusion the three-code split exists to prevent.
//!
//! The library tests cover the same property for `verify`. These run the real
//! binary, because the mapping from a `Result` to an exit code lives in `main`
//! and nothing else exercises it.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_canton-solvency-verify");
const KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// Every way a file can be wrong without being absent.
fn malformed_files(dir: &Path) -> Vec<(&'static str, String)> {
    let golden = std::fs::read_to_string(fixture("report.golden.json")).unwrap();
    let cases: Vec<(&'static str, String)> = vec![
        ("empty", String::new()),
        ("garbage", "not json at all".to_string()),
        ("truncated", golden[..golden.len() / 3].to_string()),
        (
            "wrong-shape",
            r#"{"report":{"root_sums":"zz"}}"#.to_string(),
        ),
        ("null", "null".to_string()),
        ("array", "[]".to_string()),
        ("number", "42".to_string()),
        (
            "nested",
            format!("{}{}", "[".repeat(5_000), "]".repeat(5_000)),
        ),
        ("unknown-field", {
            let mut doc: serde_json::Value = serde_json::from_str(&golden).unwrap();
            doc["report"]["surprise"] = serde_json::json!(1);
            doc.to_string()
        }),
        ("nul-byte", "{\"report\":\"\u{0}\"}".to_string()),
    ];
    for (name, body) in &cases {
        std::fs::write(dir.join(format!("{name}.json")), body).unwrap();
    }
    cases
}

fn run(args: &[&str]) -> i32 {
    let output = Command::new(BIN).args(args).output().expect("binary runs");
    output.status.code().unwrap_or(-1)
}

#[test]
fn every_verb_exits_two_on_a_malformed_document() {
    let dir = tempfile::tempdir().unwrap();
    let cases = malformed_files(dir.path());
    let proof = fixture("proof.golden.json");

    for (name, _) in &cases {
        let path = dir.path().join(format!("{name}.json"));
        let bad = path.to_str().unwrap();

        // Each verb, with the malformed file in the position it reads.
        let invocations: Vec<Vec<&str>> = vec![
            vec!["verify", "--report", bad, "--proof", &proof, "--key", KEY],
            vec!["verify", "--report", &proof, "--proof", bad, "--key", KEY],
            vec!["digest", "--report", bad],
            vec!["anchors", "--chain", bad],
            vec!["manifest-diff", "--previous", bad, "--current", bad],
            vec!["recompute", "--leaves", bad, "--report", bad],
            vec![
                "verify-group",
                "--report",
                bad,
                "--membership",
                bad,
                "--key",
                KEY,
            ],
            vec![
                "verify-pack",
                "--pack-dir",
                dir.path().to_str().unwrap(),
                "--key",
                KEY,
            ],
        ];

        for args in invocations {
            let code = run(&args);
            assert_eq!(
                code,
                2,
                "`{}` on {name}.json exited {code}; malformed input is a 2, and \
                 101 means it panicked",
                args.join(" ")
            );
        }
    }
}

/// A sweep must not be derailed by a stray file, but it must not silently
/// skip one that looks like a proof either.
#[test]
fn a_sweep_over_a_directory_of_junk_exits_two_rather_than_panicking() {
    let dir = tempfile::tempdir().unwrap();
    malformed_files(dir.path());
    std::fs::write(dir.path().join("notes.txt"), "not a document").unwrap();

    let code = run(&[
        "verify",
        "--report",
        &fixture("report.golden.json"),
        "--proof-dir",
        dir.path().to_str().unwrap(),
        "--key",
        KEY,
    ]);
    assert_eq!(code, 2, "a directory of junk should be a 2, got {code}");
}

/// A mistyped key is usage, not evidence.
#[test]
fn a_malformed_key_exits_two() {
    for key in [
        "",
        "not-hex",
        "0x00",
        &"a".repeat(63),
        &"a".repeat(65),
        &"a".repeat(10_000),
        "ZZ",
    ] {
        let code = run(&[
            "verify",
            "--report",
            &fixture("report.golden.json"),
            "--proof",
            &fixture("proof.golden.json"),
            "--key",
            key,
        ]);
        assert_eq!(code, 2, "key {key:?} exited {code}");
    }
}

/// Arguments themselves are untrusted input.
#[test]
fn hostile_arguments_exit_two() {
    let long = "x".repeat(100_000);
    let cases: Vec<Vec<&str>> = vec![
        vec![],
        vec!["verify"],
        vec!["nonsense"],
        vec!["verify", "--report"],
        vec!["verify", "--key"],
        vec![
            "verify",
            "--report",
            "/nonexistent/path.json",
            "--proof",
            "/also/missing.json",
            "--key",
            KEY,
        ],
        vec!["verify", "--report", &long, "--proof", &long, "--key", KEY],
        vec!["--", "verify"],
        vec!["verify", "--report=fixtures/report.golden.json"],
    ];
    for args in cases {
        let code = run(&args);
        assert_eq!(
            code,
            2,
            "`{}` exited {code}; a usage error is a 2 and 101 means it panicked",
            args.join(" ")
        );
    }
}

/// The one case that must NOT be a 2: a well-formed report whose proof simply
/// does not verify. Confusing that with an I/O error would make the whole
/// split pointless.
#[test]
fn a_genuine_verification_failure_is_still_a_one() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.json");
    std::fs::copy(fixture("report.golden.json"), &report).unwrap();

    // A valid proof document bound to a different report.
    let mut proof: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture("proof.golden.json")).unwrap())
            .unwrap();
    proof["report_digest"] = serde_json::json!("00".repeat(32));
    let proof_path = dir.path().join("proof.json");
    std::fs::write(&proof_path, proof.to_string()).unwrap();

    let code = run(&[
        "verify",
        "--report",
        report.to_str().unwrap(),
        "--proof",
        proof_path.to_str().unwrap(),
        "--key",
        KEY,
    ]);
    assert_eq!(code, 1, "a failed verification is a 1, not a {code}");
}
