//! Regenerates the SPEC §10 golden vectors. Run when the format changes on
//! purpose; never to make a failing golden test pass.
use canton_solvency_report::golden;

fn main() {
    let (signed, proof) = golden::fixture();
    println!("public_key : {}", signed.signature.public_key);
    println!("digest     : {}", proof.report_digest);
    println!("signature  : {}", signed.signature.value);
    println!("root_hash  : {}", signed.report.root_hash);
    println!("--- report.json ---");
    println!("{}", serde_json::to_string_pretty(&signed).unwrap());
    println!("--- proof.json ---");
    println!("{}", serde_json::to_string_pretty(&proof).unwrap());

    let (v2, v2_proof) = golden::fixture_v2();
    println!("--- report-v2.json ---");
    println!("{}", serde_json::to_string_pretty(&v2).unwrap());
    println!("--- proof-v2.json ---");
    println!("{}", serde_json::to_string_pretty(&v2_proof).unwrap());

    let (repo, repo_proof) = golden::repo_fixture();
    println!("--- repo-report.json ---");
    println!("{}", serde_json::to_string_pretty(&repo).unwrap());
    println!("--- repo-proof.json ---");
    println!("{}", serde_json::to_string_pretty(&repo_proof).unwrap());

    let (custody, statement) = golden::coverage_fixture();
    println!("--- custody-report.json ---");
    println!("{}", serde_json::to_string_pretty(&custody).unwrap());
    println!("--- coverage-statement.json ---");
    println!("{}", serde_json::to_string_pretty(&statement).unwrap());

    let (group, membership) = golden::group_fixture();
    println!("--- group-report.json ---");
    println!("{}", serde_json::to_string_pretty(&group).unwrap());
    println!("--- group-membership.json ---");
    println!("{}", serde_json::to_string_pretty(&membership).unwrap());
}
