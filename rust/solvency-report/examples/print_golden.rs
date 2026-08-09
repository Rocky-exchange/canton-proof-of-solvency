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
}
