//! The verifier must reject malformed input, never panic on it.
//!
//! Every document this crate reads arrives from the party being checked: a
//! publisher's report, a customer's proof, an auditor's pack. A wrong answer
//! on such input is a correctness bug and the rest of the suite covers it. A
//! *panic* is a different failure — the process dies, and in a service that
//! verifies proofs on request it dies on demand.
//!
//! Nothing here asserts what the error is. The only claim is that every input
//! produces a `Result`, which is the property the type signatures already
//! promise and which no other test checks.

use canton_solvency_report::document::{ProofDocument, SignedReport};
use canton_solvency_report::verify::verify;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    std::fs::read_to_string(path).expect("fixture is checked in")
}

const KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

/// Runs `f` and reports the input if it panicked rather than returning.
fn survives<F: FnOnce()>(label: &str, f: F) {
    let result = catch_unwind(AssertUnwindSafe(f));
    assert!(
        result.is_ok(),
        "panicked on {label} — malformed input must be rejected, not fatal"
    );
}

/// Parsing a document truncated at any byte must fail cleanly. Truncation is
/// what a dropped connection or a partial write actually produces.
#[test]
fn truncation_at_every_byte_is_rejected_not_fatal() {
    for name in ["report.golden.json", "proof.golden.json"] {
        let text = fixture(name);
        for cut in 0..text.len() {
            // Respect char boundaries; a truncated UTF-8 sequence is covered
            // by the byte-flip test below.
            if !text.is_char_boundary(cut) {
                continue;
            }
            let partial = &text[..cut];
            survives(&format!("{name} truncated at {cut}"), || {
                let _ = serde_json::from_str::<SignedReport>(partial);
                let _ = serde_json::from_str::<ProofDocument>(partial);
            });
        }
    }
}

/// A single altered byte, at every position. Most produce invalid JSON; the
/// interesting ones stay parseable and change a hex field or an amount.
#[test]
fn a_single_altered_byte_anywhere_is_rejected_not_fatal() {
    let report = fixture("report.golden.json");
    let proof = fixture("proof.golden.json");

    for (position, replacement) in (0..report.len()).flat_map(|i| {
        // A digit, a quote, a brace and a non-ASCII byte: enough to break
        // structure, hex, and UTF-8 respectively.
        [b'9', b'"', b'{', 0xFF].map(move |b| (i, b))
    }) {
        let mut bytes = report.clone().into_bytes();
        bytes[position] = replacement;
        let Ok(text) = String::from_utf8(bytes) else {
            continue; // not a string at all; serde never sees it
        };
        survives(
            &format!("report byte {position} -> {replacement:#x}"),
            || {
                if let Ok(signed) = serde_json::from_str::<SignedReport>(&text) {
                    if let Ok(p) = serde_json::from_str::<ProofDocument>(&proof) {
                        let _ = verify(&signed, &p, KEY);
                    }
                }
            },
        );
    }
}

/// Values of the wrong JSON type, and hex fields of the wrong shape. These
/// reach further into the code than a structural break does: the document
/// parses, and the failure has to come from a check rather than from serde.
#[test]
fn wrong_types_and_malformed_hex_are_rejected_not_fatal() {
    let proof = fixture("proof.golden.json");
    let report: serde_json::Value = serde_json::from_str(&fixture("report.golden.json")).unwrap();

    let substitutes = [
        serde_json::json!(null),
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(u64::MAX),
        serde_json::json!(""),
        serde_json::json!("zz"),
        serde_json::json!("0x00"),
        serde_json::json!("g".repeat(64)),
        serde_json::json!("a".repeat(63)),
        serde_json::json!("a".repeat(65)),
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!("\u{0}"),
        serde_json::json!("١٢٣"), // Arabic-Indic digits: numeric, not ASCII
    ];

    let paths = [
        "root_hash",
        "leaf_count",
        "format_version",
        "profile",
        "publisher",
        "snapshot_time",
        "ledger_offset",
    ];

    for path in paths {
        for value in &substitutes {
            let mut doc = report.clone();
            doc["report"][path] = value.clone();
            let text = serde_json::to_string(&doc).unwrap();
            survives(&format!("report.{path} = {value}"), || {
                if let Ok(signed) = serde_json::from_str::<SignedReport>(&text) {
                    if let Ok(p) = serde_json::from_str::<ProofDocument>(&proof) {
                        let _ = verify(&signed, &p, KEY);
                    }
                }
            });
        }
    }

    // The same for the signature block and the amount maps, which are the
    // fields a hostile publisher controls most directly.
    for path in ["public_key", "value", "algorithm"] {
        for value in &substitutes {
            let mut doc = report.clone();
            doc["signature"][path] = value.clone();
            let text = serde_json::to_string(&doc).unwrap();
            survives(&format!("signature.{path} = {value}"), || {
                if let Ok(signed) = serde_json::from_str::<SignedReport>(&text) {
                    if let Ok(p) = serde_json::from_str::<ProofDocument>(&proof) {
                        let _ = verify(&signed, &p, KEY);
                    }
                }
            });
        }
    }
}

/// The trusted key is a caller argument, so it is malformed input too — a
/// mistyped `--key` must not take the process down.
#[test]
fn a_malformed_trusted_key_is_rejected_not_fatal() {
    let signed: SignedReport = serde_json::from_str(&fixture("report.golden.json")).unwrap();
    let proof: ProofDocument = serde_json::from_str(&fixture("proof.golden.json")).unwrap();

    for key in [
        "",
        "not hex",
        "0x",
        &"a".repeat(63),
        &"a".repeat(65),
        &"a".repeat(1_000),
        "ZZ".repeat(32).as_str(),
        "\u{0}",
    ] {
        survives(&format!("trusted key {key:?}"), || {
            let _ = verify(&signed, &proof, key);
        });
    }
}

/// Deeply nested JSON is the classic way to blow the stack in a recursive
/// descent parser. serde_json has a depth limit; this asserts we rely on it.
#[test]
fn deeply_nested_json_is_rejected_not_fatal() {
    for depth in [64usize, 1_000, 100_000] {
        let text = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        survives(&format!("nesting depth {depth}"), || {
            let _ = serde_json::from_str::<SignedReport>(&text);
        });
    }
}

/// Amounts are the one field parsed by hand rather than by serde.
#[test]
fn adversarial_amounts_are_rejected_not_fatal() {
    use canton_solvency_merkle::parse_amount_18dp;
    let cases = [
        String::new(),
        ".".to_string(),
        "-".to_string(),
        "+1".to_string(),
        "1.".to_string(),
        ".1".to_string(),
        "1.2.3".to_string(),
        "1e18".to_string(),
        "０".to_string(), // fullwidth zero
        "١".to_string(),  // Arabic-Indic one
        "9".repeat(100),  // far past u128
        format!("1.{}", "0".repeat(19)),
        format!("{}.5", "9".repeat(40)),
        "\u{0}1".to_string(),
    ];
    for case in cases {
        survives(&format!("amount {case:?}"), || {
            let _ = parse_amount_18dp(&case);
        });
    }
}

/// Every other verification entry point, not just `verify`.
///
/// The suite above covered the customer-proof path and left the group,
/// coverage, anchor, pack and v2 paths untested against documents that are
/// structurally wrong rather than merely incorrect. All of them were already
/// panic-free — this records that rather than discovering it.
///
/// Worth noting why the answer differs from the TypeScript side, where the
/// same search found real throws. Rust's equivalents of the operations that
/// failed there return `Result` and the compiler will not let them be ignored;
/// `Object.keys(null)` throws with nothing in the type system to say so. The
/// two implementations need different amounts of this kind of testing, and it
/// is not because one was written more carefully.
#[test]
fn every_verification_entry_point_is_panic_free_on_structurally_wrong_input() {
    use canton_solvency_report::{anchor, coverage, golden, group, pack, verify};

    let key = golden::signer().public_key_hex();

    let (group_report, membership) = golden::group_fixture();
    for (label, mutate) in [
        ("group: entity sums emptied", 0u8),
        ("group: path emptied", 1),
        ("group: entity id emptied", 2),
    ] {
        let mut m = membership.clone();
        match mutate {
            0 => m.entity.root_sums.clear(),
            1 => m.steps.clear(),
            _ => m.entity.entity_id = String::new(),
        }
        survives(label, || {
            let _ = group::verify_membership(&group_report, &m, &key);
        });
    }

    let (custody, statement) = golden::coverage_fixture();
    let (liabilities, _) = golden::fixture();
    let mut blanked = statement.clone();
    blanked.custody_report_digest = String::new();
    blanked.liabilities_report_digest = String::new();
    survives("coverage: both binding digests blanked", || {
        let _ = coverage::verify_coverage(
            &custody,
            &liabilities,
            &blanked,
            &key,
            &key,
            coverage::SAME_RUN,
        );
    });

    survives("anchors: empty history", || {
        let _ = anchor::verify_chain(&[]);
    });
    let mut hollow = golden::anchor_fixture();
    hollow.report_digest = String::new();
    hollow.publisher_key = String::new();
    survives("anchors: digest fields blanked", || {
        let _ = anchor::verify_chain(&[hollow]);
    });

    let (signed_pack, members) = golden::pack_fixture();
    survives("pack: nothing delivered", || {
        let _ = pack::verify_pack(&signed_pack, &key, &std::collections::BTreeMap::new());
    });
    let mut empty_index = signed_pack.clone();
    empty_index.pack.entries.clear();
    survives("pack: index emptied", || {
        let _ = pack::verify_pack(&empty_index, &key, &members.iter().cloned().collect());
    });

    let (v2_report, v2_proof) = golden::repo_fixture();
    let mut no_maps = v2_proof.clone();
    no_maps.leaf.maps.clear();
    survives("proof v2: leaf maps emptied", || {
        let _ = verify::verify_v2(&v2_report, &no_maps, &key);
    });
    let mut no_steps = v2_proof.clone();
    no_steps.steps.clear();
    survives("proof v2: path emptied", || {
        let _ = verify::verify_v2(&v2_report, &no_steps, &key);
    });
}
