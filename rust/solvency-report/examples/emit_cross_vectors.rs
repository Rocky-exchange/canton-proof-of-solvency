//! Emits cross-implementation differential vectors.
//!
//! Usage: cargo run --example emit_cross_vectors -- conformance/cross-vectors.json
//!
//! Lives beside the conformance corpus rather than in `fixtures/`, where every
//! file is required to be a schema-validated wire document. This is generated
//! test data, not a document any producer emits.
//!
//! The golden vectors in SPEC §6 pin three hand-written cases, all with ASCII
//! asset names. That is exactly why the TypeScript verifier could sort keys by
//! UTF-16 code units for months without anything noticing: every published
//! vector agreed under both orderings.
//!
//! These vectors are generated instead, over asset names chosen to break
//! assumptions — astral codepoints, the private-use block, the `:` and `|` that
//! §2's join uses as delimiters, and names that differ only past a prefix. Both
//! implementations compute them independently and compare, so a divergence in
//! ordering, encoding, or canonicalisation surfaces as a failing test rather
//! than as one venue's report failing in one browser.
use canton_solvency_merkle::*;
use canton_solvency_report::digest::report_digest;
use canton_solvency_report::document::{Disclosures, Report};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// xorshift64, seeded, so the corpus is reproducible and reviewable.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Names picked to break a specific assumption, not to be exotic for its own
/// sake. Each comment says which.
const NAMES: &[&str] = &[
    "USDA",
    "CBTC",
    // Sorts before/after differently under UTF-16 than UTF-8 — the bug that
    // shipped.
    "\u{FF01}",
    "\u{10000}",
    "\u{E000}",
    "\u{1F600}",
    // The §2 delimiters themselves: a join cannot distinguish these from two
    // entries, length prefixing can.
    "A|B",
    "A:B",
    "A|B:0.000000000000000001",
    // Differ only past a shared prefix, where a length-confused encoder slips.
    "AA",
    "AAA",
    "AAB",
    // Case and separators, since bytewise order is not case-insensitive.
    "a",
    "Z",
    "a.b-c_1",
];

/// `n` assets drawn from the adversarial set. A free function rather than a
/// closure so it borrows the generator once per call.
fn pick(rng: &mut Rng, n: usize) -> BTreeMap<String, u128> {
    let mut m = BTreeMap::new();
    for _ in 0..n {
        let name = NAMES[(rng.next() % NAMES.len() as u64) as usize];
        m.insert(
            name.to_string(),
            rng.next() as u128 % 1_000_000_000_000_000_000_000,
        );
    }
    m
}

fn main() -> anyhow::Result<()> {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "conformance/cross-vectors.json".into())
        .into();

    let mut rng = Rng(0x5EED_1234_5678_9ABC);
    let mut vectors = Vec::new();

    for i in 0..200 {
        // One to four assets drawn from the adversarial set, deduplicated:
        // §2 makes a repeated asset an error, not a vector.
        let count = 1 + (rng.next() % 4) as usize;
        let mut balances: BTreeMap<String, u128> = BTreeMap::new();
        for _ in 0..count {
            let name = NAMES[(rng.next() % NAMES.len() as u64) as usize];
            let amount = rng.next() as u128 % 1_000_000_000_000_000_000_000;
            balances.insert(name.to_string(), amount);
        }

        let user_id = match i % 4 {
            0 => format!("user-{i}"),
            1 => format!("用户-{i}"),         // non-ASCII subject
            2 => format!("user\u{1F600}{i}"), // astral in the subject
            _ => format!("{i}"),
        };
        let salt = leaf_salt(b"cross-vector-master-salt", &user_id);
        let pairs: Vec<(String, u128)> = balances.clone().into_iter().collect();

        vectors.push(serde_json::json!({
            "user_id": user_id,
            "salt": hex::encode(salt),
            "balances": balances
                .iter()
                .map(|(a, v)| (a.clone(), format_amount_18dp(*v)))
                .collect::<BTreeMap<String, String>>(),
            "canonical": canonical_balances(&pairs)?,
            "leaf_hash": hex::encode(leaf_hash(&salt, &user_id, &pairs)?),
            "lpmap": hex::encode(lpmap(&balances)),
        }));
    }

    // --- §8.2 report digests ---
    // The signature covers this preimage, so a divergence here breaks every
    // cross-implementation signature check rather than one leaf. It embeds
    // four amount maps, each sorted bytewise, which is the same surface the
    // UTF-16 bug sat on.
    let mut reports = Vec::new();
    for i in 0..60 {
        // Counts drawn first: `pick(&mut rng, rng.next())` would borrow the
        // generator twice in one expression.
        let (n_sums, n_prices) = (1 + (rng.next() % 4) as usize, (rng.next() % 3) as usize);
        let (n_debt, n_excluded) = ((rng.next() % 3) as usize, (rng.next() % 3) as usize);
        let root_sums = pick(&mut rng, n_sums);
        let mark_prices = pick(&mut rng, n_prices);
        let bad_debt = pick(&mut rng, n_debt);
        let excluded_house_totals = pick(&mut rng, n_excluded);

        let report = Report {
            format_version: "canton-solvency-report-v1".to_string(),
            profile: "solvency.liabilities".to_string(),
            // Party identifiers are attacker-influenced in the general case
            // too, so they get non-ASCII treatment as well.
            publisher: if i % 3 == 0 {
                format!("venue\u{1F3E6}::{i}")
            } else {
                format!("venue::{i}")
            },
            snapshot_time: "2026-01-01T00:00:00Z".to_string(),
            ledger_offset: format!("{:018}", i),
            root_hash: hex::encode([i as u8; 32]),
            leaf_count: i as u64,
            root_sums,
            mark_prices,
            disclosures: Disclosures {
                bad_debt,
                excluded_house_accounts: i as u64 % 7,
                excluded_house_totals,
            },
            manifest: None,
        };
        reports.push(serde_json::json!({
            "report": serde_json::to_value(&report)?,
            "report_digest": hex::encode(report_digest(&report)),
        }));
    }

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &out,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "format_version": "canton-solvency-cross-vectors-v1",
                "description": "Generated differential vectors (SPEC §1–§3, §8.1). \
                                Both implementations must reproduce every field.",
                "master_salt": "cross-vector-master-salt",
                "vectors": vectors,
                "reports": reports,
            }))?
        ),
    )?;
    println!(
        "wrote {} ({} leaf vectors, {} report digests)",
        out.display(),
        vectors.len(),
        reports.len()
    );
    Ok(())
}
