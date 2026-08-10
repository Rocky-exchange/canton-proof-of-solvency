//! How much of the book do colluding proof-holders learn?
//!
//! `docs/SECURITY-REVIEW-BRIEF.md` asks this and says we do not bound it. This
//! measures it, which is not the same as answering it — a measurement over
//! random trees says what happens on average, not what an adversary who
//! chooses their positions can force.
//!
//! Usage: cargo run --release --example sibling_leakage
//!
//! ## What a colluding set knows
//!
//! A proof for leaf `i` carries, at every level, the sibling subtree's summed
//! balances. So each participant learns:
//!
//! - their own leaf, exactly;
//! - the summed balances of every sibling subtree along their path.
//!
//! The published root sums are known to everyone. From that starting set, an
//! attacker propagates: wherever two of {parent, left child, right child} are
//! known, the third follows by addition or subtraction. Iterating to a
//! fixpoint determines every leaf the collusion can reach.
//!
//! The level-0 case is the one worth stating plainly: a proof's first sibling
//! *is* another customer's leaf, so every participant already knows one other
//! customer's exact balances before any arithmetic. That is inherent to a sum
//! tree and is recorded in `docs/SECURITY-ANALYSIS.md`.

use canton_solvency_merkle::*;
use std::collections::BTreeMap;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// A complete level-by-level tree, so the analysis can address any node.
/// `levels[0]` is the leaves; the last level is the single root.
fn levels_of(leaves: Vec<Node>) -> Vec<Vec<Node>> {
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity(prev.len().div_ceil(2));
        for pair in prev.chunks(2) {
            next.push(match pair {
                [l, r] => {
                    let mut sums = l.sums.clone();
                    for (asset, v) in &r.sums {
                        *sums.entry(asset.clone()).or_insert(0) += v;
                    }
                    Node {
                        hash: [0u8; 32], // hashes are irrelevant to the leakage question
                        sums,
                    }
                }
                [odd] => odd.clone(),
                _ => unreachable!(),
            });
        }
        levels.push(next);
    }
    levels
}

/// Index a node as (level, position).
type At = (usize, usize);

/// Everything the colluding set can determine, as a fixpoint.
fn determined(levels: &[Vec<Node>], colluders: &[usize]) -> std::collections::BTreeSet<At> {
    let mut known: BTreeMap<At, BTreeMap<String, u128>> = BTreeMap::new();

    // The root sums are published to everyone.
    let top = levels.len() - 1;
    known.insert((top, 0), levels[top][0].sums.clone());

    for &leaf in colluders {
        known.insert((0, leaf), levels[0][leaf].sums.clone());
        // Each step of the proof discloses the sibling subtree's sums.
        let mut idx = leaf;
        for (level, nodes) in levels.iter().enumerate().take(levels.len() - 1) {
            let sibling = idx ^ 1;
            if sibling < nodes.len() {
                known.insert((level, sibling), nodes[sibling].sums.clone());
            }
            idx /= 2;
        }
    }

    // Propagate: parent = left + right, so any two give the third.
    loop {
        let mut learned = false;
        for (level, nodes) in levels.iter().enumerate().take(levels.len() - 1) {
            for pos in (0..nodes.len()).step_by(2) {
                let parent = (level + 1, pos / 2);
                if pos + 1 >= nodes.len() {
                    // Promoted, not combined: the parent *is* this node.
                    if let Some(v) = known.get(&(level, pos)).cloned() {
                        learned |= known.insert(parent, v).is_none();
                    } else if let Some(v) = known.get(&parent).cloned() {
                        learned |= known.insert((level, pos), v).is_none();
                    }
                    continue;
                }
                let left = (level, pos);
                let right = (level, pos + 1);
                let (l, r, p) = (
                    known.get(&left).cloned(),
                    known.get(&right).cloned(),
                    known.get(&parent).cloned(),
                );
                let sub = |a: &BTreeMap<String, u128>, b: &BTreeMap<String, u128>| {
                    let mut out = a.clone();
                    for (asset, v) in b {
                        let slot = out.entry(asset.clone()).or_insert(0);
                        *slot = slot.saturating_sub(*v);
                    }
                    out.retain(|_, v| *v > 0);
                    out
                };
                match (l, r, p) {
                    (Some(l), Some(r), None) => {
                        let mut sum = l.clone();
                        for (asset, v) in &r {
                            *sum.entry(asset.clone()).or_insert(0) += v;
                        }
                        learned |= known.insert(parent, sum).is_none();
                    }
                    (Some(l), None, Some(p)) => {
                        learned |= known.insert(right, sub(&p, &l)).is_none();
                    }
                    (None, Some(r), Some(p)) => {
                        learned |= known.insert(left, sub(&p, &r)).is_none();
                    }
                    _ => {}
                }
            }
        }
        if !learned {
            break;
        }
    }

    known.keys().copied().collect()
}

fn main() {
    println!("Leaf balances determined by a colluding set (SPEC §5 sibling sums)");
    println!();
    println!("  leaves  colluders   others exposed   % of the rest");
    println!("  ------  ---------   --------------   -------------");

    let mut rng = Rng(0x00C0_FFEE_1234_5678);
    for n in [8usize, 64, 1_024] {
        let leaves: Vec<Node> = (0..n)
            .map(|i| {
                let user_id = format!("u{i}");
                let salt = leaf_salt(b"leakage-analysis", &user_id);
                let amount = 1 + (rng.next() as u128 % 1_000_000_000_000_000_000_000);
                leaf_node(&salt, &user_id, &[("USDA".to_string(), amount)]).unwrap()
            })
            .collect();
        let levels = levels_of(leaves);

        for k in [1usize, 2, n / 8, n / 4, n / 2] {
            if k == 0 || k > n {
                continue;
            }
            // Spread the colluders rather than clustering them; adjacent
            // colluders learn less, because they already share a sibling.
            let stride = n / k;
            let colluders: Vec<usize> = (0..k).map(|i| (i * stride) % n).collect();

            let known = determined(&levels, &colluders);
            let exposed = (0..n)
                .filter(|i| !colluders.contains(i) && known.contains(&(0, *i)))
                .count();
            let rest = n - colluders.len();
            println!(
                "  {n:>6}  {k:>9}   {exposed:>14}   {:>12.1}%",
                100.0 * exposed as f64 / rest as f64
            );
        }
        println!();
    }

    // Placement matters, so measure it rather than assert it.
    println!("Placement, at 1024 leaves with 64 colluders:");
    println!();
    let n = 1024usize;
    let leaves: Vec<Node> = (0..n)
        .map(|i| {
            let user_id = format!("u{i}");
            let salt = leaf_salt(b"leakage-analysis", &user_id);
            let amount = 1 + (rng.next() as u128 % 1_000_000_000_000_000_000_000);
            leaf_node(&salt, &user_id, &[("USDA".to_string(), amount)]).unwrap()
        })
        .collect();
    let levels = levels_of(leaves);
    let k = 64;

    let arrangements: [(&str, Vec<usize>); 3] = [
        ("spread evenly", (0..k).map(|i| i * (n / k)).collect()),
        (
            "adjacent pairs",
            (0..k).map(|i| (i / 2) * 2 + (i % 2)).collect(),
        ),
        ("one contiguous block", (0..k).collect()),
    ];
    for (label, colluders) in arrangements {
        let known = determined(&levels, &colluders);
        let exposed = (0..n)
            .filter(|i| !colluders.contains(i) && known.contains(&(0, *i)))
            .count();
        println!("  {label:<22} {exposed:>4} others exposed");
    }

    println!();
    println!("Colluders spread out expose one partner each; colluders who are");
    println!("already paired expose nobody new, because each already held the");
    println!("other's leaf. The producer chooses the leaf order (SPEC §4), so the");
    println!("order is part of the privacy story rather than an implementation");
    println!("detail — and an adversary who can influence it does better than");
    println!("these numbers suggest.");
}
