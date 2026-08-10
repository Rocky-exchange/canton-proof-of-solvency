//! Merkle sum tree for exchange proof-of-solvency commitments on Canton.
//!
//! Each leaf commits to one subject's per-asset balances under a derived
//! salt, and every internal node carries the sum of its children as well as
//! their hashes. Folding an inclusion path therefore re-derives part of the
//! aggregation: equal roots imply equal totals, so a customer checking their
//! own proof also checks that the published liabilities are not understated.
//!
//! Amounts are non-negative fixed point with 18 fractional digits, carried as
//! strings, so `NUMERIC(38,18)` maps in losslessly and nothing depends on
//! floating point.
//!
//! # Example
//!
//! Commit two customers, prove one of them, and verify without the tree:
//!
//! ```
//! use canton_solvency_merkle::*;
//!
//! # fn main() -> anyhow::Result<()> {
//! // One secret per snapshot, held by the producer. Each customer learns
//! // only their own derived salt.
//! let master_salt = b"per-snapshot-secret";
//!
//! let mut leaves = Vec::new();
//! for (user_id, usda) in [("alice", "100.5"), ("bob", "0.25")] {
//!     let balances = vec![("USDA".to_string(), parse_amount_18dp(usda)?)];
//!     let salt = leaf_salt(master_salt, user_id);
//!     leaves.push(leaf_node(&salt, user_id, &balances)?);
//! }
//!
//! let tree = SumTree::build(leaves.clone())?;
//!
//! // The root publishes the totals, and they are the real sum.
//! assert_eq!(
//!     format_amount_18dp(tree.root().sums["USDA"]),
//!     "100.750000000000000000"
//! );
//!
//! // Alice verifies her own inclusion from her proof alone.
//! let proof = tree.prove(0)?;
//! assert!(verify_proof(&leaves[0], &proof, tree.root()));
//!
//! // Bob's leaf does not verify under Alice's proof.
//! assert!(!verify_proof(&leaves[1], &proof, tree.root()));
//! # Ok(())
//! # }
//! ```
//!
//! # What this does not prove
//!
//! That the tree contains *every* customer. A producer can omit one entirely,
//! and only the omitted customer can detect it, by finding their proof
//! missing. No Merkle scheme fixes that; it is a disclosure-and-audit problem.
//!
//! [`SPEC.md`]: https://github.com/Rocky-exchange/canton-proof-of-solvency/blob/main/SPEC.md

use anyhow::{bail, ensure, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const SCALE_DIGITS: usize = 18;
const SCALE: u128 = 1_000_000_000_000_000_000;

/// Parses a non-negative decimal string into 18dp fixed point. This is the
/// only amount representation the tree accepts: NUMERIC(38,18) maps in
/// losslessly and negative values (clamped upstream per the design doc)
/// are a hard error, never a wrap.
/// ```
/// # use canton_solvency_merkle::*;
/// assert_eq!(parse_amount_18dp("1.5").unwrap(), 1_500_000_000_000_000_000);
/// assert_eq!(parse_amount_18dp("0").unwrap(), 0);
///
/// // A sign, a bare dot, or more than 18 fraction digits are errors, never
/// // a silent truncation.
/// assert!(parse_amount_18dp("-1").is_err());
/// assert!(parse_amount_18dp("1.").is_err());
/// assert!(parse_amount_18dp("0.0000000000000000001").is_err());
/// ```
pub fn parse_amount_18dp(s: &str) -> Result<u128> {
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    ensure!(!int_part.is_empty(), "amount {s:?} missing integer part");
    ensure!(
        s.split_once('.').is_none() || !frac_part.is_empty(),
        "amount {s:?} has a bare decimal point"
    );
    ensure!(
        frac_part.len() <= SCALE_DIGITS,
        "amount {s:?} exceeds 18 decimal places"
    );
    ensure!(
        int_part.chars().all(|c| c.is_ascii_digit())
            && frac_part.chars().all(|c| c.is_ascii_digit()),
        "amount {s:?} is not a non-negative decimal"
    );
    let int: u128 = int_part.parse()?;
    let frac: u128 = if frac_part.is_empty() {
        0
    } else {
        format!("{frac_part:0<18}").parse()?
    };
    int.checked_mul(SCALE)
        .and_then(|v| v.checked_add(frac))
        .ok_or_else(|| anyhow::anyhow!("amount {s:?} overflows"))
}

/// Renders 18dp fixed point in the canonical form, always with exactly 18
/// fraction digits so two producers cannot disagree about the same amount.
///
/// ```
/// # use canton_solvency_merkle::*;
/// assert_eq!(format_amount_18dp(1_500_000_000_000_000_000), "1.500000000000000000");
/// assert_eq!(format_amount_18dp(0), "0.000000000000000000");
/// ```
pub fn format_amount_18dp(v: u128) -> String {
    format!("{}.{:018}", v / SCALE, v % SCALE)
}

/// Canonical wire form committed into hashes: assets sorted bytewise,
/// each rendered as `ASSET:int.<18 digits>`, joined by `|`.
/// ```
/// # use canton_solvency_merkle::*;
/// let balances = vec![
///     ("USDA".to_string(), parse_amount_18dp("1").unwrap()),
///     ("CBTC".to_string(), parse_amount_18dp("0.25").unwrap()),
/// ];
/// // Assets are ordered bytewise over UTF-8 -- not by the platform's default
/// // string comparison, which disagrees above U+FFFF.
/// assert_eq!(
///     canonical_balances(&balances).unwrap(),
///     "CBTC:0.250000000000000000|USDA:1.000000000000000000"
/// );
/// assert_eq!(canonical_balances(&[]).unwrap(), "");
/// ```
pub fn canonical_balances(balances: &[(String, u128)]) -> Result<String> {
    let mut sorted: Vec<&(String, u128)> = balances.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in sorted.windows(2) {
        if pair[0].0 == pair[1].0 {
            bail!("duplicate asset {:?} in balance set", pair[0].0);
        }
    }
    Ok(sorted
        .iter()
        .map(|(asset, v)| format!("{asset}:{}", format_amount_18dp(*v)))
        .collect::<Vec<_>>()
        .join("|"))
}

/// `u64le(len) ‖ utf8(s)`. Length prefixes keep a preimage unambiguous where
/// a delimiter join cannot: an asset literally named `A|B:1` can imitate two
/// entries in a joined encoding, and cannot here.
pub fn lp(s: &str) -> Vec<u8> {
    let mut out = (s.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(s.as_bytes());
    out
}

/// `u64le(count) ‖ (lp(asset) ‖ lp(canonical_amount))*`, assets bytewise.
pub fn lpmap(m: &BTreeMap<String, u128>) -> Vec<u8> {
    let mut out = (m.len() as u64).to_le_bytes().to_vec();
    for (asset, amount) in m {
        out.extend(lp(asset));
        out.extend(lp(&format_amount_18dp(*amount)));
    }
    out
}

const LEAF_DOMAIN: &[u8] = b"rocky-solvency-leaf-v1";
const LEAF_DOMAIN_V2: &[u8] = b"rocky-solvency-leaf-v2";

/// Map and asset names in a v2 leaf. Constrained because the §4 node hash
/// still joins sums with `:` and `|`, so an unconstrained qualified key could
/// forge a boundary. v1 has the same latent ambiguity and is left alone:
/// fixing it there would change every node hash.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Qualified key joining a map name to an asset: `collateral/USDA`.
pub fn qualified(map_name: &str, asset: &str) -> String {
    format!("{map_name}/{asset}")
}

/// H(domain ‖ salt ‖ H(subject_id) ‖ count ‖ (lp(map) ‖ lpmap(amounts))*)
///
/// A v2 leaf carries several named amount maps, so a statement can compare
/// them — a repo leg's collateral against its exposure — where a v1 leaf
/// could only carry balances.
pub fn leaf_hash_v2(
    salt: &[u8; 32],
    subject_id: &str,
    maps: &BTreeMap<String, BTreeMap<String, u128>>,
) -> Result<[u8; 32]> {
    for (map_name, amounts) in maps {
        ensure!(is_safe_name(map_name), "unsafe map name {map_name:?}");
        for asset in amounts.keys() {
            ensure!(is_safe_name(asset), "unsafe asset name {asset:?}");
        }
    }

    let mut h = Sha256::new();
    h.update(LEAF_DOMAIN_V2);
    h.update(salt);
    h.update(Sha256::digest(subject_id.as_bytes()));
    h.update((maps.len() as u64).to_le_bytes());
    for (map_name, amounts) in maps {
        h.update(lp(map_name));
        h.update(lpmap(amounts));
    }
    Ok(h.finalize().into())
}

/// A v2 leaf node. Its sums are every map flattened under qualified keys, so
/// the root publishes a total per map per asset and a statement comparing two
/// maps is checkable at the root rather than only per leaf.
pub fn leaf_node_v2(
    salt: &[u8; 32],
    subject_id: &str,
    maps: &BTreeMap<String, BTreeMap<String, u128>>,
) -> Result<Node> {
    let hash = leaf_hash_v2(salt, subject_id, maps)?;
    let mut sums = BTreeMap::new();
    for (map_name, amounts) in maps {
        for (asset, amount) in amounts {
            sums.insert(qualified(map_name, asset), *amount);
        }
    }
    Ok(Node { hash, sums })
}

/// Per-user salt the server can re-derive on demand: HMAC(master, user_id).
/// The master salt rotates per snapshot day and never leaves the server;
/// users receive only their own derived salt inside their proof.
/// ```
/// # use canton_solvency_merkle::*;
/// // Deterministic, so a proof can be reissued; distinct per subject, so two
/// // customers holding identical balances still commit to different leaves.
/// let a = leaf_salt(b"snapshot-secret", "alice");
/// assert_eq!(a, leaf_salt(b"snapshot-secret", "alice"));
/// assert_ne!(a, leaf_salt(b"snapshot-secret", "bob"));
/// assert_ne!(a, leaf_salt(b"other-snapshot", "alice"));
/// ```
pub fn leaf_salt(master_salt: &[u8], user_id: &str) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(master_salt).expect("hmac accepts any key length");
    mac.update(user_id.as_bytes());
    mac.finalize().into_bytes().into()
}

/// H(domain ‖ salt ‖ H(user_id) ‖ canonical(balances))
pub fn leaf_hash(salt: &[u8; 32], user_id: &str, balances: &[(String, u128)]) -> Result<[u8; 32]> {
    let canonical = canonical_balances(balances)?;
    let mut h = Sha256::new();
    h.update(LEAF_DOMAIN);
    h.update(salt);
    h.update(Sha256::digest(user_id.as_bytes()));
    h.update(canonical.as_bytes());
    Ok(h.finalize().into())
}

const NODE_DOMAIN: &[u8] = b"rocky-solvency-node-v1";

/// A tree node: hash plus the per-asset sums it commits to. The root's
/// `sums` are the published liability totals, provably aggregated from
/// every leaf below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub hash: [u8; 32],
    pub sums: BTreeMap<String, u128>,
}

pub fn leaf_node(salt: &[u8; 32], user_id: &str, balances: &[(String, u128)]) -> Result<Node> {
    let hash = leaf_hash(salt, user_id, balances)?;
    let mut sums = BTreeMap::new();
    for (asset, v) in balances {
        if sums.insert(asset.clone(), *v).is_some() {
            bail!("duplicate asset {asset:?} in balance set");
        }
    }
    Ok(Node { hash, sums })
}

fn sums_canonical(sums: &BTreeMap<String, u128>) -> String {
    sums.iter()
        .map(|(asset, v)| format!("{asset}:{}", format_amount_18dp(*v)))
        .collect::<Vec<_>>()
        .join("|")
}

fn combine(left: &Node, right: &Node) -> Result<Node> {
    let mut sums = left.sums.clone();
    for (asset, v) in &right.sums {
        let slot = sums.entry(asset.clone()).or_insert(0);
        *slot = slot
            .checked_add(*v)
            .ok_or_else(|| anyhow::anyhow!("sum overflow on asset {asset:?}"))?;
    }
    let mut h = Sha256::new();
    h.update(NODE_DOMAIN);
    h.update(left.hash);
    h.update(right.hash);
    h.update(sums_canonical(&sums).as_bytes());
    Ok(Node {
        hash: h.finalize().into(),
        sums,
    })
}

/// Merkle sum tree. Odd nodes are promoted to the next level unchanged
/// (never duplicated, so no value is counted twice).
pub struct SumTree {
    levels: Vec<Vec<Node>>,
}

impl SumTree {
    pub fn build(leaves: Vec<Node>) -> Result<Self> {
        ensure!(!leaves.is_empty(), "cannot build a tree with no leaves");
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                next.push(match pair {
                    [left, right] => combine(left, right)?,
                    [odd] => odd.clone(),
                    _ => unreachable!(),
                });
            }
            levels.push(next);
        }
        Ok(Self { levels })
    }

    pub fn root(&self) -> &Node {
        &self.levels.last().unwrap()[0]
    }

    /// Sibling path for `leaf_index`. Levels where the node was promoted
    /// without a sibling contribute no step.
    pub fn prove(&self, leaf_index: usize) -> Result<Proof> {
        ensure!(
            leaf_index < self.levels[0].len(),
            "leaf index {leaf_index} out of range"
        );
        let mut steps = Vec::new();
        let mut idx = leaf_index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = idx ^ 1;
            if sibling_idx < level.len() {
                steps.push(ProofStep {
                    sibling: level[sibling_idx].clone(),
                    sibling_on_left: sibling_idx < idx,
                });
            }
            idx /= 2;
        }
        Ok(Proof { steps })
    }
}

#[derive(Clone, Debug)]
pub struct ProofStep {
    pub sibling: Node,
    pub sibling_on_left: bool,
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub steps: Vec<ProofStep>,
}

/// Recomputes the path from `leaf` and compares hash AND sums against the
/// published root, so a verifier checks both inclusion and aggregation.
/// ```
/// # use canton_solvency_merkle::*;
/// # fn main() -> anyhow::Result<()> {
/// let leaves: Vec<Node> = ["a", "b", "c"]
///     .iter()
///     .map(|u| {
///         let salt = leaf_salt(b"secret", u);
///         leaf_node(&salt, u, &[("USDA".to_string(), 1_000_000_000_000_000_000)])
///     })
///     .collect::<anyhow::Result<_>>()?;
/// let tree = SumTree::build(leaves.clone())?;
///
/// // An odd tree promotes the last node unchanged, so it is never counted
/// // twice -- the root totals three units, not four.
/// assert_eq!(format_amount_18dp(tree.root().sums["USDA"]), "3.000000000000000000");
/// for (i, leaf) in leaves.iter().enumerate() {
///     assert!(verify_proof(leaf, &tree.prove(i)?, tree.root()));
/// }
/// # Ok(())
/// # }
/// ```
pub fn verify_proof(leaf: &Node, proof: &Proof, root: &Node) -> bool {
    let mut current = leaf.clone();
    for step in &proof.steps {
        let combined = if step.sibling_on_left {
            combine(&step.sibling, &current)
        } else {
            combine(&current, &step.sibling)
        };
        match combined {
            Ok(node) => current = node,
            Err(_) => return false,
        }
    }
    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_18dp_amount_strings() {
        assert_eq!(
            parse_amount_18dp("67234.12").unwrap(),
            67_234_120_000_000_000_000_000
        );
        assert_eq!(parse_amount_18dp("0").unwrap(), 0);
        assert_eq!(parse_amount_18dp("0.000000000000000001").unwrap(), 1);
        assert_eq!(parse_amount_18dp("1.5").unwrap(), 1_500_000_000_000_000_000);
    }

    #[test]
    fn rejects_malformed_amounts() {
        for bad in [
            "-1",
            "",
            "1.2.3",
            "abc",
            "1.0000000000000000001",
            ".5",
            "1.",
        ] {
            assert!(parse_amount_18dp(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn canonical_balances_sorts_assets_and_pins_18dp() {
        let s = canonical_balances(&[
            ("USDA".into(), 1_500_000_000_000_000_000),
            ("CBTC".into(), 1),
        ])
        .unwrap();
        assert_eq!(s, "CBTC:0.000000000000000001|USDA:1.500000000000000000");
    }

    #[test]
    fn canonical_balances_rejects_duplicate_assets() {
        let err = canonical_balances(&[("USDA".into(), 1), ("USDA".into(), 2)]).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn leaf_salt_is_deterministic_per_user_and_master() {
        let a = leaf_salt(b"master-1", "user-a");
        assert_eq!(a, leaf_salt(b"master-1", "user-a"));
        assert_ne!(a, leaf_salt(b"master-1", "user-b"));
        assert_ne!(a, leaf_salt(b"master-2", "user-a"));
    }

    #[test]
    fn leaf_hash_changes_with_any_input() {
        let salt = leaf_salt(b"m", "user-a");
        let balances = vec![("USDA".to_string(), 100 * SCALE)];
        let base = leaf_hash(&salt, "user-a", &balances).unwrap();
        assert_eq!(base, leaf_hash(&salt, "user-a", &balances).unwrap());
        assert_ne!(base, leaf_hash(&salt, "user-b", &balances).unwrap());
        assert_ne!(
            base,
            leaf_hash(&leaf_salt(b"m2", "user-a"), "user-a", &balances).unwrap()
        );
        assert_ne!(
            base,
            leaf_hash(&salt, "user-a", &[("USDA".to_string(), 101 * SCALE)]).unwrap()
        );
    }

    fn user_leaf(user: &str, balances: &[(&str, u128)]) -> Node {
        let balances: Vec<(String, u128)> =
            balances.iter().map(|(a, v)| (a.to_string(), *v)).collect();
        leaf_node(&leaf_salt(b"master", user), user, &balances).unwrap()
    }

    #[test]
    fn root_sums_are_the_per_asset_totals() {
        let tree = SumTree::build(vec![
            user_leaf("u1", &[("USDA", 100 * SCALE), ("CBTC", 2 * SCALE)]),
            user_leaf("u2", &[("USDA", 50 * SCALE)]),
            user_leaf("u3", &[("CETH", 7 * SCALE)]),
        ])
        .unwrap();
        let root = tree.root();
        assert_eq!(root.sums["USDA"], 150 * SCALE);
        assert_eq!(root.sums["CBTC"], 2 * SCALE);
        assert_eq!(root.sums["CETH"], 7 * SCALE);
    }

    #[test]
    fn empty_tree_is_an_error() {
        assert!(SumTree::build(vec![]).is_err());
    }

    #[test]
    fn root_hash_changes_when_any_leaf_changes() {
        let leaves = |u2_amount: u128| {
            vec![
                user_leaf("u1", &[("USDA", 100 * SCALE)]),
                user_leaf("u2", &[("USDA", u2_amount)]),
            ]
        };
        let a = SumTree::build(leaves(50 * SCALE)).unwrap();
        let b = SumTree::build(leaves(51 * SCALE)).unwrap();
        assert_ne!(a.root().hash, b.root().hash);
    }

    #[test]
    fn sum_overflow_is_an_error() {
        let big = user_leaf("u1", &[("USDA", u128::MAX - 5)]);
        let more = user_leaf("u2", &[("USDA", 100)]);
        assert!(SumTree::build(vec![big, more]).is_err());
    }

    fn five_leaves() -> Vec<Node> {
        (1..=5)
            .map(|i| user_leaf(&format!("u{i}"), &[("USDA", i as u128 * SCALE)]))
            .collect()
    }

    #[test]
    fn every_leaf_proof_verifies_against_the_root() {
        let leaves = five_leaves();
        let tree = SumTree::build(leaves.clone()).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            assert!(
                verify_proof(leaf, &proof, tree.root()),
                "leaf {i} proof failed"
            );
        }
    }

    #[test]
    fn tampered_leaf_fails_verification() {
        let leaves = five_leaves();
        let tree = SumTree::build(leaves.clone()).unwrap();
        let proof = tree.prove(1).unwrap();
        let forged = user_leaf("u2", &[("USDA", 2000 * SCALE)]);
        assert!(!verify_proof(&forged, &proof, tree.root()));
    }

    #[test]
    fn proof_against_wrong_root_fails() {
        let leaves = five_leaves();
        let tree = SumTree::build(leaves.clone()).unwrap();
        let other = SumTree::build(five_leaves()[..3].to_vec()).unwrap();
        let proof = tree.prove(0).unwrap();
        assert!(!verify_proof(&leaves[0], &proof, other.root()));
    }

    #[test]
    fn prove_rejects_out_of_range_index() {
        let tree = SumTree::build(five_leaves()).unwrap();
        assert!(tree.prove(5).is_err());
    }
}

#[cfg(test)]
mod leaf_v2 {
    use super::*;

    fn maps(entries: &[(&str, &[(&str, u128)])]) -> BTreeMap<String, BTreeMap<String, u128>> {
        entries
            .iter()
            .map(|(name, amounts)| {
                (
                    name.to_string(),
                    amounts.iter().map(|(a, v)| (a.to_string(), *v)).collect(),
                )
            })
            .collect()
    }

    fn repo_leg() -> BTreeMap<String, BTreeMap<String, u128>> {
        maps(&[
            ("collateral", &[("USDA", 110 * SCALE)]),
            ("exposure", &[("USDA", 100 * SCALE)]),
        ])
    }

    const SALT: [u8; 32] = [9u8; 32];

    #[test]
    fn a_v2_leaf_sums_every_map_under_a_qualified_key() {
        let node = leaf_node_v2(&SALT, "trade-1", &repo_leg()).unwrap();
        assert_eq!(node.sums["collateral/USDA"], 110 * SCALE);
        assert_eq!(node.sums["exposure/USDA"], 100 * SCALE);
        assert_eq!(node.sums.len(), 2);
    }

    #[test]
    fn the_hash_is_deterministic_and_independent_of_insertion_order() {
        let a = leaf_hash_v2(&SALT, "trade-1", &repo_leg()).unwrap();
        let reordered = maps(&[
            ("exposure", &[("USDA", 100 * SCALE)]),
            ("collateral", &[("USDA", 110 * SCALE)]),
        ]);
        assert_eq!(a, leaf_hash_v2(&SALT, "trade-1", &reordered).unwrap());
    }

    #[test]
    fn the_hash_changes_with_salt_subject_map_name_asset_or_amount() {
        let base = leaf_hash_v2(&SALT, "trade-1", &repo_leg()).unwrap();
        assert_ne!(
            base,
            leaf_hash_v2(&[8u8; 32], "trade-1", &repo_leg()).unwrap()
        );
        assert_ne!(base, leaf_hash_v2(&SALT, "trade-2", &repo_leg()).unwrap());

        let renamed = maps(&[
            ("collateral", &[("USDA", 110 * SCALE)]),
            ("margin", &[("USDA", 100 * SCALE)]),
        ]);
        assert_ne!(base, leaf_hash_v2(&SALT, "trade-1", &renamed).unwrap());

        let other_asset = maps(&[
            ("collateral", &[("CBTC", 110 * SCALE)]),
            ("exposure", &[("USDA", 100 * SCALE)]),
        ]);
        assert_ne!(base, leaf_hash_v2(&SALT, "trade-1", &other_asset).unwrap());

        let other_amount = maps(&[
            ("collateral", &[("USDA", 111 * SCALE)]),
            ("exposure", &[("USDA", 100 * SCALE)]),
        ]);
        assert_ne!(base, leaf_hash_v2(&SALT, "trade-1", &other_amount).unwrap());
    }

    /// Domain separation: a v1 and a v2 leaf over the same single map must
    /// not collide, or a v2 leaf could be presented as a v1 one.
    #[test]
    fn a_v1_and_a_v2_leaf_over_the_same_data_hash_differently() {
        let single = maps(&[("balances", &[("USDA", 5 * SCALE)])]);
        let v2 = leaf_hash_v2(&SALT, "u1", &single).unwrap();
        let v1 = leaf_hash(&SALT, "u1", &[("USDA".to_string(), 5 * SCALE)]).unwrap();
        assert_ne!(v1, v2);
    }

    /// The forgery the character restriction exists to stop: a qualified key
    /// must not be able to imitate a second entry in the node join.
    #[test]
    fn names_that_could_forge_a_node_boundary_are_rejected() {
        for bad in ["x|collateral/USDA", "a:b", "with/slash", "", "sp ace"] {
            let m = maps(&[("collateral", &[(bad, 1)])]);
            assert!(
                leaf_hash_v2(&SALT, "t", &m).is_err(),
                "asset {bad:?} should be rejected"
            );
            let m2 = maps(&[(bad, &[("USDA", 1)])]);
            assert!(
                leaf_hash_v2(&SALT, "t", &m2).is_err(),
                "map name {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for good in ["USDA", "C-BTC", "fund.nav", "a_b", "X1"] {
            let m = maps(&[("collateral", &[(good, 1)])]);
            assert!(leaf_hash_v2(&SALT, "t", &m).is_ok(), "{good:?} rejected");
        }
    }

    #[test]
    fn v2_leaves_build_a_tree_whose_root_totals_each_map() {
        let leaves: Vec<Node> = (1..=3)
            .map(|i| {
                let m = maps(&[
                    ("collateral", &[("USDA", i * 10 * SCALE)]),
                    ("exposure", &[("USDA", i * SCALE)]),
                ]);
                leaf_node_v2(&SALT, &format!("trade-{i}"), &m).unwrap()
            })
            .collect();
        let tree = SumTree::build(leaves.clone()).unwrap();
        assert_eq!(tree.root().sums["collateral/USDA"], 60 * SCALE);
        assert_eq!(tree.root().sums["exposure/USDA"], 6 * SCALE);
        for (i, leaf) in leaves.iter().enumerate() {
            assert!(verify_proof(leaf, &tree.prove(i).unwrap(), tree.root()));
        }
    }
}

#[cfg(test)]
mod golden {
    use super::*;

    /// Cross-implementation wire-format pin: the TS verifier in
    /// rocky.interface asserts these exact vectors. Changing any of these
    /// values is a leaf-format version bump, not a refactor.
    #[test]
    fn golden_vectors_pin_the_wire_format() {
        let master = b"golden-v1";
        let users: [(&str, Vec<(String, u128)>); 3] = [
            (
                "11111111-1111-7111-8111-111111111111",
                vec![("USDA".to_string(), 100_500_000_000_000_000_000)],
            ),
            (
                "22222222-2222-7222-8222-222222222222",
                vec![
                    ("CBTC".to_string(), 250_000_000_000_000_000),
                    ("USDA".to_string(), 1_000_000_000_000_000_001),
                ],
            ),
            ("33333333-3333-7333-8333-333333333333", vec![]),
        ];
        let leaves: Vec<Node> = users
            .iter()
            .map(|(uid, balances)| leaf_node(&leaf_salt(master, uid), uid, balances).unwrap())
            .collect();
        let salts: Vec<String> = users
            .iter()
            .map(|(uid, _)| hex::encode(leaf_salt(master, uid)))
            .collect();
        let tree = SumTree::build(leaves.clone()).unwrap();

        assert_eq!(
            salts[0],
            "3de523c46646d91361907f6158f560ed6c55b8684c595139b05df6b12e3ddbb1"
        );
        assert_eq!(
            salts[1],
            "332f77b30295afb7a346ba580de798bc08f3bada500905be6bd7a552c7eec458"
        );
        assert_eq!(
            hex::encode(leaves[1].hash),
            "b5fa416d215750e1a3ccd2b16dd0f906f35c3bfda8467cab3fe6977333e4e691"
        );
        assert_eq!(
            hex::encode(leaves[0].hash),
            "05666cf01538aa610cc1285d1acf84953a961bd8346154cec9fb8785bb626363"
        );
        assert_eq!(
            hex::encode(leaves[2].hash),
            "171f5e7577171aeabb58b3013b0e0e2d0b9f45b387fe8b1ed2027be1a0d7108c"
        );
        assert_eq!(
            hex::encode(tree.root().hash),
            "02885b0fc65c3d8992899c8acba1917cb838b18b7054b6675e3d89f2bf8f0970"
        );
        assert_eq!(
            format_amount_18dp(tree.root().sums["USDA"]),
            "101.500000000000000001"
        );
        assert_eq!(
            format_amount_18dp(tree.root().sums["CBTC"]),
            "0.250000000000000000"
        );
        let proof = tree.prove(1).unwrap();
        assert_eq!(proof.steps.len(), 2);
        assert_eq!(
            hex::encode(proof.steps[0].sibling.hash),
            "05666cf01538aa610cc1285d1acf84953a961bd8346154cec9fb8785bb626363"
        );
        assert!(proof.steps[0].sibling_on_left);
        assert!(verify_proof(&leaves[1], &proof, tree.root()));
    }
}
