//! Property tests over the commitment core (SPEC §1–§5).
//!
//! The unit tests check chosen examples. These check invariants over many
//! generated trees — the shapes nobody thinks to write down, especially the
//! odd-node promotion at every level, which is where a sum tree is most likely
//! to double-count or lose value.
//!
//! Deterministic on purpose. A seeded xorshift rather than a random source, so
//! a failure here is reproducible from the seed printed in the assertion
//! instead of being a flake somebody re-runs until it passes. Fixed seeds also
//! mean no new dependency in a crate that is now published.

use canton_solvency_merkle::*;
use std::collections::BTreeMap;

/// xorshift64*, adequate for generating test data and nothing else.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state is a fixed point for xorshift; steer around it rather
        // than silently generating a constant stream.
        Self(if seed == 0 { 0x9E3779B97F4A7C15 } else { seed })
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const ASSETS: [&str; 4] = ["USDA", "CBTC", "ETH", "a.b-c_1"];

fn balances(rng: &mut Rng) -> Balances {
    let count = rng.below(ASSETS.len() as u64 + 1) as usize;
    let mut chosen: Balances = Vec::new();
    for asset in ASSETS.iter().take(count) {
        // Values large enough to catch a mis-scaled amount, small enough that
        // a million-leaf sum cannot overflow u128 and turn a real bug into an
        // overflow error.
        let amount = rng.next() as u128 % 1_000_000_000_000_000_000_000;
        chosen.push((asset.to_string(), amount));
    }
    chosen
}

/// One asset's holdings for one leaf, before commitment.
type Balances = Vec<(String, u128)>;

/// A generated tree, the balances that went into it, and its leaf nodes.
struct Generated {
    tree: SumTree,
    balances: Vec<Balances>,
    leaves: Vec<Node>,
}

fn tree_of(seed: u64, leaf_count: usize) -> Generated {
    let mut rng = Rng::new(seed);
    let mut all = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..leaf_count {
        let b = balances(&mut rng);
        let user_id = format!("user-{i}");
        let salt = leaf_salt(b"property-master-salt", &user_id);
        nodes.push(leaf_node(&salt, &user_id, &b).expect("distinct assets"));
        all.push(b);
    }
    Generated {
        tree: SumTree::build(nodes.clone()).expect("non-empty"),
        balances: all,
        leaves: nodes,
    }
}

/// The root totals are exactly what the leaves hold. This is the claim the
/// whole format rests on, and the one odd-node promotion could break by
/// dropping a subtree or counting it twice.
#[test]
fn the_root_sums_every_leaf_exactly_once() {
    for leaf_count in 1..=64usize {
        for seed in [1u64, 42, 7919] {
            let g = tree_of(seed, leaf_count);
            let (tree, all) = (&g.tree, &g.balances);
            let mut expected: BTreeMap<String, u128> = BTreeMap::new();
            for b in all {
                for (asset, v) in b {
                    *expected.entry(asset.clone()).or_insert(0) += v;
                }
            }
            // Absent and zero are the same claim (SPEC §9.1), so compare over
            // the union rather than requiring identical key sets.
            let root = tree.root();
            for asset in expected.keys().chain(root.sums.keys()) {
                assert_eq!(
                    expected.get(asset).copied().unwrap_or(0),
                    root.sums.get(asset).copied().unwrap_or(0),
                    "leaf_count={leaf_count} seed={seed} asset={asset}"
                );
            }
        }
    }
}

/// Every leaf must be provable, at every tree size — including the odd sizes
/// where some levels contribute no step.
#[test]
fn every_leaf_verifies_at_every_tree_size() {
    for leaf_count in 1..=48usize {
        let g = tree_of(31, leaf_count);
        let (tree, nodes) = (&g.tree, &g.leaves);
        for (i, leaf) in nodes.iter().enumerate() {
            let proof = tree.prove(i).expect("index in range");
            assert!(
                verify_proof(leaf, &proof, tree.root()),
                "leaf {i} of {leaf_count} did not verify"
            );
        }
    }
}

/// A proof for one leaf must not verify another. Without this, a tree could
/// hand every customer the same proof.
#[test]
fn a_proof_does_not_verify_a_different_leaf() {
    for leaf_count in 2..=24usize {
        let g = tree_of(99, leaf_count);
        let (tree, nodes) = (&g.tree, &g.leaves);
        for i in 0..leaf_count {
            let proof = tree.prove(i).expect("index in range");
            for (j, other) in nodes.iter().enumerate() {
                if i == j || other == &nodes[i] {
                    continue; // identical leaves are legitimately interchangeable
                }
                assert!(
                    !verify_proof(other, &proof, tree.root()),
                    "leaf {j}'s node verified under leaf {i}'s proof \
                     (leaf_count={leaf_count})"
                );
            }
        }
    }
}

/// Editing any balance must move the root. A commitment that did not would let
/// a venue restate a balance after publishing.
#[test]
fn changing_any_single_balance_changes_the_root() {
    for leaf_count in 1..=32usize {
        let g = tree_of(1234, leaf_count);
        let (tree, all) = (&g.tree, &g.balances);
        let before = tree.root().hash;

        for target in 0..leaf_count {
            if all[target].is_empty() {
                continue; // nothing to perturb
            }
            let mut nodes: Vec<Node> = Vec::new();
            for (i, b) in all.iter().enumerate() {
                let mut b = b.clone();
                if i == target {
                    b[0].1 += 1;
                }
                let user_id = format!("user-{i}");
                let salt = leaf_salt(b"property-master-salt", &user_id);
                nodes.push(leaf_node(&salt, &user_id, &b).unwrap());
            }
            let after = SumTree::build(nodes).unwrap().root().hash;
            assert_ne!(
                before, after,
                "editing leaf {target} of {leaf_count} left the root unchanged"
            );
        }
    }
}

/// §1: the canonical render must survive a round trip, or two producers
/// disagree about the same amount.
#[test]
fn amounts_round_trip_through_the_canonical_render() {
    let mut rng = Rng::new(2024);
    for _ in 0..5_000 {
        let v = rng.next() as u128 * rng.below(1_000_000).max(1) as u128;
        let rendered = format_amount_18dp(v);
        assert_eq!(
            parse_amount_18dp(&rendered).expect("our own render must parse"),
            v,
            "round trip failed for {rendered}"
        );
        assert_eq!(
            rendered.split('.').nth(1).map(str::len),
            Some(18),
            "{rendered} does not carry exactly 18 fraction digits"
        );
    }
}

/// The privacy fact every customer should be told: your proof's first sibling
/// *is* another customer's leaf, so you learn their exact per-asset balances.
///
/// This is inherent to a sum tree, not a defect — a node carries its children's
/// totals, and at level 0 a child is one customer. It is asserted here so it
/// cannot stop being true quietly, and because a reader of
/// docs/SECURITY-ANALYSIS.md should be able to find the line that checks it.
#[test]
fn a_proofs_first_sibling_is_another_customers_exact_balance() {
    let g = tree_of(77, 8);
    let (tree, leaves) = (&g.tree, &g.leaves);

    for i in 0..leaves.len() {
        let proof = tree.prove(i).expect("index in range");
        let first = proof.steps.first().expect("a tree of eight has a partner");
        let partner = i ^ 1;
        assert_eq!(
            first.sibling.sums, leaves[partner].sums,
            "leaf {i}'s first sibling should be leaf {partner}'s exact balances"
        );
    }
}

/// §1 bounds the scaled value at 2^128 - 1. Pinned on both sides: the
/// TypeScript verifier parses with BigInt, which has no such limit, and
/// accepted amounts this producer cannot represent until the bound was
/// written down.
#[test]
fn the_largest_representable_amount_is_the_boundary_both_implementations_use() {
    let max = u128::MAX;
    let as_decimal = |v: u128| format!("{}.{:018}", v / SCALE_TEST, v % SCALE_TEST);
    assert_eq!(parse_amount_18dp(&as_decimal(max)).unwrap(), max);
    assert!(
        parse_amount_18dp(&"9".repeat(60)).is_err(),
        "an amount past u128 must be malformed, not wrapped"
    );
    // Checked arithmetic, so this holds in release builds too, where an
    // unchecked multiply would silently wrap a huge amount into a small one.
    assert!(parse_amount_18dp("999999999999999999999999999999999999999999").is_err());
}

const SCALE_TEST: u128 = 1_000_000_000_000_000_000;

/// §14 unanimity is only as strong as `leaf_count`, which nothing recomputes.
///
/// The argument is: each leaf contributes 0 or 1, the total equals
/// `leaf_count`, therefore every leaf contributed 1. Sound given `leaf_count`
/// — and `leaf_count` is signed metadata rather than anything the fold
/// produces. A publisher committing ten holders, eight compliant, asserts
/// eight and the check passes.
///
/// This is not a defect to fix in arithmetic: an inclusion proof attests to
/// one leaf, so no claim about every leaf follows from it. It is the same
/// limit that stops §5 from proving liabilities complete, and SPEC §14 now
/// says so instead of saying "proves".
#[test]
fn unanimity_can_be_satisfied_while_being_false() {
    let one = 1_000_000_000_000_000_000u128;
    let holder = |i: u8, attested: u128| {
        leaf_node(
            &[i; 32],
            &format!("h{i}"),
            &[("attested/R".to_string(), attested)],
        )
        .unwrap()
    };

    let mut leaves: Vec<Node> = (1u8..=8).map(|i| holder(i, one)).collect();
    leaves.push(holder(9, 0));
    leaves.push(holder(10, 0));
    let committed = leaves.len() as u128;

    let root = SumTree::build(leaves).unwrap().root().clone();
    let attested = root.sums["attested/R"] / one;

    // The indicator total is honest: the tree really does contain eight
    // compliant holders.
    assert_eq!(attested, 8);
    // And a publisher asserting leaf_count = 8 satisfies unanimity, while ten
    // holders were committed and two of them did not comply.
    let asserted_leaf_count = attested;
    assert_eq!(asserted_leaf_count, attested, "the §14 check passes");
    assert_ne!(
        asserted_leaf_count, committed,
        "yet it is not the number of leaves — the conclusion is false"
    );
}

/// The §2 join is ambiguous, demonstrated rather than asserted.
///
/// `{a: 1, b: 2}` and `{"a:1.000000000000000000|b": 2}` are different balance
/// maps with the same canonical string, so they have the same leaf hash — and
/// because §4 canonicalises node sums the same way, the collision survives all
/// the way to the root hash. A root hash therefore does not uniquely determine
/// the book it commits to.
///
/// SPEC §3.1 records this as a known limitation of v1 and fixes it for v2 by
/// restricting names. This test pins what it actually costs, so the security
/// analysis can describe a demonstrated property rather than a hypothetical.
#[test]
fn the_v1_join_admits_a_leaf_hash_collision() {
    let honest = vec![
        ("a".to_string(), parse_amount_18dp("1").unwrap()),
        ("b".to_string(), parse_amount_18dp("2").unwrap()),
    ];
    let forged = vec![(
        "a:1.000000000000000000|b".to_string(),
        parse_amount_18dp("2").unwrap(),
    )];

    assert_eq!(
        canonical_balances(&honest).unwrap(),
        canonical_balances(&forged).unwrap(),
        "the join should be ambiguous — if this fails, v1 was fixed and the \
         security analysis needs updating"
    );

    let salt = [3u8; 32];
    assert_eq!(
        leaf_hash(&salt, "u", &honest).unwrap(),
        leaf_hash(&salt, "u", &forged).unwrap(),
        "so the leaf hash collides"
    );

    // And it reaches the root: a sibling sharing no asset name lets the two
    // maps merge without interfering, so every node hash above agrees too.
    let sibling = leaf_node(&[9u8; 32], "other", &[("z".to_string(), 7)]).unwrap();
    let published = SumTree::build(vec![
        leaf_node(&salt, "u", &forged).unwrap(),
        sibling.clone(),
    ])
    .unwrap();
    let recomputed =
        SumTree::build(vec![leaf_node(&salt, "u", &honest).unwrap(), sibling]).unwrap();
    assert_eq!(
        published.root().hash,
        recomputed.root().hash,
        "the collision survives aggregation"
    );

    // What contains it: the sums are compared as maps, and these differ.
    assert_ne!(
        published.root().sums,
        recomputed.root().sums,
        "an implementation comparing canonical strings instead of maps would \
         accept this"
    );
}

/// The ambiguity stops at the report envelope, which is what the signature
/// covers. §8.1 length-prefixes where §2 joins, so the same two maps that
/// collide above do not collide here.
#[test]
fn the_length_prefixed_encoding_is_not_ambiguous_where_the_join_is() {
    let honest: BTreeMap<String, u128> = [
        ("a".to_string(), parse_amount_18dp("1").unwrap()),
        ("b".to_string(), parse_amount_18dp("2").unwrap()),
    ]
    .into_iter()
    .collect();
    let forged: BTreeMap<String, u128> = [(
        "a:1.000000000000000000|b".to_string(),
        parse_amount_18dp("2").unwrap(),
    )]
    .into_iter()
    .collect();

    let as_pairs =
        |m: &BTreeMap<String, u128>| -> Vec<(String, u128)> { m.clone().into_iter().collect() };
    assert_eq!(
        canonical_balances(&as_pairs(&honest)).unwrap(),
        canonical_balances(&as_pairs(&forged)).unwrap(),
        "§2 collides"
    );
    assert_ne!(lpmap(&honest), lpmap(&forged), "§8.1 must not");
}

/// §8.1: length prefixes exist so that no two distinct inputs share a
/// preimage. An asset literally named `A|B:0.000…001` must not be able to
/// imitate two entries.
#[test]
fn length_prefixed_maps_are_injective_where_a_join_is_not() {
    let forged: BTreeMap<String, u128> = [("A|B:0.000000000000000001".to_string(), 1u128)]
        .into_iter()
        .collect();
    let honest: BTreeMap<String, u128> = [("A".to_string(), 1u128), ("B".to_string(), 1u128)]
        .into_iter()
        .collect();
    assert_ne!(
        lpmap(&forged),
        lpmap(&honest),
        "a length-prefixed map collided with a delimiter forgery"
    );

    // And the primitive itself: concatenation must not be re-parseable.
    let mut ab = lp("ab");
    ab.extend(lp("c"));
    let mut a_bc = lp("a");
    a_bc.extend(lp("bc"));
    assert_ne!(ab, a_bc);
}

/// §3.1: v2 leaf names are restricted precisely because §4 still joins sums
/// with `:` and `|`. A name that could forge a boundary must be refused rather
/// than hashed.
#[test]
fn v2_rejects_names_that_could_forge_a_sums_boundary() {
    let salt = [7u8; 32];
    for bad in ["", "a|b", "a:b", "a b", "héllo"] {
        let maps: BTreeMap<String, BTreeMap<String, u128>> =
            [(bad.to_string(), BTreeMap::new())].into_iter().collect();
        assert!(
            leaf_hash_v2(&salt, "subject", &maps).is_err(),
            "map name {bad:?} should be refused"
        );

        let maps: BTreeMap<String, BTreeMap<String, u128>> = [(
            "collateral".to_string(),
            [(bad.to_string(), 1u128)].into_iter().collect(),
        )]
        .into_iter()
        .collect();
        assert!(
            leaf_hash_v2(&salt, "subject", &maps).is_err(),
            "asset name {bad:?} should be refused"
        );
    }
}

/// Distinct leaves must hash distinctly. Salts are derived per user, so two
/// customers holding identical balances still commit to different leaves —
/// otherwise a proof for one would serve for the other.
#[test]
fn identical_balances_under_different_users_hash_differently() {
    let b = vec![("USDA".to_string(), 1_000_000_000_000_000_000u128)];
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..500 {
        let user_id = format!("user-{i}");
        let salt = leaf_salt(b"property-master-salt", &user_id);
        let hash = leaf_hash(&salt, &user_id, &b).unwrap();
        assert!(seen.insert(hash), "leaf hash collision at {user_id}");
    }
}

/// A tree of one leaf has no steps, and its root is that leaf. Worth pinning:
/// it is the case an implementer is most likely to special-case wrongly.
#[test]
fn a_single_leaf_tree_is_its_own_root() {
    let g = tree_of(5, 1);
    let (tree, nodes) = (&g.tree, &g.leaves);
    assert_eq!(tree.root(), &nodes[0]);
    let proof = tree.prove(0).unwrap();
    assert!(proof.steps.is_empty(), "a lone leaf needs no siblings");
    assert!(verify_proof(&nodes[0], &proof, tree.root()));
}
