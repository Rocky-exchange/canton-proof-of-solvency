# Canton Proof-of-Solvency — Wire Format Specification v1

This document pins the exact byte-level format of the solvency commitment so
that independent implementations interoperate. Two reference implementations
ship in this repository — Rust (prover side) and TypeScript (browser verifier)
— and both assert the golden vectors in §6. **Any change that breaks those
vectors is a new format version, not a refactor.**

## 1. Amounts

All amounts are non-negative fixed-point decimals with **18 fractional
digits**, transported as strings.

- Parse: `int_part [ "." frac_part ]`, both ASCII digits, `frac_part` length
  ≤ 18, no sign, no bare `.`, integer part required. Value =
  `int_part · 10^18 + rpad(frac_part, 18, "0")` as an unsigned integer.
- Canonical render: `"{int}.{frac:018}"` — always exactly 18 fraction digits.
- Negative balances never enter the tree. Producers clamp negative equity to
  zero upstream and disclose the shortfall separately (bad debt).

## 2. Canonical balance serialization

A balance set `{asset → amount}` serializes as:

```
asset₁:amount₁|asset₂:amount₂|…
```

- Assets sorted by **bytewise** (ASCII) order of the asset string.
- Amounts in canonical 18-digit render (§1).
- Duplicate assets are an error. The empty set serializes to the empty string.

## 3. Leaf

```
leaf_hash = SHA-256( "rocky-solvency-leaf-v1"
                   ‖ salt
                   ‖ SHA-256(utf8(user_id))
                   ‖ utf8(canonical_balances) )
```

- `salt` is 32 bytes: `HMAC-SHA256(master_salt, utf8(user_id))`. The master
  salt is a per-snapshot secret held by the prover; each user receives only
  their own derived salt inside their proof.
- `user_id` is the UTF-8 identity string (e.g. a UUID).
- A leaf **node** carries `(leaf_hash, sums)` where `sums` is the balance map.

## 4. Merkle sum tree

Internal node over children `L`, `R`:

```
sums  = per-asset sum of L.sums and R.sums   (checked addition; overflow = error)
hash  = SHA-256( "rocky-solvency-node-v1"
               ‖ L.hash ‖ R.hash
               ‖ utf8(canonical(sums)) )
```

- Leaves are paired left-to-right in a stable order chosen by the producer
  (reference deployment: ascending `user_id`).
- An **odd node is promoted** to the next level unchanged — never duplicated,
  so no value is counted twice.
- The **root's `sums` are the published liability totals**: a verifier that
  recombines any inclusion path also re-derives (part of) the aggregation,
  and equal roots imply equal totals.

## 5. Inclusion proof

A proof for leaf `i` is the ordered list of steps from leaf level upward:

```
step = { sibling: (hash, sums), sibling_on_left: bool }
```

Levels where the node was promoted without a sibling contribute **no step**.

Verification: recompute the leaf hash from the disclosed preimage
(salt, user_id, balances), fold the steps with the §4 node rule, then compare
**both** the final hash and the final per-asset sums against the published
root. Comparing sums is what upgrades inclusion into aggregation-consistency.

## 6. Golden vectors

Master salt: ASCII `golden-v1`.

| user_id | balances |
|---|---|
| `11111111-1111-7111-8111-111111111111` | `USDA = 100.5` |
| `22222222-2222-7222-8222-222222222222` | `CBTC = 0.25`, `USDA = 1.000000000000000001` |
| `33333333-3333-7333-8333-333333333333` | (empty) |

Expected values (hex):

```
salt(u1)   = 3de523c46646d91361907f6158f560ed6c55b8684c595139b05df6b12e3ddbb1
salt(u2)   = 332f77b30295afb7a346ba580de798bc08f3bada500905be6bd7a552c7eec458
leaf(u1)   = 05666cf01538aa610cc1285d1acf84953a961bd8346154cec9fb8785bb626363
leaf(u2)   = b5fa416d215750e1a3ccd2b16dd0f906f35c3bfda8467cab3fe6977333e4e691
leaf(u3)   = 171f5e7577171aeabb58b3013b0e0e2d0b9f45b387fe8b1ed2027be1a0d7108c
root       = 02885b0fc65c3d8992899c8acba1917cb838b18b7054b6675e3d89f2bf8f0970
root sums  = CBTC: 0.250000000000000000 | USDA: 101.500000000000000001
proof(u2)  = 2 steps; step₀ sibling = leaf(u1), sibling_on_left = true
```

## 7. Producer obligations (informative)

The tree alone does not make a solvency claim. A conforming producer also
publishes, per report: the snapshot timestamp and ledger high-water mark, the
mark prices used for any unrealized-PnL folding, per-asset liability totals
(= root sums), custody asset totals, insurance/bad-debt disclosures, and the
count of excluded house accounts. See the reference deployment's methodology
page for a complete example.
