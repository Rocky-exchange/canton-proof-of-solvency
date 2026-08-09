# Leaf v2 — Named Amount Maps — Design

**Date:** 2026-08-09
**Status:** approved, implementing
**Milestone:** M3

## Why

A v1 leaf carries exactly one amount map: a customer's balances. That is
enough for `solvency.liabilities` and, via entity leaves, `solvency.group`.
It cannot express the profiles the README advertises. A repo leg has
**collateral and exposure**; comparing them is the entire statement.

Per [CONTRIBUTING.md](../../../CONTRIBUTING.md), a format change is discussed
before the PR. This is that discussion.

## The change is additive

`rocky-solvency-leaf-v2` is a **new domain string**. The §3 v1 leaf, every §6
vector, and every fixture are untouched and keep verifying — the same
discipline that let report v1 survive v2. Nothing that verifies today stops
verifying.

## Wire format

```
leaf_hash_v2 = SHA-256( "rocky-solvency-leaf-v2"
                      ‖ salt                        (32 bytes)
                      ‖ SHA-256(utf8(subject_id))
                      ‖ u64le(map_count)
                      ‖ ( lp(map_name) ‖ lpmap(amounts) )*   map names bytewise )
```

`lp`/`lpmap` are the §8.1 length-prefixed primitives, moved into the core
crate so one implementation serves both. v1's delimiter join is not reused:
having built length-prefixing for reports precisely because joins are
ambiguous under adversarial input, using a join again in a *new* format would
be indefensible.

### What the tree sums

This is the design's one real decision. A sum tree aggregates one amount
vector, and a v2 leaf has several maps.

**Qualified keys.** A leaf node's sums are `{"<map>/<asset>": amount}` across
every map. So a repo tree's root publishes `collateral/USDA` *and*
`exposure/USDA`, and coverage is checkable **at the root** rather than only
per leaf. That is what makes the profile's statement provable from a
published report rather than from a full leaf dump.

It also means the existing §4 node rule is unchanged: sums are still a flat
map of string to amount.

### Name validation

Because the §4 node hash still canonicalises sums with a `:`/`|` join, a
qualified key containing those characters could forge a boundary. v2 leaves
therefore **reject** map names and asset names that are empty or contain
anything outside `[A-Za-z0-9._-]`.

This closes the hole for v2 without a node-format change. The same latent
ambiguity exists in v1 and is **not** fixed here: fixing it would change every
node hash and therefore every §6 vector, which is a destructive change where
this one is additive. It is documented as a known limitation instead.

## Proof documents

A v2 leaf needs a v2 proof: `canton-solvency-proof-v2`, whose `leaf` carries
`{salt, subject_id, maps}` instead of `{salt, user_id, balances}`. `user_id`
becomes `subject_id` because a leaf is no longer necessarily a customer — for
`collateral.repo` it is a trade leg.

Verification dispatches on the proof version and rejects a v1 proof against a
v2-leaf profile, and vice versa, the same way §14 already refuses a customer
proof against a group report.

## First profile: `collateral.repo`

| | |
|---|---|
| A leaf is | one open repo leg |
| Maps | `collateral`, `exposure` (haircut-adjusted) |
| Root asserts | every open leg is committed; the root totals are aggregate collateral and aggregate exposure |
| Requires | `collateral/*` and `exposure/*` present |
| **Extra rule** | for every asset, aggregate `collateral` ≥ aggregate `exposure` |

That last rule is the point of the profile, and it is checked, not asserted —
a report declaring `collateral.repo` while publishing totals that do not cover
its exposure is rejected. Coverage is required per asset: a surplus in one
asset does not excuse a shortfall in another, the same rule the README states
for M1's multi-asset coverage.

Only this profile ships here. `fund.nav`, `settlement.dvp` and
`eligibility.holder` follow the same mechanism but each needs its own thought
about what a leaf is and what the root must assert; inventing three of those
in one pass would be guessing, not designing.

## Scope

**In:** `lp`/`lpmap` in the core, leaf v2 with validation, qualified sums,
proof v2, the producer and verifier paths, `collateral.repo` with its coverage
rule, golden vectors, the TypeScript mirror, SPEC §3.1/§9.2/§14.

**Out:** the other three profiles. A node-format fix for the v1 join
ambiguity. CLI verbs beyond what already dispatches.

## Testing

- Every v1 vector, fixture, and test still passes untouched.
- A v2 leaf's hash changes with the salt, subject, any map name, any asset,
  and any amount.
- Reordering maps does not change the hash; renaming one does.
- A v1 and a v2 leaf over the same single map hash differently.
- Names outside the safe character set are rejected, including the specific
  forgery: an asset named `x|collateral/USDA` cannot imitate a second entry.
- A repo report whose exposure exceeds its collateral in any asset is
  rejected, including when another asset is over-collateralised.
- A v1 proof against a `collateral.repo` report is refused, and vice versa.
- Rust and TypeScript agree on new fixtures.
