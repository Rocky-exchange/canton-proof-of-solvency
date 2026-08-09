# Hierarchical Commitments — Design

**Date:** 2026-08-09
**Status:** approved, implementing
**Milestone:** M3 (first slice)

## Problem

A large institution is not one book. A group has subsidiaries, each with its
own regulator, its own auditor, and its own confidentiality obligations toward
its siblings. Today this project can commit to one book. A group-level
liability figure would have to be asserted, and a subsidiary proving its
position to its own regulator would have to expose the whole group.

This is the "deep entity hierarchy" case the README pitches at institutions
new to Canton, and nothing in the code supports it yet.

## Key finding: no format break needed

`SumTree::build` takes `Vec<Node>` — arbitrary nodes, not user leaves. A group
tree over entity roots is therefore expressible in wire format v1 as it
stands. The only new primitive is a leaf that binds an entity's identity to
its root, which is additive: a new domain string, no change to
`rocky-solvency-{leaf,node,report}-v1` and no change to the report envelope.

Reusing an entity's root node directly as a group leaf would be simpler still,
but it would let a group swap one subsidiary's subtree for another's of equal
total without detection. Binding `entity_id` into the leaf hash closes that.

## Scope

**In:** the entity leaf, group publication, a membership-proof document, and
verification of a full chain — customer → entity → consolidated group total.

**Out:** the profile registry and the four non-solvency profiles (they need a
richer leaf than `balances`, which is a v2 conversation), the disclosure
manifest (it must be bound *into* the signed report, so it forces report v2),
and audience-scoped packaging. Nesting is one level: group over entities, not
arbitrary depth — nothing observed needs deeper, and each level is a new
verification surface.

## Wire format

```
entity_leaf_hash = SHA-256( "rocky-solvency-entity-v1"
                          ‖ lp(entity_id)
                          ‖ entity_root_hash            (32 raw bytes)
                          ‖ lpmap(entity_root_sums) )
entity_leaf_node = (entity_leaf_hash, entity_root_sums)
```

The group tree is `SumTree::build(entity_leaf_nodes)` under the existing §4
node rule, so the group root's sums are the consolidated totals by
construction.

A **group report** is an ordinary report (SPEC §8) with `profile` =
`solvency.group`, `root_hash` = the group root, `root_sums` = the consolidated
totals, and `leaf_count` = the number of entities. No envelope change.

A **membership document**:

```json
{
  "format_version": "canton-solvency-group-membership-v1",
  "group_report_digest": "<hex32>",
  "entity": { "entity_id": "...", "root_hash": "<hex32>", "root_sums": {...} },
  "steps": [ { "sibling_hash": "...", "sibling_sums": {...}, "sibling_on_left": true } ]
}
```

## Verification

`verify_membership(group_report, membership, trusted_key)` mirrors §9.1:
versions, digest binding, signature against the caller-supplied key, recompute
the entity leaf, fold, then compare **both** the folded hash against the group
root and the folded sums against the consolidated totals.

`verify_chain(group_report, membership, entity_report, proof, keys)` composes
it: the customer's proof verifies against the entity report (§9.1), and the
membership document's `entity.root_hash` and `entity.root_sums` must equal the
entity report's own root and totals. Without that equality check the two
halves would be independently valid and jointly meaningless — a group could
present entity A's membership beside entity B's report.

A subsidiary's regulator sees the entity's own report plus sibling hashes and
subtotals. Sibling *identities* are never revealed: an entity leaf hash
discloses nothing about which entity it is. Sibling subtotals are visible, as
they are for user leaves in §5 — the same trade-off, stated rather than
hidden.

## Error handling

Reuses `VerificationFailure` with two additions:

- `EntityRootMismatch` — the membership document describes a different root
  than the entity's report publishes.
- `EntitySumsMismatch { asset }` — same, for the totals.

Both are distinct from `RootHashMismatch`, which means the fold failed. A
verifier that collapsed them would leave a group unable to tell "your proof is
bad" from "you handed me the wrong entity's report".

## Testing

- Every entity's membership verifies against the group root.
- Consolidated totals equal the sum of entity totals, across ragged asset sets.
- Swapping two entities' identities while keeping totals fails — the property
  that justifies binding `entity_id`.
- A membership paired with a different entity's report fails with
  `EntityRootMismatch`, not a fold failure.
- A full chain verifies: customer → entity → group.
- A customer whose entity is absent from the group cannot produce a chain.
- One entity, and odd entity counts, verify (promotion path).
- Golden vectors: a two-entity group over the §6 fixture, asserted by Rust and
  TypeScript against checked-in files.

## Implementation sequence

1. `entity_leaf_node` + domain string, in the report crate.
2. `publish_group` producing a group report and one membership per entity.
3. `verify_membership`, then `verify_chain`.
4. Golden fixtures + SPEC §13.
5. TypeScript mirror.
6. CLI `verify-group` verb.
7. READMEs, both languages.
