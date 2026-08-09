# Security analysis

What this format protects, what it does not, and where a reviewer should push.

This is written **by the implementers**, which is exactly why it is not a
security review. A third-party review is an unfinished M6 deliverable. This
document exists to make that review efficient rather than to substitute for
it: it says where we think the sharp edges are, including the ones we have not
resolved.

## What a passing verification actually proves

A customer's proof verifying against a signed report proves:

1. their balance is committed at the amount shown to them;
2. that commitment aggregates into the published root; and
3. the root's totals equal the sum of every committed leaf.

It does **not** prove that every real customer is in the tree. One proof
cannot: the tree could omit someone entirely and every other proof would still
verify. Detection relies on customers checking, which is why verification is
one click on the reference deployment and why the `recompute` verb exists for
an auditor holding the whole leaf set.

## Threats the format addresses

| Threat | Mechanism |
|---|---|
| Understating published totals while committing an honest tree | Verification compares folded sums as well as hashes (§9.1) |
| Double-counting via duplicated odd nodes | Odd nodes are promoted, never duplicated (§4) |
| One under-water account cancelling others | Negative equity is clamped and disclosed as bad debt (§1) |
| Brute-forcing a leaf from a small balance space | Per-user salt from a per-snapshot master salt (§3) |
| Tracking one customer across reports | Salts rotate per snapshot, so leaf hashes are unlinkable |
| Replaying a stale proof after a balance changes | Proofs name their report's digest (§9) |
| Reformatting a document to break a signature | The digest covers fields, not JSON bytes (§8.2) |
| Smuggling an unsigned field into a signed document | Unknown fields are rejected (§8.2) |
| Forging a field boundary with a crafted asset name | Length-prefixed digests; v2 leaves restrict names (§8.1, §3.1) |
| Swapping one subsidiary for another of equal total | Entity identity is bound into the group leaf (§13.1) |
| Comparing today's assets to last quarter's liabilities | Coverage statements bind both reports by digest (§11.1) |
| Quietly dropping a day of history | Anchors are hash-linked and must start at genesis (§12.1) |
| Presenting a mid-history anchor as the start | Presence byte distinguishes genesis (§12) |
| Reducing disclosure between reports without notice | The manifest is inside the signature and diffable (§8.5) |
| Two audiences handed different books | Packagings must share root, totals and leaf count (§14.4) |

Each has at least one test asserting the failure, and the conformance corpus
carries the ones a second implementation must also reject.

## Unresolved: publisher key distribution

**This is the weakest point in the system and it is not solved.**

Verification requires a caller-supplied trusted key, and the API makes it a
required argument so it cannot be skipped. But nothing in the format tells a
reader where to get that key. A reader who takes it from the same page that
served the report has verified internal consistency and nothing else.

§8.4 states this. The intended answer is anchoring: a key bound on-ledger is a
key obtainable from somewhere other than the publisher's web server. That
depends on the Daml package, which has never been compiled or deployed.

Until then, a deployment must document its own key distribution, and a
reviewer should treat any deployment that does not as unverified in practice
whatever its documents say.

## Known weaknesses we have accepted

**Sibling sums are disclosed.** A proof reveals sibling subtotals, and at leaf
level that is one other customer's exact balance — anonymous, but exact. This
is inherent to Merkle sum trees. Identities are not revealed and salt rotation
prevents cross-report linkage, but a reader should not be told the scheme
discloses nothing about others.

**The v1 node join is ambiguous.** §4 canonicalises sums with a `:`/`|` join.
An asset name containing those characters could in principle forge a boundary.
Fixed for v2 leaves by restricting names; **not** fixed for v1, because that
would change every node hash and invalidate every §6 vector. Deployments
controlling their own asset naming are unaffected; one accepting arbitrary
asset names should treat this as live.

**Snapshot frequency bounds everything.** A daily report commits to daily
states. Nothing here says anything about intra-day positions, and a venue
solvent at every snapshot may not have been between them.

**The asset side rests on attestation.** Coverage proves a custody claim and a
liabilities claim were published together and compared honestly. That the
custody report describes real holdings is an attestation problem; `custody_basis`
records how custody was established and is signed, but nothing proves it.

## Where a reviewer should push hardest

1. **Key distribution**, above. Everything else assumes the reader has the
   right key.
2. **The digest preimages.** They are hand-rolled rather than a standard
   canonical form. We believe length-prefixing makes them unambiguous; that
   belief is worth attacking, particularly the boundary between a v1 report
   digest and a v2 one.
3. **`leaf_salt = HMAC(master, user_id)`.** A master salt leak exposes every
   user's salt for that snapshot, making balances brute-forceable given the
   leaf hashes in circulating proofs. Rotation limits the blast radius to one
   snapshot; whether that is enough is a judgement we would like challenged.
4. **The Ed25519 signature covers the digest, not the document.** Combined
   with unknown-field rejection we believe nothing can ride along unsigned.
   That is a claim about two mechanisms interacting, which is where these
   things usually go wrong.
5. **The Daml package**, once compiled. It has never run.
