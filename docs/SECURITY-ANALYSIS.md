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

## Publisher key distribution: answered, with a caveat

This was previously the weakest point and unsolved. Verification requires a
caller-supplied trusted key, and a reader who takes that key from the same
page that served the report has verified internal consistency and nothing
else.

An anchor now carries `publisher_key`: the Ed25519 key that signed the report
it anchors, bound into the anchor digest and into the on-ledger contract. A
reader who can see the anchor obtains the key from the ledger — a source
independent of the publisher's web server, which a key embedded in the report
can never be. `verify_with_anchor` takes the key from the anchor rather than
from the caller, and refuses an anchor that describes a different report, so
anchoring cannot launder an arbitrary key into a trusted one.

**The caveat, which a reviewer should press on.** This does not make the
ledger trustworthy on the reader's behalf. It moves the question from *"is
this the right key?"* — which a reader had no way to answer — to *"can I see
this publisher's anchors?"*, which they can. A reader with no visibility of
the anchor contract is exactly where they were before, and a deployment that
does not disclose anchors to the audience it expects to verify has not
actually solved anything. Disclosure scope is therefore a deployment
obligation, not a format guarantee.

Substituting a key is also not quiet: the key is inside the anchor digest, so
changing it breaks every later link in the history.

## Known weaknesses we have accepted

**Sibling sums are disclosed.** A proof reveals sibling subtotals, and at leaf
level that is one other customer's exact balance — anonymous, but exact. This
is inherent to Merkle sum trees. Identities are not revealed and salt rotation
prevents cross-report linkage, but a reader should not be told the scheme
discloses nothing about others.

*How far does it go under collusion?* Measured, by
[`examples/sibling_leakage.rs`](../rust/solvency-merkle/examples/sibling_leakage.rs),
which reconstructs everything a colluding set can derive: their own leaves,
every sibling subtree sum along their paths, the published root, and then the
fixpoint of `parent = left + right` applied in both directions.

| Leaves | Colluders | Other customers exposed |
|---|---|---|
| 1,024 | 1 | 1 |
| 1,024 | 2 | 2 |
| 1,024 | 128 | 128 |
| 1,024 | 512 | 512 (the whole rest of the book) |

**`k` colluders expose at most `k` others, and exactly `k` when no two of them
are already paired.** There is no cascade: the subtree sums above level 0 leave
too many unknowns to resolve into individual leaves. Half the book colluding
exposes the other half, because at that density every remaining customer is
somebody's partner.

Placement changes the number and not the shape. At 1,024 leaves with 64
colluders: spread evenly, 64 others exposed; arranged as adjacent pairs or one
contiguous block, **zero**, because each colluder already held their partner's
leaf and learns nothing new from it.

**Leaf ordering was the exploitable part, and it is fixed.** §4 lets the
producer order leaves as it likes, and the obvious choice — ascending
`user_id` — is attackable. An attacker who can influence their own identifier
registers two accounts around a target: one to fix the parity of the target's
index, one to land in the pair position. The second account's own proof then
carries the target's exact balances. Two accounts, no special access, and it
worked every time.

The reference producer now orders by the **derived salt**,
`HMAC(master_salt, user_id)`, with the master salt a per-snapshot secret. It is
equally stable and deterministic for the producer and unpredictable to everyone
else, so nobody can aim. Measured over sixty snapshots, the same attacker was
paired with the target in 13% of them — chance, where identifier ordering gave
100%.

What this does *not* do is stop the disclosure. An attacker still learns
somebody's exact balances from each proof they hold, and over enough snapshots
they will be paired with any particular customer eventually. A fixed order
leaks the same neighbour every time; a rotating one leaks a different neighbour
each time, and neither dominates. What is removed is **targeting**, which was
the only part the attacker controlled.

A deployment that keeps identifier ordering keeps the attack. This is a
producer obligation rather than a format guarantee, which is why §7 states it
and §4 does not.

**The v1 node join is ambiguous — demonstrated, and bounded.** §2 and §4
canonicalise balance maps with a `:`/`|` join. That is not merely a theoretical
weakness, so here is the collision:

```
{ "a": 1, "b": 2 }                    ->  a:1.000000000000000000|b:2.000000000000000000
{ "a:1.000000000000000000|b": 2 }     ->  a:1.000000000000000000|b:2.000000000000000000
```

Two different books, one canonical string, therefore one leaf hash. And it
survives aggregation: give the sibling an asset name that shares no key with
either reading and the two maps merge without interfering, so **every node hash
above agrees, up to and including the root**. A v1 root hash does not uniquely
determine the book it commits to. Pinned by
`the_v1_join_admits_a_leaf_hash_collision` in
`rust/solvency-merkle/tests/properties.rs`.

Two things bound it, and both are load-bearing:

1. **The report digest is not ambiguous.** §8.1 length-prefixes where §2 joins,
   so the same two maps that collide above do not collide in `lpmap`. The
   digest, and therefore the signature and the anchor chain, commit
   unambiguously to the published totals.
2. **Verification compares sums as maps.** §9.1 step 5 compares per asset, over
   the union of both key sets. Comparing the *canonical strings* instead would
   be a tempting optimisation — the string is already computed for the hash —
   and would accept the collision. Both reference implementations compare maps;
   §9.1 now says they must.

We have not found an exploit. What we have is a commitment core that is not
binding, contained by the envelope around it. A reviewer should push on whether
that containment is complete, because it is the whole defence.

Still not fixed for v1, for the reason it never was: restricting names would
change every node hash and invalidate every §6 vector. v2 leaves restrict names
(§3.1). A deployment that controls its own asset naming is unaffected; one
accepting arbitrary asset names is relying entirely on the two bounds above.

**Unanimity rests on `leaf_count`, which nothing recomputes.** §14 lets a
profile assert a property of *every* subject by summing an indicator: if each
leaf carries `0` or `1` and the total equals `leaf_count`, every leaf carried
`1`. The arithmetic is sound. The premise is not verified.

`leaf_count` enters the §8.2 digest, so it cannot be altered after signing —
but no inclusion proof can check it against the tree. A publisher committing
ten holders, eight of them compliant, asserts `leaf_count = 8` and publishes
`attested/R = 8`. The check passes; the conclusion is false. Pinned by
`unanimity_can_be_satisfied_while_being_false` in
`rust/solvency-merkle/tests/properties.rs`.

Nothing in the format closes this, and it is worth being clear why rather than
proposing a fix that does not work. A `present` indicator fails for the same
reason — the publisher sets it to `0` on the leaves they are hiding. The real
obstruction is that an inclusion proof attests to one leaf, so no statement
about every leaf can follow from it. This is the completeness limit above,
reappearing wherever a profile makes a universal claim.

What does close it is disclosure: `recompute` rebuilds the tree from a full
leaf dump and verifies `leaf_count` directly. A unanimity claim is therefore as
strong as the auditor's access, and §14 now says "consistent with" where it
used to say "proves".

**The on-ledger anchor digest is asserted, not verified.** §12's
`anchor_digest` is a field of the Daml contract, and the contract's `ensure`
can check only that it is 64 lowercase hex characters. The digest preimage is
a length-prefixed binary concatenation and the hashing available to a Daml
contract operates on text, so the contract cannot reproduce it.

The cost is bounded because every input to the digest is also a field of the
contract: a reader who can see an anchor can recompute the digest and compare,
which is what `verify_chain` does off-ledger. The failure mode is a reader who
walks the chain using the stored digests without recomputing — trusting the
publisher about exactly what anchoring exists to take out of their hands. The
template comment used to invite that reading; §12 and the template now say the
opposite.

**Snapshot frequency bounds everything.** A daily report commits to daily
states. Nothing here says anything about intra-day positions, and a venue
solvent at every snapshot may not have been between them.

**The asset side rests on attestation.** Coverage proves a custody claim and a
liabilities claim were published together and compared honestly. That the
custody report describes real holdings is an attestation problem; `custody_basis`
records how custody was established and is signed, but nothing proves it.

## Where a reviewer should push hardest

1. **Whether anchoring really answers key distribution**, above. It relies on
   the reader being able to see the anchor contract, which is a deployment
   property rather than something the format can guarantee.
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
