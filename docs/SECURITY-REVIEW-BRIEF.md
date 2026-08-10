# Brief for an external security review

Milestone 6 asks for a third-party review of the commitment core, salt
derivation and verifier, published in-repo with its remediations. This is the
scoping document for that engagement. It exists so a reviewer can start on day
one instead of spending a week working out what the system claims.

The point of an external review here is specific: everything in this
repository was written by one author, so the failure mode is not sloppiness
but **consistent wrong assumptions**. A third implementation written from the
spec alone already found one real interoperability bug and five
under-specifications ([`spec-audit/`](../spec-audit)). That is evidence the
approach works and evidence there is more to find.

## What the system claims

Read [SPEC.md](../SPEC.md) §1–§9 first; the rest is composition on top.

1. **Inclusion.** A customer holding a proof can confirm their balance is
   inside the committed tree, without seeing any other customer.
2. **Aggregation.** The published totals are the sums of the committed leaves.
   Folding an inclusion path re-derives part of that sum, so equal roots imply
   equal totals (§4, §9.1 step 5).
3. **Privacy between customers.** A proof discloses the holder's own balances
   and sibling *sums* — not sibling identities or per-customer detail.
4. **Binding.** A proof is bound to one report by digest (§9), a coverage
   statement to a pair of reports (§11), an anchor to a report and its
   predecessor (§12), a pack to its delivery (§15).
5. **Attribution.** A signature identifies the publisher, given a trusted key
   obtained out of band (§8.4).

## Where to press hardest

Ranked by what would hurt most if wrong.

**Salt derivation and leaf privacy (§3).** `salt = HMAC-SHA256(master_salt,
user_id)`, one master salt per snapshot. A customer sees their own salt. Does
that leak anything about the master salt or another customer's? Is a
per-snapshot master salt the right granularity — what does an adversary
holding proofs across many snapshots learn? Balances are low-entropy and
guessable; the salt is what stands between a sibling sum and a confirmed
balance.

**Sibling sums as a side channel (§5).** A proof discloses each sibling's
per-asset sums. In a small or sparse tree, or for an unusual asset, that may
identify a specific counterparty's position.

We have since measured the collusion question rather than leaving it open —
see [SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md) and
[`examples/sibling_leakage.rs`](../rust/solvency-merkle/examples/sibling_leakage.rs).
`k` colluders expose at most `k` other customers, exactly `k` when none are
already paired, with no cascade above level 0. What we have *not* answered, and
would most like an independent view on: an adversary who can influence where
they land in the leaf ordering, which §4 leaves to the producer. Our numbers
assume they cannot.

**Domain separation and preimage ambiguity (§2, §3.1, §8.1).** We have since
constructed the collision rather than leaving it hypothetical — see
[SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md). A v1 root hash does not uniquely
determine the book. Two things bound it: the report digest is length-prefixed
and unambiguous, and verification compares sums as maps rather than as
canonical strings. **The question we would most like answered is whether that
containment is complete**, because it is the entire defence.

Original framing: v2 leaves and
all digests are length-prefixed. **v1 leaves and §4 node sums still use a
`:`/`|` delimiter join** over asset names that are attacker-influenced in the
general case. §3.1 records this as a known limitation and restricts v2 names;
v1 is unfixed because fixing it would move every §6 vector. We would like an
independent judgement on whether that trade is defensible and on what an
attacker can actually construct.

**The tree shape (§4).** Odd nodes are promoted, never duplicated. Is there a
second-preimage or shape-confusion attack — can two different leaf multisets
produce one root, given promotion and the sums binding?

**Universal claims (§14 unanimity).** A profile can assert a property of every
subject by summing an indicator against `leaf_count`. We have since shown the
premise is unverified — `leaf_count` is signed but not recomputed, so a
publisher can assert a smaller one, satisfy the check, and have the conclusion
be false. Documented rather than fixed, because we do not believe it is
fixable from an inclusion proof at all. That judgement is the thing we would
most like checked.

**Malformed input, as distinct from wrong input.** We found six places where a
document that was not a document crashed a verifier rather than failing it, all
in TypeScript, all in code whose signature promised a result. They are fixed and
tested. What we would like judged is whether the *class* is now closed or merely
thinned: our search was a grep for one pattern after we had found it four times
by hand, which is not the same as a systematic argument that no entry point can
raise.

**Verification order (§9.1, §15.3).** Both specify a fixed order and "fail on
the first that does not hold". Is any step skippable, or does any earlier
failure mask a later one that matters?

**Key distribution (§8.4, §12).** Anchors carry `publisher_key`, so a reader
who can see the anchor takes the key from the ledger rather than from the
server that served the report. We claim this moves the problem rather than
solving it, and that a reader with no anchor visibility is where they started.
Is that framing accurate, or overclaimed?

## Explicit non-goals

Please do not report these as findings; they are documented positions, in
[SECURITY-ANALYSIS.md](SECURITY-ANALYSIS.md) and the spec.

- **Liabilities are not proven complete.** A venue can omit a customer
  entirely. Only the omitted customer can detect it, by checking their own
  proof. No Merkle scheme fixes this; it is a disclosure-and-audit problem.
- **Assets are not proven owned.** §11 coverage reads holdings over the Ledger
  API; it does not prove exclusive control or non-borrowing.
- **v1 join ambiguity is known and unfixed** (above). Argue the trade if you
  disagree — but it is not an unknown.
- **Anchoring gives tamper-evidence to parties who can see the contract**, not
  public verifiability. Visibility is a deployment decision.

## Running everything

```
cargo test --manifest-path rust/solvency-report/Cargo.toml   # and the other three
cd ts/verifier && npm install && npm test
python3 spec-audit/verify_from_spec.py --verbose             # no dependencies
daml test                                                    # in daml/solvency-anchor
```

The commitment core is `rust/solvency-merkle` (~small, start here). The
conformance corpus is `conformance/`, 39 cases with declared expectations,
run by all three implementations.

## What we commit to

Findings and remediations are published in this repository, including anything
we choose not to fix and why. A review that produces "no findings" is
published as such. We would rather have an accurate record than a flattering
one — the sort bug above is in the changelog under its own heading for the
same reason.
