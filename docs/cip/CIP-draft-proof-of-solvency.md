# CIP draft — Verifiable disclosure for Canton

**Status:** draft, not submitted
**Author:** Rocky Exchange contributors
**Discussions-to:** https://github.com/Rocky-exchange/canton-proof-of-solvency/issues

> **This has not been submitted to the Canton Improvement Proposal process.**
> Submission is not something this repository can do on its own: a CIP needs a
> sponsor, a number allocated by the process, and — per its own requirements —
> evidence of more than one implementer. This draft exists so that the
> submission, when it happens, is a review of a written proposal rather than a
> request to write one.

## Abstract

A wire format by which an institution on Canton can prove a specific statement
about private ledger data — to a specific audience — without publishing the
data. Proof of solvency is the first profile; reserve coverage, repo
collateralisation, fund NAV, settlement assurance and holder eligibility are
others already specified against the same commitment core.

## Motivation

Canton's privacy model is the reason institutions can use it and the reason
nobody outside can check anything. On a public chain, transparency is a
by-product: anyone can recompute the totals from the ledger. On Canton there
is no such ledger, so every venue must publish its own evidence — and today
each does so in its own shape, or not at all.

Assets now moving onto Canton make this concrete. A tokenised Treasury needs
to prove custody backing. A repo platform needs to prove collateralisation. A
tokenised fund needs to prove NAV is backed. An atomic DvP needs to prove both
legs settled. Each is the same cryptographic operation with a different
audience and a different disclosed subset. Six bespoke implementations is how
an ecosystem ends up with no standard at all.

## Specification

The normative specification is
[SPEC.md](https://github.com/Rocky-exchange/canton-proof-of-solvency/blob/main/SPEC.md).
Summarised:

| Section | Defines |
|---|---|
| §1–§5 | Amounts, canonical encoding, leaves, the Merkle sum tree, inclusion proofs |
| §8 | The signed report envelope and its digest |
| §8.5 | The disclosure manifest, bound into the signature |
| §9 | Proof documents |
| §11 | Coverage: custody assets paired against liabilities |
| §12 | On-ledger anchoring of report history |
| §13 | Hierarchical commitments for group structures |
| §14 | The profile registry and the conformance corpus |

Design decisions a reviewer should focus on:

- **Sums are bound into every node hash**, so a root cannot be honest about
  membership and wrong about the total.
- **Odd nodes are promoted, never duplicated** — duplication double-counts.
- **Negative equity never enters the tree**; it is clamped and disclosed as
  bad debt rather than netted against other customers.
- **Length-prefixed digests** for everything added after v1, because
  delimiter joins are ambiguous under adversarial input.
- **The manifest is inside the signature**, so reducing disclosure is on the
  record rather than something a reader had to be watching for.

## Rationale

**Why not port an Ethereum proof-of-reserves design?** Those rest on
assumptions Canton does not provide: publicly readable reserves, proof of
control by signing from an address, a canonical block height, `uint256`
arithmetic, and an on-chain verifier anyone can call. On Canton both halves of
the inequality are private, there is no global block height, `Decimal` is a
signed `NUMERIC(38,18)`, and a Daml contract is visible only to its
stakeholders. The tree is the easy tenth of the problem.

**Why a browser verifier rather than an on-ledger one?** "On-ledger" does not
mean "publicly verifiable" on Canton. Verification therefore runs in the
client, and anchoring provides tamper-evidence rather than the trust root.

## Backwards compatibility

Format versions are carried in the domain strings baked into every hash. Any
change that breaks a golden vector ships under new domain strings; v1
documents keep verifying. Report v2 and leaf v2 were both introduced this way,
with v1 vectors untouched.

## Reference implementations

Two, in the same repository, asserting identical golden vectors and both
running the conformance corpus: a Rust producer and verifier, and a TypeScript
browser verifier.

A third verifier ([`spec-audit/`](https://github.com/Rocky-exchange/canton-proof-of-solvency/tree/main/spec-audit))
was written from the specification text alone, in dependency-free Python
including Ed25519, to test whether the document is implementable without the
code. It reproduces every published vector. It is deliberately *not* counted
as an independent implementation — same author, same repository — but it did
establish that the text is sufficient, and it found two defects the two
existing implementations could not:

- The TypeScript verifier sorted map keys by UTF-16 code units where §2
  requires UTF-8 bytewise order. The two disagree above U+FFFF, so a report
  naming an asset outside the BMP verified in Rust and failed in the browser.
  Every golden vector is ASCII, where the orders agree — two implementations
  sharing an author agreed for exactly that reason.
- A conformance case passed for the wrong reason: a verifier supporting only
  report v1 "passed" the manifest-lies case by rejecting a version it had
  never implemented. Cases now declare `requires` so a partial implementation
  filters by declaration.

Both are fixed, and the first is pinned by a conformance case that fails under
a UTF-16 sort. This is the argument for the process requiring an implementer
who did not write the spec.

## Security considerations

See
[SECURITY-ANALYSIS.md](https://github.com/Rocky-exchange/canton-proof-of-solvency/blob/main/docs/SECURITY-ANALYSIS.md).
The item a reviewer should press hardest on is **publisher key distribution**.
A key fetched from the same server that served the report proves nothing. §12
anchors now carry `publisher_key`, so a reader who can see a publisher's
anchors obtains the key from the ledger rather than from that server, and
`verify_with_anchor` refuses an anchor describing a different report. That
moves the question from "is this the right key?", which a reader had no way to
answer, to "can I see this publisher's anchors?", which they can — it does not
make the ledger trustworthy on their behalf, and a reader with no visibility
of the anchor contract is where they started. Disclosure scope is therefore a
deployment obligation, not a format guarantee.

## Open questions for the process

1. Should the profile registry live in the CIP, or in a separate registry
   document that can gain entries without a new CIP?
2. Is on-ledger anchoring in scope for a CIP at all, given it needs a Daml
   package and a governance decision about a public observer party?
3. What does the process require as evidence of a second implementation? The
   spec-audit exercise suggests the useful bar is an implementer who did not
   write the specification, rather than a second codebase — two codebases by
   one author share that author's assumptions, which is precisely how the
   sort-order defect survived.

## Unfinished before submission

- A second independent implementation. One organisation's implementations are
  not two implementers, however many languages they are written in.
- A third-party security review.

Completed since this draft was first written: the Daml anchoring package
compiles, passes its Daml Script tests, and has been deployed to a running
participant, where a three-anchor history was created and read back by an
auditor and then by a regulator after disclosure widened. Publisher key
distribution is answered as far as a format can answer it (above).
