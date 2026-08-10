# Building a conforming implementation

This is for an organisation that wants to publish or verify these reports with
its own code. It exists because Milestone 6 asks for a second independent
implementation, and the honest way to ask for one is to make the work small
and the acceptance criteria unambiguous rather than to describe the goal.

You do not need to read the Rust or the TypeScript. If you find yourself
needing to, that is a specification defect — please open an issue saying which
section ran out, which is exactly how the last six were found.

## The shortest useful path

**A verifier is smaller than it looks.** The reference audit implementation
([`spec-audit/verify_from_spec.py`](../spec-audit/verify_from_spec.py)) is one
file, standard library only, Ed25519 included, and covers `report-v1`,
`proof-v1` and `pack-v1`. It was written from SPEC.md alone. Read it beside
the spec if you want a worked example; do not port it, or you inherit its
author's assumptions, which is the failure this whole exercise is about.

Implement in this order — each step is independently testable against
published vectors:

1. **§1–§2** amounts and canonical serialization. Watch the ordering rule: keys
   sort **bytewise over UTF-8**, which is *not* JavaScript's default sort. This
   is the defect the third implementation caught in our own TypeScript.
2. **§3–§4** leaf and node hashing. You can now reproduce the §6 vectors, which
   are printed in the spec — no files needed.
3. **§5, §9.1** inclusion proofs and the five verification steps. Now
   `fixtures/proof.golden.json` verifies.
4. **§8** the report envelope and digest. Now `fixtures/report.golden.json`
   verifies, including its signature.
5. Anything further — §11 coverage, §12 anchoring, §13 hierarchy, §15 packs —
   as your use case needs. None is required to be conforming.

## Declaring what you implement

You are not expected to implement everything. §14.3 cases each declare
`requires`; you claim a feature set and run the cases that fall inside it.

Current feature names: `report-v1`, `report-v2`, `manifest`, `proof-v1`,
`proof-v2`, `leaf-v2`, `group-v1`, `coverage-v1`, `anchor-v1`, `pack-v1`.

A **verifier** claiming `report-v1` + `proof-v1` is useful and conforming. So
is a **producer** that only publishes. Partial is fine; undeclared is not.

## Acceptance: the corpus and a statement

```
git clone https://github.com/Rocky-exchange/canton-proof-of-solvency
# run conformance/manifest.json against your implementation
```

You are conforming when, for every case whose `requires` fall inside what you
claim, your outcome matches `expect` — and when you publish a §14.5
compatibility statement saying so. Generate one in the shape of:

```
python3 spec-audit/verify_from_spec.py --statement
```

Three rules make a statement worth reading, and they are checked, not assumed:

- A case inside your claimed feature set **may not** be skipped. Claiming a
  feature and skipping its cases is the failure this catches.
- A case outside it **must** be skipped, never reported as a pass. A verifier
  that rejects a document because it does not implement that version has
  tested nothing — and a rejection for the wrong reason looks exactly like a
  correct one. Our own audit implementation hit this and "passed" a manifest
  case without ever reading a manifest.
- `corpus_digest` binds your statement to the exact corpus you ran. Statements
  over different corpora are not comparable.

## Showing interop in both directions

One-directional interop is the easy half and proves less than it appears. Both
directions:

- **Your reports under our tools.** Add a directory to
  [`interop/`](../interop) with your documents and the trusted key, out of
  band. Our CI verifies them on every commit from then on — so a later change
  to our verifier that broke your documents fails our build, not yours. Any
  disagreement is a spec defect until shown otherwise.
- **Our reports under yours.** The golden fixtures and the corpus are checked
  in; verify them with your implementation and publish your statement.

If our two statements agree on every shared case, the format is pinned by two
implementers rather than by one author's assumptions twice over. If they
disagree, they disagree at a **named case**, which is the entire point of the
corpus over a prose report that "we tested it".

## What we will do

Open an issue or email the maintainer address in
[SECURITY.md](../SECURITY.md). We will review your statement, run your
fixtures against both reference implementations, and fix any specification
ambiguity your implementation surfaces — the last six such fixes are recorded
in [`spec-audit/README.md`](../spec-audit/README.md), including one real
interoperability bug in our own browser verifier.
