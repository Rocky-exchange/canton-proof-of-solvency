# Third-party interop submissions

Drop your reports here and our CI verifies them with this toolkit, on every
commit, for as long as they stay in the repository.

This is one half of the interop Milestone 6 asks for. The other half — your
implementation verifying our corpus — is a [compatibility
statement](../statements/README.md). Together they close the loop: your
documents verify under our tools, ours verify under yours, and any
disagreement lands on a named document rather than in a prose report.

## Why this exists as a directory rather than an invitation

"Send us your reports and we'll check" is a promise. This is a procedure. It
means a producer can find out whether their output is acceptable *before*
asking anyone, and that once accepted it stays checked — a later change to our
verifier that broke your documents would fail our build, not yours, which is
the correct place for that cost to land.

## Layout

```
interop/
  your-org/
    submission.json
    report.json
    proof.json
```

`submission.json`:

```json
{
  "format_version": "canton-solvency-interop-v1",
  "organisation": "Your Venue",
  "contact": "someone@example.com or an issue URL",
  "implementation": "what produced these documents",
  "trusted_key": "<hex64>",
  "documents": [
    { "kind": "proof", "report": "report.json", "proof": "proof.json" }
  ]
}
```

`kind` is `proof` or `proof-v2`. List as many documents as you like; each is
verified independently.

**`trusted_key` is the point of the exercise.** You supply it here, out of
band, exactly as SPEC §8.4 requires — the harness never reads a key from the
report it is meant to authenticate. If you publish anchors, that key should be
the one your anchors carry.

## What is checked

[`rust/solvency-report/tests/interop.rs`](../rust/solvency-report/tests/interop.rs):

- every listed document verifies under [SPEC](../SPEC.md) §9.1 or §9.2, against
  the key you declared;
- every submission names a contact, so a failure has an addressee;
- the harness itself is proven able to fail — a test re-runs the worked example
  under a key that signed nothing and requires that it be rejected. A green CI
  that could not have gone red is not evidence.

## `_example/`

The worked example is our own golden fixture, and it is **not** a third-party
integration — it demonstrates the format and keeps the harness honest. It is
labelled as such in its `organisation` field rather than left to be inferred,
because a placeholder that reads like a real integration would overstate what
this project has achieved.

## Submitting

Open a pull request adding your directory. We will verify it, and if it fails
we will tell you which document and why. If the failure turns out to be our
specification being ambiguous rather than your implementation being wrong,
that is a specification defect and we fix it — six have been found that way
already, one of them a real bug in our own browser verifier. See
[`spec-audit/README.md`](../spec-audit/README.md).

Start with [`docs/INTEGRATORS.md`](../docs/INTEGRATORS.md) if you have not
built an implementation yet.
