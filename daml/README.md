# Daml package: solvency report anchoring

Implements SPEC.md §12 on Canton: one immutable contract per published report,
hash-linked into a history the publisher cannot rewrite.

## Status — not built or tested here

**This package has never been compiled or run.** Building it needs the Daml SDK,
and testing it meaningfully needs a Canton participant node or localnet, neither
of which was available when it was written. Treat it as a reviewed design in
Daml syntax rather than as working code, and expect to fix compile errors on
first build.

Everything the chain *asserts* is verifiable without it. `canton-solvency-report`
implements the anchor digest and chain rules (`src/anchor.rs`), those rules are
tested offline, and the CLI walks a chain from anchor documents on disk. The
ledger adds permanence, not arithmetic.

## What it does not carry

Digests and offsets only — never balances. Putting amounts on a ledger contract
would disclose, to every observer, exactly the data the format exists to keep
private.

## What it deliberately omits

There is no choice to amend or archive an anchor. A history that can be edited
is not a history, and an `Archive` choice would hand back the power anchoring
removes. `Disclose` only ever widens the observer set: the original contract
remains, so nobody loses sight of an anchor they were already shown.

## Before this ships

- Compile against the SDK and fix what the type checker finds.
- Daml Script tests: a chain of anchors created in order; a second anchor
  claiming the same predecessor; an anchor failing `ensure`.
- Decide how a public observer party is provisioned on the target synchronizer,
  which is a deployment question this package cannot answer by itself.
