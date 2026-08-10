# Daml package: solvency report anchoring

Implements SPEC.md §12 on Canton: one immutable contract per published report,
hash-linked into a history the publisher cannot rewrite.

## Status — built, tested, and deployed to a running participant

`daml build` produces a DAR, `daml test` runs 8 Daml Script tests, and
`Deploy:initHistory` uploads the DAR to a running participant and creates a
real three-anchor history over the Ledger API, reading it back as an auditor
and then as a regulator after disclosure widens.

That deployment has been exercised against a **local Canton sandbox**, not
against a synchronizer carrying real value. The remaining step is a decision
rather than a capability: uploading to the participant a deployment actually
uses. The only one available here serves a live exchange.

Everything the chain *asserts* is verifiable without this package.
`canton-solvency-report` implements the anchor digest and chain rules
(`src/anchor.rs`), and the CLI walks a history from documents on disk. The
ledger adds permanence, not arithmetic.

## Building and deploying

```bash
daml build   # -> .daml/dist/canton-solvency-anchor-0.1.0.dar
daml test    # 8 scripts, in-memory

# Against a running participant:
daml sandbox --port 6865 &
daml script --dar .daml/dist/canton-solvency-anchor-0.1.0.dar \
  --script-name Deploy:initHistory --ledger-host localhost --ledger-port 6865 \
  --upload-dar yes
```

Needs the Daml SDK and a JDK. Built and tested against SDK 2.10.4 with
OpenJDK 17.

## What the scripts cover

What the ledger enforces that the offline chain rules cannot:

- a genesis anchor is creatable and readable by its observers;
- a later anchor names its predecessor;
- `ensure` rejects a malformed digest, an uppercase-hex digest, an empty
  ledger offset, and an unrecognised format version — so a contract that
  could not belong to any chain never reaches the ledger;
- `Disclose` widens the observer set without revoking the original, so nobody
  loses sight of an anchor they were already shown;
- only the publisher may widen disclosure of its own history.

## What it does not carry

Digests and offsets only — never balances. An amount on a ledger contract is
disclosed to every observer of that contract, which is exactly the data this
format exists to keep private.

## What it deliberately omits

No choice to amend or archive an anchor. A history that can be edited is not a
history, and an `Archive` choice would hand back the power anchoring removes.

## Before it ships to a synchronizer

- Upload to the participant a deployment actually uses, rather than a sandbox.
- Decide how a public observer party is provisioned on the target
  synchronizer — a deployment question this package cannot answer alone.

One thing the sandbox run already taught us: the `ensure` clause rejected this
very deploy script when it first used short digest stubs. The precondition is
not decoration.
