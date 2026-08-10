# Conformance corpus

The cases an implementation must agree on to claim compatibility with this
format (SPEC.md §14.3).

## What this is for

Golden vectors pin the bytes two implementations produce. They say nothing
about the *decisions* those implementations make — a second implementation
could reproduce every hash and still accept a report this format requires it
to reject. This corpus pins the decisions.

## Running it

Each case is a directory of documents plus an expected outcome. `manifest.json`
lists them, along with the trusted public key every case is verified against.

```bash
# The reference implementations, from the repository root:
cargo test --manifest-path rust/solvency-report/Cargo.toml --test conformance
cd ts/verifier && npm test -- conformance
```

For a **third-party implementation**, read `manifest.json` and, for each case:

1. Load the files named in `files` from the case's directory.
2. Verify them according to `kind`:

   | kind | documents | check |
   |---|---|---|
   | `proof` | `report.json`, `proof.json` | SPEC §9.1 |
   | `proof-v2` | `report.json`, `proof.json` | SPEC §9.2 |
   | `membership` | `group-report.json`, `membership.json` | SPEC §13.3 |
   | `coverage` | `custody.json`, `liabilities.json`, `statement.json` | SPEC §11.2 |
   | `anchors` | `history.json` | SPEC §12.1 |

3. Compare against `expect`: `accept` means verification succeeds, `reject`
   means it fails. `failure` names the expected reason where one applies; an
   implementation may report failures differently, so matching `expect` is
   what conformance requires.

## What a passing run does and does not mean

Passing means your implementation agrees with this one on every case here. It
does not mean the corpus is exhaustive — it is a floor, not a certificate, and
a case that matters to you and is missing here is worth contributing.

The runners assert a floor on both accepting and rejecting cases. A corpus of
only-accepting cases would pass against an implementation that accepts
everything.

## Regenerating

The corpus is derived from the golden fixtures so it cannot drift from them:

```bash
cargo run --manifest-path rust/solvency-report/Cargo.toml \
  --example emit_conformance -- ./conformance
```

A mutation that matches nothing aborts generation, because a rejection case
whose mutation silently no-ops is really testing that a valid document is
accepted.
