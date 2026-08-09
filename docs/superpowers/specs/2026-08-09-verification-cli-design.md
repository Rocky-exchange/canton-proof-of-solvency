# Verification CLI — Design

**Date:** 2026-08-09
**Status:** approved, implementing
**Milestone:** M5 (first slice — the parts that need no Canton access)

## Problem

M0 made the commitment publishable, but the only way to check a published
report is to write Rust or TypeScript against the libraries. An auditor cannot
verify a venue's report without building software first, which means the
"anyone can verify" claim is not yet true for the people it most matters to.

## Scope

**In:** `canton-solvency-verify`, an offline binary that verifies a report and
one or many proofs, prints the report digest, and returns CI-usable exit codes.

**Out, and why:**

- Coverage-report and anchor-chain verbs — they check documents that M1 and M2
  have not defined yet. Adding placeholder verbs now would advertise checks
  that do not exist.
- Disclosure-manifest validation — M3.
- The standalone offline HTML verifier — it needs a bundling step to avoid
  duplicating verification logic, which is its own increment.
- Recomputing a root from a full leaf dump — needs a dump format nothing emits
  yet.

Naming the gaps matters: a verification tool that silently skips a check is
worse than one that does not offer it.

## Decisions

**Separate crate, minimal dependencies.** `rust/solvency-cli` →
`canton-solvency-verify`, depending on the report crate plus `anyhow` and
`serde_json`. No argument-parsing framework: arguments are parsed by hand as
the existing examples do. An auditor's tool is one whose dependency tree they
may have to read, so the tree stays small deliberately.

**Library first, thin `main`.** All behaviour lives in `run(args) -> Result<Summary>`
returning a structured result. `main` only maps that to stdout and an exit
code. This keeps every behaviour testable without spawning processes.

**The trusted key is mandatory.** There is no "verify without a key" mode. A
report verified against the key embedded in itself proves only internal
consistency, and offering it would let a user believe they had checked
something they had not.

## Interface

```
canton-solvency-verify verify --report <path> --key <hex64>
                              (--proof <path> | --proof-dir <dir>)
                              [--json]
canton-solvency-verify digest --report <path>
canton-solvency-verify --help | --version
```

`--proof-dir` verifies every `*.json` in the directory, so a venue can publish
a day's proofs and an auditor can check them in one pass.

**Exit codes.** `0` everything verified · `1` at least one verification failed
· `2` usage, I/O, or parse error. Distinguishing 1 from 2 matters in CI: a
missing file is not evidence of insolvency.

**Output.** Human-readable by default, one line per proof plus a summary.
`--json` emits a machine-readable summary for pipelines.

## Components

| Unit | Responsibility |
|---|---|
| `args.rs` | Parse argv into a `Command`; all usage errors surface here |
| `run.rs` | Load documents, verify, build `Summary` |
| `report.rs` (output) | Render `Summary` as text or JSON |
| `main.rs` | `Summary` → stdout + exit code |

## Error handling

Every failure names the file it came from — an auditor checking 10,000 proofs
needs to know which one broke. `Summary` carries per-proof outcomes with the
typed `VerificationFailure` rendered as a stable string, so `--json` consumers
can match on it.

A directory containing no JSON files is an error (exit 2), not a vacuous
success. Silently reporting "0 checked, all passed" is the failure mode most
likely to be mistaken for a clean audit.

## Testing

Behaviour tests against real files written to temp directories, using the M0
golden fixtures as the known-good pair:

- A valid report and proof verify; exit 0.
- A tampered balance fails with `root_hash_mismatch`; exit 1.
- A proof from another report fails with `digest_mismatch`.
- The wrong trusted key fails with `unknown_signer`.
- `--proof-dir` verifies all proofs and reports the count.
- One bad proof among many fails the whole run and names that file.
- An empty directory is an error, not a pass.
- A missing or malformed file exits 2, distinct from a verification failure.
- `digest` prints the SPEC §10 golden digest.
- Usage errors (no key, no proof source, unknown flag) exit 2.

## Implementation sequence

Test-first throughout.

1. `args.rs` — parsing and usage errors.
2. `run.rs` — single-proof verification against the golden fixtures.
3. `--proof-dir` batch behaviour, including the empty-directory error.
4. Output rendering, text and JSON.
5. `main.rs` exit-code mapping.
6. README quick-start entry, CI step.
