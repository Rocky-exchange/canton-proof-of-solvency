# Contributing to Canton Proof-of-Solvency

Thanks for your interest in contributing! This document covers the
development setup, quality bar, and the one rule that is special to this
project.

## The Golden-Vector Rule (read this first)

The Rust producer and the TypeScript verifier implement one byte-level wire
format, pinned by the golden vectors in [SPEC.md](SPEC.md) §6 and asserted by
tests on **both** sides.

- A change that keeps all golden-vector tests passing is a refactor. Welcome.
- A change that breaks any golden vector is a **wire-format version bump**:
  it must introduce new domain strings (`…-v2`), update SPEC.md with a new
  vector section, keep v1 verification working for historical reports, and be
  discussed in an issue *before* the PR.

Silent format drift is the one bug this project exists to make impossible —
including in itself.

## Development Setup

Prerequisites: Rust ≥ 1.75, Node.js ≥ 18.

```bash
# Rust core
cd rust/solvency-merkle
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check

# Rust report documents
cd rust/solvency-report
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check

# TypeScript verifier
cd ts/verifier
npm install && npm test
```

All of these must pass locally before you open a PR — CI runs exactly these.

The golden fixtures in `fixtures/` are asserted byte for byte by both
implementations. If a deliberate format change makes them stale, regenerate
with `cargo run --manifest-path rust/solvency-report/Cargo.toml --example
print_golden` and update [SPEC.md](SPEC.md) §10 in the same commit — never
edit a fixture by hand to make a test pass.

## Pull Request Guidelines

- **Tests first.** Every behavior change lands with a test that fails
  without it. Bug fixes include a regression test reproducing the bug.
- **Both sides.** If your change touches serialization, hashing, or proof
  semantics, update Rust *and* TypeScript in the same PR, with matching
  tests.
- **Small and focused.** One logical change per PR; separate refactors from
  behavior changes.
- **Commit style.** `type(scope): summary` (e.g. `fix(merkle): reject
  duplicate assets in sums`), imperative mood, body explains *why*.
- **No new runtime dependencies** in the core crate or the verifier without
  prior discussion in an issue — auditability of this code is a feature.

## Reporting Issues

- Bugs and feature requests: open a GitHub issue with reproduction steps or
  a concrete use case.
- Security vulnerabilities: **do not open an issue** — follow
  [SECURITY.md](SECURITY.md).

## Code of Conduct

This project adheres to the
[Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you are
expected to uphold it.

## License

By contributing, you agree that your contributions are licensed under the
[Apache-2.0](LICENSE) license that covers the project.
