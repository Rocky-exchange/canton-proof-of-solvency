# Changelog

Formats are versioned by the domain strings baked into their hashes. A change
that breaks a golden vector ships under new domain strings and is listed here
as a format version, never as a fix.

## 0.1.1 — unreleased

Testing and documentation, plus four defects those tests found. No wire
bytes, no format versions: every 0.1.0 vector still verifies.

### Fixed

- **Two customers could share one proof filename, and one proof overwrote the
  other.** `canton-solvency-publish` replaced every non-alphanumeric character
  with `_`, so `alice-1`, `alice_1` and `alice 1` are three customers and were
  one file. The pack index did notice the duplicate, but only after the files
  were written, reporting it as a problem with the pack rather than with the
  customer identifiers, and leaving a half-written output directory. Filenames
  now carry a digest of the full identifier whenever sanitising loses
  something; identifiers needing no sanitising keep their readable name, and
  the two forms cannot collide because only the suffixed form contains a `-`.
- **The browser verifier threw instead of reporting on a malformed document.**
  `verifyFromText` built its display facts before checking whether
  verification had succeeded, so a report whose `root_sums` was not an amount
  map raised an exception rather than showing "Could not check this". In a page
  with no error console, that is indistinguishable from the page being broken.
  The verification core was already correct; only the presentation was not.
- **TypeScript accepted amounts the producer cannot represent.** SPEC §1 bounds
  the scaled value at 2^128 − 1, which Rust enforces with checked arithmetic.
  JavaScript's `BigInt` has no such limit, so a report carrying a larger amount
  verified in the browser and was rejected as malformed by the CLI — and the
  permissive side is the one customers run. Bounded in `parseAmount18dp` and
  `formatAmount18dp`, stated in §1, and pinned at the boundary by tests in both
  implementations.

- Two broken intra-doc links, live on docs.rs since 0.1.0: `Report` and
  `ProofDocument` did not resolve from the crate root, and `reserve-attest`
  carried a redundant explicit link target. rustdoc now runs in CI with
  `-D warnings`.

### Changed

- **`canton-solvency-verify` with no arguments now exits 2 instead of 0.** Exit
  0 from this tool means "everything verified", and a run with no arguments
  verified nothing. A pipeline written as
  `canton-solvency-verify $ARGS && echo solvent` printed `solvent` on the day
  `$ARGS` expanded to nothing. Usage is still printed; an explicitly requested
  `--help` still exits 0, because being asked for help is not an error.

### Added

- Robustness suites for both implementations: truncation at every byte offset,
  single-byte alteration at every position, wrong JSON types and malformed hex
  in every field, malformed trusted keys, deeply nested JSON, and adversarial
  amount strings. Nothing asserts *which* error — only that one is returned.
  Every document these tools read comes from the party being checked, so a
  panic is a crash on demand rather than a wrong answer.
  `canton-solvency-publish` and `canton-reserve-attest` are covered too: the
  first against malformed balance exports and key files, the second against
  every shape a participant response can be wrong in, including a custody
  total that overflows `u128` — checked arithmetic there matters in release
  builds, where a wrap would understate reserves against unchanged
  liabilities.
  The CLI suite runs the real binary across every verb, asserting the exit-code
  contract a pipeline actually consumes: malformed input is a 2, a failed
  verification is a 1, and neither is ever the 101 that a panic produces.
- Property tests over the commitment core: nine invariants over generated
  trees at every size from 1 to 64. Odd-node promotion is the motive —
  duplicating the odd node instead of promoting it is the obvious
  implementation and silently overstates liabilities. The mutation fails
  conservation at three leaves.
- 311 cross-implementation differential vectors covering **every hash preimage
  the specification defines**: leaves, canonical serialization, `lpmap`, report
  digests, tree roots, pack digests and anchor digests. Rust emits, TypeScript
  recomputes, CI compares. The names are chosen to break assumptions — astral
  codepoints, the private-use block, and the `:`/`|` that §2 uses as
  delimiters — because every §6 golden vector is ASCII, which is exactly why
  the UTF-16 sort bug survived as long as it did.
- Eleven doctests across the four published crates, which had none.

## 0.1.0 — 2026-08-10

First release. Published to crates.io as `canton-solvency-merkle`,
`canton-solvency-report`, `canton-solvency-verify` and
`canton-reserve-attest`.

### Formats

- `rocky-solvency-report-v2` — reports carrying a disclosure manifest (SPEC §8.5).
- `rocky-solvency-leaf-v2` — leaves carrying named amount maps (SPEC §3.1).
- `rocky-solvency-entity-v1` — group entity leaves (SPEC §13.1).
- `rocky-solvency-anchor-v1` — report history anchors (SPEC §12).
- `canton-solvency-coverage-v1` — coverage statements (SPEC §11.1).
- `rocky-solvency-pack-v1` — evidence pack indexes (SPEC §15).

v1 leaves, nodes and reports are unchanged. Every §6 and §10 vector still
verifies, and both implementations still assert them.

### Added

- Signed report and proof documents, with Ed25519 detached signatures.
- Six disclosure profiles: `solvency.liabilities`, `solvency.group`,
  `collateral.repo`, `fund.nav`, `settlement.dvp`, `eligibility.holder`,
  plus `coverage.custody` for the asset side.
- Hierarchical group commitments and full-chain verification.
- Coverage: custody reports paired to liabilities by digest.
- Tamper-evident report history via hash-linked anchors.
- Specification v1.1, frozen against the conformance corpus, and a third
  verifier written from its text alone (`spec-audit/`).
- SPEC §14.5 compatibility statements, one per implementation in
  `statements/`, compared by a cross-implementation test. Running the corpus
  in three places proved nothing while nothing compared the results.
- `interop/`, where a third-party producer's reports are verified by this
  toolkit on every commit — the other half of bidirectional interop, which
  until now was an invitation rather than a procedure.

### Fixed

- **The TypeScript verifier sorted map keys by UTF-16 code units** where SPEC
  §2 requires bytewise UTF-8 order. The two disagree above U+FFFF, so a report
  naming an asset outside the BMP verified in Rust and failed in the browser.
  Every golden vector is ASCII, where the orders agree. Pinned by the
  `proof-astral-assets` conformance case, which fails under a UTF-16 sort.
- Conformance cases now declare `requires`. Without it a verifier supporting
  only report v1 *passed* `report-v2-manifest-lies` by rejecting a version it
  had never implemented, so a case written to test manifest consistency tested
  nothing.

### Added

- Evidence packs: a signed index over a delivery, so omitting a proof is
  detectable. Without one, a folder with a customer's proof deleted verifies
  exactly as cleanly as the complete folder.
- `canton-solvency-verify` CLI: `verify`, `verify-group`, `verify-chain`,
  `coverage`, `anchors`, `recompute`, `manifest-diff`, `digest`.
- `canton-reserve-attest`: Ledger API request construction, response parsing
  and custody report building, with the socket behind a caller-supplied
  transport.
- Self-contained pages: an offline verifier, a console viewer, and a
  disclosure designer.
- JSON Schema for every checked-in document, and a conformance corpus both
  implementations run.

### Known limitations

- Publisher key distribution is unsolved; see `docs/SECURITY-ANALYSIS.md`.
- The Daml anchoring package has never been compiled or run.
- `canton-reserve-attest` has never been run against a participant node.
