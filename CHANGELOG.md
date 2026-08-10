# Changelog

Formats are versioned by the domain strings baked into their hashes. A change
that breaks a golden vector ships under new domain strings and is listed here
as a format version, never as a fix.

## 0.1.1 — 2026-08-10

Testing and documentation only. No wire bytes, no format versions, no
behaviour change — every 0.1.0 vector still verifies.

### Added

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

### Fixed

- Two broken intra-doc links, live on docs.rs since 0.1.0: `Report` and
  `ProofDocument` did not resolve from the crate root, and `reserve-attest`
  carried a redundant explicit link target. rustdoc now runs in CI with
  `-D warnings`.

Released for the documentation alone. 0.1.0's docs.rs pages show broken links
and no examples, and the main open ask on this project is that other people
implement against it — so the reference an implementer reads first is worth a
patch release on its own.

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
