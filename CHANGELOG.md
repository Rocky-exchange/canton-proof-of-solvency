# Changelog

Formats are versioned by the domain strings baked into their hashes. A change
that breaks a golden vector ships under new domain strings and is listed here
as a format version, never as a fix.

## Unreleased

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
