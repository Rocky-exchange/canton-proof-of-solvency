# Report v2 — Disclosure Manifest — Design

**Date:** 2026-08-09
**Status:** approved, implementing
**Milestone:** M3

## Why this is a format version

[CONTRIBUTING.md](../../../CONTRIBUTING.md) requires that a change breaking the
golden vectors be discussed before the PR. This document is that discussion.

The manifest has to be **bound into the signed report**. A manifest carried
alongside the report could simply be dropped, and the property we want — that
reducing disclosure is itself on the record — would evaporate. Binding it in
changes the digest preimage, which is a new format version under a new domain
string.

**v1 does not change.** Its domain string, preimage, golden vectors and
fixtures are untouched, and v1 reports must keep verifying forever: historical
reports are the thing an auditor comes back to years later.

## What the manifest is for

Today a report is honest about what it *contains* and silent about what it
*chose not to contain*. An institution can quietly stop disclosing a field
between quarters and nothing records that it used to. The manifest makes the
disclosure decision itself part of the signed artefact, so:

- a reader can see what was withheld, not just what was shown; and
- two reports can be diffed, so a reduction in disclosure is visible rather
  than something you would have to have been watching for.

## The teeth: the manifest must agree with the document

A manifest that merely asserts things would be decoration. Verification
therefore cross-checks it against the report:

- a field declared `published` **must** carry data — declaring
  `root_sums: published` while publishing an empty map is rejected;
- a field declared `withheld` **must not** carry data — you cannot claim to
  have withheld something you in fact printed;
- `committed` means proven-but-not-shown: the field is absent from the report
  body and its content is attested through the commitment instead.

Every manifest key must come from a known vocabulary. An unrecognised key is
rejected rather than ignored, so a producer cannot bury a field the verifier
has no opinion about.

## Wire format

```
report_digest_v2 = SHA-256( "rocky-solvency-report-v2"
                          ‖ <all v1 fields, identical order and encoding>
                          ‖ lp(manifest.audience)
                          ‖ u64le(field_count)
                          ‖ ( lp(path) ‖ lp(state) )*   paths bytewise
)
```

`state` is `published`, `committed`, or `withheld`.

```json
"manifest": {
  "audience": "public",
  "fields": {
    "root_sums": "published",
    "mark_prices": "published",
    "disclosures.bad_debt": "published",
    "disclosures.excluded_house_totals": "withheld",
    "customer_balances": "committed"
  }
}
```

`audience` names who this packaging is for. Audience-scoped *packaging* — one
commitment, several packaged views — stays out of scope; this slice records
which audience a report was cut for, without yet generating the cuts.

**Serialization.** `manifest` is `Option<Manifest>` with
`skip_serializing_if = "Option::is_none"`, so a v1 report serializes to
exactly the bytes it does today and the v1 fixtures still match. A v1 report
carrying a manifest, or a v2 report without one, is rejected.

## Verification

`verify` dispatches on `format_version`:

| Version | Digest domain | Manifest |
|---|---|---|
| `canton-solvency-report-v1` | `rocky-solvency-report-v1` | must be absent |
| `canton-solvency-report-v2` | `rocky-solvency-report-v2` | must be present and consistent |

Everything after the digest — signature, fold, hash and sums comparison — is
shared. An unknown version is `UnsupportedVersion`, as now.

## Diffing

```rust
pub enum ManifestChange {
    Added { path, state },
    Removed { path, was },
    Changed { path, from, to },
}
pub fn diff(previous: &Manifest, current: &Manifest) -> Vec<ManifestChange>
pub fn is_reduction(change: &ManifestChange) -> bool
```

A reduction is any move away from `published`, or the removal of a field that
was published. Callers get the classification rather than a boolean, because
a regulator cares *which* field stopped being disclosed.

## Scope

**In:** the manifest type, report v2, digest v2, version dispatch, the
consistency check, diffing, golden vectors for v2 alongside the untouched v1
ones, the TypeScript mirror, and SPEC §8.5.

**Out:** the profile registry and the four non-solvency profiles — those need
a leaf carrying more than one amount map, which is a second, larger format
question and a separate decision. Audience-scoped packaging. A CLI diff verb,
which follows once the library settles.

## Testing

- Every v1 golden vector and fixture still passes, byte for byte.
- A v2 report round-trips, digests stably, and every field including each
  manifest entry moves the digest.
- v1 with a manifest, and v2 without one, are both rejected.
- `published` with no data is rejected; `withheld` with data is rejected.
- An unknown manifest key is rejected.
- The same report at v1 and v2 produce different digests (domain separation).
- Diff detects addition, removal, and each state transition; reductions are
  classified as such.
- Rust and TypeScript agree on the v2 digest and signature via new fixtures.

## Implementation sequence

1. `Manifest`, `Disclosure`, strict serde.
2. Digest v2 + domain separation tests.
3. `Option<Manifest>` on `Report`, v1 serialization unchanged.
4. Version dispatch in verify; v1 fixtures must stay green throughout.
5. Consistency check.
6. Diff.
7. v2 golden fixtures + SPEC §8.5.
8. TypeScript mirror.
9. READMEs.
