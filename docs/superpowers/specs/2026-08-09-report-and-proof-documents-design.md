# Report & Proof Documents — Design

**Date:** 2026-08-09
**Status:** approved, implementing
**Milestone:** M0 (foundation, prerequisite to M1–M6)

## Problem

The repository commits to balances but cannot publish. `canton-solvency-merkle`
produces in-memory `Node` and `Proof` values; nothing serializes them. SPEC.md
§7 lists what a producer *should* publish — snapshot timestamp, ledger
high-water mark, mark prices, totals, disclosures — and is explicitly marked
*informative*. No bytes are defined.

Every downstream milestone reads or writes a document that does not exist:

| Milestone | Depends on the report document for |
|---|---|
| M1 coverage | Somewhere to put reserves, liabilities, coverage ratio |
| M2 anchoring | A `report_root` and `root_sums_hash` to anchor, i.e. a canonical digest |
| M3 profiles | The manifest is a field inside the report |
| M4 console | Publishes and renders reports |
| M5 CLI | Verifies reports |

The published roadmap places schema work in M5, behind four milestones that
consume it. This increment corrects that ordering. It makes SPEC §7 normative.

## Scope

**In:** a report document, a proof document, a canonical digest for each, an
Ed25519 detached signature over the report digest, JSON serialization in Rust
and TypeScript, JSON Schemas, golden vectors asserted on both sides, and an
extended example that writes real files.

**Out:** coverage/reserves (M1), anchoring (M2), disclosure manifests and
profiles beyond `solvency.liabilities` (M3), the console (M4), the CLI (M5).
The envelope carries a `profile` field so M3 extends it without a version bump;
it deliberately carries no manifest, because the manifest's shape depends on
profiles that do not exist yet and the versioning rule makes a wrong guess
expensive.

## Decisions

**Separate crate.** `rust/solvency-report` → `canton-solvency-report`, depending
on `canton-solvency-merkle`. The core crate keeps its four dependencies
(`anyhow`, `hex`, `hmac`, `sha2`) and stays usable by anyone who wants only the
tree. Serialization and signing dependencies land in the new crate.

**Length-prefixed concatenation, not canonical JSON.** The digest is computed
over a domain-separated, length-prefixed byte string, not over JSON bytes. This
matches the existing `rocky-solvency-leaf-v1` / `-node-v1` construction, needs
no RFC 8785 implementation in two languages, and lets the JSON be reformatted
without breaking signatures. The existing `|`/`:` join used for balances is not
reused here: asset names are attacker-influenced in the general case, and
delimiter joins are ambiguous under adversarial input.

**Strict documents.** Both implementations reject unknown fields. With
length-prefixed concatenation only named fields enter the digest, so an
unknown field would otherwise ride along unsigned. Rejecting them closes that.

**The embedded public key is a convenience, not an identity.** A report carries
the public key that signed it, but verification takes the trusted key as a
parameter. A self-certifying signature proves only internal consistency. The
spec states this in normative language and the API makes the trusted key a
required argument, so the mistake is not available.

## Wire format

### Digest primitives

```
lp(s)      = u64le(byte_length(utf8(s))) ‖ utf8(s)
lpmap(m)   = u64le(entry_count) ‖ for each key in bytewise order: lp(key) ‖ lp(amount_18dp(value))
```

Length prefixes make the preimage unambiguous: no delimiter can be forged by
an asset name or a party identifier.

### Report digest

```
report_digest = SHA-256(
      "rocky-solvency-report-v1"
    ‖ lp(format_version) ‖ lp(profile) ‖ lp(publisher)
    ‖ lp(snapshot_time)  ‖ lp(ledger_offset) ‖ lp(root_hash)
    ‖ u64le(leaf_count)
    ‖ lpmap(root_sums) ‖ lpmap(mark_prices)
    ‖ lpmap(bad_debt)  ‖ u64le(excluded_house_accounts) ‖ lpmap(excluded_house_totals)
)
```

### Report document

```json
{
  "report": {
    "format_version": "canton-solvency-report-v1",
    "profile": "solvency.liabilities",
    "publisher": "rocky::1220abcd...",
    "snapshot_time": "2026-08-09T00:00:00Z",
    "ledger_offset": "000000000000012345",
    "root_hash": "<64 hex>",
    "leaf_count": 3,
    "root_sums": { "CBTC": "0.250000000000000000", "USDA": "101.500000000000000001" },
    "mark_prices": { "CBTC": "64000.000000000000000000" },
    "disclosures": {
      "bad_debt": { "USDA": "12.000000000000000000" },
      "excluded_house_accounts": 2,
      "excluded_house_totals": { "USDA": "5000.000000000000000000" }
    }
  },
  "signature": {
    "algorithm": "ed25519",
    "public_key": "<64 hex>",
    "value": "<128 hex>"
  }
}
```

`snapshot_time` is RFC 3339 UTC with a `Z` suffix and second precision.
`ledger_offset` is an opaque string — Canton offsets are not integers on all
versions, and treating them as opaque avoids a format break later.
All amounts are canonical 18-decimal strings (SPEC §1).

### Proof document

```json
{
  "format_version": "canton-solvency-proof-v1",
  "report_digest": "<64 hex>",
  "leaf": {
    "salt": "<64 hex>",
    "user_id": "22222222-2222-7222-8222-222222222222",
    "balances": { "CBTC": "0.25", "USDA": "1.000000000000000001" }
  },
  "steps": [
    { "sibling_hash": "<64 hex>", "sibling_sums": { "USDA": "100.5" }, "sibling_on_left": true }
  ]
}
```

`report_digest` binds a proof to one report. Without it, yesterday's proof
replays against today's report whenever a user's balance is unchanged.

## Verification algorithm

Identical in Rust and TypeScript:

1. Recompute `report_digest` from the report fields; reject if it differs from
   the value in the proof document.
2. Verify the Ed25519 signature over `report_digest` against the **caller-supplied**
   trusted public key; reject on mismatch with the embedded key.
3. Recompute the leaf hash from the disclosed preimage (SPEC §3).
4. Fold the sibling path (SPEC §4).
5. Compare the folded hash against `report.root_hash` **and** the folded sums
   against `report.root_sums`.

Any step failing fails the whole verification. Step 5 comparing sums as well as
hashes is what upgrades inclusion into aggregation-consistency, per SPEC §5.

## Components

| Unit | Responsibility | Depends on |
|---|---|---|
| `digest.rs` | `lp`/`lpmap` primitives, report digest | core crate (amount formatting) |
| `document.rs` | `Report`, `SignedReport`, `ProofDocument` types, serde, strict parsing | serde |
| `sign.rs` | Ed25519 sign/verify over a digest | ed25519-dalek |
| `verify.rs` | The five-step algorithm above | all of the above + core |
| `ts/verifier/src/report.ts` | TypeScript mirror: parse, digest, WebCrypto Ed25519, verify | existing `verify.ts` |
| `schemas/*.schema.json` | JSON Schema for both documents | — |

Each is independently testable. `digest.rs` needs no keys, `sign.rs` needs no
documents, `verify.rs` composes them.

## Error handling

Verification returns a typed outcome, not a boolean. A user told only "failed"
cannot tell a tampered balance from a clock skew, and the console (M4) needs to
render *which* check failed:

```rust
enum VerificationFailure {
    DigestMismatch,        // proof references a different report
    UnknownSigner,         // embedded key != trusted key
    BadSignature,
    LeafHashMismatch,
    RootHashMismatch,
    RootSumsMismatch { asset: String },
    Malformed(String),     // parse, hex, or amount errors
}
```

Parsing is strict and total: no panics on adversarial input. All hex is
length-checked, all amounts go through `parse_amount_18dp`, unknown fields are
rejected, and duplicate JSON keys are rejected by the parsers on both sides.

## Testing

**Golden vectors (the binding constraint).** SPEC gains report and proof
vectors built on the existing §6 fixture — the same three users, master salt
`golden-v1` — extended with a fixed publisher, snapshot time, offset, and a
fixed Ed25519 keypair seeded deterministically. Rust and TypeScript both assert
the same digest, the same signature bytes, and the same serialized JSON.

**Negative tests, mirrored on both sides.** One per `VerificationFailure`
variant: mutate one field of a valid report and assert the specific failure.
Notably — flipping any single report field must change the digest, which is the
property that makes the signature meaningful.

**Property test (Rust).** For arbitrary balance sets and leaf counts, every
leaf's proof document verifies against its report, and no proof verifies
against a report built from different leaves.

**Round-trip.** Serialize → parse → digest is stable, and Rust-written JSON is
accepted by the TypeScript parser and vice versa.

## SPEC.md changes

New normative sections. The existing §1–§7 are unchanged, so v1 golden vectors
still hold.

- **§8 Report envelope** — fields, digest construction, signature.
- **§9 Proof document** — fields, the report binding, verification algorithm.
- **§10 Golden vectors (report and proof)**.

This shifts the section numbers reserved in the README roadmap: coverage
becomes §11 (M1), anchoring §12 (M2), profiles §13 (M3). Both READMEs are
updated to match.

## Implementation sequence

Test-first throughout; each step lands green.

1. `digest.rs` — `lp`/`lpmap`, report digest, unit tests.
2. `document.rs` — types + strict serde, round-trip tests.
3. `sign.rs` — Ed25519 over a digest, sign/verify tests.
4. `verify.rs` — the five steps, one test per failure variant.
5. Golden vectors in Rust; write them into SPEC §10.
6. TypeScript mirror asserting the identical vectors.
7. JSON Schemas + CI validation.
8. Extend `csv_report` to emit `report.json` and `proof-<user>.json`.
9. README updates: M0 row, SPEC section renumbering, both languages.

## Risks

**WebCrypto Ed25519 availability.** Supported in current Chrome, Safari,
Firefox and Node 18+, but recent. The TypeScript verifier feature-detects and
throws a clear error naming the requirement rather than failing obscurely; the
spec names the algorithm identifier so an alternative implementation is
substitutable.

**Signature key custody is out of scope and unsolved.** This increment defines
how a signature is verified, not how the publisher's key is distributed,
rotated, or revoked. A verifier that fetches the trusted key from the same
server that served the report gains nothing. Key distribution is called out as
an open problem in SPEC §8 and belongs with M2 anchoring, where the ledger can
carry the binding.
