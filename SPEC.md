# Canton Proof-of-Solvency — Wire Format Specification v1

This document pins the exact byte-level format of the solvency commitment so
that independent implementations interoperate. Two reference implementations
ship in this repository — Rust (prover side) and TypeScript (browser verifier)
— and both assert the golden vectors in §6. **Any change that breaks those
vectors is a new format version, not a refactor.**

## 1. Amounts

All amounts are non-negative fixed-point decimals with **18 fractional
digits**, transported as strings.

- Parse: `int_part [ "." frac_part ]`, both ASCII digits, `frac_part` length
  ≤ 18, no sign, no bare `.`, integer part required. Value =
  `int_part · 10^18 + rpad(frac_part, 18, "0")` as an unsigned integer.
- Canonical render: `"{int}.{frac:018}"` — always exactly 18 fraction digits.
- Negative balances never enter the tree. Producers clamp negative equity to
  zero upstream and disclose the shortfall separately (bad debt).

## 2. Canonical balance serialization

A balance set `{asset → amount}` serializes as:

```
asset₁:amount₁|asset₂:amount₂|…
```

- Assets sorted by **bytewise** (ASCII) order of the asset string.
- Amounts in canonical 18-digit render (§1).
- Duplicate assets are an error. The empty set serializes to the empty string.

## 3. Leaf

```
leaf_hash = SHA-256( "rocky-solvency-leaf-v1"
                   ‖ salt
                   ‖ SHA-256(utf8(user_id))
                   ‖ utf8(canonical_balances) )
```

- `salt` is 32 bytes: `HMAC-SHA256(master_salt, utf8(user_id))`. The master
  salt is a per-snapshot secret held by the prover; each user receives only
  their own derived salt inside their proof.
- `user_id` is the UTF-8 identity string (e.g. a UUID).
- A leaf **node** carries `(leaf_hash, sums)` where `sums` is the balance map.

## 4. Merkle sum tree

Internal node over children `L`, `R`:

```
sums  = per-asset sum of L.sums and R.sums   (checked addition; overflow = error)
hash  = SHA-256( "rocky-solvency-node-v1"
               ‖ L.hash ‖ R.hash
               ‖ utf8(canonical(sums)) )
```

- Leaves are paired left-to-right in a stable order chosen by the producer
  (reference deployment: ascending `user_id`).
- An **odd node is promoted** to the next level unchanged — never duplicated,
  so no value is counted twice.
- The **root's `sums` are the published liability totals**: a verifier that
  recombines any inclusion path also re-derives (part of) the aggregation,
  and equal roots imply equal totals.

## 5. Inclusion proof

A proof for leaf `i` is the ordered list of steps from leaf level upward:

```
step = { sibling: (hash, sums), sibling_on_left: bool }
```

Levels where the node was promoted without a sibling contribute **no step**.

Verification: recompute the leaf hash from the disclosed preimage
(salt, user_id, balances), fold the steps with the §4 node rule, then compare
**both** the final hash and the final per-asset sums against the published
root. Comparing sums is what upgrades inclusion into aggregation-consistency.

## 6. Golden vectors

Master salt: ASCII `golden-v1`.

| user_id | balances |
|---|---|
| `11111111-1111-7111-8111-111111111111` | `USDA = 100.5` |
| `22222222-2222-7222-8222-222222222222` | `CBTC = 0.25`, `USDA = 1.000000000000000001` |
| `33333333-3333-7333-8333-333333333333` | (empty) |

Expected values (hex):

```
salt(u1)   = 3de523c46646d91361907f6158f560ed6c55b8684c595139b05df6b12e3ddbb1
salt(u2)   = 332f77b30295afb7a346ba580de798bc08f3bada500905be6bd7a552c7eec458
leaf(u1)   = 05666cf01538aa610cc1285d1acf84953a961bd8346154cec9fb8785bb626363
leaf(u2)   = b5fa416d215750e1a3ccd2b16dd0f906f35c3bfda8467cab3fe6977333e4e691
leaf(u3)   = 171f5e7577171aeabb58b3013b0e0e2d0b9f45b387fe8b1ed2027be1a0d7108c
root       = 02885b0fc65c3d8992899c8acba1917cb838b18b7054b6675e3d89f2bf8f0970
root sums  = CBTC: 0.250000000000000000 | USDA: 101.500000000000000001
proof(u2)  = 2 steps; step₀ sibling = leaf(u1), sibling_on_left = true
```

## 7. Producer obligations (informative)

The tree alone does not make a solvency claim. A conforming producer also
publishes, per report: the snapshot timestamp and ledger high-water mark, the
mark prices used for any unrealized-PnL folding, per-asset liability totals
(= root sums), custody asset totals, insurance/bad-debt disclosures, and the
count of excluded house accounts. See the reference deployment's methodology
page for a complete example.

Sections 8–10 make the transport of those obligations normative. Custody asset
totals are not yet covered — they arrive with the coverage report (§11).

## 8. Report envelope

A report is the published statement about one snapshot. Amounts are the §1
canonical form; hashes are lowercase hex.

### 8.1 Digest primitives

Every variable-length field enters a preimage length-prefixed:

```
lp(s)    = u64le(byte_length(utf8(s))) ‖ utf8(s)
lpmap(m) = u64le(entry_count) ‖ (lp(asset) ‖ lp(canonical_amount))*   assets bytewise
```

The delimiter join of §2 is **not** reused here. Asset names and party
identifiers are attacker-influenced in the general case, and a join is
ambiguous under adversarial input: an asset literally named `A|B:0.000…001`
would otherwise be indistinguishable from two entries. Length prefixes remove
that class of forgery.

### 8.2 Digest

```
report_digest = SHA-256( "rocky-solvency-report-v1"
                       ‖ lp(format_version) ‖ lp(profile) ‖ lp(publisher)
                       ‖ lp(snapshot_time)  ‖ lp(ledger_offset) ‖ lp(root_hash)
                       ‖ u64le(leaf_count)
                       ‖ lpmap(root_sums) ‖ lpmap(mark_prices)
                       ‖ lpmap(bad_debt)
                       ‖ u64le(excluded_house_accounts)
                       ‖ lpmap(excluded_house_totals) )
```

The digest is computed over these fields, **not** over the JSON encoding, so a
document may be reformatted, re-indented, or re-serialized without
invalidating its signature. Because only named fields enter the preimage,
implementations **MUST** reject unknown fields — otherwise an unsigned field
could ride along inside a signed document.

### 8.3 Fields

| Field | Type | Notes |
|---|---|---|
| `format_version` | string | `canton-solvency-report-v1` |
| `profile` | string | Disclosure profile; `solvency.liabilities` in v1 |
| `publisher` | string | Canton party identifier of the publishing institution |
| `snapshot_time` | string | RFC 3339 UTC, `Z` suffix, second precision |
| `ledger_offset` | string | **Opaque.** Participant offset pinning the snapshot; not assumed numeric |
| `root_hash` | hex(32) | §4 root |
| `leaf_count` | uint64 | Number of committed leaves |
| `root_sums` | amount map | The published liability totals (§4) |
| `mark_prices` | amount map | Prices used for any unrealized-PnL folding |
| `disclosures.bad_debt` | amount map | Clamped negative equity (§1), surfaced not netted |
| `disclosures.excluded_house_accounts` | uint64 | |
| `disclosures.excluded_house_totals` | amount map | |

### 8.4 Signature

An Ed25519 detached signature over the 32 raw digest bytes:

```json
"signature": { "algorithm": "ed25519", "public_key": "<hex(32)>", "value": "<hex(64)>" }
```

Ed25519 is deterministic, so a given key and report always yield the same
signature — which is what lets §10 pin exact bytes.

> **The embedded `public_key` is display metadata, not identity.** A verifier
> **MUST** take the trusted key as an input obtained out of band and compare
> it; a signature that certifies itself proves only internal consistency. How
> a publisher's key is distributed, rotated, and revoked is **not solved by
> this version.** Fetching the key from the same server that served the report
> gains nothing. The intended answer is to bind the key on-ledger with the
> anchor (§12); until then, deployments must document their own key
> distribution.

JSON Schema: [`schemas/report-v1.schema.json`](schemas/report-v1.schema.json).

## 9. Proof document

Carries one user's leaf preimage and sibling path (§5), bound to a report.

| Field | Type | Notes |
|---|---|---|
| `format_version` | string | `canton-solvency-proof-v1` |
| `report_digest` | hex(32) | §8.2 digest of the report this proof belongs to |
| `leaf.salt` | hex(32) | §3 derived salt |
| `leaf.user_id` | string | |
| `leaf.balances` | amount map | |
| `steps[].sibling_hash` | hex(32) | |
| `steps[].sibling_sums` | amount map | |
| `steps[].sibling_on_left` | bool | |

`report_digest` is what stops a stale proof being replayed: without it, a proof
issued for yesterday's report verifies against today's whenever the user's
balance is unchanged, and a venue could stop committing a user while their old
proof still appeared to pass.

### 9.1 Verification

A conforming verifier performs all of the following and fails on the first
that does not hold:

1. `report.format_version`, `proof.format_version`, and `signature.algorithm`
   are recognised.
2. The recomputed §8.2 digest equals `proof.report_digest`.
3. `signature.public_key` equals the caller-supplied trusted key, and the
   signature verifies over the digest.
4. The leaf hash is recomputed from the disclosed preimage (§3).
5. The path is folded (§4), and **both** the resulting hash equals
   `report.root_hash` **and** the resulting per-asset sums equal
   `report.root_sums`.

Step 5 comparing sums is not redundant. A publisher can commit a truthful tree
and still print understated totals in the report; only an independent
comparison of the folded sums against the published ones detects it.

Absent and zero are the same claim: an asset missing from one side and zero on
the other is not a mismatch.

JSON Schema: [`schemas/proof-v1.schema.json`](schemas/proof-v1.schema.json).

## 10. Golden vectors (report and proof)

Extends the §6 fixture — same three users, master salt `golden-v1` — with
report metadata and a fixed signing seed of **32 bytes of `0x01`**.

```
profile         = solvency.liabilities
publisher       = golden::publisher
snapshot_time   = 2026-01-01T00:00:00Z
ledger_offset   = 000000000000000042
mark_prices     = CBTC: 50000
bad_debt        = USDA: 2.5
excluded_house_accounts = 1
excluded_house_totals   = USDA: 1000
```

Expected values (hex):

```
public_key     = 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
report_digest  = 0800c1047c9724ea429b238b01366f2032d674425d3ed745ed3402b2f534df61
signature      = b1bf2a1fc11476610e385e5017cf7a568b13a0c84088b66ecf58ffa04b78499a
                 da7ff8ebf3c2ee7ec0d10d7130cdc868a8074ff51725252631c67f61ce575a07
root_hash      = 02885b0fc65c3d8992899c8acba1917cb838b18b7054b6675e3d89f2bf8f0970  (unchanged from §6)
```

`root_hash` is identical to the §6 vector: the envelope composes on top of
wire format v1 rather than altering it.

The complete documents are checked in as
[`fixtures/report.golden.json`](fixtures/report.golden.json) and
[`fixtures/proof.golden.json`](fixtures/proof.golden.json) — the proof is for
the second user, exercising a two-step path whose first sibling is on the
left. Both reference implementations assert these files byte for byte, and
regenerate them with `cargo run --example print_golden`.

## 11–13. Reserved

`§11` coverage reports, `§12` on-ledger anchoring, and `§13` disclosure
profiles are reserved for the milestones of the same name; see the README.
