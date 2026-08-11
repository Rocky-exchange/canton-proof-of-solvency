# Canton Proof-of-Solvency — Wire Format Specification v1.1

This document pins the exact byte-level format of the solvency commitment so
that independent implementations interoperate. Two reference implementations
ship in this repository — Rust (prover side) and TypeScript (browser verifier)
— and both assert the golden vectors in §6. **Any change that breaks those
vectors is a new format version, not a refactor.**

## Status

**v1.1 — frozen against the conformance corpus** ([`conformance/`](conformance),
§14.3). Every normative section below is implemented by both reference
implementations and exercised by at least one corpus case; a change to any of
them requires a new domain string and a new corpus case, not an edit here.

Normative: §1–§6 (commitment core), §8 (report envelope), §9 (proof
documents), §11 (coverage), §12 (anchoring), §13 (hierarchy), §14 (profiles
and conformance), §15 (evidence packs). §7 is informative. §10 records golden
vectors, which are data rather than rules.

**What v1.1 changed from v1.** No wire bytes. Every §6 and §10 vector still
verifies unchanged. v1.1 adds §11–§15 as normative text and sharpens four
under-specified points that two implementations had resolved identically by
coincidence rather than by rule: bytewise ordering over UTF-8 and its
disagreement with a UTF-16 sort (§2), serialization of explicit zeros (§2),
`lp(root_hash)` covering the hex string (§8.2), and the origin of the fold's
running sums (§5). Those were found by implementing this document from its
text alone — see [`spec-audit/`](spec-audit), which also found the
TypeScript verifier ordering keys wrongly. Any implementation that agreed with
the reference before still agrees; one that had guessed differently on §2
would have diverged only for non-ASCII asset names, which the
`proof-astral-assets` case now catches.

## 1. Amounts

All amounts are non-negative fixed-point decimals with **18 fractional
digits**, transported as strings.

- Parse: `int_part [ "." frac_part ]`, both ASCII digits, `frac_part` length
  ≤ 18, no sign, no bare `.`, integer part required. Value =
  `int_part · 10^18 + rpad(frac_part, 18, "0")` as an unsigned integer.
- Canonical render: `"{int}.{frac:018}"` — always exactly 18 fraction digits.
- **Range.** The scaled value MUST fit in an unsigned 128-bit integer: at most
  `340282366920938463463374607431768211455` scaled units, about
  `3.4 × 10^20` whole units. A larger amount is malformed, not merely large.
  This is worth stating because it is not self-evident from the grammar: an
  implementation using an arbitrary-precision integer type accepts amounts a
  producer using `u128` cannot represent, and then the permissive side —
  typically the browser a customer runs — verifies a report the producer's own
  toolchain rejects.
- Negative balances never enter the tree. Producers clamp negative equity to
  zero upstream and disclose the shortfall separately (bad debt).

## 2. Canonical balance serialization

A balance set `{asset → amount}` serializes as:

```
asset₁:amount₁|asset₂:amount₂|…
```

- Assets sorted by **bytewise order of their UTF-8 encoding**.
- Amounts in canonical 18-digit render (§1).
- Duplicate assets are an error. The empty set serializes to the empty string.
- An asset present with value zero **is serialized**, as `asset:0.000…0`. It is
  not dropped. Note this is a rule about *serialization*; §9.1's "absent and
  zero are the same claim" is a rule about *comparison*, and the two are
  independent.

> **Bytewise is not the platform default everywhere.** JavaScript's
> `Array.prototype.sort()` compares UTF-16 code units, which disagrees with
> UTF-8 byte order for any codepoint above U+FFFF: a surrogate (`0xD800`)
> sorts before U+E000..U+FFFF, while the same character's UTF-8 encoding
> (`0xF0…`) sorts after. An implementation using the default sort computes a
> different canonical string — and therefore a different leaf hash — for an
> asset named outside the BMP, and rejects a report its producer signed
> honestly. Every name in the §6 vectors is ASCII, where the orders agree, so
> the vectors do not catch it; the `proof-astral-assets` conformance case
> does.

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

### 3.1 Leaf format v2 — named amount maps

A v1 leaf carries exactly one amount map. That is enough for a customer's
balances; it cannot express a statement that *compares* two quantities, such
as a repo leg's collateral against its exposure.

```
leaf_hash_v2 = SHA-256( "rocky-solvency-leaf-v2"
                      ‖ salt                       (32 bytes)
                      ‖ SHA-256(utf8(subject_id))
                      ‖ u64le(map_count)
                      ‖ ( lp(map_name) ‖ lpmap(amounts) )*   map names bytewise )
```

`lp`/`lpmap` are the §8.1 length-prefixed primitives. §2's delimiter join is
deliberately not reused: length-prefixing exists precisely because joins are
ambiguous under adversarial input, and using a join again in a new format
would be indefensible.

`subject_id` rather than `user_id`: a v2 leaf is not necessarily a customer.

**What the tree sums.** A leaf node's sums are every map flattened under
**qualified keys**, `<map>/<asset>`. A repo tree's root therefore publishes
`collateral/USDA` *and* `exposure/USDA`, so a statement comparing two maps is
checkable **at the published root** rather than only by someone holding every
leaf. The §4 node rule is unchanged: sums remain a flat map.

**Name restriction.** Because §4 still canonicalises sums with a `:`/`|`
join, an unconstrained qualified key could forge a boundary. v2 leaves
therefore **MUST** reject map names and asset names that are empty or contain
anything outside `[A-Za-z0-9._-]`.

> **Known limitation.** v1 has the same latent join ambiguity and is *not*
> fixed here. Fixing it would change every node hash and therefore every §6
> vector — a destructive change, where this one is additive. v1 leaves, v1
> vectors and existing fixtures are untouched and keep verifying.

## 4. Merkle sum tree

Internal node over children `L`, `R`:

```
sums  = per-asset sum of L.sums and R.sums   (checked addition; overflow = error)
hash  = SHA-256( "rocky-solvency-node-v1"
               ‖ L.hash ‖ R.hash
               ‖ utf8(canonical(sums)) )
```

- Leaves are paired left-to-right in a stable order chosen by the producer.
  The order MUST be stable within a snapshot; it SHOULD NOT be predictable from
  the identifiers. See §7 — this is the difference between a customer learning
  a random other customer's balances and an attacker learning a chosen one's.
  The reference deployment orders by the derived salt (§3).
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
root. The fold's running sums start from the **preimage's own balances**, not
from any figure the report or proof publishes — a proof that seeded the fold
with an asserted total would be checking that total against itself. Comparing sums is what upgrades inclusion into aggregation-consistency.

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

**Order leaves unpredictably.** §5 discloses each sibling's sums, so at leaf
level whoever is paired with a customer learns that customer's exact balances.
If leaves are ordered by identifier, an attacker who can influence their own
identifier chooses their pair: register two accounts around a target, one to
fix the parity of the target's index and one to occupy the pair position, and
the second account's proof discloses the target's balances. Ordering by the
derived salt of §3 — a keyed function of a per-snapshot secret — is equally
stable for the producer and unpredictable to everyone else. It does not stop
the disclosure, only the aiming.

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

`lp(root_hash)` is taken over the **64-character lowercase hex string**, not
over the 32 raw bytes: §8 transports hashes as hex, and `lp` is defined on
strings. Both readings parse; they give different digests, and the §10 vector
distinguishes them.

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

> **Where the trusted key comes from.** A verifier takes it as an input
> obtained out of band. §12 anchors carry `publisher_key`, so a reader who can
> see a publisher's anchors obtains the key from the ledger rather than from
> the server that served the report; `verify_with_anchor` uses it and refuses
> an anchor describing a different report. That relies on the reader being
> able to see the anchor, which is a deployment property, not a format one.
>
> **The embedded `public_key` is display metadata, not identity.** A verifier
> **MUST** take the trusted key as an input obtained out of band and compare
> it; a signature that certifies itself proves only internal consistency. How
> a publisher's key is distributed, rotated, and revoked is **not solved by
> this version.** Fetching the key from the same server that served the report
> gains nothing. The intended answer is to bind the key on-ledger with the
> anchor (§12); until then, deployments must document their own key
> distribution.

JSON Schema: [`schemas/report-v1.schema.json`](schemas/report-v1.schema.json).

### 8.5 Disclosure manifest (format v2)

A v1 report is honest about what it contains and silent about what it chose
not to contain. An institution can quietly stop disclosing a field between
quarters and nothing records that it used to. Format **v2** adds a manifest
that makes the disclosure decision itself part of the signed artefact.

```json
"manifest": {
  "audience": "public",
  "fields": {
    "root_sums": "published",
    "mark_prices": "published",
    "customer_balances": "committed",
    "customer_identities": "withheld"
  }
}
```

| State | Meaning |
|---|---|
| `published` | Present in the report body and readable |
| `committed` | Proven through the commitment but not shown |
| `withheld` | Deliberately not disclosed to this audience |

`audience` names who this packaging was cut for. Generating audience-scoped
packagings is not part of this version; the field records the intent.

**Digest.** v2 uses its own domain string, so the same fields cannot digest
identically under both versions and a v2 signature cannot be replayed as a v1
one:

```
report_digest_v2 = SHA-256( "rocky-solvency-report-v2"
                          ‖ <every §8.2 field, identical order and encoding>
                          ‖ lp(audience)
                          ‖ u64le(field_count)
                          ‖ ( lp(path) ‖ lp(state) )*   paths bytewise )
```

**Version rules.** A v1 report **MUST NOT** carry a manifest — the v1 digest
does not cover it, so one could be added or removed without breaking the
signature. A v2 report **MUST** carry one.

**Consistency is checked, not asserted.** A manifest that merely made claims
would be decoration. For every field that lives in the report body, verifiers
**MUST** reject a report where:

- a field is declared `published` but the body carries no data for it; or
- a field is declared `committed` or `withheld` but the body publishes it.

Manifest keys **MUST** come from the defined vocabulary — `root_sums`,
`mark_prices`, `disclosures.bad_debt`,
`disclosures.excluded_house_accounts`, `disclosures.excluded_house_totals`,
`customer_balances`, `customer_identities` — and an unrecognised key is an
error rather than something to ignore, so a producer cannot bury a field the
verifier has no opinion about.

**Diffing.** Comparing two reports' manifests yields per-field additions,
removals, and state changes. A *reduction* is any move away from `published`,
or the removal of a field that was published. Because the manifest is inside
the signed and digest-covered report, a publisher cannot reduce disclosure
without that reduction being on the record.

**v1 is unaffected.** Its domain string, preimage, golden vectors and
fixtures are unchanged, and v1 reports keep verifying: historical reports are
what an auditor returns to years later.

Golden vectors: [`fixtures/report-v2.golden.json`](fixtures/report-v2.golden.json)
and [`fixtures/proof-for-report-v2.golden.json`](fixtures/proof-for-report-v2.golden.json),
built on the same tree as §10 — v2 changes the envelope, not the commitment.

The proof in that pair is a **`canton-solvency-proof-v1`** document, and its
name says so on purpose: a report v2 does not imply a proof v2. The two
version numbers move independently, because §8.5 changes the envelope and §9.2
changes the leaf. The proof-v2 vector is
[`fixtures/repo-proof.golden.json`](fixtures/repo-proof.golden.json), paired
with a report whose leaves are v2.

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
   are recognised, and the report satisfies its profile (§14.1): registered,
   carrying the aggregates it requires, and committing the leaf kind the proof
   supplies.
2. The recomputed §8.2 digest equals `proof.report_digest`.
3. `signature.public_key` equals the caller-supplied trusted key, and the
   signature verifies over the digest.
4. The leaf hash is recomputed from the disclosed preimage (§3).
5. The path is folded (§4), and **both** the resulting hash equals
   `report.root_hash` **and** the resulting per-asset sums equal
   `report.root_sums`.

Profile validation belongs in step 1, before the digest is recomputed, and the
order is normative rather than incidental. A report whose profile is
unregistered or whose statement is vacuous should be refused for that reason,
not for a digest mismatch it also happens to have: the two failures send a
reader to different places, and the profile answer is the one that says what is
wrong with the document. An implementation deferring the check until after
step 2 reports a different failure for the same document, which the §14.3
corpus notices.

Step 5 comparing sums is not redundant. A publisher can commit a truthful tree
and still print understated totals in the report; only an independent
comparison of the folded sums against the published ones detects it.

Absent and zero are the same claim: an asset missing from one side and zero on
the other is not a mismatch.

A verifier **MUST** return a verification failure for a document that is
malformed, not raise out of band. A field required to be an amount map may
arrive as `null`, a string or an array, and in languages where map access on
such a value throws implicitly this turns a rejection into a crash — leaving a
reader unable to tell an unverified report from a broken tool. The corpus
covers documents that are *wrong*; documents that are *not documents* are the
implementer's own test to write, and `docs/INTEGRATORS.md` says what ours
found.

**Sums MUST be compared as maps, per asset, over the union of both key sets.**
Comparing the §2 canonical strings instead is not equivalent, and the
difference is exploitable. The join is ambiguous: `{a: 1, b: 2}` and
`{"a:1.000000000000000000|b": 2}` render identically, so they share a leaf
hash and — given a sibling whose asset names do not interfere — the same root
hash. The per-asset comparison is what separates them. The canonical string is
already computed for hashing, which makes reusing it for the comparison a
natural optimisation and a wrong one.

JSON Schema: [`schemas/proof-v1.schema.json`](schemas/proof-v1.schema.json).

### 9.2 Proof document v2

For v2 leaves. `format_version` is `canton-solvency-proof-v2` and `leaf`
carries `{salt, subject_id, maps}` in place of `{salt, user_id, balances}`.
Everything else — the report binding, signature check, fold, and the
comparison of both hash and sums — is identical to §9.1.

Verifiers **MUST** refuse a v1 proof against a profile whose leaves are v2,
and a v2 proof against a profile whose leaves are v1 (§14.1). Without that
check the mismatch surfaces as an opaque hash failure.

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

## 11. Coverage

A liabilities report says what is owed. It cannot say whether anything backs
it. Coverage pairs it with a **custody report** — an ordinary §8 report over
`coverage.custody` leaves, whose root sums are qualified `held/<asset>` keys.

### 11.1 Coverage statement

```json
{
  "format_version": "canton-solvency-coverage-v1",
  "custody_report_digest": "<hex32>",
  "liabilities_report_digest": "<hex32>",
  "custody_basis": "omnibus custody party venue::custody"
}
```

The statement **restates no figures**. A number restated in a third document
is a number that can disagree with its sources; the comparison is derived from
the two reports it names.

Binding by digest is what makes the claim non-transferable. Without it a venue
could present today's custody totals beside last quarter's smaller
liabilities and the arithmetic would check out.

### 11.2 Verification

1. The statement's version is recognised.
2. The custody report declares `coverage.custody` and the liabilities report
   declares `solvency.liabilities`. Without this a liabilities report could
   stand in for custody and cover itself.
3. Both digests match the reports supplied.
4. Both signatures verify against caller-supplied trusted keys — which may
   differ, since a custodian and a venue are often different institutions.
5. For **every asset owed**, `held/<asset>` ≥ that asset's liability.

Step 5 is driven by what is owed, not by what is held: an asset held but not
owed is not a coverage question, while an asset owed and *not held at all*
is the worst case and must not read as "nothing required". Coverage is per
asset — a surplus in one does not excuse a shortfall in another.

### 11.3 What coverage does not prove

That the custody report describes real holdings. `custody_basis` records how
custody was established and is signed, but nothing here proves it: that is an
attestation problem, not a commitment one. What §11 does prove is that a
specific custody claim and a specific liabilities claim were published
together and compared honestly.

Golden vectors:
[`fixtures/custody-report.golden.json`](fixtures/custody-report.golden.json)
and
[`fixtures/coverage-statement.golden.json`](fixtures/coverage-statement.golden.json),
paired with the §10 report.

## 12. On-ledger anchoring

A signature proves who published a report. It does not stop a publisher
quietly replacing one, or dropping a day nobody asked about. An anchor chain
does.

```json
{
  "format_version": "canton-solvency-anchor-v1",
  "report_digest": "<hex32>",
  "root_hash": "<hex32>",
  "snapshot_time": "2026-01-01T00:00:00Z",
  "ledger_offset": "000000000000000042",
  "publisher": "golden::publisher",
  "publisher_key": "<hex32>",
  "prev_anchor": "<hex32>"
}
```

```
anchor_digest = SHA-256( "rocky-solvency-anchor-v1"
                       ‖ lp(format_version) ‖ lp(report_digest) ‖ lp(root_hash)
                       ‖ lp(snapshot_time)  ‖ lp(ledger_offset)  ‖ lp(publisher)
                       ‖ lp(publisher_key)
                       ‖ ( 0x00 | 0x01 ‖ lp(prev_anchor) ) )
```

> **On-ledger, `anchor_digest` is asserted rather than verified.** A Daml
> contract carrying an anchor can check the digest is well-formed hex and no
> more: this preimage is a length-prefixed binary concatenation and the
> hashing available to a contract operates on text. Every input to the digest
> is a field of the contract, so a reader who can see an anchor can recompute
> it and MUST do so before relying on the chain. Linking a history by trusting
> the stored digest trusts the publisher about precisely what anchoring exists
> to take out of their hands.

The predecessor is preceded by a **presence byte**, not encoded as an empty
string. Without it, a genesis anchor and an anchor naming an empty predecessor
hash identically, and a publisher could present a mid-history anchor as the
start of its history.

**Anchors carry digests and offsets, never balances.** An amount on a ledger
contract is disclosed to every observer of that contract — exactly the data
this format exists to keep private.

### 12.1 Chain rules

Verifiers walk a history oldest-first and reject:

- a first anchor that names a predecessor — a **complete** history starts at
  genesis, and verifying a suffix would let a publisher present only the days
  that suit them;
- an anchor that does not name the one before it, which covers both a dropped
  day and a fork;
- `snapshot_time` that does not strictly increase — two reports for the same
  instant are a restatement, not a history;
- `ledger_offset` that rewinds;
- a change of publisher mid-history.

Editing any past report changes its digest, so its anchor changes, so every
later link stops matching. That is the property: tampering is not merely
improbable, it is arithmetic.

### 12.2 What the ledger adds

The chain arithmetic above is verifiable **offline** from the anchor documents
alone. What a ledger contract adds is permanence — a record the publisher
cannot rewrite or quietly withdraw, witnessed by whoever it names as
observers. See [`daml/`](daml) for the package, and read its README: it is a
reviewed design that has **not** been compiled or run, because that needs the
Daml SDK and a participant node.

As §8.4 notes, anchoring is also the intended home for publisher key
distribution: a key bound on-ledger is a key a reader can obtain from
somewhere other than the server that served the report.

Golden vector: [`fixtures/anchor.golden.json`](fixtures/anchor.golden.json),
the genesis anchor of the §10 report.

## 13. Hierarchical commitments

A group is not one book. This section lets a subsidiary prove its position to
its own regulator without exposing its siblings, while the group root still
sums to the consolidated total.

No new envelope is needed: the group tree is an ordinary §4 Merkle sum tree
whose leaves are entities rather than customers, and a group report is an
ordinary §8 report with `profile` = `solvency.group`.

### 13.1 Entity leaf

```
entity_leaf_hash = SHA-256( "rocky-solvency-entity-v1"
                          ‖ lp(entity_id)
                          ‖ entity_root_hash        (32 raw bytes)
                          ‖ lpmap(entity_root_sums) )
entity_leaf_node = (entity_leaf_hash, entity_root_sums)
```

`entity_id` is bound into the hash deliberately. Using an entity's root node
directly as a group leaf would be simpler, but would let a group substitute
one subsidiary's subtree for another of equal total undetected.

Nesting is **one level**: a group over entities. Each additional level is
another verification surface, and nothing observed requires deeper.

### 13.2 Group report

An §8 report where `root_hash` is the group root, `root_sums` are the
consolidated totals, `leaf_count` is the number of entities, and `profile` is
`solvency.group`. Producers **MUST** set that profile: a group report states a
different thing from a customer-level one and must not be mistaken for it.

### 13.3 Membership document

```json
{
  "format_version": "canton-solvency-group-membership-v1",
  "group_report_digest": "<hex32>",
  "entity": { "entity_id": "…", "root_hash": "<hex32>", "root_sums": { … } },
  "steps": [ { "sibling_hash": "<hex32>", "sibling_sums": { … }, "sibling_on_left": true } ]
}
```

Verification follows §9.1 with the §13.1 leaf in place of a customer leaf:
bind to the report by digest, check the signature against the caller-supplied
trusted key, fold, and compare **both** the hash and the sums against the
group root.

### 13.4 Chain verification

To verify a customer against a group's consolidated total, all three hold:

1. The customer's proof verifies against the entity's report (§9.1).
2. The entity's membership verifies against the group report (§13.3).
3. The membership's `entity.root_hash` and `entity.root_sums` **equal** the
   entity report's own `root_hash` and `root_sums`.

Step 3 is not optional. Without it the first two are independently valid and
jointly meaningless: a group could present entity A's membership beside entity
B's report.

### 13.5 What a sibling learns

A subsidiary's regulator sees the entity's own report plus sibling leaf hashes
and subtotals. Sibling *identities* are not revealed — an entity leaf hash
discloses nothing about which entity it is — but sibling **subtotals are
visible**, exactly as for customer leaves in §5. This is the same trade-off,
stated rather than hidden.

### 13.6 Golden vectors

The §10 report as `golden-entity-a`, plus `golden-entity-b` with root
`0x11…11` and `USDA: 42`, under the §10 metadata and signing seed:

```
group_root    = f672eceb0b675040260bbc6062362c7701bddf8daaba128cae1bcaef80c5fb66
group_digest  = e2eb5175a25f845acf0059ec85a8594e2e5587d412ed3498a872c83057a93fc8
consolidated  = CBTC: 0.250000000000000000 | USDA: 143.500000000000000001
```

`143.500000000000000001` is `101.500000000000000001 + 42`, so the consolidated
total is checkable by hand against the §10 vector. Complete documents:
[`fixtures/group-report.golden.json`](fixtures/group-report.golden.json) and
[`fixtures/group-membership.golden.json`](fixtures/group-membership.golden.json),
asserted byte for byte by both implementations.

## 14. Profile registry

A report has always carried a `profile` field. Until this section nothing
checked it: any string was accepted and no rules attached to it. A profile
names the statement a root asserts, so leaving it unchecked meant a report
could claim to be one thing and be another.

Each registered profile pins what a leaf represents, the statement the root
asserts, and the aggregates the report must publish for that statement to
mean anything.

| Profile | A leaf is | The root asserts | Requires |
|---|---|---|---|
| `solvency.liabilities` | one customer's per-asset equity (§3) | every customer balance is committed, and the root's totals are the liabilities | `root_sums` |
| `solvency.group` | one subsidiary's root (§13.1) | every entity's root is committed, and the root's totals are the consolidated liabilities | `root_sums` |
| `collateral.repo` | one open repo leg (§3.1) | every open leg is committed, and the root totals are aggregate collateral and exposure | `collateral/*`, `exposure/*`, and coverage |

| `fund.nav` | one holder of a tokenized fund (§3.1) | every holder's units and entitlement are committed, and the root totals are units outstanding and total entitlement | `units/*`, `entitlement/*` |

| `settlement.dvp` | one settled trade, carrying both legs (§3.1) | every settled trade in this window is committed, and no leg settled without its counter-leg | `delivered/*`, `paid/*`, and both maps in every leaf |
| `eligibility.holder` | one holder's attested attributes (§3.1) | every committed holder satisfied each attested rule at issuance | `attested/*`, and each rule's total equal to `leaf_count` |

**Why a `settlement.dvp` leaf is a trade, not a leg.** If a leaf were a single
leg, a tree could hold a delivered leg with no matching payment and nothing
would notice — precisely the failure delivery-versus-payment exists to
prevent. Making the leaf the trade puts atomicity in the structure: a
committed trade missing a leg is rejected when its own proof is checked.

**Why `eligibility.holder` sums an indicator.** Each attested rule carries the
value `1` in every leaf, so `attested/R` totalling exactly `leaf_count` is
consistent with every committed holder having satisfied R. That is checkable
from a published report, where an eligibility claim otherwise requires the full
holder register — the thing an issuer cannot disclose. Inflating one holder's
indicator fails: the tree commits to the leaves, so the padded total no longer
matches the fold.

> **What unanimity rests on, and does not prove.** The argument is
> `total == leaf_count` and each leaf contributes `0` or `1`, therefore every
> leaf contributed `1`. It is sound given `leaf_count`. But **`leaf_count` is
> signed metadata, not a recomputed quantity**: it enters the §8.2 digest, so
> it cannot be altered after signing, and no inclusion proof can check it
> against the tree. A publisher committing ten holders, eight of them
> compliant, may assert `leaf_count = 8` and publish `attested/R = 8`; the
> check passes and the conclusion is false.
>
> No amount of arithmetic in this format closes that. An inclusion proof
> attests to one leaf, and a claim about *every* leaf cannot follow from it —
> the same limit that stops §5 from proving liabilities complete. Requiring a
> `present` indicator does not help: the same publisher sets it to `0` on the
> leaves they are hiding.
>
> What does close it is full disclosure. `recompute` (§10 tooling) rebuilds the
> tree from a complete leaf dump and so verifies `leaf_count` directly. A
> unanimity claim is therefore as strong as the auditor's access, and a report
> published without one is asserting unanimity rather than proving it.

**Why a `fund.nav` leaf is a shareholder, not a holding line item.** A
holdings tree would prove what the fund owns, but no investor could find
themselves in it, and being able to find yourself is the pattern this whole
format exists for. Whether the fund actually holds enough to back those
entitlements is an asset-side question — that is what a coverage report
answers, not something a liabilities tree can prove about itself. `units` is
keyed by share class and `entitlement` by currency, so NAV per share is
derivable from the published root by anyone.

`collateral.repo` carries an extra rule: for **every asset**, aggregate
`collateral` must be at least aggregate `exposure`. A surplus in one asset
does not excuse a shortfall in another. This is checked, not asserted — a
report declaring the profile while publishing totals that do not cover its
exposure is rejected, which is the entire point of the profile.

Golden vectors: [`fixtures/repo-report.golden.json`](fixtures/repo-report.golden.json)
and [`fixtures/repo-proof.golden.json`](fixtures/repo-proof.golden.json).
Coverage there is checkable by hand: collateral `110+55+22 = 187` against
exposure `100+50+20 = 170`.

### 14.1 Rules

Verifiers **MUST**:

- reject a report whose `profile` is not in the registry, rather than
  accepting an unrecognised one — the same discipline as manifest keys in
  §8.5;
- reject a report that omits an aggregate its profile requires, because the
  statement would be vacuous: a liabilities report with no totals asserts
  nothing; and
- reject a proof whose leaf kind does not match the profile's. A customer
  inclusion proof (§9) does not belong to a tree whose leaves are entities,
  and a group membership (§13.3) does not belong to a customer-level book.
  Without this check the mismatch surfaces later as an opaque hash failure,
  which tells the reader nothing about what went wrong.

### 14.2 Adding a profile

All six profiles the format set out to cover are registered. A seventh needs
the same treatment: a decision about what a leaf is, what the root asserts,
and which rules are checked rather than asserted. An unregistered profile is
rejected outright (§14.1), so a half-considered entry is worse than none.

### 14.3 Conformance corpus

[`conformance/`](conformance) holds the cases an implementation must agree on
to claim compatibility. Each is a directory of documents plus an expected
outcome, listed in `manifest.json`, and the corpus is generated from the
golden fixtures so it cannot drift from the vectors both implementations
already assert.

A corpus of only-accepting cases would pass against an implementation that
accepts everything, and a corpus of only-rejecting cases against one that
rejects everything, so the runners assert a floor on both. A case whose
mutation fails to apply is rejected at generation time: a mutation that
silently no-ops produces a "rejection" case that is really testing acceptance
of a valid document.

Both reference implementations run the corpus. That is the point — golden
vectors pin the bytes two implementations produce, and the corpus pins the
*decisions* they make.

A rejecting case carries a `failure`, and a runner **MUST** check that the
rejection is the declared one rather than merely that the document was
rejected. A case can exercise the check it names and a different check in
fact: `proof-understated-totals` reads as a test of the §9.1 sums comparison
and is rejected one step earlier by the digest binding, which left the sums
comparison — the format's only defence against a publisher printing
understated totals — untested by the whole corpus.

Two kinds of rule beyond required aggregates are available, and both exist
because a total alone cannot express the statement:

- **per-leaf** (`required_leaf_maps`) — checked when a proof is verified, for
  statements about each subject, such as a trade carrying both legs;
- **unanimity** (`unanimous_maps`) — checked against `leaf_count`, for
  statements about *every* subject without naming any of them.

A v2 proof belongs to *any* v2-leaf profile, so the leaf-kind gate cannot
separate two v2 profiles from each other. A fund proof presented against a
repo report is caught by the commitment itself — the report digests
differently, so the binding in §9.2 fails.

### 14.4 Audience-scoped packaging

One commitment may be packaged for several audiences. Every packaging commits
to the same leaves, so the root hash, the totals and the leaf count are
identical; only the manifest (§8.5) differs.

Two packagings therefore have **different digests and different signatures**,
which is correct: they are different statements about the same commitment.
A verifier comparing two packagings checks that the root, totals and leaf
count agree — without that check a venue could hand two audiences genuinely
different books, and each would verify in isolation.

Producers **MUST NOT** emit two packagings naming the same audience: one would
silently stand in for the other.

### 14.5 Compatibility statements

The corpus establishes what an implementation does. A **compatibility
statement** is how it says so, in a form another party can check rather than
take on trust.

```
statement = { format_version, implementation, version, supports[],
              corpus_digest, results[] }
result    = { id, expected, outcome }
```

`format_version` is `canton-solvency-compat-v1`. `supports` lists §14.3
`requires` names — the feature set the implementation claims. `results` covers
**every** case in the corpus, including skipped ones, whose outcome is `skip`.

Three rules make a statement meaningful rather than decorative:

- A case whose `requires` are a subset of `supports` **MUST NOT** be reported
  as `skip`. Claiming a feature and then skipping its cases is the failure
  mode this exists to catch.
- A case whose `requires` are *not* a subset of `supports` **MUST** be
  reported as `skip`, never as a pass. A verifier that rejects a document
  because it does not implement that document's version has not tested
  anything, and a rejection for the wrong reason is indistinguishable from a
  correct one at this level of detail.
- `corpus_digest` binds the statement to the exact corpus it was produced
  against:

```
corpus_digest = SHA-256( "rocky-solvency-corpus-v1"
                       ‖ u64le(case_count)
                       ‖ ( lp(id) ‖ lp(expect)
                         ‖ u64le(requires_count) ‖ lp(requires_i)* )* )
```

with cases in manifest order and `requires` in the order listed. Two
statements over different corpora are not comparable, and without this binding
that would not be visible.

An implementation MAY sign a statement with the §8.3 block over the statement
digest. Nothing here depends on it: a statement is a claim by its author, and
a reader who wants assurance runs the corpus themselves. Its value is that
disagreement becomes *locatable* — two implementations' statements differ at a
named case rather than in an unreproducible report of "we tested it".

## 15. Evidence packs

Every document in this format verifies on its own. That is not the same as a
*delivery* verifying.

A proof says nothing about what else was sent alongside it. Hand an auditor a
folder with one customer's proof removed and it verifies exactly as cleanly as
the complete folder: every remaining file is valid, the report is correctly
signed, the totals are right, and nothing anywhere records that a file is
absent. The same holds for a coverage statement swapped for an older one, or
an anchor quietly dropped from a history.

An evidence pack closes that gap. It is a signed index naming every member of
a delivery and its digest, so the *set* is committed rather than only its
elements.

### 15.1 The index

```
pack.json = { pack, signature }
pack      = { format_version, publisher, snapshot_time, report_digest, entries }
entry     = { name, sha256 }
```

`format_version` is `canton-solvency-pack-v1`. `report_digest` is the §8.2
digest of the report the pack is evidence for, so a pack cannot be lifted onto
a different report. `entries` is sorted by `name`, so the same files assembled
in any order produce the same pack.

`name` MUST be a plain file name: not empty, `.`, `..`, and containing neither
`/` nor `\`. A pack describes one directory; a name that could escape it would
be a delivery instruction rather than an integrity claim. Producers MUST
refuse to build such an index and verifiers MUST refuse to accept one — a name
edited in transit breaks the signature, so the only way one arrives signed is
a publisher that meant it.

`sha256` is the digest of the member's bytes **as delivered**, not of any
re-serialisation of them. A verifier that reformatted a member before hashing
it would report every honest delivery as altered.

This makes a pack correct for any byte convention but reproducible only within
one. The reference producer writes members as pretty-printed JSON with two
spaces of indentation and a trailing newline; a producer that omits the
newline emits an equally valid pack whose digests match no checked-in fixture.
Implementations comparing against the conformance corpus must reproduce that
convention.

### 15.2 Pack digest

```
sha256( "rocky-solvency-pack-v1"
      ‖ lp(format_version) ‖ lp(publisher) ‖ lp(snapshot_time)
      ‖ lp(report_digest)
      ‖ u64le(entry_count)
      ‖ (lp(name) ‖ lp(sha256))* )
```

`lp` and `u64le` are as in §8.1. The entry count is committed before the
entries: without it a pack over two members and a pack over one longer member
could be made to agree, and the number of files is part of the claim.

The signature is detached, over this digest, in the §8.3 block.

### 15.3 Verification

In order:

1. `format_version` is `canton-solvency-pack-v1`.
2. The signature verifies under a **caller-supplied trusted key** — never the
   key the pack carries, which is present for display only.
3. Every entry's name is safe (§15.1).
4. Every entry names a file that is present, whose bytes hash to `sha256`.
5. No file in the delivery is absent from the index.

Named-but-absent is reported before present-but-unnamed, because a dropped
proof is the failure this exists to catch.

A verifier MUST NOT verify a delivery's contents once the index has failed.
Reporting that the 999 proofs which did arrive all verified is true and
beside the point, and reads as a clean run.

### 15.4 What a pack does not do

A pack proves a delivery is the one that was signed. It does not establish who
should have signed it — that is the trusted key's job, and the honest source
for that key is an anchor (§8.4), which is independent of whoever assembled
the archive.

Nor does a pack say a delivery is *sufficient*. A publisher may sign an index
over a genuinely partial set. What the pack removes is the ability to reduce a
delivery after the fact without leaving a record: the omission has to be
declared and signed rather than simply performed.

## 16. Assurance levels

Every preceding section answers one question: does this document check out.
That question has more than one answer, and until this section they were all
spelled the same way.

A liabilities total recomputed from committed leaves and a custody total the
publisher merely signed both pass §9.1. Both are, against what §9.1 asks. But
the first is checkable arithmetic over a set that customers police themselves —
each can see their own leaf and will say so if it is short — and the second is
an assertion about assets held somewhere else, arithmetic over a list the
publisher wrote. A format that returns "verified" for both has told the reader
something false about the second, in the strongest word it has.

The gap is not cryptographic and cannot be closed cryptographically. §9.1
establishes that a published total equals the sum of the leaves committed to.
Whether those leaves describe anything real is outside what any commitment
scheme can reach. A custody report over invented positions recomputes
perfectly.

So a report may carry a statement declaring, per field, what kind of evidence
stands behind it, and a verifier establishes independently what it can
actually substantiate. A declaration the verifier cannot substantiate is a
verification failure. This is the whole mechanism: a taxonomy the publisher
could assert into being would record the over-claim rather than prevent it.

### 16.1 The levels

| Level | Meaning |
| --- | --- |
| `not-disclosed` | Withheld under the §8.5 manifest. Not a weaker claim — no claim. |
| `claimed-only` | The publisher signed for it; nothing else stands behind it. |
| `issuer-attested` | The party that issued the asset signed for it. |
| `third-party-attested` | A custodian, auditor or oracle signed for it — someone other than the publisher and other than the issuer. |
| `ledger-derived` | Evidenced by an anchor (§12) pinning this report to named ledger state at a named offset. |
| `cryptographically-verified` | The verifier recomputed it from the commitments (§9.1). |

`cryptographically-verified` MUST be read as the narrow claim it is: the
published figure equals the sum of the committed leaves. It does not establish
that those leaves describe assets that exist. Implementations MUST NOT present
it to a reader as though it did.

These are not a total order, and this specification does not define one.
Whether a custodian's signature outranks a derivation from ledger state
depends on the asset: for a tokenised position the ledger *is* the asset; for
a treasury bill it is a pointer to a claim someone else honours. Any single
ranking would be wrong for one of them.

Where an implementation orders them for display, `issuer-attested` MUST sort
below `third-party-attested`. The issuer is the party whose solvency is in
question, and self-attestation is the weaker of the two.

### 16.2 The assurance statement

```
assurance = { format_version, report_digest, levels }
levels    = { <field path>: <level> }
```

`format_version` is `canton-solvency-assurance-v1`. `report_digest` is the
§8.2 digest of the report the statement describes; a statement naming a
different report MUST be refused, or a statement earned by a well-attested
report could be presented beside a later one that has none.

Field paths are the §8.5 manifest's report-resident vocabulary — `root_sums`,
`mark_prices`, `disclosures.bad_debt`, `disclosures.excluded_house_accounts`,
`disclosures.excluded_house_totals` — and no others. A verifier MUST refuse a
statement naming a path outside it. A level for a field nobody checks is
decoration.

A field may be omitted, which asserts nothing about it. Omission is honest;
`claimed-only` is also honest. Neither is a failure.

### 16.3 Attestations

```
attestation.json = { attestation, signature }
attestation      = { format_version, report_digest, field, role, attestor, basis }
```

`format_version` is `canton-solvency-attestation-v1`. `role` is `issuer` or
`third-party`. `attestor` names the signing party for display only — trust
comes from the key. `basis` records how the attestor established the fact;
it is signed but proven by nothing here, the same honest limitation
`custody_basis` carries in §11.

Attestation digest:

```
sha256( "rocky-solvency-attestation-v1"
      ‖ lp(format_version) ‖ lp(report_digest) ‖ lp(field)
      ‖ lp(role) ‖ lp(attestor) ‖ lp(basis) )
```

`lp` is as in §8.1. The domain string differs from §8.2's so an attestation
signature can never be replayed as a report signature, and `field` is inside
the preimage so an attestor who signed for one field has not signed for
another.

The signature is detached, over this digest, in the §8.3 block.

### 16.4 Establishing and checking

A verifier is given the signed report, a trusted publisher key, and whatever
evidence accompanies the delivery: an inclusion proof, an anchor,
attestations. It is also given, out of band, a map from **attestor key** to
the role that key is trusted for. An attestation carrying its own key
establishes nothing — the question is never whether a document is signed but
whether it is signed by someone the reader decided to believe before opening
it. This is §8.4 applied to attestors.

In order:

1. `format_version` is `canton-solvency-assurance-v1`.
2. `report_digest` equals the §8.2 digest of the report supplied.
3. The report's signature verifies under the caller-supplied trusted
   publisher key (§9.1 steps 2–3). A statement about a report nobody vouched
   for MUST NOT be graded.
4. Every declared field path is in the §16.2 vocabulary.
5. For each field, the verifier computes the **set** of levels it can
   substantiate:
   - `not-disclosed` iff the manifest marks the field withheld and the report
     carries no data for it (§8.5).
   - `claimed-only` for every field the report carries. Always available once
     step 3 passed, and never worth more than it says.
   - `cryptographically-verified` iff the field is `root_sums` and an
     inclusion proof was supplied that verifies against this report under
     §9.1. No other field is committed in the tree; `mark_prices` and the
     `disclosures.*` fields enter the report digest and are therefore signed,
     but nothing recomputes them.
   - `ledger-derived` iff an anchor was supplied whose `format_version`,
     `report_digest`, `root_hash`, `snapshot_time`, `ledger_offset` and
     `publisher` all agree with this report. Partial agreement is not
     evidence: the digest already covers the report, so a disagreement
     elsewhere means one of the two documents was edited afterwards.
   - `issuer-attested` / `third-party-attested` iff an attestation for that
     exact field, bound to this report digest, verifies under a key the
     caller trusts **for that role**. A key trusted as a custodian MUST NOT
     establish `issuer-attested`.
6. Each declared level MUST be a member of that field's established set. A
   declaration outside it is a verification failure naming the field, the
   level declared, and the levels that were established.

A failure MUST name the field. "The report is invalid" leaves a reader unable
to tell a forged document from a publisher who claimed one level too many on
one line.

### 16.5 What this does not do

It does not make an attested figure true. A custodian can sign for reserves
that are lent out, and this format will report `third-party-attested`
faithfully. What it removes is the ability to present that figure in the same
words as one the reader could have recomputed.

Nor does it oblige anyone to publish a statement. A report without one is
exactly as valid as it was before this section existed, and a reader is
entitled to treat every figure in it as `claimed-only` — which is what the
report was always saying, and what the format previously had no way to write
down.
