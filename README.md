<div align="center">

# Canton Proof-of-Solvency

**Publish it. Prove it. Verify it yourself.**

Privacy-preserving proof-of-solvency infrastructure for exchanges and
custodial applications on the [Canton Network](https://www.canton.network/).

[![CI](https://github.com/Rocky-exchange/canton-proof-of-solvency/actions/workflows/ci.yml/badge.svg)](https://github.com/Rocky-exchange/canton-proof-of-solvency/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](rust/solvency-merkle/Cargo.toml)
[![Spec](https://img.shields.io/badge/wire_format-v1-informational.svg)](SPEC.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

English | [简体中文](README.zh-CN.md)

</div>

---

## 📖 Overview

Canton's privacy model is its greatest strength for institutions — and its
hardest problem for public trust: **there is no public ledger on which anyone
can recompute a venue's books.** Exchanges, custodians, and asset platforms on
Canton have no standard way to prove *custody assets ≥ user liabilities*
without disclosing private data.

This project closes that gap. A venue publishes a daily cryptographic
commitment to all user balances; every user verifies — entirely in their own
browser — that their balance is included in the published totals. Raw data
never leaves the venue's participant node. The public sees commitments,
proofs, and totals: the same trust shape as Canton itself.

Proof of solvency is the **first disclosure profile** built on that machinery,
not the whole of it. The same commitment, proof, and verification core answers
the more general question every institution arriving on Canton has to solve:
*how do you prove a specific statement about private ledger data, to a specific
audience, without publishing the data?* Reserve coverage, repo
collateralization, fund NAV backing, atomic settlement assurance, and holder
eligibility are all that same shape — see
[Disclosure Profiles](#-disclosure-profiles).

### In plain terms

**What "liabilities" means.** When you deposit money at an exchange, it stops
being a pile of coins with your name on it and becomes *a debt the venue owes
you*. Add up what the venue owes every customer and you have its
**liabilities**. Set that against the assets it actually holds in custody: if
assets ≥ liabilities, the venue is **solvent** — everyone could ask for their
money back at once and be paid.

**What "recompute" means.** Any venue can *claim* it is solvent. The question
is whether you have to take its word for it. On a public blockchain you don't:
anyone can download the ledger and redo the arithmetic from the raw data,
arriving at the same totals without asking permission. That is what
"recompute" means here — independently redoing the sums, instead of trusting a
number somebody published.

Canton deliberately does not work that way. Balances are private — which is
precisely why institutions use it — so no outsider can redo the arithmetic.
This project hands back the checkable part without giving up the privacy:

1. **The venue commits.** Each day it totals what it owes every customer and
   compresses that entire list — every customer, every balance — into a single
   64-character fingerprint, called the *root*. Change one balance anywhere in
   the list and the fingerprint changes completely, so publishing it pins the
   venue to one specific version of its books.
2. **The venue publishes.** The root, plus the totals it claims to owe.
3. **You check.** You download a small file: your own balance, plus roughly
   seventeen intermediate fingerprints — that is all it takes for a venue with
   100,000 customers. Your browser redoes the slice of the arithmetic that
   involves you and confirms it lands exactly on the published root *and* the
   published total.

If it lands, your money was counted, at the amount shown to you, inside the
figure the venue told the world. If the venue quietly dropped you, shrank your
balance, or understated the total, the check fails — on your computer, not on
theirs. No identities are exposed along the way: other customers appear only
as unlabeled fingerprints and subtotals, and because the salts are rotated
every snapshot, those cannot be tied to a person or tracked from one report to
the next.

**Glossary**

| Term | In plain words |
|---|---|
| Liabilities | What the venue owes its users — the sum of every customer balance |
| Solvency | Assets held ≥ liabilities owed |
| Recompute | Redo the arithmetic yourself from raw data, instead of trusting a published number |
| Commitment | A short fingerprint of a large dataset, published up front; the data cannot change afterwards without the fingerprint changing |
| Leaf / root | Your individual entry / the one fingerprint covering the whole list |
| Inclusion proof | The few extra fingerprints needed to show your entry is inside the committed list |
| Merkle sum tree | The structure that lets a single root prove membership *and* the totals at once |
| Salt | A per-user random value mixed into your entry, so nobody can guess it by trying balances |

## 🧭 Why Canton Needs This

Elsewhere, proof of solvency supplements public data. On Canton it *is* the
public data — and the gap is structural, not a matter of a venue choosing to
disclose less.

### Institutional Canton is arriving faster than its disclosure tooling

What is moving onto Canton is no longer test balances:

| Date | Who | What went on-chain |
|---|---|---|
| 2025-11-12 | Franklin Templeton | [Benji tokenized-fund platform extends to Canton](https://www.canton.network/canton-network-press-releases/franklin-templetons-benji-technology-platform-expands-to-canton-network) |
| 2025-12-17 | DTCC + Digital Asset | [Tokenizing DTC-custodied U.S. Treasuries](https://blog.digitalasset.com/press-release/dtcc-and-digital-asset-partner-to-tokenize-dtc-custodied-u.s.-treasury-securities-on-the-canton-network) — MVP in controlled production H1 2026; DTCC joins the Canton Foundation as co-chair alongside Euroclear |
| 2026-01-07 | J.P. Morgan (Kinexys) | [USD JPM Coin (JPMD) issued natively on Canton](https://www.prnewswire.com/news-releases/digital-asset-and-kinexys-by-jp-morgan-announce-intention-to-bring-usd-jpm-coin-jpmd-natively-to-the-canton-network-302654967.html) |
| 2026-07-01 | Tradeweb | [Real-time on-chain U.S. Treasury trade](https://blog.digitalasset.com/press-release/tradeweb-on-chain-us-treasuries-canton) — Franklin Templeton ↔ Virtu Financial, tokenized UST against digital cash, atomically settled |
| ongoing | Broadridge | Distributed Ledger Repo, running institutional repo volume on Canton-related infrastructure |

*These are Canton Network deployments, not users of this project — they are the
context it is built for. Actual adopters are listed under
[Who Is Using](#-who-is-using).*

Each one creates a claim that somebody downstream needs to check and currently
cannot: that a tokenized Treasury is backed by the security in custody, that a
repo is collateralized to its haircut, that a fund's NAV is backed by its
holdings, that both legs of a delivery-versus-payment actually settled. Canton
keeps the underlying data private — correctly, or these firms could not use it
at all. The missing half is a standard way to *prove* the claim to the party
entitled to check it.

### "Make it transparent" is the wrong instruction for an institution

Different audiences are entitled to different things, and the gap between them
is the whole product:

| Audience | Must be able to check | Must not see | Today's substitute |
|---|---|---|---|
| End investor / client | My position is included; the fund is backed | Other clients' positions | Monthly statement PDF |
| Trading counterparty | Collateral behind our open trades exists and covers exposure | The venue's other counterparties and their sizes | Bilateral trust, margin calls |
| Issuer / custodian | Token supply matches assets under custody | Client-level allocations | Reconciliation files |
| Auditor | The whole book reconciles; sampling is complete | (entitled to everything, under NDA) | Quarterly attestation |
| Regulator | Segregation, concentration, and limits are respected | Commercially sensitive detail beyond the mandate | Periodic filings |
| Public market | The issuer is solvent; reserves cover liabilities | Anything client-identifying | Press release |

Every row is the same cryptographic operation with a different audience and a
different disclosed subset. Six bespoke implementations, one per institution,
is how an ecosystem ends up with no standard at all.

### Underneath, the reasons are structural

- **No third party can recompute the books.** A participant node sees only
  the contracts it is a stakeholder in; there is no global state and no
  public explorer or indexer over it. The traditional substitute is an
  auditor's attestation, but it is periodic, delivered as prose, and — the
  part that matters — not checkable by the person whose money it is. You can
  read the report; you cannot find *yourself* in it.

- **The venue is the only party that can total the book.** Canton is a
  network of networks: holdings and user positions can span multiple
  synchronizers and applications, and no single vantage point aggregates
  them. The venue is therefore the sole author of the number — precisely the
  situation that calls for a commitment users can check rather than a figure
  users must accept.

- **There is no "as of block N".** Ethereum-style transparency inherits a
  canonical, globally agreed instant for free. Canton participants each have
  their own ordered event streams, so "as of when" has to be constructed,
  published, and pinned — hence the snapshot timestamp and ledger high-water
  mark this format requires ([SPEC.md](SPEC.md) §7). Without them a snapshot
  is unfalsifiable: any inconvenient balance can be blamed on timing.

- **The stakes are institutional.** Canton hosts regulated venues, tokenized
  funds, and RWA platforms whose counterparties have mandates requiring
  evidence rather than assurances — under confidentiality terms that forbid
  the usual answer of publishing everything.

- **Commitments are already Canton's native trust shape.** Participants
  detect divergence by periodically exchanging hash commitments over shared
  contract state, not by exposing the state itself. Publishing a per-user
  Merkle sum commitment and answering membership questions on demand is the
  same pattern, extended from participant-to-participant to venue-to-public.
  Nothing here runs against the grain of the network.

## 🔀 Why Not Port an Ethereum Proof-of-Reserves Design?

Because the Merkle tree is the easy tenth of the problem, and every
assumption the other nine tenths rest on is absent here.

| An Ethereum PoR design assumes… | On Canton | So this design must |
|---|---|---|
| **Reserves are public** — `balanceOf` on a known address; explorers and dashboards let anyone cross-check the asset side for free. | Custody holdings are Daml contracts visible only to their stakeholders. There is no address to point at, and no explorer to point it at. | Treat *both* sides of the inequality as private. The asset side becomes a published, committed figure with its own attestation path ([Milestone 1](#milestone-1--canton-reserve-verification)) — not a link to a block explorer. |
| **Control of reserves is provable by signing** — a wallet signs a challenge; the address is the identity. | Holdings are contracts held by parties, not balances behind a key whose state is publicly readable. | Attest and disclose custody explicitly. The tree never implies it — see [Security Model](#-security-model). |
| **The snapshot is a block height** — "as of block N" is canonical and anyone can re-derive state from it. | No global block height; each participant has its own event stream per synchronizer. | Make snapshot timestamp and ledger high-water mark normative published fields; the report is what pins the instant. |
| **A balance is an account entry**, read out of an exchange database. | A balance is an aggregate: active holding contracts, amounts locked in in-flight settlement workflows, and at a derivatives venue margin and unrealized PnL at mark. | Specify the derivation instead of leaving it to the integrator — clamp-and-disclose negatives, exclude *and* disclose house accounts, publish the mark prices used. |
| **`uint256` and integer arithmetic** — amounts are wei; decimals are a display concern. | Daml `Decimal` is a signed `NUMERIC(38,18)`. | Use exact 18-decimal fixed point end to end, one canonical string render, overflow-checked addition — otherwise two implementations disagree in the last digit and every proof fails. |
| **Verification happens against a public contract**, increasingly a ZK verifier contract anyone can call. | A Daml contract is visible only to its stakeholders, so "on-ledger" does not mean "publicly verifiable". | Run verification in the user's browser. On-ledger anchoring ([Milestone 2](#milestone-2--on-ledger-anchoring)) buys tamper-evident history, not public verifiability; the client-side check stays the trust root. |

And the trees circulating in the Ethereum ecosystem are often the ones you
least want to copy. These are not hypotheticals — each has appeared in a
deployed proof-of-reserves scheme, and each has a rule in
[SPEC.md](SPEC.md) that forecloses it:

- **Odd nodes duplicated.** Hashing a lone node against itself counts its
  subtree twice and inflates the committed total. → Odd nodes are *promoted*
  unchanged (§4).
- **Sums outside the hash.** If per-node totals aren't bound into the node
  hash, a root can be honest about membership and wrong about the total. →
  Sums are hashed at every level, and verification compares sums *and*
  hashes (§4, §5).
- **Leaves that leak.** Unsalted leaves over a small balance space are
  brute-forceable, and leaves that stay stable across reports let an observer
  track one user over time. → `salt = HMAC-SHA256(per-snapshot master salt,
  user_id)`, so the same user's leaf hash is unlinkable between snapshots
  (§3).
- **Negatives allowed to net.** One under-water account silently offsets
  other users' balances and the venue prints a solvent total. → Negative
  equity never enters the tree; it is clamped and disclosed as bad debt (§1).

## 📐 Disclosure Profiles

A **profile** is a named statement, a leaf schema, and an audience matrix. The
cryptographic core underneath never changes — which is what makes this a format
rather than a script.

**Constant across every profile:** the Merkle sum tree and its domain-separated
hashes, canonical 18-decimal encoding, per-snapshot salt derivation, the
inclusion-proof format and verification rule, the report envelope (format
version, snapshot time, ledger offset, publisher, signature), the anchor chain,
and the verifier itself.

**Varies per profile:** what a leaf represents, what statement the root
asserts, which aggregates are published, and who is entitled to which view.

| Profile | Statement proven | A leaf is | Status |
|---|---|---|---|
| `solvency.liabilities` | Every customer balance is committed, and the root's totals are the liabilities | one customer's per-asset equity | **shipped** |
| `solvency.coverage` | Custody holdings ≥ liabilities, asset by asset | one custody position | M1 |
| `collateral.repo` | Every open leg is committed, and aggregate collateral covers aggregate exposure per asset | one open repo leg, with `collateral` and `exposure` maps | **shipped** |
| `fund.nav` | Every holder's units and entitlement are committed; root totals are units outstanding and total entitlement | one shareholder, with `units` and `entitlement` maps | **shipped** |
| `settlement.dvp` | Every settled trade is committed, and no leg settled without its counter-leg | one settled trade, with `delivered` and `paid` maps | **shipped** |
| `eligibility.holder` | Every committed holder satisfied each attested rule at issuance | one holder's attested attributes | **shipped** |

**The disclosure manifest.** Each report carries a machine-readable manifest
declaring, field by field, what is *published* (visible to that audience),
*committed* (proven but not shown), or *withheld*. Because the manifest is
bound into the signed and anchored report, an institution cannot quietly
disclose less than it did last quarter — the reduction is itself on the record
and surfaces as a diff. Selective disclosure becomes an auditable decision
rather than an editorial one.

**Hierarchy.** A large institution is not one book. A Merkle sum tree composes
naturally: entity-level roots become the leaves of a group-level tree, so a
subsidiary can prove its own subtree to its own regulator without exposing its
siblings, while the group root still sums to the consolidated total.

**Extending the node rule.** Some statements need more than sums —
concentration limits ("no counterparty exceeds 10% of the pool") need a
per-node maximum alongside the per-node total. That changes the node hash, so
it ships as a new format version under new domain strings, never as a silent
upgrade (see [Versioning](#-versioning--compatibility)).

## ✨ Features

- **Merkle sum tree commitments** — every node carries per-asset totals, so
  the root *is* the published liability figure; omitting a user, shrinking a
  balance, or misstating totals breaks someone's proof.
- **Self-service verification** — users verify inclusion in the browser with
  WebCrypto; no trust in the venue, no server round-trip for the math.
- **Cross-implementation golden vectors** — the Rust producer and TypeScript
  verifier assert the identical byte-level vectors ([SPEC.md](SPEC.md) §6);
  the two implementations cannot silently diverge.
- **Honest edge handling** — negative equity is clamped and disclosed as bad
  debt (never allowed to cancel other users' balances); house accounts are
  excluded and disclosed; odd nodes are promoted, never duplicated.
- **Exact arithmetic** — 18-decimal fixed point end to end, lossless against
  `NUMERIC(38,18)` ledgers; every addition is overflow-checked.
- **Production proven** — powers the daily solvency reports and the public
  Transparency page at [Rocky](https://rocky.exchange), a derivatives and
  spot exchange built natively on Canton.

## 🏗️ Architecture

```text
 ┌────────────────────────── venue (private) ──────────────────────────┐
 │                                                                     │
 │  ledger snapshot ──► per-user equity ──► leaves ──► Merkle sum tree │
 │  (one consistent    (clamp negatives,   (HMAC     (checked totals   │
 │   read, pinned to    exclude house       per-user   at every node)  │
 │   event high-water)  accounts)           salts)          │          │
 └──────────────────────────────────────────────────────────┼──────────┘
                                                            ▼
                                       public report: root hash + totals
                                       + mark prices + disclosures
                                                            │
 ┌────────────────────────── user (browser) ────────────────┼──────────┐
 │                                                          ▼          │
 │  proof = leaf preimage (salt, balances) + sibling path              │
 │  1. recompute leaf hash   2. fold path   3. compare root AND totals │
 └─────────────────────────────────────────────────────────────────────┘
```

| Component | Path | Description |
|---|---|---|
| `canton-solvency-merkle` | [`rust/solvency-merkle`](rust/solvency-merkle) | Producer-side commitment core (Rust) |
| `canton-solvency-verifier` | [`ts/verifier`](ts/verifier) | Browser-side verifier (TypeScript, WebCrypto + BigInt) |
| Wire format | [`SPEC.md`](SPEC.md) | Byte-level format v1 + golden vectors |
| Example | [`examples/csv_report.rs`](rust/solvency-merkle/examples/csv_report.rs) | CSV → root, totals, verified proof |
| `canton-solvency-report` | [`rust/solvency-report`](rust/solvency-report) | Signed report + proof documents (Rust) |
| Fixtures & schemas | [`fixtures`](fixtures) · [`schemas`](schemas) | Golden documents + JSON Schema for every one of them |
| Offline verifier | [`offline/verifier.html`](offline/verifier.html) | Self-contained page, no build step, no network |
| `canton-disclosure-console` | *planned — [M4](#milestone-4--disclosure-console)* | Publisher + viewer web console |
| `canton-solvency-verify` | [`rust/solvency-cli`](rust/solvency-cli) | Auditor CLI, batch verification |

## 🖥️ Disclosure Console

> **Status: viewer and designer shipped; publishing itself is not.**
> [`console/viewer.html`](console/viewer.html) reads a published disclosure;
> [`console/designer.html`](console/designer.html) designs the manifest for the
> next one and diffs it against the last, refusing to export a manifest a
> verifier would reject. Both are self-contained files with no network calls.
> What remains blocked is narrower than it first looked: connecting a
> participant node, reading live data, and signing and publishing need a ledger
> connection and the producer's key, which a page loaded from a file cannot
> have. The designer exports a manifest for the producer instead.

A commitment nobody can operate is not transparency infrastructure. The console
is two surfaces over one format.

**Publisher — for the disclosing institution's operations and compliance teams**

- Connect a participant node, declare parties, pick a profile. No code.
- **Disclosure designer** — decide field by field what is published, committed,
  or withheld, per audience, with a live preview of exactly what a
  counterparty, an auditor, a regulator, and the public will each see.
- **Pre-publication diff** — before anything ships, see what changed against
  the previous report, with newly disclosed *and* newly hidden fields called
  out. Accidental disclosure and quiet de-disclosure are both caught here.
- Schedule, sign, publish, anchor
  ([Milestone 2](#milestone-2--on-ledger-anchoring)).

**Viewer — for counterparties, auditors, regulators, and end clients**

- **Provenance on every number.** Nothing is rendered without stating how it is
  known: *verified* (recomputed in your browser from the commitment),
  *disclosed* (asserted by the publisher, not proven), or *withheld*. Making
  the boundary between proof and assertion impossible to miss is the point of
  the product.
- **Data-flow view** — the Canton shape behind a figure, drawn as a graph:
  which parties, which synchronizers, which contract types feed each subtotal.
  Aimed squarely at institutions with deep entity hierarchies who are new to
  Canton and need to see where a number comes from.
- **Coverage view** — per-asset reserves against liabilities, with shortfalls
  flagged rather than netted away.
- **History view** — the anchor chain over time; a restated or missing report
  shows up as a break in the chain, not as a footnote.
- **Self-check** — drop in your own proof file and verify it locally, offline.
- **Evidence pack** — export a signed archive an auditor can re-verify years
  later with the CLI, with no dependency on the publisher's infrastructure or
  on this project's.

## 🚀 Quick Start

**Prerequisites:** Rust ≥ 1.75 (producer) · Node.js ≥ 18 (verifier).

Rust — build a commitment from a CSV and verify a proof end to end:

```bash
cd rust/solvency-merkle
cargo test                                          # includes SPEC golden vectors
cargo run --example csv_report -- balances.csv my-master-salt
```

TypeScript — run the verifier against the same golden vectors:

```bash
cd ts/verifier
npm install && npm test
```

Verify a published report from the command line — no server, no network:

```bash
# Produce a signed report and per-user proofs from a CSV
cargo run --manifest-path rust/solvency-report/Cargo.toml \
  --example publish_report -- balances.csv my-master-salt ./out

# Check every proof against it (exit 0 all verified, 1 a proof failed, 2 I/O)
cargo run --manifest-path rust/solvency-cli/Cargo.toml -- \
  verify --report ./out/report.json --proof-dir ./out --key <publisher-key-hex>
```

```text
report digest : 1a10a9f2748eddebe1a684106da043c165e6ba0ed01ad131d01dd646396a3987
FAILED ./out/proof-alice.json (alice): proof does not fold to the published root
2 of 3 proofs verified — FAILED
```

Verify a customer all the way up to a group's consolidated total — their proof
against the subsidiary's report, the subsidiary against the group, and that
those two documents describe the same book:

```bash
cargo run --manifest-path rust/solvency-cli/Cargo.toml -- verify-chain \
  --group-report fixtures/group-report.golden.json \
  --membership   fixtures/group-membership.golden.json \
  --report       fixtures/report.golden.json \
  --proof        fixtures/proof.golden.json \
  --key <publisher-key-hex>
```

Or hand a non-technical user [`offline/verifier.html`](offline/verifier.html):
a single self-contained file with no build step and no network calls. They save
it, open it with their connection off, pick their report and proof, and every
figure it shows is labelled **recomputed here** or **publisher says** — so the
line between what was proven and what was merely asserted is impossible to
miss. If their venue belongs to a group, adding the group report and
membership file checks that the venue is itself committed inside the group's
consolidated total. Rebuild it with `npm run build:offline`; CI fails if the checked-in copy
drifts from the source.

Embed verification in a web page:

```ts
import { leafHashHex, combineNodes, sumBalances } from "canton-solvency-verifier";

// 1. recompute the user's leaf from the proof's disclosed salt + balances
const leafHash = await leafHashHex(proof.leaf.salt, proof.leaf.user_id, proof.leaf.balances);
// 2. fold the sibling path upward with combineNodes(...)
// 3. compare the final hash AND per-asset sums against the published root
```

## 🔌 Integrating as a Producer

1. **Snapshot consistently** — one transaction; record a ledger high-water
   mark that pins the snapshot in your event history.
2. **Compute equity** — per user, per asset; clamp negatives to zero and
   record bad debt; exclude house accounts but disclose count and totals.
3. **Commit** — build leaves in a stable user order (`leaf_salt` +
   `leaf_node`), then `SumTree::build`.
4. **Publish** — root hash, root sums (the liability totals), mark prices,
   disclosures; serve each user their leaf preimage + `tree.prove(i)`.

The full list of producer obligations is normative in [SPEC.md](SPEC.md) §7.

## 🔒 Security Model

**What a passing verification proves:** your balance is committed exactly as
served to you; the commitment aggregates into the published root; the root's
totals equal the sum of every committed leaf.

**What it does not prove by itself:** that *every* real user is in the tree
(detection relies on users checking — which is why verification is one click
on the reference deployment), or that the asset side is honest (custody
attestation is [Milestone 1](#milestone-1--canton-reserve-verification)).
Frequency matters: a daily snapshot
commits to daily states, not intra-day ones.

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).

## 📦 Versioning & Compatibility

The wire format is versioned by the domain strings baked into every hash
(`rocky-solvency-leaf-v1`, `rocky-solvency-node-v1`). **Any change that
breaks the golden vectors in [SPEC.md](SPEC.md) §6 is a new format version**,
shipped under new domain strings — never a silent change. Crates and packages
follow [Semantic Versioning](https://semver.org/).

## 🗺️ Grant Scope & Deliverables

**Already shipped (v0.1.0, running in production):** the liability side — the
Merkle sum tree commitment core in Rust, the browser verifier in TypeScript,
wire format v1 with cross-implementation golden vectors, and a live deployment
publishing daily reports at [Rocky](https://rocky.exchange).

The milestones below complete the picture along two tracks: **Prove** extends
what the format can attest, **Use** makes it operable by institutions and
checkable by everyone else.

| # | Track | Milestone | Outcome |
|---|---|---|---|
| 0 | Foundation | [Report & Proof Documents](#milestone-0--report--proof-documents) | The commitment becomes a signed document others can consume — **done** |
| 1 | Prove | [Canton Reserve Verification](#milestone-1--canton-reserve-verification) | The asset side becomes proven, not asserted — *format and client shipped* |
| 2 | Prove | [On-ledger Anchoring](#milestone-2--on-ledger-anchoring) | Past reports cannot be restated or dropped quietly — *chain and Daml package shipped* |
| 3 | Prove | [Selective Disclosure Profiles](#milestone-3--selective-disclosure-profiles) | One format covers repo, funds, settlement, and eligibility — *hierarchy shipped* |
| 4 | Use | [Disclosure Console](#milestone-4--disclosure-console) | Institutions publish, and counterparties verify, without writing code — *viewer shipped* |
| 5 | Use | [Independent Verification Toolkit](#milestone-5--independent-verification-toolkit) | Anyone can verify without the publisher's software — *CLI shipped* |
| 6 | Use | [Ecosystem Standardization](#milestone-6--ecosystem-standardization) | One implementation becomes a network standard — *conformance suite shipped* |

*Sequencing: 0 is a prerequisite for everything — 1, 2, 3 and 5 all read or
write the report document. 1 and 2 are then independent and run in parallel; 3
builds on 1; 4 needs 3; 5 runs alongside 4; 6 needs both 4 and 5.*

### Milestone 0 — Report & Proof Documents

**Status: complete.** The core crate committed to balances but could not
publish: it returned in-memory values, and SPEC §7 was informative. Every
later milestone reads or writes a report document, so the format came first.

**Delivered**

- `canton-solvency-report` — report envelope and proof document, a
  length-prefixed domain-separated digest ([SPEC.md](SPEC.md) §8.2) rather
  than canonical JSON, so a document can be reformatted without invalidating
  its signature.
- **Ed25519 detached signatures** over the digest, with the trusted key a
  required verifier input — the embedded key is display metadata only.
- **Report binding** — every proof names its report's digest, so a stale proof
  cannot be replayed against a later report.
- **Typed verification outcomes** — a verifier reports *which* check failed,
  including the case that matters most: a truthful root hash published
  alongside understated totals.
- **Golden fixtures** in [`fixtures/`](fixtures) asserted byte for byte by
  both implementations, plus JSON Schemas in [`schemas/`](schemas) validated
  in CI.

### Milestone 1 — Canton Reserve Verification

Pairs the liability commitment with attested custody holdings, so a report
states **coverage** rather than only liabilities.

**Deliverables**

- ~~`canton-reserve-attest`~~ — **delivered**, [`rust/reserve-attest`](rust/reserve-attest). Builds the active-contract request for a declared party set, parses the response into positions, and commits them as a `coverage.custody` report. The socket sits behind a `Transport` the caller supplies, so request construction, response parsing and report building are all unit-tested; only the HTTP call itself needs a node. **Validated against a live mainnet participant** (read-only): the JSON Ledger API v2 shapes are confirmed — `/state/ledger-end` returns a numeric offset, filters are `cumulative` `TemplateFilter` entries, and responses are a bare array of `contractEntry.JsActiveContract` with a singular `createArgument`. A request must name the template by **package name** (`#name:Module:Template`) while responses come back **package-id** qualified; the client rejects the wrong form with an explanation, because the participant's own error does not say which way round it goes. A `CurlTransport` ships as a working implementation — it passes the bearer token on stdin, never in argv, since a command line is readable by every other process on the host. **Run end to end against live Canton mainnet**: four real custody positions read at offset 3020644, committed to a signed `coverage.custody` report.
- **Snapshot binding** — the asset-side read is pinned to the *same* ledger
  offset as the liability snapshot, so both halves are provably as-of one
  instant rather than two reads minutes apart.
- ~~**Coverage report format**~~ — **delivered**, [SPEC.md](SPEC.md) §11. A custody report over `coverage.custody` leaves, plus a statement binding it to a liabilities report by digest so today's assets cannot be shown against last quarter's smaller liabilities. Coverage is checked per asset, and an asset owed but not held at all is a shortfall rather than silence. The `coverage` CLI verb exits 1 on any shortfall. **Still needs a participant node:** reading real holdings over the Ledger API, and pinning that read to the liabilities snapshot's offset, cannot be built or tested without one. *Original scope:* per-asset reserves, liabilities
  and coverage ratio, plus custody party IDs, ledger offset, and mark prices;
  signed by the venue.
- **Multi-asset coverage** — ratios computed per asset; a shortfall in one
  asset is flagged, never netted against a surplus in another.

**Done when:** golden vectors are extended to the coverage report and asserted
by both implementations; an end-to-end run against a Canton localnet turns
seeded holdings plus user balances into a verified coverage report; a
regression test proves a per-asset shortfall cannot be hidden by aggregate
netting.

### Milestone 2 — On-ledger Anchoring

Makes report history tamper-evident: a venue cannot silently restate or drop a
past report.

**Deliverables**

- ~~**Hash-linked history and verification**~~ — **delivered**, [SPEC.md](SPEC.md) §12. Anchors carry digests and offsets only, never balances. A dropped day, a fork, a rewound offset, a restated instant, or an edited past report all break the chain, and the `anchors` CLI verb walks a history from disk. **Package compiles and is tested:** [`daml/`](daml) builds a DAR and passes 8 Daml Script tests covering the `ensure` rules and the disclose-only-widens property. **Deployed to a running participant**: the DAR uploads and `Deploy:initHistory` creates a real three-anchor history over the Ledger API, read back by an auditor and then by a regulator after disclosure widens. Exercised against a local Canton sandbox — the remaining step is uploading to a synchronizer carrying real value, which is a decision rather than a capability. *Original scope:*
- **Daml package `SolvencyReportAnchor`** — one immutable contract per report
  carrying `{format_version, report_root, root_sums_hash, snapshot_time,
  ledger_offset, publisher, prev_anchor}`, with an observer set the venue can
  widen to auditors, counterparties, or a public observer party.
- **Anchoring client** — build → anchor → publish, with the anchor contract ID
  embedded in the published report.
- **Hash-linked history** — each anchor references its predecessor, so a gap,
  a fork, or an edited past report becomes detectable rather than merely
  improbable.
- **Verifier support** — check a report against its anchor and walk the chain
  backwards.

**Done when:** a test suite demonstrates that editing any historical report,
omitting a day, or forking the chain fails verification; and the visibility
model is documented explicitly, including its limit — anchoring gives
tamper-evidence to parties who can see the contract, not public verifiability.

### Milestone 3 — Selective Disclosure Profiles

Generalizes the format from one statement about exchange liabilities into the
family of statements institutions on Canton actually need to make.

**Deliverables**

- ~~**Profile registry**~~ — **delivered**, [SPEC.md](SPEC.md) §14, for the
  two profiles the current leaf supports: `solvency.liabilities` and
  `solvency.group`. An unregistered profile is rejected, a report omitting an
  aggregate its profile requires is rejected as vacuous, and a proof whose
  leaf kind does not match the profile is refused — so a customer proof can no
  longer fail against a group report as an opaque hash mismatch. The four
  profiles below still need a richer leaf. *Original scope:* each profile pins a leaf schema, the
  statement its root asserts, the aggregates that must be published, and a
  default audience matrix. Profiles ship with golden vectors, like the core
  format.
- **Four profiles beyond solvency** — `collateral.repo`, `fund.nav`,
  `settlement.dvp`, `eligibility.holder`, chosen against what is actually
  moving onto Canton: repo, tokenized funds, DvP treasury settlement, and
  permissioned issuance.
- ~~**Disclosure manifest**~~ — **delivered as report v2**,
  [SPEC.md](SPEC.md) §8.5. Per-field published / committed / withheld,
  bound into the signed report under its own digest domain, and diffable
  between reports so a reduction in disclosure is on the record. Consistency
  is *checked*, not asserted: declaring a field published while omitting it,
  or withheld while printing it, is rejected. v1 is untouched and still
  verifies.
- ~~**Hierarchical commitments**~~ — **delivered**, [SPEC.md](SPEC.md) §13.
  Entity roots are the leaves of a group tree, so a subsidiary proves its
  position to its own regulator without exposing siblings while the group root
  still sums to the consolidated total. A customer can verify their own balance
  all the way up to a group's consolidated liabilities. Needed no wire-format
  break: a group tree is an ordinary §4 sum tree whose leaves are entities.
- ~~**Audience-scoped packaging**~~ — **delivered**, [SPEC.md](SPEC.md) §14.4. Every packaging commits to the same leaves, so roots and totals agree while manifests differ; two packagings naming the same audience are refused, and a comparison check catches two audiences being handed genuinely different books.

**Done when:** every profile has golden vectors asserted by both
implementations; a hierarchy test proves a subsidiary's subtree verifies
against the group root with no sibling data present; a manifest-diff test
detects a silently reduced disclosure; and at least one profile beyond
`solvency.liabilities` runs end to end against a Canton localnet.

### Milestone 4 — Disclosure Console

Turns the format into something a compliance team can operate and a
counterparty's analyst can read — the difference between a specification and
adopted infrastructure.

**Deliverables**

- ~~**Disclosure designer and pre-publication diff**~~ — **delivered**,
  [`console/designer.html`](console/designer.html). Per-field states with a
  live per-audience preview, a diff against the previous report, and reduced
  disclosure called out separately from other changes because it can be
  legitimate but never accidental. Export is blocked while any field's
  declared state contradicts the draft, so the screen catches what
  verification would reject.
- ~~**Publishing**~~ — **delivered** as [`canton-solvency-publish`](rust/solvency-report/src/bin/publish.rs). An institution that can export balances as CSV produces a signed report, one proof per customer, and a linked anchor, without writing code. The signing seed is read from a file, never an argument, because a command line is readable by every other process on the host. The full loop runs: publish → verify with the independent tool → walk the history.
- **Still blocked on a node:** connecting a participant from the browser console, reading live data, and scheduling.
- **Viewer console** — provenance state on every figure
  (verified / disclosed / withheld), the data-flow graph of parties,
  synchronizers, and contract types behind each subtotal, plus coverage and
  anchor-history views and a drop-in self-check.
- **Verification stays in the client** — the viewer recomputes proofs in the
  browser; the server is a delivery mechanism, never an authority. A hosted
  instance and a self-hostable build ship together.
- ~~**Evidence pack export**~~ — **delivered**, [SPEC.md](SPEC.md) §15. Every
  document here verifies on its own, which is not the same as a *delivery*
  verifying: hand an auditor a folder with one customer's proof deleted and
  `verify` reports "2 of 2 proofs verified" and exits 0, because nothing in a
  proof says what else was meant to be there. A pack is a signed index of the
  member files and their digests, so the *set* is committed rather than only
  its elements, and `verify-pack` catches the dropped proof, an altered byte,
  or a file slipped in. Both implementations run it, and the contrast above is
  a checked-in test rather than a claim. `canton-solvency-publish` emits
  `pack.json` alongside the report, so this costs a publisher nothing.
- **Non-technical onboarding path** — a documented walkthrough from participant
  node to first published report without writing code, plus a demo instance
  loaded with synthetic repo, fund, and settlement data.

**Done when:** an operator who writes neither Rust nor TypeScript publishes a
conforming report against a localnet from the console alone; a test fails the
build if any rendered figure lacks a provenance state; the viewer completes
verification with its origin server blocked after page load; and the
walkthrough is validated with participants who are not Canton engineers.

### Milestone 5 — Independent Verification Toolkit

Takes the publisher out of the verification path entirely.

**Delivered so far**

- **`canton-solvency-verify` CLI** — [`rust/solvency-cli`](rust/solvency-cli).
  Verifies a single proof or sweeps a directory, prints a report digest, emits
  `--json` for pipelines, and separates exit code `1` (a verification failed)
  from `2` (usage or I/O), so a mistyped path is never mistaken for evidence of
  insolvency. A bare invocation with no arguments is a `2` as well: exit `0`
  means everything verified, and a run that verified nothing must not be able
  to say so — `verify $ARGS && echo solvent` would otherwise print `solvent`
  on the day `$ARGS` expands to empty. A trusted key is mandatory — there is no mode that checks a
  report against the key embedded in itself.
- **JSON Schema** for the report and proof documents, in
  [`schemas/`](schemas), validated against the golden fixtures in CI.
- **`manifest-diff`** — compares two reports' disclosure manifests and exits
  `1` if disclosure was *reduced* (any move away from `published`, or a
  published field dropped), so a CI job can fail when a venue quietly starts
  disclosing less. It takes no key: it verifies no signature, and demanding
  one for an operation that checks nothing would be theatre.
- **Group verbs** — `verify-group` checks entity memberships against a group
  report, and `verify-chain` checks a customer all the way to a group's
  consolidated total ([SPEC.md](SPEC.md) §13). `--group-key` accepts a separate
  group publisher key, since a group and its subsidiaries need not publish
  under one.
- **Standalone offline verifier** — [`offline/verifier.html`](offline/verifier.html),
  one self-contained file with no build step and no network calls. It embeds
  the same modules the test suite exercises rather than reimplementing them,
  and labels every figure **recomputed here** or **publisher says**, so a
  reader can see which values this browser proved and which the publisher
  merely asserted. Optional group inputs verify the full chain
  ([SPEC.md](SPEC.md) §13.4) — and group figures are labelled *disclosed*
  unless the chain actually verified, so a failed chain cannot present
  unchecked totals as proven. Tests fail if the checked-in page drifts from the source or
  gains an external reference.

**Still to come**

- ~~CLI verbs for coverage reports (M1), anchor chains (M2), and disclosure
  manifests (M3)~~ — **delivered**: `coverage`, `anchors`, `manifest-diff`,
  and `verify-pack`. They were deliberately absent until those documents
  existed, because a verifier that silently skips a check is worse than one
  that does not offer it.
- ~~Recomputing a root from a full leaf dump~~ — **delivered**: the `recompute` verb rebuilds the tree from a dump and compares root *and* totals. An inclusion proof cannot show a tree contains only the entries it should; a dump can, at the cost of all privacy, which is why it is an auditor's tool under engagement rather than something a venue publishes.
- ~~Schemas for the coverage and pack documents~~ — **delivered**,
  [`schemas/`](schemas): custody report, coverage statement, anchor, group
  membership, and evidence pack, each validated against the corpus in CI. The
  disclosure manifest is schema'd inside `report-v2`, where it lives; a
  profile is a registry entry rather than a document, so it has no schema to
  publish.
- crates.io release and prebuilt binaries.
- **Reference producer integration** — a documented snapshot → equity → tree →
  publish path with a sample dataset, alongside the live Rocky deployment.

**Done when:** the CLI verifies the [SPEC.md](SPEC.md) §6 golden vectors and a
production-shaped report within a published time budget (**measured, below**);
every example document in the repository is schema-validated in CI; and the
remaining verbs above exist.

**Measured scale.** Apple M4 Pro, release build, single-threaded,
via [`examples/bench_scale.rs`](rust/solvency-report/examples/bench_scale.rs):

| Leaves | Publish (tree + sign + all proofs) | Deepest path | Verify one proof | Verify all |
|---|---|---|---|---|
| 100,000 | 0.60 s | 17 steps | 0.044 ms | 4.4 s |
| 1,000,000 | 7.3 s | 20 steps | 0.053 ms | 53 s |

The CLI sweeps 5,000 proof files off disk, parsing and verifying each, in
about 1.1 s wall. Verification cost per proof grows with the log of the leaf
count, which is why a tenfold larger book costs 20% more per proof rather than
tenfold. Reproduce with
`cargo run --release --example bench_scale -- 1000000`.

Read the third significant figure with suspicion. Re-running the million-leaf
row three times gave 0.048, 0.052 and 0.063 ms per proof — the last on a
machine still warm from the previous run. The table reports single runs, and
run-to-run spread is roughly ±20%. What the numbers are good for is the shape:
per-proof cost grows with the log of the book, and a million-customer report
verifies one customer in well under a millisecond. What they are not good for
is comparing two builds a few percent apart.

A `#[test]` asserts every sampled proof still verifies at 10,000 leaves, with
a `--ignored` variant at 100,000. Neither asserts a wall-clock threshold: a
timing bound in CI is a flake waiting to happen, so the numbers above are
measured deliberately and published rather than enforced.

### Milestone 6 — Ecosystem Standardization

Turns one implementation into something the network can rely on.

**Deliverables**

- ~~**Conformance suite**~~ — **delivered**, [`conformance/`](conformance) and [SPEC.md](SPEC.md) §25.3. 31 cases covering proofs, v2 reports and manifests, leaf-v2 profiles, group memberships, coverage pairings, anchor chains and evidence packs, each with an expected outcome and a declared feature set. All three implementations run it, so it pins the *decisions* the format requires rather than only the bytes it produces.
- **Two independent Canton integrations** — at least one producer other than
  Rocky publishing conforming reports, ideally on a different profile, with
  interop shown in both directions: their reports verify under this toolkit,
  ours verify under theirs. **Needs a counterparty, and everything on our side
  is ready:** [`docs/INTEGRATORS.md`](docs/INTEGRATORS.md) is the build order,
  the declarable feature set, and the acceptance criteria; §14.5 defines a
  **compatibility statement** so two implementations disagree at a *named
  case* rather than in a prose report, with the three rules that stop a
  statement being decorative — claim a feature and you may not skip its cases,
  skip what you do not claim rather than reporting a pass, and bind the whole
  thing to a corpus digest. `verify_from_spec.py --statement` emits one, and all three of our
  implementations publish theirs in [`statements/`](statements) — compared by
  a test that fails at a *named case* when two implementations claiming the
  same feature disagree. That comparison is what was missing when Rust and
  TypeScript diverged on key ordering for months with both suites green; a
  second implementer's statement dropped into that directory is checked by the
  same test, with no special handling. The reverse direction has a path too:
  [`interop/`](interop) is a directory a producer drops their reports into, and
  our CI verifies them under this toolkit on every commit — which turns "send
  us your reports and we'll check" from a promise into a procedure, and means a
  later change to our verifier that broke a third party's documents fails *our*
  build rather than theirs.
- ~~**Public specification v1.1**~~ — **delivered**, [SPEC.md](SPEC.md). §11
  coverage, §12 anchoring, §14 profiles and §15 evidence packs are normative,
  and the document is frozen against the conformance corpus: every normative
  section is exercised by at least one case, and changing one requires a new
  domain string and a new case. No wire bytes moved — every §6 and §10 vector
  still verifies.
- ~~**Specification implementability audit**~~ — **delivered**,
  [`spec-audit/`](spec-audit). Two implementations by one author agree where
  the spec is silent because the same person guessed twice, not because the
  format is pinned. A third verifier written from the specification text alone
  — dependency-free Python, Ed25519 included — reproduces every published
  vector, and found two defects the other two could not: the **TypeScript
  verifier sorted map keys by UTF-16 code units where §2 requires UTF-8
  bytewise order**, so a report naming an asset outside the BMP verified in
  Rust and failed in the browser; and a conformance case was passing for the
  wrong reason, a v1-only verifier "passing" the manifest-lies case by
  rejecting a version it never implemented. Both fixed, the first pinned by a
  case that fails under a UTF-16 sort, and cases now declare `requires` so a
  partial implementation filters by declaration. It runs in CI. It is
  deliberately **not** counted toward the two independent implementations
  below: same author, same repository.
- **Third-party security review** — external review of the commitment core,
  salt derivation, and verifier; findings and remediations published in-repo.
  **Needs a reviewer; the engagement is scoped:**
  [`docs/SECURITY-REVIEW-BRIEF.md`](docs/SECURITY-REVIEW-BRIEF.md) states the
  five claims, ranks where to press hardest (salt derivation, sibling sums as
  a side channel, the v1 join ambiguity we knowingly did not fix, tree-shape
  confusion, verification order, and whether our key-distribution framing is
  overclaimed), and lists the documented non-goals so a reviewer does not
  spend the engagement rediscovering them. A ready-to-send request with
  suggested sizing is drafted in
  [`docs/outreach/`](docs/outreach), alongside one for approaching a second
  implementer — kept in the repository so the ask stays accurate as the
  project changes.
- **CIP proposal** — the wire format submitted to the Canton Improvement
  Proposal process, with the conformance suite as its normative tests.

**Status.** The conformance suite, specification v1.1, the implementability
audit and the CIP draft are delivered. The two remaining deliverables each
need a party outside this project — a second implementer and a security
reviewer — so what is shipped is everything that does not: the corpus, the
statement format, the integrator guide, and the review brief. We are not
counting our own third implementation toward the two: same author, same
repository.

**Done when:** two independent implementations pass the conformance suite; the
security review and its remediations are public; and the CIP is submitted with
review comments answered. *Whether a CIP is accepted is decided by Canton
governance, not by this project — the deliverable is a submitted, maintained
proposal.*

## 🤝 Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup, test requirements, and the golden-vector rule. This
project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md); by
participating you agree to uphold it.

## 👥 Who Is Using

| User | Scenario |
|---|---|
| [Rocky](https://rocky.exchange) | Daily solvency reports + public Transparency page with per-user in-browser verification |

Using this in your project? Open a PR to add yourself.

## 📄 License

[Apache-2.0](LICENSE) © Rocky Exchange contributors.
