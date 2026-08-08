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
attestation is the next roadmap item). Frequency matters: a daily snapshot
commits to daily states, not intra-day ones.

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).

## 📦 Versioning & Compatibility

The wire format is versioned by the domain strings baked into every hash
(`rocky-solvency-leaf-v1`, `rocky-solvency-node-v1`). **Any change that
breaks the golden vectors in [SPEC.md](SPEC.md) §6 is a new format version**,
shipped under new domain strings — never a silent change. Crates and packages
follow [Semantic Versioning](https://semver.org/).

## 🗺️ Roadmap

- [ ] Custody-side attestation: pair liability commitments with Canton party
      holdings in a single coverage report
- [ ] On-ledger anchoring of report roots (tamper-evident history)
- [ ] Standalone auditor CLI for batch proof verification
- [ ] Wire-format CIP once two independent deployments exist

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
