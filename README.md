# Canton Proof-of-Solvency

Open-source proof-of-solvency framework for exchanges and custodial
applications on the [Canton Network](https://www.canton.network/). It lets a
venue publish a daily cryptographic commitment proving **custody assets ≥ user
liabilities**, and lets every user verify — entirely in their own browser —
that their balance is included in the published total, without trusting the
venue.

Canton's privacy model means there is no public ledger where anyone can
recompute an exchange's books. This framework is the missing public-trust
layer: private data stays on the participant; the public sees commitments and
proofs.

## What's in this repository

| Component | Path | Description |
|---|---|---|
| **`canton-solvency-merkle`** (Rust) | `rust/solvency-merkle` | The commitment core: 18-dp fixed-point amount codec, HMAC-derived per-user salts, domain-separated SHA-256 leaf/node hashing, Merkle **sum** tree with checked aggregation, inclusion proofs that verify both hash and totals. |
| **`canton-solvency-verifier`** (TypeScript) | `ts/verifier` | Browser-side verifier (WebCrypto + BigInt): recompute a leaf from its disclosed preimage, fold the sibling path, compare root **and** published totals. |
| **Wire format spec** | `SPEC.md` | Byte-level format v1 with golden test vectors — both implementations assert the same vectors, so they cannot silently diverge. |
| **Example** | `rust/solvency-merkle/examples/csv_report.rs` | CSV of balances → root, per-asset totals, and a verified proof. |

## Why a Merkle *sum* tree

Every internal node commits to the per-asset totals of its subtree, and the
root's totals are the published liabilities. A user who verifies their
inclusion path therefore also re-derives part of the aggregation: equal roots
imply equal totals. An exchange cannot omit a user, shrink a balance, or
publish totals that don't add up without breaking someone's proof.

Negative equity never enters the tree (it would let the producer cancel other
users' balances). Producers clamp negative accounts to zero and disclose the
shortfall as bad debt alongside insurance-fund balances.

## Reference deployment

This framework runs in production at [Rocky](https://rocky.exchange), a
derivatives and spot exchange built natively on Canton:

- Daily snapshot: consistent ledger read pinned to an event high-water mark;
  unrealized PnL folded at published mark prices; house accounts excluded and
  disclosed; in-flight withdrawals counted as liabilities.
- Public report + in-browser verification: the **Transparency** page on the
  exchange, backed by `GET /v1/solvency/latest` and
  `GET /v1/solvency/proof/me`.
- Full methodology: see Rocky's public docs ("Proof of Solvency" page).

## Quick start

Rust:

```bash
cd rust/solvency-merkle
cargo test                      # includes the SPEC.md golden vectors
cargo run --example csv_report -- balances.csv my-master-salt
```

TypeScript:

```bash
cd ts/verifier
npm install
npm test                        # asserts the same golden vectors
```

Embedding the verifier in a web app is two calls:

```ts
import { leafHashHex, combineNodes } from "canton-solvency-verifier";
// 1. recompute the leaf from the proof's disclosed salt + balances
// 2. fold proof.path with combineNodes, compare hash + sums with the root
```

## Integrating as a producer

1. Snapshot your ledger consistently (one transaction; record a high-water
   mark).
2. Compute per-user, per-asset equity; clamp negatives to zero and record bad
   debt; exclude house accounts but disclose their count.
3. Build leaves in a stable user order with `leaf_salt` + `leaf_node`, then
   `SumTree::build`.
4. Publish: root hash, root sums (the liability totals), mark prices,
   disclosures — and serve each user their leaf preimage + `tree.prove(i)`.

`SPEC.md` §7 lists the full set of producer obligations.

## Roadmap

- Custody-side attestation: pairing the liability commitment with Canton
  party holdings (asset side) in one report.
- Anchoring report roots to the Canton ledger for tamper-evident history.
- A standalone auditor CLI for batch verification of many user proofs.

## License

Apache-2.0. See [LICENSE](LICENSE).
