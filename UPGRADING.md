# Upgrading

## 0.1.0 → 0.1.1

**If you publish reports, read the first item. It is a privacy fix and it
changes your root hashes.**

### Leaf ordering (affects publishers)

0.1.0's publisher ordered leaves by ascending `user_id`. A proof discloses its
sibling's sums, and at leaf level the sibling is one other customer — so
whoever is paired with a customer learns that customer's exact balances.
Identifier ordering makes the pairing predictable, and an attacker who can
influence their own identifier can therefore choose their victim: two accounts,
one to fix the parity of the target's index and one to occupy the pair
position, and the second account's own proof carries the target's balances.

0.1.1 orders by the derived salt, `HMAC(master_salt, user_id)`, which is
equally stable for the producer and unpredictable to everyone else. See
[`docs/SECURITY-ANALYSIS.md`](docs/SECURITY-ANALYSIS.md) for what this does and
does not fix — it removes the aiming, not the disclosure.

**Are you affected?** If your producer sorts leaves by customer identifier, or
by anything a customer can influence or predict, yes. If you order by a keyed
function of a per-snapshot secret already, no.

**What changes.** The root hash for a given set of balances. A report
regenerated from the same input will not match one published under 0.1.0, so do
not treat root hashes as reproducible across this change.

**What does not change, and this is the part worth being sure of:**

- **Your anchor chain survives.** Anchors link anchor-to-anchor by digest (§12);
  nothing links one report's root to the next. A snapshot whose root shares
  nothing with its predecessor's chains exactly as before. There is a test for
  this — `verify_chain` accepts a successor whose root is unrelated.
- **Published reports stay valid.** A report and its proofs are self-contained
  and signed. Nothing about a new ordering invalidates an old publication or
  the proofs you have already issued against it.
- **No format version moved.** §4 always left ordering to the producer, so this
  is a producer obligation (§7), not a wire change. Every §6 golden vector still
  verifies.

**Migrating.** Publish your next snapshot with 0.1.1 and anchor it as usual.
There is no backfill: reissuing historical reports under the new ordering would
change roots that are already anchored, which is precisely what a tamper-evident
history is meant to prevent.

### Other fixes in 0.1.1 (affects verifiers and operators)

- **`canton-solvency-verify` with no arguments now exits 2, not 0.** Exit 0 means
  everything verified, and a run with no arguments verified nothing. Check any
  pipeline written as `canton-solvency-verify $ARGS && …` — under 0.1.0 that
  reported success on the day `$ARGS` expanded to empty.
- **Proof filenames are now collision-free.** 0.1.0 replaced every
  non-alphanumeric character with `_`, so `alice-1`, `alice_1` and `alice 1`
  wrote to one file and two proofs were lost. Identifiers needing no sanitising
  keep their readable name; the rest gain a digest suffix. If you index proofs
  by filename, expect new names for those customers.
- **The browser verifier reports malformed input instead of throwing**, and no
  longer accepts amounts above the `u128` range the producer can represent. A
  report carrying such an amount used to verify in the browser and fail on the
  command line.

### Checking your own deployment

```bash
scripts/check.sh          # what CI runs
canton-solvency-verify verify-pack --pack-dir <dir> --key <hex64>
```

If a published report of yours fails under 0.1.1 for any reason other than the
ordering change, please open an issue — that is a compatibility break we did
not intend.
