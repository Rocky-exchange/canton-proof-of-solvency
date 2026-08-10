# Spec audit — is SPEC.md implementable from its text?

```
python3 spec-audit/verify_from_spec.py --verbose
```

No install step, no dependencies, Python 3.8+.

## Why this exists

This repository ships two implementations, Rust and TypeScript, and they agree
on every golden vector. That is weaker evidence than it appears. Both were
written by the same author, so wherever SPEC.md is silent they agree because
the same person guessed the same way twice — not because the format is pinned.

[`verify_from_spec.py`](verify_from_spec.py) is a third verifier written from
the specification text alone, without consulting either implementation. Where
the text ran out, the guess was recorded rather than resolved by reading the
code. It implements §1–§6, §8, §9.1 and §15, including Ed25519 (RFC 8032) from
the standard library, so an implementer evaluating this format can read a
complete verifier in one sitting with nothing to install.

It is **not** the second independent implementation Milestone 6 requires: same
author, same repository. What it establishes is narrower and still worth
having — that someone holding the specification and nothing else arrives at
the same bytes.

## What it found

Every §6 and §10 vector reproduced from the text. Six places did not, and all
six are now closed in SPEC.md. Two were real:

**The TypeScript verifier sorted keys wrongly.** §2 requires assets ordered
bytewise over UTF-8. JavaScript's default `Array.sort()` compares UTF-16 code
units, and the two disagree for any codepoint above U+FFFF — a surrogate
(`0xD800`) sorts before U+E000..U+FFFF, while the same character's UTF-8
encoding (`0xF0…`) sorts after. So the browser verifier computed a different
canonical string, a different leaf hash, and would have rejected a report its
producer signed honestly, for any venue listing an asset named outside the
BMP. Every name in the golden vectors is ASCII, where the orders agree, which
is exactly why two implementations sharing an author agreed for months. Fixed,
and pinned by the `proof-astral-assets` conformance case, which fails under a
UTF-16 sort.

**A conformance case was passing for the wrong reason.** This verifier
implements report v1 only, so it rejected the v2 cases — and thereby "passed"
`report-v2-manifest-lies`, a case written to check that a lying manifest is
caught, without ever looking at a manifest. Every case now declares
`requires`, both reference runners assert it is present and non-empty, and a
partial implementation skips by declaration instead of by accident.

The other four were ambiguities that both implementations happened to resolve
the same way: whether an explicit zero is serialized (§2), whether
`lp(root_hash)` covers the hex string or the raw bytes (§8.2), where the
fold's running sums come from (§5), and the byte convention that makes pack
members reproducible (§15.1).

## Reading it as an implementer

The file is ordered as the spec is — amounts, canonical serialization, leaf,
node, tree, digest primitives, report digest, verification, packs — so it can
be read beside SPEC.md section by section. `FINDINGS` at the top lists every
place the text needed sharpening, with what the ambiguity would have cost.
