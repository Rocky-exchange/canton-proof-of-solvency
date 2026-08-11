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

Later additions took it from three features to eight and from seventeen corpus
cases to forty of forty-five. §9.2, §11, §12, §13 and §14 are all transcribed
from the text.

Two of those five turned up defects; three transcribed cleanly on the first
attempt, which is the more useful number to report. §13's entity leaf, its
membership verification and the §13.4 chain all worked as written. So did
§11's five verification steps — and step 4 there says plainly that both
signatures verify against caller-supplied trusted keys, which the TypeScript
implementation had been omitting. The specification was right and the code was
not, which is the opposite of the §12 finding and worth saying, because an
audit that only ever blames the document is not auditing.

The two that did not:

**SPEC §12's anchor digest formula was missing `publisher_key`.** The
key-distribution change added the field to the anchor, to its digest in both
implementations, and to the schema, and updated §8.4's prose — and left §12's
formula and JSON example alone. Transcribing the formula as written produced a
verifier that rejected every valid chain. My first pass did not catch it,
because I included the field from memory of the Rust source; removing it and
running the text as written failed `anchors-intact` immediately.

**§9.1 did not say where profile validation happens.** The numbered list runs
versions, digest, signature, leaf, fold, and never mentions the profile check
at all, so a transcription put it after the digest and reported
`digest_mismatch` where the reference reports `profile` — the same document,
two different answers, both defensible. §9.1 now places it in step 1 and says
why the order is normative rather than incidental.



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
