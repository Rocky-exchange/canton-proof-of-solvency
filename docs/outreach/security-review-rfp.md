# Draft: request for a security review

For sending to a firm or an independent reviewer. The technical scope lives in
[SECURITY-REVIEW-BRIEF.md](../SECURITY-REVIEW-BRIEF.md); this is the
engagement request that goes with it. Fill in the bracketed parts.

**Sizing.** This is a small, self-contained cryptographic review, not an audit
of a protocol. The commitment core is a few hundred lines of Rust; the whole
verifier surface is under 3,000. A reviewer who has looked at Merkle-tree
proof-of-reserves before should scope in the range of one to two weeks. Say so
up front — an under-scoped ask reads as naïve, and an over-scoped one prices
out the people most likely to find something.

---

**Subject:** Security review — Merkle sum tree proof-of-solvency, ~1–2 weeks, published findings

Hi [name],

We're looking for an external review of a proof-of-solvency wire format and
its reference implementation, and I want to be specific about scope so you can
price it quickly.

**What it is.** Merkle sum tree commitments with selective disclosure, for
institutions on Canton proving statements about their books without publishing
them. Apache-2.0, in production at Rocky. Rust producer and verifier,
TypeScript browser verifier, plus a dependency-free Python verifier written
from the spec alone.

**Scope.** The commitment core, salt derivation, and the verifier — roughly
[SPEC.md](../../SPEC.md) §1–§9. Not the Canton deployment, not the web
frontend, not operational key custody.

[docs/SECURITY-REVIEW-BRIEF.md](../SECURITY-REVIEW-BRIEF.md) states the five
claims the system makes and ranks where we think pressure is best applied,
including things we already believe are weak:

- **Salt derivation and leaf privacy.** `HMAC-SHA256(master_salt, user_id)`,
  one master salt per snapshot, each customer sees their own salt. Balances
  are low-entropy and guessable; the salt is what stands between a disclosed
  sibling sum and a confirmed balance.
- **Sibling sums as a side channel.** A proof discloses each sibling's
  per-asset totals. In a sparse tree or an unusual asset that may identify a
  counterparty's position. We do not currently bound how many colluding
  proof-holders can reconstruct the book, and we would like a real answer.
- **A known, unfixed preimage ambiguity.** v1 leaves and node sums use a
  `:`/`|` delimiter join over asset names that are attacker-influenced in the
  general case. v2 is length-prefixed; v1 is not, because fixing it would move
  every published test vector. We document the trade and would like an
  independent judgement on whether it is defensible and what an attacker can
  actually construct.
- Tree-shape confusion under odd-node promotion, verification ordering, and
  whether our framing of what on-ledger key distribution achieves is
  overclaimed.

The brief also lists explicit non-goals — completeness of liabilities,
proof of exclusive asset control — so you don't spend the engagement
rediscovering documented positions.

**Everything is runnable in minutes.** Four test suites, one with no
dependencies at all (`python3 spec-audit/verify_from_spec.py`), and a 21-case
conformance corpus with declared expectations.

**Publication.** Findings and remediations go in the repository, including
anything we choose not to fix and why. A review that finds nothing is
published as such. We are not looking for a certificate — the changelog
already carries a bug in our own browser verifier under its own heading, and
we would rather have an accurate record than a flattering one.

**Practicalities.** [Budget range / timing]. Happy to send the brief and a
repository link ahead of any call.

[signature]

---

## Reviewer profile worth prioritising

- Has looked at exchange proof-of-reserves before — the failure modes here are
  the interesting variants of familiar ones.
- Comfortable reading Rust, but the review is about the *format*; the spec is
  the artefact under review, and a reviewer who works from it and finds it
  wanting is telling us something valuable.
- Willing to publish. A review we cannot show a counterparty does a fraction
  of the work we need it to do.
