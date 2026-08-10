# Draft: approaching a second implementer

For sending to another venue, custodian, or infrastructure team on Canton.
Edit the bracketed parts and send. Keeping it in the repository means the ask
stays accurate as the project changes — a stale pitch is worse than none.

**Who to approach, in rough order of likely fit:**

1. Anyone already publishing proof-of-reserves who would rather not build the
   privacy story from scratch — they have the motivation and the data.
2. A custodian or tokenised-fund issuer on Canton. `fund.nav` and
   `settlement.dvp` profiles exist and have never been exercised by anyone but
   us, which makes them the most valuable thing a second implementer could
   pick up.
3. A Canton infrastructure or tooling team. They may not publish reports at
   all — a verifier alone is a complete, useful contribution.

---

**Subject:** Would you run our conformance suite? (Canton proof-of-solvency, ~a day's work)

Hi [name],

We've built a wire format for proof-of-solvency on Canton — Merkle sum tree
commitments with selective disclosure, so an institution can prove a statement
about its book without publishing the book. It's Apache-2.0 and running in
production at Rocky.

I'm writing because the specification has a weakness that no amount of work on
our side can fix: **everything in it was written by one author.** We have two
implementations, Rust and TypeScript, and they agree on every test vector.
That's weaker evidence than it looks — where the spec is silent, they agree
because the same person guessed the same way twice.

We recently wrote a third verifier from the specification text alone, in
dependency-free Python, to test that theory. It found a real bug: our
TypeScript verifier sorted map keys by UTF-16 code units where the spec
requires UTF-8 bytewise order. The two disagree for any character above
U+FFFF, so **a report naming a non-ASCII asset verified in Rust and failed in
the browser** — and both test suites had been green for months. Every asset
name in our vectors was ASCII, where the orders agree.

That is the argument for asking you rather than writing a fourth
implementation ourselves.

**What we're asking for.** Implement a verifier against
[SPEC.md](../../SPEC.md) — not a port of ours, since a port inherits our
assumptions — and publish a compatibility statement saying which features you
support and how you fared on our 21 conformance cases. A minimal useful
verifier is one file: our Python one covers `report-v1`, `proof-v1` and
`pack-v1`, standard library only, Ed25519 included, and is short enough to
read in a sitting.

[docs/INTEGRATORS.md](../INTEGRATORS.md) is the build order — what to write
first, which published vectors fall out at each step, and the acceptance
criteria. Realistically a day or two for someone comfortable with SHA-256 and
Ed25519.

**What you get.** A verifier for a format your counterparties may start
publishing in, built by your own team so you actually trust it. Your name on
the specification as a co-implementer. And if you're publishing reserves
already, a privacy-preserving path off the "publish a wallet address"
approach.

**What we commit to.** If your implementation disagrees with ours, we treat it
as a specification defect until shown otherwise, and we fix the specification.
Six such fixes are already recorded in
[spec-audit/README.md](../../spec-audit/README.md), including the bug above,
which was in our code and not the other implementer's.

If it's useful I'm happy to walk through the format on a call first, or just
send the three files you'd need to get started.

[signature]

---

## If they say yes

Point them at [`docs/INTEGRATORS.md`](../INTEGRATORS.md), and remind them of
the two directions:

- their statement in [`statements/`](../../statements) — their implementation
  over our corpus;
- their documents in [`interop/`](../../interop) — our toolkit over their
  reports, re-verified on every commit from then on.

Both are pull requests against this repository, checked by the same tests as
ours with no special handling.
