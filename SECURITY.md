# Security Policy

This project is security-critical infrastructure: venues use it to make
public solvency claims, and users rely on its proofs instead of trust. We
take every report seriously.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub
issues, discussions, or pull requests.**

Report privately via either channel:

- **GitHub private vulnerability reporting** (preferred): *Security* →
  *Report a vulnerability* on this repository.
- **Email:** lewis.q.zhang@gmail.com

Include: affected component (Rust crate / TS verifier / spec), a minimal
reproduction or proof-of-concept, and the impact as you understand it.

You will receive an acknowledgement within **48 hours** and a triage verdict
within **7 days**. We ask for up to **90 days** of coordinated disclosure;
we credit reporters in the release notes unless you prefer otherwise.

## Scope

In scope (examples):

- Forged or ambiguous proofs: any way to make `verify_proof` accept a leaf
  that was not committed, or accept altered balances/totals.
- Sum-tree soundness: duplicate counting, negative-value smuggling,
  aggregation mismatches between root sums and leaf contents.
- Wire-format ambiguity: two different balance sets serializing to the same
  canonical bytes, domain-separation bypasses, hash-input collisions.
- Arithmetic: overflow, precision loss, or parsing inconsistencies between
  the Rust and TypeScript implementations.
- Salt/privacy: recovering another user's balances or identity from public
  reports and proofs.

Out of scope: vulnerabilities in a specific venue's deployment (report those
to the venue), denial-of-service against public report endpoints, and issues
in dependencies without a demonstrated impact on this code.

## Supported Versions

| Version | Supported |
|---|---|
| latest release (main) | ✅ |
| wire format v1 verification | ✅ (kept working across format bumps) |
| older code releases | ❌ — please upgrade |
