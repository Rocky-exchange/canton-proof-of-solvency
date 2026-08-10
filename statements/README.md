# Compatibility statements (SPEC §14.5)

One per implementation, each saying which features it claims and how it fared
on every case in [`../conformance`](../conformance).

| File | Implementation | Claims |
|---|---|---|
| `rust.json` | `canton-solvency-report` (Rust) | all 10 features |
| `typescript.json` | `ts/verifier` (TypeScript) | all 10 features |
| `spec-audit.json` | [`spec-audit/`](../spec-audit) (Python, from SPEC.md alone) | `report-v1`, `proof-v1`, `pack-v1` |

## Why they are checked in

Running the corpus in three places proves nothing on its own if nothing
compares the results. Rust and TypeScript disagreed about key ordering for
months — §2 requires bytewise UTF-8, and JavaScript's default sort is UTF-16
code units — and both test suites passed the whole time, because each only
ever checked itself.

[`rust/solvency-report/tests/statements.rs`](../rust/solvency-report/tests/statements.rs)
compares them: wherever two implementations both claim a feature, they must
agree on every case needing it. Injecting that ordering bug into a statement
now produces

```
rust and typescript disagree on proof-astral-assets: accept vs reject.
One of them is wrong, or the specification does not determine the answer.
```

which is the sentence that was missing. A `skip` is a declaration of scope
rather than a result, so it is never compared against — that is what keeps the
Python statement, which claims three features, honest company for the two that
claim ten.

`corpus_digest` binds each statement to the exact corpus it ran against, so a
stale statement fails rather than quietly reporting on a corpus that no longer
exists.

## Regenerating

```
cargo run --manifest-path rust/solvency-report/Cargo.toml \
  --example emit_statement -- statements/rust.json
cd ts/verifier && npm run emit:statement
python3 -c "import sys,json;sys.path.insert(0,'spec-audit');\
from verify_from_spec import build_statement;\
open('statements/spec-audit.json','w').write(json.dumps(build_statement(),indent=2)+'\n')"
```

## Submitting your own

See [`docs/INTEGRATORS.md`](../docs/INTEGRATORS.md). A second implementer's
statement dropped into this directory is checked by the same test, against the
same rules, with no special handling.
