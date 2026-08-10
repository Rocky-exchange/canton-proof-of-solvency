#!/usr/bin/env python3
"""Tests for the §14.5 compatibility statement, run by verify_from_spec.py.

Kept in the audit rather than in a framework: an implementer evaluating this
format should be able to run every check here with a stock Python and no
install step, which is the whole premise of this directory.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_from_spec import (  # noqa: E402
    SUPPORTED,
    build_statement,
    corpus_digest,
    statement_defects,
)

CASES = [
    {"id": "a", "expect": "accept", "requires": ["report-v1"]},
    {"id": "b", "expect": "reject", "requires": ["group-v1"]},
]


def test_corpus_digest_covers_case_count():
    one = corpus_digest(CASES)
    assert corpus_digest(CASES[:1]) != one, "digest must depend on the case set"


def test_corpus_digest_covers_requires():
    altered = [dict(CASES[0], requires=["report-v2"]), CASES[1]]
    assert corpus_digest(altered) != corpus_digest(CASES)


def test_corpus_digest_is_order_sensitive():
    assert corpus_digest(list(reversed(CASES))) != corpus_digest(CASES)


def test_a_claimed_feature_may_not_be_skipped():
    """The failure this exists to catch: claim support, then skip the cases."""
    statement = {
        "supports": ["report-v1"],
        "results": [{"id": "a", "expected": "accept", "outcome": "skip"}],
    }
    defects = statement_defects(statement, CASES[:1])
    assert any("claims report-v1" in d for d in defects), defects


def test_an_unclaimed_feature_may_not_be_passed():
    """A rejection because a version is unimplemented is not a test result."""
    statement = {
        "supports": ["report-v1"],
        "results": [{"id": "b", "expected": "reject", "outcome": "reject"}],
    }
    defects = statement_defects(statement, CASES[1:])
    assert any("does not claim" in d for d in defects), defects


def test_every_case_must_appear():
    statement = {"supports": ["report-v1"], "results": []}
    defects = statement_defects(statement, CASES)
    assert len(defects) == 2, defects


def test_a_real_statement_is_defect_free():
    statement = build_statement()
    assert statement["format_version"] == "canton-solvency-compat-v1"
    assert set(statement["supports"]) == SUPPORTED
    import json

    corpus = json.loads(
        (Path(__file__).resolve().parent.parent / "conformance/manifest.json").read_text()
    )
    assert statement_defects(statement, corpus["cases"]) == []
    assert statement["corpus_digest"] == corpus_digest(corpus["cases"])


def main() -> int:
    failures = []
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_"):
            continue
        try:
            fn()
            print(f"  ok   {name}")
        except AssertionError as e:
            failures.append(f"{name}: {e}")
    for f in failures:
        print(f"  FAIL {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
