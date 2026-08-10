#!/usr/bin/env python3
"""A third verifier, written from SPEC.md alone, to test whether the spec is
implementable from its text (SPEC §14.3, Milestone 6).

Two implementations that share an author share his assumptions. Where SPEC.md
is silent, Rust and TypeScript agree anyway -- not because the format is
pinned, but because the same person guessed the same way twice. This file
exists to find those places: it was written from the specification text
without consulting either implementation, and every point where the text ran
out is recorded in FINDINGS below rather than resolved by reading the code.

It is *not* a second independent implementation in the sense Milestone 6
requires. Same author, same repository. What it can honestly establish is
narrower and still worth having: that an implementer with the specification
and nothing else can arrive at the same bytes.

Only the standard library is used, Ed25519 included (RFC 8032). An implementer
evaluating this format should be able to run this on any Python 3.8+ with no
install step, and read the whole verifier in one sitting.

Usage:
    python3 spec-audit/verify_from_spec.py            # golden vectors + corpus
    python3 spec-audit/verify_from_spec.py --verbose
    python3 spec-audit/verify_from_spec.py --statement   # §14.5 compat statement
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# FINDINGS — every point where SPEC.md did not determine the answer.
#
# Each was resolved by picking the reading the text most supports, then
# checked against the golden vectors. A guess that survives the vectors is
# still a guess: the vectors do not exercise it, which is exactly why the
# spec should say so. These are reported at the end of a run.
# --------------------------------------------------------------------------
FINDINGS: list[tuple[str, str]] = [
    (
        "FIXED — SPEC §2: assets sort bytewise over UTF-8, and JS does not",
        "The specification said 'bytewise (ASCII) order', which reads as a "
        "non-issue until an asset name is not ASCII. JavaScript's default "
        "Array.sort() compares UTF-16 code units: for a codepoint above "
        "U+FFFF the surrogate 0xD800 sorts before U+E000..U+FFFF, while the "
        "same character's UTF-8 encoding 0xF0.. sorts after. The TypeScript "
        "verifier used the default sort, so it computed a different canonical "
        "string -- a different leaf hash -- for an asset named outside the "
        "BMP, and would have rejected a report its producer signed honestly. "
        "Every §6 vector is ASCII, where both orders agree, which is why two "
        "implementations sharing an author agreed for months. Fixed in "
        "verify.ts and report.ts, stated in §2, and pinned by the "
        "proof-astral-assets conformance case, which fails under a UTF-16 "
        "sort.",
    ),
    (
        "FIXED — §14.3: cases now declare what they require",
        "A verifier implementing only report v1 does not merely fail the v2 "
        "cases. It *passes* report-v2-manifest-lies, by rejecting a format "
        "version it never implemented -- so a case written to test manifest "
        "consistency tested nothing at all. This file hit exactly that. Every "
        "case now carries `requires`, both reference runners assert it is "
        "present and non-empty, and this verifier skips by declaration.",
    ),
    (
        "FIXED — SPEC §2: an explicit zero is serialized, not dropped",
        "§9.1's 'absent and zero are the same claim' is about comparison; §2 "
        "said nothing about serialization, so two producers could commit "
        "different leaf hashes for the same balances. The golden vectors do "
        "not settle it -- u3's balances are empty rather than zero-valued. §2 "
        "now says zeros are serialized, and that the two rules are "
        "independent.",
    ),
    (
        "FIXED — SPEC §8.2: lp(root_hash) is over the hex string",
        "Both readings parse: lp() over the 64-character hex text, or over the "
        "32 raw bytes. They give different digests. The §10 vector "
        "distinguishes them, but only after implementing it one way and "
        "finding out. §8.2 now says which.",
    ),
    (
        "FIXED — SPEC §5: the fold's sums start from the preimage",
        "§5 said to recompute the leaf hash from the preimage, then fold. It "
        "did not say the running *sums* also start there rather than from a "
        "published figure. They must, or step 5 checks a total against "
        "itself. §5 now says so.",
    ),
    (
        "FIXED — SPEC §15.1: member bytes need a stated convention",
        "'Bytes as delivered' is correct and makes a pack reproducible only "
        "within one byte convention. A producer omitting the trailing newline "
        "emits an equally valid pack matching no checked-in fixture. §15.1 now "
        "states the reference convention.",
    ),
]

# --------------------------------------------------------------------------
# Ed25519 verification, RFC 8032. Stdlib only.
# --------------------------------------------------------------------------
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _add(p_: tuple, q_: tuple) -> tuple:
    a = (p_[1] - p_[0]) * (q_[1] - q_[0]) % _P
    b = (p_[1] + p_[0]) * (q_[1] + q_[0]) % _P
    c = 2 * p_[3] * q_[3] * _D % _P
    dd = 2 * p_[2] * q_[2] % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p_: tuple) -> tuple:
    out = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            out = _add(out, p_)
        p_ = _add(p_, p_)
        s >>= 1
    return out


def _equal(p_: tuple, q_: tuple) -> bool:
    return (p_[0] * q_[2] - q_[0] * p_[2]) % _P == 0 and (
        p_[1] * q_[2] - q_[1] * p_[2]
    ) % _P == 0


def _decompress(s: bytes) -> tuple | None:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    if a is None:
        return False
    r = _decompress(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _L
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


# --------------------------------------------------------------------------
# §1 Amounts
# --------------------------------------------------------------------------
SCALE = 10**18


def parse_amount(text: str) -> int:
    """§1: int_part [ '.' frac_part ], ASCII digits, frac ≤ 18, no sign."""
    if not isinstance(text, str) or not text:
        raise ValueError("amount must be a non-empty string")
    if text.startswith(("+", "-")):
        raise ValueError(f"amount {text!r} is signed")
    int_part, dot, frac_part = text.partition(".")
    if not int_part.isdigit():
        raise ValueError(f"amount {text!r} has no integer part")
    if dot and (not frac_part.isdigit() or len(frac_part) > 18):
        raise ValueError(f"amount {text!r} has a bad fraction")
    return int(int_part) * SCALE + int(frac_part.ljust(18, "0") or 0)


def render_amount(value: int) -> str:
    """§1: always exactly 18 fraction digits."""
    return f"{value // SCALE}.{value % SCALE:018d}"


def parse_map(raw: dict) -> dict[str, int]:
    return {asset: parse_amount(text) for asset, text in (raw or {}).items()}


# --------------------------------------------------------------------------
# §2 Canonical balance serialization
# --------------------------------------------------------------------------
def canonical(balances: dict[str, int]) -> str:
    """§2: asset:amount|asset:amount, assets in bytewise order, empty → ''."""
    items = sorted(balances.items(), key=lambda kv: kv[0].encode())
    return "|".join(f"{asset}:{render_amount(value)}" for asset, value in items)


# --------------------------------------------------------------------------
# §3 Leaf, §4 node
# --------------------------------------------------------------------------
LEAF_DOMAIN = b"rocky-solvency-leaf-v1"
NODE_DOMAIN = b"rocky-solvency-node-v1"


def derive_salt(master_salt: bytes, user_id: str) -> bytes:
    """§3: HMAC-SHA256(master_salt, utf8(user_id))."""
    return hmac.new(master_salt, user_id.encode(), hashlib.sha256).digest()


def leaf_hash(salt: bytes, user_id: str, balances: dict[str, int]) -> bytes:
    return hashlib.sha256(
        LEAF_DOMAIN
        + salt
        + hashlib.sha256(user_id.encode()).digest()
        + canonical(balances).encode()
    ).digest()


def add_sums(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    """§4: per-asset sum. Python integers do not overflow, so the checked
    addition §4 requires is a non-issue here rather than an omission."""
    out = dict(left)
    for asset, value in right.items():
        out[asset] = out.get(asset, 0) + value
    return out


def node_hash(left: bytes, right: bytes, sums: dict[str, int]) -> bytes:
    return hashlib.sha256(NODE_DOMAIN + left + right + canonical(sums).encode()).digest()


def build_root(leaves: list[tuple[bytes, dict[str, int]]]):
    """§4: pair left to right; an odd node is promoted unchanged."""
    level = list(leaves)
    if not level:
        raise ValueError("§4 does not define a tree over zero leaves")
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 == len(level):
                nxt.append(level[i])  # promoted, never duplicated
                continue
            (lh, ls), (rh, rs) = level[i], level[i + 1]
            sums = add_sums(ls, rs)
            nxt.append((node_hash(lh, rh, sums), sums))
        level = nxt
    return level[0]


# --------------------------------------------------------------------------
# §8.1 Digest primitives
# --------------------------------------------------------------------------
def u64le(n: int) -> bytes:
    return n.to_bytes(8, "little")


def lp(s: str) -> bytes:
    raw = s.encode()
    return u64le(len(raw)) + raw


def lpmap(m: dict[str, int]) -> bytes:
    items = sorted(m.items(), key=lambda kv: kv[0].encode())
    out = u64le(len(items))
    for asset, value in items:
        out += lp(asset) + lp(render_amount(value))
    return out


REPORT_DOMAIN = b"rocky-solvency-report-v1"


def report_digest(report: dict) -> bytes:
    """§8.2. Note lp(root_hash) is over the hex *string* — see FINDINGS."""
    disclosures = report.get("disclosures") or {}
    return hashlib.sha256(
        REPORT_DOMAIN
        + lp(report["format_version"])
        + lp(report["profile"])
        + lp(report["publisher"])
        + lp(report["snapshot_time"])
        + lp(report["ledger_offset"])
        + lp(report["root_hash"])
        + u64le(report["leaf_count"])
        + lpmap(parse_map(report["root_sums"]))
        + lpmap(parse_map(report.get("mark_prices")))
        + lpmap(parse_map(disclosures.get("bad_debt")))
        + u64le(disclosures.get("excluded_house_accounts", 0))
        + lpmap(parse_map(disclosures.get("excluded_house_totals")))
    ).digest()


# --------------------------------------------------------------------------
# §9.1 Verification
# --------------------------------------------------------------------------
class Rejected(Exception):
    pass


def sums_equal(left: dict[str, int], right: dict[str, int]) -> bool:
    """§9.1: absent and zero are the same claim."""
    for asset in set(left) | set(right):
        if left.get(asset, 0) != right.get(asset, 0):
            return False
    return True


def verify_proof(signed: dict, proof: dict, trusted_key_hex: str) -> None:
    """The five steps of §9.1, failing on the first that does not hold."""
    report = signed["report"]
    signature = signed["signature"]

    # 1. recognised versions
    if report["format_version"] != "canton-solvency-report-v1":
        raise Rejected(f"report format {report['format_version']}")
    if proof["format_version"] != "canton-solvency-proof-v1":
        raise Rejected(f"proof format {proof['format_version']}")
    if signature["algorithm"] != "ed25519":
        raise Rejected(f"algorithm {signature['algorithm']}")

    # 2. the digest binds the proof to this report
    digest = report_digest(report)
    if digest.hex() != proof["report_digest"]:
        raise Rejected("digest mismatch")

    # 3. trusted key, then signature. §8.4: the embedded key is display
    #    metadata, so it is compared rather than used.
    if signature["public_key"].lower() != trusted_key_hex.lower():
        raise Rejected("unknown signer")
    if not ed25519_verify(
        bytes.fromhex(trusted_key_hex), digest, bytes.fromhex(signature["value"])
    ):
        raise Rejected("bad signature")

    # 4. recompute the leaf from the disclosed preimage
    leaf = proof["leaf"]
    balances = parse_map(leaf["balances"])
    node = (
        leaf_hash(bytes.fromhex(leaf["salt"]), leaf["user_id"], balances),
        balances,
    )

    # 5. fold, then compare hash *and* sums
    for step in proof["steps"]:
        sibling = (bytes.fromhex(step["sibling_hash"]), parse_map(step["sibling_sums"]))
        left, right = (sibling, node) if step["sibling_on_left"] else (node, sibling)
        sums = add_sums(left[1], right[1])
        node = (node_hash(left[0], right[0], sums), sums)

    if node[0].hex() != report["root_hash"]:
        raise Rejected("root hash mismatch")
    if not sums_equal(node[1], parse_map(report["root_sums"])):
        raise Rejected("root sums mismatch")


# --------------------------------------------------------------------------
# §15 Evidence packs
# --------------------------------------------------------------------------
PACK_DOMAIN = b"rocky-solvency-pack-v1"


def pack_digest(pack: dict) -> bytes:
    """§15.2."""
    out = (
        PACK_DOMAIN
        + lp(pack["format_version"])
        + lp(pack["publisher"])
        + lp(pack["snapshot_time"])
        + lp(pack["report_digest"])
        + u64le(len(pack["entries"]))
    )
    for entry in pack["entries"]:
        out += lp(entry["name"]) + lp(entry["sha256"])
    return hashlib.sha256(out).digest()


def verify_pack(signed: dict, trusted_key_hex: str, members: dict[str, bytes]) -> None:
    """The five steps of §15.3, in order."""
    pack = signed["pack"]
    if pack["format_version"] != "canton-solvency-pack-v1":
        raise Rejected(f"pack format {pack['format_version']}")

    signature = signed["signature"]
    if signature["public_key"].lower() != trusted_key_hex.lower():
        raise Rejected("unknown signer")
    if not ed25519_verify(
        bytes.fromhex(trusted_key_hex),
        pack_digest(pack),
        bytes.fromhex(signature["value"]),
    ):
        raise Rejected("bad pack signature")

    for entry in pack["entries"]:
        name = entry["name"]
        if name in ("", ".", "..") or "/" in name or "\\" in name:
            raise Rejected(f"unsafe member name {name!r}")
        if name not in members:
            raise Rejected(f"missing member {name}")
        if hashlib.sha256(members[name]).hexdigest() != entry["sha256"].lower():
            raise Rejected(f"altered member {name}")

    named = {e["name"] for e in pack["entries"]}
    for name in members:
        if name not in named:
            raise Rejected(f"unlisted member {name}")


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------
GOLDEN_USERS = [
    ("11111111-1111-7111-8111-111111111111", {"USDA": "100.5"}),
    ("22222222-2222-7222-8222-222222222222", {"CBTC": "0.25", "USDA": "1.000000000000000001"}),
    ("33333333-3333-7333-8333-333333333333", {}),
]

# §6 and §10, transcribed from the specification text.
EXPECTED = {
    "salt(u1)": "3de523c46646d91361907f6158f560ed6c55b8684c595139b05df6b12e3ddbb1",
    "salt(u2)": "332f77b30295afb7a346ba580de798bc08f3bada500905be6bd7a552c7eec458",
    "leaf(u1)": "05666cf01538aa610cc1285d1acf84953a961bd8346154cec9fb8785bb626363",
    "leaf(u2)": "b5fa416d215750e1a3ccd2b16dd0f906f35c3bfda8467cab3fe6977333e4e691",
    "leaf(u3)": "171f5e7577171aeabb58b3013b0e0e2d0b9f45b387fe8b1ed2027be1a0d7108c",
    "root": "02885b0fc65c3d8992899c8acba1917cb838b18b7054b6675e3d89f2bf8f0970",
    "root_sums": "CBTC:0.250000000000000000|USDA:101.500000000000000001",
    "report_digest": "0800c1047c9724ea429b238b01366f2032d674425d3ed745ed3402b2f534df61",
    "public_key": "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
}


def check_golden_vectors(log) -> list[str]:
    """§6 and §10 — the numbers printed in the specification, recomputed."""
    failures = []

    def check(label: str, got: str) -> None:
        want = EXPECTED[label]
        if got == want:
            log(f"  ok   {label}")
        else:
            failures.append(f"{label}: got {got}, spec says {want}")

    master = b"golden-v1"
    nodes = []
    for i, (user_id, raw) in enumerate(GOLDEN_USERS, start=1):
        salt = derive_salt(master, user_id)
        balances = parse_map(raw)
        h = leaf_hash(salt, user_id, balances)
        if f"salt(u{i})" in EXPECTED:
            check(f"salt(u{i})", salt.hex())
        check(f"leaf(u{i})", h.hex())
        nodes.append((h, balances))

    root_hash, root_sums = build_root(nodes)
    check("root", root_hash.hex())
    check("root_sums", canonical(root_sums))

    report = json.loads((REPO / "fixtures/report.golden.json").read_text())
    check("report_digest", report_digest(report["report"]).hex())
    check("public_key", report["signature"]["public_key"])

    # §5: the proof's path must fold to the same root.
    proof = json.loads((REPO / "fixtures/proof.golden.json").read_text())
    try:
        verify_proof(report, proof, EXPECTED["public_key"])
        log("  ok   §9.1 verification of the golden proof")
    except Rejected as e:
        failures.append(f"golden proof rejected: {e}")
    return failures


# What this verifier implements, as §14.3 `requires` names. Everything else is
# skipped by declaration rather than by accident -- the distinction matters:
# before the corpus carried `requires`, this file *passed*
# `report-v2-manifest-lies` by rejecting a format version it had never
# implemented, so a case meant to test the manifest tested nothing.
SUPPORTED = {"report-v1", "proof-v1", "pack-v1"}


def run_case(directory: Path, kind: str, key: str) -> None:
    """Run one corpus case. Returns on accept, raises on reject.

    Shared by the corpus check and the §14.5 statement builder, so a statement
    can never report an outcome the check would not have produced.
    """
    if kind == "proof":
        verify_proof(
            json.loads((directory / "report.json").read_text()),
            json.loads((directory / "proof.json").read_text()),
            key,
        )
    elif kind == "pack":
        members = {
            f.name: f.read_bytes()
            for f in directory.iterdir()
            if f.is_file() and f.name != "pack.json"
        }
        verify_pack(json.loads((directory / "pack.json").read_text()), key, members)
    else:
        raise AssertionError(
            f"kind {kind} has no runner, yet its case declares only supported "
            "features -- SUPPORTED and the runners disagree"
        )


def check_conformance(log) -> list[str]:
    """The §14.3 corpus, for the cases this verifier declares support for."""
    corpus = REPO / "conformance"
    manifest = json.loads((corpus / "manifest.json").read_text())
    key = manifest["trusted_key"]
    failures, ran, skipped = [], 0, 0

    for case in manifest["cases"]:
        cid, expect = case["id"], case["expect"]
        missing = set(case["requires"]) - SUPPORTED
        if missing:
            log(f"  skip {cid} (needs {', '.join(sorted(missing))})")
            skipped += 1
            continue

        ran += 1
        try:
            run_case(corpus / cid, case["kind"], key)
            outcome = "accept"
        except Rejected:
            outcome = "reject"
        except AssertionError:
            raise
        except Exception as e:  # a malformed document is a rejection too
            outcome = f"reject ({type(e).__name__})"

        if outcome.startswith(expect):
            log(f"  ok   {cid} ({expect})")
        else:
            failures.append(f"{cid}: expected {expect}, got {outcome}")

    log(
        f"  ran {ran} cases; skipped {skipped} requiring features this "
        "verifier does not implement"
    )

    # A statement that disagreed with the run above would be worse than none.
    statement = build_statement()
    for defect in statement_defects(statement, manifest["cases"]):
        failures.append(f"§14.5 statement: {defect}")
    return failures


# --------------------------------------------------------------------------
# §14.5 Compatibility statements
# --------------------------------------------------------------------------
CORPUS_DOMAIN = b"rocky-solvency-corpus-v1"


def corpus_digest(cases: list[dict]) -> str:
    """§14.5. Binds a statement to the exact corpus it was produced against —
    two statements over different corpora are not comparable, and without this
    that would not be visible."""
    out = CORPUS_DOMAIN + u64le(len(cases))
    for case in cases:
        out += lp(case["id"]) + lp(case["expect"])
        out += u64le(len(case["requires"]))
        for name in case["requires"]:
            out += lp(name)
    return hashlib.sha256(out).hexdigest()


def statement_defects(statement: dict, cases: list[dict]) -> list[str]:
    """The three §14.5 rules that make a statement mean something.

    Checked here rather than only produced, because the point of the format is
    that a *reader* can hold a statement to account."""
    supports = set(statement["supports"])
    by_id = {r["id"]: r for r in statement["results"]}
    defects = []
    for case in cases:
        cid = case["id"]
        result = by_id.get(cid)
        if result is None:
            defects.append(f"{cid}: no result reported")
            continue
        needed = set(case["requires"])
        skipped = result["outcome"] == "skip"
        if needed <= supports and skipped:
            claimed = ", ".join(sorted(needed))
            defects.append(f"{cid}: claims {claimed} but skipped the case")
        if not needed <= supports and not skipped:
            missing = ", ".join(sorted(needed - supports))
            defects.append(
                f"{cid}: reported {result['outcome']} but does not claim {missing}"
            )
    return defects


def build_statement() -> dict:
    """This verifier's own §14.5 statement."""
    corpus = json.loads((REPO / "conformance/manifest.json").read_text())
    cases = corpus["cases"]
    key = corpus["trusted_key"]
    results = []
    for case in cases:
        cid = case["id"]
        if not set(case["requires"]) <= SUPPORTED:
            results.append({"id": cid, "expected": case["expect"], "outcome": "skip"})
            continue
        try:
            run_case(REPO / "conformance" / cid, case["kind"], key)
            outcome = "accept"
        except Exception:
            outcome = "reject"
        results.append({"id": cid, "expected": case["expect"], "outcome": outcome})
    return {
        "format_version": "canton-solvency-compat-v1",
        "implementation": "spec-audit/verify_from_spec.py",
        "version": "1.1",
        "supports": sorted(SUPPORTED),
        "corpus_digest": corpus_digest(cases),
        "results": results,
    }


def main() -> int:
    if "--statement" in sys.argv:
        print(json.dumps(build_statement(), indent=2))
        return 0

    verbose = "--verbose" in sys.argv
    log = print if verbose else (lambda *_: None)

    print("Golden vectors (SPEC §6, §10)")
    failures = check_golden_vectors(log)
    print(f"  {'FAILED' if failures else 'all vectors reproduced from the spec text'}")

    print("Conformance corpus (SPEC §14.3)")
    failures += check_conformance(log)

    for failure in failures:
        print(f"  FAIL {failure}")

    print(f"\n{len(FINDINGS)} findings from this audit, all now closed in SPEC.md:")
    for title, detail in FINDINGS:
        print(f"\n  {title}")
        for line in detail.split(". "):
            print(f"    {line.strip()}")

    if failures:
        print(f"\n{len(failures)} failures")
        return 1
    print("\nThe specification text is sufficient to reproduce every vector it publishes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
