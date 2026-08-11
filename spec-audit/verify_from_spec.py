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
        "FIXED — SPEC §16.4: \"every field the report carries\" was ambiguous",
        "Step 5 established claimed-only for 'every field the report carries'. "
        "A report with no manifest and an empty mark_prices map carries the "
        "field but no data under it, so the phrase admitted two readings: "
        "claimed-only, or nothing at all — and under the second reading, a "
        "publisher declaring claimed-only on an empty map would be refused for "
        "over-claiming. Found while transcribing §16 here, before writing any "
        "code: the reference implementation had taken the first reading and the "
        "text supported either. §16.4 now says claimed-only applies to every "
        "field not established as not-disclosed, and that only the manifest "
        "withholds.",
    ),
    (
        "FIXED — SPEC §12: the anchor digest formula omitted publisher_key",
        "The key-distribution change added publisher_key to the anchor and to "
        "its digest in both implementations and in the schema, and updated §8.4's "
        "prose about it, but left §12's formula and JSON example untouched. An "
        "implementer following §12 would hash six fields where the reference "
        "hashes seven, and reject every valid chain while the schema rejected "
        "their documents for missing a field the spec never mentioned. Found by "
        "implementing §12 here from the text: anchors-intact failed. Both the "
        "formula and the example now carry the field.",
    ),
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


def _report_preimage(domain: bytes, report: dict) -> bytes:
    """The §8.2 field sequence, shared so §8.5 can say "every §8.2 field,
    identical order and encoding" and mean it literally."""
    disclosures = report.get("disclosures") or {}
    return (
        domain
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
    )


def report_digest(report: dict) -> bytes:
    """§8.2 for a v1 report, §8.5 for a v2 one — the version selects the
    domain string, so a v2 signature cannot be replayed as a v1 one."""
    if report["format_version"] == "canton-solvency-report-v2":
        return report_digest_v2(report)
    return hashlib.sha256(_report_preimage(REPORT_DOMAIN, report)).digest()


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


# §14.3 failure names, as the manifest declares them.
PROFILE = "profile"
SHORTFALL = "shortfall"
MANIFEST_PRESENCE = "manifest_presence"
MANIFEST_INCONSISTENT = "manifest_inconsistent"
ENTITY_ROOT_MISMATCH = "entity_root_mismatch"
ENTITY_SUMS_MISMATCH = "entity_sums_mismatch"
DIGEST_MISMATCH = "digest_mismatch"
UNKNOWN_SIGNER = "unknown_signer"
BAD_SIGNATURE = "bad_signature"
ROOT_HASH_MISMATCH = "root_hash_mismatch"
ROOT_SUMS_MISMATCH = "root_sums_mismatch"
OVER_CLAIMED = "over_claimed"
UNKNOWN_FIELD = "unknown_field"


def verify_proof(signed: dict, proof: dict, trusted_key_hex: str) -> None:
    """The five steps of §9.1, failing on the first that does not hold."""
    report = signed["report"]
    signature = signed["signature"]

    # 1. recognised versions
    if report["format_version"] not in (
        "canton-solvency-report-v1",
        "canton-solvency-report-v2",
    ):
        raise Rejected(f"report format {report['format_version']}")
    check_manifest(report)
    if proof["format_version"] != "canton-solvency-proof-v1":
        raise Rejected(f"proof format {proof['format_version']}")
    if signature["algorithm"] != "ed25519":
        raise Rejected(f"algorithm {signature['algorithm']}")

    # 2. the digest binds the proof to this report
    digest = report_digest(report)
    if digest.hex() != proof["report_digest"]:
        raise Rejected(DIGEST_MISMATCH)

    # 3. trusted key, then signature. §8.4: the embedded key is display
    #    metadata, so it is compared rather than used.
    if signature["public_key"].lower() != trusted_key_hex.lower():
        raise Rejected(UNKNOWN_SIGNER)
    if not ed25519_verify(
        bytes.fromhex(trusted_key_hex), digest, bytes.fromhex(signature["value"])
    ):
        raise Rejected(BAD_SIGNATURE)

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
        raise Rejected(ROOT_HASH_MISMATCH)
    if not sums_equal(node[1], parse_map(report["root_sums"])):
        raise Rejected(ROOT_SUMS_MISMATCH)


# --------------------------------------------------------------------------
# §3.1 Leaf format v2 — named amount maps
# --------------------------------------------------------------------------
LEAF_V2_DOMAIN = b"rocky-solvency-leaf-v2"
SAFE_NAME = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def safe_name(name: str) -> bool:
    """§3.1: map and asset names outside [A-Za-z0-9._-] are refused, because
    §4 still canonicalises sums with a `:`/`|` join and an unconstrained
    qualified key could forge a boundary."""
    return bool(name) and all(c in SAFE_NAME for c in name)


def leaf_hash_v2(salt: bytes, subject_id: str, maps: dict[str, dict[str, int]]) -> bytes:
    """§3.1, transcribed from the formula in the specification text."""
    for map_name, amounts in maps.items():
        if not safe_name(map_name):
            raise ValueError(f"map name {map_name!r} is not permitted by §3.1")
        for asset in amounts:
            if not safe_name(asset):
                raise ValueError(f"asset name {asset!r} is not permitted by §3.1")

    out = (
        LEAF_V2_DOMAIN
        + salt
        + hashlib.sha256(subject_id.encode()).digest()
        + u64le(len(maps))
    )
    # Map names bytewise, as §3.1 says and §8.1's lpmap does for assets.
    for map_name in sorted(maps, key=lambda n: n.encode()):
        out += lp(map_name) + lpmap(maps[map_name])
    return hashlib.sha256(out).digest()


def qualified_sums(maps: dict[str, dict[str, int]]) -> dict[str, int]:
    """§3.1: a v2 leaf node's sums are every map flattened under `<map>/<asset>`."""
    return {
        f"{map_name}/{asset}": amount
        for map_name, amounts in maps.items()
        for asset, amount in amounts.items()
    }


# --------------------------------------------------------------------------
# §14 Profile registry
# --------------------------------------------------------------------------
# Transcribed from §14's table. The "Requires" column gives the aggregates a
# report must publish, and for two profiles a further rule stated in prose:
# settlement.dvp needs both maps in every leaf, eligibility.holder needs each
# attested rule's total to equal leaf_count.
PROFILES: dict[str, dict] = {
    "solvency.liabilities": {"leaf": "v1", "aggregates": ["root_sums"]},
    "solvency.group": {"leaf": "v1", "aggregates": ["root_sums"]},
    "collateral.repo": {
        "leaf": "v2",
        "aggregates": ["collateral/*", "exposure/*"],
        # §14: "for every asset, aggregate collateral must be at least
        # aggregate exposure. A surplus in one asset does not excuse a
        # shortfall in another."
        "covers": ("collateral", "exposure"),
    },
    "fund.nav": {"leaf": "v2", "aggregates": ["units/*", "entitlement/*"]},
    "settlement.dvp": {
        "leaf": "v2",
        "aggregates": ["delivered/*", "paid/*"],
        "leaf_maps": ["delivered", "paid"],
    },
    "eligibility.holder": {
        "leaf": "v2",
        "aggregates": ["attested/*"],
        "leaf_maps": ["attested"],
        "unanimous": ["attested"],
    },
    "coverage.custody": {"leaf": "v2", "aggregates": ["held/*"], "leaf_maps": ["held"]},
}


def check_profile(report: dict, leaf_maps: dict[str, dict[str, int]] | None = None) -> None:
    """§14.1's MUSTs, plus the two per-profile rules §14 states in prose."""
    rules = PROFILES.get(report["profile"])
    if rules is None:
        raise Rejected(PROFILE)

    sums = report["root_sums"]
    for aggregate in rules["aggregates"]:
        present = (
            any(k.startswith(aggregate[:-1]) for k in sums)
            if aggregate.endswith("/*")
            else bool(sums)
        )
        if not present:
            # A report omitting an aggregate its profile requires asserts
            # nothing: the statement would be vacuous.
            raise Rejected(PROFILE)

    # Per-leaf: a settled trade missing a leg is caught when its own proof is
    # checked, not by looking at the totals.
    if leaf_maps is not None:
        for required in rules.get("leaf_maps", []):
            if not leaf_maps.get(required):
                raise Rejected(PROFILE)

    covers = rules.get("covers")
    if covers is not None:
        covering, covered = covers
        totals = parse_map(sums)
        for key, owed in totals.items():
            if not key.startswith(f"{covered}/"):
                continue
            asset = key[len(covered) + 1 :]
            held = totals.get(f"{covering}/{asset}", 0)
            if held < owed:
                raise Rejected(PROFILE)

    # Unanimity: each rule carries 1 in every leaf, so the total equalling
    # leaf_count is consistent with every subject having satisfied it.
    for map_name in rules.get("unanimous", []):
        for key, total in parse_map(sums).items():
            if not key.startswith(f"{map_name}/"):
                continue
            if total != report["leaf_count"] * SCALE:
                raise Rejected(PROFILE)


# --------------------------------------------------------------------------
# §9.2 Proof document v2
# --------------------------------------------------------------------------
# §14: which profiles commit v2 leaves. A v1 proof against a v2-leaf profile
# and the reverse are both refused, so the mismatch is named rather than
# surfacing as an opaque hash failure.
LEAF_V2_PROFILES = {
    "collateral.repo",
    "fund.nav",
    "settlement.dvp",
    "eligibility.holder",
    "coverage.custody",
}


def verify_proof_v2(signed: dict, proof: dict, trusted_key_hex: str) -> None:
    """§9.2: as §9.1, with a v2 leaf in place of a v1 one."""
    report = signed["report"]
    signature = signed["signature"]

    if report["format_version"] not in (
        "canton-solvency-report-v1",
        "canton-solvency-report-v2",
    ):
        raise Rejected(f"report format {report['format_version']}")
    if proof["format_version"] != "canton-solvency-proof-v2":
        raise Rejected(f"proof format {proof['format_version']}")
    if signature["algorithm"] != "ed25519":
        raise Rejected(f"algorithm {signature['algorithm']}")

    leaf = proof["leaf"]
    maps = {name: parse_map(m) for name, m in leaf["maps"].items()}
    if PROFILES.get(report["profile"], {}).get("leaf") != "v2":
        raise Rejected(PROFILE)  # §14.1: a v2 proof against a v1-leaf profile
    # §9.1 step 1: the profile is checked before the digest, so a vacuous or
    # unregistered report is refused for that reason rather than for a digest
    # mismatch it also happens to have.
    check_profile(report, maps)

    digest = report_digest(report)
    if digest.hex() != proof["report_digest"]:
        raise Rejected(DIGEST_MISMATCH)
    if signature["public_key"].lower() != trusted_key_hex.lower():
        raise Rejected(UNKNOWN_SIGNER)
    if not ed25519_verify(
        bytes.fromhex(trusted_key_hex), digest, bytes.fromhex(signature["value"])
    ):
        raise Rejected(BAD_SIGNATURE)

    node = (
        leaf_hash_v2(bytes.fromhex(leaf["salt"]), leaf["subject_id"], maps),
        qualified_sums(maps),
    )
    for step in proof["steps"]:
        sibling = (bytes.fromhex(step["sibling_hash"]), parse_map(step["sibling_sums"]))
        left, right = (sibling, node) if step["sibling_on_left"] else (node, sibling)
        sums = add_sums(left[1], right[1])
        node = (node_hash(left[0], right[0], sums), sums)

    if node[0].hex() != report["root_hash"]:
        raise Rejected(ROOT_HASH_MISMATCH)
    if not sums_equal(node[1], parse_map(report["root_sums"])):
        raise Rejected(ROOT_SUMS_MISMATCH)


# --------------------------------------------------------------------------
# §8.5 Disclosure manifest (format v2)
# --------------------------------------------------------------------------
REPORT_DOMAIN_V2 = b"rocky-solvency-report-v2"

# §8.5: an unrecognised key is an error rather than something to ignore, so a
# producer cannot bury a field the verifier has no opinion about.
MANIFEST_FIELDS = [
    "root_sums",
    "mark_prices",
    "disclosures.bad_debt",
    "disclosures.excluded_house_accounts",
    "disclosures.excluded_house_totals",
    "customer_balances",
    "customer_identities",
]
# Which of those live in the report body, and so can be checked for
# consistency. The rest are attested through the commitment.
BODY_FIELDS = MANIFEST_FIELDS[:5]


def report_digest_v2(report: dict) -> bytes:
    """§8.5: every §8.2 field in the same order and encoding, then the manifest.

    Its own domain string, so the same fields cannot digest identically under
    both versions and a v2 signature cannot be replayed as a v1 one.
    """
    manifest = report["manifest"]
    fields = manifest["fields"]
    out = _report_preimage(REPORT_DOMAIN_V2, report) + lp(manifest["audience"])
    out += u64le(len(fields))
    for path in sorted(fields, key=lambda p: p.encode()):
        out += lp(path) + lp(fields[path])
    return hashlib.sha256(out).digest()


def carries_data(report: dict, path: str) -> bool:
    """Whether the report body actually carries the field."""
    disclosures = report.get("disclosures") or {}
    if path == "root_sums":
        return bool(report.get("root_sums"))
    if path == "mark_prices":
        return bool(report.get("mark_prices"))
    if path == "disclosures.bad_debt":
        return bool(disclosures.get("bad_debt"))
    if path == "disclosures.excluded_house_accounts":
        return int(disclosures.get("excluded_house_accounts", 0)) > 0
    if path == "disclosures.excluded_house_totals":
        return bool(disclosures.get("excluded_house_totals"))
    return False


def check_manifest(report: dict) -> None:
    """§8.5's version and consistency rules."""
    version = report["format_version"]
    manifest = report.get("manifest")
    if version == "canton-solvency-report-v1" and manifest is not None:
        raise Rejected(MANIFEST_PRESENCE)
    if version == "canton-solvency-report-v2" and manifest is None:
        raise Rejected(MANIFEST_PRESENCE)
    if manifest is None:
        return

    for path, state in manifest["fields"].items():
        if path not in MANIFEST_FIELDS:
            raise Rejected(MANIFEST_INCONSISTENT)
        if path not in BODY_FIELDS:
            continue
        has = carries_data(report, path)
        if state == "published" and not has:
            raise Rejected(MANIFEST_INCONSISTENT)
        if state in ("committed", "withheld") and has:
            raise Rejected(MANIFEST_INCONSISTENT)


# --------------------------------------------------------------------------
# §11 Coverage
# --------------------------------------------------------------------------
def verify_coverage(
    custody: dict,
    liabilities: dict,
    statement: dict,
    custody_key_hex: str,
    liabilities_key_hex: str,
) -> None:
    """§11.2's five steps, in order.

    Step 4 is the one worth naming: both signatures verify against
    caller-supplied trusted keys, which may differ, since a custodian and a
    venue are often different institutions. The TypeScript implementation
    omitted this step entirely and no case noticed — the specification was
    right and the code was not.
    """
    if statement["format_version"] != "canton-solvency-coverage-v1":
        raise Rejected(f"statement format {statement['format_version']}")
    if custody["report"]["profile"] != "coverage.custody":
        raise Rejected(PROFILE)
    if liabilities["report"]["profile"] != "solvency.liabilities":
        raise Rejected(PROFILE)

    for signed, expected in (
        (custody, statement["custody_report_digest"]),
        (liabilities, statement["liabilities_report_digest"]),
    ):
        if report_digest(signed["report"]).hex() != expected:
            raise Rejected(DIGEST_MISMATCH)

    for signed, key in ((custody, custody_key_hex), (liabilities, liabilities_key_hex)):
        if signed["signature"]["public_key"].lower() != key.lower():
            raise Rejected(UNKNOWN_SIGNER)
        if not ed25519_verify(
            bytes.fromhex(key),
            report_digest(signed["report"]),
            bytes.fromhex(signed["signature"]["value"]),
        ):
            raise Rejected(BAD_SIGNATURE)

    # Driven by what is owed: an asset owed and held nowhere is a shortfall,
    # not an absent row.
    held = parse_map(custody["report"]["root_sums"])
    for asset, owed in parse_map(liabilities["report"]["root_sums"]).items():
        if held.get(f"held/{asset}", 0) < owed:
            raise Rejected(SHORTFALL)


# --------------------------------------------------------------------------
# §13 Hierarchical commitments
# --------------------------------------------------------------------------
ENTITY_DOMAIN = b"rocky-solvency-entity-v1"


def entity_leaf_hash(entity_id: str, root_hash_hex: str, root_sums: dict[str, int]) -> bytes:
    """§13.1, transcribed from the formula.

    `entity_root_hash` enters as 32 raw bytes, not as the hex text the rest of
    §8 transports — the formula says so explicitly, and it is the one place in
    the format where a hash is hashed rather than its rendering.
    """
    return hashlib.sha256(
        ENTITY_DOMAIN
        + lp(entity_id)
        + bytes.fromhex(root_hash_hex)
        + lpmap(root_sums)
    ).digest()


def verify_membership(group_signed: dict, membership: dict, trusted_key_hex: str) -> None:
    """§13.3: §9.1 with the §13.1 leaf in place of a customer leaf."""
    report = group_signed["report"]
    signature = group_signed["signature"]

    if membership["format_version"] != "canton-solvency-group-membership-v1":
        raise Rejected(f"membership format {membership['format_version']}")
    # §13.2: a group report states a different thing and must not be mistaken
    # for a customer-level one.
    if report["profile"] != "solvency.group":
        raise Rejected(PROFILE)
    check_profile(report)

    digest = report_digest(report)
    if digest.hex() != membership["group_report_digest"]:
        raise Rejected(DIGEST_MISMATCH)
    if signature["public_key"].lower() != trusted_key_hex.lower():
        raise Rejected(UNKNOWN_SIGNER)
    if not ed25519_verify(
        bytes.fromhex(trusted_key_hex), digest, bytes.fromhex(signature["value"])
    ):
        raise Rejected(BAD_SIGNATURE)

    entity = membership["entity"]
    sums = parse_map(entity["root_sums"])
    node = (entity_leaf_hash(entity["entity_id"], entity["root_hash"], sums), sums)
    for step in membership["steps"]:
        sibling = (bytes.fromhex(step["sibling_hash"]), parse_map(step["sibling_sums"]))
        left, right = (sibling, node) if step["sibling_on_left"] else (node, sibling)
        total = add_sums(left[1], right[1])
        node = (node_hash(left[0], right[0], total), total)

    if node[0].hex() != report["root_hash"]:
        raise Rejected(ROOT_HASH_MISMATCH)
    if not sums_equal(node[1], parse_map(report["root_sums"])):
        raise Rejected(ROOT_SUMS_MISMATCH)


def verify_group_chain(
    group_signed: dict,
    membership: dict,
    entity_signed: dict,
    proof: dict,
    trusted_key_hex: str,
) -> None:
    """§13.4: all three hold, and step 3 is not optional."""
    verify_proof(entity_signed, proof, trusted_key_hex)
    verify_membership(group_signed, membership, trusted_key_hex)

    entity = membership["entity"]
    entity_report = entity_signed["report"]
    if entity["root_hash"] != entity_report["root_hash"]:
        raise Rejected(ENTITY_ROOT_MISMATCH)
    if not sums_equal(parse_map(entity["root_sums"]), parse_map(entity_report["root_sums"])):
        raise Rejected(ENTITY_SUMS_MISMATCH)


# --------------------------------------------------------------------------
# §12 Anchor chains
# --------------------------------------------------------------------------
ANCHOR_DOMAIN = b"rocky-solvency-anchor-v1"


def anchor_digest(anchor: dict) -> str:
    """§12, transcribed from the formula in the specification text.

    §12's formula omitted publisher_key when this was written, and so did the
    JSON example beside it, while both implementations and the schema included
    it. Following the text literally produced a verifier that rejected every
    valid chain — `anchors-intact` failed. The spec is corrected; this is the
    transcription of the corrected text.
    """
    out = (
        ANCHOR_DOMAIN
        + lp(anchor["format_version"])
        + lp(anchor["report_digest"])
        + lp(anchor["root_hash"])
        + lp(anchor["snapshot_time"])
        + lp(anchor["ledger_offset"])
        + lp(anchor["publisher"])
        + lp(anchor["publisher_key"])
    )
    # §12: a presence byte, not an empty string, so a genesis anchor and one
    # naming an empty predecessor cannot hash alike.
    prev = anchor.get("prev_anchor")
    out += b"\x00" if prev is None else b"\x01" + lp(prev)
    return hashlib.sha256(out).hexdigest()


def verify_chain(history: list[dict]) -> None:
    """§12.1, in order, failing on the first rule that does not hold."""
    for index, anchor in enumerate(history):
        if anchor["format_version"] != "canton-solvency-anchor-v1":
            raise Rejected("unsupported_version")
        if index == 0:
            if anchor.get("prev_anchor") is not None:
                raise Rejected("not_genesis")
            continue
        previous = history[index - 1]
        if anchor.get("prev_anchor") != anchor_digest(previous):
            raise Rejected("broken")
        if anchor["publisher"] != previous["publisher"]:
            raise Rejected("publisher_changed")
        if anchor["snapshot_time"] <= previous["snapshot_time"]:
            raise Rejected("went_backwards")
        if anchor["ledger_offset"] < previous["ledger_offset"]:
            raise Rejected("went_backwards")


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



# --- §16: assurance levels ---------------------------------------------------

ASSURANCE_FORMAT_VERSION = "canton-solvency-assurance-v1"
ATTESTATION_FORMAT_VERSION = "canton-solvency-attestation-v1"

# §16.2: the §8.5 report-resident vocabulary, and no other paths.
ASSURANCE_FIELDS = (
    "root_sums",
    "mark_prices",
    "disclosures.bad_debt",
    "disclosures.excluded_house_accounts",
    "disclosures.excluded_house_totals",
)

# §16.1 orders these for display only, and the specification is explicit that
# they are not a total order. The one ordering it does fix is issuer below
# third-party: the issuer is the party whose solvency is in question.
STRENGTH = {
    "not-disclosed": 0,
    "claimed-only": 1,
    "issuer-attested": 2,
    "third-party-attested": 3,
    "ledger-derived": 4,
    "cryptographically-verified": 5,
}


def attestation_digest(attestation: dict) -> bytes:
    """§16.3. A domain distinct from §8.2's, with the field inside the
    preimage so an attestor who signed for one field has not signed for
    another."""
    return hashlib.sha256(
        b"rocky-solvency-attestation-v1"
        + lp(attestation["format_version"])
        + lp(attestation["report_digest"])
        + lp(attestation["field"])
        + lp(attestation["role"])
        + lp(attestation["attestor"])
        + lp(attestation["basis"])
    ).digest()


def establish(
    signed: dict,
    evidence: dict,
    trusted_key_hex: str,
    attestors: dict[str, str],
) -> dict[str, set[str]]:
    """§16.4 step 5: what the evidence supports, per field."""
    report = signed["report"]
    digest = report_digest(report).hex()
    manifest = report.get("manifest") or {}
    fields = manifest.get("fields") or {}
    out: dict[str, set[str]] = {}

    for field in ASSURANCE_FIELDS:
        levels: set[str] = set()

        # Only the manifest withholds, and only over a field the body does not
        # carry data for.
        if fields.get(field) == "withheld" and not carries_data(report, field):
            out[field] = {"not-disclosed"}
            continue

        levels.add("claimed-only")

        # Only root_sums is committed in the tree. mark_prices and the
        # disclosures enter the report digest, so they are signed, but nothing
        # recomputes them.
        if field == "root_sums" and evidence.get("proof") is not None:
            try:
                verify_proof(signed, evidence["proof"], trusted_key_hex)
                levels.add("cryptographically-verified")
            except (Rejected, Exception):
                # A proof that does not verify establishes nothing. It is not
                # itself the failure: the failure, if any, is the declaration
                # that outran it.
                pass

        anchor = evidence.get("anchor")
        if anchor is not None and (
            anchor.get("format_version") == "canton-solvency-anchor-v1"
            and anchor.get("report_digest") == digest
            and anchor.get("root_hash") == report["root_hash"]
            and anchor.get("snapshot_time") == report["snapshot_time"]
            and anchor.get("ledger_offset") == report["ledger_offset"]
            and anchor.get("publisher") == report["publisher"]
        ):
            levels.add("ledger-derived")

        for signed_attestation in evidence.get("attestations") or []:
            attestation = signed_attestation.get("attestation") or {}
            if (
                attestation.get("format_version") != ATTESTATION_FORMAT_VERSION
                or attestation.get("field") != field
                or attestation.get("report_digest") != digest
            ):
                continue
            signature = signed_attestation.get("signature") or {}
            # Trust is by key and by role, decided before the document was
            # opened: a key trusted as a custodian must not establish issuer
            # attestation.
            if attestors.get(signature.get("public_key")) != attestation.get("role"):
                continue
            if signature.get("algorithm") != "ed25519":
                continue
            if ed25519_verify(
                bytes.fromhex(signature["public_key"]),
                attestation_digest(attestation),
                bytes.fromhex(signature["value"]),
            ):
                levels.add(
                    "issuer-attested"
                    if attestation["role"] == "issuer"
                    else "third-party-attested"
                )

        out[field] = levels
    return out


def verify_assurance(
    signed: dict,
    statement: dict,
    evidence: dict,
    trusted_key_hex: str,
    attestors: dict[str, str] | None = None,
) -> dict[str, str]:
    """§16.4, in the order the specification gives."""
    attestors = attestors or {}

    if statement.get("format_version") != ASSURANCE_FORMAT_VERSION:
        raise Rejected(f"assurance format {statement.get('format_version')}")

    report = signed["report"]
    digest = report_digest(report).hex()
    if statement.get("report_digest") != digest:
        raise Rejected(DIGEST_MISMATCH)

    # A statement about a report nobody vouched for must not be graded.
    if signed["signature"]["public_key"] != trusted_key_hex:
        raise Rejected(UNKNOWN_SIGNER)
    if not ed25519_verify(
        bytes.fromhex(trusted_key_hex),
        report_digest(report),
        bytes.fromhex(signed["signature"]["value"]),
    ):
        raise Rejected(BAD_SIGNATURE)

    levels = statement.get("levels") or {}
    for field in levels:
        if field not in ASSURANCE_FIELDS:
            raise Rejected(UNKNOWN_FIELD)

    established = establish(signed, evidence, trusted_key_hex, attestors)
    for field, declared in levels.items():
        supported = established.get(field, set())
        if declared not in supported:
            raise Rejected(OVER_CLAIMED)
    return dict(levels)


# What this verifier implements, as §14.3 `requires` names. Everything else is
# skipped by declaration rather than by accident -- the distinction matters:
# before the corpus carried `requires`, this file *passed*
# `report-v2-manifest-lies` by rejecting a format version it had never
# implemented, so a case meant to test the manifest tested nothing.
SUPPORTED = {
    "report-v1",
    "report-v2",
    "manifest",
    "proof-v1",
    "pack-v1",
    "anchor-v1",
    "leaf-v2",
    "proof-v2",
    "group-v1",
    "coverage-v1",
    "assurance-v1",
}


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
    elif kind == "proof-v2":
        verify_proof_v2(
            json.loads((directory / "report.json").read_text()),
            json.loads((directory / "proof.json").read_text()),
            key,
        )
    elif kind == "coverage":
        verify_coverage(
            json.loads((directory / "custody.json").read_text()),
            json.loads((directory / "liabilities.json").read_text()),
            json.loads((directory / "statement.json").read_text()),
            key,
            key,
        )
    elif kind == "membership":
        verify_membership(
            json.loads((directory / "group-report.json").read_text()),
            json.loads((directory / "membership.json").read_text()),
            key,
        )
    elif kind == "chain":
        verify_group_chain(
            json.loads((directory / "group-report.json").read_text()),
            json.loads((directory / "membership.json").read_text()),
            json.loads((directory / "entity-report.json").read_text()),
            json.loads((directory / "proof.json").read_text()),
            key,
        )
    elif kind == "anchors":
        verify_chain(json.loads((directory / "history.json").read_text()))
    elif kind == "assurance":
        def optional(name: str):
            path = directory / name
            return json.loads(path.read_text()) if path.exists() else None

        verify_assurance(
            json.loads((directory / "report.json").read_text()),
            json.loads((directory / "assurance.json").read_text()),
            {
                "proof": optional("proof.json"),
                "anchor": optional("anchor.json"),
                "attestations": optional("attestations.json") or [],
            },
            key,
            # §16.4: which attestor key is trusted for which role arrives out
            # of band. In a corpus case that is a file the case carries, not
            # one of the documents under test.
            optional("attestors.json") or {},
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
        except Rejected as e:
            outcome = "reject"
            # Rejected is not enough. A case can exercise the check it names
            # and a different check in fact -- `proof-understated-totals` reads
            # as a test of the §9.1 sums comparison and is caught a step
            # earlier by the digest binding.
            declared = case.get("failure")
            reason = str(e)
            if declared and reason in {
                DIGEST_MISMATCH,
                UNKNOWN_SIGNER,
                BAD_SIGNATURE,
                ROOT_HASH_MISMATCH,
                ROOT_SUMS_MISMATCH,
            } and reason != declared:
                failures.append(
                    f"{cid}: declares {declared}, rejected for {reason}"
                )
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
