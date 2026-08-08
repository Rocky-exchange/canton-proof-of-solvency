import { describe, expect, it } from "vitest";

import {
  canonicalBalances,
  combineNodes,
  formatAmount18dp,
  leafHashHex,
  parseAmount18dp,
  sumBalances,
  verifyProof,
  type SolvencyNode,
} from "./verify";

// Golden vectors pinned by crates/solvency-merkle (rocky-backend,
// `golden_vectors_pin_the_wire_format`). If these fail, the wire format
// diverged between the Rust prover and this verifier.
const MASTER_SALT0 = "3de523c46646d91361907f6158f560ed6c55b8684c595139b05df6b12e3ddbb1";
const U1 = "11111111-1111-7111-8111-111111111111";
const U2 = "22222222-2222-7222-8222-222222222222";
const U3 = "33333333-3333-7333-8333-333333333333";
// Salts for u2/u3 are opaque here (derived server-side); captured from a
// run of the Rust test harness with master salt "golden-v1".
const LEAF0_HASH = "05666cf01538aa610cc1285d1acf84953a961bd8346154cec9fb8785bb626363";
const LEAF2_HASH = "171f5e7577171aeabb58b3013b0e0e2d0b9f45b387fe8b1ed2027be1a0d7108c";
const ROOT_HASH = "02885b0fc65c3d8992899c8acba1917cb838b18b7054b6675e3d89f2bf8f0970";

describe("amount codec", () => {
  it("parses and formats 18dp amounts", () => {
    expect(parseAmount18dp("100.5")).toBe(100_500_000_000_000_000_000n);
    expect(parseAmount18dp("0.000000000000000001")).toBe(1n);
    expect(formatAmount18dp(100_500_000_000_000_000_000n)).toBe("100.500000000000000000");
    expect(formatAmount18dp(0n)).toBe("0.000000000000000000");
  });

  it("rejects malformed amounts", () => {
    for (const bad of ["-1", "", "1.2.3", "abc", "1.0000000000000000001"]) {
      expect(() => parseAmount18dp(bad), bad).toThrow();
    }
  });
});

describe("canonical serialization", () => {
  it("sorts assets and pins 18 fraction digits", () => {
    expect(
      canonicalBalances({ USDA: "1.000000000000000001", CBTC: "0.25" })
    ).toBe("CBTC:0.250000000000000000|USDA:1.000000000000000001");
    expect(canonicalBalances({})).toBe("");
  });
});

async function goldenLeaves(): Promise<SolvencyNode[]> {
  // u1's salt is the golden vector; u2/u3 use salts captured from the same
  // Rust run — recomputed leaf hashes must then match the pinned tree.
  const l0 = await leafHashHex(MASTER_SALT0, U1, { USDA: "100.5" });
  return [
    { hashHex: l0, sums: { USDA: parseAmount18dp("100.5") } },
    // leaf1's hash is recomputed inside tests that need it; for tree tests
    // we use the stored-hash trust model exactly like the API response.
    { hashHex: LEAF0_HASH, sums: { USDA: parseAmount18dp("100.5") } },
  ];
}

describe("leaf hashing", () => {
  it("matches the pinned golden leaf hashes", async () => {
    expect(await leafHashHex(MASTER_SALT0, U1, { USDA: "100.5" })).toBe(LEAF0_HASH);
  });
});

describe("tree combine and proof verification", () => {
  // Rebuild the golden 3-leaf tree from stored leaf hashes + balances,
  // exactly the way the proof endpoint's client sees them.
  const leaf = (hashHex: string, balances: Record<string, string>): SolvencyNode => ({
    hashHex,
    sums: sumBalances(balances),
  });

  it("recombines to the pinned root", async () => {
    // leaf1 hash: recompute is impossible without its salt, but the golden
    // root pins the full combination; leaf1's hash comes from the Rust run.
    const l0 = leaf(LEAF0_HASH, { USDA: "100.5" });
    const l1hash = await leafHashHex(
      "332f77b30295afb7a346ba580de798bc08f3bada500905be6bd7a552c7eec458",
      U2,
      { CBTC: "0.25", USDA: "1.000000000000000001" }
    );
    const l1 = leaf(l1hash, { CBTC: "0.25", USDA: "1.000000000000000001" });
    const l2 = leaf(LEAF2_HASH, {});
    const c01 = await combineNodes(l0, l1);
    const root = await combineNodes(c01, l2);
    expect(root.hashHex).toBe(ROOT_HASH);
    expect(formatAmount18dp(root.sums.USDA)).toBe("101.500000000000000001");
    expect(formatAmount18dp(root.sums.CBTC)).toBe("0.250000000000000000");
  });

  it("verifies the golden proof for leaf 1 and rejects tampering", async () => {
    const l0 = leaf(LEAF0_HASH, { USDA: "100.5" });
    const l1hash = await leafHashHex(
      "332f77b30295afb7a346ba580de798bc08f3bada500905be6bd7a552c7eec458",
      U2,
      { CBTC: "0.25", USDA: "1.000000000000000001" }
    );
    const l1 = leaf(l1hash, { CBTC: "0.25", USDA: "1.000000000000000001" });
    const l2 = leaf(LEAF2_HASH, {});
    const c01 = await combineNodes(l0, l1);
    const root = await combineNodes(c01, l2);
    const path = [
      { sibling: l0, siblingOnLeft: true },
      { sibling: l2, siblingOnLeft: false },
    ];
    expect(await verifyProof(l1, path, root)).toBe(true);
    const forged = leaf(l1.hashHex, { CBTC: "0.25", USDA: "999.0" });
    expect(await verifyProof(forged, path, root)).toBe(false);
    expect(await verifyProof(l1, path, { ...root, hashHex: LEAF0_HASH })).toBe(false);
  });
});
