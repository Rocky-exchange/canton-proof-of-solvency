import { describe, expect, it } from "vitest";

import { packDigestHex, verifyPack, type SignedPack } from "./pack";

/**
 * The pack digest has to agree with the Rust `pack` module byte for byte, or
 * a delivery signed by the publisher fails in the browser and passes on the
 * command line. The cross-implementation vector lives in the conformance
 * corpus; these cover the rules themselves.
 */
const encoder = new TextEncoder();

const members = (): Map<string, Uint8Array> =>
  new Map([
    ["report.json", encoder.encode('{"report":1}')],
    ["proof-alice.json", encoder.encode('{"proof":"a"}')],
  ]);

const digestOf = async (bytes: Uint8Array): Promise<string> => {
  const hash = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
};

async function pack(): Promise<SignedPack> {
  const entries = [...members().entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(async ([name, bytes]) => ({ name, sha256: await digestOf(bytes) }));
  return {
    pack: {
      format_version: "canton-solvency-pack-v1",
      publisher: "venue::one",
      snapshot_time: "2026-08-09T00:00:00Z",
      report_digest: "aa11",
      entries: await Promise.all(entries),
    },
    signature: { algorithm: "ed25519", public_key: "00".repeat(32), value: "00".repeat(64) },
  };
}

describe("evidence packs", () => {
  it("accepts a delivery matching its index", async () => {
    expect(await verifyPack(await pack(), members())).toEqual({ ok: true });
  });

  it("catches a member whose bytes changed", async () => {
    const m = members();
    m.set("proof-alice.json", encoder.encode('{"proof":"A"}'));
    expect(await verifyPack(await pack(), m)).toEqual({
      ok: false,
      failure: "altered",
      name: "proof-alice.json",
    });
  });

  it("catches a proof left out of the delivery", async () => {
    const m = members();
    m.delete("proof-alice.json");
    expect(await verifyPack(await pack(), m)).toEqual({
      ok: false,
      failure: "missing",
      name: "proof-alice.json",
    });
  });

  it("catches a file the index does not name", async () => {
    const m = members();
    m.set("proof-mallory.json", encoder.encode("{}"));
    expect(await verifyPack(await pack(), m)).toEqual({
      ok: false,
      failure: "unlisted",
      name: "proof-mallory.json",
    });
  });

  it("refuses an unknown pack version", async () => {
    const p = await pack();
    p.pack.format_version = "canton-solvency-pack-v2";
    expect((await verifyPack(p, members())).ok).toBe(false);
  });

  it("commits to every entry", async () => {
    const p = await pack();
    const before = await packDigestHex(p.pack);
    p.pack.entries[0].sha256 = "00".repeat(32);
    expect(await packDigestHex(p.pack)).not.toBe(before);
  });

  it("refuses an index naming a path rather than a file", async () => {
    for (const name of ["../escape.json", "sub/report.json", ""]) {
      const p = await pack();
      p.pack.entries[0].name = name;
      expect(await verifyPack(p, members())).toEqual({ ok: false, failure: "unsafe-name", name });
    }
  });

  it("commits to the number of members", async () => {
    const p = await pack();
    const before = await packDigestHex(p.pack);
    p.pack.entries.pop();
    expect(await packDigestHex(p.pack)).not.toBe(before);
  });
});
