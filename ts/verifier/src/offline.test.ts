import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verifyFromText, type Fact } from "./offline";

const fixture = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url)), "utf8");

const KEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const report = () => fixture("report.golden.json");
const proof = () => fixture("proof.golden.json");

const fact = (facts: Fact[], label: string): Fact | undefined =>
  facts.find((f) => f.label.toLowerCase().includes(label.toLowerCase()));

describe("offline verifier", () => {
  it("verifies the golden publication", async () => {
    const vm = await verifyFromText(report(), proof(), KEY);
    expect(vm.status).toBe("verified");
    expect(vm.headline.toLowerCase()).toContain("verified");
  });

  it("labels every displayed value with how it is known", async () => {
    const vm = await verifyFromText(report(), proof(), KEY);
    expect(vm.facts.length).toBeGreaterThan(0);
    for (const f of vm.facts) {
      expect(["verified", "disclosed"]).toContain(f.provenance);
    }
  });

  /**
   * The distinction the whole page exists to make: your balance and the
   * totals were recomputed here, but the snapshot metadata is only asserted.
   */
  it("marks recomputed values verified and merely-asserted metadata disclosed", async () => {
    const vm = await verifyFromText(report(), proof(), KEY);
    expect(fact(vm.facts, "your balance")?.provenance).toBe("verified");
    expect(fact(vm.facts, "total")?.provenance).toBe("verified");
    expect(fact(vm.facts, "publisher")?.provenance).toBe("disclosed");
    expect(fact(vm.facts, "snapshot")?.provenance).toBe("disclosed");
  });

  it("shows the user their own balance from the proof", async () => {
    const vm = await verifyFromText(report(), proof(), KEY);
    expect(fact(vm.facts, "your balance")?.value).toContain("1.000000000000000001");
  });

  it("reports a tampered balance as failed, not as an error", async () => {
    const tampered = proof().replace("0.250000000000000000", "9.250000000000000000");
    const vm = await verifyFromText(report(), tampered, KEY);
    expect(vm.status).toBe("failed");
    expect(vm.detail).toContain("root");
  });

  it("reports an untrusted signer distinctly from a forged proof", async () => {
    const vm = await verifyFromText(report(), proof(), "ab".repeat(32));
    expect(vm.status).toBe("failed");
    expect(vm.detail.toLowerCase()).toContain("trusted key");
  });

  it("reports malformed input as an error rather than a failed verification", async () => {
    const vm = await verifyFromText("{ not json", proof(), KEY);
    expect(vm.status).toBe("error");
    expect(vm.facts).toHaveLength(0);
  });

  it("rejects a key that is not 32 bytes of hex before verifying anything", async () => {
    const vm = await verifyFromText(report(), proof(), "abc");
    expect(vm.status).toBe("error");
    expect(vm.detail).toContain("64");
  });

  it("does not claim verified when the proof belongs to another report", async () => {
    const stale = proof().replace(/"report_digest": "[0-9a-f]{64}"/, `"report_digest": "${"cd".repeat(32)}"`);
    const vm = await verifyFromText(report(), stale, KEY);
    expect(vm.status).toBe("failed");
    expect(vm.detail.toLowerCase()).toContain("different report");
  });

  describe("with a group", () => {
    const group = () => ({
      reportText: fixture("group-report.golden.json"),
      membershipText: fixture("group-membership.golden.json"),
    });

    it("verifies a customer up to the consolidated group total", async () => {
      const vm = await verifyFromText(report(), proof(), KEY, group());
      expect(vm.status).toBe("verified");
      expect(vm.headline.toLowerCase()).toContain("group");
    });

    it("shows the consolidated total as recomputed, not merely asserted", async () => {
      const vm = await verifyFromText(report(), proof(), KEY, group());
      const consolidated = fact(vm.facts, "consolidated");
      expect(consolidated?.provenance).toBe("verified");
      expect(consolidated?.value).toContain("143.500000000000000001");
    });

    it("names the entity the customer belongs to", async () => {
      const vm = await verifyFromText(report(), proof(), KEY, group());
      expect(fact(vm.facts, "entity")?.value).toContain("golden-entity-a");
    });

    /// The chain check that stops two independently valid halves being
    /// jointly meaningless.
    it("fails when the membership describes a different entity's book", async () => {
      const g = group();
      g.membershipText = g.membershipText.replace(
        /"root_hash": "[0-9a-f]{64}"/,
        `"root_hash": "${"ab".repeat(32)}"`
      );
      const vm = await verifyFromText(report(), proof(), KEY, g);
      expect(vm.status).toBe("failed");
    });

    it("fails when the group report is signed by an untrusted key", async () => {
      const vm = await verifyFromText(report(), proof(), KEY, {
        ...group(),
        keyHex: "ab".repeat(32),
      });
      expect(vm.status).toBe("failed");
      expect(vm.detail.toLowerCase()).toContain("trusted key");
    });

    it("still reports a broken customer proof rather than a group problem", async () => {
      const tampered = proof().replace("0.250000000000000000", "9.250000000000000000");
      const vm = await verifyFromText(report(), tampered, KEY, group());
      expect(vm.status).toBe("failed");
      expect(vm.detail).toContain("root");
    });

    it("treats a malformed group file as an error, not a failed verification", async () => {
      const vm = await verifyFromText(report(), proof(), KEY, {
        reportText: "{ not json",
        membershipText: fixture("group-membership.golden.json"),
      });
      expect(vm.status).toBe("error");
    });
  });
});
