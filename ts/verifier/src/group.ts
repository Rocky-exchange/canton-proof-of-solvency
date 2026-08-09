/**
 * Client-side verification of group-level commitments (SPEC §13).
 *
 * Byte-for-byte mirror of the Rust `group` module; both sides assert the same
 * golden fixtures. A customer of a subsidiary can use this to check their
 * balance all the way up to a group's consolidated total, without ever seeing
 * a sibling entity's book.
 */

import { combineNodes, parseAmount18dp, type SolvencyNode } from "./verify";
import {
  lp,
  lpmap,
  expectLeafKind,
  reportDigestHex,
  verifyEd25519,
  verifyReport,
  type AmountMap,
  type ProofDocument,
  type SignedReport,
  type VerificationFailure,
  type VerificationResult,
} from "./report";

export const GROUP_MEMBERSHIP_FORMAT_VERSION = "canton-solvency-group-membership-v1";
export const GROUP_PROFILE = "solvency.group";
const ENTITY_DOMAIN = "rocky-solvency-entity-v1";

export type EntityRecord = { entity_id: string; root_hash: string; root_sums: AmountMap };

export type GroupMembershipDocument = {
  format_version: string;
  group_report_digest: string;
  entity: EntityRecord;
  steps: { sibling_hash: string; sibling_sums: AmountMap; sibling_on_left: boolean }[];
};

const encoder = new TextEncoder();

function concat(parts: Uint8Array[]) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function hexToBytes(hex: string) {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function parseSums(sums: AmountMap): Record<string, bigint> {
  return Object.fromEntries(Object.entries(sums).map(([a, v]) => [a, parseAmount18dp(v)]));
}

/**
 * `H(domain ‖ lp(entity_id) ‖ root_hash ‖ lpmap(sums))`. The identity is
 * bound in so a group cannot swap one subsidiary for another of equal total.
 */
export async function entityLeafNode(entity: EntityRecord): Promise<SolvencyNode> {
  const preimage = concat([
    encoder.encode(ENTITY_DOMAIN),
    lp(entity.entity_id),
    hexToBytes(entity.root_hash),
    lpmap(entity.root_sums),
  ]);
  return {
    hashHex: bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", preimage))),
    sums: parseSums(entity.root_sums),
  };
}

function fail(failure: VerificationFailure): VerificationResult {
  return { ok: false, failure };
}

/** Checks an entity is committed in the group's consolidated total. */
export async function verifyMembership(
  groupSigned: SignedReport,
  membership: GroupMembershipDocument,
  trustedPublicKeyHex: string
): Promise<VerificationResult> {
  if (membership.format_version !== GROUP_MEMBERSHIP_FORMAT_VERSION) {
    return fail({
      kind: "unsupported_version",
      field: "membership.format_version",
      found: membership.format_version,
    });
  }

  const { report } = groupSigned;
  const profileFailure = expectLeafKind(report, "entity");
  if (profileFailure) return profileFailure;

  let digest: string;
  let current: SolvencyNode;
  try {
    digest = await reportDigestHex(report);
    current = await entityLeafNode(membership.entity);
  } catch (e) {
    return fail({ kind: "malformed", detail: String(e) });
  }
  if (digest !== membership.group_report_digest) return fail({ kind: "digest_mismatch" });
  // The embedded key is display metadata; trust comes from the caller.
  if (groupSigned.signature.public_key !== trustedPublicKeyHex) {
    return fail({ kind: "unknown_signer" });
  }
  let signatureValid: boolean;
  try {
    signatureValid = await verifyEd25519(
      trustedPublicKeyHex,
      digest,
      groupSigned.signature.value
    );
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("Ed25519 is unavailable")) throw e;
    return fail({ kind: "malformed", detail: String(e) });
  }
  if (!signatureValid) return fail({ kind: "bad_signature" });

  try {
    for (const step of membership.steps) {
      const sibling: SolvencyNode = {
        hashHex: bytesToHex(hexToBytes(step.sibling_hash)),
        sums: parseSums(step.sibling_sums),
      };
      current = step.sibling_on_left
        ? await combineNodes(sibling, current)
        : await combineNodes(current, sibling);
    }
  } catch (e) {
    return fail({ kind: "malformed", detail: String(e) });
  }

  if (current.hashHex !== report.root_hash) return fail({ kind: "root_hash_mismatch" });

  const published = parseSums(report.root_sums);
  for (const asset of new Set([...Object.keys(current.sums), ...Object.keys(published)])) {
    if ((current.sums[asset] ?? 0n) !== (published[asset] ?? 0n)) {
      return fail({ kind: "root_sums_mismatch", asset });
    }
  }
  return { ok: true };
}

/**
 * A customer verified all the way to a group's consolidated total: their
 * proof against the entity's report, the entity against the group, and that
 * those two documents describe the same book.
 */
export async function verifyChain(
  groupSigned: SignedReport,
  membership: GroupMembershipDocument,
  entitySigned: SignedReport,
  proof: ProofDocument,
  groupTrustedKey: string,
  entityTrustedKey: string
): Promise<VerificationResult> {
  const inEntity = await verifyReport(entitySigned, proof, entityTrustedKey);
  if (!inEntity.ok) return inEntity;

  const inGroup = await verifyMembership(groupSigned, membership, groupTrustedKey);
  if (!inGroup.ok) return inGroup;

  if (membership.entity.root_hash !== entitySigned.report.root_hash) {
    return fail({ kind: "entity_root_mismatch" });
  }
  const claimed = parseSums(membership.entity.root_sums);
  const published = parseSums(entitySigned.report.root_sums);
  for (const asset of new Set([...Object.keys(claimed), ...Object.keys(published)])) {
    if ((claimed[asset] ?? 0n) !== (published[asset] ?? 0n)) {
      return fail({ kind: "entity_sums_mismatch", asset });
    }
  }
  return { ok: true };
}
