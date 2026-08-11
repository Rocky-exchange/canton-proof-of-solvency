/**
 * Coverage (SPEC §11) and anchor chains (SPEC §12), as library functions.
 *
 * Both sets of rules previously lived inside the conformance runner, which
 * meant the corpus was checking them against themselves and the browser had no
 * way to verify either. It also hid a real divergence: the runner's coverage
 * check never verified a signature, while the Rust implementation does, and no
 * case existed to notice. Both implementations claim `coverage-v1` in their
 * compatibility statements.
 *
 * These return typed failures for the same reason every other entry point
 * does — so a caller can say which rule refused a document, and so the corpus
 * can check that the reason is the declared one.
 */

import { anchorDigestHex, type Anchor } from "./anchor";
import { reportDigestHex, verifyEd25519, type Report, type SignedReport } from "./report";
import { instantSkew, keysOf, parseAmount18dp } from "./verify";

export type CoverageStatement = {
  format_version: string;
  custody_report_digest: string;
  liabilities_report_digest: string;
  custody_basis: string;
};

export type CoverageFailure =
  | { kind: "unsupported_version"; field: string; found: string }
  | { kind: "profile"; detail: string }
  | { kind: "digest_mismatch" }
  | { kind: "unknown_signer" }
  | { kind: "bad_signature" }
  | { kind: "shortfall"; asset: string }
  | { kind: "temporal_mismatch"; detail: string }
  | { kind: "malformed"; detail: string };

export type CoverageResult = { ok: true } | { ok: false; failure: CoverageFailure };

const fail = (failure: CoverageFailure): CoverageResult => ({ ok: false, failure });

/** §18.4 tolerances, mirroring the Rust constants. */
export const EXACT = 0;
export const SAME_RUN = 300;

async function checkSignature(
  signed: SignedReport,
  trustedKeyHex: string
): Promise<CoverageFailure | null> {
  // §8.4: the embedded key is display metadata. Trust is the caller's input.
  if (signed.signature.public_key.toLowerCase() !== trustedKeyHex.trim().toLowerCase()) {
    return { kind: "unknown_signer" };
  }
  const digest = await reportDigestHex(signed.report);
  const valid = await verifyEd25519(trustedKeyHex.trim(), digest, signed.signature.value);
  return valid ? null : { kind: "bad_signature" };
}

/**
 * Custody against liabilities, bound by a statement naming both by digest.
 *
 * Driven by what is owed: an asset held but not owed is not a coverage
 * question, and an asset owed and held nowhere is the worst case rather than
 * an absent row.
 */
export async function verifyCoverage(
  custody: SignedReport,
  liabilities: SignedReport,
  statement: CoverageStatement,
  custodyTrustedKeyHex: string,
  liabilitiesTrustedKeyHex: string,
  /**
   * §18.4. How far apart the two sides may be and still be one claim, in
   * seconds. Supplied by the caller, never by the publisher — a publisher
   * declaring its own tolerance would declare whatever pairing it wanted.
   */
  maxSkewSeconds: number = SAME_RUN
): Promise<CoverageResult> {
  try {
    if (statement.format_version !== "canton-solvency-coverage-v1") {
      return fail({
        kind: "unsupported_version",
        field: "statement.format_version",
        found: statement.format_version,
      });
    }
    if (custody.report.profile !== "coverage.custody") {
      return fail({
        kind: "profile",
        detail: `expected a coverage.custody report here, got "${custody.report.profile}"`,
      });
    }
    if (liabilities.report.profile !== "solvency.liabilities") {
      return fail({
        kind: "profile",
        detail: `expected a solvency.liabilities report here, got "${liabilities.report.profile}"`,
      });
    }

    // The statement is what binds the two, so today's assets cannot be shown
    // against last quarter's smaller liabilities.
    if ((await reportDigestHex(custody.report)) !== statement.custody_report_digest) {
      return fail({ kind: "digest_mismatch" });
    }
    if ((await reportDigestHex(liabilities.report)) !== statement.liabilities_report_digest) {
      return fail({ kind: "digest_mismatch" });
    }

    for (const [signed, key] of [
      [custody, custodyTrustedKeyHex],
      [liabilities, liabilitiesTrustedKeyHex],
    ] as const) {
      const failure = await checkSignature(signed, key);
      if (failure) return fail(failure);
    }

    // Assets at their peak against liabilities at their trough. Binding the
    // two by digest stops substitution and does not touch this: the publisher
    // signed the statement that pairs them.
    const skew = instantSkew(
      custody.report.snapshot_time,
      liabilities.report.snapshot_time
    );
    if (skew === undefined) {
      return fail({
        kind: "malformed",
        detail: "a snapshot_time is not a §18.1 timestamp",
      });
    }
    if (skew > maxSkewSeconds) {
      return fail({
        kind: "temporal_mismatch",
        detail:
          `custody is as of ${custody.report.snapshot_time} and liabilities as of ` +
          `${liabilities.report.snapshot_time}, ${skew}s apart, beyond the ` +
          `${maxSkewSeconds}s the caller allows`,
      });
    }

    for (const asset of keysOf(liabilities.report.root_sums)) {
      const owed = parseAmount18dp((liabilities.report.root_sums as Record<string, string>)[asset]);
      const heldRaw = (custody.report.root_sums as Record<string, string>)[`held/${asset}`] ?? "0";
      if (parseAmount18dp(heldRaw) < owed) {
        return fail({ kind: "shortfall", asset });
      }
    }
    return { ok: true };
  } catch (e) {
    return fail({ kind: "malformed", detail: String(e) });
  }
}

export type ChainFailure =
  | { kind: "unsupported_version"; index: number; found: string }
  | { kind: "not_genesis" }
  | { kind: "broken"; index: number }
  | { kind: "publisher_changed"; index: number }
  | { kind: "went_backwards"; index: number; field: string }
  | { kind: "malformed"; detail: string };

export type ChainResult = { ok: true } | { ok: false; failure: ChainFailure };

/**
 * Walk a publisher's anchor history (SPEC §12.1).
 *
 * Each anchor names its predecessor by digest, recomputed here rather than
 * taken on trust — the stored digest on a ledger contract is the publisher's
 * assertion, and linking a chain by trusting it gives back exactly the power
 * anchoring removes.
 */
export async function verifyAnchorChain(history: Anchor[]): Promise<ChainResult> {
  try {
    for (const [index, anchor] of history.entries()) {
      if (anchor.format_version !== "canton-solvency-anchor-v1") {
        return {
          ok: false,
          failure: {
            kind: "unsupported_version",
            index,
            found: anchor.format_version,
          },
        };
      }
      if (index === 0) {
        if (anchor.prev_anchor !== undefined) return { ok: false, failure: { kind: "not_genesis" } };
        continue;
      }
      const previous = history[index - 1];
      if (anchor.prev_anchor === undefined) {
        return { ok: false, failure: { kind: "broken", index } };
      }
      if (anchor.prev_anchor !== (await anchorDigestHex(previous))) {
        return { ok: false, failure: { kind: "broken", index } };
      }
      if (anchor.publisher !== previous.publisher) {
        return { ok: false, failure: { kind: "publisher_changed", index } };
      }
      // A restated instant and a rewound offset are both histories being
      // rewritten, which is the thing anchoring exists to make visible.
      if (anchor.snapshot_time <= previous.snapshot_time) {
        return { ok: false, failure: { kind: "went_backwards", index, field: "snapshot_time" } };
      }
      if (anchor.ledger_offset < previous.ledger_offset) {
        return { ok: false, failure: { kind: "went_backwards", index, field: "ledger_offset" } };
      }
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, failure: { kind: "malformed", detail: String(e) } };
  }
}

/** A report is only ever verified against a key the caller supplies. */
export type { Report, SignedReport };
