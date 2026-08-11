//! Assurance levels: what kind of evidence stands behind a published figure
//! (SPEC §16).
//!
//! Everything else here answers "does this document check out". That question
//! has two answers, and until now both were spelled the same way. A
//! liabilities total recomputed from committed leaves and a custody total that
//! the publisher simply signed both came back as verified, because both are —
//! against the only thing the verifier was asked to check.
//!
//! The gap is not cryptographic. `verify` proves that a published total equals
//! the sum of the leaves the publisher committed to. It cannot prove that
//! those leaves correspond to anything in the world. For customer liabilities
//! that is nearly enough, because each customer can check their own leaf and
//! will complain if it is short. For custody there is no such counterparty:
//! the publisher commits to a list of positions it wrote itself, and the
//! arithmetic over that list is impeccable regardless of whether the assets
//! exist.
//!
//! So a report carries a statement declaring, per field, what kind of evidence
//! it rests on, and the verifier establishes independently what it can
//! actually substantiate. A declaration the verifier cannot substantiate is a
//! failure — that is the whole mechanism. A taxonomy the publisher can assert
//! into being would document the over-claim rather than prevent it.

use crate::anchor::Anchor;
use crate::digest::report_digest_hex;
use crate::document::{ProofDocument, Report, SignedReport};
use crate::sign::verify_signature;
use crate::verify::VerificationFailure as F;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const ASSURANCE_FORMAT_VERSION: &str = "canton-solvency-assurance-v1";
pub const ATTESTATION_FORMAT_VERSION: &str = "canton-solvency-attestation-v1";

/// The kinds of evidence a figure can rest on.
///
/// Deliberately not a total order. Whether a custodian's signature outranks a
/// derivation from ledger state depends on the asset: for a tokenised position
/// the ledger is the asset, and for a treasury bill it is a pointer to a claim
/// someone else honours. A single ranking would have to be wrong for one of
/// them. `strength` exists for display, and orders only what can be ordered
/// without lying.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssuranceLevel {
    /// Withheld under the disclosure manifest. Not a weaker claim — no claim.
    NotDisclosed,
    /// The publisher signed for it and nothing else stands behind it.
    ClaimedOnly,
    /// The party that issued the asset signed for it. Self-attestation: the
    /// issuer is the party whose solvency is in question.
    IssuerAttested,
    /// A custodian, auditor or oracle signed for it — someone other than the
    /// publisher and other than the issuer.
    ThirdPartyAttested,
    /// Derived from named Canton state at a named offset, evidenced by an
    /// anchor that a reader can find on the ledger rather than on the
    /// publisher's web server.
    LedgerDerived,
    /// The verifier recomputed it from the commitments.
    ///
    /// Read this precisely: the published figure equals the sum of the leaves
    /// the publisher committed to. It does **not** establish that those leaves
    /// describe assets that exist, and no amount of cryptography here will.
    /// A custody report whose positions are invented recomputes perfectly.
    CryptographicallyVerified,
}

impl AssuranceLevel {
    /// For ordering displays only, and only where the order is defensible.
    ///
    /// `IssuerAttested` sits below `ThirdPartyAttested` because the issuer is
    /// attesting about itself. That is the one place this diverges from how
    /// the levels are usually listed, and it is deliberate: an institution
    /// vouching for its own reserves is the weaker of the two, not the
    /// stronger.
    pub fn strength(self) -> u8 {
        match self {
            Self::NotDisclosed => 0,
            Self::ClaimedOnly => 1,
            Self::IssuerAttested => 2,
            Self::ThirdPartyAttested => 3,
            Self::LedgerDerived => 4,
            Self::CryptographicallyVerified => 5,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotDisclosed => "not-disclosed",
            Self::ClaimedOnly => "claimed-only",
            Self::IssuerAttested => "issuer-attested",
            Self::ThirdPartyAttested => "third-party-attested",
            Self::LedgerDerived => "ledger-derived",
            Self::CryptographicallyVerified => "cryptographically-verified",
        }
    }
}

impl std::fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who is doing the attesting. The publisher is not on this list: a publisher
/// signing for its own figures is what `ClaimedOnly` already means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestorRole {
    Issuer,
    ThirdParty,
}

/// One outside party's signed statement about one field of one report.
///
/// Bound to the report by digest for the same reason coverage statements are:
/// without it, an attestation obtained for last quarter's figures could be
/// presented beside this quarter's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub format_version: String,
    pub report_digest: String,
    /// Which claim is being attested, using the same paths as the assurance
    /// statement.
    pub field: String,
    pub role: AttestorRole,
    /// Who is attesting, for display. Trust comes from the key, not from this.
    pub attestor: String,
    /// How they established it. Signed, but not proven by anything here — the
    /// same honest limitation `custody_basis` carries in §11.
    pub basis: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAttestation {
    pub attestation: Attestation,
    pub signature: crate::document::SignatureBlock,
}

/// What the publisher says each field rests on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceStatement {
    pub format_version: String,
    pub report_digest: String,
    pub levels: BTreeMap<String, AssuranceLevel>,
}

/// Everything the verifier was handed besides the report itself.
///
/// Absent evidence is not a failure — it lowers what can be established, which
/// is the point. A verifier given nothing but a signed report can still
/// substantiate `ClaimedOnly`, and a report declaring only that is honest.
#[derive(Default)]
pub struct Evidence<'a> {
    pub proof: Option<&'a ProofDocument>,
    pub anchor: Option<&'a Anchor>,
    pub attestations: &'a [SignedAttestation],
}

/// The keys the verifier trusts, and for what.
///
/// Attestor keys are supplied out of band exactly as the publisher key is
/// (§8.4). An attestation carrying its own key establishes nothing: the
/// question is never "is this signed" but "is this signed by someone I decided
/// to believe before I opened the document".
pub struct TrustedKeys {
    pub publisher: String,
    pub attestors: BTreeMap<String, AttestorRole>,
}

/// The field paths this verifier has an opinion about.
///
/// An unknown path is refused rather than ignored, matching how the manifest
/// treats one. Silently accepting a level for a field nobody checks is how a
/// declaration becomes decoration.
///
/// Deliberately the manifest's own vocabulary rather than a parallel one. Two
/// documents describing the same fields under different names cannot be
/// cross-checked, and the first thing this module needs to ask a manifest is
/// whether a field was withheld.
pub const KNOWN_FIELDS: &[&str] = crate::manifest::REPORT_RESIDENT_FIELDS;

/// SHA-256 over the attestation fields, length-prefixed, under its own domain
/// string (SPEC §16.3).
///
/// A separate domain from the report digest so an attestation signature can
/// never be replayed as a report signature, and so an attestor who signs for
/// one field has not signed for another.
pub fn attestation_digest(a: &Attestation) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ATTESTATION_DIGEST_DOMAIN);
    h.update(crate::digest::lp(&a.format_version));
    h.update(crate::digest::lp(&a.report_digest));
    h.update(crate::digest::lp(&a.field));
    h.update(crate::digest::lp(match a.role {
        AttestorRole::Issuer => "issuer",
        AttestorRole::ThirdParty => "third-party",
    }));
    h.update(crate::digest::lp(&a.attestor));
    h.update(crate::digest::lp(&a.basis));
    h.finalize().into()
}

pub const ATTESTATION_DIGEST_DOMAIN: &[u8] = b"rocky-solvency-attestation-v1";

/// Hex rendering of [`attestation_digest`].
pub fn attestation_digest_hex(a: &Attestation) -> String {
    hex::encode(attestation_digest(a))
}

/// Whether the field was genuinely withheld: the manifest says so *and* the
/// report carries nothing for it.
///
/// Both halves are required. §8.5's consistency check would already refuse a
/// report whose manifest withholds a field it publishes anyway, but that check
/// needs an inclusion proof and this path does not always have one. Trusting
/// the manifest alone here would let a report declare a published figure
/// `not-disclosed` and escape standing behind it.
fn withheld(report: &Report, field: &str) -> bool {
    let declared = report
        .manifest
        .as_ref()
        .is_some_and(|m| m.fields.get(field) == Some(&crate::manifest::Disclosure::Withheld));
    declared && !crate::manifest::carries_data(report, field)
}

/// Whether an anchor pins this exact report to ledger state.
///
/// Every field is checked, not just the digest. An anchor whose offset or
/// snapshot time disagrees with the report is not evidence about that report,
/// however well its digest matches — the digest already covers the report, so
/// a disagreement here means one of the two documents was edited after the
/// fact.
fn anchors(report: &Report, anchor: &Anchor, digest: &str) -> bool {
    anchor.format_version == crate::anchor::ANCHOR_FORMAT_VERSION
        && anchor.report_digest == digest
        && anchor.root_hash == report.root_hash
        && anchor.snapshot_time == report.snapshot_time
        && anchor.ledger_offset == report.ledger_offset
        && anchor.publisher == report.publisher
}

/// What the verifier can substantiate for each field, given the evidence.
///
/// Takes the signed report because recomputation runs through `verify`, which
/// checks the signature as part of establishing anything at all. Called
/// directly, this answers "what would the evidence support", which is what the
/// console needs in order to show a reader why a figure is only claimed.
pub fn establish(
    signed: &SignedReport,
    evidence: &Evidence,
    trusted: &TrustedKeys,
) -> BTreeMap<String, BTreeSet<AssuranceLevel>> {
    let report = &signed.report;
    let digest = report_digest_hex(report);
    let mut out = BTreeMap::new();

    for field in KNOWN_FIELDS {
        let mut levels = BTreeSet::new();
        if withheld(report, field) {
            // Nothing was published, so there is nothing to have evidence
            // about. Any other level would be a claim about absent data.
            levels.insert(AssuranceLevel::NotDisclosed);
            out.insert((*field).to_string(), levels);
            continue;
        }

        // The publisher signed the report, and the report contains this
        // figure. That is always available and never worth more than it says.
        levels.insert(AssuranceLevel::ClaimedOnly);

        // Only root_sums is bound into the tree. The merkle sum tree carries
        // each node's totals into its hash, so an inclusion proof that folds
        // to the published root also fixes the published totals. mark_prices
        // and disclosures are signed but uncommitted: no recomputation exists
        // for them, and claiming one would be exactly the over-claim this
        // module refuses.
        if *field == "root_sums"
            && evidence
                .proof
                .is_some_and(|p| crate::verify::verify(signed, p, &trusted.publisher).is_ok())
        {
            levels.insert(AssuranceLevel::CryptographicallyVerified);
        }

        // An anchor commits to the report digest, which covers every field, so
        // it lifts all of them at once.
        if evidence.anchor.is_some_and(|a| anchors(report, a, &digest)) {
            levels.insert(AssuranceLevel::LedgerDerived);
        }

        for signed in evidence.attestations {
            let a = &signed.attestation;
            if a.format_version != ATTESTATION_FORMAT_VERSION
                || a.field != *field
                || a.report_digest != digest
            {
                continue;
            }
            // Trust is by key and by role, decided before the document was
            // opened. An attestation carrying a role its key was not trusted
            // for establishes nothing, or a custodian key could vouch as an
            // issuer.
            if trusted.attestors.get(&signed.signature.public_key) != Some(&a.role) {
                continue;
            }
            if signed.signature.algorithm != crate::document::SIGNATURE_ALGORITHM {
                continue;
            }
            if verify_signature(
                &signed.signature.public_key,
                &attestation_digest(a),
                &signed.signature.value,
            )
            .is_ok()
            {
                levels.insert(match a.role {
                    AttestorRole::Issuer => AssuranceLevel::IssuerAttested,
                    AttestorRole::ThirdParty => AssuranceLevel::ThirdPartyAttested,
                });
            }
        }

        out.insert((*field).to_string(), levels);
    }
    out
}

/// Check a publisher's declarations against what the evidence supports.
///
/// Returns the accepted levels on success. The failure is always
/// [`VerificationFailure::OverClaimed`] naming the field, so a reader is told
/// which claim outran its evidence rather than that "the report is invalid".
///
/// [`VerificationFailure::OverClaimed`]: crate::verify::VerificationFailure::OverClaimed
pub fn verify_assurance(
    signed: &SignedReport,
    statement: &AssuranceStatement,
    evidence: &Evidence,
    trusted: &TrustedKeys,
) -> Result<BTreeMap<String, AssuranceLevel>, F> {
    if statement.format_version != ASSURANCE_FORMAT_VERSION {
        return Err(F::UnsupportedVersion {
            field: "assurance.format_version",
            found: statement.format_version.clone(),
        });
    }

    let digest = report_digest_hex(&signed.report);
    if statement.report_digest != digest {
        return Err(F::DigestMismatch);
    }

    // Everything below rests on the report being from the publisher the
    // caller trusts. Checking the statement against an unauthenticated report
    // would grade a document nobody vouched for.
    if signed.signature.public_key != trusted.publisher {
        return Err(F::UnknownSigner);
    }
    let digest_bytes = crate::digest::report_digest(&signed.report);
    verify_signature(&trusted.publisher, &digest_bytes, &signed.signature.value)
        .map_err(|_| F::BadSignature)?;

    for field in statement.levels.keys() {
        if !KNOWN_FIELDS.contains(&field.as_str()) {
            return Err(F::Malformed(format!(
                "assurance statement declares a level for {field:?}, which this \
                 verifier has no way to substantiate"
            )));
        }
    }

    let established = establish(signed, evidence, trusted);
    let mut accepted = BTreeMap::new();
    for (field, declared) in &statement.levels {
        let supported = established.get(field).cloned().unwrap_or_default();
        if !supported.contains(declared) {
            return Err(F::OverClaimed {
                field: field.clone(),
                declared: *declared,
                established: supported.into_iter().collect(),
            });
        }
        accepted.insert(field.clone(), *declared);
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden;
    use crate::sign::ReportSigner;

    fn publisher_key() -> String {
        ReportSigner::from_seed(&[7u8; 32]).public_key_hex()
    }

    fn trusted() -> TrustedKeys {
        TrustedKeys {
            publisher: golden::fixture().0.signature.public_key.clone(),
            attestors: BTreeMap::new(),
        }
    }

    fn statement(report: &SignedReport, levels: &[(&str, AssuranceLevel)]) -> AssuranceStatement {
        AssuranceStatement {
            format_version: ASSURANCE_FORMAT_VERSION.to_string(),
            report_digest: report_digest_hex(&report.report),
            levels: levels.iter().map(|(f, l)| (f.to_string(), *l)).collect(),
        }
    }

    #[test]
    fn a_figure_recomputed_from_the_commitments_may_be_declared_verified() {
        let (report, proof) = golden::fixture();
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        let declared = statement(
            &report,
            &[("root_sums", AssuranceLevel::CryptographicallyVerified)],
        );
        let established =
            verify_assurance(&report, &declared, &evidence, &trusted()).expect("honest statement");
        assert_eq!(
            established.get("root_sums"),
            Some(&AssuranceLevel::CryptographicallyVerified)
        );
    }

    /// The mechanism. Same report, same declaration, no proof handed over —
    /// so the verifier never recomputed anything and must not accept a claim
    /// that it did.
    #[test]
    fn declaring_verification_the_verifier_did_not_perform_is_refused() {
        let (report, _proof) = golden::fixture();
        let declared = statement(
            &report,
            &[("root_sums", AssuranceLevel::CryptographicallyVerified)],
        );
        let failure = verify_assurance(&report, &declared, &Evidence::default(), &trusted())
            .expect_err("no proof was supplied, so nothing was recomputed");
        assert!(
            matches!(&failure, F::OverClaimed { field, declared, .. }
                if field == "root_sums"
                    && *declared == AssuranceLevel::CryptographicallyVerified),
            "expected an over-claim on root_sums, got {failure}"
        );
    }

    /// A signature only establishes a level if the verifier already trusts the
    /// key for that role, which is the same rule §8.4 applies to publishers.
    #[test]
    fn an_attestation_from_an_untrusted_key_establishes_nothing() {
        let (report, _proof) = golden::fixture();
        let stranger = ReportSigner::from_seed(&[99u8; 32]);
        let attestation = Attestation {
            format_version: ATTESTATION_FORMAT_VERSION.to_string(),
            report_digest: report_digest_hex(&report.report),
            field: "root_sums".to_string(),
            role: AttestorRole::ThirdParty,
            attestor: "custodian::stranger".to_string(),
            basis: "we looked".to_string(),
        };
        let signed = SignedAttestation {
            signature: crate::document::SignatureBlock {
                algorithm: crate::document::SIGNATURE_ALGORITHM.to_string(),
                public_key: stranger.public_key_hex(),
                value: stranger.sign_digest(&attestation_digest(&attestation)),
            },
            attestation,
        };
        let evidence = Evidence {
            attestations: std::slice::from_ref(&signed),
            ..Default::default()
        };
        let declared = statement(
            &report,
            &[("root_sums", AssuranceLevel::ThirdPartyAttested)],
        );
        let failure = verify_assurance(&report, &declared, &evidence, &trusted())
            .expect_err("the attestor's key is not one the verifier trusts");
        assert!(
            matches!(&failure, F::OverClaimed { field, .. } if field == "root_sums"),
            "expected an over-claim on root_sums, got {failure}"
        );
    }

    /// The other direction of dishonesty: claiming to have withheld a figure
    /// that is sitting in the document.
    #[test]
    fn a_published_figure_cannot_be_declared_withheld() {
        let (report, proof) = golden::fixture();
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        let declared = statement(&report, &[("root_sums", AssuranceLevel::NotDisclosed)]);
        assert!(
            verify_assurance(&report, &declared, &evidence, &trusted()).is_err(),
            "root_sums is present in the report, so it was not withheld"
        );
    }

    /// `is_err()` would pass here even with the check deleted, because an
    /// unknown field establishes nothing and would be caught as an over-claim
    /// instead. Asserting the specific failure is what makes this test able to
    /// fail for the reason it names.
    #[test]
    fn a_field_the_verifier_has_no_opinion_about_is_refused() {
        let (report, proof) = golden::fixture();
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        let declared = statement(&report, &[("invented", AssuranceLevel::ClaimedOnly)]);
        let failure = verify_assurance(&report, &declared, &evidence, &trusted())
            .expect_err("a level for a field nobody checks is decoration");
        assert!(
            matches!(&failure, F::Malformed(m) if m.contains("invented")),
            "expected a malformed-statement failure naming the field, got {failure}"
        );
    }

    /// Mark prices enter the report digest, so they are signed — and they are
    /// not in the tree, so nothing recomputes them. This is the level that
    /// most invites over-claiming, because the report it sits in really does
    /// contain cryptographically verified figures.
    #[test]
    fn a_figure_that_is_only_signed_cannot_be_declared_recomputed() {
        let (report, proof) = golden::fixture();
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        for field in ["mark_prices", "disclosures.bad_debt"] {
            let declared = statement(
                &report,
                &[(field, AssuranceLevel::CryptographicallyVerified)],
            );
            let failure = verify_assurance(&report, &declared, &evidence, &trusted())
                .expect_err("nothing in the tree recomputes this field");
            assert!(
                matches!(&failure, F::OverClaimed { field: f, .. } if f == field),
                "expected an over-claim on {field}, got {failure}"
            );
        }
    }

    /// A withheld field can be declared withheld and nothing else: there is no
    /// data to have evidence about.
    #[test]
    fn a_withheld_field_supports_only_not_disclosed() {
        let (report, proof) = golden::withheld_fixture();
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        let trusted = TrustedKeys {
            publisher: report.signature.public_key.clone(),
            attestors: BTreeMap::new(),
        };

        let honest = statement(&report, &[("mark_prices", AssuranceLevel::NotDisclosed)]);
        verify_assurance(&report, &honest, &evidence, &trusted)
            .expect("the manifest withholds mark_prices, so not-disclosed is the truth");

        let overclaim = statement(&report, &[("mark_prices", AssuranceLevel::ClaimedOnly)]);
        let failure = verify_assurance(&report, &overclaim, &evidence, &trusted)
            .expect_err("nothing was published, so nothing was claimed");
        assert!(
            matches!(&failure, F::OverClaimed { field, .. } if field == "mark_prices"),
            "expected an over-claim on mark_prices, got {failure}"
        );
    }

    /// A manifest saying "withheld" over a field the report publishes anyway.
    /// §9.1 refuses such a report, but §16 can be reached without a proof, so
    /// it has to refuse it too rather than take the manifest's word.
    #[test]
    fn a_manifest_cannot_declare_a_published_figure_withheld() {
        use crate::manifest::{Disclosure, Manifest};
        let manifest = Manifest {
            audience: "public".to_string(),
            fields: [("mark_prices", Disclosure::Withheld)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        };
        // Mark prices are present, the manifest says they are not.
        let published = crate::produce::publish(
            &golden::leaves(),
            &crate::produce::ReportMetadata {
                manifest: Some(manifest),
                mark_prices: [("USDA".to_string(), 1_000_000_000_000_000_000u128)]
                    .into_iter()
                    .collect(),
                ..golden::metadata()
            },
            &golden::signer(),
        )
        .unwrap();
        let report = published.signed_report;
        let trusted = TrustedKeys {
            publisher: report.signature.public_key.clone(),
            attestors: BTreeMap::new(),
        };
        let declared = statement(&report, &[("mark_prices", AssuranceLevel::NotDisclosed)]);
        let failure = verify_assurance(&report, &declared, &Evidence::default(), &trusted)
            .expect_err("the figure is sitting in the report");
        assert!(
            matches!(&failure, F::OverClaimed { field, .. } if field == "mark_prices"),
            "expected an over-claim on mark_prices, got {failure}"
        );
    }

    /// The other direction: a field that *is* published cannot be dressed up
    /// as withheld to avoid standing behind it.
    #[test]
    fn a_disclosed_field_cannot_borrow_the_withheld_level() {
        let (report, proof) = golden::withheld_fixture();
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        let trusted = TrustedKeys {
            publisher: report.signature.public_key.clone(),
            attestors: BTreeMap::new(),
        };
        let declared = statement(&report, &[("root_sums", AssuranceLevel::NotDisclosed)]);
        assert!(
            verify_assurance(&report, &declared, &evidence, &trusted).is_err(),
            "root_sums is published in this report"
        );
    }

    /// An assurance statement is worth having only if it cannot be moved.
    /// Without the digest binding, a statement earned by a report backed by
    /// real attestations could be presented beside a later report that has
    /// none — the same transferability that coverage statements exist to stop.
    #[test]
    fn a_statement_bound_to_another_report_is_refused() {
        let (report, proof) = golden::fixture();
        let (other, _) = golden::withheld_fixture();
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        let borrowed = statement(
            &other,
            &[("root_sums", AssuranceLevel::CryptographicallyVerified)],
        );
        assert!(
            matches!(
                verify_assurance(&report, &borrowed, &evidence, &trusted()),
                Err(F::DigestMismatch)
            ),
            "a statement naming a different report says nothing about this one"
        );
    }

    /// Grading a document nobody vouched for would let an attacker publish a
    /// report, declare it fully verified, and have the verifier agree — the
    /// recomputation succeeds, because it is their tree.
    #[test]
    fn a_report_from_an_untrusted_publisher_is_not_graded() {
        let (report, proof) = golden::fixture();
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        let stranger = TrustedKeys {
            publisher: ReportSigner::from_seed(&[42u8; 32]).public_key_hex(),
            attestors: BTreeMap::new(),
        };
        let declared = statement(&report, &[("root_sums", AssuranceLevel::ClaimedOnly)]);
        assert!(
            matches!(
                verify_assurance(&report, &declared, &evidence, &stranger),
                Err(F::UnknownSigner)
            ),
            "the report is not signed by the key this verifier trusts"
        );
    }

    /// The right key with the wrong signature. Checking who signed without
    /// checking that they did is the shape of bug that leaves a scheme looking
    /// intact from the outside.
    #[test]
    fn a_report_whose_signature_does_not_verify_is_not_graded() {
        let (mut report, proof) = golden::fixture();
        let good = report.signature.value.clone();
        // Flip one hex digit, keeping it well-formed so this fails at
        // verification rather than at parsing.
        let flipped = if good.starts_with('a') { 'b' } else { 'a' };
        report.signature.value = format!("{flipped}{}", &good[1..]);
        let evidence = Evidence {
            proof: Some(&proof),
            ..Default::default()
        };
        let declared = statement(&report, &[("root_sums", AssuranceLevel::ClaimedOnly)]);
        assert!(
            matches!(
                verify_assurance(&report, &declared, &evidence, &trusted()),
                Err(F::BadSignature)
            ),
            "the signature does not verify under the trusted key"
        );
    }

    /// Recomputation is about the commitments, not about the world. This is
    /// the sentence the whole module exists to keep true, so it is worth a
    /// test that fails if the levels are ever collapsed back together.
    #[test]
    fn verification_and_existence_are_different_claims() {
        assert!(
            AssuranceLevel::CryptographicallyVerified.strength()
                > AssuranceLevel::ThirdPartyAttested.strength(),
            "recomputation is stronger evidence about the commitments"
        );
        assert!(
            AssuranceLevel::IssuerAttested.strength()
                < AssuranceLevel::ThirdPartyAttested.strength(),
            "an issuer vouching for itself is weaker than an independent party"
        );
        let _ = publisher_key();
    }
}
