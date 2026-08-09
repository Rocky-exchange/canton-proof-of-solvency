//! Consumer side: the five-step check of a proof against a signed report
//! (SPEC §9).

use crate::digest::report_digest;
use crate::document::{
    ProofDocument, SignedReport, PROOF_FORMAT_VERSION, REPORT_FORMAT_VERSION, SIGNATURE_ALGORITHM,
};

/// Why a verification failed. A bare boolean cannot distinguish a tampered
/// balance from a stale proof, and the console needs to render which check
/// broke.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationFailure {
    UnsupportedVersion {
        field: &'static str,
        found: String,
    },
    /// The proof names a different report than the one supplied.
    DigestMismatch,
    /// The report is signed, but not by the key the verifier trusts.
    UnknownSigner,
    BadSignature,
    RootHashMismatch,
    /// The root hash checks out but the published totals do not match what
    /// the committed leaves actually sum to.
    RootSumsMismatch {
        asset: String,
    },
    /// A group membership describes a different root than the entity's own
    /// report publishes — the two documents are not about the same book.
    EntityRootMismatch,
    /// Same, for the entity's totals.
    EntitySumsMismatch {
        asset: String,
    },
    /// The declared profile is not in the registry, or the report does not
    /// satisfy it.
    Profile {
        detail: String,
    },
    /// A v1 report carrying a manifest, or a v2 report without one.
    ManifestPresence {
        detail: &'static str,
    },
    /// The manifest disagrees with what the report actually carries, or names
    /// a field the verifier has no opinion about.
    ManifestInconsistent {
        path: String,
        detail: String,
    },
    Malformed(String),
}

impl std::fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { field, found } => {
                write!(f, "unsupported {field}: {found:?}")
            }
            Self::DigestMismatch => write!(f, "proof belongs to a different report"),
            Self::UnknownSigner => write!(f, "report is not signed by the trusted key"),
            Self::BadSignature => write!(f, "report signature does not verify"),
            Self::RootHashMismatch => write!(f, "proof does not fold to the published root"),
            Self::RootSumsMismatch { asset } => {
                write!(
                    f,
                    "published total for {asset} disagrees with the committed leaves"
                )
            }
            Self::EntityRootMismatch => write!(
                f,
                "the group membership and the entity report describe different roots"
            ),
            Self::EntitySumsMismatch { asset } => write!(
                f,
                "the group membership and the entity report disagree on the {asset} total"
            ),
            Self::Profile { detail } => write!(f, "{detail}"),
            Self::ManifestPresence { detail } => write!(f, "{detail}"),
            Self::ManifestInconsistent { path, detail } => {
                write!(
                    f,
                    "manifest disagrees with the report about {path}: {detail}"
                )
            }
            Self::Malformed(what) => write!(f, "malformed document: {what}"),
        }
    }
}

impl std::error::Error for VerificationFailure {}

use canton_solvency_merkle::{leaf_node, Node, Proof, ProofStep};
use std::collections::BTreeMap;
use VerificationFailure as F;

pub(crate) fn hash32(hex_str: &str, what: &str) -> Result<[u8; 32], VerificationFailure> {
    hex::decode(hex_str)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| F::Malformed(format!("{what} is not 32 bytes of hex")))
}

pub(crate) fn expect_version(
    field: &'static str,
    found: &str,
    want: &str,
) -> Result<(), VerificationFailure> {
    if found == want {
        Ok(())
    } else {
        Err(F::UnsupportedVersion {
            field,
            found: found.to_string(),
        })
    }
}

/// Recompute the leaf, fold the path, and compare both the hash and the
/// per-asset totals against the signed report.
pub fn verify(
    signed: &SignedReport,
    proof: &ProofDocument,
    trusted_public_key_hex: &str,
) -> Result<(), VerificationFailure> {
    let report = &signed.report;
    check_report_version_and_manifest(report)?;
    // A customer inclusion proof cannot belong to a tree whose leaves are
    // entities; without this it would fail later as an opaque hash mismatch.
    expect_leaf_kind(report, crate::profile::LeafKind::Customer)?;
    expect_version(
        "proof.format_version",
        &proof.format_version,
        PROOF_FORMAT_VERSION,
    )?;
    expect_version(
        "signature.algorithm",
        &signed.signature.algorithm,
        SIGNATURE_ALGORITHM,
    )?;

    let salt = hash32(&proof.leaf.salt, "leaf salt")?;
    let balances: Vec<(String, u128)> = proof.leaf.balances.clone().into_iter().collect();
    let leaf = leaf_node(&salt, &proof.leaf.user_id, &balances)
        .map_err(|e| F::Malformed(e.to_string()))?;

    verify_against_report(
        signed,
        leaf,
        &proof.steps,
        &proof.report_digest,
        trusted_public_key_hex,
    )
}

/// Validates the declared profile and requires the tree's leaves to be what
/// the caller is about to present a proof for.
pub(crate) fn expect_leaf_kind(
    report: &crate::document::Report,
    wanted: crate::profile::LeafKind,
) -> Result<(), VerificationFailure> {
    let rules = crate::profile::validate(report).map_err(|e| F::Profile {
        detail: match e {
            crate::profile::ProfileError::Unknown { found } => {
                format!("profile {found:?} is not in the registry")
            }
            crate::profile::ProfileError::Violation { profile, detail } => {
                format!("profile {profile}: {detail}")
            }
        },
    })?;
    if rules.leaf != wanted {
        return Err(F::Profile {
            detail: format!(
                "profile {} commits to {:?} leaves; this proof is for {:?} leaves",
                rules.name, rules.leaf, wanted
            ),
        });
    }
    Ok(())
}

/// v1 and v2 differ only in the manifest and the digest domain; everything
/// after is shared.
pub(crate) fn check_report_version_and_manifest(
    report: &crate::document::Report,
) -> Result<(), VerificationFailure> {
    use crate::document::REPORT_FORMAT_VERSION_V2;
    match report.format_version.as_str() {
        REPORT_FORMAT_VERSION => {
            if report.manifest.is_some() {
                return Err(F::ManifestPresence {
                    detail: "a v1 report cannot carry a manifest; the v1 digest does not cover it",
                });
            }
            Ok(())
        }
        REPORT_FORMAT_VERSION_V2 => {
            let manifest = report.manifest.as_ref().ok_or(F::ManifestPresence {
                detail: "a v2 report must carry a disclosure manifest",
            })?;
            check_manifest_consistency(report, manifest)
        }
        found => Err(F::UnsupportedVersion {
            field: "report.format_version",
            found: found.to_string(),
        }),
    }
}

/// A manifest that merely asserted things would be decoration. Every claim it
/// makes about a field living in the report body is checked against what the
/// body actually carries.
fn check_manifest_consistency(
    report: &crate::document::Report,
    manifest: &crate::manifest::Manifest,
) -> Result<(), VerificationFailure> {
    use crate::manifest::{Disclosure, KNOWN_FIELDS, REPORT_RESIDENT_FIELDS};

    for (path, state) in &manifest.fields {
        if !KNOWN_FIELDS.contains(&path.as_str()) {
            return Err(F::ManifestInconsistent {
                path: path.clone(),
                detail: "not a field this format defines".to_string(),
            });
        }
        if !REPORT_RESIDENT_FIELDS.contains(&path.as_str()) {
            continue; // e.g. customer_balances: attested through the commitment
        }

        let carries_data = match path.as_str() {
            "root_sums" => !report.root_sums.is_empty(),
            "mark_prices" => !report.mark_prices.is_empty(),
            "disclosures.bad_debt" => !report.disclosures.bad_debt.is_empty(),
            "disclosures.excluded_house_accounts" => report.disclosures.excluded_house_accounts > 0,
            "disclosures.excluded_house_totals" => {
                !report.disclosures.excluded_house_totals.is_empty()
            }
            _ => unreachable!("checked against REPORT_RESIDENT_FIELDS above"),
        };

        match state {
            Disclosure::Published if !carries_data => {
                return Err(F::ManifestInconsistent {
                    path: path.clone(),
                    detail: "declared published but the report carries no data for it".to_string(),
                })
            }
            Disclosure::Withheld | Disclosure::Committed if carries_data => {
                return Err(F::ManifestInconsistent {
                    path: path.clone(),
                    detail: format!(
                        "declared {} but the report publishes it anyway",
                        state.as_str()
                    ),
                })
            }
            _ => {}
        }
    }
    Ok(())
}

/// The tail shared by customer proofs (§9.1) and group memberships (§13):
/// bind to the report, check the signature, fold, compare hash *and* sums.
pub(crate) fn verify_against_report(
    signed: &SignedReport,
    leaf: Node,
    steps: &[crate::document::ProofStepDocument],
    expected_digest_hex: &str,
    trusted_public_key_hex: &str,
) -> Result<(), VerificationFailure> {
    let report = &signed.report;
    let digest = report_digest(report);
    if hex::encode(digest) != expected_digest_hex {
        return Err(F::DigestMismatch);
    }

    // The embedded key is display metadata; trust comes from the caller.
    if signed.signature.public_key != trusted_public_key_hex {
        return Err(F::UnknownSigner);
    }
    crate::sign::verify_signature(trusted_public_key_hex, &digest, &signed.signature.value)
        .map_err(|e| match e {
            crate::sign::SignatureError::BadSignature => F::BadSignature,
            other => F::Malformed(other.to_string()),
        })?;

    let steps = steps
        .iter()
        .map(|step| {
            Ok(ProofStep {
                sibling: Node {
                    hash: hash32(&step.sibling_hash, "sibling hash")?,
                    sums: step.sibling_sums.clone(),
                },
                sibling_on_left: step.sibling_on_left,
            })
        })
        .collect::<Result<Vec<_>, VerificationFailure>>()?;

    let root_hash = hash32(&report.root_hash, "report root hash")?;
    let folded = fold(&leaf, &Proof { steps })?;

    if folded.hash != root_hash {
        return Err(F::RootHashMismatch);
    }
    // A dishonest publisher can commit an honest tree and still understate
    // the totals it prints, so the sums are compared independently.
    if let Some(asset) = first_sum_disagreement(&folded.sums, &report.root_sums) {
        return Err(F::RootSumsMismatch { asset });
    }
    Ok(())
}

fn fold(leaf: &Node, proof: &Proof) -> Result<Node, VerificationFailure> {
    let mut current = leaf.clone();
    for step in &proof.steps {
        let (left, right) = if step.sibling_on_left {
            (&step.sibling, &current)
        } else {
            (&current, &step.sibling)
        };
        current = combine(left, right)?;
    }
    Ok(current)
}

/// Mirrors the core crate's internal node rule. Kept here rather than
/// exported from the core so the verifier's failures stay typed.
fn combine(left: &Node, right: &Node) -> Result<Node, VerificationFailure> {
    use canton_solvency_merkle::format_amount_18dp;
    use sha2::{Digest, Sha256};

    let mut sums = left.sums.clone();
    for (asset, v) in &right.sums {
        let slot = sums.entry(asset.clone()).or_insert(0);
        *slot = slot
            .checked_add(*v)
            .ok_or_else(|| F::Malformed(format!("sum overflow on asset {asset:?}")))?;
    }
    let canonical = sums
        .iter()
        .map(|(asset, v)| format!("{asset}:{}", format_amount_18dp(*v)))
        .collect::<Vec<_>>()
        .join("|");

    let mut h = Sha256::new();
    h.update(b"rocky-solvency-node-v1");
    h.update(left.hash);
    h.update(right.hash);
    h.update(canonical.as_bytes());
    Ok(Node {
        hash: h.finalize().into(),
        sums,
    })
}

/// Absent and zero are the same claim, so only real disagreements count.
fn first_sum_disagreement(
    folded: &BTreeMap<String, u128>,
    published: &BTreeMap<String, u128>,
) -> Option<String> {
    folded
        .keys()
        .chain(published.keys())
        .find(|asset| {
            folded.get(*asset).copied().unwrap_or(0) != published.get(*asset).copied().unwrap_or(0)
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::Report;
    use crate::produce::{publish, LeafInput, Publication, ReportMetadata};
    use crate::sign::ReportSigner;
    use canton_solvency_merkle::leaf_salt;
    use std::collections::BTreeMap;

    const SEED: [u8; 32] = [7u8; 32];

    fn leaves(n: usize) -> Vec<LeafInput> {
        (1..=n)
            .map(|i| {
                let user_id = format!("user-{i}");
                LeafInput {
                    salt: leaf_salt(b"master", &user_id),
                    // Two assets: dropping one must still leave a report that
                    // satisfies its profile, so the sum comparison is what
                    // catches it rather than the vacuity check.
                    balances: [
                        ("USDA".to_string(), i as u128 * 1_000_000_000_000_000_000),
                        ("CBTC".to_string(), i as u128 * 1_000_000_000_000_000),
                    ]
                    .into_iter()
                    .collect(),
                    user_id,
                }
            })
            .collect()
    }

    fn metadata() -> ReportMetadata {
        ReportMetadata {
            profile: "solvency.liabilities".to_string(),
            publisher: "rocky::122099".to_string(),
            snapshot_time: "2026-08-09T00:00:00Z".to_string(),
            ledger_offset: "000000000000012345".to_string(),
            mark_prices: BTreeMap::new(),
            disclosures: Default::default(),
            manifest: None,
        }
    }

    fn signer() -> ReportSigner {
        ReportSigner::from_seed(&SEED)
    }

    fn publication(n: usize) -> Publication {
        publish(&leaves(n), &metadata(), &signer()).unwrap()
    }

    /// A publisher who edits the report and re-signs it properly, re-binding
    /// every proof to the new digest. This is the realistic adversary: the
    /// signature is valid, so only the arithmetic can catch them.
    fn restate(mut pubn: Publication, edit: impl Fn(&mut Report)) -> Publication {
        edit(&mut pubn.signed_report.report);
        let digest = report_digest(&pubn.signed_report.report);
        pubn.signed_report.signature.value = signer().sign_digest(&digest);
        let digest_hex = hex::encode(digest);
        for proof in &mut pubn.proofs {
            proof.report_digest = digest_hex.clone();
        }
        pubn
    }

    fn check(pubn: &Publication, i: usize) -> Result<(), VerificationFailure> {
        verify(
            &pubn.signed_report,
            &pubn.proofs[i],
            &signer().public_key_hex(),
        )
    }

    #[test]
    fn every_proof_in_a_valid_publication_verifies() {
        let pubn = publication(5);
        for i in 0..5 {
            assert_eq!(check(&pubn, i), Ok(()), "proof {i}");
        }
    }

    #[test]
    fn a_proof_for_a_different_report_is_rejected() {
        let today = publication(5);
        let yesterday = publish(
            &leaves(5),
            &ReportMetadata {
                snapshot_time: "2026-08-08T00:00:00Z".to_string(),
                ..metadata()
            },
            &signer(),
        )
        .unwrap();
        assert_eq!(
            verify(
                &today.signed_report,
                &yesterday.proofs[0],
                &signer().public_key_hex()
            ),
            Err(VerificationFailure::DigestMismatch)
        );
    }

    #[test]
    fn a_report_signed_by_an_untrusted_key_is_rejected() {
        let pubn = publish(
            &leaves(3),
            &metadata(),
            &ReportSigner::from_seed(&[9u8; 32]),
        )
        .unwrap();
        assert_eq!(
            verify(
                &pubn.signed_report,
                &pubn.proofs[0],
                &signer().public_key_hex()
            ),
            Err(VerificationFailure::UnknownSigner)
        );
    }

    #[test]
    fn a_forged_signature_under_the_trusted_key_is_rejected() {
        let mut pubn = publication(3);
        pubn.signed_report.signature.value = "11".repeat(64);
        assert_eq!(check(&pubn, 0), Err(VerificationFailure::BadSignature));
    }

    #[test]
    fn a_tampered_leaf_balance_no_longer_folds_to_the_root() {
        let mut pubn = publication(5);
        pubn.proofs[0].leaf.balances.insert("USDA".into(), 999);
        assert_eq!(check(&pubn, 0), Err(VerificationFailure::RootHashMismatch));
    }

    #[test]
    fn a_tampered_sibling_no_longer_folds_to_the_root() {
        let mut pubn = publication(5);
        pubn.proofs[0].steps[0].sibling_hash = "ab".repeat(32);
        assert_eq!(check(&pubn, 0), Err(VerificationFailure::RootHashMismatch));
    }

    /// The headline attack: the root hash is honest, the signature is valid,
    /// but the published liability total is understated. Only comparing sums
    /// as well as hashes catches this.
    #[test]
    fn understated_published_totals_are_caught_even_though_the_root_hash_is_honest() {
        let pubn = restate(publication(5), |r| {
            r.root_sums.insert("USDA".into(), 1);
        });
        assert_eq!(
            check(&pubn, 0),
            Err(VerificationFailure::RootSumsMismatch {
                asset: "USDA".into()
            })
        );
    }

    #[test]
    fn dropping_an_asset_from_the_published_totals_is_caught() {
        let pubn = restate(publication(5), |r| {
            r.root_sums.remove("USDA");
        });
        assert_eq!(
            check(&pubn, 0),
            Err(VerificationFailure::RootSumsMismatch {
                asset: "USDA".into()
            })
        );
    }

    /// A liabilities report with no totals at all asserts nothing, and is
    /// rejected by the profile rules rather than by the sum comparison.
    #[test]
    fn a_report_with_no_totals_is_rejected_as_vacuous() {
        let pubn = restate(publication(5), |r| r.root_sums.clear());
        match check(&pubn, 0) {
            Err(VerificationFailure::Profile { detail }) => {
                assert!(detail.contains("root_sums"), "got {detail}");
                assert!(detail.contains("vacuous"), "got {detail}");
            }
            other => panic!("expected a profile failure, got {other:?}"),
        }
    }

    #[test]
    fn a_customer_proof_cannot_verify_against_a_group_report() {
        let pubn = restate(publication(5), |r| {
            r.profile = crate::group::GROUP_PROFILE.to_string()
        });
        match check(&pubn, 0) {
            Err(VerificationFailure::Profile { detail }) => {
                assert!(detail.contains("Entity"), "got {detail}");
            }
            other => panic!("expected a profile failure, got {other:?}"),
        }
    }

    #[test]
    fn an_unregistered_profile_is_rejected() {
        let pubn = restate(publication(5), |r| {
            r.profile = "collateral.repo".to_string()
        });
        match check(&pubn, 0) {
            Err(VerificationFailure::Profile { detail }) => {
                assert!(detail.contains("registry"), "got {detail}");
            }
            other => panic!("expected a profile failure, got {other:?}"),
        }
    }

    #[test]
    fn a_restated_root_hash_is_caught() {
        let pubn = restate(publication(5), |r| r.root_hash = "ab".repeat(32));
        assert_eq!(check(&pubn, 0), Err(VerificationFailure::RootHashMismatch));
    }

    #[test]
    fn unsupported_format_versions_are_rejected() {
        let pubn = restate(publication(3), |r| {
            r.format_version = "canton-solvency-report-v9".into()
        });
        assert_eq!(
            check(&pubn, 0),
            Err(VerificationFailure::UnsupportedVersion {
                field: "report.format_version",
                found: "canton-solvency-report-v9".to_string(),
            })
        );

        let mut other = publication(3);
        other.proofs[0].format_version = "canton-solvency-proof-v9".into();
        assert_eq!(
            check(&other, 0),
            Err(VerificationFailure::UnsupportedVersion {
                field: "proof.format_version",
                found: "canton-solvency-proof-v9".to_string(),
            })
        );
    }

    #[test]
    fn an_unsupported_signature_algorithm_is_rejected() {
        let mut pubn = publication(3);
        pubn.signed_report.signature.algorithm = "rsa".into();
        assert_eq!(
            check(&pubn, 0),
            Err(VerificationFailure::UnsupportedVersion {
                field: "signature.algorithm",
                found: "rsa".to_string(),
            })
        );
    }

    #[test]
    fn malformed_hex_is_reported_as_malformed_not_as_forgery() {
        let mut pubn = publication(3);
        pubn.proofs[0].leaf.salt = "nothex".into();
        assert!(matches!(
            check(&pubn, 0),
            Err(VerificationFailure::Malformed(_))
        ));
    }

    #[test]
    fn a_single_leaf_report_verifies_with_an_empty_path() {
        let pubn = publication(1);
        assert!(pubn.proofs[0].steps.is_empty());
        assert_eq!(check(&pubn, 0), Ok(()));
    }

    mod v2 {
        use super::*;
        use crate::manifest::{Disclosure, Manifest};

        fn manifest(entries: &[(&str, Disclosure)]) -> Manifest {
            Manifest {
                audience: "public".to_string(),
                fields: entries.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            }
        }

        /// Consistent with what `metadata()` actually publishes: root_sums
        /// carries data, mark_prices and the disclosures do not.
        fn consistent() -> Manifest {
            manifest(&[
                ("root_sums", Disclosure::Published),
                ("mark_prices", Disclosure::Withheld),
                ("customer_balances", Disclosure::Committed),
            ])
        }

        fn publish_v2(m: Manifest) -> Publication {
            publish(
                &leaves(5),
                &ReportMetadata {
                    manifest: Some(m),
                    ..metadata()
                },
                &signer(),
            )
            .unwrap()
        }

        fn check_v2(p: &Publication) -> Result<(), VerificationFailure> {
            verify(&p.signed_report, &p.proofs[0], &signer().public_key_hex())
        }

        #[test]
        fn a_v2_report_declares_v2_and_verifies() {
            let p = publish_v2(consistent());
            assert_eq!(
                p.signed_report.report.format_version,
                crate::document::REPORT_FORMAT_VERSION_V2
            );
            assert_eq!(check_v2(&p), Ok(()));
        }

        #[test]
        fn a_v1_report_carrying_a_manifest_is_rejected() {
            let mut p = publish(&leaves(5), &metadata(), &signer()).unwrap();
            p.signed_report.report.manifest = Some(consistent());
            assert!(matches!(
                check_v2(&p),
                Err(VerificationFailure::ManifestPresence { .. })
            ));
        }

        #[test]
        fn a_v2_report_without_a_manifest_is_rejected() {
            let mut p = publish_v2(consistent());
            p.signed_report.report.manifest = None;
            assert!(matches!(
                check_v2(&p),
                Err(VerificationFailure::ManifestPresence { .. })
            ));
        }

        /// The teeth: you cannot claim to have published something you did not.
        #[test]
        fn declaring_a_field_published_when_the_report_omits_it_is_rejected() {
            let p = publish_v2(manifest(&[("mark_prices", Disclosure::Published)]));
            match check_v2(&p) {
                Err(VerificationFailure::ManifestInconsistent { path, detail }) => {
                    assert_eq!(path, "mark_prices");
                    assert!(detail.contains("no data"), "got {detail}");
                }
                other => panic!("expected an inconsistency, got {other:?}"),
            }
        }

        /// Nor claim to have withheld something you in fact printed.
        #[test]
        fn declaring_a_published_field_withheld_is_rejected() {
            let p = publish_v2(manifest(&[("root_sums", Disclosure::Withheld)]));
            match check_v2(&p) {
                Err(VerificationFailure::ManifestInconsistent { path, detail }) => {
                    assert_eq!(path, "root_sums");
                    assert!(detail.contains("publishes it anyway"), "got {detail}");
                }
                other => panic!("expected an inconsistency, got {other:?}"),
            }
        }

        #[test]
        fn a_manifest_naming_an_unknown_field_is_rejected() {
            let p = publish_v2(manifest(&[("secret_sauce", Disclosure::Withheld)]));
            match check_v2(&p) {
                Err(VerificationFailure::ManifestInconsistent { path, .. }) => {
                    assert_eq!(path, "secret_sauce")
                }
                other => panic!("expected an inconsistency, got {other:?}"),
            }
        }

        /// Fields attested through the commitment are not report-resident, so
        /// the body check must not fire on them.
        #[test]
        fn committed_fields_outside_the_report_body_are_accepted() {
            let p = publish_v2(manifest(&[
                ("customer_balances", Disclosure::Committed),
                ("customer_identities", Disclosure::Withheld),
            ]));
            assert_eq!(check_v2(&p), Ok(()));
        }

        #[test]
        fn editing_the_manifest_after_signing_breaks_the_digest_binding() {
            let mut p = publish_v2(consistent());
            p.signed_report
                .report
                .manifest
                .as_mut()
                .unwrap()
                .fields
                .insert("customer_identities".into(), Disclosure::Withheld);
            assert_eq!(check_v2(&p), Err(VerificationFailure::DigestMismatch));
        }

        #[test]
        fn an_unknown_report_version_is_rejected() {
            let mut p = publish_v2(consistent());
            p.signed_report.report.format_version = "canton-solvency-report-v9".into();
            assert!(matches!(
                check_v2(&p),
                Err(VerificationFailure::UnsupportedVersion { .. })
            ));
        }
    }

    #[test]
    fn odd_leaf_counts_verify_at_every_index() {
        for n in [2usize, 3, 7, 9] {
            let pubn = publication(n);
            for i in 0..n {
                assert_eq!(check(&pubn, i), Ok(()), "n={n} i={i}");
            }
        }
    }
}
