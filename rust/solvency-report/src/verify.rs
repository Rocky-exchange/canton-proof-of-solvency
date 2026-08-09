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
    expect_version(
        "report.format_version",
        &report.format_version,
        REPORT_FORMAT_VERSION,
    )?;
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
                    balances: [("USDA".to_string(), i as u128 * 1_000_000_000_000_000_000)]
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
