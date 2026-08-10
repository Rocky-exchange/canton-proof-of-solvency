//! On-ledger anchoring: a tamper-evident history of published reports
//! (SPEC §12).
//!
//! A signature proves who published a report. It does not stop a publisher
//! quietly replacing one, or dropping a day nobody asked about. An anchor
//! chain does: each anchor names its predecessor by digest, so a gap, a fork,
//! or an edited past report becomes detectable rather than merely improbable.
//!
//! Anchoring is what gives the chain its permanence — the contract is on a
//! ledger the publisher cannot rewrite. The chain arithmetic here is
//! verifiable offline, from the anchor documents alone.

use crate::digest::lp;
use crate::document::SignedReport;
use serde::{Deserialize, Serialize};

pub const ANCHOR_FORMAT_VERSION: &str = "canton-solvency-anchor-v1";
pub const ANCHOR_DIGEST_DOMAIN: &[u8] = b"rocky-solvency-anchor-v1";

/// One report's place in a publisher's history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub format_version: String,
    /// The report this anchors, by its §8.2 digest.
    pub report_digest: String,
    pub root_hash: String,
    pub snapshot_time: String,
    pub ledger_offset: String,
    pub publisher: String,
    /// The Ed25519 key that signed the anchored report.
    ///
    /// This is what makes anchoring answer key distribution rather than only
    /// tamper-evidence. A reader who can see the anchor obtains the key from
    /// the ledger — somewhere other than the server that served the report —
    /// which is precisely what a key embedded in the report itself cannot
    /// provide.
    pub publisher_key: String,
    /// Digest of the previous anchor. `None` only for the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_anchor: Option<String>,
}

pub fn anchor_digest(anchor: &Anchor) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ANCHOR_DIGEST_DOMAIN);
    h.update(lp(&anchor.format_version));
    h.update(lp(&anchor.report_digest));
    h.update(lp(&anchor.root_hash));
    h.update(lp(&anchor.snapshot_time));
    h.update(lp(&anchor.ledger_offset));
    h.update(lp(&anchor.publisher));
    h.update(lp(&anchor.publisher_key));
    // A presence byte, not `unwrap_or("")`: without it, genesis and an anchor
    // naming an empty predecessor hash identically, and a publisher could
    // present a mid-history anchor as the start of its history.
    match &anchor.prev_anchor {
        None => h.update([0u8]),
        Some(prev) => {
            h.update([1u8]);
            h.update(lp(prev));
        }
    }
    h.finalize().into()
}

pub fn anchor_digest_hex(anchor: &Anchor) -> String {
    hex::encode(anchor_digest(anchor))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainFailure {
    /// The first anchor names a predecessor, so the history is not complete.
    NotGenesis,
    /// An anchor does not name the one before it: a gap, or a fork.
    Broken {
        index: usize,
    },
    /// Time or ledger position moved backwards, which is a restatement.
    WentBackwards {
        index: usize,
        field: &'static str,
    },
    /// Two anchors in the chain are from different publishers.
    PublisherChanged {
        index: usize,
    },
    UnsupportedVersion {
        index: usize,
        found: String,
    },
    /// An anchor describes a different report than the one supplied for it.
    ReportMismatch {
        index: usize,
    },
}

impl std::fmt::Display for ChainFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGenesis => write!(
                f,
                "the first anchor names a predecessor, so this history is incomplete"
            ),
            Self::Broken { index } => write!(f, "anchor {index} does not name the one before it"),
            Self::WentBackwards { index, field } => {
                write!(
                    f,
                    "anchor {index} moves {field} backwards, which restates history"
                )
            }
            Self::PublisherChanged { index } => {
                write!(f, "anchor {index} is from a different publisher")
            }
            Self::UnsupportedVersion { index, found } => {
                write!(f, "anchor {index} uses unsupported version {found:?}")
            }
            Self::ReportMismatch { index } => {
                write!(
                    f,
                    "anchor {index} describes a different report than the one supplied"
                )
            }
        }
    }
}

impl std::error::Error for ChainFailure {}

/// Walks a publisher's anchors oldest-first.
///
/// A complete history starts at genesis. Verifying a *suffix* would let a
/// publisher present the days that suit them, which is the thing anchoring
/// exists to prevent.
pub fn verify_chain(anchors: &[Anchor]) -> Result<(), ChainFailure> {
    for (index, anchor) in anchors.iter().enumerate() {
        if anchor.format_version != ANCHOR_FORMAT_VERSION {
            return Err(ChainFailure::UnsupportedVersion {
                index,
                found: anchor.format_version.clone(),
            });
        }
        match (index, &anchor.prev_anchor) {
            (0, Some(_)) => return Err(ChainFailure::NotGenesis),
            (0, None) => {}
            (_, None) => return Err(ChainFailure::Broken { index }),
            (_, Some(prev)) => {
                let previous = &anchors[index - 1];
                if *prev != anchor_digest_hex(previous) {
                    return Err(ChainFailure::Broken { index });
                }
                if anchor.publisher != previous.publisher {
                    return Err(ChainFailure::PublisherChanged { index });
                }
                if anchor.snapshot_time <= previous.snapshot_time {
                    return Err(ChainFailure::WentBackwards {
                        index,
                        field: "snapshot_time",
                    });
                }
                if anchor.ledger_offset < previous.ledger_offset {
                    return Err(ChainFailure::WentBackwards {
                        index,
                        field: "ledger_offset",
                    });
                }
            }
        }
    }
    Ok(())
}

/// Verifies a report and proof using the key the **anchor** names, rather
/// than one the caller had to obtain somehow.
///
/// This closes the gap §8.4 describes. Verification still needs a trusted
/// key; the difference is where it comes from. A reader who can see the
/// anchor contract on the ledger has a source independent of the publisher's
/// web server, which a key embedded in the report can never be.
///
/// What it does not do is make the ledger trustworthy on the reader's behalf.
/// It moves the question from "is this the right key?" to "can I see this
/// publisher's anchors?" — which is answerable, where the first was not.
pub fn verify_with_anchor(
    signed: &SignedReport,
    proof: &crate::document::ProofDocument,
    anchor: &Anchor,
) -> Result<(), crate::verify::VerificationFailure> {
    use crate::verify::VerificationFailure as F;

    if anchor.format_version != ANCHOR_FORMAT_VERSION {
        return Err(F::UnsupportedVersion {
            field: "anchor.format_version",
            found: anchor.format_version.clone(),
        });
    }
    // The anchor must be about this report, or its key is about another one.
    if anchor.report_digest != crate::digest::report_digest_hex(&signed.report) {
        return Err(F::DigestMismatch);
    }
    crate::verify::verify(signed, proof, &anchor.publisher_key)
}

/// Checks each anchor against the report it claims to anchor. Reports are
/// matched positionally with the anchors.
pub fn verify_anchored_reports(
    anchors: &[Anchor],
    reports: &[SignedReport],
) -> Result<(), ChainFailure> {
    for (index, (anchor, signed)) in anchors.iter().zip(reports).enumerate() {
        if anchor.report_digest != crate::digest::report_digest_hex(&signed.report)
            || anchor.root_hash != signed.report.root_hash
        {
            return Err(ChainFailure::ReportMismatch { index });
        }
    }
    Ok(())
}

/// Builds the next anchor in a history.
pub fn anchor_report(signed: &SignedReport, previous: Option<&Anchor>) -> Anchor {
    Anchor {
        format_version: ANCHOR_FORMAT_VERSION.to_string(),
        report_digest: crate::digest::report_digest_hex(&signed.report),
        root_hash: signed.report.root_hash.clone(),
        snapshot_time: signed.report.snapshot_time.clone(),
        ledger_offset: signed.report.ledger_offset.clone(),
        publisher: signed.report.publisher.clone(),
        publisher_key: signed.signature.public_key.clone(),
        prev_anchor: previous.map(anchor_digest_hex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(i: usize, prev: Option<&Anchor>) -> Anchor {
        Anchor {
            format_version: ANCHOR_FORMAT_VERSION.to_string(),
            report_digest: format!("{:02x}", i).repeat(32),
            root_hash: format!("{:02x}", i + 100).repeat(32),
            snapshot_time: format!("2026-01-{:02}T00:00:00Z", i + 1),
            ledger_offset: format!("{:018}", i * 10),
            publisher: "venue::one".to_string(),
            publisher_key: "ab".repeat(32),
            prev_anchor: prev.map(anchor_digest_hex),
        }
    }

    fn chain(n: usize) -> Vec<Anchor> {
        let mut out: Vec<Anchor> = Vec::new();
        for i in 0..n {
            let next = anchor(i, out.last());
            out.push(next);
        }
        out
    }

    #[test]
    fn a_complete_history_verifies() {
        assert_eq!(verify_chain(&chain(5)), Ok(()));
    }

    #[test]
    fn a_single_anchor_is_a_valid_history() {
        assert_eq!(verify_chain(&chain(1)), Ok(()));
    }

    #[test]
    fn the_digest_covers_every_field() {
        let base = anchor_digest(&chain(2)[1]);
        for mutate in [
            (|a: &mut Anchor| a.report_digest = "ff".repeat(32)) as fn(&mut Anchor),
            |a: &mut Anchor| a.root_hash = "ff".repeat(32),
            |a: &mut Anchor| a.snapshot_time = "2027-01-01T00:00:00Z".into(),
            |a: &mut Anchor| a.ledger_offset = "999".into(),
            |a: &mut Anchor| a.publisher = "venue::two".into(),
            |a: &mut Anchor| a.publisher_key = "cd".repeat(32),
            |a: &mut Anchor| a.prev_anchor = Some("ab".repeat(32)),
            |a: &mut Anchor| a.format_version = "canton-solvency-anchor-v9".into(),
        ] {
            let mut mutated = chain(2)[1].clone();
            mutate(&mut mutated);
            assert_ne!(base, anchor_digest(&mutated));
        }
    }

    /// Genesis is distinguishable: an absent predecessor must not hash the
    /// same as one that happens to be empty.
    #[test]
    fn genesis_differs_from_an_anchor_with_an_empty_predecessor() {
        let mut genesis = chain(1)[0].clone();
        let mut empty_prev = genesis.clone();
        empty_prev.prev_anchor = Some(String::new());
        assert_ne!(anchor_digest(&genesis), anchor_digest(&empty_prev));
        genesis.prev_anchor = None;
        assert_eq!(verify_chain(&[genesis]), Ok(()));
    }

    /// The headline property: a day cannot be dropped out of the middle.
    #[test]
    fn omitting_a_day_breaks_the_chain() {
        let full = chain(5);
        let mut gapped = full.clone();
        gapped.remove(2);
        assert_eq!(
            verify_chain(&gapped),
            Err(ChainFailure::Broken { index: 2 })
        );
    }

    /// And an edited past report changes its anchor's digest, so every later
    /// link stops matching.
    #[test]
    fn editing_a_past_anchor_breaks_every_link_after_it() {
        let mut edited = chain(4);
        edited[1].report_digest = "ff".repeat(32);
        assert_eq!(
            verify_chain(&edited),
            Err(ChainFailure::Broken { index: 2 })
        );
    }

    #[test]
    fn presenting_only_a_convenient_suffix_is_rejected() {
        let full = chain(5);
        assert_eq!(verify_chain(&full[2..]), Err(ChainFailure::NotGenesis));
    }

    #[test]
    fn a_fork_is_rejected() {
        let base = chain(3);
        let mut forked = base.clone();
        // Two different anchors claiming the same predecessor.
        forked[2] = Anchor {
            snapshot_time: "2026-06-01T00:00:00Z".to_string(),
            ..anchor(9, Some(&base[0]))
        };
        assert_eq!(
            verify_chain(&forked),
            Err(ChainFailure::Broken { index: 2 })
        );
    }

    #[test]
    fn a_history_that_moves_backwards_in_time_is_rejected() {
        let mut backwards = chain(3);
        backwards[2].snapshot_time = "2020-01-01T00:00:00Z".to_string();
        backwards[2].prev_anchor = Some(anchor_digest_hex(&backwards[1]));
        assert_eq!(
            verify_chain(&backwards),
            Err(ChainFailure::WentBackwards {
                index: 2,
                field: "snapshot_time"
            })
        );
    }

    /// Two reports for the same instant are a restatement, not a history.
    #[test]
    fn two_anchors_at_the_same_instant_are_rejected() {
        let mut same = chain(2);
        same[1].snapshot_time = same[0].snapshot_time.clone();
        same[1].prev_anchor = Some(anchor_digest_hex(&same[0]));
        assert!(matches!(
            verify_chain(&same),
            Err(ChainFailure::WentBackwards { .. })
        ));
    }

    #[test]
    fn a_ledger_offset_that_rewinds_is_rejected() {
        let mut rewound = chain(3);
        rewound[2].ledger_offset = "000000000000000000".to_string();
        rewound[2].prev_anchor = Some(anchor_digest_hex(&rewound[1]));
        assert_eq!(
            verify_chain(&rewound),
            Err(ChainFailure::WentBackwards {
                index: 2,
                field: "ledger_offset"
            })
        );
    }

    #[test]
    fn a_publisher_swap_mid_history_is_rejected() {
        let mut swapped = chain(3);
        swapped[2].publisher = "venue::two".to_string();
        swapped[2].prev_anchor = Some(anchor_digest_hex(&swapped[1]));
        assert_eq!(
            verify_chain(&swapped),
            Err(ChainFailure::PublisherChanged { index: 2 })
        );
    }

    #[test]
    fn anchors_round_trip_through_json_and_omit_a_null_predecessor() {
        let genesis = &chain(2)[0];
        let text = serde_json::to_string(genesis).unwrap();
        assert!(!text.contains("prev_anchor"), "got {text}");
        assert_eq!(serde_json::from_str::<Anchor>(&text).unwrap(), *genesis);
    }

    /// The point of §8.4: a reader takes the key from the ledger, not from
    /// the server that served the report.
    mod key_distribution {
        use super::*;

        #[test]
        fn an_anchor_carries_the_key_that_signed_its_report() {
            let (signed, _) = crate::golden::fixture();
            let a = anchor_report(&signed, None);
            assert_eq!(a.publisher_key, signed.signature.public_key);
        }

        #[test]
        fn a_report_verifies_against_the_key_its_anchor_names() {
            let (signed, proof) = crate::golden::fixture();
            let a = anchor_report(&signed, None);
            assert_eq!(verify_with_anchor(&signed, &proof, &a), Ok(()));
        }

        /// An anchor naming someone else's key must not validate this report,
        /// or anchoring would launder any key into a trusted one.
        #[test]
        fn an_anchor_naming_another_key_is_rejected() {
            let (signed, proof) = crate::golden::fixture();
            let mut a = anchor_report(&signed, None);
            a.publisher_key = "ab".repeat(32);
            assert_eq!(
                verify_with_anchor(&signed, &proof, &a),
                Err(crate::verify::VerificationFailure::UnknownSigner)
            );
        }

        /// And an anchor for a different report cannot lend its key to this
        /// one: the binding is checked before the key is used.
        #[test]
        fn an_anchor_for_another_report_is_rejected() {
            let (signed, proof) = crate::golden::fixture();
            let (other, _) = crate::golden::fixture_v2();
            let a = anchor_report(&other, None);
            assert_eq!(
                verify_with_anchor(&signed, &proof, &a),
                Err(crate::verify::VerificationFailure::DigestMismatch)
            );
        }

        #[test]
        fn an_anchor_of_an_unknown_version_is_rejected() {
            let (signed, proof) = crate::golden::fixture();
            let mut a = anchor_report(&signed, None);
            a.format_version = "canton-solvency-anchor-v9".to_string();
            assert!(matches!(
                verify_with_anchor(&signed, &proof, &a),
                Err(crate::verify::VerificationFailure::UnsupportedVersion { .. })
            ));
        }

        /// Changing the key changes the anchor digest, so a substituted key
        /// breaks the chain rather than passing quietly.
        #[test]
        fn substituting_the_key_breaks_the_history() {
            let (signed, _) = crate::golden::fixture();
            let genesis = anchor_report(&signed, None);
            let second = anchor_report(&signed, Some(&genesis));

            let mut tampered = genesis.clone();
            tampered.publisher_key = "cd".repeat(32);
            assert_eq!(
                verify_chain(&[tampered, second]),
                Err(ChainFailure::Broken { index: 1 })
            );
        }
    }

    #[test]
    fn an_anchor_built_from_a_report_describes_that_report() {
        let (signed, _) = crate::golden::fixture();
        let a = anchor_report(&signed, None);
        assert_eq!(a.root_hash, signed.report.root_hash);
        assert_eq!(a.publisher, signed.report.publisher);
        assert_eq!(
            verify_anchored_reports(std::slice::from_ref(&a), std::slice::from_ref(&signed)),
            Ok(())
        );

        let (other, _) = crate::golden::fixture_v2();
        assert_eq!(
            verify_anchored_reports(&[a], std::slice::from_ref(&other)),
            Err(ChainFailure::ReportMismatch { index: 0 })
        );
    }
}
