//! Evidence packs: one signed archive an auditor can re-verify offline
//! (SPEC §15).
//!
//! Every document in this repository verifies on its own. That is not the
//! same as verifying a *delivery*. An auditor handed a folder has no way to
//! know whether it is the folder the publisher meant to send: a proof can be
//! left out, a coverage statement swapped for an older one, an anchor quietly
//! dropped. Each surviving file still verifies perfectly, because nothing in
//! any of them says what else was supposed to be there.
//!
//! A pack is that missing statement. It is a signed index naming every member
//! file and its digest, so the *set* is committed rather than only its
//! elements. Omitting a proof is then a detectable act rather than an
//! unremarkable absence.
//!
//! What a pack does not do is establish who should have signed it. It carries
//! the publisher's key for display, and verification still demands a trusted
//! key from the caller — from an anchor, ideally, which is the one source
//! independent of whoever assembled the archive.

use crate::digest::lp;
use crate::sign::ReportSigner;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PACK_FORMAT_VERSION: &str = "canton-solvency-pack-v1";
pub const PACK_DIGEST_DOMAIN: &[u8] = b"rocky-solvency-pack-v1";

/// One member file, named and pinned by digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackEntry {
    pub name: String,
    pub sha256: String,
}

/// The signed index of an evidence pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub format_version: String,
    pub publisher: String,
    pub snapshot_time: String,
    /// The report this pack is evidence for, by its §8.2 digest. A pack
    /// cannot be lifted onto a different report without breaking this.
    pub report_digest: String,
    /// Sorted by name, so assembling the same files in a different order
    /// produces the same pack.
    pub entries: Vec<PackEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPack {
    pub pack: Pack,
    pub signature: crate::document::SignatureBlock,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackFailure {
    UnsupportedVersion {
        found: String,
    },
    /// Two members share a name, so the index is ambiguous about which one it
    /// pins.
    DuplicateEntry {
        name: String,
    },
    /// A member name that is a path rather than a file name. A pack describes
    /// one directory; a name that could escape it would be a delivery
    /// instruction rather than an integrity claim.
    UnsafeName {
        name: String,
    },
    /// The index names a file the delivery does not contain.
    Missing {
        name: String,
    },
    /// A member's bytes are not the bytes the index pinned.
    Altered {
        name: String,
    },
    /// The delivery contains a file the index does not name.
    Unlisted {
        name: String,
    },
    /// The pack is evidence for a different report than the one supplied.
    ReportMismatch,
    UnknownSigner,
    BadSignature,
}

impl std::fmt::Display for PackFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => {
                write!(f, "unsupported pack format version {found:?}")
            }
            Self::DuplicateEntry { name } => write!(f, "{name} appears twice in the pack"),
            Self::UnsafeName { name } => {
                write!(f, "{name:?} is not a plain file name")
            }
            Self::Missing { name } => write!(f, "the pack names {name}, which is not present"),
            Self::Altered { name } => write!(f, "{name} does not match the digest the pack pins"),
            Self::Unlisted { name } => write!(f, "{name} is present but the pack does not name it"),
            Self::ReportMismatch => write!(f, "the pack is evidence for a different report"),
            Self::UnknownSigner => write!(f, "the pack is not signed by the trusted key"),
            Self::BadSignature => write!(f, "the pack signature does not verify"),
        }
    }
}

impl std::error::Error for PackFailure {}

/// A member name must be a plain file name. Verified on both sides: a pack is
/// not always built by the tool that reads it, and an index naming
/// `../secrets` would be a delivery instruction rather than an integrity
/// claim.
fn check_name(name: &str) -> Result<(), PackFailure> {
    let unsafe_name =
        name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == "..";
    if unsafe_name {
        return Err(PackFailure::UnsafeName {
            name: name.to_string(),
        });
    }
    Ok(())
}

pub fn member_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

pub fn pack_digest(pack: &Pack) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(PACK_DIGEST_DOMAIN);
    h.update(lp(&pack.format_version));
    h.update(lp(&pack.publisher));
    h.update(lp(&pack.snapshot_time));
    h.update(lp(&pack.report_digest));
    // The count is committed before the entries, little-endian like every
    // other length in §8.1. Without it a pack over two members and a pack over
    // one longer member could be made to agree, and the whole point here is
    // that the *number* of files is part of the claim.
    h.update((pack.entries.len() as u64).to_le_bytes());
    for entry in &pack.entries {
        h.update(lp(&entry.name));
        h.update(lp(&entry.sha256));
    }
    h.finalize().into()
}

pub fn pack_digest_hex(pack: &Pack) -> String {
    hex::encode(pack_digest(pack))
}

/// Assemble a pack over `members`, keyed by the name each file is delivered
/// under.
pub fn build_pack(
    publisher: &str,
    snapshot_time: &str,
    report_digest: &str,
    members: &[(String, Vec<u8>)],
    signer: &ReportSigner,
) -> Result<SignedPack, PackFailure> {
    let mut entries: BTreeMap<String, String> = BTreeMap::new();
    for (name, bytes) in members {
        check_name(name)?;
        if entries.contains_key(name) {
            return Err(PackFailure::DuplicateEntry { name: name.clone() });
        }
        entries.insert(name.clone(), member_digest(bytes));
    }
    let pack = Pack {
        format_version: PACK_FORMAT_VERSION.to_string(),
        publisher: publisher.to_string(),
        snapshot_time: snapshot_time.to_string(),
        report_digest: report_digest.to_string(),
        // BTreeMap gives the sorted order §15 requires, so the same files
        // assembled in any order produce the same pack.
        entries: entries
            .into_iter()
            .map(|(name, sha256)| PackEntry { name, sha256 })
            .collect(),
    };
    let signature = crate::document::SignatureBlock {
        algorithm: "ed25519".to_string(),
        public_key: signer.public_key_hex(),
        value: signer.sign_digest(&pack_digest(&pack)),
    };
    Ok(SignedPack { pack, signature })
}

/// Check a delivery against its index: the signature, then that the members
/// present are exactly the members named, byte for byte.
pub fn verify_pack(
    signed: &SignedPack,
    trusted_key: &str,
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<(), PackFailure> {
    if signed.pack.format_version != PACK_FORMAT_VERSION {
        return Err(PackFailure::UnsupportedVersion {
            found: signed.pack.format_version.clone(),
        });
    }
    if !signed
        .signature
        .public_key
        .eq_ignore_ascii_case(trusted_key.trim())
    {
        return Err(PackFailure::UnknownSigner);
    }
    crate::sign::verify_signature(
        trusted_key.trim(),
        &pack_digest(&signed.pack),
        &signed.signature.value,
    )
    .map_err(|_| PackFailure::BadSignature)?;

    // Named-but-absent before present-but-unnamed: a dropped proof is the
    // failure this exists to catch, and reporting it first keeps the message
    // pointed at the missing evidence rather than at whatever else is in the
    // folder.
    for entry in &signed.pack.entries {
        check_name(&entry.name)?;
        let bytes = members
            .get(&entry.name)
            .ok_or_else(|| PackFailure::Missing {
                name: entry.name.clone(),
            })?;
        if !member_digest(bytes).eq_ignore_ascii_case(&entry.sha256) {
            return Err(PackFailure::Altered {
                name: entry.name.clone(),
            });
        }
    }
    for name in members.keys() {
        if !signed.pack.entries.iter().any(|e| &e.name == name) {
            return Err(PackFailure::Unlisted { name: name.clone() });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> ReportSigner {
        ReportSigner::from_seed(&[9u8; 32])
    }

    fn members() -> Vec<(String, Vec<u8>)> {
        vec![
            ("report.json".to_string(), b"{\"report\":1}".to_vec()),
            (
                "proof-alice.json".to_string(),
                b"{\"proof\":\"a\"}".to_vec(),
            ),
            ("proof-bob.json".to_string(), b"{\"proof\":\"b\"}".to_vec()),
        ]
    }

    fn delivered(members: &[(String, Vec<u8>)]) -> BTreeMap<String, Vec<u8>> {
        members.iter().cloned().collect()
    }

    fn pack_of(members: &[(String, Vec<u8>)]) -> SignedPack {
        build_pack(
            "venue::one",
            "2026-08-09T00:00:00Z",
            "aa11",
            members,
            &signer(),
        )
        .expect("the fixture is well formed")
    }

    #[test]
    fn a_pack_verifies_against_the_files_it_names() {
        let m = members();
        let signed = pack_of(&m);
        assert_eq!(
            verify_pack(&signed, &signer().public_key_hex(), &delivered(&m)),
            Ok(())
        );
    }

    #[test]
    fn a_member_whose_bytes_changed_is_caught() {
        let m = members();
        let signed = pack_of(&m);
        let mut d = delivered(&m);
        d.insert("proof-bob.json".to_string(), b"{\"proof\":\"B\"}".to_vec());
        assert_eq!(
            verify_pack(&signed, &signer().public_key_hex(), &d),
            Err(PackFailure::Altered {
                name: "proof-bob.json".to_string()
            })
        );
    }

    /// The reason packs exist. Every remaining file still verifies on its own;
    /// only the index knows Bob was meant to be there.
    #[test]
    fn a_proof_left_out_of_the_delivery_is_caught() {
        let m = members();
        let signed = pack_of(&m);
        let mut d = delivered(&m);
        d.remove("proof-bob.json");
        assert_eq!(
            verify_pack(&signed, &signer().public_key_hex(), &d),
            Err(PackFailure::Missing {
                name: "proof-bob.json".to_string()
            })
        );
    }

    #[test]
    fn a_file_the_index_does_not_name_is_caught() {
        let m = members();
        let signed = pack_of(&m);
        let mut d = delivered(&m);
        d.insert("proof-mallory.json".to_string(), b"{}".to_vec());
        assert_eq!(
            verify_pack(&signed, &signer().public_key_hex(), &d),
            Err(PackFailure::Unlisted {
                name: "proof-mallory.json".to_string()
            })
        );
    }

    #[test]
    fn two_members_under_one_name_are_refused_at_build() {
        let mut m = members();
        m.push((
            "proof-bob.json".to_string(),
            b"{\"proof\":\"other\"}".to_vec(),
        ));
        assert_eq!(
            build_pack("venue::one", "t", "aa11", &m, &signer()),
            Err(PackFailure::DuplicateEntry {
                name: "proof-bob.json".to_string()
            })
        );
    }

    #[test]
    fn assembly_order_does_not_change_the_pack() {
        let m = members();
        let mut reversed = m.clone();
        reversed.reverse();
        assert_eq!(
            pack_digest_hex(&pack_of(&m).pack),
            pack_digest_hex(&pack_of(&reversed).pack)
        );
    }

    #[test]
    fn the_digest_covers_every_entry() {
        let signed = pack_of(&members());
        let before = pack_digest_hex(&signed.pack);
        let mut edited = signed.pack.clone();
        edited.entries[1].sha256 = "00".repeat(32);
        assert_ne!(before, pack_digest_hex(&edited));
    }

    /// Names and digests are length-prefixed, so no rearrangement of the same
    /// characters across fields produces the same digest.
    #[test]
    fn entry_fields_cannot_be_shifted_across_the_boundary() {
        let one = Pack {
            format_version: PACK_FORMAT_VERSION.to_string(),
            publisher: "venue::one".to_string(),
            snapshot_time: "t".to_string(),
            report_digest: "aa11".to_string(),
            entries: vec![PackEntry {
                name: "ab".to_string(),
                sha256: "c".to_string(),
            }],
        };
        let two = Pack {
            entries: vec![PackEntry {
                name: "a".to_string(),
                sha256: "bc".to_string(),
            }],
            ..one.clone()
        };
        assert_ne!(pack_digest_hex(&one), pack_digest_hex(&two));
    }

    #[test]
    fn a_pack_cannot_be_moved_onto_another_report() {
        let signed = pack_of(&members());
        let mut moved = signed.clone();
        moved.pack.report_digest = "bb22".to_string();
        assert_eq!(
            verify_pack(&moved, &signer().public_key_hex(), &delivered(&members())),
            Err(PackFailure::BadSignature)
        );
    }

    #[test]
    fn a_pack_signed_by_someone_else_is_refused() {
        let signed = pack_of(&members());
        let other = ReportSigner::from_seed(&[7u8; 32]);
        assert_eq!(
            verify_pack(&signed, &other.public_key_hex(), &delivered(&members())),
            Err(PackFailure::UnknownSigner)
        );
    }

    #[test]
    fn an_unknown_pack_version_is_refused() {
        let mut signed = pack_of(&members());
        signed.pack.format_version = "canton-solvency-pack-v2".to_string();
        assert_eq!(
            verify_pack(&signed, &signer().public_key_hex(), &delivered(&members())),
            Err(PackFailure::UnsupportedVersion {
                found: "canton-solvency-pack-v2".to_string()
            })
        );
    }

    #[test]
    fn a_member_name_that_is_a_path_is_refused() {
        for name in ["../report.json", "sub/report.json", "a\\b.json", ""] {
            let m = vec![(name.to_string(), b"{}".to_vec())];
            assert_eq!(
                build_pack("v", "t", "aa11", &m, &signer()),
                Err(PackFailure::UnsafeName {
                    name: name.to_string()
                }),
                "{name:?} should be refused"
            );
        }
    }

    /// Refused on the reading side too, and this is the case that matters:
    /// editing a name in transit breaks the signature, so the only way such an
    /// index arrives signed is a publisher that meant it.
    #[test]
    fn an_index_signed_over_a_path_is_still_refused() {
        let pack = Pack {
            format_version: PACK_FORMAT_VERSION.to_string(),
            publisher: "venue::one".to_string(),
            snapshot_time: "t".to_string(),
            report_digest: "aa11".to_string(),
            entries: vec![PackEntry {
                name: "../escape.json".to_string(),
                sha256: member_digest(b"{}"),
            }],
        };
        let signed = SignedPack {
            signature: crate::document::SignatureBlock {
                algorithm: "ed25519".to_string(),
                public_key: signer().public_key_hex(),
                value: signer().sign_digest(&pack_digest(&pack)),
            },
            pack,
        };
        assert_eq!(
            verify_pack(&signed, &signer().public_key_hex(), &BTreeMap::new()),
            Err(PackFailure::UnsafeName {
                name: "../escape.json".to_string()
            })
        );
    }

    #[test]
    fn an_empty_pack_is_a_pack() {
        let signed = pack_of(&[]);
        assert_eq!(
            verify_pack(&signed, &signer().public_key_hex(), &BTreeMap::new()),
            Ok(())
        );
    }
}
