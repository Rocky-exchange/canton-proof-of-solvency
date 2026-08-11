//! Signed report and proof documents for Canton proof-of-solvency
//! commitments.
//!
//! The core crate ([`canton_solvency_merkle`]) commits to balances; this crate
//! makes the commitment publishable. A [`document::Report`] carries the root hash, the
//! liability totals, and the snapshot metadata that pins them to a point in a
//! participant's event history. A [`document::ProofDocument`] carries one user's leaf
//! preimage and sibling path, bound to the report it belongs to.
//!
//! Both documents are hashed by length-prefixed concatenation under their own
//! domain strings ([`SPEC.md`] §8, §9) rather than over their JSON encoding,
//! so reformatting the JSON cannot invalidate a signature.
//!
//! # Example
//!
//! Publish a signed report and verify one customer's proof against it, with
//! the verifier holding only the trusted key:
//!
//! ```
//! use canton_solvency_merkle::{leaf_salt, parse_amount_18dp};
//! use canton_solvency_report::produce::{publish, LeafInput, ReportMetadata};
//! use canton_solvency_report::sign::ReportSigner;
//! use canton_solvency_report::verify::verify;
//! use std::collections::BTreeMap;
//!
//! # fn main() -> anyhow::Result<()> {
//! let master_salt = b"per-snapshot-secret";
//! let leaves: Vec<LeafInput> = [("alice", "100.5"), ("bob", "0.25")]
//!     .iter()
//!     .map(|(user_id, usda)| {
//!         let mut balances = BTreeMap::new();
//!         balances.insert("USDA".to_string(), parse_amount_18dp(usda).unwrap());
//!         LeafInput {
//!             salt: leaf_salt(master_salt, user_id),
//!             user_id: user_id.to_string(),
//!             balances,
//!         }
//!     })
//!     .collect();
//!
//! let meta = ReportMetadata {
//!     profile: "solvency.liabilities".to_string(),
//!     publisher: "venue::example".to_string(),
//!     snapshot_time: "2026-01-01T00:00:00Z".to_string(),
//!     ledger_offset: "000000000000000042".to_string(),
//!     mark_prices: BTreeMap::new(),
//!     disclosures: Default::default(),
//!     manifest: None,
//! };
//!
//! // A real deployment signs with a key in an HSM or KMS.
//! let signer = ReportSigner::from_seed(&[1u8; 32]);
//! let published = publish(&leaves, &meta, &signer)?;
//!
//! // The verifier is given the key out of band -- never taken from the
//! // report, which would prove only internal consistency.
//! let trusted_key = signer.public_key_hex();
//! assert_eq!(
//!     verify(&published.signed_report, &published.proofs[0], &trusted_key),
//!     Ok(())
//! );
//!
//! // A proof issued for a different report does not verify against this one.
//! let mut restated = published.signed_report.clone();
//! restated.report.leaf_count += 1;
//! assert!(verify(&restated, &published.proofs[0], &trusted_key).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! [`SPEC.md`]: https://github.com/Rocky-exchange/canton-proof-of-solvency/blob/main/SPEC.md

pub mod anchor;
pub mod assurance;
pub mod compat;
pub mod corpus_gen;
pub mod coverage;
pub mod digest;
pub mod document;
pub mod golden;
pub mod group;
pub mod manifest;
pub mod pack;
pub mod produce;
pub mod profile;
pub mod sign;
pub mod verify;
