//! Signed report and proof documents for Canton proof-of-solvency
//! commitments.
//!
//! The core crate ([`canton_solvency_merkle`]) commits to balances; this crate
//! makes the commitment publishable. A [`Report`] carries the root hash, the
//! liability totals, and the snapshot metadata that pins them to a point in a
//! participant's event history. A [`ProofDocument`] carries one user's leaf
//! preimage and sibling path, bound to the report it belongs to.
//!
//! Both documents are hashed by length-prefixed concatenation under their own
//! domain strings ([`SPEC.md`] §8, §9) rather than over their JSON encoding,
//! so reformatting the JSON cannot invalidate a signature.
//!
//! [`SPEC.md`]: https://github.com/Rocky-exchange/canton-proof-of-solvency/blob/main/SPEC.md

pub mod coverage;
pub mod digest;
pub mod document;
pub mod golden;
pub mod group;
pub mod manifest;
pub mod produce;
pub mod profile;
pub mod sign;
pub mod verify;
