//! Wire types for the report and proof documents (SPEC §8, §9).
//!
//! Amounts are parsed into 18-decimal fixed point on the way in and rendered
//! canonically on the way out, so a document digests identically however its
//! publisher chose to write `100.5`. Unknown fields are rejected: the digest
//! covers named fields only, so anything else would ride along unsigned.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const REPORT_FORMAT_VERSION: &str = "canton-solvency-report-v1";
pub const PROOF_FORMAT_VERSION: &str = "canton-solvency-proof-v1";
pub const SIGNATURE_ALGORITHM: &str = "ed25519";

/// serde codec mapping decimal strings to/from 18dp fixed point.
mod amount_map {
    use canton_solvency_merkle::{format_amount_18dp, parse_amount_18dp};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S: Serializer>(m: &BTreeMap<String, u128>, s: S) -> Result<S::Ok, S::Error> {
        let rendered: BTreeMap<&String, String> =
            m.iter().map(|(k, v)| (k, format_amount_18dp(*v))).collect();
        rendered.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<String, u128>, D::Error> {
        let raw = BTreeMap::<String, String>::deserialize(d)?;
        raw.into_iter()
            .map(|(asset, v)| {
                parse_amount_18dp(&v)
                    .map(|parsed| (asset.clone(), parsed))
                    .map_err(|e| serde::de::Error::custom(format!("asset {asset}: {e}")))
            })
            .collect()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disclosures {
    #[serde(with = "amount_map")]
    pub bad_debt: BTreeMap<String, u128>,
    pub excluded_house_accounts: u64,
    #[serde(with = "amount_map")]
    pub excluded_house_totals: BTreeMap<String, u128>,
}

/// The published statement. Its digest (SPEC §8) is what gets signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub format_version: String,
    pub profile: String,
    /// Canton party identifier of the publishing institution.
    pub publisher: String,
    /// RFC 3339 UTC, `Z` suffix.
    pub snapshot_time: String,
    /// Opaque participant ledger offset pinning the snapshot in event history.
    pub ledger_offset: String,
    pub root_hash: String,
    pub leaf_count: u64,
    #[serde(with = "amount_map")]
    pub root_sums: BTreeMap<String, u128>,
    #[serde(with = "amount_map")]
    pub mark_prices: BTreeMap<String, u128>,
    pub disclosures: Disclosures,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureBlock {
    pub algorithm: String,
    pub public_key: String,
    pub value: String,
}

/// A report plus its detached signature. The embedded `public_key` is a
/// convenience for display; verification requires a caller-supplied trusted
/// key, because a self-certifying signature proves only internal consistency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReport {
    pub report: Report,
    pub signature: SignatureBlock,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafPreimage {
    pub salt: String,
    pub user_id: String,
    #[serde(with = "amount_map")]
    pub balances: BTreeMap<String, u128>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofStepDocument {
    pub sibling_hash: String,
    #[serde(with = "amount_map")]
    pub sibling_sums: BTreeMap<String, u128>,
    pub sibling_on_left: bool,
}

/// One user's inclusion proof, bound to the report it belongs to by
/// `report_digest` so a stale proof cannot be replayed against a later report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofDocument {
    pub format_version: String,
    pub report_digest: String,
    pub leaf: LeafPreimage,
    pub steps: Vec<ProofStepDocument>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_json(extra: &str) -> String {
        format!(
            r#"{{
              "format_version": "canton-solvency-report-v1",
              "profile": "solvency.liabilities",
              "publisher": "rocky::122099",
              "snapshot_time": "2026-08-09T00:00:00Z",
              "ledger_offset": "000000000000012345",
              "root_hash": "02885b0fc65c3d8992899c8acba1917cb838b18b7054b6675e3d89f2bf8f0970",
              "leaf_count": 3,
              "root_sums": {{ "USDA": "100.5" }},
              "mark_prices": {{}},
              "disclosures": {{
                "bad_debt": {{}},
                "excluded_house_accounts": 0,
                "excluded_house_totals": {{}}
              }}{extra}
            }}"#
        )
    }

    fn parsed() -> Report {
        serde_json::from_str(&report_json("")).unwrap()
    }

    #[test]
    fn amounts_are_canonicalised_to_18dp_on_parse() {
        let json = serde_json::to_value(parsed()).unwrap();
        assert_eq!(
            json["root_sums"]["USDA"], "100.500000000000000000",
            "a report must digest the same however the publisher wrote its amounts"
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = serde_json::from_str::<Report>(&report_json(r#", "extra": 1"#)).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "unknown fields would ride outside the signed preimage; got {err}"
        );
    }

    #[test]
    fn negative_amounts_are_rejected() {
        let json = report_json("").replace(r#""100.5""#, r#""-1""#);
        let err = serde_json::from_str::<Report>(&json).unwrap_err();
        assert!(err.to_string().contains("USDA"), "got {err}");
    }

    #[test]
    fn report_round_trips_through_json() {
        let report = parsed();
        let reparsed: Report =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(report, reparsed);
    }

    #[test]
    fn proof_document_round_trips_through_json() {
        let proof = ProofDocument {
            format_version: PROOF_FORMAT_VERSION.to_string(),
            report_digest: "aa".repeat(32),
            leaf: LeafPreimage {
                salt: "bb".repeat(32),
                user_id: "u1".to_string(),
                balances: [("USDA".to_string(), 1u128)].into_iter().collect(),
            },
            steps: vec![ProofStepDocument {
                sibling_hash: "cc".repeat(32),
                sibling_sums: [("USDA".to_string(), 2u128)].into_iter().collect(),
                sibling_on_left: true,
            }],
        };
        let reparsed: ProofDocument =
            serde_json::from_str(&serde_json::to_string(&proof).unwrap()).unwrap();
        assert_eq!(proof, reparsed);
    }
}
