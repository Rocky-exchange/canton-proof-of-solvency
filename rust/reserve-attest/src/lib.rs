//! Reading custody holdings from a Canton participant and committing them as
//! a `coverage.custody` report (SPEC §11).
//!
//! **The socket is not here.** Talking to a participant node is the one part
//! of this that cannot be tested without a participant node, so it sits
//! behind a [`Transport`] the caller supplies. Everything else — how the
//! request is built, how the response is read, how positions become a
//! committed report — is ordinary code with ordinary tests.
//!
//! That boundary is not a workaround. An integration that hard-codes its HTTP
//! client is an integration nobody can test, and this crate has to be
//! trustworthy to an auditor who will never run it against production.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod build;

/// One custody position as the ledger reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyPosition {
    /// Contract identifier, used as the leaf subject so each position is
    /// individually provable.
    pub contract_id: String,
    pub asset: String,
    /// 18dp fixed point, parsed from the ledger's decimal string.
    pub amount: u128,
}

/// Anything that can carry a request to a participant and return its body.
///
/// Implemented over HTTP by the caller; implemented over a canned response in
/// tests. The trait is deliberately about bytes, not about Canton: a
/// transport that understood the protocol would be a second place for the
/// protocol to be wrong.
pub trait Transport {
    fn post(&self, path: &str, body: &str) -> Result<String>;
}

/// Which parties' holdings to read, and of which template.
#[derive(Clone, Debug)]
pub struct HoldingsQuery {
    pub custody_parties: Vec<String>,
    /// Fully qualified template identifier of the holding contract.
    pub template_id: String,
    /// The offset the read is pinned to. Both halves of a coverage claim must
    /// be as-of one instant, or the comparison is between two different days.
    pub ledger_offset: String,
}

/// The Ledger API JSON request for an active-contract snapshot.
///
/// Built as a value rather than a string so a test can assert its shape
/// rather than its formatting.
pub fn active_contracts_request(query: &HoldingsQuery) -> Result<serde_json::Value> {
    if query.custody_parties.is_empty() {
        bail!("no custody parties declared: an empty party set reads an empty book");
    }
    if query.ledger_offset.is_empty() {
        bail!("no ledger offset: an unpinned read cannot be paired with a liabilities snapshot");
    }
    Ok(serde_json::json!({
        "filter": {
            "filtersByParty": query
                .custody_parties
                .iter()
                .map(|p| (p.clone(), serde_json::json!({
                    "inclusive": { "templateIds": [query.template_id] }
                })))
                .collect::<serde_json::Map<_, _>>(),
        },
        "verbose": false,
        "activeAtOffset": query.ledger_offset,
    }))
}

/// One entry of the participant's response.
#[derive(Debug, Deserialize)]
struct ActiveContract {
    #[serde(rename = "contractId")]
    contract_id: String,
    #[serde(rename = "createArguments")]
    create_arguments: HoldingArguments,
}

#[derive(Debug, Deserialize)]
struct HoldingArguments {
    instrument: String,
    amount: String,
}

#[derive(Debug, Deserialize)]
struct ActiveContractsResponse {
    result: Vec<ActiveContract>,
}

/// Parses a participant's active-contract response into positions.
pub fn parse_holdings(body: &str) -> Result<Vec<CustodyPosition>> {
    let parsed: ActiveContractsResponse =
        serde_json::from_str(body).context("parsing the participant's response")?;

    let mut seen = std::collections::BTreeSet::new();
    parsed
        .result
        .into_iter()
        .map(|contract| {
            // A repeated contract id would double-count a position, which is
            // the asset-side equivalent of duplicating an odd node.
            if !seen.insert(contract.contract_id.clone()) {
                bail!(
                    "contract {} appears twice in one snapshot",
                    contract.contract_id
                );
            }
            let amount =
                canton_solvency_merkle::parse_amount_18dp(&contract.create_arguments.amount)
                    .with_context(|| format!("amount for contract {}", contract.contract_id))?;
            Ok(CustodyPosition {
                contract_id: contract.contract_id,
                asset: contract.create_arguments.instrument,
                amount,
            })
        })
        .collect()
}

/// Reads holdings over a caller-supplied transport.
pub fn read_holdings<T: Transport>(
    transport: &T,
    query: &HoldingsQuery,
) -> Result<Vec<CustodyPosition>> {
    let request = active_contracts_request(query)?;
    let body = transport
        .post("/v1/query", &serde_json::to_string(&request)?)
        .context("querying the participant")?;
    parse_holdings(&body)
}

/// Totals per asset, for a caller that wants the figure without the tree.
pub fn totals(positions: &[CustodyPosition]) -> Result<BTreeMap<String, u128>> {
    let mut out: BTreeMap<String, u128> = BTreeMap::new();
    for position in positions {
        let slot = out.entry(position.asset.clone()).or_insert(0);
        *slot = slot
            .checked_add(position.amount)
            .with_context(|| format!("custody total for {} overflows", position.asset))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> HoldingsQuery {
        HoldingsQuery {
            custody_parties: vec!["venue::custody".to_string(), "venue::omnibus".to_string()],
            template_id: "Holding:Fungible".to_string(),
            ledger_offset: "000000000000000042".to_string(),
        }
    }

    /// A canned participant. The socket is the only part of this crate that
    /// needs a real node; everything else is exercised here.
    struct FakeLedger {
        body: String,
        seen: std::cell::RefCell<Vec<String>>,
    }

    impl Transport for FakeLedger {
        fn post(&self, path: &str, body: &str) -> Result<String> {
            self.seen.borrow_mut().push(format!("{path} {body}"));
            Ok(self.body.clone())
        }
    }

    fn ledger(body: &str) -> FakeLedger {
        FakeLedger {
            body: body.to_string(),
            seen: std::cell::RefCell::new(Vec::new()),
        }
    }

    const TWO_POSITIONS: &str = r#"{
      "result": [
        {"contractId": "c1", "createArguments": {"instrument": "USDA", "amount": "100.5"}},
        {"contractId": "c2", "createArguments": {"instrument": "CBTC", "amount": "0.25"}}
      ]
    }"#;

    #[test]
    fn the_request_names_every_declared_party_and_pins_the_offset() {
        let request = active_contracts_request(&query()).unwrap();
        let parties = request["filter"]["filtersByParty"].as_object().unwrap();
        assert_eq!(parties.len(), 2);
        assert!(parties.contains_key("venue::custody"));
        assert_eq!(
            parties["venue::custody"]["inclusive"]["templateIds"][0],
            "Holding:Fungible"
        );
        assert_eq!(request["activeAtOffset"], "000000000000000042");
    }

    /// An empty party set reads an empty book, which would publish as "no
    /// custody" rather than as a mistake.
    #[test]
    fn a_query_with_no_parties_is_refused() {
        let err = active_contracts_request(&HoldingsQuery {
            custody_parties: vec![],
            ..query()
        })
        .unwrap_err();
        assert!(err.to_string().contains("empty book"), "got {err}");
    }

    #[test]
    fn a_query_with_no_offset_is_refused() {
        let err = active_contracts_request(&HoldingsQuery {
            ledger_offset: String::new(),
            ..query()
        })
        .unwrap_err();
        assert!(err.to_string().contains("unpinned"), "got {err}");
    }

    #[test]
    fn holdings_are_parsed_into_positions() {
        let positions = parse_holdings(TWO_POSITIONS).unwrap();
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0].contract_id, "c1");
        assert_eq!(positions[0].asset, "USDA");
        assert_eq!(positions[0].amount, 100_500_000_000_000_000_000);
    }

    /// The asset-side equivalent of duplicating an odd node.
    #[test]
    fn a_repeated_contract_in_one_snapshot_is_refused() {
        let body = r#"{"result":[
          {"contractId":"c1","createArguments":{"instrument":"USDA","amount":"1"}},
          {"contractId":"c1","createArguments":{"instrument":"USDA","amount":"1"}}]}"#;
        let err = parse_holdings(body).unwrap_err();
        assert!(err.to_string().contains("twice"), "got {err}");
    }

    #[test]
    fn a_malformed_amount_names_the_contract_it_came_from() {
        let body = r#"{"result":[
          {"contractId":"c9","createArguments":{"instrument":"USDA","amount":"-1"}}]}"#;
        let err = format!("{:#}", parse_holdings(body).unwrap_err());
        assert!(err.contains("c9"), "got {err}");
    }

    #[test]
    fn a_response_that_is_not_a_snapshot_is_refused() {
        assert!(parse_holdings("{\"unexpected\": true}").is_err());
        assert!(parse_holdings("not json").is_err());
    }

    #[test]
    fn an_empty_snapshot_parses_to_no_positions() {
        assert_eq!(parse_holdings(r#"{"result":[]}"#).unwrap(), vec![]);
    }

    #[test]
    fn reading_posts_the_request_and_returns_the_positions() {
        let ledger = ledger(TWO_POSITIONS);
        let positions = read_holdings(&ledger, &query()).unwrap();
        assert_eq!(positions.len(), 2);
        let seen = ledger.seen.borrow();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].starts_with("/v1/query "), "got {}", seen[0]);
        assert!(seen[0].contains("000000000000000042"));
    }

    #[test]
    fn totals_add_positions_per_asset() {
        let positions = vec![
            CustodyPosition {
                contract_id: "a".into(),
                asset: "USDA".into(),
                amount: 100,
            },
            CustodyPosition {
                contract_id: "b".into(),
                asset: "USDA".into(),
                amount: 50,
            },
            CustodyPosition {
                contract_id: "c".into(),
                asset: "CBTC".into(),
                amount: 7,
            },
        ];
        let totals = totals(&positions).unwrap();
        assert_eq!(totals["USDA"], 150);
        assert_eq!(totals["CBTC"], 7);
    }

    #[test]
    fn a_total_that_overflows_is_an_error_not_a_wrap() {
        let positions = vec![
            CustodyPosition {
                contract_id: "a".into(),
                asset: "USDA".into(),
                amount: u128::MAX,
            },
            CustodyPosition {
                contract_id: "b".into(),
                asset: "USDA".into(),
                amount: 1,
            },
        ];
        assert!(totals(&positions).is_err());
    }
}
