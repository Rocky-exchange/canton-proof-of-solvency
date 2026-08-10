//! Reading custody holdings from a Canton participant and committing them as
//! a `coverage.custody` report (SPEC §11).
//!
//! The wire shape here is the **JSON Ledger API v2** one — `/state/ledger-end`
//! and `/state/active-contracts`, filters expressed as `cumulative` entries
//! carrying a `TemplateFilter`, and responses that are a bare array of
//! `contractEntry.JsActiveContract`. An earlier draft of this crate used the
//! older JSON API v1 shape (`/v1/query`, `inclusive.templateIds`,
//! `{"result": [...]}`, `createArguments`). No participant accepts that, and
//! nothing in a unit test would have told us: the shape was only wrong
//! against a real ledger.
//!
//! **The socket is still not here.** Talking to a participant is the one part
//! that cannot be exercised without one, so it sits behind a [`Transport`] the
//! caller supplies. An integration that hard-codes its HTTP client is an
//! integration nobody can test, and this has to be trustworthy to an auditor
//! who will never run it against production.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod build;

/// `GET` the offset a snapshot is pinned to.
pub const LEDGER_END_PATH: &str = "/state/ledger-end";
/// `POST` the active-contract snapshot query.
pub const ACTIVE_CONTRACTS_PATH: &str = "/state/active-contracts";

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
/// Implemented over HTTP by the caller; implemented over canned responses in
/// tests. Deliberately about bytes rather than about Canton: a transport that
/// understood the protocol would be a second place for the protocol to be
/// wrong.
pub trait Transport {
    fn get(&self, path: &str) -> Result<String>;
    fn post(&self, path: &str, body: &str) -> Result<String>;
}

/// Which template's `createArgument` fields carry the asset and the amount.
///
/// Holding templates differ between deployments, so the caller names them
/// rather than this crate guessing.
#[derive(Clone, Debug)]
pub struct HoldingFields {
    pub asset: String,
    pub amount: String,
}

/// Which parties' holdings to read, of which template, as of when.
#[derive(Clone, Debug)]
pub struct HoldingsQuery {
    pub custody_parties: Vec<String>,
    /// Fully qualified template id, e.g. `#perp-custody:PerpCustody:Holding`.
    pub template_id: String,
    /// Exactly what `/state/ledger-end` returned. Kept as a JSON value
    /// because v2 offsets are numbers; re-encoding one as a string produces a
    /// request the participant rejects.
    pub active_at_offset: serde_json::Value,
}

impl HoldingsQuery {
    /// The offset in the report's opaque string form (SPEC §8.3).
    pub fn offset_string(&self) -> String {
        match &self.active_at_offset {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }
}

/// Reads the offset out of a `/state/ledger-end` response.
pub fn parse_ledger_end(body: &str) -> Result<serde_json::Value> {
    let parsed: serde_json::Value =
        serde_json::from_str(body).context("parsing the ledger-end response")?;
    parsed
        .get("offset")
        .cloned()
        .context("ledger-end response has no offset")
}

/// Whether a template id is package-*name* qualified, as a v2 request needs.
///
/// A participant rejects a package-id-qualified id with
/// `INVALID_FIELD: … expected a package name`, which does not obviously mean
/// "use `#package-name:` instead". Catching it here says so. Confirmed
/// against a mainnet participant: the request needs the name, the response
/// comes back qualified by id, and the two are not interchangeable.
pub fn is_package_name_qualified(template_id: &str) -> bool {
    match template_id.split_once(':') {
        Some((prefix, _)) => !(prefix.len() == 64 && prefix.chars().all(|c| c.is_ascii_hexdigit())),
        None => false,
    }
}

/// The v2 request for an active-contract snapshot.
pub fn active_contracts_request(query: &HoldingsQuery) -> Result<serde_json::Value> {
    if query.custody_parties.is_empty() {
        bail!("no custody parties declared: an empty party set reads an empty book");
    }
    if !is_package_name_qualified(&query.template_id) {
        bail!(
            "template id {:?} is package-id qualified; a v2 request needs the package name, \
             as in #package-name:Module:Template. Responses come back package-id qualified, \
             so the two forms are not interchangeable",
            query.template_id
        );
    }
    if query.active_at_offset.is_null() {
        bail!("no ledger offset: an unpinned read cannot be paired with a liabilities snapshot");
    }

    let party_filter = serde_json::json!({
        "cumulative": [{
            "identifierFilter": {
                "TemplateFilter": {
                    "value": {
                        "templateId": query.template_id,
                        "includeCreatedEventBlob": false
                    }
                }
            }
        }]
    });

    Ok(serde_json::json!({
        "filter": {
            "filtersByParty": query
                .custody_parties
                .iter()
                .map(|p| (p.clone(), party_filter.clone()))
                .collect::<serde_json::Map<_, _>>(),
        },
        "verbose": true,
        "activeAtOffset": query.active_at_offset,
    }))
}

/// Reads positions out of a v2 active-contracts response.
///
/// Unrecognised fields are ignored rather than rejected: a participant may
/// add fields, and refusing one would break on the next Canton release. That
/// is the opposite of the rule for our own documents, where an unknown field
/// could ride along unsigned — here the signature is ours, applied later.
pub fn parse_holdings(body: &str, fields: &HoldingFields) -> Result<Vec<CustodyPosition>> {
    let parsed: serde_json::Value =
        serde_json::from_str(body).context("parsing the participant's response")?;
    let items = parsed
        .as_array()
        .context("a v2 active-contracts response is a JSON array")?;

    let mut seen = std::collections::BTreeSet::new();
    let mut positions = Vec::with_capacity(items.len());
    for item in items {
        let created = item
            .pointer("/contractEntry/JsActiveContract/createdEvent")
            .context("entry has no contractEntry.JsActiveContract.createdEvent")?;
        let contract_id = created
            .get("contractId")
            .and_then(serde_json::Value::as_str)
            .context("createdEvent has no contractId")?
            .to_string();

        // A repeated contract id would double-count a position: the
        // asset-side equivalent of duplicating an odd node.
        if !seen.insert(contract_id.clone()) {
            bail!("contract {contract_id} appears twice in one snapshot");
        }

        let arguments = created
            .get("createArgument")
            .with_context(|| format!("contract {contract_id} has no createArgument"))?;
        let asset = arguments
            .get(&fields.asset)
            .and_then(serde_json::Value::as_str)
            .with_context(|| format!("contract {contract_id} has no {}", fields.asset))?
            .to_string();
        let raw = arguments
            .get(&fields.amount)
            .and_then(serde_json::Value::as_str)
            .with_context(|| {
                format!(
                    "contract {contract_id} has no {}, or it is not a string",
                    fields.amount
                )
            })?;
        let amount = canton_solvency_merkle::parse_amount_18dp(raw)
            .with_context(|| format!("amount for contract {contract_id}"))?;

        positions.push(CustodyPosition {
            contract_id,
            asset,
            amount,
        });
    }
    Ok(positions)
}

/// Reads holdings pinned to the participant's current ledger end.
///
/// Two calls, deliberately: the offset a snapshot is pinned to must be one
/// the participant reported, not one the caller guessed.
pub fn read_holdings<T: Transport>(
    transport: &T,
    custody_parties: Vec<String>,
    template_id: String,
    fields: &HoldingFields,
) -> Result<(Vec<CustodyPosition>, serde_json::Value)> {
    let end = transport
        .get(LEDGER_END_PATH)
        .context("reading the participant's ledger end")?;
    let offset = parse_ledger_end(&end)?;

    let query = HoldingsQuery {
        custody_parties,
        template_id,
        active_at_offset: offset.clone(),
    };
    let body = transport
        .post(
            ACTIVE_CONTRACTS_PATH,
            &serde_json::to_string(&active_contracts_request(&query)?)?,
        )
        .context("querying the participant")?;
    Ok((parse_holdings(&body, fields)?, offset))
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

    fn fields() -> HoldingFields {
        HoldingFields {
            asset: "instrument".to_string(),
            amount: "amount".to_string(),
        }
    }

    fn query() -> HoldingsQuery {
        HoldingsQuery {
            custody_parties: vec!["venue::custody".to_string(), "venue::omnibus".to_string()],
            template_id: "#perp-custody:PerpCustody:Holding".to_string(),
            active_at_offset: serde_json::json!(4242),
        }
    }

    /// A canned participant. The socket is the only part of this crate that
    /// needs a real node; everything else is exercised here.
    struct FakeLedger {
        end: String,
        contracts: String,
        seen: std::cell::RefCell<Vec<String>>,
    }

    impl Transport for FakeLedger {
        fn get(&self, path: &str) -> Result<String> {
            self.seen.borrow_mut().push(format!("GET {path}"));
            Ok(self.end.clone())
        }
        fn post(&self, path: &str, body: &str) -> Result<String> {
            self.seen.borrow_mut().push(format!("POST {path} {body}"));
            Ok(self.contracts.clone())
        }
    }

    /// Shaped exactly like a real v2 response, taken from the wire format the
    /// production bridge parses.
    /// The exact shape a mainnet participant returns, with identifiers
    /// replaced. Captured from a live read rather than written from the docs
    /// — the extra fields here are why unrecognised ones are ignored.
    const TWO_POSITIONS: &str = r#"[
      {"workflowId":"","contractEntry":{"JsActiveContract":{"createdEvent":{
        "offset":2699612,"nodeId":0,
        "contractId":"00c1",
        "templateId":"c98324dbef348a967e3de31c9ed90778aa6d9b788f5ff833a080f410c0f12f26:PerpCustody:Holding",
        "contractKey":null,"contractKeyHash":"",
        "createArgument":{"instrument":"USDA","amount":"100.5","owner":"venue::custody"},
        "createdEventBlob":""}}}},
      {"workflowId":"","contractEntry":{"JsActiveContract":{"createdEvent":{
        "offset":2699613,"nodeId":0,
        "contractId":"00c2",
        "templateId":"c98324dbef348a967e3de31c9ed90778aa6d9b788f5ff833a080f410c0f12f26:PerpCustody:Holding",
        "contractKey":null,"contractKeyHash":"",
        "createArgument":{"instrument":"CBTC","amount":"0.25","owner":"venue::custody"},
        "createdEventBlob":""}}}}
    ]"#;

    fn ledger(contracts: &str) -> FakeLedger {
        FakeLedger {
            end: r#"{"offset": 4242}"#.to_string(),
            contracts: contracts.to_string(),
            seen: std::cell::RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn the_request_uses_the_v2_cumulative_template_filter() {
        let request = active_contracts_request(&query()).unwrap();
        let filter = &request["filter"]["filtersByParty"]["venue::custody"];
        assert_eq!(
            filter["cumulative"][0]["identifierFilter"]["TemplateFilter"]["value"]["templateId"],
            "#perp-custody:PerpCustody:Holding"
        );
        // The v1 shape must not reappear: no participant accepts it.
        assert!(filter.get("inclusive").is_none());
    }

    #[test]
    fn the_request_names_every_declared_party() {
        let request = active_contracts_request(&query()).unwrap();
        let parties = request["filter"]["filtersByParty"].as_object().unwrap();
        assert_eq!(parties.len(), 2);
        assert!(parties.contains_key("venue::omnibus"));
    }

    /// v2 offsets are numbers. Sending `"4242"` where the participant expects
    /// `4242` is rejected, and a string round-trip would do exactly that.
    #[test]
    fn the_offset_keeps_the_type_the_participant_reported() {
        let request = active_contracts_request(&query()).unwrap();
        assert_eq!(request["activeAtOffset"], serde_json::json!(4242));
        assert!(request["activeAtOffset"].is_number());
    }

    #[test]
    fn the_offset_still_renders_as_an_opaque_string_for_the_report() {
        assert_eq!(query().offset_string(), "4242");
        assert_eq!(
            HoldingsQuery {
                active_at_offset: serde_json::json!("000000042"),
                ..query()
            }
            .offset_string(),
            "000000042"
        );
    }

    #[test]
    fn ledger_end_is_read_from_the_offset_field() {
        assert_eq!(
            parse_ledger_end(r#"{"offset": 99}"#).unwrap(),
            serde_json::json!(99)
        );
        assert!(parse_ledger_end(r#"{"nope": 1}"#).is_err());
    }

    /// The live participant's own error does not say "prefix it with #".
    #[test]
    fn a_package_id_qualified_template_is_refused_with_an_explanation() {
        let err = active_contracts_request(&HoldingsQuery {
            template_id:
                "c98324dbef348a967e3de31c9ed90778aa6d9b788f5ff833a080f410c0f12f26:PerpCustody:Holding"
                    .to_string(),
            ..query()
        })
        .unwrap_err();
        assert!(err.to_string().contains("package name"), "got {err}");
        assert!(err.to_string().contains('#'), "got {err}");
    }

    #[test]
    fn package_name_qualification_is_recognised_either_way() {
        assert!(is_package_name_qualified(
            "#perp-custody:PerpCustody:Holding"
        ));
        assert!(is_package_name_qualified(
            "perp-custody:PerpCustody:Holding"
        ));
        assert!(!is_package_name_qualified(
            "c98324dbef348a967e3de31c9ed90778aa6d9b788f5ff833a080f410c0f12f26:M:T"
        ));
        assert!(!is_package_name_qualified("no-colons"));
    }

    /// Responses carry package-id-qualified template ids even though requests
    /// must not. Parsing must not care.
    #[test]
    fn a_response_with_package_id_qualified_templates_still_parses() {
        assert_eq!(parse_holdings(TWO_POSITIONS, &fields()).unwrap().len(), 2);
    }

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
            active_at_offset: serde_json::Value::Null,
            ..query()
        })
        .unwrap_err();
        assert!(err.to_string().contains("unpinned"), "got {err}");
    }

    #[test]
    fn a_v2_response_is_parsed_into_positions() {
        let positions = parse_holdings(TWO_POSITIONS, &fields()).unwrap();
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0].contract_id, "00c1");
        assert_eq!(positions[0].asset, "USDA");
        assert_eq!(positions[0].amount, 100_500_000_000_000_000_000);
    }

    /// A participant may add fields; refusing one would break on the next
    /// Canton release.
    #[test]
    fn unrecognised_fields_in_the_response_are_ignored() {
        let body = mutate(
            r#""owner":"venue::custody""#,
            r#""owner":"venue::custody","somethingNew":{"a":1}"#,
        );
        assert_eq!(parse_holdings(&body, &fields()).unwrap().len(), 2);
    }

    /// The v1 shape must fail loudly rather than silently reading nothing.
    #[test]
    fn a_v1_shaped_response_is_refused() {
        let v1 = r#"{"result":[{"contractId":"c1","createArguments":{"instrument":"USDA","amount":"1"}}]}"#;
        let err = parse_holdings(v1, &fields()).unwrap_err();
        assert!(err.to_string().contains("JSON array"), "got {err}");
    }

    #[test]
    fn a_repeated_contract_in_one_snapshot_is_refused() {
        let body = mutate("00c2", "00c1");
        let err = parse_holdings(&body, &fields()).unwrap_err();
        assert!(err.to_string().contains("twice"), "got {err}");
    }

    /// Mutating a fixture that does not contain the pattern silently tests
    /// the unmutated document. This has bitten this repository twice.
    fn mutate(from: &str, to: &str) -> String {
        assert!(
            TWO_POSITIONS.contains(from),
            "fixture mutation {from:?} matched nothing"
        );
        TWO_POSITIONS.replacen(from, to, 1)
    }

    #[test]
    fn a_malformed_amount_names_the_contract_it_came_from() {
        let body = mutate(r#""amount":"100.5""#, r#""amount":"-1""#);
        let err = format!("{:#}", parse_holdings(&body, &fields()).unwrap_err());
        assert!(err.contains("00c1"), "got {err}");
    }

    #[test]
    fn a_missing_amount_field_names_the_contract() {
        let body = mutate(r#""amount":"100.5","#, "");
        let err = format!("{:#}", parse_holdings(&body, &fields()).unwrap_err());
        assert!(err.contains("00c1") && err.contains("amount"), "got {err}");
    }

    #[test]
    fn an_empty_snapshot_parses_to_no_positions() {
        assert_eq!(parse_holdings("[]", &fields()).unwrap(), vec![]);
    }

    #[test]
    fn reading_pins_to_ledger_end_and_returns_the_offset() {
        let ledger = ledger(TWO_POSITIONS);
        let (positions, offset) = read_holdings(
            &ledger,
            vec!["venue::custody".to_string()],
            "#perp-custody:PerpCustody:Holding".to_string(),
            &fields(),
        )
        .unwrap();

        assert_eq!(positions.len(), 2);
        assert_eq!(offset, serde_json::json!(4242));

        let seen = ledger.seen.borrow();
        assert_eq!(seen[0], "GET /state/ledger-end");
        assert!(seen[1].starts_with("POST /state/active-contracts "));
        // The snapshot is pinned to the offset the participant reported, not
        // to one the caller chose.
        assert!(
            seen[1].contains("\"activeAtOffset\":4242"),
            "got {}",
            seen[1]
        );
    }

    #[test]
    fn totals_add_positions_per_asset() {
        let positions = parse_holdings(TWO_POSITIONS, &fields()).unwrap();
        let totals = totals(&positions).unwrap();
        assert_eq!(totals["USDA"], 100_500_000_000_000_000_000);
        assert_eq!(totals["CBTC"], 250_000_000_000_000_000);
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
