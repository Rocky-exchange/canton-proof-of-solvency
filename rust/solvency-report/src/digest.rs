//! Length-prefixed digest primitives.
//!
//! Every variable-length field enters a digest preimage as an explicit byte
//! length followed by its bytes. Delimiter-joined encodings (as used for
//! balance sets in the core crate) are ambiguous once any component is
//! attacker-influenced: an asset named `A|B:1` can imitate two entries.
//! Length prefixes remove that class of forgery entirely.

use crate::document::Report;
use canton_solvency_merkle::format_amount_18dp;
use std::collections::BTreeMap;

pub const REPORT_DIGEST_DOMAIN: &[u8] = b"rocky-solvency-report-v1";

/// SHA-256 over the domain string and every report field, length-prefixed
/// (SPEC §8). This is the value that gets signed, and the value a proof
/// document names to bind itself to one report.
pub fn report_digest(report: &Report) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(REPORT_DIGEST_DOMAIN);
    h.update(lp(&report.format_version));
    h.update(lp(&report.profile));
    h.update(lp(&report.publisher));
    h.update(lp(&report.snapshot_time));
    h.update(lp(&report.ledger_offset));
    h.update(lp(&report.root_hash));
    h.update(report.leaf_count.to_le_bytes());
    h.update(lpmap(&report.root_sums));
    h.update(lpmap(&report.mark_prices));
    h.update(lpmap(&report.disclosures.bad_debt));
    h.update(report.disclosures.excluded_house_accounts.to_le_bytes());
    h.update(lpmap(&report.disclosures.excluded_house_totals));
    h.finalize().into()
}

/// `u64le(len) ‖ utf8(s)`.
pub fn lp(s: &str) -> Vec<u8> {
    let mut out = (s.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(s.as_bytes());
    out
}

/// `u64le(count) ‖ (lp(asset) ‖ lp(canonical_amount))*`, assets bytewise.
pub fn lpmap(m: &BTreeMap<String, u128>) -> Vec<u8> {
    let mut out = (m.len() as u64).to_le_bytes().to_vec();
    for (asset, amount) in m {
        out.extend(lp(asset));
        out.extend(lp(&format_amount_18dp(*amount)));
    }
    out
}

/// Hex rendering of [`report_digest`], the form that appears in proof
/// documents and on the wire.
pub fn report_digest_hex(report: &Report) -> String {
    hex::encode(report_digest(report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, u128)]) -> BTreeMap<String, u128> {
        entries.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn lp_prefixes_the_utf8_length_as_little_endian_u64() {
        assert_eq!(
            lp("ab"),
            vec![2, 0, 0, 0, 0, 0, 0, 0, b'a', b'b'],
            "expected an 8-byte LE length followed by the raw bytes"
        );
    }

    #[test]
    fn lpmap_counts_entries_then_emits_them_in_bytewise_asset_order() {
        let mut expected = 2u64.to_le_bytes().to_vec();
        expected.extend(lp("AAA"));
        expected.extend(lp("0.000000000000000002"));
        expected.extend(lp("ZZZ"));
        expected.extend(lp("0.000000000000000001"));

        assert_eq!(lpmap(&map(&[("ZZZ", 1), ("AAA", 2)])), expected);
    }

    #[test]
    fn lpmap_is_empty_but_counted_for_an_empty_map() {
        assert_eq!(lpmap(&map(&[])), 0u64.to_le_bytes().to_vec());
    }

    /// A named way a publisher could edit a report after signing it.
    type Mutation = (&'static str, Box<dyn Fn(&mut Report)>);

    fn sample() -> Report {
        Report {
            format_version: crate::document::REPORT_FORMAT_VERSION.to_string(),
            profile: "solvency.liabilities".to_string(),
            publisher: "rocky::122099".to_string(),
            snapshot_time: "2026-08-09T00:00:00Z".to_string(),
            ledger_offset: "000000000000012345".to_string(),
            root_hash: "02".repeat(32),
            leaf_count: 3,
            root_sums: map(&[("USDA", 100)]),
            mark_prices: map(&[("CBTC", 64_000)]),
            disclosures: crate::document::Disclosures {
                bad_debt: map(&[("USDA", 12)]),
                excluded_house_accounts: 2,
                excluded_house_totals: map(&[("USDA", 5000)]),
            },
        }
    }

    /// Each mutation is a way a publisher could restate a report while
    /// reusing an old signature. All of them must move the digest.
    #[test]
    fn every_report_field_is_covered_by_the_digest() {
        let base = report_digest(&sample());
        let mutations: Vec<Mutation> = vec![
            ("profile", Box::new(|r: &mut Report| r.profile.push('x'))),
            (
                "publisher",
                Box::new(|r: &mut Report| r.publisher.push('x')),
            ),
            (
                "snapshot_time",
                Box::new(|r: &mut Report| r.snapshot_time = "2026-08-10T00:00:00Z".into()),
            ),
            (
                "ledger_offset",
                Box::new(|r: &mut Report| r.ledger_offset.push('9')),
            ),
            (
                "root_hash",
                Box::new(|r: &mut Report| r.root_hash = "03".repeat(32)),
            ),
            ("leaf_count", Box::new(|r: &mut Report| r.leaf_count += 1)),
            (
                "root_sums",
                Box::new(|r: &mut Report| {
                    r.root_sums.insert("USDA".into(), 101);
                }),
            ),
            (
                "mark_prices",
                Box::new(|r: &mut Report| {
                    r.mark_prices.insert("CBTC".into(), 1);
                }),
            ),
            (
                "bad_debt",
                Box::new(|r: &mut Report| {
                    r.disclosures.bad_debt.insert("USDA".into(), 13);
                }),
            ),
            (
                "excluded_house_accounts",
                Box::new(|r: &mut Report| r.disclosures.excluded_house_accounts += 1),
            ),
            (
                "excluded_house_totals",
                Box::new(|r: &mut Report| {
                    r.disclosures.excluded_house_totals.insert("USDA".into(), 1);
                }),
            ),
            (
                "format_version",
                Box::new(|r: &mut Report| r.format_version.push('9')),
            ),
        ];
        for (field, mutate) in mutations {
            let mut mutated = sample();
            mutate(&mut mutated);
            assert_ne!(
                base,
                report_digest(&mutated),
                "changing {field} left the digest unchanged, so a signature would still verify"
            );
        }
    }

    /// The reason for length prefixes: an asset name cannot impersonate a
    /// delimiter and shift the boundary between two fields.
    #[test]
    fn asset_names_cannot_forge_map_boundaries() {
        let mut a = sample();
        a.root_sums = map(&[("A|B:0.000000000000000001", 1)]);
        let mut b = sample();
        b.root_sums = map(&[("A", 1), ("B", 1)]);
        assert_ne!(report_digest(&a), report_digest(&b));
    }

    #[test]
    fn report_digest_hex_is_the_lowercase_hex_of_the_digest() {
        let report = sample();
        assert_eq!(
            report_digest_hex(&report),
            hex::encode(report_digest(&report))
        );
        assert_eq!(report_digest_hex(&report).len(), 64);
    }

    #[test]
    fn report_digest_is_stable_across_calls() {
        assert_eq!(report_digest(&sample()), report_digest(&sample()));
    }
}
