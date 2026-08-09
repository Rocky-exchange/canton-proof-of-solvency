//! The disclosure profile registry (SPEC §14).
//!
//! A report already carries a `profile` field, but until now nothing checked
//! it: any string was accepted and no rules attached to it. A profile names
//! the statement a root asserts, so leaving it unchecked meant a report could
//! claim to be one thing and be another.
//!
//! Each entry pins what a leaf represents, the statement the root asserts,
//! and the aggregates the report must publish for that statement to mean
//! anything.

use crate::document::Report;

/// What a leaf of the committed tree stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafKind {
    /// One customer's per-asset equity (SPEC §3).
    Customer,
    /// One subsidiary's root, in a group tree (SPEC §13.1).
    Entity,
    /// One open repo leg, carrying collateral and exposure (SPEC §3.1).
    RepoLeg,
    /// One holder of a tokenized fund, carrying units and entitlement.
    Shareholder,
}

impl LeafKind {
    /// Whether this kind is committed with a v2 leaf (SPEC §3.1). A v2 proof
    /// belongs to any v2-leaf profile, not to one specific profile.
    pub fn uses_leaf_v2(&self) -> bool {
        matches!(self, Self::RepoLeg | Self::Shareholder)
    }
}

/// A profile rule requiring one map to cover another, per asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub covering: &'static str,
    pub covered: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileRules {
    pub name: &'static str,
    /// What a verifier learns when a proof against this root succeeds.
    pub statement: &'static str,
    pub leaf: LeafKind,
    /// Report fields that must carry data, or the statement is vacuous. A
    /// name ending in `/*` requires at least one qualified sum with that
    /// prefix, as produced by a v2 leaf.
    pub required_aggregates: &'static [&'static str],
    /// Enforced at the root: the covering map must be at least the covered
    /// one for every asset.
    pub coverage: Option<Coverage>,
}

pub const SOLVENCY_LIABILITIES: ProfileRules = ProfileRules {
    name: "solvency.liabilities",
    statement: "every customer balance is committed, and the root's totals are the liabilities",
    leaf: LeafKind::Customer,
    required_aggregates: &["root_sums"],
    coverage: None,
};

pub const SOLVENCY_GROUP: ProfileRules = ProfileRules {
    name: "solvency.group",
    statement:
        "every entity's root is committed, and the root's totals are the consolidated liabilities",
    leaf: LeafKind::Entity,
    required_aggregates: &["root_sums"],
    coverage: None,
};

/// The first profile a v1 leaf could not express: comparing two amount maps
/// is the entire statement.
pub const COLLATERAL_REPO: ProfileRules = ProfileRules {
    name: "collateral.repo",
    statement:
        "every open repo leg is committed, and the root totals are aggregate collateral and exposure",
    leaf: LeafKind::RepoLeg,
    required_aggregates: &["collateral/*", "exposure/*"],
    coverage: Some(Coverage {
        covering: "collateral",
        covered: "exposure",
    }),
};

/// A leaf is one **shareholder**, not one holding line item.
///
/// A holdings tree would prove what the fund owns, but no investor could find
/// themselves in it, and being able to find yourself is the whole pattern of
/// this project. Whether the fund actually holds enough to back those
/// entitlements is an asset-side question, which is what a coverage report
/// answers — not something a liabilities tree can prove about itself.
///
/// `units` is keyed by share class and `entitlement` by currency, so NAV per
/// share is derivable from the published root by anyone.
pub const FUND_NAV: ProfileRules = ProfileRules {
    name: "fund.nav",
    statement:
        "every holder's units and entitlement are committed, and the root totals are units outstanding and total entitlement",
    leaf: LeafKind::Shareholder,
    required_aggregates: &["units/*", "entitlement/*"],
    coverage: None,
};

pub const REGISTRY: &[ProfileRules] = &[
    SOLVENCY_LIABILITIES,
    SOLVENCY_GROUP,
    COLLATERAL_REPO,
    FUND_NAV,
];

pub fn lookup(name: &str) -> Option<&'static ProfileRules> {
    REGISTRY.iter().find(|rules| rules.name == name)
}

/// The declared profile must be registered, and the report must carry the
/// aggregates that profile requires.
pub fn validate(report: &Report) -> Result<&'static ProfileRules, ProfileError> {
    let rules = lookup(&report.profile).ok_or_else(|| ProfileError::Unknown {
        found: report.profile.clone(),
    })?;

    for aggregate in rules.required_aggregates {
        let present = match *aggregate {
            "root_sums" => !report.root_sums.is_empty(),
            "mark_prices" => !report.mark_prices.is_empty(),
            qualified if qualified.ends_with("/*") => {
                let prefix = &qualified[..qualified.len() - 1];
                report.root_sums.keys().any(|k| k.starts_with(prefix))
            }
            other => {
                return Err(ProfileError::Violation {
                    profile: rules.name.to_string(),
                    detail: format!(
                        "registry names an aggregate the verifier cannot check: {other}"
                    ),
                })
            }
        };
        if !present {
            return Err(ProfileError::Violation {
                profile: rules.name.to_string(),
                detail: format!(
                    "{aggregate} is required by this profile but the report carries none, \
                     so the statement would be vacuous"
                ),
            });
        }
    }
    if let Some(Coverage { covering, covered }) = rules.coverage {
        // Per asset: a surplus in one asset does not excuse a shortfall in
        // another, which is the same rule the coverage report will use.
        for (key, required) in &report.root_sums {
            let Some(asset) = key.strip_prefix(&format!("{covered}/")) else {
                continue;
            };
            let held = report
                .root_sums
                .get(&format!("{covering}/{asset}"))
                .copied()
                .unwrap_or(0);
            if held < *required {
                return Err(ProfileError::Violation {
                    profile: rules.name.to_string(),
                    detail: format!(
                        "{covering} of {} does not cover {covered} of {} for {asset}",
                        canton_solvency_merkle::format_amount_18dp(held),
                        canton_solvency_merkle::format_amount_18dp(*required)
                    ),
                });
            }
        }
    }
    Ok(rules)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    Unknown { found: String },
    Violation { profile: String, detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden;

    #[test]
    fn the_registry_resolves_known_profiles_and_rejects_others() {
        assert_eq!(lookup("solvency.liabilities"), Some(&SOLVENCY_LIABILITIES));
        assert_eq!(lookup("solvency.group"), Some(&SOLVENCY_GROUP));
        assert_eq!(lookup("collateral.repo"), Some(&COLLATERAL_REPO));
        assert_eq!(lookup("fund.nav"), Some(&FUND_NAV));
        assert_eq!(lookup("eligibility.holder"), None, "not yet designed");
        assert_eq!(lookup(""), None);
    }

    #[test]
    fn registry_names_match_their_entries() {
        for rules in REGISTRY {
            assert_eq!(lookup(rules.name), Some(rules), "{}", rules.name);
        }
    }

    #[test]
    fn a_customer_profile_and_a_group_profile_commit_to_different_leaves() {
        assert_eq!(SOLVENCY_LIABILITIES.leaf, LeafKind::Customer);
        assert_eq!(SOLVENCY_GROUP.leaf, LeafKind::Entity);
    }

    #[test]
    fn the_golden_report_satisfies_its_declared_profile() {
        let (signed, _) = golden::fixture();
        assert_eq!(validate(&signed.report), Ok(&SOLVENCY_LIABILITIES));
    }

    #[test]
    fn the_golden_group_report_satisfies_the_group_profile() {
        let (group, _) = golden::group_fixture();
        assert_eq!(validate(&group.report), Ok(&SOLVENCY_GROUP));
    }

    #[test]
    fn an_unregistered_profile_is_rejected_rather_than_waved_through() {
        let (mut signed, _) = golden::fixture();
        signed.report.profile = "settlement.dvp".to_string();
        assert_eq!(
            validate(&signed.report),
            Err(ProfileError::Unknown {
                found: "settlement.dvp".to_string()
            })
        );
    }

    fn repo_report(sums: &[(&str, u128)]) -> Report {
        let (mut signed, _) = golden::fixture();
        signed.report.profile = "collateral.repo".to_string();
        signed.report.root_sums = sums.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        signed.report
    }

    #[test]
    fn a_repo_report_covering_its_exposure_is_accepted() {
        let report = repo_report(&[("collateral/USDA", 110), ("exposure/USDA", 100)]);
        assert_eq!(validate(&report), Ok(&COLLATERAL_REPO));
    }

    #[test]
    fn exactly_covering_the_exposure_is_enough() {
        let report = repo_report(&[("collateral/USDA", 100), ("exposure/USDA", 100)]);
        assert!(validate(&report).is_ok());
    }

    /// The statement the profile exists to make, checked rather than asserted.
    #[test]
    fn a_repo_report_short_of_its_exposure_is_rejected() {
        let report = repo_report(&[("collateral/USDA", 99), ("exposure/USDA", 100)]);
        match validate(&report) {
            Err(ProfileError::Violation { detail, .. }) => {
                assert!(detail.contains("does not cover"), "got {detail}");
                assert!(detail.contains("USDA"), "got {detail}");
            }
            other => panic!("expected a violation, got {other:?}"),
        }
    }

    /// A surplus in one asset must not excuse a shortfall in another.
    #[test]
    fn coverage_is_required_per_asset_not_in_aggregate() {
        let report = repo_report(&[
            ("collateral/USDA", 1_000),
            ("exposure/USDA", 1),
            ("collateral/CBTC", 1),
            ("exposure/CBTC", 500),
        ]);
        match validate(&report) {
            Err(ProfileError::Violation { detail, .. }) => {
                assert!(detail.contains("CBTC"), "got {detail}")
            }
            other => panic!("expected a violation, got {other:?}"),
        }
    }

    /// Exposure in an asset with no collateral at all is the worst case, and
    /// an absent key must not read as "no requirement".
    #[test]
    fn exposure_with_no_collateral_entry_is_rejected() {
        let report = repo_report(&[("collateral/USDA", 100), ("exposure/CBTC", 1)]);
        assert!(validate(&report).is_err());
    }

    #[test]
    fn a_repo_report_missing_a_required_map_is_rejected() {
        let report = repo_report(&[("collateral/USDA", 100)]);
        match validate(&report) {
            Err(ProfileError::Violation { detail, .. }) => {
                assert!(detail.contains("exposure"), "got {detail}")
            }
            other => panic!("expected a violation, got {other:?}"),
        }
    }

    #[test]
    fn a_fund_report_publishing_units_and_entitlement_is_accepted() {
        let (mut signed, _) = golden::fixture();
        signed.report.profile = "fund.nav".to_string();
        signed.report.root_sums = [
            ("units/CLASS_A".to_string(), 1_000u128),
            ("entitlement/USDA".to_string(), 2_000u128),
        ]
        .into_iter()
        .collect();
        assert_eq!(validate(&signed.report), Ok(&FUND_NAV));
    }

    /// Units with no entitlement, or the reverse, cannot express a NAV.
    #[test]
    fn a_fund_report_missing_either_map_is_rejected() {
        for only in ["units/CLASS_A", "entitlement/USDA"] {
            let (mut signed, _) = golden::fixture();
            signed.report.profile = "fund.nav".to_string();
            signed.report.root_sums = [(only.to_string(), 1u128)].into_iter().collect();
            assert!(
                validate(&signed.report).is_err(),
                "{only} alone was accepted"
            );
        }
    }

    #[test]
    fn only_v2_leaf_profiles_report_using_leaf_v2() {
        assert!(COLLATERAL_REPO.leaf.uses_leaf_v2());
        assert!(FUND_NAV.leaf.uses_leaf_v2());
        assert!(!SOLVENCY_LIABILITIES.leaf.uses_leaf_v2());
        assert!(!SOLVENCY_GROUP.leaf.uses_leaf_v2());
    }

    /// A liabilities report with no totals asserts nothing at all.
    #[test]
    fn a_profile_missing_its_required_aggregates_is_rejected() {
        let (mut signed, _) = golden::fixture();
        signed.report.root_sums.clear();
        match validate(&signed.report) {
            Err(ProfileError::Violation { profile, detail }) => {
                assert_eq!(profile, "solvency.liabilities");
                assert!(detail.contains("root_sums"), "got {detail}");
            }
            other => panic!("expected a violation, got {other:?}"),
        }
    }
}
