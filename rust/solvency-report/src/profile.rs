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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileRules {
    pub name: &'static str,
    /// What a verifier learns when a proof against this root succeeds.
    pub statement: &'static str,
    pub leaf: LeafKind,
    /// Report fields that must carry data, or the statement is vacuous.
    pub required_aggregates: &'static [&'static str],
}

pub const SOLVENCY_LIABILITIES: ProfileRules = ProfileRules {
    name: "solvency.liabilities",
    statement: "every customer balance is committed, and the root's totals are the liabilities",
    leaf: LeafKind::Customer,
    required_aggregates: &["root_sums"],
};

pub const SOLVENCY_GROUP: ProfileRules = ProfileRules {
    name: "solvency.group",
    statement:
        "every entity's root is committed, and the root's totals are the consolidated liabilities",
    leaf: LeafKind::Entity,
    required_aggregates: &["root_sums"],
};

pub const REGISTRY: &[ProfileRules] = &[SOLVENCY_LIABILITIES, SOLVENCY_GROUP];

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
        assert_eq!(lookup("collateral.repo"), None);
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
        signed.report.profile = "collateral.repo".to_string();
        assert_eq!(
            validate(&signed.report),
            Err(ProfileError::Unknown {
                found: "collateral.repo".to_string()
            })
        );
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
