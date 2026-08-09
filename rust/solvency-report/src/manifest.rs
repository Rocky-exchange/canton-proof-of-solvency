//! The disclosure manifest (SPEC §8.5).
//!
//! A report is otherwise honest about what it contains and silent about what
//! it chose not to contain. The manifest makes the disclosure decision itself
//! part of the signed artefact, so a reduction between reports is on the
//! record rather than something a reader had to be watching for.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a field was handled in this report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disclosure {
    /// Present in the report body and readable.
    Published,
    /// Proven through the commitment but not shown.
    Committed,
    /// Deliberately not disclosed to this audience.
    Withheld,
}

impl Disclosure {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Committed => "committed",
            Self::Withheld => "withheld",
        }
    }
}

/// Field paths a manifest may speak about. An unrecognised key is rejected
/// rather than ignored, so a producer cannot bury a field the verifier has no
/// opinion about.
pub const KNOWN_FIELDS: &[&str] = &[
    "root_sums",
    "mark_prices",
    "disclosures.bad_debt",
    "disclosures.excluded_house_accounts",
    "disclosures.excluded_house_totals",
    "customer_balances",
    "customer_identities",
];

/// Fields that live in the report body, and can therefore be cross-checked
/// against what the report actually carries.
pub const REPORT_RESIDENT_FIELDS: &[&str] = &[
    "root_sums",
    "mark_prices",
    "disclosures.bad_debt",
    "disclosures.excluded_house_accounts",
    "disclosures.excluded_house_totals",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Who this packaging of the report is cut for, e.g. `public`, `auditor`.
    pub audience: String,
    pub fields: BTreeMap<String, Disclosure>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestChange {
    Added {
        path: String,
        state: Disclosure,
    },
    Removed {
        path: String,
        was: Disclosure,
    },
    Changed {
        path: String,
        from: Disclosure,
        to: Disclosure,
    },
}

impl ManifestChange {
    pub fn path(&self) -> &str {
        match self {
            Self::Added { path, .. } | Self::Removed { path, .. } | Self::Changed { path, .. } => {
                path
            }
        }
    }

    /// A move away from `published`, or the removal of a field that was
    /// published. This is the direction a regulator cares about.
    pub fn is_reduction(&self) -> bool {
        match self {
            Self::Added { .. } => false,
            Self::Removed { was, .. } => *was == Disclosure::Published,
            Self::Changed { from, to, .. } => {
                *from == Disclosure::Published && *to != Disclosure::Published
            }
        }
    }
}

/// Field-by-field comparison of two manifests, in path order.
pub fn diff(previous: &Manifest, current: &Manifest) -> Vec<ManifestChange> {
    let mut paths: Vec<&String> = previous
        .fields
        .keys()
        .chain(current.fields.keys())
        .collect();
    paths.sort();
    paths.dedup();

    paths
        .into_iter()
        .filter_map(
            |path| match (previous.fields.get(path), current.fields.get(path)) {
                (Some(from), Some(to)) if from != to => Some(ManifestChange::Changed {
                    path: path.clone(),
                    from: *from,
                    to: *to,
                }),
                (Some(_), Some(_)) => None,
                (None, Some(state)) => Some(ManifestChange::Added {
                    path: path.clone(),
                    state: *state,
                }),
                (Some(was), None) => Some(ManifestChange::Removed {
                    path: path.clone(),
                    was: *was,
                }),
                (None, None) => unreachable!("path came from one of the two maps"),
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(entries: &[(&str, Disclosure)]) -> Manifest {
        Manifest {
            audience: "public".to_string(),
            fields: entries.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    use Disclosure::*;

    #[test]
    fn a_manifest_round_trips_through_json_with_lowercase_states() {
        let m = manifest(&[("root_sums", Published), ("mark_prices", Withheld)]);
        let text = serde_json::to_string(&m).unwrap();
        assert!(text.contains("\"published\""), "got {text}");
        assert_eq!(serde_json::from_str::<Manifest>(&text).unwrap(), m);
    }

    #[test]
    fn unknown_manifest_keys_are_rejected_by_the_schema_of_states() {
        let bad = r#"{"audience":"public","fields":{"root_sums":"maybe"}}"#;
        assert!(serde_json::from_str::<Manifest>(bad).is_err());
    }

    #[test]
    fn diff_reports_nothing_for_identical_manifests() {
        let m = manifest(&[("root_sums", Published)]);
        assert!(diff(&m, &m).is_empty());
    }

    #[test]
    fn diff_reports_an_added_field() {
        let before = manifest(&[("root_sums", Published)]);
        let after = manifest(&[("root_sums", Published), ("mark_prices", Published)]);
        assert_eq!(
            diff(&before, &after),
            vec![ManifestChange::Added {
                path: "mark_prices".to_string(),
                state: Published
            }]
        );
    }

    #[test]
    fn diff_reports_a_removed_field() {
        let before = manifest(&[("root_sums", Published), ("mark_prices", Published)]);
        let after = manifest(&[("root_sums", Published)]);
        assert_eq!(
            diff(&before, &after),
            vec![ManifestChange::Removed {
                path: "mark_prices".to_string(),
                was: Published
            }]
        );
    }

    #[test]
    fn diff_reports_a_state_change() {
        let before = manifest(&[("mark_prices", Published)]);
        let after = manifest(&[("mark_prices", Withheld)]);
        assert_eq!(
            diff(&before, &after),
            vec![ManifestChange::Changed {
                path: "mark_prices".to_string(),
                from: Published,
                to: Withheld
            }]
        );
    }

    #[test]
    fn diff_is_ordered_by_path_so_output_is_stable() {
        let before = manifest(&[("root_sums", Published)]);
        let after = manifest(&[
            ("root_sums", Published),
            ("mark_prices", Published),
            ("customer_balances", Committed),
        ]);
        let changes = diff(&before, &after);
        let paths: Vec<&str> = changes.iter().map(|c| c.path()).collect();
        assert_eq!(paths, vec!["customer_balances", "mark_prices"]);
    }

    /// The classification a regulator acts on: what stopped being disclosed.
    #[test]
    fn reductions_are_distinguished_from_expansions() {
        let published_to_withheld = ManifestChange::Changed {
            path: "mark_prices".into(),
            from: Published,
            to: Withheld,
        };
        let published_to_committed = ManifestChange::Changed {
            path: "mark_prices".into(),
            from: Published,
            to: Committed,
        };
        let removed_published = ManifestChange::Removed {
            path: "mark_prices".into(),
            was: Published,
        };
        assert!(published_to_withheld.is_reduction());
        assert!(published_to_committed.is_reduction());
        assert!(removed_published.is_reduction());

        let withheld_to_published = ManifestChange::Changed {
            path: "mark_prices".into(),
            from: Withheld,
            to: Published,
        };
        let added = ManifestChange::Added {
            path: "mark_prices".into(),
            state: Published,
        };
        let removed_withheld = ManifestChange::Removed {
            path: "mark_prices".into(),
            was: Withheld,
        };
        assert!(!withheld_to_published.is_reduction());
        assert!(!added.is_reduction());
        assert!(!removed_withheld.is_reduction());
    }
}
