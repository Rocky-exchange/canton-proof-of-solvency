//! Argument parsing. Every usage error surfaces here so `run` only ever sees
//! a well-formed command.

use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const USAGE: &str = "\
canton-solvency-verify — offline verification of Canton solvency reports

USAGE:
  canton-solvency-verify verify --report <path> --key <hex64>
                                (--proof <path> | --proof-dir <dir>) [--json]
  canton-solvency-verify verify-group --report <group-report> --key <hex64>
                                (--membership <path> | --membership-dir <dir>) [--json]
  canton-solvency-verify verify-chain --group-report <path> --membership <path>
                                --report <path> --proof <path>
                                --key <hex64> [--group-key <hex64>] [--json]
  canton-solvency-verify digest --report <path>
  canton-solvency-verify --help | --version

The trusted key is required. A report checked against the key embedded in
itself proves only internal consistency, never who published it.

EXIT CODES:
  0  everything verified
  1  at least one verification failed
  2  usage, I/O, or parse error";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofSource {
    File(PathBuf),
    Dir(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Verify {
        report: PathBuf,
        proofs: ProofSource,
        trusted_key: String,
        json: bool,
    },
    /// Entity memberships against a group report (SPEC §13.3).
    VerifyGroup {
        report: PathBuf,
        memberships: ProofSource,
        trusted_key: String,
        json: bool,
    },
    /// A customer all the way to a group's consolidated total (SPEC §13.4).
    VerifyChain {
        group_report: PathBuf,
        membership: PathBuf,
        report: PathBuf,
        proof: PathBuf,
        trusted_key: String,
        /// Defaults to `trusted_key`; groups and entities may publish under
        /// different keys.
        group_key: String,
        json: bool,
    },
    Digest {
        report: PathBuf,
    },
    Help,
    Version,
}

/// A trusted key is 32 bytes of lowercase hex. Checked here so a typo fails
/// before any file is read, rather than surfacing later as a signature error.
fn validate_key(key: &str) -> Result<()> {
    if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        bail!(
            "--key must be 32 bytes of hex (64 characters), got {} characters",
            key.len()
        )
    }
}

pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Result<Command> {
    let mut args = argv.into_iter().peekable();
    let Some(first) = args.next() else {
        return Ok(Command::Help);
    };

    match first.as_str() {
        "--help" | "-h" | "help" => return Ok(Command::Help),
        "--version" | "-V" => return Ok(Command::Version),
        "verify" | "verify-group" | "verify-chain" | "digest" => {}
        other => bail!("unknown command {other:?}\n\n{USAGE}"),
    }

    let mut flags: BTreeMap<String, String> = BTreeMap::new();
    let mut json = false;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--json" => json = true,
            "--help" | "-h" => return Ok(Command::Help),
            "--report" | "--proof" | "--proof-dir" | "--key" | "--group-report"
            | "--membership" | "--membership-dir" | "--group-key" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("{flag} needs a value"))?;
                flags.insert(flag, value);
            }
            other => bail!("unknown flag {other:?}\n\n{USAGE}"),
        }
    }

    let path = |name: &str| -> Option<PathBuf> { flags.get(name).map(PathBuf::from) };
    let required_path = |name: &str| -> Result<PathBuf> {
        path(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
    };
    let key = || -> Result<String> {
        let k = flags.get("--key").cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "--key is required: a report checked against its own embedded key \
                 proves only internal consistency"
            )
        })?;
        validate_key(&k)?;
        Ok(k)
    };
    // One `--proof`/`--membership`, or one directory of them, never both.
    let source = |file: &str, dir: &str| -> Result<ProofSource> {
        match (path(file), path(dir)) {
            (Some(p), None) => Ok(ProofSource::File(p)),
            (None, Some(d)) => Ok(ProofSource::Dir(d)),
            (None, None) => bail!("one of {file} or {dir} is required"),
            (Some(_), Some(_)) => bail!("{file} and {dir} are mutually exclusive"),
        }
    };

    match first.as_str() {
        "digest" => Ok(Command::Digest {
            report: required_path("--report")?,
        }),
        "verify" => Ok(Command::Verify {
            report: required_path("--report")?,
            proofs: source("--proof", "--proof-dir")?,
            trusted_key: key()?,
            json,
        }),
        "verify-group" => Ok(Command::VerifyGroup {
            report: required_path("--report")?,
            memberships: source("--membership", "--membership-dir")?,
            trusted_key: key()?,
            json,
        }),
        "verify-chain" => {
            let trusted_key = key()?;
            let group_key = match flags.get("--group-key") {
                Some(k) => {
                    validate_key(k)?;
                    k.clone()
                }
                None => trusted_key.clone(),
            };
            Ok(Command::VerifyChain {
                group_report: required_path("--group-report")?,
                membership: required_path("--membership")?,
                report: required_path("--report")?,
                proof: required_path("--proof")?,
                trusted_key,
                group_key,
                json,
            })
        }
        _ => unreachable!("subcommand already validated"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(s: &str) -> Result<Command> {
        parse(s.split_whitespace().map(String::from))
    }

    const KEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";

    #[test]
    fn parses_a_single_proof_verification() {
        assert_eq!(
            parse_str(&format!(
                "verify --report r.json --proof p.json --key {KEY}"
            ))
            .unwrap(),
            Command::Verify {
                report: PathBuf::from("r.json"),
                proofs: ProofSource::File(PathBuf::from("p.json")),
                trusted_key: KEY.to_string(),
                json: false,
            }
        );
    }

    #[test]
    fn parses_a_directory_verification_with_json_output() {
        assert_eq!(
            parse_str(&format!(
                "verify --report r.json --proof-dir d --key {KEY} --json"
            ))
            .unwrap(),
            Command::Verify {
                report: PathBuf::from("r.json"),
                proofs: ProofSource::Dir(PathBuf::from("d")),
                trusted_key: KEY.to_string(),
                json: true,
            }
        );
    }

    #[test]
    fn parses_digest_and_help_and_version() {
        assert_eq!(
            parse_str("digest --report r.json").unwrap(),
            Command::Digest {
                report: PathBuf::from("r.json")
            }
        );
        assert_eq!(parse_str("--help").unwrap(), Command::Help);
        assert_eq!(parse_str("").unwrap(), Command::Help);
        assert_eq!(parse_str("--version").unwrap(), Command::Version);
    }

    #[test]
    fn verification_without_a_trusted_key_is_refused() {
        let err = parse_str("verify --report r.json --proof p.json").unwrap_err();
        assert!(err.to_string().contains("--key"), "got {err}");
    }

    #[test]
    fn a_malformed_key_is_rejected_before_any_file_is_read() {
        for bad in ["deadbeef", "zz".repeat(32).as_str()] {
            let err = parse_str(&format!(
                "verify --report r.json --proof p.json --key {bad}"
            ))
            .unwrap_err();
            assert!(err.to_string().contains("key"), "got {err} for {bad}");
        }
    }

    #[test]
    fn a_proof_source_is_required_and_must_be_unambiguous() {
        let missing = parse_str(&format!("verify --report r.json --key {KEY}")).unwrap_err();
        assert!(missing.to_string().contains("--proof"), "got {missing}");

        let both = parse_str(&format!(
            "verify --report r.json --proof p.json --proof-dir d --key {KEY}"
        ))
        .unwrap_err();
        assert!(both.to_string().contains("--proof"), "got {both}");
    }

    #[test]
    fn unknown_flags_and_subcommands_are_rejected() {
        assert!(parse_str(&format!(
            "verify --report r.json --proof p.json --key {KEY} --deep"
        ))
        .is_err());
        assert!(parse_str("frobnicate").is_err());
    }

    #[test]
    fn parses_a_group_membership_verification() {
        assert_eq!(
            parse_str(&format!(
                "verify-group --report g.json --membership m.json --key {KEY}"
            ))
            .unwrap(),
            Command::VerifyGroup {
                report: PathBuf::from("g.json"),
                memberships: ProofSource::File(PathBuf::from("m.json")),
                trusted_key: KEY.to_string(),
                json: false,
            }
        );
    }

    #[test]
    fn parses_a_group_membership_directory() {
        let cmd = parse_str(&format!(
            "verify-group --report g.json --membership-dir d --key {KEY} --json"
        ))
        .unwrap();
        assert_eq!(
            cmd,
            Command::VerifyGroup {
                report: PathBuf::from("g.json"),
                memberships: ProofSource::Dir(PathBuf::from("d")),
                trusted_key: KEY.to_string(),
                json: true,
            }
        );
    }

    #[test]
    fn parses_a_full_chain_verification() {
        assert_eq!(
            parse_str(&format!(
                "verify-chain --group-report g.json --membership m.json \
                 --report r.json --proof p.json --key {KEY}"
            ))
            .unwrap(),
            Command::VerifyChain {
                group_report: PathBuf::from("g.json"),
                membership: PathBuf::from("m.json"),
                report: PathBuf::from("r.json"),
                proof: PathBuf::from("p.json"),
                trusted_key: KEY.to_string(),
                group_key: KEY.to_string(),
                json: false,
            }
        );
    }

    /// A group and its subsidiaries need not publish under one key.
    #[test]
    fn a_chain_can_name_a_separate_group_key() {
        let other = "cd".repeat(32);
        let cmd = parse_str(&format!(
            "verify-chain --group-report g.json --membership m.json --report r.json \
             --proof p.json --key {KEY} --group-key {other}"
        ))
        .unwrap();
        match cmd {
            Command::VerifyChain {
                trusted_key,
                group_key,
                ..
            } => {
                assert_eq!(trusted_key, KEY);
                assert_eq!(group_key, other);
            }
            other => panic!("expected a chain command, got {other:?}"),
        }
    }

    #[test]
    fn a_chain_missing_any_of_its_four_documents_is_rejected() {
        let full = format!(
            "verify-chain --group-report g.json --membership m.json --report r.json \
             --proof p.json --key {KEY}"
        );
        for missing in [
            "--group-report g.json",
            "--membership m.json",
            "--report r.json",
            "--proof p.json",
        ] {
            let err = parse_str(&full.replace(missing, "")).unwrap_err();
            let flag = missing.split_whitespace().next().unwrap();
            assert!(err.to_string().contains(flag), "removing {flag}: got {err}");
        }
    }

    #[test]
    fn a_malformed_group_key_is_rejected() {
        let err = parse_str(&format!(
            "verify-chain --group-report g.json --membership m.json --report r.json \
             --proof p.json --key {KEY} --group-key nope"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("key"), "got {err}");
    }

    #[test]
    fn group_verification_requires_a_membership_source() {
        let err = parse_str(&format!("verify-group --report g.json --key {KEY}")).unwrap_err();
        assert!(err.to_string().contains("--membership"), "got {err}");
    }

    #[test]
    fn a_flag_missing_its_value_is_rejected() {
        let err = parse_str("verify --report").unwrap_err();
        assert!(err.to_string().contains("--report"), "got {err}");
    }
}
