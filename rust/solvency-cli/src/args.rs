//! Argument parsing. Every usage error surfaces here so `run` only ever sees
//! a well-formed command.

use anyhow::{bail, Result};
use std::path::PathBuf;

pub const USAGE: &str = "\
canton-solvency-verify — offline verification of Canton solvency reports

USAGE:
  canton-solvency-verify verify --report <path> --key <hex64>
                                (--proof <path> | --proof-dir <dir>) [--json]
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
        "verify" | "digest" => {}
        other => bail!("unknown command {other:?}\n\n{USAGE}"),
    }

    let mut report: Option<PathBuf> = None;
    let mut proof: Option<PathBuf> = None;
    let mut proof_dir: Option<PathBuf> = None;
    let mut trusted_key: Option<String> = None;
    let mut json = false;

    while let Some(flag) = args.next() {
        let mut value = || -> Result<String> {
            args.next()
                .ok_or_else(|| anyhow::anyhow!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--report" => report = Some(PathBuf::from(value()?)),
            "--proof" => proof = Some(PathBuf::from(value()?)),
            "--proof-dir" => proof_dir = Some(PathBuf::from(value()?)),
            "--key" => trusted_key = Some(value()?),
            "--json" => json = true,
            "--help" | "-h" => return Ok(Command::Help),
            other => bail!("unknown flag {other:?}\n\n{USAGE}"),
        }
    }

    let report = report.ok_or_else(|| anyhow::anyhow!("--report is required"))?;

    if first == "digest" {
        return Ok(Command::Digest { report });
    }

    let proofs = match (proof, proof_dir) {
        (Some(p), None) => ProofSource::File(p),
        (None, Some(d)) => ProofSource::Dir(d),
        (None, None) => bail!("one of --proof or --proof-dir is required"),
        (Some(_), Some(_)) => bail!("--proof and --proof-dir are mutually exclusive"),
    };

    let trusted_key = trusted_key.ok_or_else(|| {
        anyhow::anyhow!(
            "--key is required: a report checked against its own embedded key \
             proves only internal consistency"
        )
    })?;
    validate_key(&trusted_key)?;

    Ok(Command::Verify {
        report,
        proofs,
        trusted_key,
        json,
    })
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
    fn a_flag_missing_its_value_is_rejected() {
        let err = parse_str("verify --report").unwrap_err();
        assert!(err.to_string().contains("--report"), "got {err}");
    }
}
