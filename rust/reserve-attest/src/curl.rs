//! A [`Transport`](crate::Transport) over the `curl` binary.
//!
//! Deliberately not an HTTP library. This crate is meant to be readable by an
//! auditor who will check what it sends, and shelling out to a tool they
//! already trust is easier to audit than a TLS stack pulled in as a
//! dependency. A deployment that would rather use its own HTTP client
//! implements `Transport` and ignores this.
//!
//! The bearer token is passed to curl on stdin, never on the command line,
//! because a command line is readable by every other process on the host.

use crate::Transport;
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

pub struct CurlTransport {
    base_url: String,
    token: String,
    timeout_seconds: u32,
}

impl CurlTransport {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            timeout_seconds: 30,
        }
    }

    pub fn with_timeout(mut self, seconds: u32) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// The arguments curl is invoked with, minus the token.
    ///
    /// Exposed so a test can assert what would be sent without a network, and
    /// so an operator can see exactly what this does.
    pub fn args(&self, path: &str, body: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "--silent".to_string(),
            "--show-error".to_string(),
            "--fail".to_string(),
            "--max-time".to_string(),
            self.timeout_seconds.to_string(),
            // Read the Authorization header from stdin, so the token never
            // appears in the process table.
            "--header".to_string(),
            "@-".to_string(),
        ];
        if let Some(body) = body {
            args.push("--header".to_string());
            args.push("Content-Type: application/json".to_string());
            args.push("--data-binary".to_string());
            args.push(body.to_string());
        }
        args.push(format!("{}{}", self.base_url, path));
        args
    }

    fn run(&self, path: &str, body: Option<&str>) -> Result<String> {
        let mut child = Command::new("curl")
            .args(self.args(path, body))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawning curl")?;
        child
            .stdin
            .as_mut()
            .context("curl stdin")?
            .write_all(format!("Authorization: Bearer {}\n", self.token).as_bytes())
            .context("writing the authorization header")?;

        let out = child.wait_with_output().context("running curl")?;
        if !out.status.success() {
            bail!(
                "curl failed for {path}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        String::from_utf8(out.stdout).context("participant response is not UTF-8")
    }
}

impl Transport for CurlTransport {
    fn get(&self, path: &str) -> Result<String> {
        self.run(path, None)
    }
    fn post(&self, path: &str, body: &str) -> Result<String> {
        self.run(path, Some(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> CurlTransport {
        CurlTransport::new("https://api.validator.example/v2/", "secret-token")
    }

    #[test]
    fn a_trailing_slash_on_the_base_url_does_not_double_up() {
        let args = transport().args("/state/ledger-end", None);
        assert_eq!(
            args.last().unwrap(),
            "https://api.validator.example/v2/state/ledger-end"
        );
    }

    /// The token must never be an argument: a command line is readable by
    /// every other process on the host.
    #[test]
    fn the_token_never_appears_in_the_arguments() {
        let args = transport().args("/state/active-contracts", Some(r#"{"a":1}"#));
        assert!(
            !args.iter().any(|a| a.contains("secret-token")),
            "token leaked into argv: {args:?}"
        );
        assert!(args.iter().any(|a| a == "@-"), "header not read from stdin");
    }

    #[test]
    fn a_post_carries_the_body_and_a_json_content_type() {
        let args = transport().args("/state/active-contracts", Some(r#"{"a":1}"#));
        assert!(args.contains(&"Content-Type: application/json".to_string()));
        assert!(args.contains(&r#"{"a":1}"#.to_string()));
    }

    #[test]
    fn a_get_carries_no_body() {
        let args = transport().args("/state/ledger-end", None);
        assert!(!args.iter().any(|a| a == "--data-binary"));
    }

    /// --fail makes curl exit non-zero on an HTTP error, so a 500 body is not
    /// parsed as if it were a snapshot.
    #[test]
    fn http_errors_are_failures_rather_than_bodies() {
        assert!(transport().args("/x", None).contains(&"--fail".to_string()));
    }

    #[test]
    fn the_timeout_is_configurable_and_always_present() {
        let args = transport().with_timeout(5).args("/x", None);
        assert!(args.contains(&"--max-time".to_string()));
        assert!(args.contains(&"5".to_string()));
    }
}
