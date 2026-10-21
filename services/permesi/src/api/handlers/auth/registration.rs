//! Signup-only admission policy; existing account identities and login remain unchanged.
//!
//! Flow Overview: dispatch validates registration mode and exact domain lists. Both
//! OPAQUE endpoints and transactional insertion apply this policy independently.
//! Domain eligibility is not mailbox verification, tenant membership or user consent.

use anyhow::{Context, Result, ensure};
use clap::ArgMatches;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mode {
    Public,
    Restricted,
    Closed,
}

/// Server-owned signup admission; browser fields cannot override any policy decision.
#[derive(Clone, Debug)]
pub struct Policy {
    mode: Mode,
    allowed: Vec<String>,
    development: Vec<String>,
    pub(crate) timeout_ms: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Public,
            allowed: Vec::new(),
            development: Vec::new(),
            timeout_ms: crate::cli::commands::DEFAULT_REGISTRATION_TIMEOUT_MS,
        }
    }
}

impl Policy {
    /// Revalidates CLI policy, requiring explicit restricted lists and outbox-only exceptions.
    pub(crate) fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let mode = match matches.get_one::<String>("signup-mode").map(String::as_str) {
            Some("public") => Mode::Public,
            Some("restricted") => Mode::Restricted,
            Some("closed") => Mode::Closed,
            _ => anyhow::bail!("invalid signup mode"),
        };
        let list = |name| -> Result<Vec<String>> {
            matches
                .get_many::<String>(name)
                .into_iter()
                .flatten()
                .map(|s| parse_domain(s).map_err(anyhow::Error::msg))
                .collect()
        };
        let allowed = list("signup-allowed-domain")?;
        let development = list("signup-development-domain")?;
        ensure!(
            mode != Mode::Restricted || !allowed.is_empty(),
            "restricted signup requires allowed domains"
        );
        ensure!(
            mode == Mode::Restricted || allowed.is_empty(),
            "allowed domains require restricted signup"
        );
        ensure!(
            development.is_empty()
                || matches
                    .get_one::<String>("email-delivery")
                    .is_some_and(|v| v == "outbox"),
            "development domains require outbox delivery"
        );
        ensure!(
            development.iter().all(|v| reserved(v)),
            "development exceptions must be reserved domains"
        );
        let timeout_ms = *matches
            .get_one::<i64>("auth-registration-timeout-ms")
            .context("missing registration deadline")?;
        ensure!(
            (1..=10000).contains(&timeout_ms),
            "invalid registration deadline"
        );
        Ok(Self {
            mode,
            allowed,
            development,
            timeout_ms,
        })
    }

    /// Authorizes only new registration, never authentication, membership or delegated scopes.
    pub(crate) fn permits(&self, email: &str) -> bool {
        if self.mode == Mode::Closed || email.len() > 255 || !super::utils::valid_email(email) {
            return false;
        }
        let Some((_, domain)) = email.rsplit_once('@') else {
            return false;
        };
        let Ok(domain) = parse_domain(domain) else {
            return false;
        };
        if reserved(&domain) && !self.development.contains(&domain) {
            return false;
        }
        self.mode == Mode::Public || self.allowed.contains(&domain)
    }

    /// Explicit local-test policy; production construction never installs exceptions implicitly.
    #[cfg(test)]
    pub(crate) fn development() -> Self {
        Self {
            development: vec![
                "example.com".into(),
                "example.test".into(),
                "test.example".into(),
            ],
            ..Self::default()
        }
    }
}

/// Parses a DNS domain without silently accepting URL, literal-address or trailing-dot forms.
/// ASCII A-labels support international domains without changing OPAQUE identity normalization.
pub(crate) fn parse_domain(value: &str) -> Result<String, String> {
    let domain = value.to_ascii_lowercase();
    if domain.len() > 253
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || v == b'-')
        })
        || domain.parse::<std::net::IpAddr>().is_ok()
    {
        return Err("invalid signup email domain".into());
    }
    Ok(domain)
}

/// Classifies only reserved namespaces with label boundaries; lookalike suffixes do not match.
fn reserved(domain: &str) -> bool {
    [
        "example.com",
        "example.net",
        "example.org",
        "example",
        "test",
        "invalid",
        "localhost",
        "local",
    ]
    .iter()
    .any(|suffix| {
        domain == *suffix
            || domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signup_policy_rejects_reserved_domains_and_label_bypasses() {
        let policy = Policy::default();
        for email in [
            "a@example.com",
            "a@sub.example.com",
            "a@example.net",
            "a@sub.example.org",
            "a@example.test",
            "a@domain.invalid",
            "a@EXAMPLE.COM",
            "a@example.com.",
            "a@-example.com",
            "a@127.0.0.1",
            "a@x..com",
        ] {
            assert!(!policy.permits(email), "{email}");
        }
        for email in [
            "a@notexample.com",
            "a@example.com.attacker.tld",
            "a@permesi.dev",
            "a@xn--bcher-kva.de",
        ] {
            assert!(policy.permits(email), "{email}");
        }
    }
}

/// Bounds the complete SQL phase; pre-commit cancellation rolls back, while lost commit acknowledgements remain ambiguous.
pub(super) async fn bounded<T>(
    timeout_ms: i64,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(
        std::time::Duration::from_millis(u64::try_from(timeout_ms)?),
        operation,
    )
    .await
    .context("registration persistence deadline exceeded")?
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    /// Every mode/exception is dispatch-validated and domain matching never grants tenant authority.
    #[test]
    fn registration_policy_modes_and_development_exceptions_are_explicit() -> Result<()> {
        let parse = |args: &[&str]| -> Result<Policy> {
            let matches = crate::cli::commands::with_registration_args(clap::Command::new("test"))
                .mut_args(|arg| arg.env(None::<&str>))
                .try_get_matches_from(args)?;
            Policy::from_matches(&matches)
        };
        let closed = parse(&["test", "--signup-mode", "closed"])?;
        assert!(!closed.permits("a@permesi.dev"));
        assert!(parse(&["test", "--signup-mode", "restricted"]).is_err());
        let restricted = parse(&[
            "test",
            "--signup-mode",
            "restricted",
            "--signup-allowed-domain",
            "permesi.dev",
        ])?;
        assert!(restricted.permits("a@permesi.dev"));
        assert!(!restricted.permits("a@sub.permesi.dev"));
        assert!(!restricted.permits("a@permesi.dev.attacker.tld"));
        assert!(
            parse(&[
                "test",
                "--signup-development-domain",
                "example.com",
                "--email-delivery",
                "smtp"
            ])
            .is_err()
        );
        assert!(parse(&["test", "--signup-development-domain", "permesi.dev"]).is_err());
        let development = parse(&["test", "--signup-development-domain", "example.com"])?;
        assert!(development.permits("a@example.com"));
        assert!(!development.permits("a@sub.example.com"));
        Ok(())
    }
}
