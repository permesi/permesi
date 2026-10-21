//! Explicit delivery policy parsed by dispatch; outbox mode never pretends mail was delivered.
//! SMTP uses authenticated TLS, bounded network deadlines and opaque diagnostics.

use anyhow::{Context, Result, ensure};
use clap::ArgMatches;
use lettre::message::Mailbox;
use secrecy::{ExposeSecret as _, SecretString};
use std::time::Duration;

/// Credentials are redacted in derived Debug; no configuration URL contains a password.
#[derive(Clone, Debug)]
pub(crate) struct SmtpSettings {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) starttls: bool,
    pub(super) from: Mailbox,
    pub(super) username: Option<SecretString>,
    pub(super) password: Option<SecretString>,
    pub(super) timeout: Duration,
}

/// Validated delivery and durable claim policy shared by every local outbox worker.
#[derive(Clone, Debug)]
pub struct DeliveryConfig {
    pub(super) smtp: Option<SmtpSettings>,
    pub(super) lease_seconds: i64,
    pub(super) database_timeout_ms: i64,
}
impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            smtp: None,
            lease_seconds: crate::cli::commands::DEFAULT_EMAIL_LEASE_SECONDS,
            database_timeout_ms: crate::cli::commands::DEFAULT_REGISTRATION_TIMEOUT_MS,
        }
    }
}
impl DeliveryConfig {
    /// Revalidates credentials, TLS policy and lease/deadline ordering without exposing input values.
    pub(crate) fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let value = |name| matches.get_one::<String>(name).cloned();
        let timeout = *matches
            .get_one::<u64>("smtp-timeout-seconds")
            .context("missing SMTP deadline")?;
        let lease_seconds = *matches
            .get_one::<i64>("email-lease-seconds")
            .context("missing email lease")?;
        let database_timeout_ms = *matches
            .get_one::<i64>("auth-registration-timeout-ms")
            .context("missing database deadline")?;
        ensure!(
            (1..=60).contains(&timeout)
                && (5..=600).contains(&lease_seconds)
                && (1..=10000).contains(&database_timeout_ms),
            "invalid email operation deadlines"
        );
        ensure!(
            lease_seconds * 1000 > i64::try_from(timeout)? * 1000 + database_timeout_ms * 2,
            "email lease must exceed SMTP and database deadlines"
        );
        let smtp = match value("email-delivery").as_deref() {
            Some("outbox") => {
                ensure!(
                    ["smtp-host", "smtp-from", "smtp-username", "smtp-password"]
                        .iter()
                        .all(|name| value(name).is_none()),
                    "SMTP settings require SMTP delivery"
                );
                None
            }
            Some("smtp") => {
                let host = value("smtp-host").context("SMTP delivery requires a host")?;
                ensure!(
                    !host.is_empty()
                        && host.is_ascii()
                        && !host.chars().any(char::is_whitespace)
                        && !host.contains(['/', '@', ':']),
                    "invalid SMTP host"
                );
                let port = *matches
                    .get_one::<u16>("smtp-port")
                    .context("missing SMTP port")?;
                ensure!(port > 0, "invalid SMTP port");
                let from = value("smtp-from")
                    .context("SMTP delivery requires a from mailbox")?
                    .parse::<Mailbox>()
                    .map_err(|_| anyhow::anyhow!("invalid SMTP from mailbox"))?;
                let username = value("smtp-username").map(SecretString::from);
                let password = value("smtp-password").map(SecretString::from);
                ensure!(
                    username.is_some() == password.is_some(),
                    "SMTP credentials require both username and password"
                );
                ensure!(
                    username
                        .as_ref()
                        .is_none_or(|v| !v.expose_secret().is_empty())
                        && password
                            .as_ref()
                            .is_none_or(|v| !v.expose_secret().is_empty()),
                    "SMTP credentials must not be empty"
                );
                let starttls = match value("smtp-tls").as_deref() {
                    Some("implicit") => false,
                    Some("starttls") => true,
                    _ => anyhow::bail!("invalid SMTP TLS mode"),
                };
                Some(SmtpSettings {
                    host,
                    port,
                    starttls,
                    from,
                    username,
                    password,
                    timeout: Duration::from_secs(timeout),
                })
            }
            _ => anyhow::bail!("invalid email delivery mode"),
        };
        Ok(Self {
            smtp,
            lease_seconds,
            database_timeout_ms,
        })
    }
}
