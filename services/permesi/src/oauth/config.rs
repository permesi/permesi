//! Explicit issuer/resource configuration, independent of admission-token policy.
//!
//! OAuth stays disabled until both issuer and audience are supplied. Clap and dispatch
//! validate the same policy so deployment identity cannot be inferred from Host headers.
//! Access-token audiences represent resources; ID tokens use the public client ID.

use anyhow::{Context, Result, ensure};
use clap::ArgMatches;
use url::Url;

/// Nonsecret deployment policy shared by all replicas of one issuer.
#[derive(Clone, Debug)]
pub struct OAuthConfig {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub signing_key: String,
    pub code_ttl: i64,
    pub request_ttl: i64,
    pub lock_timeout_ms: i64,
    pub jwks_cache_ttl: i64,
    pub credentials: super::credentials::CredentialConfig,
    pub tokens: super::tokens::TokenConfig,
}

impl OAuthConfig {
    /// Revalidates clap values at the dispatch boundary, including bounded lifetimes.
    pub(crate) fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let issuer = matches.get_one::<String>("oidc-issuer").cloned();
        let audience = matches.get_one::<String>("oauth-audience").cloned();
        ensure!(
            issuer.is_some() == audience.is_some(),
            "issuer and audience must be configured together"
        );
        if let Some(value) = &issuer {
            parse_issuer(value)?;
            parse_issuer(
                matches
                    .get_one::<String>("frontend-base-url")
                    .context("missing frontend origin")?,
            )
            .context("OAuth login requires a canonical HTTPS frontend origin")?;
        }
        if let Some(value) = &audience {
            parse_audience(value)?;
        }
        let signing_key = matches
            .get_one::<String>("oidc-signing-key")
            .context("missing signing key")?
            .clone();
        parse_key_name(&signing_key)?;
        let code_ttl = *matches
            .get_one::<i64>("oauth-code-ttl-seconds")
            .context("missing code TTL")?;
        let request_ttl = *matches
            .get_one::<i64>("oauth-request-ttl-seconds")
            .context("missing request TTL")?;
        let lock_timeout_ms = *matches
            .get_one::<i64>("oauth-lock-timeout-ms")
            .context("missing OAuth lock timeout")?;
        let jwks_cache_ttl = *matches
            .get_one::<i64>("oidc-jwks-cache-ttl-seconds")
            .context("missing JWKS cache TTL")?;
        ensure!(
            (1..=300).contains(&code_ttl)
                && (1..=1800).contains(&request_ttl)
                && (1..=10_000).contains(&lock_timeout_ms)
                && (1..=300).contains(&jwks_cache_ttl),
            "invalid OAuth lifetime"
        );
        Ok(Self {
            issuer,
            audience,
            signing_key,
            code_ttl,
            request_ttl,
            lock_timeout_ms,
            jwks_cache_ttl,
            credentials: super::credentials::CredentialConfig::from_matches(matches)?,
            tokens: super::tokens::TokenConfig::from_matches(matches)?,
        })
    }

    /// Builds disabled state for inert router fixtures; production reads clap defaults.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            issuer: None,
            audience: None,
            signing_key: "oidc-signing".into(),
            code_ttl: 120,
            request_ttl: 600,
            lock_timeout_ms: 1000,
            jwks_cache_ttl: 30,
            credentials: super::credentials::CredentialConfig::for_tests(),
            tokens: super::tokens::TokenConfig::for_tests(),
        }
    }
}

/// Accepts an exact canonical HTTPS origin, without paths, userinfo, query or fragment.
/// Restricting issuers to origins keeps well-known routing unambiguous in this phase.
pub(crate) fn parse_issuer(value: &str) -> Result<String> {
    let url = Url::parse(value).context("issuer must be an HTTPS origin")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && value == url.origin().ascii_serialization(),
        "issuer must be an exact HTTPS origin without a trailing slash"
    );
    Ok(value.to_owned())
}

/// Accepts one explicit audience without whitespace or controls; never defaults to admission.
pub(crate) fn parse_audience(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty()
            && value.len() <= 2048
            && !value.chars().any(|c| c.is_whitespace() || c.is_control()),
        "invalid OAuth audience"
    );
    Ok(value.to_owned())
}

/// Prevents transit path injection by limiting the operator-selected key to one segment.
pub(crate) fn parse_key_name(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)),
        "invalid OIDC signing key name"
    );
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_configuration_rejects_ambiguous_identity() {
        for value in [
            "http://issuer.test",
            "https://issuer.test/",
            "https://issuer.test/path",
            "https://user@issuer.test",
            "https://issuer.test?x",
            "https://ISSUER.test",
            "https://issuer.test:443",
        ] {
            assert!(parse_issuer(value).is_err(), "{value}");
        }
        assert!(parse_issuer("https://issuer.test:8443").is_ok());
        assert!(parse_audience("jobs-api").is_ok());
        assert!(parse_audience("jobs api").is_err());
        assert!(parse_key_name("../other").is_err());
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    /// Builds the normal command without contacting Vault or production infrastructure.
    fn arguments() -> Vec<&'static str> {
        vec![
            "permesi",
            "--dsn",
            "postgres://",
            "--socket-path",
            "/tmp/oauth-test.sock",
            "--vault-url",
            "/tmp/vault-test.sock",
            "--admission-paserk-url",
            "https://genesis.test/paserk.json",
        ]
    }
    #[test]
    fn oauth_clap_and_dispatch_require_explicit_identity_and_bounded_ttls() -> Result<()> {
        temp_env::with_vars(
            [
                ("PERMESI_TLS_PEM_BUNDLE", None::<&str>),
                ("PERMESI_PORT", None),
                ("PERMESI_OIDC_ISSUER", None),
                ("PERMESI_OAUTH_AUDIENCE", None),
                ("PERMESI_OAUTH_CODE_TTL_SECONDS", None),
                ("PERMESI_OAUTH_REQUEST_TTL_SECONDS", None),
                ("PERMESI_OAUTH_LOCK_TIMEOUT_MS", None),
                ("PERMESI_OIDC_JWKS_CACHE_TTL_SECONDS", None),
                ("PERMESI_OAUTH_ACCESS_TOKEN_TTL_SECONDS", None),
                ("PERMESI_OIDC_ID_TOKEN_TTL_SECONDS", None),
                ("PERMESI_OAUTH_TOKEN_TIMEOUT_MS", None),
                ("PERMESI_OAUTH_TOKEN_MAX_BODY_BYTES", None),
                ("PERMESI_OAUTH_TOKEN_RATE_WINDOW_SECONDS", None),
                ("PERMESI_OAUTH_TOKEN_RATE_IP_ATTEMPTS", None),
                ("PERMESI_OAUTH_TOKEN_RATE_CLIENT_IP_ATTEMPTS", None),
                ("PERMESI_FRONTEND_BASE_URL", Some("https://permesi.dev")),
            ],
            || -> Result<()> {
                let mut args = arguments();
                args.extend(["--oidc-issuer", "https://issuer.test"]);
                assert!(
                    crate::cli::commands::new()
                        .try_get_matches_from(args)
                        .is_err()
                );
                let mut args = arguments();
                args.extend([
                    "--oidc-issuer",
                    "https://issuer.test",
                    "--oauth-audience",
                    "jobs-api",
                    "--oauth-code-ttl-seconds",
                    "300",
                    "--oauth-request-ttl-seconds",
                    "1800",
                ]);
                let matches = crate::cli::commands::new().try_get_matches_from(args)?;
                let config = OAuthConfig::from_matches(&matches)?;
                assert_eq!(config.code_ttl, 300);
                assert_eq!(config.request_ttl, 1800);
                for (option, value) in [
                    ("--oauth-client-secret-grace-seconds", "0"),
                    ("--oauth-client-secret-grace-seconds", "3601"),
                    ("--oauth-client-secret-memory-kib", "19455"),
                    ("--oauth-client-secret-memory-kib", "65537"),
                    ("--oauth-client-secret-iterations", "1"),
                    ("--oauth-client-secret-iterations", "7"),
                    ("--oauth-client-secret-parallelism", "0"),
                    ("--oauth-client-secret-parallelism", "5"),
                    ("--oauth-client-secret-hash-workers", "0"),
                    ("--oauth-client-secret-hash-workers", "9"),
                    ("--oauth-token-rate-window-seconds", "0"),
                    ("--oauth-token-rate-window-seconds", "3601"),
                    ("--oauth-token-rate-ip-attempts", "0"),
                    ("--oauth-token-rate-ip-attempts", "100001"),
                    ("--oauth-token-rate-client-ip-attempts", "0"),
                    ("--oauth-token-rate-client-ip-attempts", "100001"),
                    ("--oauth-access-token-ttl-seconds", "0"),
                    ("--oauth-access-token-ttl-seconds", "3601"),
                    ("--oidc-id-token-ttl-seconds", "0"),
                    ("--oidc-id-token-ttl-seconds", "3601"),
                    ("--oauth-token-timeout-ms", "0"),
                    ("--oauth-token-timeout-ms", "30001"),
                    ("--oauth-token-max-body-bytes", "1023"),
                    ("--oauth-token-max-body-bytes", "65537"),
                    ("--oauth-code-ttl-seconds", "0"),
                    ("--oauth-code-ttl-seconds", "301"),
                    ("--oauth-request-ttl-seconds", "1801"),
                    ("--oauth-lock-timeout-ms", "0"),
                    ("--oauth-lock-timeout-ms", "10001"),
                    ("--oidc-jwks-cache-ttl-seconds", "0"),
                    ("--oidc-jwks-cache-ttl-seconds", "301"),
                ] {
                    let mut args = arguments();
                    args.extend([option, value]);
                    assert!(
                        crate::cli::commands::new()
                            .try_get_matches_from(args)
                            .is_err()
                    );
                }
                let mut args = arguments();
                args.extend([
                    "--oidc-issuer",
                    "https://issuer.test",
                    "--oauth-audience",
                    "jobs-api",
                    "--frontend-base-url",
                    "http://frontend.test",
                ]);
                let matches = crate::cli::commands::new().try_get_matches_from(args)?;
                assert!(OAuthConfig::from_matches(&matches).is_err());
                Ok(())
            },
        )
    }
    /// Independently checks both numeric limits and the idle/absolute lifetime relationship.
    #[test]
    fn refresh_policy_clap_and_dispatch_reject_unsafe_lifetimes() -> Result<()> {
        let command = || crate::cli::commands::new().mut_args(|arg| arg.env(None::<&str>));
        for (option, value) in [
            ("--oauth-refresh-absolute-ttl-seconds", "0"),
            ("--oauth-refresh-absolute-ttl-seconds", "7776001"),
            ("--oauth-refresh-idle-ttl-seconds", "0"),
            ("--oauth-refresh-idle-ttl-seconds", "7776001"),
        ] {
            let mut args = arguments();
            args.extend([option, value]);
            assert!(command().try_get_matches_from(args).is_err());
        }
        let mut args = arguments();
        args.extend([
            "--oauth-refresh-absolute-ttl-seconds",
            "1",
            "--oauth-refresh-idle-ttl-seconds",
            "2",
        ]);
        let matches = command().try_get_matches_from(args)?;
        assert!(super::super::tokens::TokenConfig::from_matches(&matches).is_err());
        let matches = command().try_get_matches_from(arguments())?;
        let config = super::super::tokens::TokenConfig::from_matches(&matches)?;
        assert_eq!(config.refresh_absolute_ttl, 2_592_000);
        assert_eq!(config.refresh_idle_ttl, 604_800);
        Ok(())
    }
}
