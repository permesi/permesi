//! Shared authentication admission policy and verified transport metadata.
//!
//! Flow Overview: clap/dispatch validate independent flow and subject budgets.
//! The served router replaces incoming IP hints using the actual transport peer;
//! only explicitly trusted proxies may supply a single canonical `X-Real-IP`.
//! Missing transport identity shares a bounded unknown bucket. No header grants
//! proxy trust, and forwarded chains/Cloudflare claims are never used as identity.

use anyhow::{Context, Result, ensure};
use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};
use clap::ArgMatches;
use sqlx::types::ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};

/// Cluster-wide admission budgets and explicitly configured transport trust.
#[derive(Clone, Debug)]
pub struct OperationsConfig {
    pub(crate) subject_limit: i64,
    pub(crate) login_limit: i64,
    pub(crate) reauth_limit: i64,
    pub(crate) registration_limit: i64,
    pub(crate) mfa_limit: i64,
    trusted_proxies: Vec<IpNetwork>,
    trust_unix_proxy: bool,
}

impl OperationsConfig {
    /// Revalidates clap-defined policy before server construction; no environment fallback.
    pub(crate) fn from_matches(matches: &ArgMatches) -> Result<Self> {
        let value = |name| {
            matches
                .get_one::<i64>(name)
                .copied()
                .context("missing authentication budget")
        };
        let config = Self {
            subject_limit: value("auth-pending-subject-limit")?,
            login_limit: value("auth-pending-login-limit")?,
            reauth_limit: value("auth-pending-reauth-limit")?,
            registration_limit: value("auth-pending-registration-limit")?,
            mfa_limit: value("auth-pending-mfa-limit")?,
            trusted_proxies: matches
                .get_many::<IpNetwork>("auth-trusted-proxy")
                .map(|v| v.copied().collect())
                .unwrap_or_default(),
            trust_unix_proxy: matches.get_flag("auth-trust-unix-proxy"),
        };
        ensure!(
            [
                config.subject_limit,
                config.login_limit,
                config.reauth_limit,
                config.registration_limit,
                config.mfa_limit
            ]
            .iter()
            .all(|v| (1..=1_000_000).contains(v)),
            "invalid authentication admission limits"
        );
        Ok(config)
    }

    /// Inert constructor defaults are defined in the clap configuration module.
    pub(crate) fn defaults() -> Self {
        Self {
            subject_limit: crate::cli::commands::DEFAULT_AUTH_SUBJECT_LIMIT,
            login_limit: crate::cli::commands::DEFAULT_AUTH_LOGIN_LIMIT,
            reauth_limit: crate::cli::commands::DEFAULT_AUTH_REAUTH_LIMIT,
            registration_limit: crate::cli::commands::DEFAULT_AUTH_REGISTRATION_LIMIT,
            mfa_limit: crate::cli::commands::DEFAULT_AUTH_MFA_LIMIT,
            trusted_proxies: Vec::new(),
            trust_unix_proxy: false,
        }
    }

    /// Authorizes forwarding metadata only for configured transport peers, never header claims.
    fn trusts(&self, peer: Option<IpAddr>, unix: bool) -> bool {
        (unix && self.trust_unix_proxy)
            || peer.is_some_and(|ip| {
                self.trusted_proxies
                    .iter()
                    .any(|network| network.contains(ip))
            })
    }
}

/// Marker installed only by the Unix listener; absent TCP metadata does not grant trust.
#[derive(Clone, Copy)]
pub(crate) struct UnixPeer;

/// Adds a short retry hint to capacity denial; dependency responses expose no private cause.
pub(crate) fn failure(status: axum::http::StatusCode, message: String) -> Response {
    use axum::response::IntoResponse;
    let mut response = (status, message).into_response();
    if status == axum::http::StatusCode::TOO_MANY_REQUESTS {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
    }
    response
}

/// Bounds pool acquisition as well as SQL locks/statements; transaction-local policy resets on return.
pub(crate) async fn begin(
    pool: &sqlx::PgPool,
    timeout_ms: i64,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    ensure!(
        (1..=10000).contains(&timeout_ms),
        "invalid authentication database deadline"
    );
    let duration = std::time::Duration::from_millis(u64::try_from(timeout_ms)?);
    let mut transaction = tokio::time::timeout(duration, pool.begin()).await??;
    crate::oauth::locking::deadline(&mut transaction, timeout_ms).await?;
    Ok(transaction)
}

/// Fails closed before factor work with separate shared IP/account action budgets.
pub(crate) async fn factor_admission(
    auth: &super::AuthState,
    headers: &axum::http::HeaderMap,
    email: &str,
    action: super::RateLimitAction,
) -> Result<(), axum::http::StatusCode> {
    if let Some(status) = auth
        .rate_limiter()
        .check_ip(super::utils::extract_client_ip(headers).as_deref(), action)
        .await
        .denial_status()
    {
        return Err(status);
    }
    if let Some(status) = auth
        .rate_limiter()
        .check_email(email, action)
        .await
        .denial_status()
    {
        return Err(status);
    }
    Ok(())
}

/// Fixed-cardinality outcome/timing event emitted even when a storage future is canceled.
pub(crate) struct Observation {
    flow: &'static str,
    operation: &'static str,
    started: std::time::Instant,
    pub(crate) outcome: &'static str,
}
impl Observation {
    /// Starts a value-free storage observation; errors default to dependency unavailability.
    pub(crate) fn new(flow: &'static str, operation: &'static str) -> Self {
        Self {
            flow,
            operation,
            started: std::time::Instant::now(),
            outcome: "unavailable",
        }
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        tracing::info!(
            flow = self.flow,
            operation = self.operation,
            outcome = self.outcome,
            elapsed_ms = self.started.elapsed().as_secs_f64() * 1000.0,
            "authentication exchange outcome"
        );
    }
}

/// Removes spoofable forwarding headers before handlers, audit and throttling read them.
pub(crate) async fn verified_peer(
    State(config): State<OperationsConfig>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    let trusted = config.trusts(peer, request.extensions().get::<UnixPeer>().is_some());
    sanitize(request.headers_mut(), peer, trusted);
    next.run(request).await
}

/// Accepts exactly one edge-overwritten address after verifying the transport peer.
fn sanitize(headers: &mut axum::http::HeaderMap, peer: Option<IpAddr>, trusted: bool) {
    let forwarded = if trusted && headers.get_all("x-real-ip").iter().count() == 1 {
        headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<IpAddr>().ok())
    } else {
        None
    };
    for name in [
        "x-permesi-client-ip",
        "cf-connecting-ip",
        "x-forwarded-for",
        "x-real-ip",
        "forwarded",
    ] {
        headers.remove(name);
    }
    if !trusted {
        headers.remove("cf-ipcountry");
    }
    if let Some(ip) = forwarded.or(peer)
        && let Ok(value) = ip.to_string().parse()
    {
        headers.insert("x-permesi-client-ip", value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_headers_cannot_replace_transport_peer() -> Result<()> {
        let mut headers = axum::http::HeaderMap::new();
        for name in ["x-real-ip", "cf-connecting-ip", "x-permesi-client-ip"] {
            headers.insert(name, "198.51.100.1".parse()?);
        }
        sanitize(&mut headers, Some("192.0.2.1".parse()?), false);
        assert_eq!(
            headers
                .get("x-permesi-client-ip")
                .and_then(|v| v.to_str().ok()),
            Some("192.0.2.1")
        );
        assert!(!headers.contains_key("x-real-ip"));
        sanitize(&mut headers, None, false);
        assert!(!headers.contains_key("x-permesi-client-ip"));
        Ok(())
    }
    #[test]
    fn explicit_proxy_accepts_only_one_valid_canonical_ip() -> Result<()> {
        let mut config = OperationsConfig::defaults();
        config.trusted_proxies.push("192.0.2.0/24".parse()?);
        assert!(config.trusts(Some("192.0.2.1".parse()?), false));
        assert!(!config.trusts(Some("198.51.100.1".parse()?), false));
        assert!(!config.trusts(None, true));
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-real-ip", "2001:db8::1".parse()?);
        sanitize(&mut headers, Some("192.0.2.1".parse()?), true);
        assert_eq!(
            headers
                .get("x-permesi-client-ip")
                .and_then(|v| v.to_str().ok()),
            Some("2001:db8::1")
        );
        headers.append("x-real-ip", "198.51.100.1".parse()?);
        headers.append("x-real-ip", "198.51.100.2".parse()?);
        sanitize(&mut headers, Some("192.0.2.1".parse()?), true);
        assert_eq!(
            headers
                .get("x-permesi-client-ip")
                .and_then(|v| v.to_str().ok()),
            Some("192.0.2.1")
        );
        Ok(())
    }

    #[test]
    fn admission_cli_rejects_zero_limits_and_invalid_proxy_networks() {
        for args in [
            ["test", "--auth-pending-subject-limit", "0"],
            ["test", "--auth-pending-login-limit", "1000001"],
            ["test", "--auth-trusted-proxy", "attacker"],
        ] {
            assert!(
                crate::cli::commands::with_operations_args(clap::Command::new("test"))
                    .try_get_matches_from(args)
                    .is_err()
            );
        }
    }

    #[test]
    fn admission_dispatch_preserves_explicit_flow_and_proxy_policy() -> Result<()> {
        let matches = crate::cli::commands::with_operations_args(clap::Command::new("test"))
            .try_get_matches_from([
                "test",
                "--auth-pending-subject-limit",
                "2",
                "--auth-pending-login-limit",
                "3",
                "--auth-trusted-proxy",
                "192.0.2.0/24",
                "--auth-trust-unix-proxy",
            ])?;
        let config = OperationsConfig::from_matches(&matches)?;
        assert_eq!(config.subject_limit, 2);
        assert_eq!(config.login_limit, 3);
        assert!(config.trusts(None, true));
        assert!(config.trusts(Some("192.0.2.7".parse()?), false));
        Ok(())
    }
}
