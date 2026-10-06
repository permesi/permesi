//! Shared rate limiting for unauthenticated authentication flows.
//!
//! Production checks use `PostgreSQL` so limits are enforced consistently across
//! replicas, and any storage failure fails closed. Tests can use the explicit
//! no-op backend where throttling is outside the behavior under test.
//!
//! Subjects (client IPs and normalized emails) are stored only as HMAC-SHA256
//! tags under a [`SubjectKey`] derived from a Vault-held server secret. A plain
//! hash would not protect them: the IPv4 space and likely email addresses are
//! small enough to enumerate, so anyone reading `auth_rate_limits` could recover
//! who attempted to log in. The key is identical on every replica, so counters
//! stay shared, and it never leaves process memory.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use std::fmt;
use tracing::error;

#[derive(Clone, Copy, Debug)]
pub enum RateLimitAction {
    Reauthenticate,
    PasskeyLogin,
    WebauthnEnrollment,
    MfaVerification,
    Signup,
    Login,
    VerifyEmail,
    ResendVerification,
    MfaRecovery,
    Authorize,
    TokenExchange,
    JwksRefresh,
    ClientCredentials,
    ClientCredentialRevocation,
}

impl RateLimitAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reauthenticate => "reauthenticate",
            Self::PasskeyLogin => "passkey_login",
            Self::WebauthnEnrollment => "webauthn_enrollment",
            Self::MfaVerification => "mfa_verification",
            Self::Signup => "signup",
            Self::Login => "login",
            Self::VerifyEmail => "verify_email",
            Self::ResendVerification => "resend_verification",
            Self::MfaRecovery => "mfa_recovery",
            Self::Authorize => "authorize",
            Self::TokenExchange => "token_exchange",
            Self::JwksRefresh => "jwks_refresh",
            Self::ClientCredentials => "client_credentials_management",
            Self::ClientCredentialRevocation => "client_credentials_revocation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited,
    Unavailable,
}

impl RateLimitDecision {
    /// Every non-allowed result denies admission; dependency failure is distinct from abuse.
    pub(crate) const fn denial_status(self) -> Option<axum::http::StatusCode> {
        match self {
            Self::Allowed => None,
            Self::Limited => Some(axum::http::StatusCode::TOO_MANY_REQUESTS),
            Self::Unavailable => Some(axum::http::StatusCode::SERVICE_UNAVAILABLE),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    window_seconds: i64,
    ip_attempts: i64,
    account_attempts: i64,
}

impl RateLimitConfig {
    #[must_use]
    pub const fn new(window_seconds: i64, ip_attempts: i64, account_attempts: i64) -> Self {
        Self {
            window_seconds,
            ip_attempts,
            account_attempts,
        }
    }
}

type HmacSha256 = Hmac<Sha256>;

/// Domain label that separates the rate-limit key from the secret's primary use.
const SUBJECT_KEY_LABEL: &[u8] = b"permesi/auth-rate-limit/subject-key/v1";

/// Secret key for rate-limit subject tags; its `Debug` output is redacted.
#[derive(Clone)]
pub struct SubjectKey([u8; 32]);

impl SubjectKey {
    /// Derive the key as `HMAC-SHA256(secret, label)`, so it is independent of any
    /// other use of `secret` (the OPAQUE server seed in production).
    ///
    /// # Errors
    /// Returns an error if the HMAC key cannot be initialized.
    pub fn derive(secret: &[u8]) -> anyhow::Result<Self> {
        mac(secret, SUBJECT_KEY_LABEL)
            .map(Self)
            .ok_or_else(|| anyhow::anyhow!("failed to derive the rate-limit subject key"))
    }

    /// Keyed tag stored in place of the raw subject.
    pub(crate) fn tag(&self, subject: &str) -> Option<[u8; 32]> {
        mac(&self.0, subject.as_bytes())
    }
}

impl fmt::Debug for SubjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubjectKey(<redacted>)")
    }
}

/// `HMAC-SHA256(key, message)`; HMAC accepts any key length, so `None` is not expected.
fn mac(key: &[u8], message: &[u8]) -> Option<[u8; 32]> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).ok()?;
    mac.update(message);
    Some(mac.finalize().into_bytes().into())
}

#[derive(Clone, Debug)]
enum Backend {
    #[cfg(test)]
    Noop,
    Postgres {
        pool: PgPool,
        config: RateLimitConfig,
        key: SubjectKey,
    },
}

/// Rate limiter used by authentication handlers.
///
/// The `PostgreSQL` backend atomically increments fixed-window counters and
/// treats database failures as limited so an outage cannot disable protection.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    backend: Backend,
}

impl RateLimiter {
    /// Reuses the verified subject key/shared storage with an independent protocol policy.
    /// This grants no authority and does not alter login or other action budgets.
    pub(crate) fn configured(&self, policy: RateLimitConfig) -> Self {
        let backend = match &self.backend {
            #[cfg(test)]
            Backend::Noop => Backend::Noop,
            Backend::Postgres { pool, key, .. } => Backend::Postgres {
                pool: pool.clone(),
                key: key.clone(),
                config: policy,
            },
        };
        Self { backend }
    }
    #[cfg(test)]
    #[must_use]
    pub const fn noop() -> Self {
        Self {
            backend: Backend::Noop,
        }
    }

    /// Build the shared `PostgreSQL` limiter; subjects are tagged with `key`.
    #[must_use]
    pub fn postgres(pool: PgPool, config: RateLimitConfig, key: SubjectKey) -> Self {
        Self {
            backend: Backend::Postgres { pool, config, key },
        }
    }

    /// Count an IP attempt for an action and return whether it may proceed.
    ///
    /// A missing client IP shares a sentinel bucket rather than bypassing the
    /// IP limit. Deployments must still sanitize forwarding headers at the
    /// trusted reverse-proxy boundary.
    pub async fn check_ip(&self, ip: Option<&str>, action: RateLimitAction) -> RateLimitDecision {
        let subject = ip.unwrap_or("unknown");
        self.check("ip", subject, action, |config| config.ip_attempts)
            .await
    }

    /// Count a normalized account identifier attempt for an action.
    pub async fn check_email(&self, email: &str, action: RateLimitAction) -> RateLimitDecision {
        self.check("account", email, action, |config| config.account_attempts)
            .await
    }

    async fn check(
        &self,
        dimension: &'static str,
        subject: &str,
        action: RateLimitAction,
        limit: impl FnOnce(RateLimitConfig) -> i64,
    ) -> RateLimitDecision {
        let (pool, config, key) = match &self.backend {
            #[cfg(test)]
            Backend::Noop => return RateLimitDecision::Allowed,
            Backend::Postgres { pool, config, key } => (pool, config, key),
        };

        let Some(subject_hash) = key.tag(subject) else {
            error!(dimension, "rate-limit subject tag failed; failing closed");
            return RateLimitDecision::Unavailable;
        };
        let query = r"
            INSERT INTO auth_rate_limits (
                dimension, subject_hash, action, attempts, expires_at
            )
            VALUES (
                $1, $2, $3, 1, clock_timestamp() + ($4 * INTERVAL '1 second')
            )
            ON CONFLICT (dimension, subject_hash, action) DO UPDATE
            SET attempts = CASE
                    WHEN auth_rate_limits.expires_at <= clock_timestamp() THEN 1
                    ELSE auth_rate_limits.attempts + 1
                END,
                expires_at = CASE
                    WHEN auth_rate_limits.expires_at <= clock_timestamp()
                    THEN clock_timestamp() + ($4 * INTERVAL '1 second')
                    ELSE auth_rate_limits.expires_at
                END
            RETURNING attempts
        ";

        if let Ok(attempts) = sqlx::query_scalar::<_, i64>(query)
            .bind(dimension)
            .bind(subject_hash.as_slice())
            .bind(action.as_str())
            .bind(config.window_seconds)
            .fetch_one(pool)
            .await
        {
            decision_for_attempts(attempts, limit(*config))
        } else {
            error!(
                dimension,
                action = action.as_str(),
                "authentication rate-limit check failed closed"
            );
            RateLimitDecision::Unavailable
        }
    }
}

const fn decision_for_attempts(attempts: i64, limit: i64) -> RateLimitDecision {
    if attempts <= limit {
        RateLimitDecision::Allowed
    } else {
        RateLimitDecision::Limited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_rate_limiter_allows() {
        let limiter = RateLimiter::noop();
        assert_eq!(
            limiter.check_ip(None, RateLimitAction::Signup).await,
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter
                .check_email("user@example.com", RateLimitAction::Login)
                .await,
            RateLimitDecision::Allowed
        );
    }

    #[tokio::test]
    async fn postgres_rate_limiter_fails_closed_when_unavailable() -> anyhow::Result<()> {
        let pool =
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/permesi")?;
        pool.close().await;
        let limiter = RateLimiter::postgres(
            pool,
            RateLimitConfig::new(60, 10, 5),
            SubjectKey::derive(b"test secret")?,
        );

        assert_eq!(
            limiter
                .check_email("user@example.com", RateLimitAction::Login)
                .await,
            RateLimitDecision::Unavailable
        );
        Ok(())
    }

    #[test]
    fn subject_tags_are_keyed_and_not_plain_hashes() -> anyhow::Result<()> {
        use sha2::Digest;
        let key = SubjectKey::derive(&[7u8; 32])?;
        let tag = key.tag("user@example.com");

        assert!(tag.is_some());
        assert_eq!(tag, key.tag("user@example.com"));
        assert_ne!(tag, SubjectKey::derive(&[8u8; 32])?.tag("user@example.com"));
        assert_ne!(
            tag.map(|tag| tag.to_vec()),
            Some(Sha256::digest(b"user@example.com").to_vec())
        );
        assert_eq!(format!("{key:?}"), "SubjectKey(<redacted>)");
        Ok(())
    }

    #[test]
    fn attempt_after_limit_is_rejected() {
        assert_eq!(decision_for_attempts(10, 10), RateLimitDecision::Allowed);
        assert_eq!(decision_for_attempts(11, 10), RateLimitDecision::Limited);
    }
}
