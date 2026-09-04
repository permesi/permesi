//! Shared rate limiting for unauthenticated authentication flows.
//!
//! Production checks use `PostgreSQL` so limits are enforced consistently across
//! replicas. Subjects are hashed before persistence, and any storage failure
//! fails closed. Tests can use the explicit no-op backend where throttling is
//! outside the behavior under test.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::error;

#[derive(Clone, Copy, Debug)]
pub enum RateLimitAction {
    Signup,
    Login,
    VerifyEmail,
    ResendVerification,
    MfaRecovery,
}

impl RateLimitAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Signup => "signup",
            Self::Login => "login",
            Self::VerifyEmail => "verify_email",
            Self::ResendVerification => "resend_verification",
            Self::MfaRecovery => "mfa_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited,
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

#[derive(Clone, Debug)]
enum Backend {
    #[cfg(test)]
    Noop,
    Postgres {
        pool: PgPool,
        config: RateLimitConfig,
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
    #[cfg(test)]
    #[must_use]
    pub const fn noop() -> Self {
        Self {
            backend: Backend::Noop,
        }
    }

    #[must_use]
    pub fn postgres(pool: PgPool, config: RateLimitConfig) -> Self {
        Self {
            backend: Backend::Postgres { pool, config },
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
        let (pool, config) = match &self.backend {
            #[cfg(test)]
            Backend::Noop => return RateLimitDecision::Allowed,
            Backend::Postgres { pool, config } => (pool, config),
        };

        let subject_hash = Sha256::digest(subject.as_bytes()).to_vec();
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

        match sqlx::query_scalar::<_, i64>(query)
            .bind(dimension)
            .bind(subject_hash)
            .bind(action.as_str())
            .bind(config.window_seconds)
            .fetch_one(pool)
            .await
        {
            Ok(attempts) => decision_for_attempts(attempts, limit(*config)),
            Err(err) => {
                error!(
                    dimension,
                    action = action.as_str(),
                    "authentication rate-limit check failed closed: {err}"
                );
                RateLimitDecision::Limited
            }
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
        let limiter = RateLimiter::postgres(pool, RateLimitConfig::new(60, 10, 5));

        assert_eq!(
            limiter
                .check_email("user@example.com", RateLimitAction::Login)
                .await,
            RateLimitDecision::Limited
        );
        Ok(())
    }

    #[test]
    fn attempt_after_limit_is_rejected() {
        assert_eq!(decision_for_attempts(10, 10), RateLimitDecision::Allowed);
        assert_eq!(decision_for_attempts(11, 10), RateLimitDecision::Limited);
    }
}
