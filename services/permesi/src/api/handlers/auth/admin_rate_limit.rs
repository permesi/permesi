//! Database-backed rate limiting for admin elevation and bootstrap flows.
//!
//! Flow Overview:
//! 1) Track per-user and per-IP attempts in `admin_attempts` table.
//! 2) Enforce rolling window limits (3 per user, 10 per IP in 10 minutes).
//! 3) Trigger 15-minute cooldown after 3 consecutive failures.
//!
//! Scaling: Uses `PostgreSQL` to synchronize limits across multiple service instances.

use anyhow::Result;
use sqlx::{PgPool, Row};
use std::time::Duration;
use tracing::{Instrument, error};
use uuid::Uuid;

const ATTEMPT_WINDOW: Duration = Duration::from_secs(10 * 60);
const USER_ATTEMPT_LIMIT: i64 = 3;
const IP_ATTEMPT_LIMIT: i64 = 10;
const FAILURE_LIMIT: i64 = 3;
const COOLDOWN_DURATION: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdminRateLimitError {
    #[error("Rate limited")]
    Limited,
    #[error("Cooldown active: {remaining_seconds}s remaining")]
    Cooldown { remaining_seconds: u64 },
}

#[derive(Debug)]
pub struct AdminRateLimiter {
    pool: PgPool,
}

impl AdminRateLimiter {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Checks limits and registers a new attempt.
    ///
    /// # Errors
    /// Returns `AdminRateLimitError::Limited` if rolling window limits are exceeded.
    /// Returns `AdminRateLimitError::Cooldown` if the user is in a failure-triggered cooldown.
    pub async fn register_attempt(
        &self,
        user_id: Uuid,
        ip: Option<&str>,
        country_code: Option<&str>,
    ) -> Result<Uuid, AdminRateLimitError> {
        let cooldown = self.cooldown_seconds(user_id).await;
        if cooldown > 0 {
            return Err(AdminRateLimitError::Cooldown {
                remaining_seconds: cooldown,
            });
        }

        // Check user rolling window.
        let user_attempts = self.count_user_attempts(user_id).await.map_err(|err| {
            error!("Failed to count user admin attempts: {err}");
            AdminRateLimitError::Limited // Fail closed
        })?;
        if user_attempts >= USER_ATTEMPT_LIMIT {
            return Err(AdminRateLimitError::Limited);
        }

        // Check IP rolling window.
        if let Some(ip) = ip {
            let ip_attempts = self.count_ip_attempts(ip).await.map_err(|err| {
                error!("Failed to count IP admin attempts: {err}");
                AdminRateLimitError::Limited
            })?;
            if ip_attempts >= IP_ATTEMPT_LIMIT {
                return Err(AdminRateLimitError::Limited);
            }
        }

        // Register the attempt. Defaults to is_failure = TRUE (pessimistic).
        // It will be marked as success (is_failure = FALSE) only if record_success is called.
        let query = "INSERT INTO admin_attempts (user_id, ip_address, country_code, is_failure) VALUES ($1, $2::inet, $3, TRUE) RETURNING id";
        let span = tracing::info_span!(
            "db.query",
            db.system = "postgresql",
            db.operation = "INSERT"
        );
        let row = sqlx::query(query)
            .bind(user_id)
            .bind(ip)
            .bind(country_code)
            .fetch_one(&self.pool)
            .instrument(span)
            .await
            .map_err(|err| {
                error!("Failed to register admin attempt: {err}");
                AdminRateLimitError::Limited
            })?;

        Ok(row.get(0))
    }

    /// Confirms that the attempt was successful by clearing the failure flag.
    pub async fn record_success(&self, attempt_id: Uuid) {
        let query = "UPDATE admin_attempts SET is_failure = FALSE WHERE id = $1";
        let span = tracing::info_span!(
            "db.query",
            db.system = "postgresql",
            db.operation = "UPDATE"
        );
        if let Err(err) = sqlx::query(query)
            .bind(attempt_id)
            .execute(&self.pool)
            .instrument(span)
            .await
        {
            error!("Failed to record admin success: {err}");
        }
    }

    /// No-op if using the pessimistic default (where `register_attempt` sets `is_failure=TRUE`).
    /// Kept for API consistency.
    pub fn record_failure(&self, _attempt_id: Uuid) {
        let _ = self;
    }

    /// Returns the remaining cooldown time in seconds.
    pub async fn cooldown_seconds(&self, user_id: Uuid) -> u64 {
        let query = r"
            WITH last_attempts AS (
                SELECT is_failure, created_at
                FROM admin_attempts
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2
            )
            SELECT MAX(created_at) as last_failure_at
            FROM last_attempts
            HAVING COUNT(*) = $2 AND BOOL_AND(is_failure)
        ";
        let span = tracing::info_span!(
            "db.query",
            db.system = "postgresql",
            db.operation = "SELECT"
        );
        let row = sqlx::query(query)
            .bind(user_id)
            .bind(FAILURE_LIMIT)
            .fetch_optional(&self.pool)
            .instrument(span)
            .await;

        match row {
            Ok(Some(row)) => {
                let last_failure_at: chrono::DateTime<chrono::Utc> = row.get("last_failure_at");
                let now = chrono::Utc::now();
                let elapsed = now.signed_duration_since(last_failure_at);
                let cooldown_secs = i64::try_from(COOLDOWN_DURATION.as_secs()).unwrap_or(i64::MAX);
                if elapsed.num_seconds() < cooldown_secs {
                    u64::try_from(cooldown_secs - elapsed.num_seconds()).unwrap_or(0)
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    async fn count_user_attempts(&self, user_id: Uuid) -> Result<i64> {
        let query = "SELECT COUNT(*) FROM admin_attempts WHERE user_id = $1 AND created_at > NOW() - $2::interval";
        let span = tracing::info_span!(
            "db.query",
            db.system = "postgresql",
            db.operation = "SELECT"
        );
        let row = sqlx::query(query)
            .bind(user_id)
            .bind(format!("{} seconds", ATTEMPT_WINDOW.as_secs()))
            .fetch_one(&self.pool)
            .instrument(span)
            .await?;
        Ok(row.get(0))
    }

    async fn count_ip_attempts(&self, ip: &str) -> Result<i64> {
        let query = "SELECT COUNT(*) FROM admin_attempts WHERE ip_address = $1::inet AND created_at > NOW() - $2::interval";
        let span = tracing::info_span!(
            "db.query",
            db.system = "postgresql",
            db.operation = "SELECT"
        );
        let row = sqlx::query(query)
            .bind(ip)
            .bind(format!("{} seconds", ATTEMPT_WINDOW.as_secs()))
            .fetch_one(&self.pool)
            .instrument(span)
            .await?;
        Ok(row.get(0))
    }
}

#[cfg(test)]
mod tests {
    use super::{AdminRateLimitError, AdminRateLimiter};
    use anyhow::{Context, Result};
    use sqlx::{PgPool, Row, postgres::PgPoolOptions};
    use test_support::{postgres::PostgresContainer, runtime};
    use uuid::Uuid;

    const SCHEMA_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../db/sql/02_permesi.sql"
    ));

    async fn get_test_pool() -> Result<(PgPool, PostgresContainer)> {
        let postgres = PostgresContainer::start("bridge").await?;
        postgres.wait_until_ready().await?;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(&postgres.admin_dsn())
            .await?;

        sqlx::Executor::execute(&pool, SCHEMA_SQL)
            .await
            .context("failed to execute schema SQL")?;

        Ok((pool, postgres))
    }

    async fn insert_user(pool: &PgPool, email: &str) -> Result<Uuid> {
        let row = sqlx::query(
            "INSERT INTO users (email, opaque_registration_record, status) VALUES ($1, $2, 'active') RETURNING id",
        )
        .bind(email)
        .bind(vec![1_u8, 2_u8, 3_u8])
        .fetch_one(pool)
        .await
        .context("failed to insert user")?;
        Ok(row.get("id"))
    }

    #[tokio::test]
    async fn rate_limiter_allows_first_attempts() -> Result<()> {
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let (pool, _container) = get_test_pool().await?;
        sqlx::query("TRUNCATE users, admin_attempts CASCADE")
            .execute(&pool)
            .await?;

        let limiter = AdminRateLimiter::new(pool.clone());
        let user_id = insert_user(&pool, "user@example.com").await?;

        let result = limiter
            .register_attempt(user_id, Some("127.0.0.1"), Some("ES"))
            .await;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn rate_limiter_triggers_cooldown_after_failures() -> Result<()> {
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let (pool, _container) = get_test_pool().await?;
        sqlx::query("TRUNCATE users, admin_attempts CASCADE")
            .execute(&pool)
            .await?;

        let limiter = AdminRateLimiter::new(pool.clone());
        let user_id = insert_user(&pool, "fail@example.com").await?;

        for _ in 0..3 {
            let _attempt_id = limiter
                .register_attempt(user_id, None, None)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }

        let result = limiter.register_attempt(user_id, None, None).await;
        assert!(matches!(result, Err(AdminRateLimitError::Cooldown { .. })));
        Ok(())
    }

    #[tokio::test]
    async fn rate_limiter_resets_failures_on_success() -> Result<()> {
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let (pool, _container) = get_test_pool().await?;
        sqlx::query("TRUNCATE users, admin_attempts CASCADE")
            .execute(&pool)
            .await?;

        let limiter = AdminRateLimiter::new(pool.clone());
        let user_id = insert_user(&pool, "reset@example.com").await?;

        // 1 failure
        limiter
            .register_attempt(user_id, None, None)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        // 1 success
        let attempt_id = limiter
            .register_attempt(user_id, None, None)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        limiter.record_success(attempt_id).await;

        // 3rd attempt: Should NOT be in cooldown (needs 3 consecutive failures)
        let result = limiter.register_attempt(user_id, None, None).await;
        assert!(result.is_ok());
        Ok(())
    }
}
