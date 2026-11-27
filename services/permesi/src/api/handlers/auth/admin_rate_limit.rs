//! Database-backed rate limiting for admin elevation and bootstrap flows.
//!
//! Flow Overview:
//! 1) Track per-user and per-IP attempts in `admin_attempts` table.
//! 2) Enforce rolling window limits (3 per user, 10 per IP in 10 minutes).
//! 3) Trigger 15-minute cooldown after 3 consecutive failures.
//!
//! Scaling: Uses `PostgreSQL` to synchronize limits across multiple service instances.
//! Checking the limits and reserving the attempt happen in one transaction that holds
//! an advisory lock for the user and one for the address, so concurrent requests, on
//! one replica or several, cannot each count the window before any of them is recorded.
//! The reservation commits before OpenBao is asked and starts as a failure; only a
//! request that ends in an elevation or a bootstrap marks it successful. A database that
//! cannot be read refuses the attempt, which the caller answers as rate limited.

use anyhow::Result;
use sqlx::{PgConnection, PgPool, Row};
use std::time::Duration;
use tracing::{Instrument, error};
use uuid::Uuid;

const ATTEMPT_WINDOW: Duration = Duration::from_mins(10);
const USER_ATTEMPT_LIMIT: i64 = 3;
const IP_ATTEMPT_LIMIT: i64 = 10;
const FAILURE_LIMIT: i64 = 3;
const COOLDOWN_DURATION: Duration = Duration::from_mins(15);
/// Advisory lock classes; the second key is a hash of the user id or the address.
const USER_LOCK_CLASS: i32 = 4_201_111;
const IP_LOCK_CLASS: i32 = 4_201_112;

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
    /// The checks and the reservation are one transaction under the user's and the
    /// address's advisory locks, taken in that order, so the window limits hold under
    /// concurrency. Any database failure refuses the attempt.
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
        let refused = |step: &'static str| {
            move |err: sqlx::Error| {
                // Fail closed: an unavailable database must not reopen operator-token guessing.
                error!("Failed to {step}: {err}");
                AdminRateLimitError::Limited
            }
        };
        let mut transaction = service_utils::database::begin(&self.pool)
            .await
            .map_err(|err| {
                error!("Failed to begin admin attempt registration: {err}");
                AdminRateLimitError::Limited
            })?;
        // Each statement below has to see what the request before it committed while
        // this one waited for the lock. Under REPEATABLE READ the snapshot would be
        // taken before the wait and miss it, whatever the database default is.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .execute(&mut *transaction)
            .await
            .map_err(refused("set the admin attempt isolation level"))?;
        lock_subject(&mut transaction, USER_LOCK_CLASS, &user_id.to_string())
            .await
            .map_err(refused("lock the user's admin attempts"))?;
        if let Some(ip) = ip {
            lock_subject(&mut transaction, IP_LOCK_CLASS, ip)
                .await
                .map_err(refused("lock the address's admin attempts"))?;
        }

        // A cooldown that cannot be read is treated as active.
        let cooldown = cooldown(&mut transaction, user_id)
            .await
            .map_err(refused("read admin cooldown"))?;
        if cooldown > 0 {
            return Err(AdminRateLimitError::Cooldown {
                remaining_seconds: cooldown,
            });
        }

        let user_attempts = count_attempts(&mut transaction, Subject::User(user_id))
            .await
            .map_err(refused("count user admin attempts"))?;
        if user_attempts >= USER_ATTEMPT_LIMIT {
            return Err(AdminRateLimitError::Limited);
        }
        if let Some(ip) = ip {
            let ip_attempts = count_attempts(&mut transaction, Subject::Ip(ip))
                .await
                .map_err(refused("count IP admin attempts"))?;
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
            .fetch_one(&mut *transaction)
            .instrument(span)
            .await
            .map_err(refused("register admin attempt"))?;
        let attempt: Uuid = row.get(0);
        transaction
            .commit()
            .await
            .map_err(refused("commit admin attempt"))?;
        Ok(attempt)
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

    /// Clears the failure flag of `attempt_id` on the caller's transaction, so the
    /// success is recorded together with what it stands for or not at all. Returns
    /// whether exactly that attempt was updated.
    ///
    /// # Errors
    /// Returns the database error; the caller's transaction must then roll back.
    pub async fn record_success_on(
        connection: &mut PgConnection,
        attempt_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let updated = sqlx::query("UPDATE admin_attempts SET is_failure = FALSE WHERE id = $1")
            .bind(attempt_id)
            .execute(connection)
            .await?;
        Ok(updated.rows_affected() == 1)
    }

    /// No-op if using the pessimistic default (where `register_attempt` sets `is_failure=TRUE`).
    /// Kept for API consistency.
    pub fn record_failure(&self, _attempt_id: Uuid) {
        let _ = self;
    }

    /// Returns the remaining cooldown time in seconds for display. A failed lookup
    /// shows no cooldown; enforcement in `register_attempt` fails closed instead.
    pub async fn cooldown_seconds(&self, user_id: Uuid) -> u64 {
        let Ok(mut connection) = self.pool.acquire().await else {
            return 0;
        };
        cooldown(&mut connection, user_id).await.unwrap_or(0)
    }
}

/// Who a window count is for.
#[derive(Clone, Copy)]
enum Subject<'a> {
    User(Uuid),
    Ip(&'a str),
}

/// Serializes registrations for one user or one address until the transaction ends.
async fn lock_subject(
    connection: &mut PgConnection,
    class: i32,
    subject: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(class)
        .bind(subject)
        .execute(connection)
        .await
        .map(|_| ())
}

/// Remaining cooldown in seconds, or the database error that prevented reading it.
async fn cooldown(connection: &mut PgConnection, user_id: Uuid) -> Result<u64, sqlx::Error> {
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
        .fetch_optional(connection)
        .instrument(span)
        .await;

    Ok(match row? {
        Some(row) => {
            let last_failure_at: jiff_sqlx::Timestamp = row.get("last_failure_at");
            let now = jiff::Timestamp::now();
            let elapsed = now.duration_since(last_failure_at.to_jiff()).as_secs();
            let cooldown_secs = i64::try_from(COOLDOWN_DURATION.as_secs()).unwrap_or(i64::MAX);
            if elapsed < cooldown_secs {
                u64::try_from(cooldown_secs - elapsed).unwrap_or(0)
            } else {
                0
            }
        }
        None => 0,
    })
}

/// Attempts registered for `subject` inside the rolling window.
async fn count_attempts(
    connection: &mut PgConnection,
    subject: Subject<'_>,
) -> Result<i64, sqlx::Error> {
    let window = format!("{} seconds", ATTEMPT_WINDOW.as_secs());
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT"
    );
    let count = match subject {
        Subject::User(user_id) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_attempts WHERE user_id = $1 AND created_at > NOW() - $2::interval",
        )
        .bind(user_id),
        Subject::Ip(ip) => sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_attempts WHERE ip_address = $1::inet AND created_at > NOW() - $2::interval",
        )
        .bind(ip),
    };
    count
        .bind(window)
        .fetch_one(connection)
        .instrument(span)
        .await
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

    /// Runs every attempt at the same moment on several threads and returns how many
    /// were admitted and how the others were refused.
    async fn burst(
        limiter: &std::sync::Arc<AdminRateLimiter>,
        attempts: Vec<(Uuid, Option<&'static str>)>,
    ) -> Result<(usize, Vec<AdminRateLimitError>)> {
        let start = std::sync::Arc::new(tokio::sync::Barrier::new(attempts.len()));
        let tasks: Vec<_> = attempts
            .into_iter()
            .map(|(user, ip)| {
                let (limiter, start) = (limiter.clone(), start.clone());
                tokio::spawn(async move {
                    start.wait().await;
                    limiter.register_attempt(user, ip, None).await
                })
            })
            .collect();
        let (mut admitted, mut refused) = (0, Vec::new());
        for task in tasks {
            match task.await? {
                Ok(_) => admitted += 1,
                Err(refusal) => refused.push(refusal),
            }
        }
        Ok((admitted, refused))
    }

    /// Counting the window and reserving the attempt were separate statements on separate
    /// connections, so requests arriving together each saw room and all got in. They now
    /// take turns: exactly the limit is admitted, per user and per address, whatever
    /// isolation level the database or the role defaults to.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_registrations_cannot_exceed_the_window_limits() -> Result<()> {
        runtime::ensure_container_runtime()
            .context("The window limits require PostgreSQL; a skip is not coverage")?;
        let (pool, container) = get_test_pool().await?;
        for isolation in ["read committed", "repeatable read"] {
            // More connections than either limit, and not a divisor of one: requests that
            // are not serialized then count the window together and overshoot it.
            let wide = PgPoolOptions::new()
                .max_connections(16)
                .acquire_timeout(std::time::Duration::from_secs(30))
                .after_connect(move |connection, _| {
                    Box::pin(async move {
                        sqlx::query(sqlx::AssertSqlSafe(format!(
                            "SET default_transaction_isolation TO '{isolation}'"
                        )))
                        .execute(connection)
                        .await
                        .map(|_| ())
                    })
                })
                .connect(&container.admin_dsn())
                .await?;
            // Open every connection first, so the burst is not staggered by connecting.
            let mut warm = Vec::new();
            for _ in 0..16 {
                warm.push(wide.acquire().await?);
            }
            drop(warm);
            let limiter = std::sync::Arc::new(AdminRateLimiter::new(wide));
            let tag = isolation.replace(' ', "-");

            let user = insert_user(&pool, &format!("burst-{tag}@example.com")).await?;
            let (admitted, _) = burst(&limiter, vec![(user, None); 24]).await?;
            assert_eq!(admitted, 3, "{isolation}: per user");
            let recorded: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM admin_attempts WHERE user_id=$1")
                    .bind(user)
                    .fetch_one(&pool)
                    .await?;
            assert_eq!(recorded, 3, "{isolation}: per user");

            // Two confirmed attempts leave room for one more and keep the cooldown out
            // of it, so every refusal here is the window's own.
            let seeded = insert_user(&pool, &format!("seeded-{tag}@example.com")).await?;
            sqlx::query(
                "INSERT INTO admin_attempts(user_id,is_failure) VALUES($1,FALSE),($1,FALSE)",
            )
            .bind(seeded)
            .execute(&pool)
            .await?;
            let (admitted, refused) = burst(&limiter, vec![(seeded, None); 24]).await?;
            assert_eq!(admitted, 1, "{isolation}: window");
            assert!(
                refused
                    .iter()
                    .all(|refusal| *refusal == AdminRateLimitError::Limited),
                "{isolation}: {refused:?}"
            );

            let address: &'static str = if isolation == "read committed" {
                "203.0.113.7"
            } else {
                "203.0.113.8"
            };
            let mut one_address = Vec::new();
            for index in 0..24 {
                let user = insert_user(&pool, &format!("burst-{tag}-{index}@example.com")).await?;
                one_address.push((user, Some(address)));
            }
            let (admitted, _) = burst(&limiter, one_address).await?;
            assert_eq!(admitted, 10, "{isolation}: per address");
            let recorded: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM admin_attempts WHERE ip_address=$1::inet")
                    .bind(address)
                    .fetch_one(&pool)
                    .await?;
            assert_eq!(recorded, 10, "{isolation}: per address");
        }
        Ok(())
    }

    /// The transaction starts, and then the attempt log cannot be read: the role has no
    /// privilege on it. The attempt is refused and nothing is reserved.
    #[tokio::test]
    async fn register_attempt_fails_closed_when_the_attempt_log_cannot_be_read() -> Result<()> {
        runtime::ensure_container_runtime()
            .context("The refusal requires PostgreSQL; a skip is not coverage")?;
        let (pool, container) = get_test_pool().await?;
        let user = insert_user(&pool, "unreadable@example.com").await?;
        let name = format!("no_privileges_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "REVOKE ALL ON admin_attempts FROM PUBLIC; CREATE ROLE {name} LOGIN PASSWORD '{password}';"
        )))
        .execute(&pool)
        .await?;
        let admin = url::Url::parse(&container.admin_dsn())?;
        let mut unprivileged = admin.clone();
        unprivileged
            .set_username(&name)
            .and_then(|()| unprivileged.set_password(Some(&password)))
            .map_err(|()| anyhow::anyhow!("role credentials"))?;
        let limiter = AdminRateLimiter::new(
            PgPoolOptions::new()
                .max_connections(2)
                .connect(unprivileged.as_str())
                .await?,
        );
        assert_eq!(
            limiter.register_attempt(user, None, None).await,
            Err(AdminRateLimitError::Limited)
        );
        let recorded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_attempts")
            .fetch_one(&pool)
            .await?;
        assert_eq!(recorded, 0);
        Ok(())
    }

    /// With the database unreachable no reservation can start. Enforcement must
    /// refuse the attempt; only the display helper may fall back to "no cooldown".
    #[tokio::test]
    async fn register_attempt_fails_closed_when_the_database_is_unreachable() -> Result<()> {
        let pool = PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://invalid@127.0.0.1:1/invalid?sslmode=disable")?;
        let limiter = AdminRateLimiter::new(pool);
        let user = Uuid::new_v4();

        let attempt = limiter
            .register_attempt(user, Some("192.0.2.1"), None)
            .await;
        assert!(
            matches!(attempt, Err(AdminRateLimitError::Limited)),
            "an unreadable cooldown must not admit the attempt"
        );
        assert_eq!(limiter.cooldown_seconds(user).await, 0);
        Ok(())
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
