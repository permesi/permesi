//! Database access for platform operator bootstrap and lookup.
//!
//! Flow Overview:
//! 1) Read operator count to determine bootstrap availability.
//! 2) Check enabled status for operator gating.
//! 3) Insert the first operator under an advisory lock for concurrency safety.

use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use tracing::Instrument;
use uuid::Uuid;

const BOOTSTRAP_LOCK_ID: i64 = 4_201_110;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    Inserted,
    Closed,
}

pub async fn platform_operator_count(pool: &PgPool) -> Result<i64> {
    let query = "SELECT COUNT(*) AS count FROM platform_operators";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .fetch_one(pool)
        .instrument(span)
        .await
        .context("failed to count platform operators")?;
    Ok(row.get("count"))
}

pub async fn operator_enabled(pool: &PgPool, user_id: Uuid) -> Result<bool> {
    let query = r"
        SELECT enabled
        FROM platform_operators
        WHERE user_id = $1
        LIMIT 1
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(user_id)
        .fetch_optional(pool)
        .instrument(span)
        .await
        .context("failed to lookup platform operator")?;
    Ok(row.is_some_and(|row| row.get::<bool, _>("enabled")))
}

pub async fn bootstrap_operator(
    pool: &PgPool,
    user_id: Uuid,
    note: Option<&str>,
) -> Result<BootstrapOutcome> {
    let mut tx = pool
        .begin()
        .await
        .context("failed to begin bootstrap transaction")?;

    let lock_query = "SELECT pg_advisory_xact_lock($1)";
    let lock_span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = lock_query
    );
    sqlx::query(lock_query)
        .bind(BOOTSTRAP_LOCK_ID)
        .execute(&mut *tx)
        .instrument(lock_span)
        .await
        .context("failed to acquire bootstrap lock")?;

    let count_query = "SELECT COUNT(*) AS count FROM platform_operators";
    let count_span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = count_query
    );
    let row = sqlx::query(count_query)
        .fetch_one(&mut *tx)
        .instrument(count_span)
        .await
        .context("failed to count platform operators")?;
    let count: i64 = row.get("count");
    if count != 0 {
        tx.rollback()
            .await
            .context("failed to rollback bootstrap transaction")?;
        return Ok(BootstrapOutcome::Closed);
    }

    let insert_query = r"
        INSERT INTO platform_operators (user_id, created_by, note)
        VALUES ($1, $2, $3)
    ";
    let insert_span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = insert_query
    );
    sqlx::query(insert_query)
        .bind(user_id)
        .bind(user_id)
        .bind(note)
        .execute(&mut *tx)
        .instrument(insert_span)
        .await
        .context("failed to insert platform operator")?;

    tx.commit()
        .await
        .context("failed to commit bootstrap transaction")?;

    Ok(BootstrapOutcome::Inserted)
}

#[cfg(test)]
mod tests {
    use super::{BootstrapOutcome, bootstrap_operator, operator_enabled, platform_operator_count};
    use anyhow::{Context, Result};
    use sqlx::{PgPool, Row, postgres::PgPoolOptions};
    use test_support::{TestNetwork, postgres::PostgresContainer, runtime};
    use tokio::sync::OnceCell;
    use uuid::Uuid;

    const SCHEMA_SQL: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/sql/schema.sql"));

    static TEST_CONTAINER: OnceCell<PostgresContainer> = OnceCell::const_new();

    async fn get_test_pool() -> Result<PgPool> {
        let container = TEST_CONTAINER
            .get_or_try_init(|| async {
                let network = TestNetwork::new("permesi-admin-storage-test");
                let postgres = PostgresContainer::start(network.name()).await?;
                postgres.wait_until_ready().await?;
                Ok::<PostgresContainer, anyhow::Error>(postgres)
            })
            .await?;

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(&container.admin_dsn())
            .await?;

        sqlx::Executor::execute(&pool, SCHEMA_SQL)
            .await
            .context("failed to execute schema SQL")?;

        Ok(pool)
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

    static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn bootstrap_only_once() -> Result<()> {
        let _guard = TEST_MUTEX.lock().await;
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let pool = get_test_pool().await?;
        sqlx::query("TRUNCATE users, platform_operators CASCADE")
            .execute(&pool)
            .await?;

        let user_id = insert_user(&pool, "operator@example.com").await?;
        let first = bootstrap_operator(&pool, user_id, Some("first")).await?;
        let second = bootstrap_operator(&pool, user_id, Some("second")).await?;
        let count = platform_operator_count(&pool).await?;

        assert_eq!(first, BootstrapOutcome::Inserted);
        assert_eq!(second, BootstrapOutcome::Closed);
        assert_eq!(count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_concurrent_only_inserts_once() -> Result<()> {
        let _guard = TEST_MUTEX.lock().await;
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let pool = get_test_pool().await?;
        sqlx::query("TRUNCATE users, platform_operators CASCADE")
            .execute(&pool)
            .await?;

        let user_a = insert_user(&pool, "a@example.com").await?;
        let user_b = insert_user(&pool, "b@example.com").await?;

        let pool_a = pool.clone();
        let task_a = tokio::spawn(async move { bootstrap_operator(&pool_a, user_a, None).await });
        let pool_b = pool.clone();
        let task_b = tokio::spawn(async move { bootstrap_operator(&pool_b, user_b, None).await });

        let (result_a, result_b) = tokio::try_join!(task_a, task_b)?;
        assert!(result_a.is_ok());
        assert!(result_b.is_ok());
        let count = platform_operator_count(&pool).await?;
        assert_eq!(count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn operator_enabled_false_when_missing() -> Result<()> {
        let _guard = TEST_MUTEX.lock().await;
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let pool = get_test_pool().await?;
        sqlx::query("TRUNCATE users, platform_operators CASCADE")
            .execute(&pool)
            .await?;

        let user_id = insert_user(&pool, "missing@example.com").await?;
        let enabled = operator_enabled(&pool, user_id).await?;
        assert!(!enabled);
        Ok(())
    }
}
