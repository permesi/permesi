//! The pool's session timeouts against a real PostgreSQL.
//!
//! The unit tests pin the validation; this pins what the server then does: every
//! pooled connection carries both limits, including one opened to replace a dropped
//! connection, a statement that runs too long is cancelled, a wait for a lock nobody
//! releases ends, and a transaction can still set its own bound.

use anyhow::{Context, Result, ensure};
use service_utils::database::PoolConfig;
use sqlx::{PgPool, Row};
use std::time::{Duration, Instant};
use test_support::{postgres::PostgresContainer, runtime};

/// SQLSTATE of the error a session receives when its limit fires.
const QUERY_CANCELED: &str = "57014";
const LOCK_NOT_AVAILABLE: &str = "55P03";

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|error| error.code().map(std::borrow::Cow::into_owned))
}

async fn timeouts(pool: &PgPool) -> Result<(String, String, i32)> {
    let row = sqlx::query(
        "SELECT current_setting('statement_timeout'), current_setting('lock_timeout'), \
         pg_backend_pid()",
    )
    .fetch_one(pool)
    .await?;
    Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?))
}

#[tokio::test]
async fn every_pooled_connection_is_bounded() -> Result<()> {
    runtime::ensure_container_runtime()?;
    let postgres = PostgresContainer::start("bridge").await?;
    postgres.wait_until_ready().await?;
    let dsn = postgres.admin_dsn();

    // PostgreSQL itself imposes no limit, which is what the pool has to replace.
    let bare = PgPool::connect(&dsn).await?;
    let unbounded: (String, String) = sqlx::query_as(
        "SELECT current_setting('statement_timeout'), current_setting('lock_timeout')",
    )
    .fetch_one(&bare)
    .await?;
    ensure!(
        unbounded == ("0".to_string(), "0".to_string()),
        "the fixture already bounds sessions: {unbounded:?}"
    );

    let shape = || {
        PoolConfig::new(
            2,
            0,
            Duration::from_secs(3),
            Duration::from_secs(60),
            Duration::from_mins(5),
        )
    };

    // The defaults both services start from.
    let defaults = shape()?.connect(&dsn, "session-timeouts").await?;
    let (statement, lock, _) = timeouts(&defaults).await?;
    ensure!(
        (statement.as_str(), lock.as_str()) == ("30s", "5s"),
        "default session timeouts are {statement}/{lock}"
    );
    defaults.close().await;

    let pool = shape()?
        .with_session_timeouts(Duration::from_millis(1_500), Duration::from_millis(400))?
        .connect(&dsn, "session-timeouts")
        .await?;
    let (statement, lock, first) = timeouts(&pool).await?;
    ensure!(
        (statement.as_str(), lock.as_str()) == ("1500ms", "400ms"),
        "configured session timeouts are {statement}/{lock}"
    );

    slow_statement_is_cancelled(&pool).await?;
    lock_wait_ends_at_the_lock_limit(&bare, &pool).await?;
    replacement_connection_is_bounded(&bare, &pool, first).await?;

    pool.close().await;
    bare.close().await;
    Ok(())
}

/// A statement that outlives the limit is cancelled by the server, promptly.
async fn slow_statement_is_cancelled(pool: &PgPool) -> Result<()> {
    let started = Instant::now();
    let slow = sqlx::query("SELECT pg_sleep(20)").execute(pool).await;
    let Err(error) = slow else {
        anyhow::bail!("a 20 s statement finished under a 1.5 s limit");
    };
    ensure!(
        sqlstate(&error).as_deref() == Some(QUERY_CANCELED),
        "unexpected error for the slow statement: {error}"
    );
    ensure!(
        started.elapsed() < Duration::from_secs(10),
        "the slow statement ran for {:?}",
        started.elapsed()
    );
    Ok(())
}

/// A wait for a lock that is never released ends at the lock limit, not the statement
/// limit, and says so. A transaction that needs longer can still say so, for itself.
async fn lock_wait_ends_at_the_lock_limit(bare: &PgPool, pool: &PgPool) -> Result<()> {
    sqlx::query("CREATE TABLE bounded (id int PRIMARY KEY)")
        .execute(bare)
        .await?;
    sqlx::query("INSERT INTO bounded VALUES (1)")
        .execute(bare)
        .await?;
    let mut holder = bare.begin().await?;
    sqlx::query("SELECT id FROM bounded WHERE id = 1 FOR UPDATE")
        .execute(&mut *holder)
        .await?;
    let started = Instant::now();
    let blocked = sqlx::query("UPDATE bounded SET id = 2 WHERE id = 1")
        .execute(pool)
        .await;
    let Err(error) = blocked else {
        anyhow::bail!("an update got past a held row lock");
    };
    ensure!(
        sqlstate(&error).as_deref() == Some(LOCK_NOT_AVAILABLE),
        "unexpected error for the blocked statement: {error}"
    );
    ensure!(
        started.elapsed() < Duration::from_millis(1_400),
        "the lock wait lasted {:?}, past the lock limit",
        started.elapsed()
    );

    // A transaction that needs longer can still say so, for itself only.
    let mut transaction = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = '4s'")
        .execute(&mut *transaction)
        .await?;
    sqlx::query("SELECT pg_sleep(2)")
        .execute(&mut *transaction)
        .await
        .context("a transaction-level limit did not override the session limit")?;
    transaction.commit().await?;
    let (statement, _, _) = timeouts(pool).await?;
    ensure!(statement == "1500ms", "SET LOCAL leaked: {statement}");
    holder.rollback().await?;
    Ok(())
}

/// Connections opened later, to replace ones the server closed, are bounded too.
async fn replacement_connection_is_bounded(bare: &PgPool, pool: &PgPool, first: i32) -> Result<()> {
    sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE application_name = 'session-timeouts'",
    )
    .execute(bare)
    .await?;
    let mut replaced = None;
    for _ in 0..20 {
        if let Ok((statement, lock, pid)) = timeouts(pool).await
            && pid != first
        {
            replaced = Some((statement, lock));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(
        replaced == Some(("1500ms".to_string(), "400ms".to_string())),
        "a replacement connection came back as {replaced:?}"
    );
    Ok(())
}
