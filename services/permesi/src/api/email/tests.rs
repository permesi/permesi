//! Outbox regressions use real PostgreSQL and independently owned worker leases.
use super::*;

/// Outbox-only mode must never deliver, consume or falsely acknowledge an email.
#[tokio::test]
async fn outbox_worker_stops_when_cancelled() -> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://invalid@127.0.0.1:1/invalid")?;
    let cancel = CancellationToken::new();
    let worker = spawn_outbox_worker(
        pool,
        DeliveryConfig::default(),
        EmailWorkerConfig::new(),
        cancel.clone(),
    )?;
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), worker).await??;
    Ok(())
}

mod smtp;

/// Fresh owned database; unavailable dependencies fail these security regressions explicitly.
async fn database() -> Result<(test_support::postgres::PostgresContainer, PgPool)> {
    use sqlx::Connection as _;
    test_support::runtime::ensure_container_runtime()?;
    let postgres = test_support::postgres::PostgresContainer::start("bridge").await?;
    postgres.wait_until_ready().await?;
    let mut connection = sqlx::PgConnection::connect(&postgres.admin_dsn()).await?;
    test_support::sql::execute_script(
        &mut connection,
        "02_permesi.sql",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../db/sql/02_permesi.sql"
        )),
    )
    .await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&postgres.admin_dsn())
        .await?;
    Ok((postgres, pool))
}

/// Uses a private fake capability in memory; no message content is printed or written to test artifacts.
async fn enqueue(pool: &PgPool) -> Result<()> {
    sqlx::query("INSERT INTO email_outbox(to_email,template,payload_json) VALUES('recipient@example.test','verify_email','{\"email\":\"recipient@example.test\",\"verify_url\":\"https://permesi.test/verify-email#token=private-test-capability\"}'::jsonb)").execute(pool).await?;
    Ok(())
}

/// Claims commit before delivery; a second process sees the lease and can still lock the outbox row.
#[tokio::test]
async fn outbox_claims_do_not_hold_locks_during_delivery() -> Result<()> {
    let (postgres, pool) = database().await?;
    let independent_pool = sqlx::PgPool::connect(&postgres.admin_dsn()).await?;
    enqueue(&pool).await?;
    let delivery = DeliveryConfig::default();
    let config = EmailWorkerConfig::new();
    let (a, b) = tokio::join!(
        storage::claim(&pool, &delivery, &config),
        storage::claim(&independent_pool, &delivery, &config)
    );
    let claims: Vec<_> = [a?, b?].into_iter().flatten().collect();
    assert_eq!(claims.len(), 1);
    let claim = claims.first().context("claim")?;
    let mut independent = pool.begin().await?;
    sqlx::query("SELECT id FROM email_outbox WHERE id=$1 FOR UPDATE NOWAIT")
        .bind(claim.id)
        .execute(&mut *independent)
        .await?;
    independent.rollback().await?;
    assert!(storage::complete(&pool, &delivery, &config, claim, true).await?);
    assert!(!storage::complete(&pool, &delivery, &config, claim, true).await?);
    let status: String = sqlx::query_scalar("SELECT status::text FROM email_outbox")
        .fetch_one(&pool)
        .await?;
    assert_eq!(status, "sent");
    Ok(())
}

/// A crash abandons a lease, never the queue; the stale process cannot acknowledge a replacement.
#[tokio::test]
async fn outbox_expired_lease_recovery_rejects_stale_worker() -> Result<()> {
    let (postgres, pool) = database().await?;
    let replacement_pool = sqlx::PgPool::connect(&postgres.admin_dsn()).await?;
    enqueue(&pool).await?;
    let delivery = DeliveryConfig::default();
    let config = EmailWorkerConfig::new();
    let old = storage::claim(&pool, &delivery, &config)
        .await?
        .context("old claim")?;
    sqlx::query("UPDATE email_outbox SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'")
        .execute(&pool)
        .await?;
    assert!(!storage::complete(&pool, &delivery, &config, &old, true).await?);
    let new = storage::claim(&replacement_pool, &delivery, &config)
        .await?
        .context("replacement claim")?;
    assert_ne!(old.lease, new.lease);
    assert_eq!(new.attempts, 2);
    assert!(!storage::complete(&pool, &delivery, &config, &old, false).await?);
    assert!(storage::complete(&pool, &delivery, &config, &new, false).await?);
    let row: (String, bool, String) =
        sqlx::query_as("SELECT status::text,sent_at IS NULL,last_error FROM email_outbox")
            .fetch_one(&pool)
            .await?;
    assert_eq!(row, ("pending".into(), true, "smtp_delivery_failed".into()));
    Ok(())
}

/// Crashes count toward the configured attempt budget instead of creating an infinite retry loop.
#[tokio::test]
async fn outbox_crashed_final_attempt_is_retired() -> Result<()> {
    let (_postgres, pool) = database().await?;
    enqueue(&pool).await?;
    let delivery = DeliveryConfig::default();
    let config = EmailWorkerConfig::new().with_max_attempts(1);
    let _ = storage::claim(&pool, &delivery, &config)
        .await?
        .context("claim")?;
    sqlx::query("UPDATE email_outbox SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'")
        .execute(&pool)
        .await?;
    assert!(storage::claim(&pool, &delivery, &config).await?.is_none());
    let row: (String, bool, bool) =
        sqlx::query_as("SELECT status::text,sent_at IS NULL,claim_id IS NULL FROM email_outbox")
            .fetch_one(&pool)
            .await?;
    assert_eq!(row, ("failed".into(), true, true));
    Ok(())
}

/// Outbox mode never acknowledges messages and configuration never exposes SMTP credentials.
#[tokio::test]
async fn outbox_only_mode_keeps_messages_pending() -> Result<()> {
    let (_postgres, pool) = database().await?;
    enqueue(&pool).await?;
    let cancel = CancellationToken::new();
    let worker = spawn_outbox_worker(
        pool.clone(),
        DeliveryConfig::default(),
        EmailWorkerConfig::new(),
        cancel.clone(),
    )?;
    tokio::task::yield_now().await;
    cancel.cancel();
    worker.await?;
    let row: (String, i32, bool) =
        sqlx::query_as("SELECT status::text,attempts,claim_id IS NULL FROM email_outbox")
            .fetch_one(&pool)
            .await?;
    assert_eq!(row, ("pending".into(), 0, true));
    Ok(())
}

/// In-memory trace capture never writes the synthetic capability to an artifact.
#[derive(Clone)]
struct TraceSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for TraceSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("capture poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Real least-privilege logins claim/complete messages and retain valid leases across schema reapply.
#[tokio::test]
async fn outbox_runtime_login_and_schema_reapplication_preserve_claims() -> Result<()> {
    use sqlx::Connection as _;
    test_support::runtime::ensure_container_runtime()?;
    let postgres = test_support::postgres::PostgresContainer::start("bridge").await?;
    postgres.wait_until_ready().await?;
    postgres.bootstrap().await?;
    let name = format!("outbox_runtime_{}", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().simple().to_string();
    let mut admin = sqlx::PgConnection::connect(&postgres.admin_dsn_for_db("permesi")).await?;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE ROLE {name} LOGIN PASSWORD '{password}'; GRANT permesi_runtime TO {name};"
    )))
    .execute(&mut admin)
    .await?;
    let options = sqlx::postgres::PgConnectOptions::new()
        .host("127.0.0.1")
        .port(postgres.host_port())
        .database("permesi")
        .username(&name)
        .password(&password);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_with(options)
        .await?;
    let privileged: bool = sqlx::query_scalar(
        "SELECT rolsuper OR rolcreaterole OR rolbypassrls FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(&pool)
    .await?;
    assert!(!privileged);
    enqueue(&pool).await?;
    let delivery = DeliveryConfig::default();
    let config = EmailWorkerConfig::new();
    let receipt = storage::claim(&pool, &delivery, &config)
        .await?
        .context("runtime claim")?;
    postgres.bootstrap().await?;
    assert!(storage::complete(&pool, &delivery, &config, &receipt, true).await?);
    let status: String = sqlx::query_scalar("SELECT status::text FROM email_outbox")
        .fetch_one(&pool)
        .await?;
    assert_eq!(status, "sent");
    Ok(())
}
