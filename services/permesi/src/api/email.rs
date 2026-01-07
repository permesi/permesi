//! Email outbox worker and delivery abstractions.
//!
//! Signup and verification flows enqueue rows in `email_outbox` with status `pending`.
//! A background task periodically polls that table, locks a batch via
//! `FOR UPDATE SKIP LOCKED`, and hands each row to an `EmailSender`.
//! The sender decides how to deliver (SMTP, API, etc.) and returns `Ok`/`Err`.
//! The worker then updates the outbox row to `sent` or `failed`.
//!
//! ### Consistency & Scalability
//!
//! This is a lightweight transactional outbox (DB-backed queue) used to keep API
//! latency low and ensure atomicity between user creation and email enqueuing.
//!
//! - **Throughput:** For current scale, the DB outbox keeps infrastructure minimal.
//!   If higher throughput or multi-service fan-out is needed, the `EmailSender`
//!   trait can be implemented to publish to a broker (e.g., NATS `JetStream`, `RabbitMQ`).
//! - **Retries:** Failed rows are retried with exponential backoff and jitter
//!   until a max attempt threshold is reached, then marked `failed`.
//!
//! The default sender for local dev is `LogEmailSender`, which logs and returns `Ok(())`.
//! Poll interval and retry/backoff settings are configurable via `EmailWorkerConfig`.
use anyhow::{Context, Result};
use rand::Rng;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{Instrument, error, info, info_span};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct EmailMessage {
    pub to_email: String,
    pub template: String,
    pub payload_json: String,
}

/// Email delivery abstraction used by the outbox worker.
pub trait EmailSender: Send + Sync {
    /// Deliver a message or return an error to mark it as failed.
    fn send(&self, message: &EmailMessage) -> Result<()>;
}

/// Local dev sender that logs the payload instead of sending real email.
#[derive(Clone, Debug)]
pub struct LogEmailSender;

impl EmailSender for LogEmailSender {
    fn send(&self, message: &EmailMessage) -> Result<()> {
        info!(
            to_email = %message.to_email,
            template = %message.template,
            payload = %message.payload_json,
            "email outbox send stub"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EmailWorkerConfig {
    poll_interval: Duration,
    batch_size: usize,
    max_attempts: u32,
    backoff_base: Duration,
    backoff_max: Duration,
}

impl EmailWorkerConfig {
    /// Default worker config: 5s poll interval, 10 messages per batch,
    /// 5 max attempts, and 5s->5m exponential backoff with jitter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            batch_size: 10,
            max_attempts: 5,
            backoff_base: Duration::from_secs(5),
            backoff_max: Duration::from_secs(300),
        }
    }

    #[must_use]
    pub fn with_poll_interval_seconds(mut self, seconds: u64) -> Self {
        self.poll_interval = Duration::from_secs(seconds);
        self
    }

    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    #[must_use]
    pub fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    #[must_use]
    pub fn with_backoff_base_seconds(mut self, seconds: u64) -> Self {
        self.backoff_base = Duration::from_secs(seconds);
        self
    }

    #[must_use]
    pub fn with_backoff_max_seconds(mut self, seconds: u64) -> Self {
        self.backoff_max = Duration::from_secs(seconds);
        self
    }

    #[must_use]
    pub fn normalize(self) -> Self {
        let poll_interval = if self.poll_interval.is_zero() {
            Duration::from_secs(1)
        } else {
            self.poll_interval
        };
        let batch_size = if self.batch_size == 0 {
            1
        } else {
            self.batch_size
        };
        let max_attempts = self.max_attempts.max(1);
        let backoff_base = if self.backoff_base.is_zero() {
            Duration::from_secs(1)
        } else {
            self.backoff_base
        };
        let backoff_max = if self.backoff_max < backoff_base {
            backoff_base
        } else {
            self.backoff_max
        };
        Self {
            poll_interval,
            batch_size,
            max_attempts,
            backoff_base,
            backoff_max,
        }
    }

    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    #[must_use]
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    #[must_use]
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    #[must_use]
    pub fn backoff_base(&self) -> Duration {
        self.backoff_base
    }

    #[must_use]
    pub fn backoff_max(&self) -> Duration {
        self.backoff_max
    }
}

impl Default for EmailWorkerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn a background task that polls and processes the email outbox.
pub fn spawn_outbox_worker(
    pool: PgPool,
    sender: Arc<dyn EmailSender>,
    config: EmailWorkerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let config = config.normalize();
        let poll_interval = config.poll_interval();

        loop {
            // Poll the outbox table on a fixed cadence; sender handles delivery or logging.
            let batch_result = process_outbox_batch(&pool, sender.as_ref(), &config).await;
            if let Err(err) = batch_result {
                error!("email outbox batch failed: {err}");
            }

            sleep(poll_interval).await;
        }
    })
}

async fn process_outbox_batch(
    pool: &PgPool,
    sender: &dyn EmailSender,
    config: &EmailWorkerConfig,
) -> Result<usize> {
    let mut tx = pool
        .begin()
        .await
        .context("failed to start email outbox transaction")?;

    // Grab a locked batch so multiple workers can run without double-sending.
    let query = r"
        SELECT id, to_email, template, payload_json::text AS payload_json, attempts
        FROM email_outbox
        WHERE status = 'pending'
          AND next_attempt_at <= NOW()
        ORDER BY next_attempt_at ASC, created_at ASC
        LIMIT $1
        FOR UPDATE SKIP LOCKED
    ";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let rows = sqlx::query(query)
        .bind(i64::try_from(config.batch_size()).unwrap_or(0))
        .fetch_all(&mut *tx)
        .instrument(span)
        .await
        .context("failed to load email outbox batch")?;

    if rows.is_empty() {
        // Commit even on empty to release locks and keep poll loop consistent.
        tx.commit()
            .await
            .context("failed to commit empty outbox batch")?;
        return Ok(0);
    }

    let row_count = rows.len();
    for row in rows {
        let id: Uuid = row.get("id");
        let attempts: i32 = row.get("attempts");
        let attempts = u32::try_from(attempts).unwrap_or(0);
        let message = EmailMessage {
            to_email: row.get("to_email"),
            template: row.get("template"),
            payload_json: row.get("payload_json"),
        };

        let send_result = sender.send(&message);
        update_outbox_status(&mut tx, id, attempts, send_result, config).await?;
    }

    tx.commit()
        .await
        .context("failed to commit email outbox batch")?;

    Ok(row_count)
}

async fn update_outbox_status(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    attempts: u32,
    send_result: Result<()>,
    config: &EmailWorkerConfig,
) -> Result<()> {
    // Retry failures with exponential backoff and jitter until max_attempts.
    let next_attempt = attempts.saturating_add(1);
    let next_attempts_i32 = i32::try_from(next_attempt).unwrap_or(i32::MAX);
    match send_result {
        Ok(()) => {
            let query = r"
                UPDATE email_outbox
                SET status = 'sent',
                    attempts = $2,
                    last_error = NULL,
                    sent_at = NOW(),
                    next_attempt_at = NOW()
                WHERE id = $1
            ";
            let span = info_span!(
                "db.query",
                db.system = "postgresql",
                db.operation = "UPDATE",
                db.statement = query
            );
            sqlx::query(query)
                .bind(id)
                .bind(next_attempts_i32)
                .execute(&mut **tx)
                .instrument(span)
                .await
                .context("failed to update outbox status to sent")?;
        }
        Err(err) => {
            let max_attempts = config.max_attempts();
            if next_attempt >= max_attempts {
                let query = r"
                    UPDATE email_outbox
                    SET status = 'failed',
                        attempts = $2,
                        last_error = $3,
                        next_attempt_at = NOW()
                    WHERE id = $1
                ";
                let span = info_span!(
                    "db.query",
                    db.system = "postgresql",
                    db.operation = "UPDATE",
                    db.statement = query
                );
                sqlx::query(query)
                    .bind(id)
                    .bind(next_attempts_i32)
                    .bind(err.to_string())
                    .execute(&mut **tx)
                    .instrument(span)
                    .await
                    .context("failed to update outbox status to failed")?;
            } else {
                let delay =
                    backoff_delay(next_attempt, config.backoff_base(), config.backoff_max());
                let delay_ms = i64::try_from(delay.as_millis()).unwrap_or(i64::MAX);
                let query = r"
                    UPDATE email_outbox
                    SET status = 'pending',
                        attempts = $2,
                        last_error = $3,
                        next_attempt_at = NOW() + ($4 * INTERVAL '1 millisecond')
                    WHERE id = $1
                ";
                let span = info_span!(
                    "db.query",
                    db.system = "postgresql",
                    db.operation = "UPDATE",
                    db.statement = query
                );
                sqlx::query(query)
                    .bind(id)
                    .bind(next_attempts_i32)
                    .bind(err.to_string())
                    .bind(delay_ms)
                    .execute(&mut **tx)
                    .instrument(span)
                    .await
                    .context("failed to update outbox retry schedule")?;
            }
        }
    }

    Ok(())
}

fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let shift = attempt.saturating_sub(1).min(31);
    let factor = 1u32 << shift;
    let delay = base.checked_mul(factor).unwrap_or(max);
    let capped = if delay > max { max } else { delay };
    jitter_delay(capped)
}

fn jitter_delay(delay: Duration) -> Duration {
    let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
    if delay_ms < 2 {
        return delay;
    }
    let half = delay_ms / 2;
    let jitter = rand::thread_rng().gen_range(0..=half);
    Duration::from_millis(half + jitter)
}
