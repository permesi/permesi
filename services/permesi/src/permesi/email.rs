use anyhow::{Context, Result};
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

pub trait EmailSender: Send + Sync {
    fn send(&self, message: &EmailMessage) -> Result<()>;
}

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
}

impl EmailWorkerConfig {
    #[must_use]
    pub fn new() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            batch_size: 10,
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
}

impl Default for EmailWorkerConfig {
    fn default() -> Self {
        Self::new()
    }
}

pub fn spawn_outbox_worker(
    pool: PgPool,
    sender: Arc<dyn EmailSender>,
    config: EmailWorkerConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut poll_interval = config.poll_interval();
        if poll_interval.is_zero() {
            poll_interval = Duration::from_secs(1);
        }

        loop {
            let batch_result =
                process_outbox_batch(&pool, sender.as_ref(), config.batch_size()).await;
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
    batch_size: usize,
) -> Result<usize> {
    let mut tx = pool
        .begin()
        .await
        .context("failed to start email outbox transaction")?;

    let query = r"
        SELECT id, to_email, template, payload_json::text AS payload_json
        FROM email_outbox
        WHERE status = 'pending'
        ORDER BY created_at ASC
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
        .bind(i64::try_from(batch_size).unwrap_or(0))
        .fetch_all(&mut *tx)
        .instrument(span)
        .await
        .context("failed to load email outbox batch")?;

    if rows.is_empty() {
        tx.commit()
            .await
            .context("failed to commit empty outbox batch")?;
        return Ok(0);
    }

    let row_count = rows.len();
    for row in rows {
        let id: Uuid = row.get("id");
        let message = EmailMessage {
            to_email: row.get("to_email"),
            template: row.get("template"),
            payload_json: row.get("payload_json"),
        };

        let send_result = sender.send(&message);
        update_outbox_status(&mut tx, id, send_result).await?;
    }

    tx.commit()
        .await
        .context("failed to commit email outbox batch")?;

    Ok(row_count)
}

async fn update_outbox_status(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    send_result: Result<()>,
) -> Result<()> {
    match send_result {
        Ok(()) => {
            let query = r"
                UPDATE email_outbox
                SET status = 'sent',
                    attempts = attempts + 1,
                    last_error = NULL,
                    sent_at = NOW()
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
                .execute(&mut **tx)
                .instrument(span)
                .await
                .context("failed to update outbox status to sent")?;
        }
        Err(err) => {
            let query = r"
                UPDATE email_outbox
                SET status = 'failed',
                    attempts = attempts + 1,
                    last_error = $2
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
                .bind(err.to_string())
                .execute(&mut **tx)
                .instrument(span)
                .await
                .context("failed to update outbox status to failed")?;
        }
    }

    Ok(())
}
