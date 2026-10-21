//! Verification email delivery with durable PostgreSQL leases and no secret-bearing logs.
//!
//! Flow Overview: outbox mode retains messages for explicit local inspection. SMTP
//! workers claim one row and commit, send under a network deadline, then acknowledge
//! only their live claim. No network call holds a database lock or pool connection.
//! Delivery is at least once across crashes; verification capabilities remain single-use.

mod config;
mod storage;
#[cfg(test)]
mod tests;
mod transport;
use anyhow::{Context, Result};
pub use config::DeliveryConfig;
use rand::RngExt;
use sqlx::PgPool;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Secret-bearing outbox content has no Debug implementation and is never emitted to telemetry.
pub(super) struct EmailMessage {
    to_email: String,
    template: String,
    payload_json: String,
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
            backoff_max: Duration::from_mins(5),
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

/// Starts a worker only for configured SMTP; outbox mode leaves rows pending without delivery claims.
pub(crate) fn spawn_outbox_worker(
    pool: PgPool,
    delivery: DeliveryConfig,
    config: EmailWorkerConfig,
    cancel: CancellationToken,
) -> Result<tokio::task::JoinHandle<()>> {
    let sender = delivery
        .smtp
        .clone()
        .map(transport::Sender::new)
        .transpose()?;
    Ok(tokio::spawn(async move {
        let Some(sender) = sender else {
            cancel.cancelled().await;
            return;
        };
        loop {
            if cancel.is_cancelled() {
                break;
            }
            if process_outbox_batch(&pool, &sender, &delivery, &config, &cancel)
                .await
                .is_err()
            {
                tracing::error!("email outbox storage unavailable");
            }
            tokio::select! {
                () = cancel.cancelled() => break,
                () = tokio::time::sleep(config.poll_interval()) => {}
            }
        }
    }))
}

/// Delivers a bounded number of independently leased messages; network errors never enter SQL/logs.
async fn process_outbox_batch(
    pool: &PgPool,
    sender: &transport::Sender,
    delivery: &DeliveryConfig,
    config: &EmailWorkerConfig,
    cancel: &CancellationToken,
) -> Result<()> {
    for _ in 0..config.batch_size() {
        if cancel.is_cancelled() {
            break;
        }
        let Some(claim) = storage::claim(pool, delivery, config).await? else {
            break;
        };
        let sent = sender.send(&claim.message).await.is_ok();
        tracing::info!(
            outcome = if sent { "sent" } else { "delivery_failed" },
            "email delivery attempt"
        );
        if !storage::complete(pool, delivery, config, &claim, sent).await? {
            tracing::warn!("email delivery claim expired before acknowledgement");
        }
    }
    Ok(())
}

/// Bounds each complete SQL phase including acquisition, lock waits and commit.
async fn bounded<T>(
    config: &DeliveryConfig,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(
        Duration::from_millis(u64::try_from(config.database_timeout_ms)?),
        operation,
    )
    .await
    .context("email database deadline exceeded")?
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
    let jitter = rand::rng().random_range(0..=half);
    Duration::from_millis(half + jitter)
}
