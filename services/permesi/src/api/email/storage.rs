//! Durable outbox claims keep SMTP outside transactions and coordinate every replica.
//!
//! Flow Overview: a short SKIP LOCKED transaction leases one eligible row and commits.
//! After delivery, a second transaction conditionally acknowledges only that live lease.
//! Crashed workers lose their claim on expiry; SMTP acceptance before a crash may duplicate
//! an email on retry, but can never duplicate verification authority.
use super::{DeliveryConfig, EmailMessage, EmailWorkerConfig};
use anyhow::Result;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Private lease receipt; no recipient or message content is Debug-printable.
pub(super) struct Claim {
    pub(super) id: Uuid,
    pub(super) lease: Uuid,
    pub(super) attempts: i32,
    pub(super) message: EmailMessage,
}

/// Claims only one row, committing before the caller starts network delivery.
pub(super) async fn claim(
    pool: &PgPool,
    delivery: &DeliveryConfig,
    config: &EmailWorkerConfig,
) -> Result<Option<Claim>> {
    super::bounded(delivery, async {
        let mut tx = crate::api::handlers::auth::operations::begin(pool, delivery.database_timeout_ms).await?;
        sqlx::query("UPDATE email_outbox SET status='failed',last_error='delivery_attempts_exhausted',claim_id=NULL,claim_expires_at=NULL WHERE status='pending' AND attempts >= $1 AND (claim_expires_at IS NULL OR claim_expires_at<=clock_timestamp())")
            .bind(i32::try_from(config.max_attempts())?).execute(&mut *tx).await?;
        let lease = Uuid::new_v4();
        let row = sqlx::query("WITH candidate AS (SELECT id FROM email_outbox WHERE status='pending' AND attempts<$1 AND next_attempt_at<=clock_timestamp() AND (claim_expires_at IS NULL OR claim_expires_at<=clock_timestamp()) ORDER BY next_attempt_at,created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE email_outbox e SET claim_id=$2,claim_expires_at=clock_timestamp()+$3*INTERVAL '1 second',attempts=e.attempts+1 FROM candidate c WHERE e.id=c.id RETURNING e.id,e.attempts,e.to_email::text,e.template,e.payload_json::text")
            .bind(i32::try_from(config.max_attempts())?).bind(lease).bind(delivery.lease_seconds).fetch_optional(&mut *tx).await?;
        tx.commit().await?;
        Ok(row.map(|row| Claim {
            id: row.get("id"), lease, attempts: row.get("attempts"),
            message: EmailMessage { to_email: row.get("to_email"), template: row.get("template"), payload_json: row.get("payload_json") }
        }))
    }).await
}

/// Records only fixed diagnostic codes and refuses stale-worker results after expiry/reclaim.
pub(super) async fn complete(
    pool: &PgPool,
    delivery: &DeliveryConfig,
    config: &EmailWorkerConfig,
    claim: &Claim,
    sent: bool,
) -> Result<bool> {
    super::bounded(delivery, async {
        let mut tx = crate::api::handlers::auth::operations::begin(pool, delivery.database_timeout_ms).await?;
        let status = if sent { "sent" } else if u32::try_from(claim.attempts)? >= config.max_attempts() { "failed" } else { "pending" };
        let delay_ms = i64::try_from(super::backoff_delay(u32::try_from(claim.attempts)?, config.backoff_base(), config.backoff_max()).as_millis())?;
        let result = sqlx::query("UPDATE email_outbox SET status=$3::email_outbox_status,sent_at=CASE WHEN $4 THEN clock_timestamp() ELSE NULL END,last_error=CASE WHEN $4 THEN NULL ELSE 'smtp_delivery_failed' END,next_attempt_at=clock_timestamp()+$5*INTERVAL '1 millisecond',claim_id=NULL,claim_expires_at=NULL WHERE id=$1 AND claim_id=$2 AND status='pending' AND claim_expires_at>clock_timestamp()")
            .bind(claim.id).bind(claim.lease).bind(status).bind(sent).bind(delay_ms).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }).await
}
