//! Database helpers for auth and verification state.

use anyhow::{Context, Result, anyhow};
use serde_json::json;
use sqlx::{PgPool, Row};
use tracing::Instrument;
use uuid::Uuid;

use super::state::AuthConfig;
use super::utils::{
    build_verify_url, generate_session_token, generate_verification_token, hash_session_token,
    hash_verification_token, is_unique_violation,
};

/// Outcome when attempting to create a new user + verification record.
#[derive(Debug)]
pub(super) enum SignupOutcome {
    Created,
    Conflict,
}

/// Outcome for a resend request (always 204 to avoid account probing).
#[derive(Debug)]
pub(super) enum ResendOutcome {
    Queued,
    Cooldown,
    Noop,
}

/// Minimal fields needed to start OPAQUE login.
pub(super) struct LoginRecord {
    pub(super) user_id: Uuid,
    pub(super) status: String,
    pub(super) opaque_record: Vec<u8>,
}

/// Minimal data returned for a valid session cookie.
pub(crate) struct SessionRecord {
    pub(crate) user_id: Uuid,
    pub(crate) email: String,
}

/// Look up login data by email (used by OPAQUE login start).
pub(super) async fn lookup_login_record(pool: &PgPool, email: &str) -> Result<Option<LoginRecord>> {
    let query =
        "SELECT id, status::text AS status, opaque_registration_record FROM users WHERE email = $1";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(email)
        .fetch_optional(pool)
        .instrument(span)
        .await
        .context("failed to lookup login record")?;

    Ok(row.map(|row| LoginRecord {
        user_id: row.get("id"),
        status: row.get("status"),
        opaque_record: row.get("opaque_registration_record"),
    }))
}

pub(super) async fn insert_user_and_verification(
    pool: &PgPool,
    email: &str,
    opaque_record: &[u8],
    config: &AuthConfig,
) -> Result<SignupOutcome> {
    // Transaction ensures user creation, verification token, and email outbox row
    // stay consistent even if something fails.
    let mut tx = pool.begin().await.context("begin signup transaction")?;

    let query = r"
        INSERT INTO users
            (email, opaque_registration_record)
        VALUES ($1, $2)
        RETURNING id
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(email)
        .bind(opaque_record)
        .fetch_one(&mut *tx)
        .instrument(span)
        .await;

    let user_id: Uuid = match row {
        Ok(row) => row.get("id"),
        Err(err) => {
            if is_unique_violation(&err) {
                let _ = tx.rollback().await;
                return Ok(SignupOutcome::Conflict);
            }
            return Err(err).context("failed to insert user");
        }
    };

    let _token = insert_verification_records(&mut tx, user_id, email, config).await?;

    tx.commit().await.context("commit signup transaction")?;

    Ok(SignupOutcome::Created)
}

pub(super) async fn insert_verification_records(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    email: &str,
    config: &AuthConfig,
) -> Result<String> {
    // Generate a raw token for the email link and store only its hash.
    let token = generate_verification_token()?;
    let token_hash = hash_verification_token(&token);

    let query = r"
        INSERT INTO email_verification_tokens
            (user_id, token_hash, expires_at)
        VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 second'))
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    sqlx::query(query)
        .bind(user_id)
        .bind(token_hash)
        .bind(config.email_token_ttl_seconds())
        .execute(&mut **tx)
        .instrument(span)
        .await
        .context("failed to insert email verification token")?;

    let verify_url = build_verify_url(config.frontend_base_url(), &token);
    let payload_json = json!({
        "email": email,
        "verify_url": verify_url,
    });
    let payload_text =
        serde_json::to_string(&payload_json).context("failed to serialize email payload")?;

    let query = r"
        INSERT INTO email_outbox (to_email, template, payload_json)
        VALUES ($1, $2, $3::jsonb)
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    sqlx::query(query)
        .bind(email)
        .bind("verify_email")
        .bind(payload_text)
        .execute(&mut **tx)
        .instrument(span)
        .await
        .context("failed to insert email outbox row")?;

    Ok(token)
}

pub(super) async fn insert_session(
    pool: &PgPool,
    user_id: Uuid,
    ttl_seconds: i64,
) -> Result<String> {
    // Generate a random token, store only its hash, and return the raw value
    // so the caller can set the session cookie.
    let query = r"
        INSERT INTO user_sessions (user_id, session_hash, expires_at)
        VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 second'))
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );

    for _ in 0..3 {
        let token = generate_session_token()?;
        let token_hash = hash_session_token(&token);
        let result = sqlx::query(query)
            .bind(user_id)
            .bind(token_hash)
            .bind(ttl_seconds)
            .execute(pool)
            .instrument(span.clone())
            .await;

        match result {
            Ok(_) => return Ok(token),
            Err(err) if is_unique_violation(&err) => {}
            Err(err) => return Err(err).context("failed to insert session"),
        }
    }

    Err(anyhow!("failed to generate unique session token"))
}

pub(super) async fn lookup_session(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<SessionRecord>> {
    // Only accept active users and unexpired sessions.
    let query = r"
        SELECT users.id, users.email
        FROM user_sessions
        JOIN users ON users.id = user_sessions.user_id
        WHERE user_sessions.session_hash = $1
          AND user_sessions.expires_at > NOW()
          AND users.status = 'active'
        LIMIT 1
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(token_hash)
        .fetch_optional(pool)
        .instrument(span)
        .await
        .context("failed to lookup session")?;

    if row.is_none() {
        return Ok(None);
    }

    // Record activity for audit/visibility without extending the session TTL.
    let query = r"
        UPDATE user_sessions
        SET last_seen_at = NOW()
        WHERE session_hash = $1
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "UPDATE",
        db.statement = query
    );
    sqlx::query(query)
        .bind(token_hash)
        .execute(pool)
        .instrument(span)
        .await
        .context("failed to update session last_seen_at")?;

    Ok(row.map(|row| SessionRecord {
        user_id: row.get("id"),
        email: row.get("email"),
    }))
}

pub(super) async fn delete_session(pool: &PgPool, token_hash: &[u8]) -> Result<()> {
    // Logout is idempotent; it's fine if no rows are deleted.
    let query = "DELETE FROM user_sessions WHERE session_hash = $1";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "DELETE",
        db.statement = query
    );
    sqlx::query(query)
        .bind(token_hash)
        .execute(pool)
        .instrument(span)
        .await
        .context("failed to delete session")?;
    Ok(())
}

pub(super) async fn consume_verification_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_hash: &[u8],
) -> Result<bool> {
    // Mark the token consumed if still valid; then activate the user in the same transaction.
    let query = r"
        UPDATE email_verification_tokens
        SET consumed_at = NOW()
        WHERE token_hash = $1
          AND consumed_at IS NULL
          AND expires_at > NOW()
        RETURNING user_id
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "UPDATE",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(token_hash)
        .fetch_optional(&mut **tx)
        .instrument(span)
        .await
        .context("failed to consume verification token")?;

    let Some(row) = row else {
        return Ok(false);
    };

    let user_id: Uuid = row.get("user_id");
    let query = r"
        UPDATE users
        SET email_verified_at = NOW(),
            status = 'active',
            updated_at = NOW()
        WHERE id = $1
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "UPDATE",
        db.statement = query
    );
    sqlx::query(query)
        .bind(user_id)
        .execute(&mut **tx)
        .instrument(span)
        .await
        .context("failed to update user status")?;

    Ok(true)
}

pub(super) async fn lookup_email_by_token_hash(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_hash: &[u8],
) -> Result<Option<String>> {
    // Used for per-email rate limiting during verification.
    let query = r"
        SELECT users.email
        FROM email_verification_tokens
        JOIN users ON users.id = email_verification_tokens.user_id
        WHERE email_verification_tokens.token_hash = $1
        LIMIT 1
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(token_hash)
        .fetch_optional(&mut **tx)
        .instrument(span)
        .await
        .context("failed to lookup email for token")?;
    Ok(row.map(|row| row.get("email")))
}

pub(super) async fn enqueue_resend_verification(
    pool: &PgPool,
    email: &str,
    config: &AuthConfig,
) -> Result<ResendOutcome> {
    // Resend is intentionally opaque: callers always get 204 to avoid account probing.
    let mut tx = pool.begin().await.context("begin resend transaction")?;

    let query = r"
        SELECT id, email, status::text AS status
        FROM users
        WHERE email = $1
        LIMIT 1
    ";
    let span = tracing::info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    let row = sqlx::query(query)
        .bind(email)
        .fetch_optional(&mut *tx)
        .instrument(span)
        .await
        .context("failed to lookup user for resend")?;

    let Some(row) = row else {
        tx.commit().await.context("commit resend noop")?;
        return Ok(ResendOutcome::Noop);
    };

    let status: String = row.get("status");
    if status != "pending_verification" {
        tx.commit().await.context("commit resend noop")?;
        return Ok(ResendOutcome::Noop);
    }

    let user_id: Uuid = row.get("id");
    if resend_cooldown_active(&mut tx, user_id, config.resend_cooldown_seconds()).await? {
        tx.commit().await.context("commit resend cooldown")?;
        return Ok(ResendOutcome::Cooldown);
    }

    let email: String = row.get("email");
    let _ = insert_verification_records(&mut tx, user_id, &email, config).await?;
    tx.commit().await.context("commit resend enqueue")?;
    Ok(ResendOutcome::Queued)
}

async fn resend_cooldown_active(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    cooldown_seconds: i64,
) -> Result<bool> {
    // Cooldown prevents repeated resend requests from spamming the outbox.
    let query = r"
        SELECT 1
        FROM email_verification_tokens
        WHERE user_id = $1
          AND created_at > NOW() - ($2 * INTERVAL '1 second')
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
        .bind(cooldown_seconds)
        .fetch_optional(&mut **tx)
        .instrument(span)
        .await
        .context("failed to check resend cooldown")?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::{LoginRecord, ResendOutcome, SignupOutcome};
    use uuid::Uuid;

    #[test]
    fn signup_outcome_debug_names() {
        assert_eq!(format!("{:?}", SignupOutcome::Created), "Created");
        assert_eq!(format!("{:?}", SignupOutcome::Conflict), "Conflict");
    }

    #[test]
    fn resend_outcome_debug_names() {
        assert_eq!(format!("{:?}", ResendOutcome::Queued), "Queued");
        assert_eq!(format!("{:?}", ResendOutcome::Cooldown), "Cooldown");
        assert_eq!(format!("{:?}", ResendOutcome::Noop), "Noop");
    }

    #[test]
    fn login_record_holds_values() {
        let record = LoginRecord {
            user_id: Uuid::nil(),
            status: "active".to_string(),
            opaque_record: vec![1, 2, 3],
        };
        assert_eq!(record.user_id, Uuid::nil());
        assert_eq!(record.status, "active");
        assert_eq!(record.opaque_record, vec![1, 2, 3]);
    }
}
