//! Storage helpers for MFA state and recovery codes.
//!
//! NOTE: Schema is draft-only; migrations will be added later.

use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::MfaState;

/// MFA state and active factor data for a user.
#[derive(Clone, Debug)]
pub struct MfaStateRecord {
    pub state: MfaState,
    pub recovery_batch_id: Option<Uuid>,
}

/// Load the MFA state for a user (returns `None` when no state is recorded).
pub async fn load_mfa_state(pool: &PgPool, user_id: Uuid) -> Result<Option<MfaStateRecord>> {
    let query = r"
        SELECT state::text AS state, recovery_batch_id
        FROM user_mfa_state
        WHERE user_id = $1
        LIMIT 1
    ";
    let row = sqlx::query(query)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .context("failed to load MFA state")?;
    Ok(row.map(|row| {
        let state_text: String = row.get("state");
        let state = MfaState::from_str(&state_text).unwrap_or(MfaState::Disabled);
        MfaStateRecord {
            state,
            recovery_batch_id: row.get("recovery_batch_id"),
        }
    }))
}

/// Upsert MFA state and active recovery batch for a user.
pub async fn upsert_mfa_state(
    pool: &PgPool,
    user_id: Uuid,
    state: MfaState,
    recovery_batch_id: Option<Uuid>,
) -> Result<()> {
    let query = r"
        INSERT INTO user_mfa_state (user_id, state, recovery_batch_id, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (user_id) DO UPDATE
        SET state = $2,
            recovery_batch_id = $3,
            updated_at = NOW()
    ";
    sqlx::query(query)
        .bind(user_id)
        .bind(state.as_str())
        .bind(recovery_batch_id)
        .execute(pool)
        .await
        .context("failed to upsert MFA state")?;
    Ok(())
}

/// Insert a batch of recovery code hashes for a user.
pub async fn insert_recovery_codes(
    pool: &PgPool,
    user_id: Uuid,
    batch_id: Uuid,
    code_hashes: &[String],
) -> Result<()> {
    let query = r"
        INSERT INTO user_mfa_recovery_codes (user_id, batch_id, code_hash)
        VALUES ($1, $2, $3)
    ";
    for hash in code_hashes {
        sqlx::query(query)
            .bind(user_id)
            .bind(batch_id)
            .bind(hash)
            .execute(pool)
            .await
            .context("failed to insert recovery code")?;
    }
    Ok(())
}

/// List recovery code hashes for the active batch.
pub async fn list_recovery_code_hashes(
    pool: &PgPool,
    user_id: Uuid,
    batch_id: Uuid,
) -> Result<Vec<String>> {
    let query = r"
        SELECT code_hash
        FROM user_mfa_recovery_codes
        WHERE user_id = $1
          AND batch_id = $2
          AND used_at IS NULL
    ";
    let rows = sqlx::query(query)
        .bind(user_id)
        .bind(batch_id)
        .fetch_all(pool)
        .await
        .context("failed to list recovery codes")?;
    Ok(rows
        .into_iter()
        .map(|row| row.get::<String, _>("code_hash"))
        .collect())
}

/// Mark a recovery code as used (atomic).
pub async fn consume_recovery_code_hash(
    pool: &PgPool,
    user_id: Uuid,
    batch_id: Uuid,
    code_hash: &str,
) -> Result<bool> {
    let query = r"
        UPDATE user_mfa_recovery_codes
        SET used_at = NOW()
        WHERE user_id = $1
          AND batch_id = $2
          AND code_hash = $3
          AND used_at IS NULL
        RETURNING user_id
    ";
    let row = sqlx::query(query)
        .bind(user_id)
        .bind(batch_id)
        .bind(code_hash)
        .fetch_optional(pool)
        .await
        .context("failed to consume recovery code")?;
    Ok(row.is_some())
}

/// Delete all full sessions for a user.
pub async fn delete_full_sessions(pool: &PgPool, user_id: Uuid) -> Result<()> {
    let query = "DELETE FROM user_sessions WHERE user_id = $1";
    sqlx::query(query)
        .bind(user_id)
        .execute(pool)
        .await
        .context("failed to delete full sessions")?;
    Ok(())
}

/// Delete all MFA challenge sessions for a user.
pub async fn delete_mfa_challenge_sessions(pool: &PgPool, user_id: Uuid) -> Result<()> {
    let query = "DELETE FROM user_mfa_challenge_sessions WHERE user_id = $1";
    sqlx::query(query)
        .bind(user_id)
        .execute(pool)
        .await
        .context("failed to delete MFA challenge sessions")?;
    Ok(())
}
