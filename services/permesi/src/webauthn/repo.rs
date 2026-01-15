use crate::webauthn::models::SecurityKey;
use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

pub struct SecurityKeyRepo;

impl SecurityKeyRepo {
    /// Saves a new security key.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn create_key(
        pool: &PgPool,
        user_id: Uuid,
        credential_id: &[u8],
        public_key: &[u8],
        label: &str,
        sign_count: i64,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO security_keys (credential_id, user_id, label, public_key, sign_count)
            VALUES ($1, $2, $3, $4, $5)
            ",
        )
        .bind(credential_id)
        .bind(user_id)
        .bind(label)
        .bind(public_key)
        .bind(sign_count)
        .execute(pool)
        .await
        .context("Failed to insert security key")?;

        Ok(())
    }

    /// Lists all keys for a user.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn list_user_keys(pool: &PgPool, user_id: Uuid) -> Result<Vec<SecurityKey>> {
        sqlx::query_as::<_, SecurityKey>(
            "SELECT * FROM security_keys WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .context("Failed to list security keys")
    }

    /// Gets a single key by its credential ID.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn get_key(pool: &PgPool, credential_id: &[u8]) -> Result<Option<SecurityKey>> {
        sqlx::query_as::<_, SecurityKey>("SELECT * FROM security_keys WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_optional(pool)
            .await
            .context("Failed to fetch security key")
    }

    /// Updates the sign count and last used timestamp for a key.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn update_key_usage(
        pool: &PgPool,
        credential_id: &[u8],
        sign_count: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE security_keys SET sign_count = $1, last_used_at = NOW() WHERE credential_id = $2",
        )
        .bind(sign_count)
        .bind(credential_id)
        .execute(pool)
        .await
        .context("Failed to update security key usage")?;
        Ok(())
    }

    /// Deletes a key by credential ID and user ID.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn delete_key(pool: &PgPool, user_id: Uuid, credential_id: &[u8]) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM security_keys WHERE user_id = $1 AND credential_id = $2")
                .bind(user_id)
                .bind(credential_id)
                .execute(pool)
                .await
                .context("Failed to delete security key")?;
        Ok(result.rows_affected() > 0)
    }

    /// Logs an action.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn log_audit(
        pool: &PgPool,
        user_id: Uuid,
        credential_id: Option<&[u8]>,
        action: &str,
        ip: Option<&str>,
        ua: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO security_key_audit_log (user_id, credential_id, action, ip_address, user_agent)
            VALUES ($1, $2, $3, $4::inet, $5)
            ",
        )
        .bind(user_id)
        .bind(credential_id)
        .bind(action)
        .bind(ip)
        .bind(ua)
        .execute(pool)
        .await
        .context("Failed to write security key audit log")?;
        Ok(())
    }
}
