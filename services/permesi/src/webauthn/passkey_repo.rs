use crate::webauthn::models::PasskeyCredential;
use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PasskeyRepo;

impl PasskeyRepo {
    /// Saves a new passkey credential.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn create_passkey(
        pool: &PgPool,
        user_id: Uuid,
        credential_id: &[u8],
        passkey_data: &[u8],
        label: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO passkeys (credential_id, user_id, label, passkey_data)
            VALUES ($1, $2, $3, $4)
            ",
        )
        .bind(credential_id)
        .bind(user_id)
        .bind(label)
        .bind(passkey_data)
        .execute(pool)
        .await
        .context("Failed to insert passkey")?;

        Ok(())
    }

    /// Lists all passkeys for a user.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn list_user_passkeys(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<PasskeyCredential>> {
        sqlx::query_as::<_, PasskeyCredential>(
            "SELECT * FROM passkeys WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .context("Failed to list passkeys")
    }

    /// Gets a single passkey by credential ID.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn get_passkey(
        pool: &PgPool,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>> {
        sqlx::query_as::<_, PasskeyCredential>("SELECT * FROM passkeys WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_optional(pool)
            .await
            .context("Failed to fetch passkey")
    }

    /// Updates the serialized passkey and last-used timestamp.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn update_passkey_usage(
        pool: &PgPool,
        credential_id: &[u8],
        passkey_data: &[u8],
    ) -> Result<()> {
        sqlx::query(
            r"
            UPDATE passkeys
            SET passkey_data = $1, last_used_at = NOW()
            WHERE credential_id = $2
            ",
        )
        .bind(passkey_data)
        .bind(credential_id)
        .execute(pool)
        .await
        .context("Failed to update passkey usage")?;

        Ok(())
    }

    /// Updates only the last-used timestamp.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn touch_passkey(pool: &PgPool, credential_id: &[u8]) -> Result<()> {
        sqlx::query("UPDATE passkeys SET last_used_at = NOW() WHERE credential_id = $1")
            .bind(credential_id)
            .execute(pool)
            .await
            .context("Failed to update passkey last_used_at")?;
        Ok(())
    }

    /// Deletes a passkey by credential ID and user ID.
    ///
    /// # Errors
    /// Returns error if the database query fails.
    pub async fn delete_passkey(
        pool: &PgPool,
        user_id: Uuid,
        credential_id: &[u8],
    ) -> Result<bool> {
        let result = sqlx::query("DELETE FROM passkeys WHERE user_id = $1 AND credential_id = $2")
            .bind(user_id)
            .bind(credential_id)
            .execute(pool)
            .await
            .context("Failed to delete passkey")?;
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
            INSERT INTO passkey_audit_log (user_id, credential_id, action, ip_address, user_agent)
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
        .context("Failed to write passkey audit log")?;
        Ok(())
    }
}
