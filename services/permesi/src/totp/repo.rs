use crate::totp::models::TotpCredential;
use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;

pub struct TotpRepo;

impl TotpRepo {
    /// Creates a new TOTP credential in unconfirmed state.
    ///
    /// # Errors
    /// Returns an error if database insertion fails.
    pub async fn create_credential(
        pool: &PgPool,
        credential_id: Uuid,
        user_id: Uuid,
        dek_id: Uuid,
        seed_ciphertext: &[u8],
        label: Option<&str>,
    ) -> Result<()> {
        let mut tx = pool.begin().await?;

        // Remove any existing unconfirmed attempts for this user to keep the table clean.
        sqlx::query("DELETE FROM totp_credentials WHERE user_id = $1 AND confirmed_at IS NULL")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r"
            INSERT INTO totp_credentials 
            (credential_id, user_id, dek_id, seed_ciphertext, label, algo, digits, period)
            VALUES ($1, $2, $3, $4, $5, 'SHA1', 6, 30)
            ",
        )
        .bind(credential_id)
        .bind(user_id)
        .bind(dek_id)
        .bind(seed_ciphertext)
        .bind(label)
        .execute(&mut *tx)
        .await
        .context("Failed to insert TOTP credential")?;

        tx.commit().await?;

        Ok(())
    }

    /// Gets a credential by ID.
    ///
    /// # Errors
    /// Returns an error if database query fails.
    pub async fn get_credential(
        pool: &PgPool,
        credential_id: Uuid,
    ) -> Result<Option<TotpCredential>> {
        sqlx::query_as::<_, TotpCredential>(
            "SELECT * FROM totp_credentials WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_optional(pool)
        .await
        .context("Failed to fetch credential")
    }

    /// Gets the active (confirmed, not disabled) credential for a user.
    ///
    /// # Errors
    /// Returns an error if database query fails.
    pub async fn get_active_credential(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Option<TotpCredential>> {
        sqlx::query_as::<_, TotpCredential>(
            r"
            SELECT * FROM totp_credentials 
            WHERE user_id = $1 
              AND confirmed_at IS NOT NULL 
            ORDER BY created_at DESC
            LIMIT 1
            ",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .context("Failed to fetch active credential")
    }

    /// Marks a credential as confirmed and disables all other credentials for the user.
    ///
    /// # Errors
    /// Returns an error if database update fails.
    pub async fn confirm_credential(
        pool: &PgPool,
        user_id: Uuid,
        credential_id: Uuid,
    ) -> Result<()> {
        let mut tx = pool.begin().await?;

        // 1. Hard delete all other credentials for this user (confirmed or otherwise)
        sqlx::query("DELETE FROM totp_credentials WHERE user_id = $1 AND credential_id != $2")
            .bind(user_id)
            .bind(credential_id)
            .execute(&mut *tx)
            .await?;

        // 2. Confirm the target credential
        sqlx::query("UPDATE totp_credentials SET confirmed_at = NOW() WHERE credential_id = $1")
            .bind(credential_id)
            .execute(&mut *tx)
            .await
            .context("Failed to confirm credential")?;

        tx.commit().await?;
        Ok(())
    }

    /// Updates last used timestamp.
    ///
    /// # Errors
    /// Returns an error if database update fails.
    pub async fn touch_last_used(pool: &PgPool, credential_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE totp_credentials SET last_used_at = NOW() WHERE credential_id = $1")
            .bind(credential_id)
            .execute(pool)
            .await
            .context("Failed to touch last_used_at")?;
        Ok(())
    }

    /// Hard deletes all TOTP credentials for a user.
    ///
    /// # Errors
    /// Returns an error if database execution fails.
    pub async fn disable_active_credentials(pool: &PgPool, user_id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM totp_credentials WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await
            .context("Failed to delete TOTP credentials")?;
        Ok(())
    }

    /// Logs a TOTP audit action.
    ///
    /// # Errors
    /// Returns an error if database insertion fails.
    pub async fn log_audit(
        pool: &PgPool,
        user_id: Uuid,
        credential_id: Option<Uuid>,
        action: &str,
        ip: Option<&str>,
        ua: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO totp_audit_log (user_id, credential_id, action, ip_address, user_agent)
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
        .context("Failed to write audit log")?;
        Ok(())
    }
}
