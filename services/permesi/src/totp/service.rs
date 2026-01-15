use crate::totp::{crypto, dek_manager::DekManager, repo::TotpRepo};
use anyhow::{Result, anyhow};
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

#[derive(Clone)]
pub struct TotpService {
    dek_manager: DekManager,
    pool: PgPool,
    issuer: String,
}

impl TotpService {
    #[must_use]
    pub fn new(dek_manager: DekManager, pool: PgPool, issuer: String) -> Self {
        Self {
            dek_manager,
            pool,
            issuer,
        }
    }

    /// Begins enrollment: generates a secret, encrypts it, stores it, and returns the plaintext/QR for the user.
    ///
    /// Returns: (`secret_base32`, `qr_code_data_url`, `credential_id`)
    ///
    /// # Errors
    /// Returns an error if secret generation, encryption, or database insertion fails.
    pub async fn enroll_begin(
        &self,
        user_id: Uuid,
        user_email: &str,
        label: Option<String>,
    ) -> Result<(String, String, Uuid)> {
        // 1. Generate new random secret
        let secret = Secret::generate_secret();
        let secret_bytes = secret
            .to_bytes()
            .map_err(|e| anyhow!("Secret gen error: {e}"))?;

        // 2. Get active DEK
        let dek_id = self.dek_manager.get_active_dek_id(&self.pool).await?;
        let dek_bytes = self
            .dek_manager
            .get_dek(dek_id)
            .ok_or_else(|| anyhow!("Active DEK not found in cache (try waiting/refreshing)"))?;

        // 3. Encrypt secret (binding AAD to ID)
        let credential_id = Uuid::new_v4();

        let ciphertext =
            crypto::encrypt_seed(&dek_bytes, &secret_bytes, None, user_id, credential_id)?;

        // 4. Store in DB
        TotpRepo::create_credential(
            &self.pool,
            credential_id,
            user_id,
            dek_id,
            &ciphertext,
            label.as_deref(),
        )
        .await?;

        // 5. Generate QR (base64 data URL)
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some(self.issuer.clone()),
            user_email.to_string(),
        )
        .map_err(|e| anyhow!("TOTP init error: {e}"))?;

        let qr = totp
            .get_qr_base64()
            .map_err(|e| anyhow!("QR gen error: {e}"))?; // "data:image/png;base64,..."
        let qr = format!("data:image/png;base64,{qr}");
        let secret_str = totp.get_secret_base32();

        Ok((secret_str, qr, credential_id))
    }

    /// Confirms enrollment by verifying the first code.
    ///
    /// # Errors
    /// Returns an error if the credential is not found, does not belong to the user,
    /// or if decryption/database update fails.
    pub async fn enroll_confirm(
        &self,
        user_id: Uuid,
        credential_id: Uuid,
        code: &str,
        ip: Option<&str>,
        ua: Option<&str>,
    ) -> Result<bool> {
        let cred = TotpRepo::get_credential(&self.pool, credential_id)
            .await?
            .ok_or_else(|| anyhow!("Credential not found"))?;

        if cred.user_id != user_id {
            return Err(anyhow!("Credential does not belong to user"));
        }

        if cred.confirmed_at.is_some() {
            return Ok(true);
        }

        let dek_bytes = self
            .dek_manager
            .get_dek(cred.dek_id)
            .ok_or_else(|| anyhow!("DEK not available (rotated out?)"))?;

        let secret_bytes = crypto::decrypt_seed(
            &dek_bytes,
            &cred.seed_ciphertext,
            None,
            user_id,
            credential_id,
        )?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some(self.issuer.clone()),
            "user".to_string(), // label doesn't matter for check
        )
        .map_err(|e| anyhow!("TOTP init error: {e}"))?;

        let valid = totp.check_current(code).unwrap_or(false);

        if valid {
            TotpRepo::confirm_credential(&self.pool, user_id, credential_id).await?;
            TotpRepo::log_audit(&self.pool, user_id, Some(credential_id), "confirm", ip, ua)
                .await?;
            Ok(true)
        } else {
            TotpRepo::log_audit(
                &self.pool,
                user_id,
                Some(credential_id),
                "confirm_fail",
                ip,
                ua,
            )
            .await?;
            Ok(false)
        }
    }

    /// Verifies a code against the active confirmed credential.
    ///
    /// # Errors
    /// Returns an error if database fetch, decryption, or audit logging fails.
    pub async fn verify(
        &self,
        user_id: Uuid,
        code: &str,
        ip: Option<&str>,
        ua: Option<&str>,
    ) -> Result<bool> {
        let Some(cred) = TotpRepo::get_active_credential(&self.pool, user_id).await? else {
            return Ok(false);
        };

        let dek_bytes = self
            .dek_manager
            .get_dek(cred.dek_id)
            .ok_or_else(|| anyhow!("DEK not available"))?;

        let secret_bytes = crypto::decrypt_seed(
            &dek_bytes,
            &cred.seed_ciphertext,
            None,
            user_id,
            cred.credential_id,
        )?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some(self.issuer.clone()),
            "user".to_string(),
        )
        .map_err(|e| anyhow!("TOTP init error: {e}"))?;

        let valid = totp.check_current(code).unwrap_or(false);

        if valid {
            TotpRepo::touch_last_used(&self.pool, cred.credential_id).await?;
            TotpRepo::log_audit(
                &self.pool,
                user_id,
                Some(cred.credential_id),
                "verify_success",
                ip,
                ua,
            )
            .await?;
            Ok(true)
        } else {
            TotpRepo::log_audit(
                &self.pool,
                user_id,
                Some(cred.credential_id),
                "verify_failure",
                ip,
                ua,
            )
            .await?;
            Ok(false)
        }
    }
}
