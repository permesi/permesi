use crate::totp::{crypto, dek_manager::DekManager, repo::TotpRepo};
use anyhow::{Context, Result, anyhow};
use sqlx::PgPool;
use totp_rs::{Algorithm, Builder, Secret, Totp};
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
        let secret = Secret::generate();
        let secret_bytes = secret.as_bytes().to_vec();

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
        let totp = build_totp(secret_bytes, &self.issuer, user_email)?;

        let qr = totp
            .to_qr_base64()
            .map_err(|e| anyhow!("QR gen error: {e}"))?; // "data:image/png;base64,..."
        let qr = format!("data:image/png;base64,{qr}");
        let secret_str = totp.secret().to_base32();

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

        let totp = build_totp(secret_bytes, &self.issuer, "user")?;

        let valid = check_current_totp(&totp, code)?;

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

        let totp = build_totp(secret_bytes, &self.issuer, "user")?;

        let valid = check_current_totp(&totp, code)?;

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

/// Builds the RFC 6238 configuration shared by enrollment and verification.
/// The SHA-1 algorithm, six digits, one-step skew, and 30-second period preserve
/// compatibility with already-enrolled authenticators.
fn build_totp(secret: Vec<u8>, issuer: &str, account_name: &str) -> Result<Totp> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(issuer))
        .with_account_name(account_name)
        .build()
        .map_err(|error| anyhow!("TOTP init error: {error}"))
}

/// Checks a TOTP code against the current Unix time without relying on the
/// library's panicking system-clock convenience method.
fn check_current_totp(totp: &Totp, code: &str) -> Result<bool> {
    let unix_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    Ok(totp.check(code, unix_time).is_some())
}
