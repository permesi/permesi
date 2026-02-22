use crate::{cli::globals::GlobalArgs, totp::models::TotpDek, vault};
use anyhow::{Context, Result, anyhow};
use base64ct::{Base64, Encoding};
use reqwest::Client;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing::{Instrument, error, info, info_span, instrument, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct DekManager {
    // In-memory cache of decrypted DEKs: dek_id -> plaintext_bytes
    cache: Arc<RwLock<HashMap<Uuid, Vec<u8>>>>,
    globals: GlobalArgs,
}

impl DekManager {
    #[must_use]
    pub fn new(globals: GlobalArgs) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            globals,
        }
    }

    /// Loads all active and decrypt-only DEKs from the database, unwraps them via Vault,
    /// and populates the in-memory cache.
    ///
    /// # Errors
    /// Returns an error if database fetch fails or if the cache lock is poisoned.
    #[instrument(skip(self, pool))]
    pub async fn init(&self, pool: &PgPool) -> Result<()> {
        info!("Initializing TOTP DEK manager...");

        // 1. Fetch DEKs from DB
        let mut deks = sqlx::query_as::<_, TotpDek>(
            "SELECT * FROM totp_deks WHERE status IN ('active', 'decrypt_only')",
        )
        .fetch_all(pool)
        .await
        .context("Failed to fetch DEKs from database")?;

        if deks.is_empty() {
            info!("No TOTP DEKs found. Bootstrapping initial DEK...");
            match self.rotate(pool).await {
                Ok(_) => {
                    // rotate updates the cache, so we are good.
                    // But we might want to reload purely for sanity, or just return.
                    // rotate updates cache directly.
                    return Ok(());
                }
                Err(e) => {
                    warn!("Bootstrap rotation failed: {e}. Checking if another instance won...");
                    // Try fetching again
                    deks = sqlx::query_as::<_, TotpDek>(
                        "SELECT * FROM totp_deks WHERE status IN ('active', 'decrypt_only')",
                    )
                    .fetch_all(pool)
                    .await
                    .context("Failed to fetch DEKs from database (retry)")?;

                    if deks.is_empty() {
                        // Still empty? Then we really failed.
                        // We return error here so startup might fail or just log error.
                        // api::new logs error.
                        return Err(anyhow!(
                            "Failed to bootstrap TOTP DEK and none found in DB: {e}"
                        ));
                    }
                }
            }
        }

        // 2. Unwrap each DEK (without holding the lock)
        let mut unwrapped = HashMap::new();
        for dek in deks {
            match self.unwrap_dek(&dek.wrapped_dek).await {
                Ok(plaintext) => {
                    unwrapped.insert(dek.dek_id, plaintext);
                }
                Err(e) => {
                    error!(dek_id = ?dek.dek_id, error = ?e, "Failed to unwrap DEK. Ignoring.");
                }
            }
        }

        // 3. Populate the cache
        {
            let mut cache = self.cache.write().map_err(|_| anyhow!("Poisoned lock"))?;
            let loaded_count = unwrapped.len();
            cache.extend(unwrapped);
            info!("Loaded {} TOTP DEKs into memory.", loaded_count);
        }

        Ok(())
    }

    /// Retrieves a DEK from memory.
    #[must_use]
    pub fn get_dek(&self, dek_id: Uuid) -> Option<Vec<u8>> {
        self.cache.read().ok()?.get(&dek_id).cloned()
    }

    /// Fetches the currently active DEK ID from the database.
    ///
    /// # Errors
    /// Returns an error if no active DEK is found or if database query fails.
    pub async fn get_active_dek_id(&self, pool: &PgPool) -> Result<Uuid> {
        let rec = sqlx::query("SELECT dek_id FROM totp_deks WHERE status = 'active'")
            .fetch_optional(pool)
            .await?;

        match rec {
            Some(row) => {
                let id: Uuid = row.try_get("dek_id")?;
                Ok(id)
            }
            None => Err(anyhow!("No active TOTP DEK found")),
        }
    }

    /// Rotates the DEK: generates a new one, marks it active, demotes the old one.
    ///
    /// # Errors
    /// Returns an error if Vault key generation fails or if database transaction fails.
    #[instrument(skip(self, pool))]
    pub async fn rotate(&self, pool: &PgPool) -> Result<Uuid> {
        info!("Rotating TOTP DEK...");

        // 1. Generate new datakey from Vault
        let (ciphertext, plaintext) = self.generate_datakey().await?;
        let plaintext_bytes = Base64::decode_vec(&plaintext)?;
        let new_dek_id = Uuid::new_v4();

        // 2. Transaction: Demote old active -> decrypt_only, Insert new active
        let mut tx = pool.begin().await?;

        // Demote current active
        sqlx::query(
            "UPDATE totp_deks SET status = 'decrypt_only', rotated_at = NOW() WHERE status = 'active'"
        )
        .execute(&mut *tx)
        .await?;

        // Insert new
        let transit_mount = self.globals.vault_transit_mount.trim_matches('/');
        sqlx::query(
            r"
            INSERT INTO totp_deks (dek_id, status, wrapped_dek, kek_mount, kek_key)
            VALUES ($1, 'active', $2, $3, 'totp')
            ",
        )
        .bind(new_dek_id)
        .bind(ciphertext)
        .bind(transit_mount)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // 3. Update cache
        {
            let mut cache = self.cache.write().map_err(|_| anyhow!("Poisoned lock"))?;
            cache.insert(new_dek_id, plaintext_bytes);
        }

        info!(new_dek_id = ?new_dek_id, "TOTP DEK rotated successfully.");
        Ok(new_dek_id)
    }

    // --- Vault Helpers ---

    async fn unwrap_dek(&self, wrapped_dek: &str) -> Result<Vec<u8>> {
        let client = Client::builder()
            .user_agent(crate::APP_USER_AGENT)
            .build()?;

        let url = vault::endpoint_url(
            &self.globals.vault_url,
            &format!(
                "/v1/{}/decrypt/totp",
                self.globals.vault_transit_mount.trim_matches('/')
            ),
        )?;

        let payload = json!({
            "ciphertext": wrapped_dek,
        });

        let span = info_span!("vault.transit.decrypt_dek", http.method = "POST", url = %url);
        let response = client
            .post(&url)
            .header("X-Vault-Token", self.globals.vault_token.expose_secret())
            .json(&payload)
            .send()
            .instrument(span)
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body: Value = response.json().await.unwrap_or_default();
            return Err(anyhow!("Vault decrypt failed: {status} - {body:?}"));
        }

        let body: Value = response.json().await?;
        let plaintext_b64 = body
            .get("data")
            .and_then(|d| d.get("plaintext"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("No plaintext in Vault response"))?;

        Ok(Base64::decode_vec(plaintext_b64)?)
    }

    async fn generate_datakey(&self) -> Result<(String, String)> {
        let client = Client::builder()
            .user_agent(crate::APP_USER_AGENT)
            .build()?;

        let url = vault::endpoint_url(
            &self.globals.vault_url,
            &format!(
                "/v1/{}/datakey/plaintext/totp",
                self.globals.vault_transit_mount.trim_matches('/')
            ),
        )?;

        let span = info_span!("vault.transit.generate_datakey", http.method = "POST", url = %url);
        let response = client
            .post(&url)
            .header("X-Vault-Token", self.globals.vault_token.expose_secret())
            .send()
            .instrument(span)
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body: Value = response.json().await.unwrap_or_default();
            return Err(anyhow!("Vault datakey gen failed: {status} - {body:?}"));
        }

        let body: Value = response.json().await?;
        let data = body
            .get("data")
            .ok_or_else(|| anyhow!("No data in response"))?;

        let ciphertext = data
            .get("ciphertext")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("No ciphertext in response"))?
            .to_string();

        let plaintext = data
            .get("plaintext")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("No plaintext in response"))?
            .to_string();

        Ok((ciphertext, plaintext))
    }
}
