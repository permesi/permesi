use crate::{cli::globals::GlobalArgs, totp::models::TotpDek};
use anyhow::{Context, Result, anyhow};
use base64ct::{Base64, Encoding};
use http::Method;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing::{error, info, instrument, warn};
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

    fn vault_token(&self) -> Option<&str> {
        self.globals
            .vault_transport
            .is_tcp()
            .then(|| self.globals.vault_token.expose_secret())
    }

    async fn unwrap_dek(&self, wrapped_dek: &str) -> Result<Vec<u8>> {
        let mount = self.globals.vault_transit_mount.trim_matches('/');
        let path = format!("/v1/{mount}/decrypt/totp");

        let payload = json!({
            "ciphertext": wrapped_dek,
        });

        let response = self
            .globals
            .vault_transport
            .request_json(Method::POST, &path, self.vault_token(), Some(&payload))
            .await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Vault decrypt failed: {} - {:?}",
                response.status,
                response.body
            ));
        }

        let plaintext_b64 = response
            .body
            .get("data")
            .and_then(|d| d.get("plaintext"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("No plaintext in Vault response"))?;

        Ok(Base64::decode_vec(plaintext_b64)?)
    }

    async fn generate_datakey(&self) -> Result<(String, String)> {
        let mount = self.globals.vault_transit_mount.trim_matches('/');
        let path = format!("/v1/{mount}/datakey/plaintext/totp");
        let response = self
            .globals
            .vault_transport
            .request_json(Method::POST, &path, self.vault_token(), None)
            .await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "Vault datakey gen failed: {} - {:?}",
                response.status,
                response.body
            ));
        }

        let data = response
            .body
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::DekManager;
    use crate::cli::globals::GlobalArgs;
    use anyhow::Result;
    use http::{Method, Request, Response, StatusCode};
    use http_body_util::Full;
    use hyper::{body::Bytes, service::service_fn};
    use hyper_util::rt::TokioIo;
    use serde_json::json;
    use std::path::PathBuf;
    use tokio::net::UnixListener;
    use vault_client::{VaultTarget, VaultTransport};

    async fn mock_agent_service(
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let path = req.uri().path();
        let method = req.method();

        if method == Method::POST && path == "/v1/transit/permesi/datakey/plaintext/totp" {
            let body = json!({
                "data": {
                    "ciphertext": "vault:v1:ciphertext",
                    "plaintext": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
                }
            });
            return Ok(Response::new(Full::new(Bytes::from(
                serde_json::to_vec(&body).expect("failed to serialize json"),
            ))));
        }

        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from(r#"{"errors":["path not found"]}"#)))
            .expect("failed to build response"))
    }

    struct SocketGuard {
        path: PathBuf,
    }

    impl Drop for SocketGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[tokio::test]
    async fn generate_datakey_supports_agent_socket_mode() -> Result<()> {
        let socket_path = std::env::temp_dir().join(format!(
            "vault-agent-dek-manager-{}.sock",
            uuid::Uuid::new_v4()
        ));
        let _guard = SocketGuard {
            path: socket_path.clone(),
        };

        let listener = UnixListener::bind(&socket_path)?;
        let server_handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service_fn(mock_agent_service))
                        .await;
                });
            }
        });

        let target = VaultTarget::parse(&format!("unix://{}", socket_path.display()))?;
        let transport = VaultTransport::from_target("test-suite", target)?;
        let mut globals = GlobalArgs::new(socket_path.display().to_string(), transport);
        globals.vault_transit_mount = "transit/permesi".to_string();

        let manager = DekManager::new(globals);
        let (ciphertext, plaintext) = manager.generate_datakey().await?;

        assert_eq!(ciphertext, "vault:v1:ciphertext");
        assert_eq!(plaintext, "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=");

        server_handle.abort();
        Ok(())
    }
}
