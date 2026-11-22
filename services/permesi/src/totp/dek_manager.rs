use crate::{
    cli::globals::GlobalArgs,
    totp::models::{TotpDek, TotpDekStatus},
};
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

    /// Loads all active and decrypt-only DEKs from the database, unwraps them via OpenBao,
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
                        // Still empty: no replica bootstrapped a key. Startup fails.
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
                // New enrolments encrypt under the active DEK, and the cache is
                // never reloaded: starting without it would leave this replica
                // unable to enrol TOTP until restarted. Retired keys only affect
                // the credentials still wrapped by them, so those are skipped.
                Err(e) if dek.status == TotpDekStatus::Active => {
                    return Err(e.context("Failed to unwrap the active TOTP DEK"));
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
    pub async fn get_active_dek_id<'a>(
        &self,
        executor: impl sqlx::Executor<'a, Database = sqlx::Postgres>,
    ) -> Result<Uuid> {
        let rec = sqlx::query("SELECT dek_id FROM totp_deks WHERE status = 'active'")
            .fetch_optional(executor)
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
    /// Returns an error if OpenBao key generation fails or if database transaction fails.
    #[instrument(skip(self, pool))]
    pub async fn rotate(&self, pool: &PgPool) -> Result<Uuid> {
        info!("Rotating TOTP DEK...");

        // 1. Generate new datakey from OpenBao
        let (ciphertext, plaintext) = self.generate_datakey().await?;
        let plaintext_bytes = Base64::decode_vec(&plaintext)?;
        let new_dek_id = Uuid::new_v4();

        // 2. Transaction: Demote old active -> decrypt_only, Insert new active
        let mut tx = service_utils::database::begin(pool).await?;

        // Demote current active
        sqlx::query(
            "UPDATE totp_deks SET status = 'decrypt_only', rotated_at = NOW() WHERE status = 'active'"
        )
        .execute(&mut *tx)
        .await?;

        // Insert new
        let transit_mount = self.globals.openbao_transit_mount.trim_matches('/');
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

    // --- OpenBao Helpers ---

    fn openbao_token(&self) -> Option<&str> {
        self.globals
            .openbao_transport
            .is_tcp()
            .then(|| self.globals.openbao_token.expose_secret())
    }

    async fn unwrap_dek(&self, wrapped_dek: &str) -> Result<Vec<u8>> {
        let mount = self.globals.openbao_transit_mount.trim_matches('/');
        let path = format!("/v1/{mount}/decrypt/totp");

        let payload = json!({
            "ciphertext": wrapped_dek,
        });

        let response = self
            .globals
            .openbao_transport
            .request_json(Method::POST, &path, self.openbao_token(), Some(&payload))
            .await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "OpenBao decrypt failed: {} - {:?}",
                response.status,
                response.body
            ));
        }

        let plaintext_b64 = response
            .body
            .get("data")
            .and_then(|d| d.get("plaintext"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("No plaintext in OpenBao response"))?;

        Ok(Base64::decode_vec(plaintext_b64)?)
    }

    async fn generate_datakey(&self) -> Result<(String, String)> {
        let mount = self.globals.openbao_transit_mount.trim_matches('/');
        let path = format!("/v1/{mount}/datakey/plaintext/totp");
        let response = self
            .globals
            .openbao_transport
            .request_json(Method::POST, &path, self.openbao_token(), None)
            .await?;

        if !response.status.is_success() {
            return Err(anyhow!(
                "OpenBao datakey gen failed: {} - {:?}",
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
    use openbao_client::{OpenBaoTarget, OpenBaoTransport};
    use serde_json::json;
    use std::path::PathBuf;
    use tokio::net::UnixListener;

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
            "openbao-agent-dek-manager-{}.sock",
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

        let target = OpenBaoTarget::parse(&format!("unix://{}", socket_path.display()))?;
        let transport = OpenBaoTransport::from_target("test-suite", target)?;
        let mut globals = GlobalArgs::new(socket_path.display().to_string(), transport);
        globals.openbao_transit_mount = "transit/permesi".to_string();

        let manager = DekManager::new(globals);
        let (ciphertext, plaintext) = manager.generate_datakey().await?;

        assert_eq!(ciphertext, "vault:v1:ciphertext");
        assert_eq!(plaintext, "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=");

        server_handle.abort();
        Ok(())
    }

    /// Runs `init` against a real schema with one stored key per given status. The
    /// mock transit unwraps only ciphertexts ending in `good`.
    async fn init_with_keys(keys: &[(&str, &str)]) -> Result<Option<Result<usize>>> {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_json, method, path},
        };
        if test_support::runtime::ensure_container_runtime().is_err() {
            eprintln!("Skipping integration test: no container runtime");
            return Ok(None);
        }
        let postgres = test_support::postgres::PostgresContainer::start("bridge").await?;
        postgres.wait_until_ready().await?;
        let pool = sqlx::PgPool::connect(&postgres.admin_dsn()).await?;
        sqlx::Executor::execute(
            &pool,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../db/sql/02_permesi.sql"
            )),
        )
        .await?;
        for (status, wrapped) in keys {
            sqlx::query("INSERT INTO totp_deks (dek_id, status, wrapped_dek) VALUES ($1, $2, $3)")
                .bind(uuid::Uuid::new_v4())
                .bind(status)
                .bind(wrapped)
                .execute(&pool)
                .await?;
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/permesi/decrypt/totp"))
            .and(body_json(json!({ "ciphertext": "vault:v1:good" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "plaintext": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=" }
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/transit/permesi/decrypt/totp"))
            .respond_with(ResponseTemplate::new(503).set_body_json(json!({ "errors": ["sealed"] })))
            .mount(&server)
            .await;

        let transport =
            OpenBaoTransport::from_target("test-suite", OpenBaoTarget::parse(&server.uri())?)?;
        let mut globals = GlobalArgs::new(server.uri(), transport);
        globals.openbao_transit_mount = "transit/permesi".to_string();
        let manager = DekManager::new(globals);
        let outcome = manager.init(&pool).await;
        let loaded = manager.cache.read().unwrap().len();
        Ok(Some(outcome.map(|()| loaded)))
    }

    /// The cache is filled once: starting without the active key would leave the
    /// replica unable to enrol TOTP while reporting healthy, so startup must fail.
    #[tokio::test]
    async fn init_fails_when_the_active_key_cannot_be_unwrapped() -> Result<()> {
        let Some(outcome) = init_with_keys(&[
            ("active", "vault:v1:bad"),
            ("decrypt_only", "vault:v1:good"),
        ])
        .await?
        else {
            return Ok(());
        };
        let error = outcome.expect_err("startup must not continue without the active key");
        assert!(
            format!("{error:#}").contains("active TOTP DEK"),
            "{error:#}"
        );
        Ok(())
    }

    /// A retired key that cannot be unwrapped only affects credentials still
    /// wrapped by it; it must not keep the service from starting.
    #[tokio::test]
    async fn init_tolerates_an_unreadable_retired_key() -> Result<()> {
        let Some(outcome) = init_with_keys(&[
            ("active", "vault:v1:good"),
            ("decrypt_only", "vault:v1:bad"),
        ])
        .await?
        else {
            return Ok(());
        };
        assert_eq!(outcome?, 1);
        Ok(())
    }
}
