//! Platform operator bootstrap and admin elevation endpoints.
//!
//! Flow Overview:
//! 1) Authenticate via session cookie.
//! 2) Apply bootstrap gating + recent-auth checks + rate limits.
//! 3) Validate Vault step-up tokens on every elevation.
//! 4) Issue short-lived admin PASETOs scoped to platform actions.
//!
//! Security boundaries:
//! - Vault tokens are never persisted or logged.
//! - Operator membership is a UI gate only; Vault policy is authoritative.
//! - Admin tokens are short-lived and require step-up for each issuance.

use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, StatusCode, header::CONTENT_LENGTH},
    response::IntoResponse,
};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use super::{
    admin_rate_limit::{AdminRateLimitError, AdminRateLimiter},
    admin_storage::{
        BootstrapOutcome, bootstrap_operator, operator_enabled, platform_operator_count,
    },
    admin_token::AdminTokenSigner,
    principal::{Principal, require_auth},
    types::{
        AdminBootstrapRequest, AdminBootstrapResponse, AdminElevateRequest, AdminElevateResponse,
        AdminInfraResponse, AdminStatusResponse, DatabaseStats, PlatformStats,
    },
    utils::{extract_client_ip, extract_country_code},
};
use crate::vault::step_up::{LookupSelfError, StepUpClient};
use vault_client::VaultTransport;

const DEFAULT_ADMIN_TTL_SECONDS: i64 = 12 * 60 * 60; // 12 hours
const DEFAULT_RECENT_AUTH_SECONDS: i64 = 3600; // 1 hour
const DEFAULT_VAULT_POLICY: &str = "permesi-operators";
const MAX_BODY_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug)]
pub struct AdminConfig {
    vault_addr: String,
    vault_policy: String,
    admin_ttl_seconds: i64,
    recent_auth_seconds: i64,
}

impl AdminConfig {
    #[must_use]
    pub fn new(vault_addr: String) -> Self {
        Self {
            vault_addr,
            vault_policy: DEFAULT_VAULT_POLICY.to_string(),
            admin_ttl_seconds: DEFAULT_ADMIN_TTL_SECONDS,
            recent_auth_seconds: DEFAULT_RECENT_AUTH_SECONDS,
        }
    }

    #[must_use]
    pub fn with_vault_policy(mut self, policy: String) -> Self {
        self.vault_policy = policy;
        self
    }

    #[must_use]
    pub fn with_admin_ttl_seconds(mut self, seconds: i64) -> Self {
        self.admin_ttl_seconds = seconds;
        self
    }

    #[must_use]
    pub fn with_recent_auth_seconds(mut self, seconds: i64) -> Self {
        self.recent_auth_seconds = seconds;
        self
    }

    #[must_use]
    pub fn vault_addr(&self) -> &str {
        &self.vault_addr
    }

    #[must_use]
    pub fn vault_policy(&self) -> &str {
        &self.vault_policy
    }

    #[must_use]
    pub fn admin_ttl_seconds(&self) -> i64 {
        self.admin_ttl_seconds
    }

    #[must_use]
    pub fn recent_auth_seconds(&self) -> i64 {
        self.recent_auth_seconds
    }
}

#[derive(Debug)]
pub struct AdminState {
    config: AdminConfig,
    rate_limiter: AdminRateLimiter,
    token_signer: AdminTokenSigner,
    vault_client: StepUpClient,
}

impl AdminState {
    /// # Errors
    /// Returns an error if the Vault client or token signer cannot be initialized.
    pub fn new(
        config: AdminConfig,
        pool: sqlx::PgPool,
        transport: VaultTransport,
    ) -> anyhow::Result<Self> {
        let vault_client = StepUpClient::new(transport)?;
        let token_signer = AdminTokenSigner::new()?;
        Ok(Self {
            config,
            rate_limiter: AdminRateLimiter::new(pool),
            token_signer,
            vault_client,
        })
    }

    #[must_use]
    pub fn config(&self) -> &AdminConfig {
        &self.config
    }

    #[must_use]
    pub fn rate_limiter(&self) -> &AdminRateLimiter {
        &self.rate_limiter
    }

    #[must_use]
    pub fn token_signer(&self) -> &AdminTokenSigner {
        &self.token_signer
    }

    #[must_use]
    pub fn vault_client(&self) -> &StepUpClient {
        &self.vault_client
    }
}

#[utoipa::path(
    get,
    path = "/v1/auth/admin/status",
    responses(
        (status = 200, description = "Admin status for the current session.", body = AdminStatusResponse),
        (status = 401, description = "Missing or invalid session."),
    ),
    tag = "auth"
)]
pub async fn admin_status(
    headers: HeaderMap,
    pool: Extension<sqlx::PgPool>,
    admin_state: Extension<Arc<AdminState>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let count = match platform_operator_count(&pool).await {
        Ok(count) => count,
        Err(err) => {
            error!("Failed to count platform operators: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let operator = match operator_enabled(&pool, principal.user_id).await {
        Ok(enabled) => enabled,
        Err(err) => {
            error!("Failed to lookup operator status: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let cooldown_seconds = admin_state
        .rate_limiter()
        .cooldown_seconds(principal.user_id)
        .await;

    let response = AdminStatusResponse {
        bootstrap_open: count == 0,
        operator,
        cooldown_seconds,
    };
    (StatusCode::OK, Json(response)).into_response()
}

#[utoipa::path(
    get,
    path = "/v1/auth/admin/infra",
    responses(
        (status = 200, description = "Detailed infrastructure status.", body = AdminInfraResponse),
        (status = 401, description = "Missing or invalid admin token."),
        (status = 403, description = "Not an operator."),
    ),
    tag = "auth"
)]
pub async fn admin_infra(
    headers: HeaderMap,
    pool: Extension<sqlx::PgPool>,
    admin_state: Extension<Arc<AdminState>>,
) -> impl IntoResponse {
    let user_id = match verify_admin_token(&headers, &admin_state) {
        Ok(id) => id,
        Err(status) => return status.into_response(),
    };

    match operator_enabled(&pool, user_id).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::FORBIDDEN.into_response(),
        Err(err) => {
            error!("Failed to lookup operator status: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    let db_status = if pool.acquire().await.is_ok() {
        "ok"
    } else {
        "unhealthy"
    };
    let permesi_size_bytes = database_size_bytes(&pool, "permesi").await;
    let database = DatabaseStats {
        status: db_status.to_string(),
        pool_size: pool.size(),
        active_connections: pool
            .size()
            .saturating_sub(u32::try_from(pool.num_idle()).unwrap_or(0)),
        idle_connections: u32::try_from(pool.num_idle()).unwrap_or(0),
        permesi_size_bytes,
    };

    let vault = match admin_state.vault_client().health().await {
        Ok(status) => status,
        Err(err) => {
            error!("Failed to get Vault health: {err}");
            crate::api::handlers::auth::types::VaultStatus {
                status: "error".to_string(),
                version: "unknown".to_string(),
                sealed: true,
            }
        }
    };

    let operator_count = platform_operator_count(&pool).await.unwrap_or(0);
    let recent_attempts = sqlx::query(
        "SELECT COUNT(*) FROM admin_attempts WHERE created_at > NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(&*pool)
    .await
    .map(|row| row.get::<i64, _>(0))
    .unwrap_or(0);

    let platform = PlatformStats {
        operator_count,
        recent_attempts_count: recent_attempts,
    };

    let response = AdminInfraResponse {
        database,
        vault,
        platform,
    };
    (StatusCode::OK, Json(response)).into_response()
}

/// Returns the size of a database in bytes, or `None` when unavailable.
async fn database_size_bytes(pool: &PgPool, name: &str) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT pg_database_size(datname)
         FROM pg_database
         WHERE datname = $1
           AND has_database_privilege(datname, 'CONNECT')",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .ok()?
}

/// Validates an admin elevation token and return the operator's user id.
pub fn verify_admin_token(
    headers: &HeaderMap,
    admin_state: &AdminState,
) -> Result<Uuid, StatusCode> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = value
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| value.trim().strip_prefix("bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?
        .trim();

    admin_state
        .token_signer()
        .verify(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

#[utoipa::path(
    post,
    path = "/v1/auth/admin/bootstrap",
    request_body = AdminBootstrapRequest,
    responses(
        (status = 200, description = "Bootstrap succeeded.", body = AdminBootstrapResponse),
        (status = 400, description = "Invalid request.", body = String),
        (status = 401, description = "Missing or invalid session."),
        (status = 404, description = "Bootstrap closed."),
        (status = 429, description = "Rate limited."),
        (status = 503, description = "Vault unavailable."),
    ),
    tag = "auth"
)]
pub async fn admin_bootstrap(
    headers: HeaderMap,
    pool: Extension<sqlx::PgPool>,
    admin_state: Extension<Arc<AdminState>>,
    payload: Option<Json<AdminBootstrapRequest>>,
) -> impl IntoResponse {
    if let Some(status) = reject_large_body(&headers) {
        return status.into_response();
    }
    let Some(Json(request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response();
    };

    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let count = match platform_operator_count(&pool).await {
        Ok(count) => count,
        Err(err) => {
            error!("Failed to count platform operators: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if count != 0 {
        return StatusCode::NOT_FOUND.into_response();
    }

    if !recent_auth_ok(&principal, admin_state.config().recent_auth_seconds()) {
        return (
            StatusCode::UNAUTHORIZED,
            "Recent authentication required".to_string(),
        )
            .into_response();
    }

    let client_ip = extract_client_ip(&headers);
    let country_code = extract_country_code(&headers);
    let attempt_id = match admin_state
        .rate_limiter()
        .register_attempt(
            principal.user_id,
            client_ip.as_deref(),
            country_code.as_deref(),
        )
        .await
    {
        Ok(id) => id,
        Err(err) => return rate_limit_response(err),
    };

    let token = match normalize_vault_token(&request.vault_token) {
        Ok(token) => token,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    let _vault_info =
        match validate_vault_token(admin_state.as_ref(), principal.user_id, token).await {
            Ok(info) => info,
            Err(response) => return response,
        };

    let note = request
        .note
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match bootstrap_operator(&pool, principal.user_id, note).await {
        Ok(BootstrapOutcome::Inserted) => {
            admin_state.rate_limiter().record_success(attempt_id).await;
            let response = AdminBootstrapResponse {
                ok: true,
                bootstrap_complete: true,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Ok(BootstrapOutcome::Closed) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to bootstrap operator: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/auth/admin/elevate",
    request_body = AdminElevateRequest,
    responses(
        (status = 200, description = "Admin token issued.", body = AdminElevateResponse),
        (status = 400, description = "Invalid request.", body = String),
        (status = 401, description = "Missing or invalid session."),
        (status = 403, description = "Not an operator."),
        (status = 429, description = "Rate limited."),
        (status = 503, description = "Vault unavailable."),
    ),
    tag = "auth"
)]
pub async fn admin_elevate(
    headers: HeaderMap,
    pool: Extension<sqlx::PgPool>,
    admin_state: Extension<Arc<AdminState>>,
    payload: Option<Json<AdminElevateRequest>>,
) -> impl IntoResponse {
    if let Some(status) = reject_large_body(&headers) {
        return status.into_response();
    }
    let Some(Json(request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response();
    };

    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    match operator_enabled(&pool, principal.user_id).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::FORBIDDEN.into_response(),
        Err(err) => {
            error!("Failed to lookup operator status: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    let client_ip = extract_client_ip(&headers);
    let country_code = extract_country_code(&headers);
    let attempt_id = match admin_state
        .rate_limiter()
        .register_attempt(
            principal.user_id,
            client_ip.as_deref(),
            country_code.as_deref(),
        )
        .await
    {
        Ok(id) => id,
        Err(err) => return rate_limit_response(err),
    };

    let token = match normalize_vault_token(&request.vault_token) {
        Ok(token) => token,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    let vault_info =
        match validate_vault_token(admin_state.as_ref(), principal.user_id, token).await {
            Ok(info) => info,
            Err(response) => return response,
        };

    // Cap the admin token TTL to the vault token's remaining life if it is shorter
    // than our configured maximum.
    let ttl_seconds = admin_state.config().admin_ttl_seconds().min(vault_info.ttl);

    let admin_token = match admin_state
        .token_signer()
        .issue(principal.user_id, ttl_seconds)
    {
        Ok(token) => token,
        Err(err) => {
            error!("Failed to mint admin token: {err}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    admin_state.rate_limiter().record_success(attempt_id).await;
    let response = AdminElevateResponse {
        admin_token: admin_token.token,
        expires_at: admin_token.expires_at,
    };
    (StatusCode::OK, Json(response)).into_response()
}

fn reject_large_body(headers: &HeaderMap) -> Option<StatusCode> {
    let length = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())?;
    (length > MAX_BODY_BYTES).then_some(StatusCode::PAYLOAD_TOO_LARGE)
}

fn normalize_vault_token(token: &str) -> Result<&str, String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err("Missing vault token".to_string());
    }
    if trimmed.len() > MAX_BODY_BYTES {
        return Err("Invalid vault token".to_string());
    }
    Ok(trimmed)
}

fn rate_limit_response(err: AdminRateLimitError) -> axum::response::Response {
    match err {
        AdminRateLimitError::Limited | AdminRateLimitError::Cooldown { .. } => {
            (StatusCode::TOO_MANY_REQUESTS, err.to_string()).into_response()
        }
    }
}

async fn validate_vault_token(
    admin_state: &AdminState,
    user_id: Uuid,
    token: &str,
) -> Result<crate::vault::step_up::VaultTokenInfo, axum::response::Response> {
    let lookup = admin_state.vault_client().lookup_self(token).await;
    let info = match lookup {
        Ok(info) => info,
        Err(err) => {
            return Err(match err {
                LookupSelfError::Unauthorized => {
                    admin_state.rate_limiter().record_failure(user_id);
                    (StatusCode::UNAUTHORIZED, "Invalid vault token".to_string()).into_response()
                }
                LookupSelfError::Unavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Vault unavailable".to_string(),
                )
                    .into_response(),
                LookupSelfError::InvalidResponse => (
                    StatusCode::BAD_GATEWAY,
                    "Vault response invalid".to_string(),
                )
                    .into_response(),
            });
        }
    };

    if info
        .policies
        .iter()
        .any(|policy| policy == admin_state.config().vault_policy())
    {
        Ok(info)
    } else {
        admin_state.rate_limiter().record_failure(user_id);
        Err((StatusCode::FORBIDDEN, "Vault policy missing".to_string()).into_response())
    }
}

fn recent_auth_ok(principal: &Principal, max_age_seconds: i64) -> bool {
    let now = unix_now();
    let auth_time = principal
        .session_auth_time_unix
        .unwrap_or(principal.session_issued_at_unix);
    now.saturating_sub(auth_time) <= max_age_seconds
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| {
            #[allow(clippy::cast_possible_wrap)]
            {
                duration.as_secs() as i64
            }
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{AdminConfig, AdminState, validate_vault_token};
    use anyhow::{Context, Result};
    use serde_json::json;
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use std::net::TcpListener;
    use test_support::{postgres::PostgresContainer, runtime};
    use uuid::Uuid;
    use vault_client::{VaultTarget, VaultTransport};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SCHEMA_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../db/sql/02_permesi.sql"
    ));

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    fn create_transport(url: &str) -> VaultTransport {
        let target = VaultTarget::parse(url).unwrap();
        VaultTransport::from_target("test", target).unwrap()
    }

    async fn get_test_pool() -> Result<(PgPool, PostgresContainer)> {
        let postgres = PostgresContainer::start("bridge").await?;
        postgres.wait_until_ready().await?;
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect(&postgres.admin_dsn())
            .await?;

        sqlx::Executor::execute(&pool, SCHEMA_SQL)
            .await
            .context("failed to execute schema SQL")?;

        Ok((pool, postgres))
    }

    #[tokio::test]
    async fn validate_vault_token_requires_policy() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let (pool, _container) = get_test_pool().await?;
        sqlx::query("TRUNCATE users, platform_operators, admin_attempts CASCADE")
            .execute(&pool)
            .await?;

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .and(header("X-Vault-Token", "token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "policies": ["default"],
                    "ttl": 43200
                }
            })))
            .mount(&server)
            .await;

        let config = AdminConfig::new(server.uri());
        let state = AdminState::new(config, pool, create_transport(&server.uri()))?;
        let response = validate_vault_token(&state, Uuid::new_v4(), "token").await;
        assert!(response.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn validate_vault_token_calls_vault_each_time() -> Result<()> {
        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let (pool, _container) = get_test_pool().await?;
        sqlx::query("TRUNCATE users, platform_operators, admin_attempts CASCADE")
            .execute(&pool)
            .await?;

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "policies": ["permesi-operators"],
                    "ttl": 43200
                }
            })))
            .expect(2)
            .mount(&server)
            .await;

        let config = AdminConfig::new(server.uri());
        let state = AdminState::new(config, pool, create_transport(&server.uri()))?;
        let _ = validate_vault_token(&state, Uuid::new_v4(), "token").await;
        let _ = validate_vault_token(&state, Uuid::new_v4(), "token").await;
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_happy_path() -> Result<()> {
        use crate::api::handlers::auth::{
            admin::admin_bootstrap,
            types::AdminBootstrapRequest,
            utils::{generate_session_token, hash_session_token},
        };
        use axum::{Extension, Json, http::header::COOKIE, response::IntoResponse};
        use std::sync::Arc;

        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let (pool, _container) = get_test_pool().await?;
        sqlx::query("TRUNCATE users, platform_operators, admin_attempts, user_sessions CASCADE")
            .execute(&pool)
            .await?;

        // 1. Setup User & Session
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, email, status, opaque_registration_record) VALUES ($1, 'admin@example.com', 'active', $2)")
            .bind(user_id)
            .bind(vec![0u8; 16])
            .execute(&pool)
            .await?;

        let token = generate_session_token()?;
        let hash = hash_session_token(&token);

        sqlx::query("INSERT INTO user_sessions (user_id, session_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')")
            .bind(user_id)
            .bind(hash)
            .execute(&pool)
            .await?;

        // 2. Setup Mock Vault
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "policies": ["permesi-operators"],
                    "ttl": 43200
                }
            })))
            .mount(&server)
            .await;

        let config = AdminConfig::new(server.uri());
        let state = Arc::new(AdminState::new(
            config,
            pool.clone(),
            create_transport(&server.uri()),
        )?);

        // 3. Prepare Request
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(COOKIE, format!("permesi_session={token}").parse()?);

        let payload = AdminBootstrapRequest {
            vault_token: "s.validtoken".to_string(),
            note: Some("Initial bootstrap".to_string()),
        };

        // 4. Call Handler
        let response = admin_bootstrap(
            headers,
            Extension(pool.clone()),
            Extension(state),
            Some(Json(payload)),
        )
        .await
        .into_response();

        // 5. Assertions
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Verify DB update
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM platform_operators")
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, 1);

        let enabled: bool =
            sqlx::query_scalar("SELECT enabled FROM platform_operators WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await?;
        assert!(enabled);

        Ok(())
    }

    #[tokio::test]
    async fn admin_infra_rejects_non_operator() -> Result<()> {
        use crate::api::handlers::auth::admin::admin_infra;
        use axum::{Extension, http::header::AUTHORIZATION, response::IntoResponse};
        use std::sync::Arc;

        if !can_bind_localhost() {
            eprintln!("Skipping test: cannot bind localhost");
            return Ok(());
        }
        if let Err(err) = runtime::ensure_container_runtime() {
            eprintln!("Skipping integration test: {err}");
            return Ok(());
        }

        let (pool, _container) = get_test_pool().await?;
        sqlx::query("TRUNCATE users, platform_operators, admin_attempts, user_sessions CASCADE")
            .execute(&pool)
            .await?;

        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, email, status, opaque_registration_record) VALUES ($1, 'non-operator@example.com', 'active', $2)")
            .bind(user_id)
            .bind(vec![0u8; 16])
            .execute(&pool)
            .await?;

        let server = MockServer::start().await;
        let config = AdminConfig::new(server.uri());
        let state = Arc::new(AdminState::new(
            config,
            pool.clone(),
            create_transport(&server.uri()),
        )?);

        let admin_token = state.token_signer().issue(user_id, 60)?.token;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {admin_token}").parse()?);

        let response = admin_infra(headers, Extension(pool), Extension(state))
            .await
            .into_response();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        Ok(())
    }
}
