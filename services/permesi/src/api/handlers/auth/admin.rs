//! Platform operator bootstrap and admin elevation endpoints.
//!
//! Flow Overview:
//! 1) Authenticate via session cookie.
//! 2) Apply bootstrap gating + recent-auth checks + rate limits.
//! 3) Validate OpenBao step-up tokens on every elevation.
//! 4) Record the elevation in PostgreSQL against the exact session, under the
//!    identity and session locks, and authorize infrastructure reads from that row.
//!
//! Security boundaries:
//! - OpenBao tokens are never persisted or logged.
//! - The session and the operator designation in PostgreSQL authorize; the OpenBao
//!   policy is the additional factor an elevation or the first bootstrap requires.
//! - An elevation is short-lived, requires step-up for each issuance, belongs to one
//!   session and ends with it; see `admin_elevation` for the storage rules.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::CONTENT_LENGTH},
    response::IntoResponse,
};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use super::{
    AuthState,
    admin_elevation::{self, Access},
    admin_rate_limit::{AdminRateLimitError, AdminRateLimiter},
    admin_storage::{
        BootstrapOutcome, bootstrap_operator, operator_enabled, platform_operator_count,
    },
    authority_guard::{AuthorityGuard, Policy},
    principal::{Principal, require_auth},
    session::extract_session_token,
    session_kind::SessionKind,
    types::{
        AdminBootstrapRequest, AdminBootstrapResponse, AdminElevateRequest, AdminElevateResponse,
        AdminInfraResponse, AdminStatusResponse, DatabaseStats, PlatformStats,
    },
    utils::{extract_client_ip, extract_country_code, hash_session_token},
};
use crate::openbao::step_up::{LookupSelfError, StepUpClient};
use openbao_client::OpenBaoTransport;

const DEFAULT_ADMIN_TTL_SECONDS: i64 = 12 * 60 * 60; // 12 hours
const DEFAULT_RECENT_AUTH_SECONDS: i64 = 3600; // 1 hour
const DEFAULT_OPENBAO_POLICY: &str = "permesi-operators";
const MAX_BODY_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct AdminConfig {
    openbao_addr: String,
    openbao_policy: String,
    admin_ttl_seconds: i64,
    recent_auth_seconds: i64,
}

/// The address is the operator-supplied one when it could not be reduced to an origin,
/// so it is formatted without userinfo or query string. This type is nested in the
/// application state, whose `Debug` output would otherwise carry it.
impl std::fmt::Debug for AdminConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field(
                "openbao_addr",
                &openbao_client::loggable_url(&self.openbao_addr),
            )
            .field("openbao_policy", &self.openbao_policy)
            .field("admin_ttl_seconds", &self.admin_ttl_seconds)
            .field("recent_auth_seconds", &self.recent_auth_seconds)
            .finish()
    }
}

impl AdminConfig {
    #[must_use]
    pub fn new(openbao_addr: String) -> Self {
        Self {
            openbao_addr,
            openbao_policy: DEFAULT_OPENBAO_POLICY.to_string(),
            admin_ttl_seconds: DEFAULT_ADMIN_TTL_SECONDS,
            recent_auth_seconds: DEFAULT_RECENT_AUTH_SECONDS,
        }
    }

    #[must_use]
    pub fn with_openbao_policy(mut self, policy: String) -> Self {
        self.openbao_policy = policy;
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
    pub fn openbao_addr(&self) -> &str {
        &self.openbao_addr
    }

    #[must_use]
    pub fn openbao_policy(&self) -> &str {
        &self.openbao_policy
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
    openbao_client: StepUpClient,
}

impl AdminState {
    /// # Errors
    /// Returns an error if the OpenBao client cannot be initialized.
    pub fn new(
        config: AdminConfig,
        pool: sqlx::PgPool,
        transport: OpenBaoTransport,
    ) -> anyhow::Result<Self> {
        let openbao_client = StepUpClient::new(transport)?;
        Ok(Self {
            config,
            rate_limiter: AdminRateLimiter::new(pool),
            openbao_client,
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
    pub fn openbao_client(&self) -> &StepUpClient {
        &self.openbao_client
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
    pool: State<sqlx::PgPool>,
    admin_state: State<Arc<AdminState>>,
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
        (status = 200, description = "Detailed infrastructure status. Cache-Control: no-store.", body = AdminInfraResponse),
        (status = 401, description = "Missing, expired or limited session, or inactive account."),
        (status = 403, description = "The session holds no current elevation: never elevated, expired, disabled operator, or stale designation revision."),
        (status = 503, description = "Authorization storage unavailable; the read is refused."),
    ),
    tag = "auth"
)]
pub async fn admin_infra(
    headers: HeaderMap,
    pool: State<sqlx::PgPool>,
    admin_state: State<Arc<AdminState>>,
) -> impl IntoResponse {
    if let Err(status) = require_elevation(&headers, &pool).await {
        return status.into_response();
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

    let openbao = match admin_state.openbao_client().health().await {
        Ok(status) => status,
        Err(err) => {
            error!("Failed to get OpenBao health: {err}");
            crate::api::handlers::auth::types::OpenBaoStatus {
                status: "error".to_string(),
                version: "unknown".to_string(),
                sealed: true,
            }
        }
    };

    // A count that could not be read is reported as absent, never as zero.
    let operator_count = platform_operator_count(&pool).await.ok();
    let recent_attempts = sqlx::query(
        "SELECT COUNT(*) FROM admin_attempts WHERE created_at > NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(&*pool)
    .await
    .ok()
    .map(|row| row.get::<i64, _>(0));

    let platform = PlatformStats {
        operator_count,
        recent_attempts_count: recent_attempts,
    };

    let response = AdminInfraResponse {
        database,
        openbao,
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

/// Authorizes an infrastructure read from the session cookie alone: a full session of an
/// active account that holds a current elevation. A missing, limited or dead session is
/// `401`; a live session without a usable elevation is `403`. The decision is made by
/// `admin_elevation::authorize` from server data, and a failed lookup refuses the read
/// with `503`.
async fn require_elevation(headers: &HeaderMap, pool: &PgPool) -> Result<(), StatusCode> {
    let token = extract_session_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if SessionKind::from_token(&token) != SessionKind::Full {
        return Err(StatusCode::UNAUTHORIZED);
    }
    match admin_elevation::authorize(pool, &hash_session_token(&token)).await {
        Ok(Access::Elevated) => Ok(()),
        Ok(Access::NotElevated) => Err(StatusCode::FORBIDDEN),
        Ok(Access::NoSession) => Err(StatusCode::UNAUTHORIZED),
        Err(err) => {
            error!("Failed to look up operator elevation: {err}");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
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
        (status = 503, description = "OpenBao unavailable."),
    ),
    tag = "auth"
)]
pub async fn admin_bootstrap(
    headers: HeaderMap,
    pool: State<sqlx::PgPool>,
    admin_state: State<Arc<AdminState>>,
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

    let token = match normalize_openbao_token(&request.openbao_token) {
        Ok(token) => token,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    let _openbao_info =
        match validate_openbao_token(admin_state.as_ref(), principal.user_id, token).await {
            Ok(info) => info,
            Err(response) => return *response,
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
        (status = 200, description = "The session is elevated until `expires_at`. Cache-Control: no-store.", body = AdminElevateResponse),
        (status = 400, description = "Invalid request.", body = String),
        (status = 401, description = "Missing or invalid session, including one that ended during the request, or an OpenBao token that OpenBao rejects.", body = String),
        (status = 403, description = "Not an operator, the OpenBao token lacks the policy or has no remaining lifetime, or the session or designation stopped qualifying during the request.", body = String),
        (status = 413, description = "Request body too large."),
        (status = 429, description = "Rate limited or in cooldown; also answered when the attempt log cannot be read."),
        (status = 502, description = "OpenBao answered the token lookup with an invalid response.", body = String),
        (status = 503, description = "OpenBao or authentication storage unavailable. No elevation is recorded unless the failure was the loss of the commit's acknowledgement; the attempt reserved before the failure still counts toward the limits."),
    ),
    tag = "auth"
)]
pub async fn admin_elevate(
    headers: HeaderMap,
    pool: State<sqlx::PgPool>,
    auth_state: State<Arc<AuthState>>,
    admin_state: State<Arc<AdminState>>,
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
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
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

    let token = match normalize_openbao_token(&request.openbao_token) {
        Ok(token) => token,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    // Read before the lookup: the elevation's deadline is this instant plus the token's
    // remaining life, so time spent on OpenBao and on the locks below is never added.
    let anchor = match admin_elevation::clock(&pool).await {
        Ok(anchor) => anchor,
        Err(err) => {
            error!("Failed to read the database clock: {err}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let openbao_info =
        match validate_openbao_token(admin_state.as_ref(), principal.user_id, token).await {
            Ok(info) => info,
            Err(response) => return *response,
        };

    let step_up = StepUp {
        user_id: principal.user_id,
        attempt_id,
        anchor,
        openbao_ttl_seconds: openbao_info.ttl,
    };
    match record_elevation(&headers, &pool, &auth_state, &admin_state, step_up).await {
        Ok(expires_at) => {
            let expires_at = crate::api::timestamp::rfc3339(expires_at);
            (StatusCode::OK, Json(AdminElevateResponse { expires_at })).into_response()
        }
        Err(status) => status.into_response(),
    }
}

/// A validated OpenBao step-up waiting to be recorded.
struct StepUp {
    user_id: Uuid,
    /// The rate limiter's reservation for this request.
    attempt_id: Uuid,
    /// Database clock read before the OpenBao lookup.
    anchor: jiff_sqlx::Timestamp,
    /// Remaining life OpenBao reported for the token.
    openbao_ttl_seconds: i64,
}

/// Commits the elevation for the exact session that asked for it and returns its expiry.
///
/// The session was authenticated before the OpenBao call, which can take long enough for
/// a logout, password rotation or designation change to commit. So the account and the
/// exact session are locked again here, in the order every lifecycle mutation uses, and
/// the grant is written on that transaction: either the mutation committed first and
/// this request is refused (`401` for a dead session, `403` for a lost designation), or
/// the grant commits first and the mutation deletes or invalidates it. The lifetime is
/// bounded by the configured one and by the deadline fixed before the OpenBao lookup.
/// The rate limiter's reservation is marked successful in the same transaction, so a
/// grant and its success mark commit together or not at all. Storage failures answer
/// `503`; no elevation is recorded unless the failure was the loss of the commit's
/// acknowledgement. The reservation itself was committed earlier and, unmarked, counts
/// as a failed attempt.
async fn record_elevation(
    headers: &HeaderMap,
    pool: &PgPool,
    auth_state: &AuthState,
    admin_state: &AdminState,
    step_up: StepUp,
) -> Result<jiff_sqlx::Timestamp, StatusCode> {
    let configured = admin_state.config().admin_ttl_seconds();
    let deadline = admin_elevation::openbao_deadline(step_up.anchor, step_up.openbao_ttl_seconds)
        .ok_or(StatusCode::FORBIDDEN)?;
    let session_hash = extract_session_token(headers)
        .map(|token| hash_session_token(&token))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let mut guard = AuthorityGuard::acquire(
        pool,
        headers,
        step_up.user_id,
        Policy::Full,
        auth_state.config().opaque_exchange_timeout_ms(),
    )
    .await?;

    // `grant` writes nothing when the deadline has passed, or when the session, the
    // account or the designation stopped qualifying before the locks were taken.
    let unavailable = |step: &'static str| {
        move |err: &dyn std::fmt::Display| {
            error!("Failed to {step}: {err}");
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    let expires_at = admin_elevation::grant(
        guard.connection(),
        step_up.user_id,
        &session_hash,
        configured,
        deadline,
    )
    .await
    .map_err(|err| unavailable("record operator elevation")(&err))?
    .ok_or(StatusCode::FORBIDDEN)?;
    let recorded = AdminRateLimiter::record_success_on(guard.connection(), step_up.attempt_id)
        .await
        .map_err(|err| unavailable("record the elevation attempt's success")(&err))?;
    if !recorded {
        // The reservation is gone, so the elevation would have no audit record.
        return Err(unavailable("record the elevation attempt's success")(
            &"the attempt no longer exists",
        ));
    }
    guard
        .commit()
        .await
        .map_err(|err| unavailable("commit operator elevation")(&err))?;
    Ok(expires_at)
}

fn reject_large_body(headers: &HeaderMap) -> Option<StatusCode> {
    let length = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())?;
    (length > MAX_BODY_BYTES).then_some(StatusCode::PAYLOAD_TOO_LARGE)
}

fn normalize_openbao_token(token: &str) -> Result<&str, String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err("Missing bao token".to_string());
    }
    if trimmed.len() > MAX_BODY_BYTES {
        return Err("Invalid bao token".to_string());
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

/// Verifies the submitted OpenBao token and requires the configured elevation policy.
///
/// Validation is performed through OpenBao with the authenticated user's server-side
/// identity. Unauthorized or under-scoped attempts are recorded by the rate limiter;
/// the token itself is never returned or logged. Error responses are boxed only to
/// keep the async result small and do not change the response sent to the client.
async fn validate_openbao_token(
    admin_state: &AdminState,
    user_id: Uuid,
    token: &str,
) -> Result<crate::openbao::step_up::OpenBaoTokenInfo, Box<axum::response::Response>> {
    let lookup = admin_state.openbao_client().lookup_self(token).await;
    let info = match lookup {
        Ok(info) => info,
        Err(err) => {
            return Err(Box::new(match err {
                LookupSelfError::Unauthorized => {
                    admin_state.rate_limiter().record_failure(user_id);
                    (StatusCode::UNAUTHORIZED, "Invalid bao token".to_string()).into_response()
                }
                LookupSelfError::Unavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "OpenBao unavailable".to_string(),
                )
                    .into_response(),
                LookupSelfError::InvalidResponse => (
                    StatusCode::BAD_GATEWAY,
                    "OpenBao response invalid".to_string(),
                )
                    .into_response(),
            }));
        }
    };

    if info
        .policies
        .iter()
        .any(|policy| policy == admin_state.config().openbao_policy())
    {
        Ok(info)
    } else {
        admin_state.rate_limiter().record_failure(user_id);
        Err(Box::new(
            (StatusCode::FORBIDDEN, "OpenBao policy missing".to_string()).into_response(),
        ))
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
        .map_or_else(
            |_| 0,
            |duration| {
                #[allow(clippy::cast_possible_wrap)]
                {
                    duration.as_secs() as i64
                }
            },
        )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{AdminConfig, AdminState, validate_openbao_token};
    use anyhow::{Context, Result};
    use openbao_client::{OpenBaoTarget, OpenBaoTransport};
    use serde_json::json;
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use std::net::TcpListener;
    use test_support::{postgres::PostgresContainer, runtime};
    use uuid::Uuid;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SCHEMA_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../db/sql/02_permesi.sql"
    ));

    fn can_bind_localhost() -> bool {
        TcpListener::bind("127.0.0.1:0").is_ok()
    }

    fn create_transport(url: &str) -> OpenBaoTransport {
        let target = OpenBaoTarget::parse(url).unwrap();
        OpenBaoTransport::from_target("test", target).unwrap()
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
    async fn validate_openbao_token_requires_policy() -> Result<()> {
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
        let response = validate_openbao_token(&state, Uuid::new_v4(), "token").await;
        assert!(response.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn validate_openbao_token_calls_openbao_each_time() -> Result<()> {
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
        let _ = validate_openbao_token(&state, Uuid::new_v4(), "token").await;
        let _ = validate_openbao_token(&state, Uuid::new_v4(), "token").await;
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_happy_path() -> Result<()> {
        use crate::api::handlers::auth::{
            admin::admin_bootstrap,
            types::AdminBootstrapRequest,
            utils::{generate_session_token, hash_session_token},
        };
        use axum::{Json, extract::State, http::header::COOKIE, response::IntoResponse};
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

        // 2. Setup Mock OpenBao
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
            openbao_token: "s.validtoken".to_string(),
            note: Some("Initial bootstrap".to_string()),
        };

        // 4. Call Handler
        let response = admin_bootstrap(
            headers,
            State(pool.clone()),
            State(state),
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
}
