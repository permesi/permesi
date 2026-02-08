//! Passkey (`WebAuthn`) handlers for authenticated user self-service.
//!
//! This module provides endpoints for users to register, list, and delete
//! passkeys. It integrates with the OPAQUE authentication system and
//! requires a fresh zero token for sensitive registration actions.

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{error, info, warn};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, RegisterPublicKeyCredential};

use super::{
    AdmissionVerifier,
    auth::{
        AuthState, RateLimitAction, RateLimitDecision, extract_client_ip, hash_session_token,
        principal::require_auth, session::extract_session_token,
    },
    verify_token,
};
use crate::webauthn::{PasskeyRegistrationError, PasskeyRepo, PasskeyService, serialize_passkey};

const MAX_WEBAUTHN_JSON_BYTES: usize = 32 * 1024;
const ZERO_TOKEN_HEADER: &str = "x-permesi-zero-token";
type HandlerError = Box<axum::response::Response>;

struct RegisterFinishContext {
    user_id: Uuid,
    request_id: String,
    reg_id: Uuid,
    reg_response: RegisterPublicKeyCredential,
    origin: String,
    session_hash: Vec<u8>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyRegisterOptionsResponse {
    pub reg_id: String,
    pub challenge: serde_json::Value,
    pub preview_mode: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRegisterFinishRequest {
    pub reg_id: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyRegisterFinishResponse {
    pub stored: bool,
    pub warning: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyCredentialSummary {
    pub id: String,
    pub label: Option<String>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyCredentialListResponse {
    pub preview_mode: bool,
    pub credentials: Vec<PasskeyCredentialSummary>,
}

#[utoipa::path(
    post,
    path = "/v1/me/webauthn/register/options",
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "Passkey registration options", body = PasskeyRegisterOptionsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Rate limited")
    ),
    tag = "me"
)]
/// Generate passkey registration options for the current user.
///
/// Requires a full session and a valid zero token; binds the challenge to the
/// current session and validates the request Origin before issuing options.
pub async fn register_options(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    admission: Extension<Arc<AdmissionVerifier>>,
    passkey_service: Extension<Arc<PasskeyService>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let request_id = request_id(&headers);
    info!(
        user_id = %principal.user_id,
        request_id = %request_id,
        "passkey register options requested"
    );

    if let Err(response) = enforce_rate_limits(&headers, &auth_state, &principal.email) {
        warn!(
            user_id = %principal.user_id,
            request_id = %request_id,
            "passkey register options rate limited"
        );
        return *response;
    }

    if let Err(response) = require_zero_token(&headers, &admission).await {
        warn!(
            user_id = %principal.user_id,
            request_id = %request_id,
            "passkey register options rejected: zero token"
        );
        return *response;
    }

    let origin = match extract_origin(&headers, &passkey_service) {
        Ok(origin) => origin,
        Err(response) => return *response,
    };

    let Some(session_token) = extract_session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let session_hash = hash_session_token(&session_token);

    let display_name = match fetch_display_name(&pool, principal.user_id).await {
        Ok(name) => name.unwrap_or_else(|| principal.email.clone()),
        Err(err) => {
            error!(
                user_id = %principal.user_id,
                request_id = %request_id,
                "failed to load display name for passkey options: {err}"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    match passkey_service
        .register_begin(
            principal.user_id,
            &principal.email,
            &display_name,
            session_hash,
            &origin,
        )
        .await
    {
        Ok((reg_id, challenge)) => (
            StatusCode::OK,
            Json(PasskeyRegisterOptionsResponse {
                reg_id: reg_id.to_string(),
                challenge: serde_json::to_value(challenge).unwrap_or_default(),
                preview_mode: passkey_service.config().preview_mode(),
            }),
        )
            .into_response(),
        Err(err) => {
            error!(
                user_id = %principal.user_id,
                request_id = %request_id,
                "failed to start passkey registration: {err}"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/me/webauthn/register/finish",
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    request_body = PasskeyRegisterFinishRequest,
    responses(
        (status = 200, description = "Passkey registration finished", body = PasskeyRegisterFinishResponse),
        (status = 400, description = "Invalid registration response"),
        (status = 401, description = "Unauthorized"),
        (status = 413, description = "Payload too large"),
        (status = 429, description = "Rate limited")
    ),
    tag = "me"
)]
/// Verify and finalize passkey registration for the current user.
///
/// Requires a full session and a valid zero token; consumes the one-time
/// challenge and never persists credentials while preview mode is enabled.
pub async fn register_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    admission: Extension<Arc<AdmissionVerifier>>,
    passkey_service: Extension<Arc<PasskeyService>>,
    body: Bytes,
) -> impl IntoResponse {
    let context = match load_register_finish_context(
        &headers,
        &pool,
        &auth_state,
        &admission,
        &passkey_service,
        &body,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };

    let finish_result = passkey_service
        .register_finish(
            context.reg_id,
            context.user_id,
            &context.session_hash,
            &context.origin,
            context.reg_response,
        )
        .await;

    match finish_result {
        Ok(passkey) => {
            info!(
                user_id = %context.user_id,
                request_id = %context.request_id,
                "passkey registration succeeded"
            );
            let preview = passkey_service.config().preview_mode();
            if preview {
                return (
                    StatusCode::OK,
                    Json(PasskeyRegisterFinishResponse {
                        stored: false,
                        warning: Some(
                            "Preview mode: passkey was verified but not stored".to_string(),
                        ),
                    }),
                )
                    .into_response();
            }

            if let Err(response) = persist_passkey(
                &pool,
                context.user_id,
                &passkey,
                &context.request_id,
                extract_client_ip(&headers).as_deref(),
            )
            .await
            {
                return *response;
            }

            (
                StatusCode::OK,
                Json(PasskeyRegisterFinishResponse {
                    stored: true,
                    warning: None,
                }),
            )
                .into_response()
        }
        Err(err) => {
            warn!(
                user_id = %context.user_id,
                request_id = %context.request_id,
                "passkey registration failed"
            );
            let response = match err {
                PasskeyRegistrationError::NotFound
                | PasskeyRegistrationError::Expired
                | PasskeyRegistrationError::UserMismatch
                | PasskeyRegistrationError::SessionMismatch
                | PasskeyRegistrationError::OriginMismatch => {
                    (StatusCode::BAD_REQUEST, "Registration session invalid")
                }
                PasskeyRegistrationError::Webauthn(_) => {
                    (StatusCode::BAD_REQUEST, "Registration verification failed")
                }
            };
            response.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/me/webauthn/credentials",
    responses(
        (status = 200, description = "Registered passkeys", body = PasskeyCredentialListResponse),
        (status = 401, description = "Unauthorized")
    ),
    tag = "me"
)]
/// List registered passkeys for the current user.
///
/// Returns an empty list in preview mode; requires a full session.
pub async fn list_credentials(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    passkey_service: Extension<Arc<PasskeyService>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let request_id = request_id(&headers);
    info!(
        user_id = %principal.user_id,
        request_id = %request_id,
        "passkey list requested"
    );

    if passkey_service.config().preview_mode() {
        return (
            StatusCode::OK,
            Json(PasskeyCredentialListResponse {
                preview_mode: true,
                credentials: Vec::new(),
            }),
        )
            .into_response();
    }

    match PasskeyRepo::list_user_passkeys(&pool, principal.user_id).await {
        Ok(rows) => {
            let credentials = rows
                .into_iter()
                .map(|row| PasskeyCredentialSummary {
                    id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(row.credential_id),
                    label: row.label,
                    created_at: Some(row.created_at.to_rfc3339()),
                    last_used_at: row.last_used_at.map(|ts| ts.to_rfc3339()),
                })
                .collect::<Vec<_>>();
            (
                StatusCode::OK,
                Json(PasskeyCredentialListResponse {
                    preview_mode: false,
                    credentials,
                }),
            )
                .into_response()
        }
        Err(err) => {
            error!(
                user_id = %principal.user_id,
                request_id = %request_id,
                "passkey list failed: {err}"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/v1/me/webauthn/credentials/{credential_id}",
    params(("credential_id" = String, Path, description = "Base64url credential id")),
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Passkey deleted"),
        (status = 400, description = "Invalid credential id or missing zero token"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found")
    ),
    tag = "me"
)]
/// Delete a registered passkey by credential id.
///
/// Requires a full session and a valid zero token; not supported in preview mode.
pub async fn delete_credential(
    Path(credential_id_b64): Path<String>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
    admission: Extension<Arc<AdmissionVerifier>>,
    passkey_service: Extension<Arc<PasskeyService>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let request_id = request_id(&headers);
    info!(
        user_id = %principal.user_id,
        request_id = %request_id,
        "passkey delete requested"
    );

    if let Err(response) = require_zero_token(&headers, &admission).await {
        warn!(
            user_id = %principal.user_id,
            request_id = %request_id,
            "passkey delete rejected: zero token"
        );
        return *response;
    }

    if passkey_service.config().preview_mode() {
        warn!(
            user_id = %principal.user_id,
            request_id = %request_id,
            "passkey delete not supported in preview mode"
        );
        return StatusCode::NOT_FOUND.into_response();
    }

    let credential_id = match decode_credential_id(&credential_id_b64) {
        Ok(id) => id,
        Err(response) => return *response,
    };

    match PasskeyRepo::delete_passkey(&pool, principal.user_id, &credential_id).await {
        Ok(true) => {
            if let Err(err) = PasskeyRepo::log_audit(
                &pool,
                principal.user_id,
                Some(&credential_id),
                "delete",
                extract_client_ip(&headers).as_deref(),
                None,
            )
            .await
            {
                warn!(
                    user_id = %principal.user_id,
                    request_id = %request_id,
                    "passkey audit delete failed: {err}"
                );
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!(
                user_id = %principal.user_id,
                request_id = %request_id,
                "passkey delete failed: {err}"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn extract_origin(
    headers: &HeaderMap,
    passkey_service: &PasskeyService,
) -> Result<String, HandlerError> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Box::new((StatusCode::BAD_REQUEST, "Missing Origin header").into_response())
        })?;

    passkey_service
        .match_origin(origin)
        .ok_or_else(|| Box::new((StatusCode::BAD_REQUEST, "Origin not allowed").into_response()))
}

async fn load_register_finish_context(
    headers: &HeaderMap,
    pool: &PgPool,
    auth_state: &AuthState,
    admission: &AdmissionVerifier,
    passkey_service: &PasskeyService,
    body: &Bytes,
) -> Result<RegisterFinishContext, HandlerError> {
    let principal = match require_auth(headers, pool).await {
        Ok(principal) => principal,
        Err(status) => return Err(Box::new(status.into_response())),
    };

    let request_id = request_id(headers);
    info!(
        user_id = %principal.user_id,
        request_id = %request_id,
        "passkey register finish requested"
    );

    let (reg_id, reg_response) = parse_register_finish(body)?;

    if let Err(response) = enforce_rate_limits(headers, auth_state, &principal.email) {
        warn!(
            user_id = %principal.user_id,
            request_id = %request_id,
            "passkey register finish rate limited"
        );
        return Err(response);
    }

    if let Err(response) = require_zero_token(headers, admission).await {
        warn!(
            user_id = %principal.user_id,
            request_id = %request_id,
            "passkey register finish rejected: zero token"
        );
        return Err(response);
    }

    let origin = extract_origin(headers, passkey_service)?;

    let Some(session_token) = extract_session_token(headers) else {
        return Err(Box::new(StatusCode::UNAUTHORIZED.into_response()));
    };
    let session_hash = hash_session_token(&session_token);

    Ok(RegisterFinishContext {
        user_id: principal.user_id,
        request_id,
        reg_id,
        reg_response,
        origin,
        session_hash,
    })
}

fn parse_register_finish(
    body: &Bytes,
) -> Result<(Uuid, RegisterPublicKeyCredential), HandlerError> {
    if body.len() > MAX_WEBAUTHN_JSON_BYTES {
        return Err(Box::new(StatusCode::PAYLOAD_TOO_LARGE.into_response()));
    }

    let request: PasskeyRegisterFinishRequest = serde_json::from_slice(body)
        .map_err(|_| Box::new((StatusCode::BAD_REQUEST, "Invalid payload").into_response()))?;

    let reg_id = Uuid::parse_str(request.reg_id.trim()).map_err(|_| {
        Box::new((StatusCode::BAD_REQUEST, "Invalid registration ID").into_response())
    })?;

    let reg_response: RegisterPublicKeyCredential = serde_json::from_value(request.response)
        .map_err(|_| {
            Box::new((StatusCode::BAD_REQUEST, "Invalid WebAuthn response").into_response())
        })?;

    Ok((reg_id, reg_response))
}

async fn persist_passkey(
    pool: &PgPool,
    user_id: Uuid,
    passkey: &Passkey,
    request_id: &str,
    ip: Option<&str>,
) -> Result<(), HandlerError> {
    let credential_id = passkey.cred_id().as_slice();
    match PasskeyRepo::get_passkey(pool, credential_id).await {
        Ok(Some(_)) => {
            warn!(
                user_id = %user_id,
                request_id = %request_id,
                "passkey registration rejected: credential already exists"
            );
            return Err(Box::new(
                (StatusCode::BAD_REQUEST, "Passkey already registered").into_response(),
            ));
        }
        Ok(None) => {}
        Err(err) => {
            error!(
                user_id = %user_id,
                request_id = %request_id,
                "passkey registration lookup failed: {err}"
            );
            return Err(Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()));
        }
    }

    let passkey_data = match serialize_passkey(passkey) {
        Ok(data) => data,
        Err(err) => {
            error!(
                user_id = %user_id,
                request_id = %request_id,
                "passkey serialization failed: {err}"
            );
            return Err(Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()));
        }
    };

    if let Err(err) =
        PasskeyRepo::create_passkey(pool, user_id, credential_id, &passkey_data, None).await
    {
        error!(
            user_id = %user_id,
            request_id = %request_id,
            "passkey persistence failed: {err}"
        );
        return Err(Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response()));
    }

    if let Err(err) =
        PasskeyRepo::log_audit(pool, user_id, Some(credential_id), "register", ip, None).await
    {
        warn!(
            user_id = %user_id,
            request_id = %request_id,
            "passkey audit log failed: {err}"
        );
    }

    Ok(())
}

fn decode_credential_id(encoded: &str) -> Result<Vec<u8>, HandlerError> {
    let trimmed = encoded.trim();
    if trimmed.is_empty() {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, "Invalid credential id").into_response(),
        ));
    }

    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|_| Box::new((StatusCode::BAD_REQUEST, "Invalid credential id").into_response()))
}

async fn require_zero_token(
    headers: &HeaderMap,
    admission: &AdmissionVerifier,
) -> Result<(), HandlerError> {
    let Some(zero_token) = headers
        .get(ZERO_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
    else {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, "Missing zero token").into_response(),
        ));
    };

    if verify_token(admission, &zero_token).await {
        Ok(())
    } else {
        Err(Box::new(
            (StatusCode::BAD_REQUEST, "Invalid token").into_response(),
        ))
    }
}

fn enforce_rate_limits(
    headers: &HeaderMap,
    auth_state: &AuthState,
    email: &str,
) -> Result<(), HandlerError> {
    let client_ip = extract_client_ip(headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Login)
        == RateLimitDecision::Limited
    {
        return Err(Box::new(
            (StatusCode::TOO_MANY_REQUESTS, "Rate limited").into_response(),
        ));
    }

    if auth_state
        .rate_limiter()
        .check_email(email, RateLimitAction::Login)
        == RateLimitDecision::Limited
    {
        return Err(Box::new(
            (StatusCode::TOO_MANY_REQUESTS, "Rate limited").into_response(),
        ));
    }

    Ok(())
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

async fn fetch_display_name(pool: &PgPool, user_id: Uuid) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT display_name FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|row| row.try_get("display_name").ok()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::auth::hash_session_token;
    use crate::api::handlers::auth::{AuthConfig, AuthState, NoopRateLimiter, OpaqueState};
    use admission_token::{
        AdmissionTokenFooter, PaserkKey, PaserkKeySet, build_token, encode_signing_input,
    };
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header::CONTENT_TYPE},
        routing::{delete, get, post},
    };
    use chrono::Utc;
    use ed25519_dalek::Signer;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use sqlx::{Connection, PgConnection, PgPool, postgres::PgPoolOptions};
    use test_support::{postgres::PostgresContainer, runtime};
    use tokio::time::Duration;
    use tower::ServiceExt;

    const PERMESI_SCHEMA_SQL: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../db/sql/02_permesi.sql"
    ));

    struct TestDb {
        _postgres: PostgresContainer,
        pool: PgPool,
    }

    impl TestDb {
        async fn new() -> anyhow::Result<Self> {
            if let Err(err) = runtime::ensure_container_runtime() {
                eprintln!("Skipping integration test: {err}");
                return Err(err);
            }

            let postgres = PostgresContainer::start("bridge").await?;
            postgres.wait_until_ready().await?;
            apply_schema(&postgres).await?;

            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&postgres.admin_dsn())
                .await?;

            Ok(Self {
                _postgres: postgres,
                pool,
            })
        }
    }

    async fn apply_schema(postgres: &PostgresContainer) -> anyhow::Result<()> {
        let mut connection = PgConnection::connect(&postgres.admin_dsn()).await?;

        for statement in split_sql_statements(PERMESI_SCHEMA_SQL) {
            sqlx::query(&statement).execute(&mut connection).await?;
        }

        Ok(())
    }

    fn split_sql_statements(sql: &str) -> Vec<String> {
        let mut statements = Vec::new();
        let mut current = String::new();

        for line in sql.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("\\ir ") {
                continue;
            }
            current.push_str(line);
            current.push('\n');
            if trimmed.ends_with(';') {
                let statement = current.trim();
                if !statement.is_empty() {
                    statements.push(statement.to_string());
                }
                current.clear();
            }
        }

        statements
    }

    async fn insert_user(pool: &PgPool) -> anyhow::Result<(Uuid, String)> {
        let user_id = Uuid::new_v4();
        let email = format!("user-{}@example.com", user_id.simple());
        let mut record = vec![0u8; 32];
        OsRng.fill_bytes(&mut record);
        sqlx::query(
            "INSERT INTO users (id, email, opaque_registration_record, status, display_name) VALUES ($1, $2, $3, 'active', 'Example User')",
        )
        .bind(user_id)
        .bind(&email)
        .bind(record)
        .execute(pool)
        .await?;
        Ok((user_id, email))
    }

    async fn insert_session(pool: &PgPool, user_id: Uuid) -> anyhow::Result<String> {
        let token = crate::api::handlers::auth::generate_session_token()?;
        let hash = hash_session_token(&token);
        sqlx::query(
            "INSERT INTO user_sessions (user_id, session_hash, expires_at, auth_time) VALUES ($1, $2, NOW() + INTERVAL '1 hour', NOW())",
        )
        .bind(user_id)
        .bind(hash)
        .execute(pool)
        .await?;
        Ok(token)
    }

    fn build_admission() -> anyhow::Result<(Arc<AdmissionVerifier>, String)> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let key = PaserkKey::from_ed25519_public_key_bytes(&verifying_key.to_bytes())?;
        let keyset = PaserkKeySet {
            version: "v4".to_string(),
            purpose: "public".to_string(),
            active_kid: key.kid.clone(),
            keys: vec![key.clone()],
        };
        let admission = Arc::new(AdmissionVerifier::new(
            keyset,
            "https://genesis.test".to_string(),
            "permesi".to_string(),
        ));

        let now_unix = Utc::now().timestamp();
        let admission_claims = admission_token::AdmissionTokenClaims {
            iss: "https://genesis.test".to_string(),
            aud: "permesi".to_string(),
            iat: admission_token::rfc3339_from_unix(now_unix)?,
            exp: admission_token::rfc3339_from_unix(now_unix + 600)?,
            jti: "test".to_string(),
            sub: None,
            action: "zero".to_string(),
        };
        let footer = AdmissionTokenFooter { kid: key.kid };
        let signing_input = encode_signing_input(&admission_claims, &footer)?;
        let signature = signing_key.sign(&signing_input.pre_auth);
        let token = build_token(
            &signing_input.payload,
            &signing_input.footer,
            &signature.to_bytes(),
        );

        Ok((admission, token))
    }

    #[tokio::test]
    async fn register_options_returns_public_key() -> anyhow::Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };

        let (user_id, _email) = insert_user(&db.pool).await?;
        let session_token = insert_session(&db.pool, user_id).await?;

        let auth_config = AuthConfig::new("https://permesi.dev".to_string());
        let auth_state = Arc::new(AuthState::new(
            auth_config.clone(),
            OpaqueState::from_seed(
                [0u8; 32],
                "api.permesi.dev".to_string(),
                Duration::from_secs(300),
            ),
            Arc::new(NoopRateLimiter),
            crate::api::handlers::auth::mfa::MfaConfig::new(),
        ));

        let passkey_config = crate::webauthn::PasskeyConfig::new(
            auth_config.webauthn_rp_id().to_string(),
            "Permesi".to_string(),
            vec![auth_config.webauthn_rp_origin().to_string()],
            Duration::from_secs(300),
            true,
        )?;
        let passkey_service = Arc::new(PasskeyService::new(passkey_config)?);

        let (admission, zero_token) = build_admission()?;

        let app = Router::new()
            .route("/v1/me/webauthn/register/options", post(register_options))
            .layer(Extension(auth_state))
            .layer(Extension(admission))
            .layer(Extension(passkey_service))
            .layer(Extension(db.pool));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/me/webauthn/register/options")
                    .header("Origin", "https://permesi.dev")
                    .header("X-Permesi-Zero-Token", zero_token)
                    .header(CONTENT_TYPE, "application/json")
                    .header("Cookie", format!("permesi_session={session_token}"))
                    .body(Body::from("{}"))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let payload: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(payload.get("reg_id").and_then(|v| v.as_str()).is_some());
        assert!(
            payload
                .get("challenge")
                .and_then(|v| v.get("publicKey"))
                .is_some()
        );

        Ok(())
    }

    #[tokio::test]
    async fn list_credentials_returns_empty_in_preview_mode() -> anyhow::Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };

        let (user_id, _email) = insert_user(&db.pool).await?;
        let session_token = insert_session(&db.pool, user_id).await?;

        let passkey_config = crate::webauthn::PasskeyConfig::new(
            "permesi.dev".to_string(),
            "Permesi".to_string(),
            vec!["https://permesi.dev".to_string()],
            Duration::from_secs(300),
            true,
        )?;
        let passkey_service = Arc::new(PasskeyService::new(passkey_config)?);

        let app = Router::new()
            .route("/v1/me/webauthn/credentials", get(list_credentials))
            .layer(Extension(passkey_service))
            .layer(Extension(db.pool));

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/me/webauthn/credentials")
                    .header("Cookie", format!("permesi_session={session_token}"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let payload: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload
                .get("preview_mode")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            payload
                .get("credentials")
                .and_then(|v| v.as_array())
                .map(Vec::len),
            Some(0)
        );

        Ok(())
    }

    #[tokio::test]
    async fn delete_credential_requires_zero_token() -> anyhow::Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };

        let (user_id, _email) = insert_user(&db.pool).await?;
        let session_token = insert_session(&db.pool, user_id).await?;

        let auth_config = AuthConfig::new("https://permesi.dev".to_string());
        let auth_state = Arc::new(AuthState::new(
            auth_config.clone(),
            OpaqueState::from_seed(
                [0u8; 32],
                "api.permesi.dev".to_string(),
                Duration::from_secs(300),
            ),
            Arc::new(NoopRateLimiter),
            crate::api::handlers::auth::mfa::MfaConfig::new(),
        ));

        let passkey_config = crate::webauthn::PasskeyConfig::new(
            auth_config.webauthn_rp_id().to_string(),
            "Permesi".to_string(),
            vec![auth_config.webauthn_rp_origin().to_string()],
            Duration::from_secs(300),
            false,
        )?;
        let passkey_service = Arc::new(PasskeyService::new(passkey_config)?);
        let (admission, _zero_token) = build_admission()?;

        let app = Router::new()
            .route(
                "/v1/me/webauthn/credentials/:credential_id",
                delete(delete_credential),
            )
            .layer(Extension(auth_state))
            .layer(Extension(admission))
            .layer(Extension(passkey_service))
            .layer(Extension(db.pool));

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/me/webauthn/credentials/AA")
                    .header("Cookie", format!("permesi_session={session_token}"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        assert_eq!(std::str::from_utf8(&body)?, "Missing zero token");

        Ok(())
    }

    #[tokio::test]
    async fn delete_credential_rejects_invalid_credential_id() -> anyhow::Result<()> {
        let Ok(db) = TestDb::new().await else {
            return Ok(());
        };

        let (user_id, _email) = insert_user(&db.pool).await?;
        let session_token = insert_session(&db.pool, user_id).await?;

        let auth_config = AuthConfig::new("https://permesi.dev".to_string());
        let auth_state = Arc::new(AuthState::new(
            auth_config.clone(),
            OpaqueState::from_seed(
                [0u8; 32],
                "api.permesi.dev".to_string(),
                Duration::from_secs(300),
            ),
            Arc::new(NoopRateLimiter),
            crate::api::handlers::auth::mfa::MfaConfig::new(),
        ));

        let passkey_config = crate::webauthn::PasskeyConfig::new(
            auth_config.webauthn_rp_id().to_string(),
            "Permesi".to_string(),
            vec![auth_config.webauthn_rp_origin().to_string()],
            Duration::from_secs(300),
            false,
        )?;
        let passkey_service = Arc::new(PasskeyService::new(passkey_config)?);
        let (admission, zero_token) = build_admission()?;

        let app = Router::new()
            .route(
                "/v1/me/webauthn/credentials/:credential_id",
                delete(delete_credential),
            )
            .layer(Extension(auth_state))
            .layer(Extension(admission))
            .layer(Extension(passkey_service))
            .layer(Extension(db.pool));

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/me/webauthn/credentials/0")
                    .header("Cookie", format!("permesi_session={session_token}"))
                    .header("X-Permesi-Zero-Token", zero_token)
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        assert_eq!(std::str::from_utf8(&body)?, "Invalid credential id");

        Ok(())
    }
}
