//! Passkey (`WebAuthn`) handlers for authenticated user self-service.
//!
//! This module provides endpoints for users to register, list, and delete
//! passkeys. It integrates with the OPAQUE authentication system and
//! requires a fresh zero token for sensitive registration actions.

use axum::{
    Json,
    body::Bytes,
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use service_utils::request_id::RequestId;
use sqlx::{PgConnection, PgPool, Row};
use std::sync::Arc;
use tracing::{error, info, warn};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, RegisterPublicKeyCredential};

use super::{
    AdmissionVerifier,
    auth::{
        AuthState, RateLimitAction,
        authority_guard::{AuthorityGuard, FACTOR_RECENT_AUTH_SECONDS},
        extract_client_ip, hash_session_token,
        principal::require_auth,
        session::extract_session_token,
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
        (status = 503, description = "Authentication storage unavailable"),
        (status = 429, description = "Authentication capacity or rate limit exceeded"),
        (status = 200, description = "Passkey registration options", body = PasskeyRegisterOptionsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized or recent authentication required"),
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
    Extension(request_id): Extension<RequestId>,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    passkey_service: State<Arc<PasskeyService>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };
    if !super::me::recent_auth_ok(&principal) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let request_id = request_id.to_string();
    info!(
        user_id = %principal.user_id,
        request_id = %request_id,
        "passkey register options requested"
    );

    if let Err(response) = enforce_rate_limits(&headers, &auth_state, &principal.email).await {
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
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
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
            crate::webauthn::exchange::error_response(&err)
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
        (status = 503, description = "Authentication storage unavailable"),
        (status = 429, description = "Authentication capacity or rate limit exceeded"),
        (status = 200, description = "Passkey registration finished", body = PasskeyRegisterFinishResponse),
        (status = 400, description = "Invalid registration response"),
        (status = 401, description = "Unauthorized or recent authentication required"),
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
    Extension(request_id): Extension<RequestId>,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    passkey_service: State<Arc<PasskeyService>>,
    body: Bytes,
) -> impl IntoResponse {
    let context = match load_register_finish_context(
        &headers,
        request_id,
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

            let mut guard = match AuthorityGuard::acquire_recent_full(
                &pool,
                &headers,
                context.user_id,
                auth_state.config().opaque_exchange_timeout_ms(),
                FACTOR_RECENT_AUTH_SECONDS,
            )
            .await
            {
                Ok(guard) => guard,
                Err(status) => return status.into_response(),
            };
            if let Err(response) = persist_passkey(
                guard.connection(),
                context.user_id,
                &passkey,
                &context.request_id,
                extract_client_ip(&headers).as_deref(),
            )
            .await
            {
                return *response;
            }

            if guard.commit().await.is_err() {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
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
                PasskeyRegistrationError::Unavailable => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authentication temporarily unavailable",
                ),
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
        (status = 503, description = "Authentication storage unavailable"),
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
    Extension(request_id): Extension<RequestId>,
    pool: State<PgPool>,
    passkey_service: State<Arc<PasskeyService>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let request_id = request_id.to_string();
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
        (status = 503, description = "Authentication storage unavailable"),
        (status = 204, description = "Passkey deleted"),
        (status = 400, description = "Invalid credential id or missing zero token"),
        (status = 401, description = "Unauthorized or recent authentication required"),
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
    Extension(request_id): Extension<RequestId>,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    passkey_service: State<Arc<PasskeyService>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let request_id = request_id.to_string();
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

    let mut guard = match AuthorityGuard::acquire_recent_full(
        &pool,
        &headers,
        principal.user_id,
        auth_state.config().opaque_exchange_timeout_ms(),
        FACTOR_RECENT_AUTH_SECONDS,
    )
    .await
    {
        Ok(guard) => guard,
        Err(status) => return status.into_response(),
    };
    let deleted = sqlx::query("DELETE FROM passkeys WHERE user_id=$1 AND credential_id=$2")
        .bind(principal.user_id)
        .bind(&credential_id)
        .execute(guard.connection())
        .await;
    match deleted {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    if sqlx::query(
        "INSERT INTO passkey_audit_log (user_id,action,ip_address) VALUES ($1,'delete',$2::inet)",
    )
    .bind(principal.user_id)
    .bind(extract_client_ip(&headers))
    .execute(guard.connection())
    .await
    .is_err()
        || guard.commit().await.is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
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
    request_id: RequestId,
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
    if !super::me::recent_auth_ok(&principal) {
        return Err(Box::new(StatusCode::UNAUTHORIZED.into_response()));
    }

    let request_id = request_id.to_string();
    info!(
        user_id = %principal.user_id,
        request_id = %request_id,
        "passkey register finish requested"
    );

    let (reg_id, reg_response) = parse_register_finish(body)?;

    if let Err(response) = enforce_rate_limits(headers, auth_state, &principal.email).await {
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

/// Persists a verified credential and audit in the current-session lifecycle transaction.
async fn persist_passkey(
    connection: &mut PgConnection,
    user_id: Uuid,
    passkey: &Passkey,
    request_id: &str,
    ip: Option<&str>,
) -> Result<(), HandlerError> {
    let data = serialize_passkey(passkey)
        .map_err(|_| Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
    let result = sqlx::query("INSERT INTO passkeys (credential_id,user_id,passkey_data) VALUES ($1,$2,$3) ON CONFLICT (credential_id) DO NOTHING")
        .bind(passkey.cred_id().as_slice()).bind(user_id).bind(data).execute(&mut *connection).await.map_err(|_|Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
    if result.rows_affected() != 1 {
        warn!(
            request_id,
            "passkey registration rejected: credential already exists"
        );
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, "Passkey already registered").into_response(),
        ));
    }
    sqlx::query("INSERT INTO passkey_audit_log (user_id,credential_id,action,ip_address) VALUES ($1,$2,'register',$3::inet)")
        .bind(user_id).bind(passkey.cred_id().as_slice()).bind(ip).execute(&mut *connection).await.map_err(|_|Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
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

async fn enforce_rate_limits(
    headers: &HeaderMap,
    auth_state: &AuthState,
    email: &str,
) -> Result<(), HandlerError> {
    let client_ip = extract_client_ip(headers);
    if let Some(status) = auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::WebauthnEnrollment)
        .await
        .denial_status()
    {
        return Err(Box::new((status, "Rate limited").into_response()));
    }

    if let Some(status) = auth_state
        .rate_limiter()
        .check_email(email, RateLimitAction::WebauthnEnrollment)
        .await
        .denial_status()
    {
        return Err(Box::new((status, "Rate limited").into_response()));
    }

    Ok(())
}

async fn fetch_display_name(pool: &PgPool, user_id: Uuid) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT display_name FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|row| row.try_get("display_name").ok()))
}

#[cfg(test)]
mod tests;
