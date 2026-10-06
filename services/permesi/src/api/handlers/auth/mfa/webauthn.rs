//! `WebAuthn` (Security Key) handlers for MFA registration and authentication.
//!
//! This module provides endpoints for users to register physical security keys
//! as an additional authentication factor and verify them during challenge sessions.

use crate::{
    api::handlers::auth::{
        AuthState,
        authority_guard::{AuthorityGuard, Policy},
        mfa::{MfaState, storage as mfa_storage},
        principal::{require_any_auth, require_mfa_challenge},
        session::extract_session_token,
        types::{
            WebauthnAuthenticateFinishRequest, WebauthnAuthenticateStartResponse,
            WebauthnRegisterFinishRequest, WebauthnRegisterStartResponse,
        },
        utils::extract_client_ip,
        utils::hash_session_token,
    },
    webauthn::{SecurityKeyRepo, SecurityKeyService},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use sha2::Digest;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;
use webauthn_rs::prelude::*;

type HandlerError = Box<axum::response::Response>;

/// Starts the registration of a new `WebAuthn` security key.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/webauthn/register/start",
    responses(
        (status = 503, description = "Authentication storage unavailable"),
        (status = 200, description = "Registration challenge generated", body = WebauthnRegisterStartResponse),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn register_start(
    headers: HeaderMap,
    pool: State<PgPool>,
    webauthn_service: State<Arc<SecurityKeyService>>,
) -> axum::response::Response {
    let principal = match require_any_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Some(session_token) = extract_session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let session_hash = hash_session_token(&session_token);
    let origin = match extract_origin(&headers, webauthn_service.0.as_ref()) {
        Ok(origin) => origin,
        Err(response) => return *response,
    };

    match webauthn_service
        .register_begin(principal.user_id, &principal.email, &origin, &session_hash)
        .await
    {
        Ok((challenge, reg_id)) => (
            StatusCode::OK,
            Json(WebauthnRegisterStartResponse {
                reg_id: reg_id.to_string(),
                challenge: serde_json::to_value(challenge).unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(err) => {
            error!("Failed to start WebAuthn registration: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Finishes the registration of a new `WebAuthn` security key.
///
/// Side Effects:
/// - Enables MFA (`MfaState::Enabled`) for the user if not already enabled.
/// - Logs an audit event.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/webauthn/register/finish",
    request_body = WebauthnRegisterFinishRequest,
    responses(
        (status = 503, description = "Authentication storage unavailable"),
        (status = 204, description = "Security key registered successfully"),
        (status = 400, description = "Invalid registration response"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn register_finish(
    headers: HeaderMap,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    webauthn_service: State<Arc<SecurityKeyService>>,
    payload: Option<Json<WebauthnRegisterFinishRequest>>,
) -> axum::response::Response {
    let principal = match require_any_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Some(Json(request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload").into_response();
    };

    let Ok(reg_id) = Uuid::parse_str(&request.reg_id) else {
        return (StatusCode::BAD_REQUEST, "Invalid registration ID").into_response();
    };

    let Some(session_token) = extract_session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let session_hash = hash_session_token(&session_token);
    let origin = match extract_origin(&headers, webauthn_service.0.as_ref()) {
        Ok(origin) => origin,
        Err(response) => return *response,
    };

    let reg_response: RegisterPublicKeyCredential = match serde_json::from_value(request.response) {
        Ok(res) => res,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid WebAuthn response: {err}"),
            )
                .into_response();
        }
    };

    let client_ip = extract_client_ip(&headers);

    match webauthn_service
        .verify_registration(
            reg_id,
            &origin,
            reg_response,
            principal.user_id,
            &session_hash,
        )
        .await
    {
        Ok(key) => {
            let mut guard = match AuthorityGuard::acquire(
                &pool,
                &headers,
                principal.user_id,
                Policy::Enrollment,
                auth_state.config().opaque_exchange_timeout_ms(),
            )
            .await
            {
                Ok(guard) => guard,
                Err(status) => return status.into_response(),
            };

            if persist_registered_key(
                guard.connection(),
                principal.user_id,
                &key,
                &request.label,
                client_ip.as_deref(),
            )
            .await
            .is_err()
            {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            match guard.issue_full(&auth_state).await {
                Ok(cookie) => (
                    StatusCode::NO_CONTENT,
                    [(axum::http::header::SET_COOKIE, cookie)],
                )
                    .into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(err) => {
            error!("Failed to finish WebAuthn registration: {err}");
            (StatusCode::BAD_REQUEST, "Registration failed".to_string()).into_response()
        }
    }
}

/// Saves the verified key, preserved recovery batch and audit atomically with current session authority.
async fn persist_registered_key(
    connection: &mut sqlx::PgConnection,
    user: Uuid,
    key: &SecurityKey,
    label: &str,
    ip: Option<&str>,
) -> anyhow::Result<()> {
    SecurityKeyRepo::create_key(
        &mut *connection,
        user,
        key.cred_id().as_slice(),
        &serde_json::to_vec(key)?,
        label,
        0,
    )
    .await?;
    let batch = mfa_storage::load_mfa_state(&mut *connection, user)
        .await?
        .and_then(|r| r.recovery_batch_id);
    mfa_storage::upsert_mfa_state(&mut *connection, user, MfaState::Enabled, batch).await?;
    sqlx::query("INSERT INTO security_key_audit_log (user_id,credential_id,action,ip_address) VALUES ($1,$2,'register',$3::inet)")
        .bind(user).bind(key.cred_id().as_slice()).bind(ip).execute(&mut *connection).await?;
    Ok(())
}

/// Starts the authentication flow for a `WebAuthn` security key.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/webauthn/authenticate/start",
    responses(
        (status = 503, description = "Authentication storage unavailable"),
        (status = 200, description = "Authentication challenge generated", body = WebauthnAuthenticateStartResponse),
        (status = 401, description = "Unauthorized"),
        (status = 400, description = "Authentication unavailable")
    ),
    tag = "auth"
)]
pub async fn authenticate_start(
    headers: HeaderMap,
    pool: State<PgPool>,
    webauthn_service: State<Arc<SecurityKeyService>>,
) -> axum::response::Response {
    let principal = match require_mfa_challenge(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Some(session_token) = extract_session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let session_hash = hash_session_token(&session_token);
    let origin = match extract_origin(&headers, webauthn_service.0.as_ref()) {
        Ok(origin) => origin,
        Err(response) => return *response,
    };

    if let Ok((challenge, auth_id)) = webauthn_service
        .auth_begin(principal.user_id, &origin, &session_hash)
        .await
    {
        (
            StatusCode::OK,
            Json(WebauthnAuthenticateStartResponse {
                auth_id: auth_id.to_string(),
                challenge: serde_json::to_value(challenge).unwrap_or_default(),
            }),
        )
            .into_response()
    } else {
        error!("Failed to start WebAuthn authentication");
        (StatusCode::BAD_REQUEST, "Authentication unavailable").into_response()
    }
}

/// Finishes the `WebAuthn` authentication flow and upgrades the session.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/webauthn/authenticate/finish",
    request_body = WebauthnAuthenticateFinishRequest,
    responses(
        (status = 503, description = "Authentication storage unavailable"),
        (status = 204, description = "Authentication successful"),
        (status = 400, description = "Invalid authentication response"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn authenticate_finish(
    headers: HeaderMap,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    webauthn_service: State<Arc<SecurityKeyService>>,
    payload: Option<Json<WebauthnAuthenticateFinishRequest>>,
) -> axum::response::Response {
    let principal = match require_mfa_challenge(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Some(Json(request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload").into_response();
    };

    let Ok(auth_id) = Uuid::parse_str(&request.auth_id) else {
        return (StatusCode::BAD_REQUEST, "Invalid authentication ID").into_response();
    };

    let Some(session_token) = extract_session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let session_hash = hash_session_token(&session_token);
    let origin = match extract_origin(&headers, webauthn_service.0.as_ref()) {
        Ok(origin) => origin,
        Err(response) => return *response,
    };

    let auth_response: PublicKeyCredential = match serde_json::from_value(request.response) {
        Ok(res) => res,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid WebAuthn response: {err}"),
            )
                .into_response();
        }
    };

    let client_ip = extract_client_ip(&headers);

    match webauthn_service
        .auth_finish(
            auth_id,
            &origin,
            auth_response,
            principal.user_id,
            &session_hash,
        )
        .await
    {
        Ok(proof) => {
            let mut guard = match AuthorityGuard::acquire(
                &pool,
                &headers,
                principal.user_id,
                Policy::Challenge,
                auth_state.config().opaque_exchange_timeout_ms(),
            )
            .await
            {
                Ok(guard) => guard,
                Err(status) => return status.into_response(),
            };

            let current = sqlx::query_as::<_, (Uuid, Vec<u8>)>(
                "SELECT user_id,public_key FROM security_keys WHERE credential_id=$1 FOR SHARE",
            )
            .bind(&proof.id)
            .fetch_optional(guard.connection())
            .await;
            if !matches!(current,Ok(Some((user,key))) if user==principal.user_id && user==proof.user && <[u8;32]>::from(sha2::Sha256::digest(&key))==proof.fingerprint)
            {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            match guard.issue_full(&auth_state).await {
                Ok(cookie) => (
                    StatusCode::NO_CONTENT,
                    [(axum::http::header::SET_COOKIE, cookie)],
                )
                    .into_response(),
                Err(status) => status.into_response(),
            }
        }
        Err(err) => {
            error!("Failed to finish WebAuthn authentication: {err}");
            let _ = SecurityKeyRepo::log_audit(
                &pool,
                principal.user_id,
                None,
                "verify_failure",
                client_ip.as_deref(),
                None,
            )
            .await;
            (StatusCode::BAD_REQUEST, "Authentication failed".to_string()).into_response()
        }
    }
}

/// Extract and normalize the browser `Origin` for `WebAuthn` MFA flows.
///
/// The origin must be explicitly configured for the security-key service and
/// is bound to the in-progress challenge state.
fn extract_origin(
    headers: &HeaderMap,
    webauthn_service: &SecurityKeyService,
) -> Result<String, HandlerError> {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Box::new((StatusCode::BAD_REQUEST, "Missing Origin header").into_response())
        })?;

    webauthn_service
        .match_origin(origin)
        .ok_or_else(|| Box::new((StatusCode::BAD_REQUEST, "Origin not allowed").into_response()))
}

/// Deletes a registered `WebAuthn` security key.
///
/// Side Effects:
/// - Disables MFA (`MfaState::Disabled`) if this was the last security key AND no TOTP is configured.
/// - Logs an audit event.
#[utoipa::path(
    delete,
    path = "/v1/me/mfa/webauthn/{credential_id}",
    params(
        ("credential_id" = String, Path, description = "Hex-encoded credential ID")
    ),
    responses(
        (status = 503, description = "Authentication storage unavailable"),
        (status = 204, description = "Security key deleted successfully"),
        (status = 400, description = "Invalid credential id"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Security key not found")
    ),
    tag = "me"
)]
pub async fn delete_key(
    Path(credential_id_hex): Path<String>,
    headers: HeaderMap,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
) -> axum::response::Response {
    let principal = match require_any_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Ok(credential_id) = hex::decode(credential_id_hex.trim()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let mut guard = match AuthorityGuard::acquire(
        &pool,
        &headers,
        principal.user_id,
        Policy::Enrollment,
        auth_state.config().opaque_exchange_timeout_ms(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(status) => return status.into_response(),
    };
    let result = sqlx::query("DELETE FROM security_keys WHERE user_id=$1 AND credential_id=$2")
        .bind(principal.user_id)
        .bind(&credential_id)
        .execute(guard.connection())
        .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let remaining = sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM security_keys WHERE user_id=$1) OR EXISTS(SELECT 1 FROM totp_credentials WHERE user_id=$1 AND confirmed_at IS NOT NULL)").bind(principal.user_id).fetch_one(guard.connection()).await;
    match remaining {
        Ok(true) => {}
        Ok(false) => {
            if mfa_storage::upsert_mfa_state(
                guard.connection(),
                principal.user_id,
                MfaState::Disabled,
                None,
            )
            .await
            .is_err()
            {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    if sqlx::query("INSERT INTO security_key_audit_log (user_id,action,ip_address) VALUES ($1,'delete',$2::inet)").bind(principal.user_id).bind(extract_client_ip(&headers)).execute(guard.connection()).await.is_err() || guard.commit().await.is_err() { return StatusCode::SERVICE_UNAVAILABLE.into_response(); }
    StatusCode::NO_CONTENT.into_response()
}
