use crate::{
    api::handlers::auth::{
        AuthState,
        mfa::{MfaState, storage as mfa_storage},
        principal::{require_any_auth, require_mfa_challenge},
        session::session_cookie_with_ttl,
        storage::insert_session,
        types::{
            WebauthnAuthenticateFinishRequest, WebauthnAuthenticateStartResponse,
            WebauthnRegisterFinishRequest, WebauthnRegisterStartResponse,
        },
        utils::extract_client_ip,
    },
    webauthn::{SecurityKeyRepo, SecurityKeyService},
};
use axum::{
    Json,
    extract::{Extension, Path},
    http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Starts the registration of a new `WebAuthn` security key.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/webauthn/register/start",
    responses(
        (status = 200, description = "Registration challenge generated", body = WebauthnRegisterStartResponse),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn register_start(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    webauthn_service: Extension<Arc<SecurityKeyService>>,
) -> axum::response::Response {
    let principal = match require_any_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    match webauthn_service
        .register_begin(principal.user_id, &principal.email)
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
        (status = 204, description = "Security key registered successfully"),
        (status = 400, description = "Invalid registration response"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn register_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    webauthn_service: Extension<Arc<SecurityKeyService>>,
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
        .register_finish(reg_id, reg_response, principal.user_id, &request.label)
        .await
    {
        Ok(()) => {
            // Load existing MFA state to preserve recovery codes
            let recovery_batch_id =
                match mfa_storage::load_mfa_state(&pool, principal.user_id).await {
                    Ok(Some(record)) => record.recovery_batch_id,
                    Ok(None) => None,
                    Err(err) => {
                        error!("Failed to load MFA state: {err}");
                        // Proceed with None (safe fallback, but risk losing recovery codes if DB is flaky)
                        None
                    }
                };

            // Enable MFA for the user
            if let Err(err) = mfa_storage::upsert_mfa_state(
                &pool,
                principal.user_id,
                MfaState::Enabled,
                recovery_batch_id,
            )
            .await
            {
                error!("Failed to enable MFA after security key registration: {err}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            let _ = SecurityKeyRepo::log_audit(
                &pool,
                principal.user_id,
                None,
                "register",
                client_ip.as_deref(),
                None,
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => {
            error!("Failed to finish WebAuthn registration: {err}");
            (
                StatusCode::BAD_REQUEST,
                format!("Registration failed: {err}"),
            )
                .into_response()
        }
    }
}

/// Starts the authentication flow for a `WebAuthn` security key.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/webauthn/authenticate/start",
    responses(
        (status = 200, description = "Authentication challenge generated", body = WebauthnAuthenticateStartResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "No security keys registered")
    ),
    tag = "auth"
)]
pub async fn authenticate_start(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    webauthn_service: Extension<Arc<SecurityKeyService>>,
) -> axum::response::Response {
    let principal = match require_mfa_challenge(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    match webauthn_service.auth_begin(principal.user_id).await {
        Ok((challenge, auth_id)) => (
            StatusCode::OK,
            Json(WebauthnAuthenticateStartResponse {
                auth_id: auth_id.to_string(),
                challenge: serde_json::to_value(challenge).unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(err) => {
            error!("Failed to start WebAuthn authentication: {err}");
            (StatusCode::NOT_FOUND, err.to_string()).into_response()
        }
    }
}

/// Finishes the `WebAuthn` authentication flow and upgrades the session.
#[utoipa::path(
    post,
    path = "/v1/auth/mfa/webauthn/authenticate/finish",
    request_body = WebauthnAuthenticateFinishRequest,
    responses(
        (status = 204, description = "Authentication successful"),
        (status = 400, description = "Invalid authentication response"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
pub async fn authenticate_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    webauthn_service: Extension<Arc<SecurityKeyService>>,
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

    match webauthn_service.auth_finish(auth_id, auth_response).await {
        Ok(_) => {
            // Success: Upgrade to full session
            let (token, ttl_seconds) = match insert_session(
                &pool,
                principal.user_id,
                auth_state.config().session_ttl_seconds(),
            )
            .await
            {
                Ok(token) => (token, auth_state.config().session_ttl_seconds()),
                Err(err) => {
                    error!("Failed to create full session after WebAuthn auth: {err}");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };

            let _ = SecurityKeyRepo::log_audit(
                &pool,
                principal.user_id,
                None,
                "verify_success",
                client_ip.as_deref(),
                None,
            )
            .await;

            let mut response_headers = HeaderMap::new();
            match session_cookie_with_ttl(&auth_state, &token, ttl_seconds) {
                Ok(cookie) => {
                    response_headers.insert(axum::http::header::SET_COOKIE, cookie);
                    if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
                    {
                        response_headers.insert(AUTHORIZATION, value);
                    }
                    (StatusCode::NO_CONTENT, response_headers).into_response()
                }
                Err(err) => {
                    error!("Failed to set session cookie: {err}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
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
            (
                StatusCode::BAD_REQUEST,
                format!("Authentication failed: {err}"),
            )
                .into_response()
        }
    }
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
        (status = 204, description = "Security key deleted successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Security key not found")
    ),
    tag = "me"
)]
pub async fn delete_key(
    Path(credential_id_hex): Path<String>,
    headers: HeaderMap,
    pool: Extension<PgPool>,
) -> axum::response::Response {
    let principal = match require_any_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let Ok(credential_id) = hex::decode(credential_id_hex.trim()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let client_ip = extract_client_ip(&headers);

    match SecurityKeyRepo::delete_key(&pool, principal.user_id, &credential_id).await {
        Ok(true) => {
            let _ = SecurityKeyRepo::log_audit(
                &pool,
                principal.user_id,
                Some(&credential_id),
                "delete",
                client_ip.as_deref(),
                None,
            )
            .await;

            // Check if we need to disable MFA
            let remaining_keys = SecurityKeyRepo::list_user_keys(&pool, principal.user_id)
                .await
                .unwrap_or_default();

            let mfa_record = mfa_storage::load_mfa_state(&pool, principal.user_id)
                .await
                .unwrap_or(None);

            let has_totp = mfa_record
                .as_ref()
                .is_some_and(|r| r.recovery_batch_id.is_some());

            if remaining_keys.is_empty()
                && !has_totp
                && let Err(e) = mfa_storage::upsert_mfa_state(
                    &pool,
                    principal.user_id,
                    MfaState::Disabled,
                    None,
                )
                .await
            {
                error!("Failed to disable MFA after last key deletion: {e}");
            }

            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            error!("Failed to delete security key: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
