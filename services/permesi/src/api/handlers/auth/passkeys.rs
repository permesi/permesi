//! Passkey login endpoints.
//!
//! Flow Overview:
//! 1) Validate zero-token + rate limits, then generate a passkey authentication challenge.
//! 2) Store the authentication state with a short TTL.
//! 3) Verify the authenticator response and mint a session like password login.
//!
//! Security boundaries:
//! - Origin and RP ID validation are enforced on every request.
//! - Authentication challenges are single-use and expire quickly.
//! - Passkey data and raw `WebAuthn` payloads are never logged.

use crate::api::handlers::{
    AdmissionVerifier,
    auth::{
        AuthState, RateLimitAction, RateLimitDecision,
        mfa::{self, MfaState},
        session::session_cookie_with_ttl,
        storage::{insert_mfa_bootstrap_session, insert_mfa_challenge_session, insert_session},
        utils::extract_client_ip,
        zero_token::{require_zero_token, zero_token_error_response},
    },
};
use crate::webauthn::{
    PasskeyCredential, PasskeyRepo, PasskeyService, deserialize_passkey, serialize_passkey,
};
use axum::{
    Json,
    body::Bytes,
    extract::Extension,
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, DiscoverableKey, Passkey, PublicKeyCredential};

const MAX_WEBAUTHN_JSON_BYTES: usize = 32 * 1024;
type HandlerError = Box<axum::response::Response>;

#[derive(Debug, Deserialize, ToSchema)]
pub struct PasskeyLoginStartRequest {}

#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyLoginStartResponse {
    pub auth_id: String,
    pub challenge: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLoginFinishRequest {
    pub auth_id: String,
    pub response: serde_json::Value,
}

#[utoipa::path(
    post,
    path = "/v1/auth/passkey/login/start",
    request_body = PasskeyLoginStartRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "Passkey login started", body = PasskeyLoginStartResponse),
        (status = 400, description = "Invalid request"),
        (status = 429, description = "Rate limited")
    ),
    tag = "auth"
)]
/// Start passkey login by issuing an authentication challenge.
pub async fn passkey_login_start(
    headers: HeaderMap,
    auth_state: Extension<Arc<AuthState>>,
    admission: Extension<Arc<AdmissionVerifier>>,
    passkey_service: Extension<Arc<PasskeyService>>,
    payload: Option<Json<PasskeyLoginStartRequest>>,
) -> impl IntoResponse {
    let request_id = request_id(&headers);
    let Some(Json(_request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response();
    };

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Login)
        .await
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    if passkey_service.config().preview_mode() {
        return (
            StatusCode::BAD_REQUEST,
            "Passkey login is unavailable in preview mode".to_string(),
        )
            .into_response();
    }

    let origin = match extract_origin(&headers, &passkey_service) {
        Ok(origin) => origin,
        Err(response) => return *response,
    };

    info!(
        request_id = %request_id,
        "passkey login start requested"
    );

    match passkey_service.auth_begin(&origin).await {
        Ok((auth_id, challenge)) => (
            StatusCode::OK,
            Json(PasskeyLoginStartResponse {
                auth_id: auth_id.to_string(),
                challenge: serde_json::to_value(challenge).unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(err) => {
            error!(
                request_id = %request_id,
                "failed to start passkey login: {err}"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed".to_string(),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/auth/passkey/login/finish",
    request_body = PasskeyLoginFinishRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Passkey login finished"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
/// Finish passkey login and issue a session cookie.
pub async fn passkey_login_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    admission: Extension<Arc<AdmissionVerifier>>,
    passkey_service: Extension<Arc<PasskeyService>>,
    body: Bytes,
) -> impl IntoResponse {
    let request_id = request_id(&headers);
    let request = match parse_passkey_finish(&body) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Login)
        .await
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let origin = match extract_origin(&headers, &passkey_service) {
        Ok(origin) => origin,
        Err(response) => return *response,
    };

    if passkey_service.config().preview_mode() {
        return (
            StatusCode::BAD_REQUEST,
            "Passkey login unavailable".to_string(),
        )
            .into_response();
    }

    let Ok(auth_id) = Uuid::parse_str(&request.auth_id) else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid authentication id".to_string(),
        )
            .into_response();
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

    let (user_id, auth_result) = match verify_passkey_assertion(
        &pool,
        &passkey_service,
        auth_id,
        &origin,
        auth_response,
        &request_id,
    )
    .await
    {
        Ok(verified) => verified,
        Err(response) => return *response,
    };

    if let Err(response) = update_passkey_after_auth(
        &pool,
        user_id,
        &auth_result,
        &request_id,
        client_ip.as_deref(),
    )
    .await
    {
        return *response;
    }

    issue_session_for_user(&pool, &auth_state, user_id, &request_id).await
}

/// Resolve a discoverable credential and verify its proof before trusting its user handle.
///
/// Every pre-verification failure consumes the pending challenge. Account status is checked
/// only after `webauthn-rs` has authenticated the stored credential, so untrusted assertion
/// fields cannot select a session identity or disclose whether an account is active.
async fn verify_passkey_assertion(
    pool: &PgPool,
    passkey_service: &PasskeyService,
    auth_id: Uuid,
    origin: &str,
    auth_response: PublicKeyCredential,
    request_id: &str,
) -> Result<(Uuid, AuthenticationResult), HandlerError> {
    let (user_id, credential_id) =
        match passkey_service.identify_authentication(origin, &auth_response) {
            Ok(identifiers) => identifiers,
            Err(err) => {
                passkey_service.discard_authentication(auth_id).await;
                warn!(request_id = %request_id, "passkey identification failed: {err}");
                return Err(Box::new(
                    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
                ));
            }
        };

    let passkey_row =
        match load_passkey_row_for_user(pool, user_id, &credential_id, request_id).await {
            Ok(row) => row,
            Err(response) => {
                passkey_service.discard_authentication(auth_id).await;
                return Err(response);
            }
        };
    let passkey = match decode_stored_passkey(user_id, request_id, &passkey_row.passkey_data) {
        Ok(passkey) => passkey,
        Err(response) => {
            passkey_service.discard_authentication(auth_id).await;
            return Err(response);
        }
    };
    let credentials = [DiscoverableKey::from(&passkey)];
    let auth_result = passkey_service
        .auth_finish(auth_id, origin, auth_response, &credentials)
        .await
        .map_err(|err| {
            warn!(request_id = %request_id, "passkey login failed: {err:?}");
            Box::new((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response())
        })?;

    match user_is_active(pool, user_id).await {
        Ok(true) => Ok((user_id, auth_result)),
        Ok(false) => Err(Box::new(
            (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
        )),
        Err(err) => {
            error!(
                user_id = %user_id,
                request_id = %request_id,
                "failed to load passkey account status: {err}"
            );
            Err(Box::new(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Login failed".to_string(),
                )
                    .into_response(),
            ))
        }
    }
}

/// Check account status only after the passkey assertion has been verified.
async fn user_is_active(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND status = 'active')",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
}

async fn load_passkey_row_for_user(
    pool: &PgPool,
    user_id: Uuid,
    credential_id: &[u8],
    request_id: &str,
) -> Result<PasskeyCredential, HandlerError> {
    let passkey_row = match PasskeyRepo::get_passkey(pool, credential_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            warn!(
                user_id = %user_id,
                request_id = %request_id,
                "passkey login failed: credential not found"
            );
            return Err(Box::new(
                (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
            ));
        }
        Err(err) => {
            error!(
                user_id = %user_id,
                request_id = %request_id,
                "failed to load passkey: {err}"
            );
            return Err(Box::new(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Login failed".to_string(),
                )
                    .into_response(),
            ));
        }
    };

    if passkey_row.user_id != user_id {
        warn!(
            user_id = %user_id,
            request_id = %request_id,
            "passkey login failed: user mismatch"
        );
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
        ));
    }

    Ok(passkey_row)
}

fn decode_stored_passkey(
    user_id: Uuid,
    request_id: &str,
    passkey_data: &[u8],
) -> Result<Passkey, HandlerError> {
    deserialize_passkey(passkey_data).map_err(|err| {
        error!(
            user_id = %user_id,
            request_id = %request_id,
            "failed to decode stored passkey: {err}"
        );
        Box::new(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed".to_string(),
            )
                .into_response(),
        )
    })
}

fn encode_updated_passkey(
    user_id: Uuid,
    request_id: &str,
    passkey: &Passkey,
) -> Result<Vec<u8>, HandlerError> {
    serialize_passkey(passkey).map_err(|err| {
        error!(
            user_id = %user_id,
            request_id = %request_id,
            "failed to serialize updated passkey: {err}"
        );
        Box::new(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed".to_string(),
            )
                .into_response(),
        )
    })
}

async fn update_passkey_after_auth(
    pool: &PgPool,
    user_id: Uuid,
    auth_result: &AuthenticationResult,
    request_id: &str,
    client_ip: Option<&str>,
) -> Result<(), HandlerError> {
    let credential_id = auth_result.cred_id().as_slice();
    let passkey_row = load_passkey_row_for_user(pool, user_id, credential_id, request_id).await?;
    let mut passkey = decode_stored_passkey(user_id, request_id, &passkey_row.passkey_data)?;

    let updated = passkey.update_credential(auth_result).unwrap_or(false);

    if updated {
        let encoded = encode_updated_passkey(user_id, request_id, &passkey)?;
        if let Err(err) = PasskeyRepo::update_passkey_usage(pool, credential_id, &encoded).await {
            error!(
                user_id = %user_id,
                request_id = %request_id,
                "failed to update passkey usage: {err}"
            );
        }
    } else if let Err(err) = PasskeyRepo::touch_passkey(pool, credential_id).await {
        warn!(
            user_id = %user_id,
            request_id = %request_id,
            "failed to update passkey last_used_at: {err}"
        );
    }

    if let Err(err) = PasskeyRepo::log_audit(
        pool,
        user_id,
        Some(credential_id),
        "verify_success",
        client_ip,
        None,
    )
    .await
    {
        warn!(
            user_id = %user_id,
            request_id = %request_id,
            "passkey audit log failed: {err}"
        );
    }

    info!(
        user_id = %user_id,
        request_id = %request_id,
        "passkey login verified"
    );

    Ok(())
}

async fn create_session_token(
    pool: &PgPool,
    auth_state: &AuthState,
    user_id: Uuid,
    request_id: &str,
    mfa_state: MfaState,
) -> Result<(String, i64), HandlerError> {
    match mfa_state {
        MfaState::RequiredUnenrolled => {
            if let Err(err) = mfa::storage::delete_full_sessions(pool, user_id).await {
                error!(
                    user_id = %user_id,
                    request_id = %request_id,
                    "failed to revoke full sessions for MFA bootstrap: {err}"
                );
            }
            insert_mfa_bootstrap_session(
                pool,
                user_id,
                auth_state.mfa().bootstrap_session_ttl_seconds(),
            )
            .await
            .map(|token| (token, auth_state.mfa().bootstrap_session_ttl_seconds()))
            .map_err(|err| {
                error!(
                    user_id = %user_id,
                    request_id = %request_id,
                    "failed to create MFA bootstrap session: {err}"
                );
                Box::new(
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Login failed".to_string(),
                    )
                        .into_response(),
                )
            })
        }
        MfaState::Enabled => insert_mfa_challenge_session(
            pool,
            user_id,
            auth_state.mfa().challenge_session_ttl_seconds(),
        )
        .await
        .map(|token| (token, auth_state.mfa().challenge_session_ttl_seconds()))
        .map_err(|err| {
            error!(
                user_id = %user_id,
                request_id = %request_id,
                "failed to create MFA challenge session: {err}"
            );
            Box::new(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Login failed".to_string(),
                )
                    .into_response(),
            )
        }),
        MfaState::Disabled => {
            insert_session(pool, user_id, auth_state.config().session_ttl_seconds())
                .await
                .map(|token| (token, auth_state.config().session_ttl_seconds()))
                .map_err(|err| {
                    error!(
                        user_id = %user_id,
                        request_id = %request_id,
                        "failed to create session: {err}"
                    );
                    Box::new(
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Login failed".to_string(),
                        )
                            .into_response(),
                    )
                })
        }
    }
}

async fn issue_session_for_user(
    pool: &PgPool,
    auth_state: &AuthState,
    user_id: Uuid,
    request_id: &str,
) -> axum::response::Response {
    let mfa_state = match mfa::resolve_login_mfa_state(pool, user_id, auth_state.mfa()).await {
        Ok(state) => state,
        Err(err) => {
            error!(
                user_id = %user_id,
                request_id = %request_id,
                "failed to resolve MFA state: {err}"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed".to_string(),
            )
                .into_response();
        }
    };

    let (token, ttl_seconds) =
        match create_session_token(pool, auth_state, user_id, request_id, mfa_state).await {
            Ok(result) => result,
            Err(response) => return *response,
        };

    let mut response_headers = HeaderMap::new();
    match session_cookie_with_ttl(auth_state, &token, ttl_seconds) {
        Ok(cookie) => {
            response_headers.insert(SET_COOKIE, cookie);
            (StatusCode::NO_CONTENT, response_headers).into_response()
        }
        Err(err) => {
            error!(
                user_id = %user_id,
                request_id = %request_id,
                "failed to set session cookie: {err}"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed".to_string(),
            )
                .into_response()
        }
    }
}

fn parse_passkey_finish(
    body: &Bytes,
) -> Result<PasskeyLoginFinishRequest, Box<axum::response::Response>> {
    if body.len() > MAX_WEBAUTHN_JSON_BYTES {
        return Err(Box::new(StatusCode::PAYLOAD_TOO_LARGE.into_response()));
    }

    let request: PasskeyLoginFinishRequest = serde_json::from_slice(body).map_err(|_| {
        Box::new((StatusCode::BAD_REQUEST, "Invalid WebAuthn response").into_response())
    })?;

    Ok(request)
}

fn extract_origin(
    headers: &HeaderMap,
    passkey_service: &PasskeyService,
) -> Result<String, Box<axum::response::Response>> {
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

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}
