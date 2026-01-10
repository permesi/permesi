//! `OPAQUE` re-authentication endpoints.
//!
//! These handlers let an authenticated session refresh its "recent auth" marker
//! without creating a new session. This keeps sensitive actions gated on a fresh
//! password proof while preserving existing session state and audit trails.
//!
//! Flow Overview: start runs the server-side login step for the current session
//! user, and finish validates the password proof before updating the session's
//! auth timestamp.
//!
//! Security boundaries: the caller must already hold a valid session cookie,
//! supply a zero-token, and prove knowledge of the current password via OPAQUE;
//! no raw passwords or derived secrets are ever stored or logged.

use crate::api::handlers::{
    AdmissionVerifier,
    auth::{
        principal::{Principal, require_auth},
        rate_limit::{RateLimitAction, RateLimitDecision},
        session::extract_session_token,
        state::{AuthState, OpaqueSuite},
        storage::{lookup_login_record, update_session_auth_time},
        types::{OpaqueLoginStartResponse, OpaqueReauthFinishRequest, OpaqueReauthStartRequest},
        utils::{decode_base64_field, extract_client_ip, hash_session_token},
        zero_token::{require_zero_token, zero_token_error_response},
    },
};
use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, ServerLogin,
    ServerLoginStartParameters, ServerRegistration,
};
use rand::rngs::OsRng;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

/// Start a password re-auth flow for the current session user.
#[utoipa::path(
    post,
    path = "/v1/auth/opaque/reauth/start",
    request_body = OpaqueReauthStartRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "OPAQUE re-auth started", body = OpaqueLoginStartResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 401, description = "Missing or invalid session cookie."),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_reauth_start(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    admission: Extension<Arc<AdmissionVerifier>>,
    payload: Option<Json<OpaqueReauthStartRequest>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let request: OpaqueReauthStartRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    // Rate-limit before zero-token verification to keep abuse cheap to reject.
    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Login)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if auth_state
        .rate_limiter()
        .check_email(&principal.email, RateLimitAction::Login)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    // Decode the OPAQUE credential request before touching stored credentials.
    let credential_bytes = match decode_base64_field(&request.credential_request) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(credential_request) = CredentialRequest::<OpaqueSuite>::deserialize(&credential_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid credential request".to_string(),
        )
            .into_response();
    };

    match build_reauth_start_response(&pool, &auth_state, &principal, credential_request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err((status, message)) => (status, message).into_response(),
    }
}

async fn build_reauth_start_response(
    pool: &PgPool,
    auth_state: &AuthState,
    principal: &Principal,
    credential_request: CredentialRequest<OpaqueSuite>,
) -> Result<OpaqueLoginStartResponse, (StatusCode, String)> {
    let login_record = match lookup_login_record(pool, &principal.email).await {
        Ok(record) => record,
        Err(err) => {
            error!("Re-auth lookup failed: {err}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Re-auth failed".to_string(),
            ));
        }
    };

    let Some(record) = login_record else {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    };
    if record.status != "active" || record.user_id != principal.user_id {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()));
    }

    let password_file = match ServerRegistration::deserialize(&record.opaque_record) {
        Ok(file) => file,
        Err(err) => {
            error!("Invalid registration record for re-auth: {err}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Re-auth failed".to_string(),
            ));
        }
    };

    let params = ServerLoginStartParameters {
        context: None,
        identifiers: Identifiers {
            client: Some(principal.email.as_bytes()),
            server: Some(auth_state.opaque().server_id()),
        },
    };

    let mut rng = OsRng;
    let Ok(start_result) = ServerLogin::start(
        &mut rng,
        auth_state.opaque().server_setup(),
        Some(password_file),
        credential_request,
        principal.email.as_bytes(),
        params,
    ) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid credential request".to_string(),
        ));
    };

    let login_id = auth_state
        .opaque()
        .store_login_state(start_result.state, Some(record.user_id))
        .await;
    let credential_response =
        base64::engine::general_purpose::STANDARD.encode(start_result.message.serialize());
    Ok(OpaqueLoginStartResponse {
        login_id: login_id.to_string(),
        credential_response,
    })
}

/// Finish a password re-auth flow and refresh the session auth timestamp.
#[utoipa::path(
    post,
    path = "/v1/auth/opaque/reauth/finish",
    request_body = OpaqueReauthFinishRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Re-auth success"),
        (status = 400, description = "Validation error", body = String),
        (status = 401, description = "Missing or invalid session cookie.")
    ),
    tag = "auth"
)]
pub async fn opaque_reauth_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    admission: Extension<Arc<AdmissionVerifier>>,
    payload: Option<Json<OpaqueReauthFinishRequest>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let request: OpaqueReauthFinishRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let Ok(login_id) = Uuid::parse_str(request.login_id.trim()) else {
        return (StatusCode::BAD_REQUEST, "Invalid login id".to_string()).into_response();
    };

    let credential_bytes = match decode_base64_field(&request.credential_finalization) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    let Ok(credential_finalization) =
        CredentialFinalization::<OpaqueSuite>::deserialize(&credential_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid credential finalization".to_string(),
        )
            .into_response();
    };

    let Some(login_state) = auth_state.opaque().take_login_state(login_id).await else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    };
    if login_state.user_id != Some(principal.user_id) {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    }

    if login_state.state.finish(credential_finalization).is_err() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    }

    let Some(token) = extract_session_token(&headers) else {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    };
    let token_hash = hash_session_token(&token);
    match update_session_auth_time(&pool, principal.user_id, &token_hash).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::UNAUTHORIZED.into_response(),
        Err(err) => {
            error!("Failed to update session auth time: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
