//! OPAQUE authentication handlers for session re-authentication.
//!
//! Flow Overview: a verified full session starts an admission-protected password
//! exchange, stored encrypted in PostgreSQL with its exact user and session hash.
//! Any replica can consume the single attempt, verify the proof and refresh only
//! that session's authentication timestamp. A user-row lock holds current identity
//! and credential checks through the update; browser fields confer no identity or
//! session authority. Login exchanges cannot be reused for elevation.

use crate::api::handlers::{
    AdmissionVerifier,
    auth::{
        principal::{Principal, require_auth},
        rate_limit::RateLimitAction,
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
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, ServerLogin, ServerLoginParameters,
    ServerRegistration,
};
use opaque_rand_core::OsRng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use super::exchange::{ExchangeIdentity, ExchangePurpose, lock_identity};

/// Start an admission-protected password proof bound to the verified full session.
/// The user, credential revision and session hash come from server-side state.
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
        (status = 429, description = "Rate limited or shared exchange capacity exhausted", body = String),
        (status = 503, description = "Authentication storage unavailable; no exchange is issued", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_reauth_start(
    headers: HeaderMap,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
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
    if let Some(status) = auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Reauthenticate)
        .await
        .denial_status()
    {
        return (status, "Rate limited".to_string()).into_response();
    }
    if let Some(status) = auth_state
        .rate_limiter()
        .check_email(&principal.email, RateLimitAction::Reauthenticate)
        .await
        .denial_status()
    {
        return (status, "Rate limited".to_string()).into_response();
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

    let Some(token) = extract_session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(session_hash) = <[u8; 32]>::try_from(hash_session_token(&token)) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match build_reauth_start_response(
        &pool,
        &auth_state,
        &principal,
        session_hash,
        credential_request,
    )
    .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err((status, message)) => super::super::operations::failure(status, message),
    }
}

/// Bind the protocol to server-derived user identity, password revision and current session.
async fn build_reauth_start_response(
    pool: &PgPool,
    auth_state: &AuthState,
    principal: &Principal,
    session_hash: [u8; 32],
    credential_request: CredentialRequest<OpaqueSuite>,
) -> Result<OpaqueLoginStartResponse, (StatusCode, String)> {
    let login_record = match lookup_login_record(pool, &principal.email).await {
        Ok(record) => record,
        Err(err) => {
            error!("Re-auth lookup failed: {err}");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
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
                StatusCode::SERVICE_UNAVAILABLE,
                "Re-auth failed".to_string(),
            ));
        }
    };

    let params = ServerLoginParameters {
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

    let login_id = match auth_state
        .opaque()
        .store_login_state(
            pool,
            start_result.state,
            Some(ExchangeIdentity {
                user_id: record.user_id,
                credential_hash: Sha256::digest(&record.opaque_record).into(),
            }),
            ExchangePurpose::Reauthenticate {
                user_id: principal.user_id,
                session_hash,
            },
            super::exchange::Admission {
                subject: &principal.email,
                policy: auth_state.config().operations(),
                timeout_ms: auth_state.config().opaque_exchange_timeout_ms(),
            },
        )
        .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Too many pending login attempts".to_string(),
            ));
        }
        Err(_) => {
            error!("OPAQUE exchange storage failed");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Re-auth failed".to_string(),
            ));
        }
    };
    let credential_response =
        base64::engine::general_purpose::STANDARD.encode(start_result.message.serialize());
    Ok(OpaqueLoginStartResponse {
        login_id: login_id.to_string(),
        credential_response,
    })
}

/// Consume one proof attempt and refresh only its original verified full session.
/// Require current active identity/credentials and commit elevation before returning success.
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
        (status = 401, description = "Invalid session, expired/attempted exchange or session binding mismatch"),
        (status = 503, description = "Authentication storage unavailable; no successful elevation", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_reauth_finish(
    headers: HeaderMap,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
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

    let Some(token) = extract_session_token(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(session_hash) = <[u8; 32]>::try_from(hash_session_token(&token)) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let login_state = match auth_state
        .opaque()
        .take_login_state(
            &pool,
            login_id,
            ExchangePurpose::Reauthenticate {
                user_id: principal.user_id,
                session_hash,
            },
            auth_state.config().opaque_exchange_timeout_ms(),
        )
        .await
    {
        Ok(Some(state)) => state,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
        Err(_) => {
            error!("OPAQUE exchange storage failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Re-auth failed".to_string(),
            )
                .into_response();
        }
    };

    if login_state
        .state
        .finish(credential_finalization, ServerLoginParameters::default())
        .is_err()
    {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    }

    let Some(identity) = login_state.identity else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let mut tx = match lock_identity(
        &pool,
        &identity,
        auth_state.config().opaque_exchange_timeout_ms(),
    )
    .await
    {
        Ok(Some(tx)) => tx,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => {
            error!("OPAQUE reauthentication identity validation failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    match update_session_auth_time(&mut *tx, principal.user_id, &session_hash).await {
        Ok(true) => {
            if tx.commit().await.is_err() {
                error!("OPAQUE reauthentication session transaction commit failed");
                StatusCode::SERVICE_UNAVAILABLE.into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        Ok(false) => StatusCode::UNAUTHORIZED.into_response(),
        Err(err) => {
            error!("Failed to update session auth time: {err}");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}
