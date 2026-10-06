//! `OPAQUE` password change endpoints for authenticated users.
//!
//! Password changes reuse the OPAQUE registration flow so the server only ever
//! stores a new registration record. The flow is split into start/finish to keep
//! the protocol transcript on the client and to enforce a recent re-auth check.
//!
//! ### Flow Overview
//!
//! The change password process is a combined re-authentication and rotation:
//! 1. `POST /v1/auth/opaque/reauth/start`: Initiate authentication with current password.
//! 2. `POST /v1/auth/opaque/reauth/finish`: Verify current password proof and grant temporary elevation.
//! 3. `POST /v1/auth/opaque/password/start`: Initiate registration of the new password.
//! 4. `POST /v1/auth/opaque/password/finish`: Commit the new registration record.
//!
//! ### Security Invariants
//!
//! - **Plaintext Isolation**: Plaintext passwords (current or new) never touch the server.
//! - **Session Gating**: Only the authenticated user can change their own password.
//!   The exact full session and recent authentication are rechecked under identity/session
//!   locks immediately before rotation, so revocation during admission cannot authorize it.
//! - **Recent Authentication**: The finish step requires the full session's server-stored
//!   authentication time to be within `PASSWORD_RECENT_AUTH_SECONDS`. The Web password flow
//!   obtains this through OPAQUE reauthentication; other genuine fresh full logins retain
//!   the existing authentication policy.
//! - **Global Revocation**: All active sessions for the user are revoked upon successful rotation.
//! - **Zero Token Enforcement**: Every step is gated by a valid admission token.

use crate::api::handlers::{
    AdmissionVerifier,
    auth::{
        authority_guard::{AuthorityGuard, Policy},
        principal::{Principal, require_auth},
        session::clear_session_cookie,
        state::{AuthState, OpaqueSuite},
        storage::rotate_password_and_clear_sessions_on,
        types::{
            OpaquePasswordFinishRequest, OpaquePasswordStartRequest, OpaquePasswordStartResponse,
        },
        utils::decode_base64_field,
        zero_token::{require_zero_token, zero_token_error_response},
    },
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::IntoResponse,
};
use base64::Engine;
use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistration};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;

const PASSWORD_RECENT_AUTH_SECONDS: i64 = 10 * 60;

/// Start a password change registration flow for the authenticated user.
#[utoipa::path(
    post,
    path = "/v1/auth/opaque/password/start",
    request_body = OpaquePasswordStartRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "OPAQUE password change started", body = OpaquePasswordStartResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 401, description = "Missing or invalid session cookie.")
    ),
    tag = "auth"
)]
pub async fn opaque_password_start(
    headers: HeaderMap,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    pool: State<PgPool>,
    payload: Option<Json<OpaquePasswordStartRequest>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    let request: OpaquePasswordStartRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let request_bytes = match decode_base64_field(&request.registration_request) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(registration_request) = RegistrationRequest::<OpaqueSuite>::deserialize(&request_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid registration request".to_string(),
        )
            .into_response();
    };

    let Ok(response) = ServerRegistration::start(
        auth_state.opaque().server_setup(),
        registration_request,
        principal.email.as_bytes(),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid registration request".to_string(),
        )
            .into_response();
    };

    let registration_response =
        base64::engine::general_purpose::STANDARD.encode(response.message.serialize());
    (
        StatusCode::OK,
        Json(OpaquePasswordStartResponse {
            registration_response,
        }),
    )
        .into_response()
}

/// Rotates on the exact current, recently authenticated full session's guarded transaction.
/// All revocations and the password revision commit together; failures publish no change.
#[utoipa::path(
    post,
    path = "/v1/auth/opaque/password/finish",
    request_body = OpaquePasswordFinishRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Password updated"),
        (status = 400, description = "Validation error", body = String),
        (status = 503, description = "Authentication storage unavailable."),
        (status = 401, description = "Missing or invalid session cookie.")
    ),
    tag = "auth"
)]
pub async fn opaque_password_finish(
    headers: HeaderMap,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    pool: State<PgPool>,
    payload: Option<Json<OpaquePasswordFinishRequest>>,
) -> impl IntoResponse {
    let principal = match require_auth(&headers, &pool).await {
        Ok(principal) => principal,
        Err(status) => return status.into_response(),
    };

    if !recent_auth_ok(&principal) {
        return (
            StatusCode::UNAUTHORIZED,
            "Recent authentication required".to_string(),
        )
            .into_response();
    }

    let request: OpaquePasswordFinishRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    let record_bytes = match decode_base64_field(&request.registration_record) {
        Ok(bytes) => bytes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let Ok(registration_upload) = RegistrationUpload::<OpaqueSuite>::deserialize(&record_bytes)
    else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid registration record".to_string(),
        )
            .into_response();
    };

    let password_file = ServerRegistration::finish(registration_upload);
    let opaque_record = password_file.serialize().to_vec();

    let mut guard = match AuthorityGuard::acquire(
        &pool,
        &headers,
        principal.user_id,
        Policy::Full,
        auth_state.config().opaque_exchange_timeout_ms(),
    )
    .await
    {
        Ok(guard) => guard,
        Err(status) => return status.into_response(),
    };
    if let Err(status) = guard
        .require_recent_auth(PASSWORD_RECENT_AUTH_SECONDS)
        .await
    {
        return status.into_response();
    }
    let Ok(cookie) = clear_session_cookie(auth_state.config()) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match rotate_password_and_clear_sessions_on(
        guard.connection(),
        principal.user_id,
        &opaque_record,
    )
    .await
    {
        Ok(true) => {
            if guard.commit().await.is_err() {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            let mut response_headers = HeaderMap::new();
            response_headers.insert(SET_COOKIE, cookie);
            (StatusCode::NO_CONTENT, response_headers).into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            error!("Password rotation storage unavailable");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// Rejects stale full-session snapshots early; the guarded row supplies the final decision.
fn recent_auth_ok(principal: &Principal) -> bool {
    let now = unix_now();
    let auth_time = principal
        .session_auth_time_unix
        .unwrap_or(principal.session_issued_at_unix);
    now.saturating_sub(auth_time) <= PASSWORD_RECENT_AUTH_SECONDS
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}
