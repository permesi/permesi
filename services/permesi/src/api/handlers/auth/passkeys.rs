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
        AuthState, RateLimitAction,
        mfa::{self, MfaState},
        session::session_cookie_with_ttl,
        storage::{
            insert_mfa_bootstrap_session_on, insert_mfa_challenge_session_on, insert_session_on,
        },
        utils::extract_client_ip,
        zero_token::{require_zero_token, zero_token_error_response},
    },
};
use crate::webauthn::{PasskeyCredential, PasskeyService, deserialize_passkey, serialize_passkey};
use axum::{
    Json,
    body::Bytes,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use service_utils::request_id::RequestId;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
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
        (status = 503, description = "Authentication storage unavailable"),
        (status = 200, description = "Passkey login started", body = PasskeyLoginStartResponse),
        (status = 400, description = "Invalid request"),
        (status = 429, description = "Rate limited")
    ),
    tag = "auth"
)]
/// Start passkey login by issuing an authentication challenge.
pub async fn passkey_login_start(
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    passkey_service: State<Arc<PasskeyService>>,
    payload: Option<Json<PasskeyLoginStartRequest>>,
) -> impl IntoResponse {
    let request_id = request_id.to_string();
    let Some(Json(_request)) = payload else {
        return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response();
    };

    let client_ip = extract_client_ip(&headers);
    if let Some(status) = auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::PasskeyLogin)
        .await
        .denial_status()
    {
        return (status, "Rate limited".to_string()).into_response();
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

    match passkey_service
        .auth_begin_for_ip(&origin, client_ip.as_deref())
        .await
    {
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
            crate::webauthn::exchange::error_response(&err)
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
        (status = 503, description = "Authentication storage unavailable"),
        (status = 204, description = "Passkey login finished"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 429, description = "Rate limited")
    ),
    tag = "auth"
)]
/// Finish passkey login and issue a session cookie.
pub async fn passkey_login_finish(
    headers: HeaderMap,
    Extension(request_id): Extension<RequestId>,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    passkey_service: State<Arc<PasskeyService>>,
    body: Bytes,
) -> impl IntoResponse {
    let request_id = request_id.to_string();
    let request = match parse_passkey_finish(&body) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };

    let client_ip = extract_client_ip(&headers);
    if let Some(status) = auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::PasskeyLogin)
        .await
        .denial_status()
    {
        return (status, "Rate limited".to_string()).into_response();
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

    let (user_id, auth_result, mut guard) = match verify_passkey_assertion(
        &pool,
        &passkey_service,
        auth_id,
        &origin,
        auth_response,
        &request_id,
        auth_state.config().opaque_exchange_timeout_ms(),
    )
    .await
    {
        Ok(verified) => verified,
        Err(response) => return *response,
    };

    if let Err(response) = update_passkey_after_auth(
        &mut guard,
        user_id,
        &auth_result,
        &request_id,
        client_ip.as_deref(),
    )
    .await
    {
        return *response;
    }

    issue_session_for_user(&auth_state, user_id, &request_id, guard).await
}

/// Resolve a discoverable credential and verify its proof before trusting its user handle.
///
/// Every pre-verification failure consumes the pending challenge. Account status is checked
/// only after `webauthn-rs` has authenticated the stored credential, so untrusted assertion
/// fields cannot select a session identity or disclose whether an account is active.
async fn verify_passkey_assertion<'a>(
    pool: &'a PgPool,
    passkey_service: &PasskeyService,
    auth_id: Uuid,
    origin: &str,
    auth_response: PublicKeyCredential,
    request_id: &str,
    timeout_ms: i64,
) -> Result<(Uuid, AuthenticationResult, Transaction<'a, Postgres>), HandlerError> {
    let authentication = passkey_service
        .consume_authentication(auth_id, origin)
        .await
        .map_err(|error| {
            Box::new(
                match error {
                    crate::webauthn::PasskeyAuthenticationError::Unavailable => {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                    _ => StatusCode::UNAUTHORIZED,
                }
                .into_response(),
            )
        })?;
    let (user_id, credential_id) =
        match passkey_service.identify_authentication(origin, &auth_response) {
            Ok(identifiers) => identifiers,
            Err(err) => {
                warn!(request_id = %request_id, "passkey identification failed: {err}");
                return Err(Box::new(
                    (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
                ));
            }
        };

    let mut guard = super::operations::begin(pool, timeout_ms)
        .await
        .map_err(|_| Box::new(login_storage_error()))?;
    // Lock identity before credential, consistently with password/status mutation paths.
    let status =
        sqlx::query_scalar::<_, String>("SELECT status::text FROM users WHERE id=$1 FOR SHARE")
            .bind(user_id)
            .fetch_optional(&mut *guard)
            .await
            .map_err(|_| Box::new(login_storage_error()))?;
    let row = sqlx::query_as::<_, PasskeyCredential>(
        "SELECT * FROM passkeys WHERE user_id=$1 AND credential_id=$2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(&credential_id)
    .fetch_optional(&mut *guard)
    .await
    .map_err(|_| Box::new(login_storage_error()))?;
    let Some(passkey_row) = row else {
        return Err(Box::new(StatusCode::UNAUTHORIZED.into_response()));
    };
    let passkey = match decode_stored_passkey(user_id, request_id, &passkey_row.passkey_data) {
        Ok(passkey) => passkey,
        Err(response) => {
            return Err(response);
        }
    };
    let credentials = [DiscoverableKey::from(&passkey)];
    let auth_result = passkey_service
        .verify_consumed_authentication(origin, &auth_response, authentication, &credentials)
        .map_err(|err| {
            warn!(request_id = %request_id, "passkey login failed: {err:?}");
            Box::new((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response())
        })?;

    if status.as_deref() != Some("active") {
        return Err(Box::new(StatusCode::UNAUTHORIZED.into_response()));
    }
    Ok((user_id, auth_result, guard))
}

/// Emits a value-free dependency error without retaining SQL or credential diagnostics.
fn login_storage_error() -> axum::response::Response {
    tracing::error!("passkey login storage unavailable");
    (StatusCode::SERVICE_UNAVAILABLE, "Login unavailable").into_response()
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

/// Updates the locked credential using the same transaction as subsequent session issuance.
async fn update_passkey_after_auth(
    connection: &mut PgConnection,
    user_id: Uuid,
    auth_result: &AuthenticationResult,
    request_id: &str,
    client_ip: Option<&str>,
) -> Result<(), HandlerError> {
    let credential_id = auth_result.cred_id().as_slice();
    let passkey_row = sqlx::query_as::<_, PasskeyCredential>(
        "SELECT * FROM passkeys WHERE user_id=$1 AND credential_id=$2",
    )
    .bind(user_id)
    .bind(credential_id)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| Box::new(login_storage_error()))?;
    let mut passkey = decode_stored_passkey(user_id, request_id, &passkey_row.passkey_data)?;

    let updated = passkey.update_credential(auth_result).unwrap_or(false);

    if updated {
        let encoded = encode_updated_passkey(user_id, request_id, &passkey)?;
        sqlx::query(
            "UPDATE passkeys SET passkey_data=$1,last_used_at=NOW() WHERE credential_id=$2",
        )
        .bind(encoded)
        .bind(credential_id)
        .execute(&mut *connection)
        .await
        .map_err(|_| Box::new(login_storage_error()))?;
    } else {
        sqlx::query("UPDATE passkeys SET last_used_at=NOW() WHERE credential_id=$1")
            .bind(credential_id)
            .execute(&mut *connection)
            .await
            .map_err(|_| Box::new(login_storage_error()))?;
    }

    // The audit FK locks the credential too: use this connection to avoid waiting
    // on our own FOR UPDATE lock through a second pool connection.
    sqlx::query("INSERT INTO passkey_audit_log (user_id,credential_id,action,ip_address) VALUES ($1,$2,'verify_success',$3::inet)")
        .bind(user_id).bind(credential_id).bind(client_ip)
        .execute(&mut *connection).await.map_err(|_| Box::new(login_storage_error()))?;

    info!(
        user_id = %user_id,
        request_id = %request_id,
        "passkey login verified"
    );

    Ok(())
}

/// Creates full or limited authority inside the identity/credential transaction; failures roll back.
async fn create_session_token(
    connection: &mut PgConnection,
    auth_state: &AuthState,
    user_id: Uuid,
    mfa_state: MfaState,
) -> Result<(String, i64), HandlerError> {
    let (token, ttl) = match mfa_state {
        MfaState::RequiredUnenrolled => {
            sqlx::query("DELETE FROM user_sessions WHERE user_id=$1")
                .bind(user_id)
                .execute(&mut *connection)
                .await
                .map_err(|_| Box::new(login_storage_error()))?;
            let ttl = auth_state.mfa().bootstrap_session_ttl_seconds();
            (
                insert_mfa_bootstrap_session_on(connection, user_id, ttl).await,
                ttl,
            )
        }
        MfaState::Enabled => {
            let ttl = auth_state.mfa().challenge_session_ttl_seconds();
            (
                insert_mfa_challenge_session_on(connection, user_id, ttl).await,
                ttl,
            )
        }
        MfaState::Disabled => {
            let ttl = auth_state.config().session_ttl_seconds();
            (insert_session_on(connection, user_id, ttl).await, ttl)
        }
    };
    Ok((token.map_err(|_| Box::new(login_storage_error()))?, ttl))
}

/// Commits credential usage and authority together while current user/credential locks remain held.
async fn issue_session_for_user(
    auth_state: &AuthState,
    user_id: Uuid,
    request_id: &str,
    mut guard: Transaction<'_, Postgres>,
) -> axum::response::Response {
    let mfa_state =
        match mfa::resolve_login_mfa_state_on(&mut guard, user_id, auth_state.mfa()).await {
            Ok(state) => state,
            Err(err) => {
                error!(
                    user_id = %user_id,
                    request_id = %request_id,
                    "failed to resolve MFA state: {err}"
                );
                return login_storage_error();
            }
        };

    let (token, ttl_seconds) =
        match create_session_token(&mut guard, auth_state, user_id, mfa_state).await {
            Ok(result) => result,
            Err(response) => return *response,
        };

    if guard.commit().await.is_err() {
        return login_storage_error();
    }

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
