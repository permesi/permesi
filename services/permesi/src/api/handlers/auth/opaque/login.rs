//! `OPAQUE` login endpoints.

use crate::api::handlers::{
    AdmissionVerifier,
    auth::{
        rate_limit::{RateLimitAction, RateLimitDecision},
        session::session_cookie,
        state::{AuthState, OpaqueSuite},
        storage::{insert_session, lookup_login_record},
        types::{OpaqueLoginFinishRequest, OpaqueLoginStartRequest, OpaqueLoginStartResponse},
        utils::{decode_base64_field, extract_client_ip, normalize_email, valid_email},
        zero_token::{require_zero_token, zero_token_error_response},
    },
};
use anyhow::anyhow;
use axum::{
    Json,
    extract::Extension,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, SET_COOKIE},
    },
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

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/login/start",
    request_body = OpaqueLoginStartRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "OPAQUE login started", body = OpaqueLoginStartResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_login_start(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    admission: Extension<Arc<AdmissionVerifier>>,
    payload: Option<Json<OpaqueLoginStartRequest>>,
) -> impl IntoResponse {
    let request: OpaqueLoginStartRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let email = normalize_email(&request.email);
    if !valid_email(&email) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

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
        .check_email(&email, RateLimitAction::Login)
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

    // Build a response even for unknown users to keep the flow indistinguishable.
    let response =
        match build_login_start_response(&pool, &auth_state, &email, credential_request).await {
            Ok(response) => response,
            Err((status, message)) => return (status, message).into_response(),
        };

    (StatusCode::OK, Json(response)).into_response()
}

async fn build_login_start_response(
    pool: &PgPool,
    auth_state: &AuthState,
    email: &str,
    credential_request: CredentialRequest<OpaqueSuite>,
) -> Result<OpaqueLoginStartResponse, (StatusCode, String)> {
    let login_record = match lookup_login_record(pool, email).await {
        Ok(record) => record,
        Err(err) => {
            error!("Login lookup failed: {err}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed".to_string(),
            ));
        }
    };

    // Only active users get a real password file; inactive users get a dummy flow.
    let (password_file, user_id) = match login_record {
        Some(record) if record.status == "active" => {
            let password_file = ServerRegistration::deserialize(&record.opaque_record)
                .map_err(|_| anyhow!("Invalid stored registration record"));
            match password_file {
                Ok(file) => (Some(file), Some(record.user_id)),
                Err(err) => {
                    error!("Invalid registration record: {err}");
                    (None, None)
                }
            }
        }
        _ => (None, None),
    };

    let params = ServerLoginStartParameters {
        context: None,
        identifiers: Identifiers {
            client: Some(email.as_bytes()),
            server: Some(auth_state.opaque().server_id()),
        },
    };

    let mut rng = OsRng;
    let Ok(start_result) = ServerLogin::start(
        &mut rng,
        auth_state.opaque().server_setup(),
        password_file,
        credential_request,
        email.as_bytes(),
        params,
    ) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid credential request".to_string(),
        ));
    };

    // Store the login state server-side so finish can complete the exchange.
    let login_id = auth_state
        .opaque()
        .store_login_state(start_result.state, user_id)
        .await;
    let credential_response =
        base64::engine::general_purpose::STANDARD.encode(start_result.message.serialize());

    Ok(OpaqueLoginStartResponse {
        login_id: login_id.to_string(),
        credential_response,
    })
}

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/login/finish",
    request_body = OpaqueLoginFinishRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Login success"),
        (status = 400, description = "Validation error", body = String),
        (status = 401, description = "Unauthorized", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_login_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    admission: Extension<Arc<AdmissionVerifier>>,
    payload: Option<Json<OpaqueLoginFinishRequest>>,
) -> impl IntoResponse {
    let request: OpaqueLoginFinishRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    // Login IDs are opaque server-side references; reject anything malformed.
    let Ok(login_id) = Uuid::parse_str(request.login_id.trim()) else {
        return (StatusCode::BAD_REQUEST, "Invalid login id".to_string()).into_response();
    };

    // Decode the finalization message before finishing the OPAQUE exchange.
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

    // Missing user IDs mean the login was intentionally made non-committal.
    if login_state.user_id.is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
    }

    match login_state.state.finish(credential_finalization) {
        Ok(_) => {
            let Some(user_id) = login_state.user_id else {
                return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response();
            };
            // Generate a fresh session token, store only its hash, and return the raw
            // value for the cookie header.
            let token =
                match insert_session(&pool, user_id, auth_state.config().session_ttl_seconds())
                    .await
                {
                    Ok(token) => token,
                    Err(err) => {
                        error!("Failed to create session: {err}");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Login failed".to_string(),
                        )
                            .into_response();
                    }
                };

            let mut response_headers = HeaderMap::new();
            match session_cookie(&auth_state, &token) {
                Ok(cookie) => {
                    // Attach the cookie so the browser can present it on future requests.
                    response_headers.insert(SET_COOKIE, cookie);
                    if let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}")) {
                        response_headers.insert(AUTHORIZATION, value);
                    }
                    (StatusCode::NO_CONTENT, response_headers).into_response()
                }
                Err(err) => {
                    error!("Failed to set session cookie: {err}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Login failed".to_string(),
                    )
                        .into_response()
                }
            }
        }
        Err(_) => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::{opaque_login_finish, opaque_login_start};
    use crate::api::handlers::auth::opaque::test_support::{admission_verifier, auth_state};
    use anyhow::Result;
    use axum::{
        extract::Extension,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
    };
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn opaque_login_start_missing_payload() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = opaque_login_start(
            HeaderMap::new(),
            Extension(pool),
            Extension(auth_state()),
            Extension(admission_verifier()?),
            None,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn opaque_login_finish_missing_payload() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = opaque_login_finish(
            HeaderMap::new(),
            Extension(pool),
            Extension(auth_state()),
            Extension(admission_verifier()?),
            None,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
