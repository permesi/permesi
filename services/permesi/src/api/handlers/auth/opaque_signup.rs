//! `OPAQUE` signup endpoints.

use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistration};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;

use super::rate_limit::{RateLimitAction, RateLimitDecision};
use super::state::{AuthState, OpaqueSuite};
use super::storage::{SignupOutcome, insert_user_and_verification};
use super::types::{
    OpaqueSignupFinishRequest, OpaqueSignupFinishResponse, OpaqueSignupStartRequest,
    OpaqueSignupStartResponse,
};
use super::utils::{
    decode_base64_field, extract_client_ip, normalize_email, normalize_username, valid_email,
    valid_username,
};
use super::zero_token::{ZeroTokenError, require_zero_token, zero_token_error_response};

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/signup/start",
    request_body = OpaqueSignupStartRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 200, description = "OPAQUE signup started", body = OpaqueSignupStartResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_signup_start(
    headers: HeaderMap,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<OpaqueSignupStartRequest>>,
) -> impl IntoResponse {
    let request: OpaqueSignupStartRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let username = request.username.trim().to_string();
    let email = request.email.trim().to_string();

    let username_normalized = normalize_username(&username);
    if !valid_username(&username_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid username".to_string()).into_response();
    }

    let email_normalized = normalize_email(&email);
    if !valid_email(&email_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Signup)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if auth_state
        .rate_limiter()
        .check_email(&email_normalized, RateLimitAction::Signup)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
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
        email_normalized.as_bytes(),
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
        Json(OpaqueSignupStartResponse {
            registration_response,
        }),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/v1/auth/opaque/signup/finish",
    request_body = OpaqueSignupFinishRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 201, description = "Signup accepted", body = OpaqueSignupFinishResponse),
        (status = 400, description = "Validation error", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_signup_finish(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<OpaqueSignupFinishRequest>>,
) -> impl IntoResponse {
    let request: OpaqueSignupFinishRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let username = request.username.trim().to_string();
    let email = request.email.trim().to_string();

    let username_normalized = normalize_username(&username);
    if !valid_username(&username_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid username".to_string()).into_response();
    }

    let email_normalized = normalize_email(&email);
    if !valid_email(&email_normalized) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Signup)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }
    if auth_state
        .rate_limiter()
        .check_email(&email_normalized, RateLimitAction::Signup)
        == RateLimitDecision::Limited
    {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
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

    let outcome = insert_user_and_verification(
        &pool,
        &username,
        &username_normalized,
        &email,
        &email_normalized,
        &opaque_record,
        auth_state.config(),
    )
    .await;

    let message = "If the account can be created, you'll receive a verification email.".to_string();
    match outcome {
        Ok(SignupOutcome::Created | SignupOutcome::Conflict) => (
            StatusCode::CREATED,
            Json(OpaqueSignupFinishResponse { message }),
        )
            .into_response(),
        Err(err) => {
            error!("Signup failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OpaqueSignupFinishResponse {
                    message: "Signup failed".to_string(),
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::rate_limit::{NoopRateLimiter, RateLimiter};
    use super::super::state::{AuthConfig, AuthState, OpaqueState};
    use super::{opaque_signup_finish, opaque_signup_start};
    use anyhow::Result;
    use axum::extract::Extension;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use std::time::Duration;

    fn auth_state() -> Result<Arc<AuthState>> {
        let config = AuthConfig::new(
            "http://genesis.test/v1/zero-token/validate".to_string(),
            "https://permesi.dev".to_string(),
        );
        let opaque = OpaqueState::from_seed(
            [1u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_secs(30),
        );
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
        Ok(Arc::new(AuthState::new(config, opaque, limiter)?))
    }

    #[tokio::test]
    async fn opaque_signup_start_missing_payload() -> Result<()> {
        let response = opaque_signup_start(HeaderMap::new(), Extension(auth_state()?), None)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn opaque_signup_finish_missing_payload() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = opaque_signup_finish(
            HeaderMap::new(),
            Extension(pool),
            Extension(auth_state()?),
            None,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
