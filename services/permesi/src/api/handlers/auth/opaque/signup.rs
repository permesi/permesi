//! OPAQUE authentication handlers for user registration.
//!
//! This module provides endpoints for starting and finishing the OPAQUE PAKE
//! registration flow. Both endpoints apply server-owned signup eligibility independently;
//! finish atomically stores only a pending user, hashed verifier and protected email outbox.
//! Admission is not proof of mailbox control, tenant membership or user consent.

use crate::api::handlers::{
    AdmissionVerifier,
    auth::{
        rate_limit::RateLimitAction,
        state::{AuthState, OpaqueSuite},
        storage::{SignupOutcome, insert_user_and_verification},
        types::{
            OpaqueSignupFinishRequest, OpaqueSignupFinishResponse, OpaqueSignupStartRequest,
            OpaqueSignupStartResponse,
        },
        utils::{decode_base64_field, extract_client_ip, normalize_email, valid_email},
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
use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistration};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;

/// Starts registration only after server-owned domain/mode, shared limits and admission checks.
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
        (status = 403, description = "Registration not available", body = String),
        (status = 503, description = "Registration storage unavailable", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_signup_start(
    headers: HeaderMap,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    payload: Option<Json<OpaqueSignupStartRequest>>,
) -> impl IntoResponse {
    let request: OpaqueSignupStartRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let email = normalize_email(&request.email);
    if !valid_email(&email) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

    if !auth_state.config().registration().permits(&email) {
        return (
            StatusCode::FORBIDDEN,
            "Registration not available".to_owned(),
        )
            .into_response();
    }

    // Rate-limit before zero-token verification to keep abuse cheap to reject.
    let client_ip = extract_client_ip(&headers);
    if let Some(status) = auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Signup)
        .await
        .denial_status()
    {
        return (status, "Rate limited".to_string()).into_response();
    }
    if let Some(status) = auth_state
        .rate_limiter()
        .check_email(&email, RateLimitAction::Signup)
        .await
        .denial_status()
    {
        return (status, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    // Decode the OPAQUE registration request before starting the server flow.
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
        email.as_bytes(),
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

/// Rechecks signup admission independently; browser fields cannot activate the pending account.
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
        (status = 403, description = "Registration not available", body = String),
        (status = 503, description = "Registration storage unavailable", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn opaque_signup_finish(
    headers: HeaderMap,
    pool: State<PgPool>,
    auth_state: State<Arc<AuthState>>,
    admission: State<Arc<AdmissionVerifier>>,
    payload: Option<Json<OpaqueSignupFinishRequest>>,
) -> impl IntoResponse {
    let request: OpaqueSignupFinishRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let email = normalize_email(&request.email);
    if !valid_email(&email) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string()).into_response();
    }

    if !auth_state.config().registration().permits(&email) {
        return (
            StatusCode::FORBIDDEN,
            "Registration not available".to_owned(),
        )
            .into_response();
    }

    // Rate-limit before zero-token verification to keep abuse cheap to reject.
    let client_ip = extract_client_ip(&headers);
    if let Some(status) = auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::Signup)
        .await
        .denial_status()
    {
        return (status, "Rate limited".to_string()).into_response();
    }
    if let Some(status) = auth_state
        .rate_limiter()
        .check_email(&email, RateLimitAction::Signup)
        .await
        .denial_status()
    {
        return (status, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    // Decode the OPAQUE registration record before storing the password file.
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

    // The password file is derived server-side; the raw password never leaves the client.
    let password_file = ServerRegistration::finish(registration_upload);
    let opaque_record = password_file.serialize().to_vec();

    // This inserts the user, stores the registration record, and queues a
    // verification token (stored hashed, emailed as a link).
    let outcome =
        insert_user_and_verification(&pool, &email, &opaque_record, auth_state.config()).await;

    // The response is intentionally vague to avoid account enumeration.
    let message = "If the account can be created, you'll receive a verification email.".to_string();
    match outcome {
        Ok(SignupOutcome::Created | SignupOutcome::Conflict) => (
            StatusCode::CREATED,
            Json(OpaqueSignupFinishResponse { message }),
        )
            .into_response(),
        Ok(SignupOutcome::Rejected) => (
            StatusCode::FORBIDDEN,
            "Registration not available".to_owned(),
        )
            .into_response(),
        Err(_err) => {
            error!("Signup persistence unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
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
    use super::{opaque_signup_finish, opaque_signup_start};
    use crate::api::handlers::auth::opaque::test_support::{admission_verifier, auth_state};
    use anyhow::Result;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
    };
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn opaque_signup_start_missing_payload() -> Result<()> {
        let response = opaque_signup_start(
            HeaderMap::new(),
            State(auth_state()),
            State(admission_verifier()?),
            None,
        )
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
            State(pool),
            State(auth_state()),
            State(admission_verifier()?),
            None,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }
}
