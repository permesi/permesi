//! Email verification endpoints.

use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::error;

use super::rate_limit::{RateLimitAction, RateLimitDecision};
use super::state::AuthState;
use super::storage::{
    ResendOutcome, consume_verification_token, enqueue_resend_verification,
    lookup_email_by_token_hash,
};
use super::types::{ResendVerificationRequest, VerifyEmailRequest};
use super::utils::{extract_client_ip, hash_verification_token, normalize_email, valid_email};
use super::zero_token::{ZeroTokenError, require_zero_token, zero_token_error_response};

#[utoipa::path(
    post,
    path = "/v1/auth/verify-email",
    request_body = VerifyEmailRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Email verified"),
        (status = 400, description = "Invalid/expired token", body = String),
        (status = 429, description = "Rate limited", body = String)
    ),
    tag = "auth"
)]
pub async fn verify_email(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<VerifyEmailRequest>>,
) -> impl IntoResponse {
    let request: VerifyEmailRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let token = request.token.trim();
    if token.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing token".to_string()).into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::VerifyEmail)
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

    let token_hash = hash_verification_token(token);
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            error!("Failed to start verify-email transaction: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Verification failed".to_string(),
            )
                .into_response();
        }
    };

    if let Ok(Some(email_normalized)) = lookup_email_by_token_hash(&mut tx, &token_hash).await
        && auth_state
            .rate_limiter()
            .check_email(&email_normalized, RateLimitAction::VerifyEmail)
            == RateLimitDecision::Limited
    {
        let _ = tx.rollback().await;
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    match consume_verification_token(&mut tx, &token_hash).await {
        Ok(true) => {
            if let Err(err) = tx.commit().await {
                error!("Failed to commit verify-email transaction: {err}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Verification failed".to_string(),
                )
                    .into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => {
            let _ = tx.rollback().await;
            (StatusCode::BAD_REQUEST, "Invalid token".to_string()).into_response()
        }
        Err(err) => {
            error!("Failed to verify email: {err}");
            let _ = tx.rollback().await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Verification failed".to_string(),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/v1/auth/resend-verification",
    request_body = ResendVerificationRequest,
    params(
        ("X-Permesi-Zero-Token" = String, Header, description = "Genesis zero token")
    ),
    responses(
        (status = 204, description = "Resend accepted")
    ),
    tag = "auth"
)]
pub async fn resend_verification(
    headers: HeaderMap,
    pool: Extension<PgPool>,
    auth_state: Extension<Arc<AuthState>>,
    payload: Option<Json<ResendVerificationRequest>>,
) -> impl IntoResponse {
    let request: ResendVerificationRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let email = request.email.trim().to_string();
    let email_normalized = normalize_email(&email);
    if !valid_email(&email_normalized) {
        return StatusCode::NO_CONTENT.into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::ResendVerification)
        == RateLimitDecision::Limited
    {
        return StatusCode::NO_CONTENT.into_response();
    }
    if auth_state
        .rate_limiter()
        .check_email(&email_normalized, RateLimitAction::ResendVerification)
        == RateLimitDecision::Limited
    {
        return StatusCode::NO_CONTENT.into_response();
    }

    if let Err(err) = require_zero_token(&headers, &auth_state).await {
        if let ZeroTokenError::Unavailable(ref inner) = err {
            error!("Zero token validation failed: {inner}");
        }
        return StatusCode::NO_CONTENT.into_response();
    }

    match enqueue_resend_verification(&pool, &email_normalized, auth_state.config()).await {
        Ok(ResendOutcome::Queued | ResendOutcome::Cooldown | ResendOutcome::Noop) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => {
            error!("Failed to enqueue resend verification: {err}");
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::rate_limit::{NoopRateLimiter, RateLimiter};
    use super::super::state::{AuthConfig, AuthState, OpaqueState};
    use super::{VerifyEmailRequest, resend_verification, verify_email};
    use anyhow::Result;
    use axum::Json;
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
    async fn verify_email_missing_payload() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = verify_email(
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

    #[tokio::test]
    async fn verify_email_empty_token() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = verify_email(
            HeaderMap::new(),
            Extension(pool),
            Extension(auth_state()?),
            Some(Json(VerifyEmailRequest {
                token: " ".to_string(),
            })),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn resend_verification_missing_payload() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = resend_verification(
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
