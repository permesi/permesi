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

use crate::api::handlers::AdmissionVerifier;

use super::rate_limit::{RateLimitAction, RateLimitDecision};
use super::state::AuthState;
use super::storage::{
    ResendOutcome, consume_verification_token, enqueue_resend_verification,
    lookup_email_by_token_hash,
};
use super::types::{ResendVerificationRequest, VerifyEmailRequest};
use super::utils::{extract_client_ip, hash_verification_token, normalize_email, valid_email};
use super::zero_token::{require_zero_token, zero_token_error_response};

/// Verify the email link by consuming the hashed token and activating the user.
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
    admission: Extension<Arc<AdmissionVerifier>>,
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
        // Rate limits are enforced before any token work to avoid amplification.
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limited".to_string()).into_response();
    }

    if let Err(err) = require_zero_token(&headers, &admission).await {
        let (status, message) = zero_token_error_response(&err);
        return (status, message).into_response();
    }

    // Hash the token before lookup; raw tokens are never stored server-side.
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

    if let Ok(Some(email)) = lookup_email_by_token_hash(&mut tx, &token_hash).await
        && auth_state
            .rate_limiter()
            .check_email(&email, RateLimitAction::VerifyEmail)
            == RateLimitDecision::Limited
    {
        // Email-based limits reduce repeated verification attempts for the same address.
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

/// Resend a verification email (always returns 204 to avoid user enumeration).
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
    admission: Extension<Arc<AdmissionVerifier>>,
    payload: Option<Json<ResendVerificationRequest>>,
) -> impl IntoResponse {
    let request: ResendVerificationRequest = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()).into_response(),
    };

    let email = normalize_email(&request.email);
    if !valid_email(&email) {
        // Always return 204 for invalid emails to avoid account probing.
        return StatusCode::NO_CONTENT.into_response();
    }

    let client_ip = extract_client_ip(&headers);
    if auth_state
        .rate_limiter()
        .check_ip(client_ip.as_deref(), RateLimitAction::ResendVerification)
        == RateLimitDecision::Limited
    {
        // Resend is intentionally opaque; rate limits still return 204.
        return StatusCode::NO_CONTENT.into_response();
    }
    if auth_state
        .rate_limiter()
        .check_email(&email, RateLimitAction::ResendVerification)
        == RateLimitDecision::Limited
    {
        return StatusCode::NO_CONTENT.into_response();
    }

    if let Err(_err) = require_zero_token(&headers, &admission).await {
        // Fail closed but keep the response opaque.
        return StatusCode::NO_CONTENT.into_response();
    }

    match enqueue_resend_verification(&pool, &email, auth_state.config()).await {
        Ok(ResendOutcome::Queued | ResendOutcome::Cooldown | ResendOutcome::Noop) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Err(err) => {
            error!("Failed to enqueue resend verification: {err}");
            // Avoid leaking failures; always return 204 to callers.
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::rate_limit::{NoopRateLimiter, RateLimiter};
    use super::super::state::{AuthConfig, AuthState, OpaqueState};
    use super::{VerifyEmailRequest, resend_verification, verify_email};
    use crate::api::handlers::AdmissionVerifier;
    use admission_token::{PaserkKey, PaserkKeySet};
    use anyhow::Result;
    use axum::Json;
    use axum::extract::Extension;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use std::time::Duration;

    fn admission_verifier() -> Result<Arc<AdmissionVerifier>> {
        let key = PaserkKey::from_ed25519_public_key_bytes(&[7u8; 32])?;
        let keyset = PaserkKeySet {
            version: "v4".to_string(),
            purpose: "public".to_string(),
            active_kid: key.kid.clone(),
            keys: vec![key],
        };
        Ok(Arc::new(AdmissionVerifier::new(
            keyset,
            "https://genesis.test".to_string(),
            "permesi".to_string(),
        )))
    }

    fn auth_state() -> Arc<AuthState> {
        let config = AuthConfig::new("https://permesi.dev".to_string());
        let opaque = OpaqueState::from_seed(
            [1u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_secs(30),
        );
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
        Arc::new(AuthState::new(config, opaque, limiter))
    }

    #[tokio::test]
    async fn verify_email_missing_payload() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = verify_email(
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
    async fn verify_email_empty_token() -> Result<()> {
        let pool = PgPoolOptions::new().connect_lazy("postgres://postgres@localhost/postgres")?;
        let response = verify_email(
            HeaderMap::new(),
            Extension(pool),
            Extension(auth_state()),
            Extension(admission_verifier()?),
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
