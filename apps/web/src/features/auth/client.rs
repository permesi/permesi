//! Client wrappers for permesi auth API endpoints. These helpers centralize
//! headers and session-aware requests, keeping auth flows consistent and
//! preventing token leakage in route code.

use crate::{
    app_lib::{
        AppError, get_optional_json_with_credentials, post_empty_with_credentials,
        post_json_with_headers, post_json_with_headers_response,
        post_json_with_headers_with_credentials,
    },
    features::auth::types::{
        OpaqueLoginFinishRequest, OpaqueLoginStartRequest, OpaqueLoginStartResponse,
        OpaqueSignupFinishRequest, OpaqueSignupStartRequest, OpaqueSignupStartResponse,
        ResendVerificationRequest, UserSession, VerifyEmailRequest,
    },
};

/// Starts OPAQUE signup and returns the server response.
/// Requires a zero-token header and must never log the registration payload.
pub async fn opaque_signup_start(
    request: &OpaqueSignupStartRequest,
    zero_token: &str,
) -> Result<OpaqueSignupStartResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_response("/v1/auth/opaque/signup/start", request, &headers).await
}

/// Finishes OPAQUE signup by sending the registration record.
/// Requires a zero-token header and must never log the record.
pub async fn opaque_signup_finish(
    request: &OpaqueSignupFinishRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers("/v1/auth/opaque/signup/finish", request, &headers).await
}

/// Starts OPAQUE login and returns the server response.
/// Requires a zero-token header and must never log the credential request.
pub async fn opaque_login_start(
    request: &OpaqueLoginStartRequest,
    zero_token: &str,
) -> Result<OpaqueLoginStartResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_response("/v1/auth/opaque/login/start", request, &headers).await
}

/// Finishes OPAQUE login and allows the server to set session cookies.
/// The request must include credentials so the `HttpOnly` cookie is set.
pub async fn opaque_login_finish(
    request: &OpaqueLoginFinishRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_with_credentials("/v1/auth/opaque/login/finish", request, &headers).await
}

/// Verifies an email token after the user follows the link.
/// Requires a zero-token header and must never log the token.
pub async fn verify_email(request: &VerifyEmailRequest, zero_token: &str) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers("/v1/auth/verify-email", request, &headers).await
}

/// Requests a new verification email without leaking account existence.
/// Requires a zero-token header and should not log the email address.
pub async fn resend_verification(
    request: &ResendVerificationRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers("/v1/auth/resend-verification", request, &headers).await
}

/// Fetches the current session using cookie-based auth.
/// Returns `None` when the session is missing or expired.
pub async fn fetch_session() -> Result<Option<UserSession>, AppError> {
    get_optional_json_with_credentials("/v1/auth/session").await
}

/// Clears the current session on the server.
/// Uses cookie-based auth to invalidate the server-side session.
pub async fn logout() -> Result<(), AppError> {
    post_empty_with_credentials("/v1/auth/logout").await
}
