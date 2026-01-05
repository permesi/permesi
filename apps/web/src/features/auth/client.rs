//! Client wrappers for permesi auth API endpoints. These helpers centralize
//! headers and session-aware requests, keeping auth flows consistent and
//! preventing token leakage in route code.

use crate::{
    app_lib::{
        AppError, get_json_with_headers_with_credentials, get_optional_json_with_credentials,
        get_optional_json_with_headers_with_credentials, post_empty_with_credentials,
        post_json_with_headers, post_json_with_headers_response,
        post_json_with_headers_with_credentials, post_json_with_headers_with_credentials_raw,
        post_json_with_headers_with_credentials_response,
    },
    features::auth::types::{
        AdminBootstrapRequest, AdminElevateRequest, AdminElevateResponse, AdminInfraResponse,
        AdminStatusResponse, OpaqueLoginFinishRequest, OpaqueLoginStartRequest,
        OpaqueLoginStartResponse, OpaqueSignupFinishRequest, OpaqueSignupStartRequest,
        OpaqueSignupStartResponse, ResendVerificationRequest, UserSession, VerifyEmailRequest,
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
) -> Result<Option<String>, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    let response = post_json_with_headers_with_credentials_raw(
        "/v1/auth/opaque/login/finish",
        request,
        &headers,
    )
    .await?;
    Ok(extract_bearer_token(&response))
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
pub async fn fetch_session(token: Option<&str>) -> Result<Option<UserSession>, AppError> {
    let headers = auth_headers(token);
    if headers.is_empty() {
        get_optional_json_with_credentials("/v1/auth/session").await
    } else {
        get_optional_json_with_headers_with_credentials("/v1/auth/session", &headers).await
    }
}

/// Clears the current session on the server.
/// Uses cookie-based auth to invalidate the server-side session.
pub async fn logout() -> Result<(), AppError> {
    post_empty_with_credentials("/v1/auth/logout").await
}

/// Fetches admin bootstrap/elevation status for the current session.
pub async fn admin_status(token: Option<&str>) -> Result<AdminStatusResponse, AppError> {
    let headers = auth_headers(token);
    get_json_with_headers_with_credentials("/v1/auth/admin/status", &headers).await
}

/// Fetches detailed infrastructure status for operators.
pub async fn admin_infra(token: Option<&str>) -> Result<AdminInfraResponse, AppError> {
    let headers = auth_headers(token);
    get_json_with_headers_with_credentials("/v1/auth/admin/infra", &headers).await
}

/// Attempts to bootstrap the first platform operator.
pub async fn admin_bootstrap(
    token: Option<&str>,
    request: &AdminBootstrapRequest,
) -> Result<(), AppError> {
    let headers = auth_headers(token);
    post_json_with_headers_with_credentials("/v1/auth/admin/bootstrap", request, &headers).await
}

/// Exchanges a Vault token for a short-lived admin elevation token.
pub async fn admin_elevate(
    token: Option<&str>,
    request: &AdminElevateRequest,
) -> Result<AdminElevateResponse, AppError> {
    let headers = auth_headers(token);
    post_json_with_headers_with_credentials_response("/v1/auth/admin/elevate", request, &headers)
        .await
}

/// Checks if an expiration timestamp string (ISO format) is in the past.
pub fn is_token_expired(expires_at: &str) -> bool {
    let parsed = js_sys::Date::parse(expires_at);
    if parsed.is_nan() {
        return false;
    }
    parsed <= js_sys::Date::now()
}

fn auth_headers(token: Option<&str>) -> Vec<(String, String)> {
    token
        .map(|token| vec![("Authorization".to_string(), format!("Bearer {token}"))])
        .unwrap_or_default()
}

fn extract_bearer_token(response: &gloo_net::http::Response) -> Option<String> {
    let header = response.headers().get("Authorization")?;
    let trimmed = header.trim();
    if let Some(token) = trimmed.strip_prefix("Bearer ") {
        return Some(token.trim().to_string());
    }
    if let Some(token) = trimmed.strip_prefix("bearer ") {
        return Some(token.trim().to_string());
    }
    None
}
