//! Client wrappers for permesi auth API endpoints. These helpers centralize
//! headers and session-aware requests, keeping auth flows consistent and
//! preventing token leakage in route code.

use crate::{
    app_lib::{
        AppError, get_json_with_credentials, get_json_with_headers,
        get_optional_json_with_credentials, post_empty_with_credentials, post_json_with_headers,
        post_json_with_headers_response, post_json_with_headers_with_credentials,
        post_json_with_headers_with_credentials_response,
    },
    features::auth::types::{
        AdminBootstrapRequest, AdminBootstrapResponse, AdminElevateRequest, AdminElevateResponse,
        AdminInfraResponse, AdminStatusResponse, MfaRecoveryRequest, MfaTotpEnrollFinishRequest,
        MfaTotpEnrollStartResponse, MfaTotpVerifyRequest, OpaqueLoginFinishRequest,
        OpaqueLoginStartRequest, OpaqueLoginStartResponse, OpaquePasswordFinishRequest,
        OpaquePasswordStartRequest, OpaquePasswordStartResponse, OpaqueReauthFinishRequest,
        OpaqueReauthStartRequest, OpaqueSignupFinishRequest, OpaqueSignupStartRequest,
        OpaqueSignupStartResponse, PasskeyLoginFinishRequest, PasskeyLoginStartRequest,
        PasskeyLoginStartResponse, RecoveryCodesResponse, ResendVerificationRequest, UserSession,
        VerifyEmailRequest, WebauthnAuthenticateFinishRequest, WebauthnAuthenticateStartResponse,
        WebauthnRegisterFinishRequest, WebauthnRegisterStartResponse,
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

/// Starts passkey login for the supplied email address.
pub async fn passkey_login_start(
    request: &PasskeyLoginStartRequest,
    zero_token: &str,
) -> Result<PasskeyLoginStartResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_response("/v1/auth/passkey/login/start", request, &headers).await
}

/// Finishes passkey login and allows the server to set session cookies.
pub async fn passkey_login_finish(
    request: &PasskeyLoginFinishRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_with_credentials("/v1/auth/passkey/login/finish", request, &headers)
        .await
}

/// Starts OPAQUE re-auth to refresh the session auth timestamp.
/// Requires a zero-token header and must never log the credential request.
pub async fn opaque_reauth_start(
    request: &OpaqueReauthStartRequest,
    zero_token: &str,
) -> Result<OpaqueLoginStartResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_with_credentials_response(
        "/v1/auth/opaque/reauth/start",
        request,
        &headers,
    )
    .await
}

/// Finishes OPAQUE re-auth after the password proof.
/// The request must include credentials so the session cookie is present.
pub async fn opaque_reauth_finish(
    request: &OpaqueReauthFinishRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_with_credentials("/v1/auth/opaque/reauth/finish", request, &headers)
        .await
}

/// Starts OPAQUE password change and returns the registration response.
/// Requires a zero-token header and must never log the registration payload.
pub async fn opaque_password_start(
    request: &OpaquePasswordStartRequest,
    zero_token: &str,
) -> Result<OpaquePasswordStartResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_with_credentials_response(
        "/v1/auth/opaque/password/start",
        request,
        &headers,
    )
    .await
}

/// Finishes OPAQUE password change after sending the registration record.
/// The request must include credentials so the server can clear cookies.
pub async fn opaque_password_finish(
    request: &OpaquePasswordFinishRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_with_credentials("/v1/auth/opaque/password/finish", request, &headers)
        .await
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

/// Starts TOTP enrollment and returns the secret and QR code URL.
pub async fn mfa_totp_enroll_start() -> Result<MfaTotpEnrollStartResponse, AppError> {
    post_json_with_headers_with_credentials_response("/v1/auth/mfa/totp/enroll/start", &(), &vec![])
        .await
}

/// Finishes TOTP enrollment and returns recovery codes.
pub async fn mfa_totp_enroll_finish(
    request: &MfaTotpEnrollFinishRequest,
) -> Result<RecoveryCodesResponse, AppError> {
    post_json_with_headers_with_credentials_response(
        "/v1/auth/mfa/totp/enroll/finish",
        request,
        &vec![],
    )
    .await
}

/// Verifies a TOTP code during challenge.
pub async fn mfa_totp_verify(request: &MfaTotpVerifyRequest) -> Result<(), AppError> {
    post_json_with_headers_with_credentials("/v1/auth/mfa/totp/verify", request, &vec![]).await
}

/// Verifies a recovery code during challenge.
pub async fn mfa_recovery(request: &MfaRecoveryRequest) -> Result<(), AppError> {
    post_json_with_headers_with_credentials("/v1/auth/mfa/recovery", request, &vec![]).await
}

/// Disables TOTP MFA.
pub async fn mfa_totp_disable() -> Result<(), AppError> {
    crate::app_lib::delete_json_with_headers_with_credentials("/v1/me/mfa/totp", &[]).await
}

/// Regenerates MFA recovery codes.
pub async fn regenerate_recovery_codes() -> Result<RecoveryCodesResponse, AppError> {
    post_json_with_headers_with_credentials_response("/v1/me/mfa/recovery-codes", &(), &[]).await
}

/// Starts WebAuthn registration.
pub async fn mfa_webauthn_register_start() -> Result<WebauthnRegisterStartResponse, AppError> {
    post_json_with_headers_with_credentials_response(
        "/v1/auth/mfa/webauthn/register/start",
        &(),
        &vec![],
    )
    .await
}

/// Finishes WebAuthn registration.
pub async fn mfa_webauthn_register_finish(
    request: &WebauthnRegisterFinishRequest,
) -> Result<(), AppError> {
    post_json_with_headers_with_credentials(
        "/v1/auth/mfa/webauthn/register/finish",
        request,
        &vec![],
    )
    .await
}

/// Starts WebAuthn authentication.
pub async fn mfa_webauthn_authenticate_start() -> Result<WebauthnAuthenticateStartResponse, AppError>
{
    post_json_with_headers_with_credentials_response(
        "/v1/auth/mfa/webauthn/authenticate/start",
        &(),
        &vec![],
    )
    .await
}

/// Finishes WebAuthn authentication.
pub async fn mfa_webauthn_authenticate_finish(
    request: &WebauthnAuthenticateFinishRequest,
) -> Result<(), AppError> {
    post_json_with_headers_with_credentials(
        "/v1/auth/mfa/webauthn/authenticate/finish",
        request,
        &vec![],
    )
    .await
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

/// Fetches admin bootstrap/elevation status for the current session.
pub async fn admin_status() -> Result<AdminStatusResponse, AppError> {
    get_json_with_credentials("/v1/auth/admin/status").await
}

/// Fetches detailed infrastructure status for operators.
pub async fn admin_infra(token: Option<&str>) -> Result<AdminInfraResponse, AppError> {
    let headers = auth_headers(token);
    get_json_with_headers("/v1/auth/admin/infra", &headers).await
}

/// Attempts to bootstrap the first platform operator.
pub async fn admin_bootstrap(
    request: &AdminBootstrapRequest,
) -> Result<AdminBootstrapResponse, AppError> {
    post_json_with_headers_with_credentials_response("/v1/auth/admin/bootstrap", request, &[]).await
}

/// Exchanges a Vault token for a short-lived admin elevation token.
pub async fn admin_elevate(
    request: &AdminElevateRequest,
) -> Result<AdminElevateResponse, AppError> {
    post_json_with_headers_with_credentials_response("/v1/auth/admin/elevate", request, &[]).await
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

/// Fetches the system health status.
pub async fn fetch_health() -> Result<crate::features::auth::types::HealthResponse, AppError> {
    crate::app_lib::get_json_with_credentials("/health").await
}
