use crate::app_lib::{AppError, post_json_with_headers, post_json_with_headers_response};
use crate::features::auth::types::{
    OpaqueLoginFinishRequest, OpaqueLoginStartRequest, OpaqueLoginStartResponse,
    OpaqueSignupFinishRequest, OpaqueSignupStartRequest, OpaqueSignupStartResponse,
    ResendVerificationRequest, VerifyEmailRequest,
};

pub async fn opaque_signup_start(
    request: &OpaqueSignupStartRequest,
    zero_token: &str,
) -> Result<OpaqueSignupStartResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_response("/v1/auth/opaque/signup/start", request, &headers).await
}

pub async fn opaque_signup_finish(
    request: &OpaqueSignupFinishRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers("/v1/auth/opaque/signup/finish", request, &headers).await
}

pub async fn opaque_login_start(
    request: &OpaqueLoginStartRequest,
    zero_token: &str,
) -> Result<OpaqueLoginStartResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_response("/v1/auth/opaque/login/start", request, &headers).await
}

pub async fn opaque_login_finish(
    request: &OpaqueLoginFinishRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers("/v1/auth/opaque/login/finish", request, &headers).await
}

pub async fn verify_email(request: &VerifyEmailRequest, zero_token: &str) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers("/v1/auth/verify-email", request, &headers).await
}

pub async fn resend_verification(
    request: &ResendVerificationRequest,
    zero_token: &str,
) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers("/v1/auth/resend-verification", request, &headers).await
}
