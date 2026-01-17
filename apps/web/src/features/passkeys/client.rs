//! Client helpers for passkey (WebAuthn) endpoints.

use crate::app_lib::{
    AppError, delete_json_with_headers_with_credentials, get_json_with_credentials,
    post_json_with_headers_with_credentials_response,
};

use super::types::{
    PasskeyCredentialListResponse, PasskeyRegisterFinishRequest, PasskeyRegisterFinishResponse,
    PasskeyRegisterOptionsResponse,
};

/// Request passkey registration options. Requires a zero token header.
pub async fn register_options(
    zero_token: &str,
) -> Result<PasskeyRegisterOptionsResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_with_credentials_response(
        "/v1/me/webauthn/register/options",
        &serde_json::json!({}),
        &headers,
    )
    .await
}

/// Finish passkey registration. Requires a zero token header.
pub async fn register_finish(
    request: &PasskeyRegisterFinishRequest,
    zero_token: &str,
) -> Result<PasskeyRegisterFinishResponse, AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    post_json_with_headers_with_credentials_response(
        "/v1/me/webauthn/register/finish",
        request,
        &headers,
    )
    .await
}

/// List passkey credentials for the current user.
pub async fn list_credentials() -> Result<PasskeyCredentialListResponse, AppError> {
    get_json_with_credentials("/v1/me/webauthn/credentials").await
}

/// Delete a passkey credential. Requires a zero token header.
pub async fn delete_credential(credential_id: &str, zero_token: &str) -> Result<(), AppError> {
    let headers = vec![("X-Permesi-Zero-Token".to_string(), zero_token.to_string())];
    delete_json_with_headers_with_credentials(
        &format!("/v1/me/webauthn/credentials/{credential_id}"),
        &headers,
    )
    .await
}
