//! Client helpers for current-user endpoints.

use crate::{
    app_lib::{AppError, delete_json_with_headers_with_credentials, get_json_with_credentials},
    features::me::types::{MeProfile, SecurityKeySummary},
};

/// Fetch the authenticated user's profile.
pub async fn fetch_me() -> Result<MeProfile, AppError> {
    get_json_with_credentials("/v1/me").await
}

/// List the user's registered security keys.
pub async fn list_security_keys() -> Result<Vec<SecurityKeySummary>, AppError> {
    get_json_with_credentials("/v1/me/mfa/security-keys").await
}

/// Delete a security key by credential ID.
pub async fn delete_security_key(credential_id: &str, token: Option<&str>) -> Result<(), AppError> {
    let headers = token
        .map(|t| vec![("Authorization".to_string(), format!("Bearer {t}"))])
        .unwrap_or_default();
    delete_json_with_headers_with_credentials(
        &format!("/v1/me/mfa/webauthn/{credential_id}"),
        &headers,
    )
    .await
}
