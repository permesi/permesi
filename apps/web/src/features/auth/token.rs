//! Fetches short-lived admission (zero) tokens from genesis. These tokens gate
//! auth calls into permesi, so they must be handled carefully and never logged
//! or persisted beyond the request.

use crate::app_lib::{AppError, config::AppConfig, get_json_with_base};
use serde::Deserialize;

/// Deserializes the genesis token response payload.
#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

/// Requests a zero token from genesis for auth calls and validates required config.
/// The token is short-lived and must never be logged.
pub async fn fetch_admission_token() -> Result<String, AppError> {
    let config = AppConfig::load();
    let base_url = config.token_base_url.trim();
    if base_url.is_empty() {
        return Err(AppError::Config(
            "Admission token host is not configured.".to_string(),
        ));
    }

    let client_id = config.client_id.trim();
    if client_id.is_empty() {
        return Err(AppError::Config(
            "Admission client ID is not configured.".to_string(),
        ));
    }

    let path = format!("/token?client_id={client_id}");
    let response: TokenResponse = get_json_with_base(&config.token_base_url, &path).await?;
    Ok(response.token)
}

/// Alias for admission token fetch, kept for naming consistency.
pub async fn fetch_zero_token() -> Result<String, AppError> {
    fetch_admission_token().await
}
