use crate::app_lib::config::AppConfig;
use crate::app_lib::{AppError, get_json_with_base};
use serde::Deserialize;

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

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
