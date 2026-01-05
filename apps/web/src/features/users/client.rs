//! Client helpers for user-related API endpoints. These functions keep endpoint
//! paths centralized and assume the backend enforces authorization.

use crate::{
    app_lib::{AppError, get_json_with_credentials},
    features::users::types::{UserDetail, UserSummary},
};

/// Fetches the user list from the API.
pub async fn list_users() -> Result<Vec<UserSummary>, AppError> {
    get_json_with_credentials("/v1/users").await
}

/// Fetches user details by id after basic input validation.
pub async fn get_user(id: &str) -> Result<UserDetail, AppError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(AppError::Config("User id is required.".to_string()));
    }

    get_json_with_credentials(&format!("/v1/users/{trimmed}")).await
}

/// Updates a user's platform role.
pub async fn set_user_role(id: &str, role: &str) -> Result<(), AppError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(AppError::Config("User id is required.".to_string()));
    }

    crate::app_lib::post_json_with_headers_with_credentials(
        &format!("/v1/users/{trimmed}/role"),
        &serde_json::json!({ "role": role }),
        &[],
    )
    .await
}
