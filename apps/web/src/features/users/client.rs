//! Client helpers for user-related API endpoints. These functions keep endpoint
//! paths centralized and assume the backend enforces authorization.

use crate::{
    app_lib::{AppError, get_json},
    features::users::types::{UserDetail, UserSummary},
};

/// Fetches the user list from the API.
pub async fn list_users() -> Result<Vec<UserSummary>, AppError> {
    get_json("/api/users").await
}

/// Fetches user details by id after basic input validation.
pub async fn get_user(id: &str) -> Result<UserDetail, AppError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(AppError::Config("User id is required.".to_string()));
    }

    get_json(&format!("/api/users/{trimmed}")).await
}
