use crate::app_lib::{AppError, get_json};
use crate::features::users::types::{UserDetail, UserSummary};

pub async fn list_users() -> Result<Vec<UserSummary>, AppError> {
    get_json("/api/users").await
}

pub async fn get_user(id: &str) -> Result<UserDetail, AppError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(AppError::Config("User id is required.".to_string()));
    }

    get_json(&format!("/api/users/{trimmed}")).await
}
