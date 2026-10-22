//! Client helpers for user-related API endpoints. These functions keep endpoint
//! paths centralized and assume the backend enforces authorization.

use crate::{
    app_lib::{AppError, get_json_with_credentials},
    features::users::types::{OperatorStatus, UserDetail, UserSummary},
};

/// Fetches the user list from the API.
pub async fn list_users() -> Result<Vec<UserSummary>, AppError> {
    get_json_with_credentials("/v1/users").await
}

/// Reads designation state through the operator-only API.
pub async fn get_operator(id: &str) -> Result<OperatorStatus, AppError> {
    get_json_with_credentials(&format!("/v1/users/{id}/operator")).await
}

/// Sends one fixed, recently authenticated designation operation.
pub async fn operator_action(id: &str, action: &str, reason: &str) -> Result<(), AppError> {
    if !matches!(action, "request-enable" | "enable" | "disable") {
        return Err(AppError::Config("Unsupported operator action.".to_owned()));
    }
    crate::app_lib::post_json_with_headers_with_credentials(
        &format!("/v1/users/{id}/operator/{action}"),
        &serde_json::json!({"reason":reason}),
        &[],
    )
    .await
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
