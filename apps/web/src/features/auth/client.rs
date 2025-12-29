use crate::app_lib::{AppError, post_json_no_response};
use crate::features::auth::types::{LoginRequest, UserSession};

pub async fn login(request: &LoginRequest) -> Result<UserSession, AppError> {
    post_json_no_response("/api/auth/login", request).await?;
    Ok(UserSession {
        user_id: request.email.clone(),
        access_token: request.token.clone(),
    })
}
