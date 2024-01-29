use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgPool};
use tracing::{debug, error, instrument};
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct User {
    username: String,
    password: String,
    token: String,
}

#[utoipa::path(
    post,
    path= "/register",
    responses (
        (status = 201, description = "Registration successful", body = [User], content_type = "application/json"),
        (status = 409, description = "User with the specified username or email already exists", body = [User]),
    ),
    tag= "register"
)]
// axum handler for health
#[instrument]
pub async fn register(pool: Extension<PgPool>, payload: Option<Json<User>>) -> impl IntoResponse {
    let user: User = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()),
    };

    debug!("user: {:?}", user);

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Not implemented yet".to_string(),
    )
}
