use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgPool};
use tracing::{debug, error, instrument};
use ulid::Ulid;
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct User {
    username: String,
    password: String,
    token: String,
    recaptcha: Option<String>,
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

    // if not valid username, password or token return 400
    if !valid_email(&user.username) {
        return (StatusCode::BAD_REQUEST, "Invalid username".to_string());
    }

    if !valid_password(&user.password) {
        return (StatusCode::BAD_REQUEST, "Invalid password".to_string());
    }

    if !valid_token(&user.token) {
        return (StatusCode::BAD_REQUEST, "Invalid token".to_string());
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "Not implemented yet".to_string(),
    )
}

fn valid_email(email: &str) -> bool {
    match Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$") {
        Ok(re) => re.is_match(email),
        Err(_) => false,
    }
}

fn valid_password(password: &str) -> bool {
    // length must be between 64 hex characters
    match Regex::new(r"^[0-9a-fA-F]{64}$") {
        Ok(re) => re.is_match(password),
        Err(_) => false,
    }
}

fn valid_token(token: &str) -> bool {
    match Ulid::from_string(token) {
        Ok(_) => true,
        Err(_) => false,
    }
}
