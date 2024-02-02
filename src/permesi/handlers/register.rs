use crate::{cli::globals::GlobalArgs, vault::transit::encrypt};
use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use tracing::{debug, error, instrument};
use ulid::Ulid;
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct User {
    email: String,
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
pub async fn register(
    pool: Extension<PgPool>,
    globals: Extension<GlobalArgs>,
    payload: Option<Json<User>>,
) -> impl IntoResponse {
    let user: User = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()),
    };

    debug!("user: {:?}", user);

    // if not valid username, password or token return 400
    if !valid_email(&user.email) {
        return (StatusCode::BAD_REQUEST, "Invalid username".to_string());
    }

    if !valid_password(&user.password) {
        return (StatusCode::BAD_REQUEST, "Invalid password".to_string());
    }

    if !valid_token(&user.token) {
        return (StatusCode::BAD_REQUEST, "Invalid token".to_string());
    }

    // check if user exists
    match user_exists(&pool, &user.email).await {
        Ok(true) => {
            error!("User already exists");
            return (StatusCode::CONFLICT, "User already exists".to_string());
        }
        Ok(false) => (),
        Err(e) => {
            error!("Error checking if user exists: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error checking if user exists".to_string(),
            );
        }
    }

    // encrypt password using vault transit engine
    let password = match encrypt(&globals, &user.password, &user.email).await {
        Ok(password) => password,
        Err(e) => {
            error!("Error encrypting password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error encrypting password".to_string(),
            );
        }
    };

    // insert user into database
    match sqlx::query("INSERT INTO users (email, password) VALUES ($1, $2)")
        .bind(&user.email)
        .bind(&password)
        .execute(&*pool)
        .await
    {
        Ok(_) => (StatusCode::CREATED, "User created".to_string()),
        Err(e) => {
            error!("Error inserting user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error inserting user".to_string(),
            );
        }
    }
}

fn valid_email(email: &str) -> bool {
    Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").map_or(false, |re| re.is_match(email))
}

fn valid_password(password: &str) -> bool {
    // length must be between 64 hex characters
    Regex::new(r"^[0-9a-fA-F]{64}$").map_or(false, |re| re.is_match(password))
}

const fn valid_token(token: &str) -> bool {
    Ulid::from_string(token).is_ok()
}

async fn user_exists(pool: &PgPool, email: &str) -> Result<bool, sqlx::Error> {
    match sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) AS exists")
        .bind(email)
        .fetch_one(pool)
        .await
    {
        Ok(row) => Ok(row.get("exists")),
        Err(e) => Err(e),
    }
}
