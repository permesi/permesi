use crate::{
    cli::globals::GlobalArgs,
    permesi::handlers::{AdmissionVerifier, valid_email, valid_password, verify_token},
    vault::transit::encrypt,
};
use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{debug, error, instrument};
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct UserRegister {
    email: String,
    password: String,
    token: String,
    recaptcha: Option<String>,
}

#[utoipa::path(
    post,
    path= "/user/register",
    responses (
        (status = 201, description = "Registration successful", body = [UserRegister], content_type = "application/json"),
        (status = 409, description = "User with the specified username or email already exists", body = [UserRegister]),
    ),
    tag= "register"
)]
// axum handler for health
#[instrument]
pub async fn register(
    pool: Extension<PgPool>,
    globals: Extension<GlobalArgs>,
    admission: Extension<Arc<AdmissionVerifier>>,
    payload: Option<Json<UserRegister>>,
) -> impl IntoResponse {
    let user: UserRegister = match payload {
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

    if !verify_token(&admission, &user.token).await {
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
