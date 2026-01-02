use crate::{
    api::handlers::{AdmissionVerifier, valid_email, valid_password, verify_token},
    cli::globals::GlobalArgs,
    vault::transit::encrypt,
};
use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{Instrument, debug, error, info_span, instrument};
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
        (status = 409, description = "User with the specified email already exists", body = [UserRegister]),
    ),
    tag= "register"
)]
// axum handler for health
#[instrument(skip(pool, globals, admission, payload))]
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
    let email = user.email.trim().to_lowercase();

    // if not valid email, password or token return 400
    if !valid_email(&email) {
        return (StatusCode::BAD_REQUEST, "Invalid email".to_string());
    }

    if !valid_password(&user.password) {
        return (StatusCode::BAD_REQUEST, "Invalid password".to_string());
    }

    if !verify_token(&admission, &user.token).await {
        return (StatusCode::BAD_REQUEST, "Invalid token".to_string());
    }

    // check if user exists
    match user_exists(&pool, &email).await {
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
    let password = match encrypt(&globals, &user.password, &email).await {
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
    let query = "INSERT INTO users (email, password) VALUES ($1, $2)";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "INSERT",
        db.statement = query
    );
    match sqlx::query(query)
        .bind(&email)
        .bind(&password)
        .execute(&*pool)
        .instrument(span)
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
    let query = "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) AS exists";
    let span = info_span!(
        "db.query",
        db.system = "postgresql",
        db.operation = "SELECT",
        db.statement = query
    );
    match sqlx::query(query)
        .bind(email)
        .fetch_one(pool)
        .instrument(span)
        .await
    {
        Ok(row) => Ok(row.get("exists")),
        Err(e) => Err(e),
    }
}
