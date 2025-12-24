use crate::{
    cli::globals::GlobalArgs,
    permesi::handlers::{AdmissionVerifier, valid_email, valid_password, verify_token},
    vault::transit::decrypt,
};
use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tracing::{debug, error, instrument};
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct UserLogin {
    email: String,
    password: String,
    token: String,
    recaptcha: Option<String>,
}

#[utoipa::path(
    post,
    path= "/user/login",
    responses (
        (status = 200, description = "Login successful", body = [UserLogin], content_type = "application/json"),
        (status = 401, description = "Unauthorized", body = [UserLogin]),
    ),
    tag= "login"
)]
// axum handler for health
#[instrument]
pub async fn login(
    pool: Extension<PgPool>,
    globals: Extension<GlobalArgs>,
    admission: Extension<Arc<AdmissionVerifier>>,
    payload: Option<Json<UserLogin>>,
) -> impl IntoResponse {
    let user: UserLogin = match payload {
        Some(Json(payload)) => payload,
        None => return (StatusCode::BAD_REQUEST, "Missing payload".to_string()),
    };

    debug!("user: {:?}", user);

    // if not valid username, password or token return 400
    if !valid_email(&user.email) {
        error!("Invalid username");

        return (StatusCode::BAD_REQUEST, "Invalid username".to_string());
    }

    if !valid_password(&user.password) {
        error!("Invalid password");

        return (StatusCode::BAD_REQUEST, "Invalid password".to_string());
    }

    if !verify_token(&admission, &user.token).await {
        return (StatusCode::BAD_REQUEST, "Invalid token".to_string());
    }

    // get password from database and decrypt it using vault transit
    let stored_password = match get_password(&pool, &user.email).await {
        Ok(ciphertext) => decrypt(&globals, &ciphertext, &user.email)
            .await
            .map_err(|e| {
                error!("Error decrypting password: {:?}", e);

                StatusCode::INTERNAL_SERVER_ERROR
            }),

        Err(sqlx::Error::RowNotFound) => {
            debug!("User not found");

            return (StatusCode::UNAUTHORIZED, String::from("Unauthorized"));
        }

        Err(e) => {
            error!("Error getting password from database: {:?}", e);

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Error getting password"),
            );
        }
    };

    // compare decrypted password with user password
    match stored_password {
        Ok(password) => {
            if password == user.password {
                debug!("Login successful");

                (StatusCode::OK, String::from("Login successful"))
            } else {
                debug!("Unauthorized");

                (StatusCode::UNAUTHORIZED, String::from("Unauthorized"))
            }
        }

        Err(e) => {
            error!("Error getting password: {:?}", e);

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting password".to_string(),
            )
        }
    }
}

async fn get_password(pool: &PgPool, email: &str) -> Result<String, sqlx::Error> {
    match sqlx::query("SELECT password FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(pool)
        .await
    {
        Ok(row) => Ok(row.get(0)),
        Err(e) => Err(e),
    }
}
