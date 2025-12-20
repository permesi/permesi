use crate::genesis::admission::admission_config;
use crate::genesis::handlers::token::TOKEN_EXPIRATION;
use admission_token::verify_rs256;
use axum::{Json, extract::Extension, http::StatusCode, response::IntoResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use tracing::{debug, error, instrument};
use ulid::Ulid;
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct Token {
    token: String,
}

#[utoipa::path(
    post,
    path= "/verify",
    responses (
        (status = 202, description = "Return token", body = [Token], content_type = "application/json"),
        (status = 403, description = "Token expired or invalid"),
    ),
    tag = "verify",
)]
#[instrument]
pub async fn verify(Extension(pool): Extension<PgPool>, payload: Json<Token>) -> impl IntoResponse {
    let token = &payload.token;

    let cfg = match admission_config() {
        Ok(cfg) => cfg,
        Err(err) => {
            error!("Admission config error: {err:#}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    let now = Utc::now().timestamp();
    let claims = match verify_rs256(token, cfg.jwks(), &cfg.issuer, &cfg.audience, now) {
        Ok(c) => c,
        Err(err) => {
            error!("Invalid admission token: {err}");
            return StatusCode::FORBIDDEN;
        }
    };

    match Ulid::from_string(&claims.jti) {
        Ok(_) => (),
        Err(e) => {
            error!("Error while parsing jti: {}", e);
            return StatusCode::FORBIDDEN;
        }
    }

    let query = format!(
        "SELECT EXISTS(SELECT 1 FROM tokens WHERE id = $1::ulid AND id::timestamp > NOW() - INTERVAL '{TOKEN_EXPIRATION} seconds') AS valid"
    );

    match sqlx::query(&query).bind(&claims.jti).fetch_one(&pool).await {
        Ok(row) => {
            let valid: bool = row.get("valid");
            if valid {
                debug!("Token is valid");

                StatusCode::ACCEPTED
            } else {
                error!("Token is invalid");

                StatusCode::FORBIDDEN
            }
        }

        Err(e) => {
            error!("Error while verifying token: {}", e);

            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
