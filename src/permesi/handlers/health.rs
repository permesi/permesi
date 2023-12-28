use crate::permesi::GIT_COMMIT_HASH;
use axum::{
    body::Body,
    extract::Extension,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgPool};
use tracing::{debug, error, instrument};
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct Health {
    name: String,
    version: String,
    build: String,
}

#[utoipa::path(
    get,
    path= "/health",
    responses (
        (status = 200, description = "Database connection is healthy", body = [Health]),
        (status = 503, description = "Database connection is unhealthy", body = [Health])
    )
)]
// axum handler for health
#[instrument]
pub async fn health(method: Method, pool: Extension<PgPool>) -> impl IntoResponse {
    debug!(method = ?method, "HTTP request method: {}", method);

    // Create a health struct
    let health = Health {
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        build: GIT_COMMIT_HASH.to_string(),
    };

    let body = if method == Method::GET {
        Json(&health).into_response()
    } else {
        Body::empty().into_response()
    };

    let short_hash = if health.build.len() > 7 {
        &health.build[0..7]
    } else {
        ""
    };

    // Create headers using the map method
    let headers = format!("{}:{}:{}", health.name, health.version, short_hash)
        .parse::<HeaderValue>()
        .map(|x_app_header_value| {
            debug!("X-App header: {:?}", x_app_header_value);

            let mut headers = HeaderMap::new();

            headers.insert("X-App", x_app_header_value);

            headers
        })
        .map_err(|err| {
            error!("Failed to parse X-App header: {}", err);
        });

    // Unwrap the headers or provide a default value (empty headers) in case of an error
    let headers = headers.unwrap_or_else(|()| HeaderMap::new());

    let result = match pool.0.acquire().await {
        Ok(mut conn) => match conn.ping().await {
            Ok(()) => Ok(()),
            Err(error) => {
                error!("Failed to ping database: {}", error);
                Err(StatusCode::SERVICE_UNAVAILABLE)
            }
        },

        Err(error) => {
            error!("Failed to acquire database connection: {}", error);
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    };

    match result {
        Ok(()) => {
            debug!("Database connection is healthy");
            (StatusCode::OK, headers, body)
        }

        Err(status_code) => {
            debug!("Database connection is unhealthy");
            (status_code, headers, body)
        }
    }
}
