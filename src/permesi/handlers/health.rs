use crate::permesi::GIT_COMMIT_HASH;
use axum::{
    extract::Extension,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json},
};
use serde_json::json;
use sqlx::{Connection, PgPool};
use tracing::{debug, error, instrument};

// axum handler for health
#[instrument]
pub async fn health(method: Method, pool: Extension<PgPool>) -> impl IntoResponse {
    debug!(method = ?method, "HTTP request method: {}", method);

    let body = if method == Method::GET {
        Json(json!({
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
            "build": GIT_COMMIT_HASH,
        }))
    } else {
        Json(json!({}))
    };

    let short_hash = if GIT_COMMIT_HASH.len() > 7 {
        &GIT_COMMIT_HASH[0..7]
    } else {
        ""
    };

    // Create headers using the map method
    let headers = format!(
        "{}:{}:{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        short_hash
    )
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
        Ok(mut conn) => {
            let ping_result = conn.ping().await;
            Ok(ping_result.map(|()| conn))
        }

        Err(error) => {
            error!("Failed to acquire database connection: {}", error);
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    };

    match result {
        Ok(_) => {
            debug!("Database connection is healthy");
            (StatusCode::OK, headers, body)
        }

        Err(status_code) => {
            debug!("Database connection is unhealthy");
            (status_code, headers, body)
        }
    }
}
