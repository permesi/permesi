use super::{AdmissionVerifier, DependencyStatus};
use crate::api::GIT_COMMIT_HASH;
use axum::{
    body::Body,
    extract::Extension,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgPool};
use std::sync::Arc;
use tracing::{Instrument, debug, error, info_span};
use utoipa::ToSchema;

#[derive(ToSchema, Serialize, Deserialize, Debug)]
pub struct Health {
    commit: String,
    name: String,
    version: String,
    database: String,
    admission_keyset: String,
}

#[utoipa::path(
    get,
    path= "/health",
    responses (
        (status = 200, description = "Database and admission PASERK endpoint are healthy", body = [Health]),
        (status = 503, description = "Database or admission PASERK endpoint is unhealthy", body = [Health])
    ),
    tag= "health"
)]
// axum handler for health
pub async fn health(
    method: Method,
    pool: Extension<PgPool>,
    admission: Extension<Arc<AdmissionVerifier>>,
) -> impl IntoResponse {
    let acquire_span = info_span!(
        "db.acquire",
        db.system = "postgresql",
        db.operation = "ACQUIRE"
    );
    let result = match pool.0.acquire().instrument(acquire_span).await {
        Ok(mut conn) => {
            let ping_span = info_span!("db.ping", db.system = "postgresql", db.operation = "PING");
            match conn.ping().instrument(ping_span).await {
                Ok(()) => Ok(()),
                Err(error) => {
                    error!("Failed to ping database: {}", error);

                    Err(StatusCode::SERVICE_UNAVAILABLE)
                }
            }
        }

        Err(error) => {
            error!("Failed to acquire database connection: {}", error);

            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    };

    let admission_status = admission.0.dependency_status().await;
    let is_healthy = result.is_ok() && admission_status.is_healthy();

    // Create a health struct
    let health = Health {
        commit: GIT_COMMIT_HASH.to_string(),
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: if result.is_ok() {
            "ok".to_string()
        } else {
            "error".to_string()
        },
        admission_keyset: admission_status.as_str().to_string(),
    };

    let body = if method == Method::GET {
        Json(&health).into_response()
    } else {
        Body::empty().into_response()
    };

    let short_hash = if health.commit.len() > 7 {
        &health.commit[0..7]
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

    match admission_status {
        DependencyStatus::Ok => debug!("Admission keyset is healthy"),
        DependencyStatus::Error => debug!("Admission keyset is unhealthy"),
        DependencyStatus::Static => debug!("Admission keyset is static"),
    }

    if result.is_ok() {
        debug!("Database connection is healthy");
    } else {
        debug!("Database connection is unhealthy");
    }

    if is_healthy {
        (StatusCode::OK, headers, body)
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, headers, body)
    }
}
