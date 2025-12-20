#![allow(clippy::needless_for_each)]

#[allow(unused_imports)]
use crate::{
    cli::globals::GlobalArgs,
    genesis::handlers::{
        headers::__path_headers, health, health::__path_health, jwks, jwks::__path_jwks, token,
        token::__path_token,
    },
    vault,
};
use anyhow::{Context, Result};
use axum::{
    Extension, Router,
    body::Body,
    http::{HeaderName, HeaderValue, Method, Request},
    routing::{get, post},
};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tokio::{net::TcpListener, sync::mpsc};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::PropagateRequestIdLayer,
    set_header::SetRequestHeaderLayer,
    trace::TraceLayer,
};
use tracing::{Span, debug_span, info};
use ulid::Ulid;
use utoipa::OpenApi;

mod admission;
mod handlers;

#[allow(clippy::doc_markdown, clippy::needless_raw_string_hashes)]
pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const GIT_COMMIT_HASH: &str = match built_info::GIT_COMMIT_HASH {
    Some(hash) => hash,
    None => "unknown",
};

#[derive(OpenApi)]
#[openapi(
    paths(health, headers, token, jwks),
    components(
        schemas(health::Health, token::Token)
    ),
    tags(
        (name = "genesis", description = "Token Zero generator API"),
    )

)]
struct ApiDoc;

#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

/// router
/// # Errors
/// Returns an error if the server fails to start
pub async fn new(port: u16, dsn: String, globals: &GlobalArgs) -> Result<()> {
    // Renew vault token, gracefully shutdown if failed
    let (tx, mut rx) = mpsc::unbounded_channel();

    vault::renew::try_renew(globals, tx).await?;

    // Connect to database
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(5)
        .max_lifetime(Duration::from_secs(60 * 2))
        .test_before_acquire(true)
        .connect(&dsn)
        .await
        .context("Failed to connect to database")?;

    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any);

    let app = Router::new()
        .route("/headers", get(handlers::headers))
        .route("/token", get(handlers::token))
        .route("/verify", post(handlers::verify))
        .route("/jwks.json", get(handlers::jwks))
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestHeaderLayer::if_not_present(
                    HeaderName::from_static("x-request-id"),
                    |_req: &_| HeaderValue::from_str(Ulid::new().to_string().as_str()).ok(),
                ))
                .layer(PropagateRequestIdLayer::new(HeaderName::from_static(
                    "x-request-id",
                )))
                .layer(TraceLayer::new_for_http().make_span_with(make_span))
                .layer(cors)
                .layer(Extension(pool.clone())),
        )
        .route("/health", get(handlers::health).options(handlers::health))
        .layer(Extension(pool));

    let listener = TcpListener::bind(format!("::0:{port}")).await?;

    info!("Listening on [::]:{}", port);

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async move {
            rx.recv().await;
            info!("Gracefully shutdown");
        })
        .await?;

    Ok(())
}

// span
fn make_span(request: &Request<Body>) -> Span {
    let headers = request.headers();
    let path = request.uri().path();
    let request_id = headers
        .get("x-request-id")
        .and_then(|val| val.to_str().ok())
        .unwrap_or("none");

    debug_span!("http-request", path, ?headers, request_id)
}
