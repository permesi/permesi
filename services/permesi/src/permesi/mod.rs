#![allow(clippy::needless_for_each)]

use crate::{
    cli::globals::GlobalArgs,
    permesi::handlers::{
        health, health::__path_health, user_login, user_login::__path_login, user_register,
        user_register::__path_register,
    },
    vault,
};
use anyhow::{Context, Result};
use axum::{
    Extension, Router,
    body::Body,
    extract::MatchedPath,
    http::{
        HeaderName, HeaderValue, Method, Request,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    routing::{get, post},
};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::{net::TcpListener, sync::mpsc};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::PropagateRequestIdLayer,
    set_header::SetRequestHeaderLayer,
    trace::TraceLayer,
};
use tracing::{Span, info, info_span};
use ulid::Ulid;
use utoipa::OpenApi;

pub(crate) mod handlers;

#[allow(clippy::doc_markdown, clippy::needless_raw_string_hashes)]
pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const GIT_COMMIT_HASH: &str = match built_info::GIT_COMMIT_HASH {
    Some(hash) => hash,
    None => "unknown",
};

pub static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[derive(OpenApi)]
#[openapi(
    paths(health, register, login),
    components(schemas(health::Health, user_register::UserRegister, user_login::UserLogin)),
    tags(
        (name = "permesi", description = "Identity and access management API")
    )
)]
struct ApiDoc;

#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

/// Start the server
/// # Errors
/// Return error if failed to start the server
pub async fn new(
    port: u16,
    dsn: String,
    globals: &GlobalArgs,
    admission: Arc<handlers::AdmissionVerifier>,
) -> Result<()> {
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
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(Any);

    let app = Router::new()
        .route("/", get(|| async { "🌱" }))
        .route("/user/register", post(handlers::register))
        .route("/user/login", post(handlers::login))
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
                .layer(Extension(admission.clone()))
                .layer(Extension(globals.clone()))
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

fn make_span(request: &Request<Body>) -> Span {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|val| val.to_str().ok())
        .unwrap_or("none");
    let matched_path = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| request.uri().path(), MatchedPath::as_str);

    info_span!(
        "http.request",
        http.method = %request.method(),
        http.route = matched_path,
        request_id
    )
}
