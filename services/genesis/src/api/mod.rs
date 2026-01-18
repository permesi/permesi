use crate::{
    api::handlers::{health, root},
    cli::globals::GlobalArgs,
    tls, vault,
};
use anyhow::{Context, Result};
use axum::{
    Extension,
    body::Body,
    http::{HeaderName, HeaderValue, Method, Request},
    routing::{get, options},
};
use sqlx::postgres::PgPoolOptions;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::mpsc;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::PropagateRequestIdLayer,
    set_header::SetRequestHeaderLayer,
    trace::TraceLayer,
};
use tracing::{Span, debug_span, info};
use ulid::Ulid;
use utoipa_axum::router::OpenApiRouter;
// OpenAPI router wiring and route registration live in openapi.rs.
mod admission;
mod handlers;
mod openapi;

pub use openapi::openapi;

/// Build the API router with all documented routes registered.
#[must_use]
pub fn router() -> OpenApiRouter {
    openapi::api_router()
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

    let admission = Arc::new(admission::AdmissionSigner::new(globals).await?);

    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any);

    let (router, _openapi) = router().split_for_parts();
    let app = router
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
                .layer(Extension(pool.clone())),
        )
        .route("/", get(root::root))
        .route("/health", options(health::health))
        .layer(Extension(pool));

    let rustls_config = tls::load_server_config()?;
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(rustls_config));
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let handle = axum_server::Handle::new();

    tokio::spawn({
        let handle = handle.clone();
        async move {
            rx.recv().await;
            info!("Gracefully shutdown");
            handle.graceful_shutdown(Some(Duration::from_secs(30)));
        }
    });

    let tls_paths = crate::tls::runtime_paths()?;
    info!(
        "TLS enabled; cert loaded from {}",
        tls_paths.cert_path().display()
    );
    info!("Listening on https://[::]:{}", port);

    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service())
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
