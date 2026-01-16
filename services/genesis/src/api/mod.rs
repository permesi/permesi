use crate::{
    api::handlers::{headers, health, paserk, root, token},
    cli::globals::GlobalArgs,
    vault,
};
use anyhow::{Context, Result};
use axum::{
    Extension,
    body::Body,
    http::{HeaderName, HeaderValue, Method, Request},
    routing::{get, options},
};
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};
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
use utoipa::openapi::{Contact, InfoBuilder, License, OpenApiBuilder, Tag};
use utoipa_axum::{router::OpenApiRouter, routes};
mod admission;
mod handlers;

#[must_use]
pub fn openapi() -> utoipa::openapi::OpenApi {
    // Reuse the same router wiring and only return the generated OpenAPI spec.
    let (_router, openapi) = api_router().split_for_parts();
    openapi
}

/// Build the API router with all documented routes registered.
#[must_use]
pub fn router() -> OpenApiRouter {
    api_router()
}

/// Build the router that also drives the `OpenAPI` document.
///
/// Add new endpoints here via `.routes(routes!(...))` so they are both served
/// and included in the generated `OpenAPI` spec.
/// Routes added outside (like `OPTIONS /health`) are intentionally not documented.
fn api_router() -> OpenApiRouter {
    // `routes!` reads #[utoipa::path] to bind HTTP method + path and add the route to OpenAPI.
    let mut router = OpenApiRouter::with_openapi(cargo_openapi())
        .routes(routes!(health::health))
        .routes(routes!(headers::headers))
        .routes(routes!(token::token))
        .routes(routes!(paserk::paserk));

    let mut genesis_tag = Tag::new("genesis");
    genesis_tag.description = Some("Token Zero generator API".to_string());
    router.get_openapi_mut().tags = Some(vec![genesis_tag]);

    router
}

fn cargo_openapi() -> utoipa::openapi::OpenApi {
    // Use Cargo.toml metadata instead of the utoipa-axum crate info defaults.
    let mut info = InfoBuilder::new()
        .title(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .description(optional_str(env!("CARGO_PKG_DESCRIPTION")))
        .build();

    info.contact = cargo_contact();
    info.license = cargo_license();

    OpenApiBuilder::new().info(info).build()
}

fn cargo_contact() -> Option<Contact> {
    // Cargo authors are `;` separated and may include "Name <email>".
    let authors = env!("CARGO_PKG_AUTHORS");
    let primary = authors.split(';').next().map(str::trim)?;
    if primary.is_empty() {
        return None;
    }

    let (name, email) = parse_author(primary);
    if name.is_none() && email.is_none() {
        return None;
    }

    let mut contact = Contact::new();
    contact.name = name.map(str::to_string);
    contact.email = email.map(str::to_string);
    Some(contact)
}

fn cargo_license() -> Option<License> {
    let identifier = optional_str(env!("CARGO_PKG_LICENSE"))?;
    let mut license = License::new(identifier);
    license.identifier = Some(identifier.to_string());
    Some(license)
}

fn optional_str(value: &'static str) -> Option<&'static str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn parse_author(author: &str) -> (Option<&str>, Option<&str>) {
    if let Some(start) = author.find('<') {
        let name = author[..start].trim();
        let email = author[start + 1..].trim_end_matches('>').trim();
        let name = if name.is_empty() { None } else { Some(name) };
        let email = if email.is_empty() { None } else { Some(email) };
        (name, email)
    } else {
        let name = author.trim();
        (if name.is_empty() { None } else { Some(name) }, None)
    }
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
