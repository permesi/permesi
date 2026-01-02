use crate::{
    api::handlers::{auth, health, root},
    cli::globals::GlobalArgs,
    vault,
};
use anyhow::{Context, Result, anyhow};
use axum::{
    Extension,
    body::Body,
    extract::MatchedPath,
    http::{
        HeaderName, HeaderValue, Method, Request,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    routing::{get, options},
};
use sqlx::postgres::PgPoolOptions;
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc};
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::PropagateRequestIdLayer,
    set_header::SetRequestHeaderLayer,
    trace::TraceLayer,
};
use tracing::{Span, info, info_span};
use ulid::Ulid;
use url::Url;
use utoipa_axum::router::OpenApiRouter;
// Keep these internal to the crate while allowing CLI/server wiring to reference them.
pub(crate) mod email;
pub(crate) mod handlers;
// OpenAPI router wiring and route registration live in openapi.rs.
mod openapi;

pub use openapi::openapi;

/// Build the API router with all documented routes registered.
#[must_use]
pub fn router() -> OpenApiRouter {
    openapi::api_router()
}

#[allow(clippy::doc_markdown, clippy::needless_raw_string_hashes)]
pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const GIT_COMMIT_HASH: &str = match built_info::GIT_COMMIT_HASH {
    Some(hash) => hash,
    None => "unknown",
};

pub static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

/// Start the server
/// # Errors
/// Return error if failed to start the server
pub async fn new(
    port: u16,
    dsn: String,
    globals: &GlobalArgs,
    admission: Arc<handlers::AdmissionVerifier>,
    auth_config: auth::AuthConfig,
    email_config: email::EmailWorkerConfig,
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

    let opaque_seed = vault::kv::read_opaque_seed(
        globals,
        auth_config.opaque_kv_mount(),
        auth_config.opaque_kv_path(),
    )
    .await
    .context("Failed to load OPAQUE seed from Vault")?;
    let opaque_state = auth::OpaqueState::from_seed(
        opaque_seed,
        auth_config.opaque_server_id().to_string(),
        Duration::from_secs(auth_config.opaque_login_ttl_seconds()),
    );
    let auth_state = Arc::new(auth::AuthState::new(
        auth_config,
        opaque_state,
        Arc::new(auth::NoopRateLimiter),
    ));

    // Background worker polls email_outbox (DB-backed queue) for pending rows,
    // delivers/logs them, and retries failures with exponential backoff.
    email::spawn_outbox_worker(pool.clone(), Arc::new(email::LogEmailSender), email_config);

    let frontend_origin = frontend_origin(auth_state.config().frontend_base_url())?;
    let cors = CorsLayer::new()
        .allow_headers([
            CONTENT_TYPE,
            AUTHORIZATION,
            HeaderName::from_static("x-permesi-zero-token"),
        ])
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(AllowOrigin::exact(frontend_origin))
        .allow_credentials(true);

    // Build the router from OpenAPI-wired routes, then extend it with non-doc routes like `/` and
    // preflight-only `OPTIONS /health`. The spec stays in openapi.rs for the `openapi` binary.
    let (router, _openapi) = router().split_for_parts();
    let app = router
        .route("/", get(root::root))
        .route("/health", options(health::health))
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
                .layer(Extension(auth_state.clone()))
                .layer(Extension(admission.clone()))
                .layer(Extension(globals.clone()))
                .layer(Extension(pool.clone())),
        )
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

fn frontend_origin(frontend_base_url: &str) -> Result<HeaderValue> {
    let parsed = Url::parse(frontend_base_url)
        .with_context(|| format!("Invalid frontend base URL: {frontend_base_url}"))?;
    let host = parsed.host_str().ok_or_else(|| {
        anyhow!("Frontend base URL must include a valid host: {frontend_base_url}")
    })?;
    let port = parsed
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    let origin = format!("{}://{}{}", parsed.scheme(), host, port);
    HeaderValue::from_str(&origin).context("Failed to build frontend origin header")
}
