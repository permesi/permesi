//! API entrypoint and router configuration for Genesis.
//!
//! This module coordinates the server lifecycle, including database connectivity,
//! background task management (Vault renewals), and TLS serving.

use crate::{
    api::handlers::{health, root},
    cli::globals::GlobalArgs,
    tls, vault,
};
use anyhow::{Context, Result, anyhow};
use axum::{
    Extension, Router,
    body::Body,
    http::{HeaderName, HeaderValue, Method, Request},
    routing::{get, options},
};
use sqlx::postgres::PgPoolOptions;
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, mpsc};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    request_id::PropagateRequestIdLayer,
    set_header::SetRequestHeaderLayer,
    trace::TraceLayer,
};
use tracing::{Span, debug_span, info, warn};
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

/// Initialize and start the Genesis server.
///
/// # Errors
/// Returns an error if database connectivity fails, Vault initialization fails,
/// or the TLS server fails to start.
pub async fn new(
    port: u16,
    socket_path: Option<String>,
    dsn: String,
    globals: &GlobalArgs,
) -> Result<()> {
    // Renew vault token, gracefully shutdown if failed
    let (tx, rx) = mpsc::unbounded_channel();

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

    if let Some(path) = socket_path {
        serve_socket(app, path, rx).await?;
    } else {
        serve_tls(app, port, rx).await?;
    }

    Ok(())
}

/// Serve the API over a Unix socket, cleaning up the socket file on shutdown.
///
/// # Errors
/// Returns an error if the socket cannot be created, permissions cannot be set,
/// the server fails to start, or a shutdown signal is received.
/// Serve the API over a Unix socket, cleaning up the socket file on shutdown.
///
/// # Errors
/// Returns an error if the socket cannot be created, permissions cannot be set,
/// the server fails to start, or a shutdown signal is received.
async fn serve_socket(
    app: Router,
    path: String,
    mut shutdown_rx: mpsc::UnboundedReceiver<vault::renew::ShutdownSignal>,
) -> Result<()> {
    let path = std::path::PathBuf::from(path);
    if path.exists() {
        tokio::fs::remove_file(&path)
            .await
            .context("Failed to remove existing socket file")?;
    }
    let listener = tokio::net::UnixListener::bind(&path).context("Failed to bind Unix socket")?;

    // Restrict socket access to owner/group; reverse proxies should join the same group.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
        .context("Failed to set socket permissions")?;

    let shutdown_reason = Arc::new(Mutex::new(None));
    let shutdown_reason_task = shutdown_reason.clone();

    info!("Listening on unix:{}", path.display());
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            if let Some(signal) = shutdown_rx.recv().await {
                *shutdown_reason_task.lock().await = Some(signal);
                info!(reason = signal.as_str(), "Gracefully shutdown");
            }
        })
        .await?;
    if let Err(err) = tokio::fs::remove_file(&path).await {
        warn!(error = %err, "Failed to remove unix socket on shutdown");
    }
    if let Some(signal) = shutdown_reason.lock().await.take() {
        return Err(anyhow!("Shutdown requested: {}", signal.as_str()));
    }
    Ok(())
}

async fn serve_tls(
    app: Router,
    port: u16,
    mut shutdown_rx: mpsc::UnboundedReceiver<vault::renew::ShutdownSignal>,
) -> Result<()> {
    let rustls_config = tls::load_server_config()?;
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(rustls_config));
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let handle = axum_server::Handle::new();

    let shutdown_reason = Arc::new(Mutex::new(None));
    let shutdown_reason_task = shutdown_reason.clone();

    tokio::spawn({
        let handle = handle.clone();
        async move {
            if let Some(signal) = shutdown_rx.recv().await {
                *shutdown_reason_task.lock().await = Some(signal);
                info!(reason = signal.as_str(), "Gracefully shutdown");
                handle.graceful_shutdown(Some(Duration::from_secs(30)));
            }
        }
    });

    let tls_paths = crate::tls::runtime_paths()?;
    info!(
        "TLS enabled; bundle loaded from {}",
        tls_paths.pem_bundle_path().display()
    );
    info!("Listening on https://[::]:{}", port);

    axum_server::bind_rustls(addr, tls_config)
        .handle(handle)
        .serve(app.into_make_service())
        .await?;

    if let Some(signal) = shutdown_reason.lock().await.take() {
        return Err(anyhow!("Shutdown requested: {}", signal.as_str()));
    }

    Ok(())
}

/// Build a request tracing span without recording request headers.
///
/// This avoids leaking secret-bearing headers (for example authorization cookies
/// or tokens) into logs and tracing backends.
fn make_span(request: &Request<Body>) -> Span {
    let path = request.uri().path();
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|val| val.to_str().ok())
        .unwrap_or("none");

    debug_span!("http-request", path, request_id)
}

#[cfg(test)]
mod tests {
    use super::serve_socket;
    use crate::vault::renew::ShutdownSignal;
    use anyhow::{Context, Result};
    use axum::Router;
    use std::fs;
    use tokio::{
        sync::mpsc,
        time::{Duration, sleep, timeout},
    };
    use ulid::Ulid;

    #[tokio::test]
    async fn serve_socket_returns_error_on_shutdown_signal() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("genesis-{}", Ulid::new()));
        fs::create_dir_all(&dir).context("create temp dir failed")?;
        let socket_path = dir.join("genesis.sock");

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            sleep(Duration::from_millis(50)).await;
            let _ = tx.send(ShutdownSignal::TokenRenewalFailed);
        });

        let result =
            serve_socket(Router::new(), socket_path.to_string_lossy().to_string(), rx).await;
        assert!(result.is_err(), "expected shutdown error");
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn serve_socket_removes_file_on_shutdown() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("genesis-{}", Ulid::new()));
        fs::create_dir_all(&dir).context("create temp dir failed")?;
        let socket_path = dir.join("genesis.sock");
        let socket_path_wait = socket_path.clone();

        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let _ = timeout(Duration::from_secs(1), async {
                while !socket_path_wait.exists() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            let _ = tx.send(ShutdownSignal::TokenRenewalFailed);
        });

        let result =
            serve_socket(Router::new(), socket_path.to_string_lossy().to_string(), rx).await;
        assert!(result.is_err(), "expected shutdown error");
        assert!(
            !socket_path.exists(),
            "expected socket file to be removed on shutdown"
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
