//! API entrypoint and router configuration for Genesis.
//!
//! This module coordinates the server lifecycle, including database connectivity,
//! background task management (Vault renewals), and TLS serving.
//!
//! The server runs until SIGTERM/SIGINT or a fail-closed `ShutdownSignal` from
//! the Vault renewers starts a drain bounded by `shutdown::DRAIN_TIMEOUT`. A
//! platform-requested stop returns `Ok`; a fail-closed stop returns an error so
//! the supervisor restarts the process with fresh credentials.

use crate::{
    api::handlers::{health, root},
    cli::globals::GlobalArgs,
    tls, vault,
};
use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    http::Method,
    routing::{get, options},
};
use service_utils::{
    api_error,
    database::{self, PoolConfig},
    request_id, shutdown,
};
use std::{future::IntoFuture, os::unix::fs::PermissionsExt, sync::Arc};
use tokio::{
    sync::{Mutex, mpsc},
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use utoipa_axum::router::OpenApiRouter;

// OpenAPI router wiring and route registration live in openapi.rs.
mod admission;
mod handlers;
mod openapi;
mod state;

pub use openapi::openapi;
pub use state::AppState;

/// Build the API router with all documented routes registered.
///
/// The router still needs its [`AppState`]; `new` supplies it with `with_state`.
#[must_use]
pub fn router() -> OpenApiRouter<AppState> {
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
    pool_config: PoolConfig,
    globals: &GlobalArgs,
) -> Result<()> {
    // Renew vault token, gracefully shutdown if failed
    let (shutdown_tx, rx) = mpsc::unbounded_channel();

    vault::renew::try_renew(globals, shutdown_tx.clone()).await?;

    let pool = pool_config.connect(&dsn, env!("CARGO_PKG_NAME")).await?;

    let admission = Arc::new(admission::AdmissionSigner::new(globals).await?);

    let app = build_router(AppState {
        admission,
        shutdown: shutdown_tx,
        pool: pool.clone(),
    });

    let served = match socket_path {
        Some(path) => serve_socket(app, path, rx).await,
        None => serve_tls(app, port, rx).await,
    };
    database::close(&pool).await;

    served
}

/// Assemble the served router: documented routes, `/`, `OPTIONS /health`, the JSON
/// error envelope, CORS, shared state, and request correlation (outermost).
///
/// Every route is registered before layering so `/` and `OPTIONS /health` get the
/// same layers as the documented routes, and error responses carry CORS headers.
fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        // allow `GET` and `POST` when accessing the resource
        .allow_methods([Method::GET, Method::POST])
        // allow requests from any origin
        .allow_origin(Any);

    let (router, _openapi) = router().split_for_parts();
    let app = api_error::with_error_envelope(
        router
            .route("/", get(root::root))
            .route("/health", options(health::health)),
    )
    .layer(cors)
    .with_state(state);
    request_id::with_request_correlation(app)
}

/// Serve the API over a Unix socket, cleaning up the socket file on shutdown.
///
/// SIGTERM/SIGINT and fail-closed signals both drain for at most
/// [`shutdown::DRAIN_TIMEOUT`]; only a fail-closed signal is returned as an error.
///
/// # Errors
/// Returns an error if the socket cannot be created, permissions cannot be set,
/// the server fails, or a fail-closed shutdown signal is received.
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
    let drain_started = CancellationToken::new();

    info!("Listening on unix:{}", path.display());
    let socket_server = axum::serve(listener, app).with_graceful_shutdown({
        let shutdown_reason = shutdown_reason.clone();
        let drain_started = drain_started.clone();
        async move {
            *shutdown_reason.lock().await = shutdown::requested(&mut shutdown_rx).await;
            drain_started.cancel();
        }
    });
    // axum waits for every connection to close; bound the drain like the TLS server.
    let drain_deadline = async {
        drain_started.cancelled().await;
        sleep(shutdown::DRAIN_TIMEOUT).await;
    };
    let served = tokio::select! {
        result = socket_server.into_future() => result.context("Unix socket server failed"),
        () = drain_deadline => {
            warn!("Graceful drain timed out; closing remaining connections");
            Ok(())
        }
    };

    if let Err(err) = tokio::fs::remove_file(&path).await {
        warn!(error = %err, "Failed to remove unix socket on shutdown");
    }
    served?;
    if let Some(signal) = shutdown_reason.lock().await.take() {
        return Err(anyhow!("Shutdown requested: {}", signal.as_str()));
    }
    Ok(())
}

/// Serve the API over TLS using Vault-issued certificates.
///
/// The listener prefers a dual-stack IPv6 socket so one bind can accept both
/// IPv6 and IPv4 traffic. Hosts without usable IPv6 support fall back to an
/// IPv4 wildcard listener.
///
/// SIGTERM/SIGINT and fail-closed signals both start a graceful drain bounded
/// by [`shutdown::DRAIN_TIMEOUT`]; only a fail-closed signal is returned as an error.
///
/// # Errors
/// Returns an error if TLS configuration or the server fails to start, or a
/// fail-closed shutdown signal is received.
async fn serve_tls(
    app: Router,
    port: u16,
    mut shutdown_rx: mpsc::UnboundedReceiver<vault::renew::ShutdownSignal>,
) -> Result<()> {
    let rustls_config = tls::load_server_config()?;
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(rustls_config));
    let (listener, listen_addr) = tls::bind_dual_stack_listener(port)?;
    let handle = axum_server::Handle::new();

    let shutdown_reason = Arc::new(Mutex::new(None));

    tokio::spawn({
        let handle = handle.clone();
        let shutdown_reason = shutdown_reason.clone();
        async move {
            *shutdown_reason.lock().await = shutdown::requested(&mut shutdown_rx).await;
            handle.graceful_shutdown(Some(shutdown::DRAIN_TIMEOUT));
        }
    });

    let tls_paths = crate::tls::runtime_paths()?;
    info!(
        "TLS enabled; bundle loaded from {}",
        tls_paths.pem_bundle_path().display()
    );
    info!("Listening on https://{listen_addr}");

    axum_server::from_tcp_rustls(listener, tls_config)
        .context("Failed to configure TLS server from pre-bound TCP listener")?
        .handle(handle)
        .serve(app.into_make_service())
        .await?;

    if let Some(signal) = shutdown_reason.lock().await.take() {
        return Err(anyhow!("Shutdown requested: {}", signal.as_str()));
    }

    Ok(())
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

    /// Tests that listen for OS signals share the process: a SIGTERM sent by one
    /// reaches every listener, so they must not overlap.
    static OS_SIGNAL_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn serve_socket_returns_error_on_shutdown_signal() -> Result<()> {
        let _serial = OS_SIGNAL_TESTS.lock().await;
        let dir = std::env::temp_dir().join(format!("genesis-{}", Ulid::generate()));
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
    async fn serve_socket_exits_cleanly_on_sigterm() -> Result<()> {
        let _serial = OS_SIGNAL_TESTS.lock().await;
        // Hold a SIGTERM listener so the signal can never use the default action
        // and kill the test binary, even before the server installs its own.
        let _guard = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let dir = std::env::temp_dir().join(format!("genesis-{}", Ulid::generate()));
        fs::create_dir_all(&dir).context("create temp dir failed")?;
        let socket_path = dir.join("genesis.sock");
        let socket_path_wait = socket_path.clone();

        let (_tx, rx) = mpsc::unbounded_channel::<ShutdownSignal>();
        tokio::spawn(async move {
            let _ = timeout(Duration::from_secs(1), async {
                while !socket_path_wait.exists() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            // Let the server poll its shutdown future so its handler is registered.
            sleep(Duration::from_millis(100)).await;
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &std::process::id().to_string()])
                .status();
        });

        let result = timeout(
            Duration::from_secs(5),
            serve_socket(Router::new(), socket_path.to_string_lossy().to_string(), rx),
        )
        .await
        .context("server did not stop after SIGTERM")?;
        assert!(
            result.is_ok(),
            "SIGTERM must be a clean shutdown: {result:?}"
        );
        assert!(
            !socket_path.exists(),
            "expected socket file to be removed on shutdown"
        );
        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[tokio::test]
    async fn serve_socket_removes_file_on_shutdown() -> Result<()> {
        let _serial = OS_SIGNAL_TESTS.lock().await;
        let dir = std::env::temp_dir().join(format!("genesis-{}", Ulid::generate()));
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
