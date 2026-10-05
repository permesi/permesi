//! HTTP API router and server lifecycle for Permesi.
//!
//! `new` loads configuration secrets from Vault, connects the PostgreSQL pool,
//! builds the per-module state (auth, admin, TOTP, `WebAuthn`), and serves the
//! router over TLS or a Unix socket until a shutdown is requested.
//!
//! Flow Overview:
//! 1) Start the Vault token/lease renewers, which send a `ShutdownSignal` when
//!    renewal fails so the process fails closed.
//! 2) Build state and the router, then start the email outbox worker.
//! 3) Serve until SIGTERM/SIGINT or a fail-closed signal starts a drain bounded
//!    by `shutdown::DRAIN_TIMEOUT`.
//! 4) Stop the email worker at a batch boundary before returning, so a batch
//!    that is being delivered is committed rather than cut off, then close the
//!    PostgreSQL pool so the database sees clean disconnects.
//!
//! A platform-requested stop returns `Ok` (clean exit); a fail-closed stop
//! returns an error so the supervisor restarts the process with fresh Vault
//! credentials.

use crate::{
    api::handlers::{auth, health, root},
    cli::globals::GlobalArgs,
    tls,
    totp::{DekManager, TotpService},
    vault,
    webauthn::{PasskeyConfig, PasskeyService, SecurityKeyService},
};
use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    http::{
        HeaderName, Method,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    routing::{get, options},
};
use service_utils::{
    api_error,
    database::{self, PoolConfig},
    request_id, shutdown,
};
use std::{future::IntoFuture, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{debug, info, warn};
use url::Url;
use utoipa_axum::router::OpenApiRouter;
// Keep these internal to the crate while allowing CLI/server wiring to reference them.
pub(crate) mod email;
pub(crate) mod handlers;
// OpenAPI router wiring and route registration live in openapi.rs.
mod openapi;
mod state;

pub use openapi::openapi;
pub use state::AppState;

/// Build the API router with all documented routes registered.
///
/// The router still needs its [`AppState`]; `build_router` supplies it with `with_state`.
#[must_use]
pub fn router() -> OpenApiRouter<AppState> {
    openapi::api_router()
}

/// Configuration for Vault KV-v2 configuration secrets.
#[derive(Debug, Clone)]
pub struct VaultKvConfig {
    /// Mount path of the KV-v2 engine.
    pub mount: String,
    /// Path to the configuration secret.
    pub path: String,
}

/// Comprehensive application configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Auth module configuration.
    pub auth: auth::AuthConfig,
    /// Admin module configuration.
    pub admin: auth::AdminConfig,
    /// Email module configuration.
    pub email: email::EmailWorkerConfig,
    /// Vault KV module configuration.
    pub kv: VaultKvConfig,
    /// PostgreSQL pool shape shared by handlers and the email outbox worker.
    pub database: PoolConfig,
    /// Opt-in OAuth issuer, resource audience, and bounded transaction lifetimes.
    pub oauth: crate::oauth::config::OAuthConfig,
}

/// Start the server
/// # Errors
/// Return error if failed to start the server
pub async fn new(
    port: u16,
    socket_path: Option<String>,
    dsn: String,
    globals: &GlobalArgs,
    admission: Arc<handlers::AdmissionVerifier>,
    config: AppConfig,
) -> Result<()> {
    // Renew vault token, gracefully shutdown if failed
    let (shutdown_tx, rx) = mpsc::unbounded_channel();

    vault::renew::try_renew(globals, shutdown_tx.clone()).await?;

    let pool = config
        .database
        .connect(&dsn, env!("CARGO_PKG_NAME"))
        .await?;

    let secrets = vault::kv::read_config_secrets(globals, &config.kv.mount, &config.kv.path)
        .await
        .context("Failed to load configuration secrets from Vault")?;

    let opaque_state = auth::OpaqueState::from_seed(
        secrets.opaque_server_seed,
        config.auth.opaque_server_id().to_string(),
        Duration::from_secs(config.auth.opaque_login_ttl_seconds()),
        config.auth.auth_max_pending_states(),
    );

    let mut mfa_config = auth::mfa::MfaConfig::from_env();
    // Set pepper from Vault
    mfa_config = mfa_config.with_recovery_pepper(Arc::from(secrets.mfa_recovery_pepper));

    if mfa_config.required() && mfa_config.recovery_pepper().is_none() {
        return Err(anyhow!(
            "MFA is required but recovery pepper is missing from Vault configuration"
        ));
    }
    let auth_state = Arc::new(auth::AuthState::new(
        config.auth.clone(),
        opaque_state,
        Arc::new(auth::RateLimiter::postgres(
            pool.clone(),
            auth::RateLimitConfig::new(
                config.auth.rate_limit_window_seconds(),
                config.auth.rate_limit_ip_attempts(),
                config.auth.rate_limit_account_attempts(),
            ),
            auth::SubjectKey::derive(&secrets.opaque_server_seed)?,
        )),
        mfa_config,
    ));
    let admin_state = Arc::new(
        auth::AdminState::new(
            config.admin.clone(),
            pool.clone(),
            globals.vault_transport.clone(),
        )
        .context("Failed to initialize admin state")?,
    );

    // Initialize TOTP
    let dek_manager = DekManager::new(globals.clone());
    if let Err(e) = dek_manager.init(&pool).await {
        tracing::error!("Failed to initialize TOTP DEK manager: {e}");
    }
    let totp_service = TotpService::new(dek_manager, pool.clone(), "Permesi".to_string());

    // Initialize Security Keys (WebAuthn)
    let webauthn_allowed_origins = config
        .auth
        .webauthn_allowed_origins()
        .context("Failed to derive WebAuthn allowed origins")?;
    let security_key_service = SecurityKeyService::new(
        pool.clone(),
        config.auth.webauthn_rp_id(),
        &webauthn_allowed_origins,
    )
    .context("Failed to initialize Security Key service")?;

    // Initialize Passkeys (preview mode supported via env)
    let passkey_service = init_passkey_service(&config.auth)?;

    let oauth_state = Arc::new(crate::oauth::oidc::OAuthState::new(
        config.oauth.clone(),
        globals,
    ));
    if oauth_state.config.issuer.is_some() {
        oauth_state
            .jwks()
            .await
            .context("OIDC signing key is unavailable or invalid")?;
    }

    let app = build_router(AppState {
        oauth: oauth_state,
        auth: auth_state,
        admin: admin_state,
        admission,
        shutdown: shutdown_tx,
        pool: pool.clone(),
        totp: totp_service,
        security_keys: Arc::new(security_key_service),
        passkeys: Arc::new(passkey_service),
    })?;

    // Background worker polls email_outbox (DB-backed queue) for pending rows,
    // delivers/logs them, and retries failures with exponential backoff.
    let workers = CancellationToken::new();
    let email_worker = email::spawn_outbox_worker(
        pool.clone(),
        Arc::new(email::LogEmailSender),
        config.email,
        workers.child_token(),
    );

    let served = match socket_path {
        Some(path) => serve_socket(app, path, rx).await,
        None => serve_tls(app, port, rx).await,
    };

    workers.cancel();
    stop_worker("email outbox", email_worker).await;
    database::close(&pool).await;

    served
}

/// Longest wait for a cancelled background worker to reach a safe stopping point.
const WORKER_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Wait for a cancelled worker to finish, abandoning it after [`WORKER_STOP_TIMEOUT`].
///
/// An abandoned worker is dropped with the runtime; its open transaction rolls
/// back, so claimed outbox rows stay pending and are retried by the next process.
async fn stop_worker(name: &str, worker: JoinHandle<()>) {
    match timeout(WORKER_STOP_TIMEOUT, worker).await {
        Ok(Ok(())) => debug!(worker = name, "background worker stopped"),
        Ok(Err(err)) => warn!(worker = name, error = %err, "background worker failed"),
        Err(_) => warn!(worker = name, "background worker did not stop in time"),
    }
}

/// Assemble the served router: documented routes, `/`, `OPTIONS /health`, the JSON
/// error envelope, CORS, shared state, and request correlation (outermost, so every
/// response carries it).
fn build_router(state: AppState) -> Result<Router> {
    let allowed_origins = frontend_origins(state.auth.config().cors_allowed_origins())?;
    let cors = CorsLayer::new()
        .allow_headers([
            CONTENT_TYPE,
            AUTHORIZATION,
            HeaderName::from_static("x-permesi-zero-token"),
            HeaderName::from_static("x-permesi-expected-organization-id"),
        ])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            origin
                .to_str()
                .is_ok_and(|o| allowed_origins.iter().any(|a| a == o))
        }))
        .allow_credentials(true)
        .max_age(Duration::from_hours(24));

    // Build the router from OpenAPI-wired routes, then extend it with non-doc routes like `/` and
    // preflight-only `OPTIONS /health`. The spec stays in openapi.rs for the `openapi` binary.
    // Error responses get the JSON envelope inside CORS, so browsers can read them.
    let (router, _openapi) = router().split_for_parts();
    let app = api_error::with_error_envelope(
        router
            .route("/", get(root::root))
            .route("/health", options(health::health)),
    )
    .layer(cors)
    .with_state(state);
    Ok(request_id::with_request_correlation(app))
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

fn frontend_origins(urls: &[String]) -> Result<Vec<String>> {
    urls.iter()
        .map(|url| {
            let parsed =
                Url::parse(url).with_context(|| format!("Invalid frontend base URL: {url}"))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow!("Frontend base URL must include a valid host: {url}"))?;
            let port = parsed
                .port()
                .map_or_else(String::new, |port| format!(":{port}"));
            Ok(format!("{}://{}{}", parsed.scheme(), host, port))
        })
        .collect()
}

fn init_passkey_service(auth_config: &auth::AuthConfig) -> Result<PasskeyService> {
    let default_origins = auth_config
        .webauthn_allowed_origins()
        .context("Failed to derive passkey origins")?;
    let passkey_config = PasskeyConfig::from_env(auth_config.webauthn_rp_id(), &default_origins)
        .context("Failed to load passkey configuration")?;
    PasskeyService::new(passkey_config, auth_config.auth_max_pending_states())
        .context("Failed to initialize Passkey service")
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
        let dir = std::env::temp_dir().join(format!("permesi-{}", Ulid::generate()));
        fs::create_dir_all(&dir).context("create temp dir failed")?;
        let socket_path = dir.join("permesi.sock");

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
        let dir = std::env::temp_dir().join(format!("permesi-{}", Ulid::generate()));
        fs::create_dir_all(&dir).context("create temp dir failed")?;
        let socket_path = dir.join("permesi.sock");
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
        let dir = std::env::temp_dir().join(format!("permesi-{}", Ulid::generate()));
        fs::create_dir_all(&dir).context("create temp dir failed")?;
        let socket_path = dir.join("permesi.sock");
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

    /// The full router composed exactly as the server composes it, with inert state.
    fn served_app() -> Result<Router> {
        let pool =
            sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://localhost/permesi")?;
        super::build_router(super::AppState::for_tests(pool)?)
    }

    async fn error_envelope(
        response: axum::response::Response,
    ) -> Result<service_utils::api_error::ErrorEnvelope> {
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert!(response.headers().contains_key("x-request-id"));
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    #[tokio::test]
    async fn served_router_answers_unknown_routes_with_envelope() -> Result<()> {
        use tower::ServiceExt;
        let response = served_app()?
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/does-not-exist")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        assert_eq!(error_envelope(response).await?.error.code, "not_found");
        Ok(())
    }

    #[tokio::test]
    async fn served_router_wraps_handler_errors_and_keeps_cors() -> Result<()> {
        use tower::ServiceExt;
        // Signup start without a zero token fails before touching the database.
        let response = served_app()?
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/auth/opaque/signup/start")
                    .header("content-type", "application/json")
                    .header("origin", "https://permesi.dev")
                    .body(axum::body::Body::from(
                        r#"{"email":"user@example.com","registration_request":"AA"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|value| value.to_str().ok()),
            Some("https://permesi.dev")
        );
        let envelope = error_envelope(response).await?;
        assert_eq!(envelope.error.code, "invalid_request");
        assert_eq!(envelope.error.message, "Missing zero token");
        Ok(())
    }

    #[test]
    fn frontend_origins_parses_multiple_urls() -> Result<()> {
        let urls = vec![
            "https://permesi.dev".to_string(),
            "https://k8s.permesi.dev".to_string(),
            "https://www.permesi.dev".to_string(),
        ];
        let origins = super::frontend_origins(&urls)?;
        assert_eq!(
            origins,
            vec![
                "https://permesi.dev",
                "https://k8s.permesi.dev",
                "https://www.permesi.dev",
            ]
        );
        Ok(())
    }

    /// Confirmation UUID preflights retain the configured credentialed-origin boundary.
    #[tokio::test]
    async fn served_router_allows_organization_uuid_header_only_for_trusted_origins() -> Result<()>
    {
        use tower::ServiceExt;
        for origin in ["https://permesi.dev", "https://untrusted.example"] {
            let response = served_app()?
                .oneshot(
                    axum::http::Request::builder()
                        .method("OPTIONS")
                        .uri("/v1/orgs/tenant")
                        .header("origin", origin)
                        .header("access-control-request-method", "DELETE")
                        .header(
                            "access-control-request-headers",
                            "x-permesi-expected-organization-id",
                        )
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            if origin == "https://permesi.dev" {
                assert_eq!(
                    response
                        .headers()
                        .get("access-control-allow-origin")
                        .and_then(|h| h.to_str().ok()),
                    Some(origin)
                );
                assert!(
                    response
                        .headers()
                        .get("access-control-allow-headers")
                        .and_then(|h| h.to_str().ok())
                        .is_some_and(|h| h.contains("x-permesi-expected-organization-id"))
                );
            } else {
                assert!(
                    !response
                        .headers()
                        .contains_key("access-control-allow-origin")
                );
            }
        }
        Ok(())
    }

    /// Real browser preflights must permit the existing OAuth replacement APIs
    /// only for configured origins, preserving credentialed-session boundaries.
    #[tokio::test]
    async fn served_router_allows_oauth_put_preflight_only_for_trusted_origins() -> Result<()> {
        use tower::ServiceExt;
        for origin in ["https://permesi.dev", "https://untrusted.example"] {
            let response = served_app()?
                .oneshot(
                    axum::http::Request::builder()
                        .method("OPTIONS")
                        .uri("/v1/orgs/org/projects/project/envs/env/apps/11111111-1111-4111-8111-111111111111/oauth/clients/22222222-2222-4222-8222-222222222222/redirect-uris")
                        .header("origin", origin)
                        .header("access-control-request-method", "PUT")
                        .header("access-control-request-headers", "content-type")
                        .body(axum::body::Body::empty())?,
                )
                .await?;
            let headers = response.headers();
            if origin == "https://permesi.dev" {
                assert!(response.status().is_success());
                assert_eq!(
                    headers
                        .get("access-control-allow-origin")
                        .and_then(|value| value.to_str().ok()),
                    Some(origin)
                );
                assert_eq!(
                    headers
                        .get("access-control-allow-credentials")
                        .and_then(|value| value.to_str().ok()),
                    Some("true")
                );
                let methods = headers
                    .get("access-control-allow-methods")
                    .context("missing allowed methods")?
                    .to_str()?;
                assert!(methods.split(',').any(|method| method.trim() == "PUT"));
            } else {
                assert!(!headers.contains_key("access-control-allow-origin"));
            }
        }
        Ok(())
    }

    #[test]
    fn frontend_origins_strips_paths_and_ports() -> Result<()> {
        let urls = vec![
            "https://permesi.dev/some/path".to_string(),
            "http://localhost:3000".to_string(),
        ];
        let origins = super::frontend_origins(&urls)?;
        assert_eq!(
            origins,
            vec!["https://permesi.dev", "http://localhost:3000"]
        );
        Ok(())
    }

    #[test]
    fn frontend_origins_rejects_invalid_url() {
        let urls = vec!["not-a-url".to_string()];
        assert!(super::frontend_origins(&urls).is_err());
    }
}
