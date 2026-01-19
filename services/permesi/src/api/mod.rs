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
    Extension, Router,
    body::Body,
    extract::MatchedPath,
    http::{
        HeaderName, HeaderValue, Method, Request,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
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
}

/// Start the server
/// # Errors
/// Return error if failed to start the server
pub async fn new(
    port: u16,
    dsn: String,
    globals: &GlobalArgs,
    admission: Arc<handlers::AdmissionVerifier>,
    config: AppConfig,
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

    let secrets = vault::kv::read_config_secrets(globals, &config.kv.mount, &config.kv.path)
        .await
        .context("Failed to load configuration secrets from Vault")?;

    let opaque_state = auth::OpaqueState::from_seed(
        secrets.opaque_server_seed,
        config.auth.opaque_server_id().to_string(),
        Duration::from_secs(config.auth.opaque_login_ttl_seconds()),
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
        Arc::new(auth::NoopRateLimiter),
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

    // Background worker polls email_outbox (DB-backed queue) for pending rows,
    // delivers/logs them, and retries failures with exponential backoff.
    email::spawn_outbox_worker(pool.clone(), Arc::new(email::LogEmailSender), config.email);

    // Initialize TOTP
    let dek_manager = DekManager::new(globals.clone());
    if let Err(e) = dek_manager.init(&pool).await {
        tracing::error!("Failed to initialize TOTP DEK manager: {e}");
    }
    let totp_service = TotpService::new(dek_manager, pool.clone(), "Permesi".to_string());

    // Initialize Security Keys (WebAuthn)
    let security_key_service = SecurityKeyService::new(
        pool.clone(),
        config.auth.webauthn_rp_id(),
        config.auth.webauthn_rp_origin(),
    )
    .context("Failed to initialize Security Key service")?;

    // Initialize Passkeys (preview mode supported via env)
    let passkey_service = init_passkey_service(&config.auth)?;

    let frontend_origin = frontend_origin(auth_state.config().frontend_base_url())?;
    let cors = CorsLayer::new()
        .allow_headers([
            CONTENT_TYPE,
            AUTHORIZATION,
            HeaderName::from_static("x-permesi-zero-token"),
        ])
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .expose_headers([AUTHORIZATION])
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
                .layer(Extension(admin_state.clone()))
                .layer(Extension(admission.clone()))
                .layer(Extension(globals.clone()))
                .layer(Extension(pool.clone()))
                .layer(Extension(totp_service))
                .layer(Extension(Arc::new(security_key_service)))
                .layer(Extension(Arc::new(passkey_service))),
        )
        .layer(Extension(pool));

    serve_tls(app, port, rx).await?;

    Ok(())
}

/// Serve the API over TLS using Vault-issued certificates.
///
/// # Errors
/// Returns an error if TLS configuration or the server fails to start.
async fn serve_tls(
    app: Router,
    port: u16,
    mut shutdown_rx: mpsc::UnboundedReceiver<()>,
) -> Result<()> {
    let rustls_config = tls::load_server_config()?;
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(rustls_config));
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let handle = axum_server::Handle::new();

    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown_rx.recv().await;
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

fn init_passkey_service(auth_config: &auth::AuthConfig) -> Result<PasskeyService> {
    let passkey_config = PasskeyConfig::from_env(
        auth_config.webauthn_rp_id(),
        auth_config.webauthn_rp_origin(),
    )
    .context("Failed to load passkey configuration")?;
    PasskeyService::new(passkey_config).context("Failed to initialize Passkey service")
}
