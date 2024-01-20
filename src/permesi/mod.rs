use crate::{
    cli::globals::GlobalArgs,
    permesi::handlers::{health, health::__path_health},
    vault,
};
use anyhow::{Context, Result};
use axum::{
    http::{HeaderName, HeaderValue},
    routing::get,
    Extension, Router,
};
use mac_address::get_mac_address;
use sqlx::{postgres::PgPoolOptions, Connection};
use std::time::Duration;
use tokio::{net::TcpListener, sync::mpsc};
use tower::ServiceBuilder;
use tower_http::{
    propagate_header::PropagateHeaderLayer, set_header::SetRequestHeaderLayer, trace::TraceLayer,
};
use tracing::info;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod handlers;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const GIT_COMMIT_HASH: &str = if let Some(hash) = built_info::GIT_COMMIT_HASH {
    hash
} else {
    ":-("
};

#[derive(OpenApi)]
#[openapi(paths(health), components(schemas(health::Health)))]
struct ApiDoc;

pub async fn new(port: u16, dsn: String, globals: &GlobalArgs) -> Result<()> {
    // Renew vault token, gracefully shutdown if failed
    let (tx, mut rx) = mpsc::channel::<()>(1);

    vault::renew::try_renew(globals, tx).await?;

    // Connect to database
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(5)
        .max_lifetime(Duration::from_secs(60 * 2))
        .test_before_acquire(false)
        .before_acquire(|conn, meta| {
            Box::pin(async move {
                // One minute
                if meta.idle_for.as_secs() > 60 {
                    conn.ping().await?;
                }

                Ok(true)
            })
        })
        .connect(&dsn)
        .await
        .context("Failed to connect to database")?;

    let app = Router::new()
        .route("/health", get(handlers::health).options(handlers::health))
        .route("/", get(|| async { "Hello, World!" }))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .layer(
            ServiceBuilder::new()
                .layer(Extension(pool))
                .layer(PropagateHeaderLayer::new(HeaderName::from_static(
                    "x-request-id",
                )))
                .layer(SetRequestHeaderLayer::if_not_present(
                    HeaderName::from_static("x-request-id"),
                    |_req: &_| {
                        let node_id: [u8; 6] = node_id();
                        let uuid = uuid::Uuid::now_v1(&node_id);
                        HeaderValue::from_str(uuid.to_string().as_str()).ok()
                    },
                ))
                .layer(TraceLayer::new_for_http()),
        );

    let listener = TcpListener::bind(format!("::0:{port}")).await?;

    info!("Listening on [::]:{}", port);

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async move {
            rx.recv().await;
        })
        .await?;

    Ok(())
}

#[must_use]
pub fn node_id() -> [u8; 6] {
    get_mac_address().map_or([0; 6], |mac| {
        mac.map_or([0; 6], |mac| {
            let bytes = mac.bytes();
            let mut node_id = [0; 6];
            node_id.copy_from_slice(&bytes);
            node_id
        })
    })
}
