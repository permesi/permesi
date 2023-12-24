use anyhow::{Context, Result};
use axum::{
    http::{HeaderName, HeaderValue},
    routing::get,
    Extension, Router,
};
use mac_address::get_mac_address;
use sqlx::{postgres::PgPoolOptions, Connection};
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::{
    propagate_header::PropagateHeaderLayer, set_header::SetRequestHeaderLayer, trace::TraceLayer,
};
use tracing::info;

mod handlers;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const GIT_COMMIT_HASH: &str = if let Some(hash) = built_info::GIT_COMMIT_HASH {
    hash
} else {
    ":-("
};

pub async fn new(port: u16, dsn: String) -> Result<()> {
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

    let listener = TcpListener::bind(format!("::0:{port}")).await?;

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/", get(|| async { "Hello, World!" }))
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
        .layer(Extension(pool))
        .layer(TraceLayer::new_for_http());

    info!("Listening on [::]:{}", port);

    axum::serve(listener, app.into_make_service()).await?;

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
