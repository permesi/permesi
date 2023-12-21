use anyhow::{Context, Result};
use axum::{routing::get, Extension, Router};
use sqlx::{postgres::PgPoolOptions, Connection};
use std::time::Duration;
use tokio::net::TcpListener;
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
        .layer(Extension(pool));

    info!("Listening on [::]:{}", port);

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
