use anyhow::Result;
use axum::{routing::get, Router};
use tokio::net::TcpListener;

mod handlers;

pub mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub const GIT_COMMIT_HASH: &str = if let Some(hash) = built_info::GIT_COMMIT_HASH {
    hash
} else {
    ":-("
};

pub async fn new(port: u16, _dsn: String) -> Result<()> {
    let listener = TcpListener::bind(format!("::0:{port}")).await?;

    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/", get(|| async { "Hello, World!" }));

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
