use anyhow::Result;
use axum::{routing::get, Router};
use tokio::net::TcpListener;

pub async fn new(port: u16, _dsn: String) -> Result<()> {
    let listener = TcpListener::bind(format!("::0:{port}")).await?;

    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
