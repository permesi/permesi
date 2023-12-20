use axum::{
    http::HeaderMap,
    response::{IntoResponse, Json},
};
use serde_json::json;

use crate::permesi::GIT_COMMIT_HASH;

// axum handler for health
pub async fn health() -> impl IntoResponse {
    let body = Json(json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "build": GIT_COMMIT_HASH,
    }));

    let short_hash = if GIT_COMMIT_HASH.len() > 7 {
        &GIT_COMMIT_HASH[0..7]
    } else {
        ""
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        "X-App",
        format!(
            "{}:{}:{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            short_hash
        )
        .parse()
        .unwrap(),
    );

    (headers, body)
}
