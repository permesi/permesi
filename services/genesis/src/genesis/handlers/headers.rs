use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::fmt::Write;
use tracing::instrument;

#[utoipa::path(
    get,
    path= "/headers",
    responses (
        (status = 200, description = "headers"),
    ),
    tag = "headers",
)]
// axum handler for health
#[instrument(skip(headers))]
pub async fn headers(headers: HeaderMap) -> impl IntoResponse {
    let body = headers
        .iter()
        .fold(String::new(), |mut acc, (name, value)| {
            if writeln!(acc, "{}: {}", name, value.to_str().unwrap_or_default()).is_err() {
                return acc;
            }
            acc
        });

    (StatusCode::OK, body)
}
