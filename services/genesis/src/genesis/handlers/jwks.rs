use crate::genesis::admission::admission_config;
use axum::{http::StatusCode, response::IntoResponse};
use tracing::error;

#[utoipa::path(
    get,
    path= "/jwks.json",
    responses (
        (status = 200, description = "JWKS public keys", body = String, content_type = "application/json"),
    ),
    tag= "jwks"
)]
pub async fn jwks() -> impl IntoResponse {
    match admission_config()
        .and_then(|cfg| cfg.jwks().to_json_pretty().map_err(anyhow::Error::from))
    {
        Ok(jwks_json) => (StatusCode::OK, jwks_json),
        Err(e) => {
            error!("Failed to render JWKS: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "{}".to_string())
        }
    }
}
