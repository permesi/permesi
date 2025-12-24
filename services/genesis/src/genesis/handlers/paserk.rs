use crate::genesis::admission::AdmissionSigner;
use axum::{
    extract::Extension,
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::error;

#[utoipa::path(
    get,
    path= "/paserk.json",
    responses (
        (status = 200, description = "PASERK public keys", body = String, content_type = "application/json"),
    ),
    tag= "paserk"
)]
pub async fn paserk(Extension(admission): Extension<Arc<AdmissionSigner>>) -> impl IntoResponse {
    match admission.paserk_snapshot().await {
        Ok(snapshot) => match snapshot.keyset.to_json_pretty() {
            Ok(keyset_json) => {
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                headers.insert(
                    CACHE_CONTROL,
                    HeaderValue::from_static("public, max-age=300"),
                );
                (StatusCode::OK, headers, keyset_json).into_response()
            }
            Err(e) => {
                error!("Failed to render PASERK keyset: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "{}".to_string()).into_response()
            }
        },
        Err(e) => {
            error!("Failed to render PASERK keyset: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "{}".to_string()).into_response()
        }
    }
}
