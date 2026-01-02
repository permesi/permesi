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

#[cfg(test)]
mod tests {
    use super::headers;
    use anyhow::Result;
    use axum::{
        body::to_bytes,
        http::{HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse,
    };

    #[tokio::test]
    async fn headers_returns_lines() -> Result<()> {
        let mut header_map = HeaderMap::new();
        header_map.insert("x-one", HeaderValue::from_static("one"));
        header_map.insert("x-two", HeaderValue::from_static("two"));

        let response = headers(header_map).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_text = String::from_utf8(body.to_vec())?;

        assert!(body_text.contains("x-one: one"));
        assert!(body_text.contains("x-two: two"));
        Ok(())
    }

    #[tokio::test]
    async fn headers_empty_returns_blank_body() -> Result<()> {
        let response = headers(HeaderMap::new()).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let body_text = String::from_utf8(body.to_vec())?;

        assert!(body_text.is_empty());
        Ok(())
    }
}
