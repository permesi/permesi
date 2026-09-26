//! Uniform JSON error envelope for the HTTP services.
//!
//! Every error response (status 4xx or 5xx) carries the body
//! `{"error": {"code": "<stable code>", "message": "<human text>"}}` with
//! `content-type: application/json`. Clients parse one shape and branch on the
//! stable `code` instead of matching message text or guessing from overloaded
//! status codes.
//!
//! Two paths produce the envelope. Handlers and router fallbacks return
//! [`ApiError`] when they want a specific code. Everything else goes through
//! [`normalize_errors`], a middleware that rewrites any error response that is
//! not already JSON: hand-written `(StatusCode, String)` tuples, bare status
//! codes with empty bodies, and axum extractor rejections. It keeps the status
//! and the message and derives the code from the status, so the wire format is
//! uniform without converting every handler at once, and handlers added later
//! are covered automatically. JSON error bodies (the envelope itself, or health
//! reports) pass through untouched.
//!
//! Messages are cut to 256 characters, so a hostile request cannot inflate an
//! error response by echoing its own input, and they never carry more than the
//! handler already returned. The auth endpoints' deliberately generic messages
//! (which avoid revealing whether an account exists) keep their text, and their
//! codes depend only on the status.
//!
//! Flow Overview:
//! 1) A handler, extractor, or fallback produces an error response.
//! 2) If it is already JSON, [`normalize_errors`] leaves it alone.
//! 3) Otherwise the middleware reads at most [`MAX_ERROR_BODY_BYTES`] of the body,
//!    uses it as the message (or a default for the status), keeps the original
//!    headers (`Allow`, `Retry-After`, `Set-Cookie`, ...), and emits the envelope.

use axum::{
    Json, Router,
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Longest message returned to a caller, in characters.
pub const MESSAGE_MAX_CHARS: usize = 256;

/// Largest error body the middleware reads before falling back to a default message.
pub const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;

/// Body of every error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

/// Stable error code plus a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    /// Stable, machine-readable code (for example `rate_limited`).
    pub code: String,
    /// Human-readable explanation; safe to show to the caller.
    pub message: String,
}

/// HTTP error rendered as an [`ErrorEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    /// Build an error with an explicit code, truncating the message to a safe length.
    pub fn new(status: StatusCode, code: &'static str, message: &str) -> Self {
        Self {
            status,
            code,
            message: message.chars().take(MESSAGE_MAX_CHARS).collect(),
        }
    }

    /// Build an error whose code and message are the defaults for `status`.
    #[must_use]
    pub fn from_status(status: StatusCode) -> Self {
        Self::new(status, default_code(status), default_message(status))
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code: self.code.to_string(),
                    message: self.message,
                },
            }),
        )
            .into_response()
    }
}

/// Stable code for an error status that no handler specialized.
#[must_use]
pub fn default_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => "invalid_request",
        StatusCode::UNAUTHORIZED => "unauthenticated",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        StatusCode::CONFLICT => "conflict",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::SERVICE_UNAVAILABLE => "dependency_unavailable",
        status if status.is_server_error() => "internal_error",
        _ => "request_failed",
    }
}

/// Message used when an error response had no usable body.
fn default_message(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "authentication is required",
        StatusCode::FORBIDDEN => "operation is not authorized",
        StatusCode::NOT_FOUND => "resource was not found",
        StatusCode::METHOD_NOT_ALLOWED => "method is not allowed for this route",
        StatusCode::TOO_MANY_REQUESTS => "too many requests",
        StatusCode::SERVICE_UNAVAILABLE => "a required service is unavailable",
        status if status.is_server_error() => "internal server error",
        _ => "request failed",
    }
}

/// Answer unmatched paths with the envelope instead of an empty 404.
pub async fn route_not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "no API route matches this path",
    )
}

/// Answer unsupported methods with the envelope; axum keeps the `Allow` header.
pub async fn method_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "this route does not support the requested HTTP method",
    )
}

/// Attach the fallbacks and the normalizing middleware to a fully routed router.
///
/// `method_not_allowed_fallback` only applies to routes that already exist, so
/// call this after every route is registered and before CORS and correlation
/// layers, which then also apply to error responses.
pub fn with_error_envelope<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .fallback(route_not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(normalize_errors))
}

/// Rewrite non-JSON error responses into the envelope, keeping status and headers.
pub async fn normalize_errors(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) || is_json(response.headers()) {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let text = match to_bytes(body, MAX_ERROR_BODY_BYTES).await {
        Ok(bytes) => String::from_utf8(bytes.to_vec()).ok(),
        Err(_) => None,
    };
    let message = text
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| default_message(status));

    let envelope = ApiError::new(status, default_code(status), message).into_response();
    let (envelope_parts, envelope_body) = envelope.into_parts();
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(
        header::CONTENT_TYPE,
        envelope_parts
            .headers
            .get(header::CONTENT_TYPE)
            .cloned()
            .unwrap_or_else(|| header::HeaderValue::from_static("application/json")),
    );
    Response::from_parts(parts, envelope_body)
}

/// Document the envelope on every 4xx/5xx response in `openapi` that returns it.
///
/// Handlers annotate error statuses with a description only, or with a
/// `text/plain` string body; [`normalize_errors`] turns both into the envelope.
/// This registers the `ErrorEnvelope` schema and makes it the `application/json`
/// body of those responses, so clients and contract tests see what the service
/// actually returns. Responses that already declare a JSON body (for example a
/// health report on 503) are kept.
pub fn document_error_envelope(openapi: &mut utoipa::openapi::OpenApi) {
    use utoipa::{
        PartialSchema,
        openapi::{Content, Ref, RefOr},
    };

    let components = openapi.components.get_or_insert_with(Default::default);
    let mut schemas = Vec::new();
    <ErrorEnvelope as ToSchema>::schemas(&mut schemas);
    components
        .schemas
        .insert(ErrorEnvelope::name().into_owned(), ErrorEnvelope::schema());
    components.schemas.extend(schemas);

    let content = Content::new(Some(Ref::from_schema_name(ErrorEnvelope::name())));
    for item in openapi.paths.paths.values_mut() {
        let operations = [
            &mut item.get,
            &mut item.put,
            &mut item.post,
            &mut item.delete,
            &mut item.options,
            &mut item.head,
            &mut item.patch,
            &mut item.trace,
        ];
        for operation in operations.into_iter().flatten() {
            for (status, response) in &mut operation.responses.responses {
                let is_error = status
                    .parse::<u16>()
                    .is_ok_and(|code| (400..600).contains(&code));
                let RefOr::T(response) = response else {
                    continue;
                };
                let plain_text_only =
                    response.content.len() == 1 && response.content.contains_key("text/plain");
                if is_error && (response.content.is_empty() || plain_text_only) {
                    response.content.clear();
                    response
                        .content
                        .insert("application/json".to_string(), RefOr::T(content.clone()));
                }
            }
        }
    }
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|mime| {
            mime.eq_ignore_ascii_case("application/json")
                || mime.to_ascii_lowercase().ends_with("+json")
        })
}

#[cfg(test)]
mod tests {
    use super::{ErrorEnvelope, MESSAGE_MAX_CHARS, with_error_envelope};
    use anyhow::Result;
    use axum::{
        Json, Router,
        body::{self, Body},
        http::{HeaderValue, Request, StatusCode, header},
        response::IntoResponse,
        routing::{get, post},
    };
    use serde::Deserialize;
    use serde_json::json;
    use tower::ServiceExt;

    #[derive(Deserialize)]
    struct Probe {
        name: String,
    }

    async fn plain_text() -> impl IntoResponse {
        (StatusCode::BAD_REQUEST, "Origin not allowed")
    }

    async fn bare_status() -> StatusCode {
        StatusCode::UNAUTHORIZED
    }

    async fn rate_limited() -> impl IntoResponse {
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, HeaderValue::from_static("30"))],
            "Rate limited",
        )
    }

    async fn json_report() -> impl IntoResponse {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "unhealthy"})),
        )
    }

    async fn huge() -> impl IntoResponse {
        (StatusCode::BAD_REQUEST, "x".repeat(10 * MESSAGE_MAX_CHARS))
    }

    async fn accept(Json(probe): Json<Probe>) -> String {
        probe.name
    }

    fn app() -> Router {
        with_error_envelope(
            Router::new()
                .route("/plain", get(plain_text))
                .route("/bare", get(bare_status))
                .route("/limited", get(rate_limited))
                .route("/report", get(json_report))
                .route("/huge", get(huge))
                .route("/json", post(accept)),
        )
    }

    async fn call(request: Request<Body>) -> Result<axum::response::Response> {
        Ok(app().oneshot(request).await?)
    }

    async fn envelope(response: axum::response::Response) -> Result<ErrorEnvelope> {
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = body::to_bytes(response.into_body(), 64 * 1024).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    fn get_request(uri: &str) -> Result<Request<Body>> {
        Ok(Request::builder().uri(uri).body(Body::empty())?)
    }

    #[test]
    fn document_error_envelope_attaches_schema_to_bodyless_errors() -> Result<()> {
        use utoipa::openapi::{
            OpenApiBuilder, PathItem, PathsBuilder, ResponseBuilder, ResponsesBuilder,
            path::{HttpMethod, OperationBuilder},
        };
        let operation = OperationBuilder::new()
            .responses(
                ResponsesBuilder::new()
                    .response("200", ResponseBuilder::new().description("ok"))
                    .response("429", ResponseBuilder::new().description("Rate limited"))
                    .response(
                        "400",
                        ResponseBuilder::new().description("Bad request").content(
                            "text/plain",
                            utoipa::openapi::Content::new(Some(
                                utoipa::openapi::ObjectBuilder::new().build(),
                            )),
                        ),
                    ),
            )
            .build();
        let mut openapi = OpenApiBuilder::new()
            .paths(PathsBuilder::new().path("/probe", PathItem::new(HttpMethod::Get, operation)))
            .build();

        super::document_error_envelope(&mut openapi);

        let document = serde_json::to_value(&openapi)?;
        let responses = &document["paths"]["/probe"]["get"]["responses"];
        assert_eq!(
            responses["429"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ErrorEnvelope"
        );
        assert_eq!(
            responses["400"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ErrorEnvelope"
        );
        assert!(responses["400"]["content"].get("text/plain").is_none());
        assert!(responses["200"].get("content").is_none());
        assert!(document["components"]["schemas"]["ErrorBody"].is_object());
        Ok(())
    }

    #[tokio::test]
    async fn plain_text_errors_become_envelopes_with_same_status_and_message() -> Result<()> {
        let response = call(get_request("/plain")?).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let envelope = envelope(response).await?;
        assert_eq!(envelope.error.code, "invalid_request");
        assert_eq!(envelope.error.message, "Origin not allowed");
        Ok(())
    }

    #[tokio::test]
    async fn empty_error_bodies_get_default_messages() -> Result<()> {
        let response = call(get_request("/bare")?).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let envelope = envelope(response).await?;
        assert_eq!(envelope.error.code, "unauthenticated");
        assert_eq!(envelope.error.message, "authentication is required");
        Ok(())
    }

    #[tokio::test]
    async fn normalized_errors_keep_original_headers() -> Result<()> {
        let response = call(get_request("/limited")?).await?;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("30"))
        );
        assert_eq!(envelope(response).await?.error.code, "rate_limited");
        Ok(())
    }

    #[tokio::test]
    async fn json_error_bodies_pass_through_unchanged() -> Result<()> {
        let response = call(get_request("/report")?).await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body::to_bytes(response.into_body(), 1024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            json!({"status": "unhealthy"})
        );
        Ok(())
    }

    #[tokio::test]
    async fn messages_are_bounded() -> Result<()> {
        let envelope = envelope(call(get_request("/huge")?).await?).await?;
        assert_eq!(envelope.error.message.chars().count(), MESSAGE_MAX_CHARS);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_routes_and_methods_return_envelopes() -> Result<()> {
        let missing = call(get_request("/missing")?).await?;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(envelope(missing).await?.error.code, "not_found");

        let wrong_method = call(
            Request::builder()
                .method("DELETE")
                .uri("/plain")
                .body(Body::empty())?,
        )
        .await?;
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(
            wrong_method
                .headers()
                .get(header::ALLOW)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|allow| allow.contains("GET"))
        );
        assert_eq!(
            envelope(wrong_method).await?.error.code,
            "method_not_allowed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn extractor_rejections_become_envelopes() -> Result<()> {
        let malformed = call(
            Request::builder()
                .method("POST")
                .uri("/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{\"name\":"))?,
        )
        .await?;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(envelope(malformed).await?.error.code, "invalid_request");

        let missing_type = call(
            Request::builder()
                .method("POST")
                .uri("/json")
                .body(Body::from("{\"name\":\"x\"}"))?,
        )
        .await?;
        assert_eq!(missing_type.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            envelope(missing_type).await?.error.code,
            "unsupported_media_type"
        );
        Ok(())
    }
}
