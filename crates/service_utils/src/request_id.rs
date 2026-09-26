//! Server-owned request correlation for the HTTP services.
//!
//! Every HTTP request gets a fresh ULID before any other middleware runs. The
//! same value is stored as a [`RequestId`] request extension, recorded on the
//! request's trace span, available to handlers through `Extension<RequestId>`,
//! and returned in the `x-request-id` response header. An operator can
//! therefore match a user's failing response to its log lines.
//!
//! A client-supplied `x-request-id` is never adopted. Accepting caller input as
//! the correlation ID would let one client collide with or impersonate another
//! request's log trail, and would put unbounded attacker-chosen text into the
//! logs of security events. A client value is kept only as the separate
//! `client_request_id` span field, and only when it is at most 128 visible
//! ASCII characters.
//!
//! Flow Overview:
//! 1) [`assign`] mints the ID and inserts [`RequestId`].
//! 2) [`make_span`] opens the `http.request` span with method, matched route,
//!    and both IDs; the span never records other headers, which may carry
//!    credentials.
//! 3) Handlers read the ID from the extension when they log.
//! 4) [`assign`] writes the ID into the response header on the way out, which
//!    also covers responses produced by inner layers (CORS, fallbacks, errors).
//!
//! [`with_request_correlation`] applies both layers in that order and must wrap
//! the fully routed router so the span can see `MatchedPath`.

use axum::{
    Router,
    extract::{MatchedPath, Request},
    http::{HeaderMap, HeaderName, HeaderValue},
    middleware::{self, Next},
    response::Response,
};
use std::fmt;
use tower_http::trace::TraceLayer;
use tracing::{Span, field};
use ulid::Ulid;

/// Header that carries the server-issued correlation ID in responses.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Longest client-supplied request ID recorded in logs.
const CLIENT_REQUEST_ID_MAX_LEN: usize = 128;

/// Correlation ID issued by this server for one HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId(Ulid);

impl RequestId {
    /// The underlying ULID.
    #[must_use]
    pub const fn get(self) -> Ulid {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Wrap a fully routed router in request-ID assignment and the trace span.
///
/// Axum runs the last-added layer first, so requests pass through [`assign`]
/// and then the trace layer, which reads the ID `assign` inserted.
pub fn with_request_correlation(router: Router) -> Router {
    router
        .layer(TraceLayer::new_for_http().make_span_with(make_span))
        .layer(middleware::from_fn(assign))
}

/// Mint a request ID, expose it to inner layers, and echo it in the response.
///
/// Any `x-request-id` a handler or inner layer set is replaced so the header
/// always matches the logged ID.
pub async fn assign(mut request: Request, next: Next) -> Response {
    let request_id = RequestId(Ulid::generate());
    request.extensions_mut().insert(request_id);
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

/// Build the per-request trace span.
///
/// The route comes from [`MatchedPath`] (for example `/v1/orgs/{org_id}`) rather
/// than the raw URI, so resource IDs, tokens in paths, and query strings stay out
/// of the field, and unmatched scanner traffic leaves it empty instead of adding
/// one value per probed path.
pub fn make_span(request: &Request) -> Span {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|id| field::display(*id));
    tracing::info_span!(
        "http.request",
        http.method = %request.method(),
        http.route = route,
        request_id = request_id,
        client_request_id = client_request_id(request.headers()),
    )
}

/// Return the caller's `x-request-id` when it is safe to log verbatim.
fn client_request_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= CLIENT_REQUEST_ID_MAX_LEN)
}

#[cfg(test)]
mod tests {
    use super::{
        CLIENT_REQUEST_ID_MAX_LEN, REQUEST_ID_HEADER, RequestId, client_request_id,
        with_request_correlation,
    };
    use anyhow::{Context, Result};
    use axum::{
        Extension, Router,
        body::{self, Body},
        http::{HeaderMap, HeaderValue, Request, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use tower::ServiceExt;
    use ulid::Ulid;

    async fn echo_request_id(Extension(request_id): Extension<RequestId>) -> String {
        request_id.to_string()
    }

    async fn sets_its_own_header() -> impl IntoResponse {
        ([(REQUEST_ID_HEADER, "handler-chosen")], "ok")
    }

    fn probe_app() -> Router {
        with_request_correlation(
            Router::new()
                .route("/probe", get(echo_request_id))
                .route("/override", get(sets_its_own_header)),
        )
    }

    fn issued_request_id(response: &axum::response::Response) -> Result<Ulid> {
        let header = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .context("response is missing x-request-id")?
            .to_str()?;
        Ok(Ulid::from_string(header)?)
    }

    #[tokio::test]
    async fn responses_carry_server_generated_request_id() -> Result<()> {
        let request = Request::builder()
            .uri("/probe")
            .header(REQUEST_ID_HEADER, "client-chosen")
            .body(Body::empty())?;
        let response = probe_app().oneshot(request).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let issued = issued_request_id(&response)?;
        let body = body::to_bytes(response.into_body(), 1024).await?;
        assert_eq!(std::str::from_utf8(&body)?, issued.to_string());
        Ok(())
    }

    #[tokio::test]
    async fn each_request_receives_a_distinct_request_id() -> Result<()> {
        let app = probe_app();
        let first = app
            .clone()
            .oneshot(Request::builder().uri("/probe").body(Body::empty())?)
            .await?;
        let second = app
            .oneshot(Request::builder().uri("/probe").body(Body::empty())?)
            .await?;
        assert_ne!(issued_request_id(&first)?, issued_request_id(&second)?);
        Ok(())
    }

    #[tokio::test]
    async fn response_header_overrides_handler_value() -> Result<()> {
        let response = probe_app()
            .oneshot(Request::builder().uri("/override").body(Body::empty())?)
            .await?;
        issued_request_id(&response)?;
        Ok(())
    }

    #[tokio::test]
    async fn unmatched_routes_still_carry_request_id() -> Result<()> {
        let response = probe_app()
            .oneshot(Request::builder().uri("/missing").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        issued_request_id(&response)?;
        Ok(())
    }

    #[test]
    fn client_request_id_is_logged_only_when_bounded() -> Result<()> {
        let mut headers = HeaderMap::new();
        assert_eq!(client_request_id(&headers), None);

        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("trace-42"));
        assert_eq!(client_request_id(&headers), Some("trace-42"));

        let oversized = "a".repeat(CLIENT_REQUEST_ID_MAX_LEN + 1);
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_str(&oversized)?);
        assert_eq!(client_request_id(&headers), None);

        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static(""));
        assert_eq!(client_request_id(&headers), None);

        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_bytes(b"caf\xc3\xa9")?);
        assert_eq!(client_request_id(&headers), None);
        Ok(())
    }
}
