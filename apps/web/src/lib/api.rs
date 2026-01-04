//! HTTP helpers for JSON APIs with consistent timeouts and error handling. Feature
//! clients use these helpers to avoid duplicating request setup and to enforce a
//! predictable timeout policy. The helpers do not store secrets or tokens; they only
//! attach headers or cookies provided by callers.

use super::{config::AppConfig, errors::AppError};
use gloo_net::http::Request;
use gloo_timers::callback::Timeout;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::to_string;
use web_sys::{AbortController, RequestCredentials};

/// Default request timeout (milliseconds) applied to all HTTP helpers.
const DEFAULT_TIMEOUT_MS: u32 = 10_000;
/// Maximum number of error body characters surfaced to the UI.
const MAX_ERROR_CHARS: usize = 200;

/// Fetches JSON with cookies for session-authenticated APIs.
pub async fn get_json_with_credentials<T: DeserializeOwned>(path: &str) -> Result<T, AppError> {
    let url = build_url(path);
    let response = send_with_timeout(|signal| {
        Request::get(&url)
            .credentials(RequestCredentials::Include)
            .abort_signal(Some(signal))
            .build()
            .map_err(|err| AppError::Serialization(format!("Failed to build request: {err}")))
    })
    .await?;

    handle_json_response(response).await
}

/// Fetches JSON from an explicit base URL, used for genesis token calls.
pub async fn get_json_with_base<T: DeserializeOwned>(
    base_url: &str,
    path: &str,
) -> Result<T, AppError> {
    let url = build_url_with_base(base_url, path);
    let response = send_with_timeout(|signal| {
        Request::get(&url)
            .abort_signal(Some(signal))
            .build()
            .map_err(|err| AppError::Serialization(format!("Failed to build request: {err}")))
    })
    .await?;

    handle_json_response(response).await
}

/// Posts JSON with custom headers and expects an empty response body.
pub async fn post_json_with_headers<B: Serialize>(
    path: &str,
    body: &B,
    headers: &[(String, String)],
) -> Result<(), AppError> {
    let url = build_url(path);
    let payload = to_string(body)
        .map_err(|err| AppError::Serialization(format!("Failed to encode request: {err}")))?;
    let response = send_with_timeout(move |signal| {
        let mut builder = Request::post(&url)
            .header("Content-Type", "application/json")
            .abort_signal(Some(signal));

        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        builder
            .body(payload)
            .map_err(|err| AppError::Serialization(format!("Failed to build request: {err}")))
    })
    .await?;

    handle_empty_response(response).await
}

/// Posts JSON with custom headers and parses a JSON response.
pub async fn post_json_with_headers_response<B: Serialize, T: DeserializeOwned>(
    path: &str,
    body: &B,
    headers: &[(String, String)],
) -> Result<T, AppError> {
    let url = build_url(path);
    let payload = to_string(body)
        .map_err(|err| AppError::Serialization(format!("Failed to encode request: {err}")))?;
    let response = send_with_timeout(move |signal| {
        let mut builder = Request::post(&url)
            .header("Content-Type", "application/json")
            .abort_signal(Some(signal));

        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        builder
            .body(payload)
            .map_err(|err| AppError::Serialization(format!("Failed to build request: {err}")))
    })
    .await?;

    handle_json_response(response).await
}

/// Posts JSON with custom headers and includes cookies for session-based auth.
/// Use this only for calls against the permesi API base where cookies are expected.
pub async fn post_json_with_headers_with_credentials<B: Serialize>(
    path: &str,
    body: &B,
    headers: &[(String, String)],
) -> Result<(), AppError> {
    let url = build_url(path);
    let payload = to_string(body)
        .map_err(|err| AppError::Serialization(format!("Failed to encode request: {err}")))?;
    let response = send_with_timeout(move |signal| {
        let mut builder = Request::post(&url)
            .header("Content-Type", "application/json")
            .credentials(RequestCredentials::Include)
            .abort_signal(Some(signal));

        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        builder
            .body(payload)
            .map_err(|err| AppError::Serialization(format!("Failed to build request: {err}")))
    })
    .await?;

    handle_empty_response(response).await
}

/// Posts an empty body with cookies, used to clear a session.
pub async fn post_empty_with_credentials(path: &str) -> Result<(), AppError> {
    let url = build_url(path);
    let response = send_with_timeout(move |signal| {
        Request::post(&url)
            .credentials(RequestCredentials::Include)
            .abort_signal(Some(signal))
            .body("")
            .map_err(|err| AppError::Serialization(format!("Failed to build request: {err}")))
    })
    .await?;

    handle_empty_response(response).await
}

/// Fetches JSON with cookies and returns `None` on 204 or 401.
pub async fn get_optional_json_with_credentials<T: DeserializeOwned>(
    path: &str,
) -> Result<Option<T>, AppError> {
    let url = build_url(path);
    let response = send_with_timeout(|signal| {
        Request::get(&url)
            .credentials(RequestCredentials::Include)
            .abort_signal(Some(signal))
            .build()
            .map_err(|err| AppError::Serialization(format!("Failed to build request: {err}")))
    })
    .await?;

    handle_optional_json_response(response).await
}

/// Builds a URL from the configured API base URL and the provided path.
fn build_url(path: &str) -> String {
    let config = AppConfig::load();
    build_url_with_base(&config.api_base_url, path)
}

/// Builds a URL from an explicit base URL and the provided path.
fn build_url_with_base(base_url: &str, path: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    let path = path.trim();

    if base.is_empty() {
        path.to_string()
    } else {
        format!("{}/{}", base, path.trim_start_matches('/'))
    }
}

/// Maps network errors into user-facing `AppError` variants with timeout detection.
fn map_request_error(err: gloo_net::Error) -> AppError {
    let message = err.to_string();
    let lowered = message.to_lowercase();

    if lowered.contains("timeout") || lowered.contains("abort") {
        AppError::Timeout("Request timed out. Please try again.".to_string())
    } else {
        AppError::Network(format!("Unable to reach the server: {message}"))
    }
}

/// Sends a request with an abort timeout to avoid hanging UI state.
async fn send_with_timeout(
    build_request: impl FnOnce(&web_sys::AbortSignal) -> Result<gloo_net::http::Request, AppError>,
) -> Result<gloo_net::http::Response, AppError> {
    let controller = AbortController::new()
        .map_err(|_| AppError::Config("Failed to initialize request timeout.".to_string()))?;
    let signal = controller.signal();
    let timeout_controller = controller.clone();
    let _timeout = Timeout::new(DEFAULT_TIMEOUT_MS, move || timeout_controller.abort());

    let request = build_request(&signal)?;
    request.send().await.map_err(map_request_error)
}

/// Parses JSON responses and surfaces HTTP errors with sanitized bodies.
async fn handle_json_response<T: DeserializeOwned>(
    response: gloo_net::http::Response,
) -> Result<T, AppError> {
    if response.ok() {
        response
            .json::<T>()
            .await
            .map_err(|err| AppError::Parse(format!("Failed to decode response: {err}")))
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(AppError::Http {
            status,
            message: sanitize_body(body),
        })
    }
}

/// Handles empty responses and returns sanitized HTTP errors when needed.
async fn handle_empty_response(response: gloo_net::http::Response) -> Result<(), AppError> {
    if response.ok() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(AppError::Http {
            status,
            message: sanitize_body(body),
        })
    }
}

/// Parses optional JSON responses and treats 204/401 as no session.
async fn handle_optional_json_response<T: DeserializeOwned>(
    response: gloo_net::http::Response,
) -> Result<Option<T>, AppError> {
    if response.status() == 204 {
        return Ok(None);
    }
    if response.ok() {
        response
            .json::<T>()
            .await
            .map(Some)
            .map_err(|err| AppError::Parse(format!("Failed to decode response: {err}")))
    } else {
        let status = response.status();
        if status == 401 {
            return Ok(None);
        }
        let body = response.text().await.unwrap_or_default();
        Err(AppError::Http {
            status,
            message: sanitize_body(body),
        })
    }
}

/// Sanitizes HTTP error bodies for user-facing messages by trimming and truncating.
fn sanitize_body(body: String) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        "Request failed.".to_string()
    } else {
        trimmed.chars().take(MAX_ERROR_CHARS).collect()
    }
}
