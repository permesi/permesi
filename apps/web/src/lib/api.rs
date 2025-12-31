use super::config::AppConfig;
use super::errors::AppError;
use gloo_net::http::Request;
use gloo_timers::callback::Timeout;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::to_string;
use web_sys::AbortController;

const DEFAULT_TIMEOUT_MS: u32 = 10_000;
const MAX_ERROR_CHARS: usize = 200;

pub async fn get_json<T: DeserializeOwned>(path: &str) -> Result<T, AppError> {
    let url = build_url(path);
    let response = send_with_timeout(|signal| {
        Request::get(&url)
            .abort_signal(Some(signal))
            .build()
            .map_err(|err| AppError::Serialization(format!("Failed to build request: {err}")))
    })
    .await?;

    handle_json_response(response).await
}

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

fn build_url(path: &str) -> String {
    let config = AppConfig::load();
    build_url_with_base(&config.api_base_url, path)
}

fn build_url_with_base(base_url: &str, path: &str) -> String {
    let base = base_url.trim().trim_end_matches('/');
    let path = path.trim();

    if base.is_empty() {
        path.to_string()
    } else {
        format!("{}/{}", base, path.trim_start_matches('/'))
    }
}

fn map_request_error(err: gloo_net::Error) -> AppError {
    let message = err.to_string();
    let lowered = message.to_lowercase();

    if lowered.contains("timeout") || lowered.contains("abort") {
        AppError::Timeout("Request timed out. Please try again.".to_string())
    } else {
        AppError::Network(format!("Unable to reach the server: {message}"))
    }
}

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

fn sanitize_body(body: String) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        "Request failed.".to_string()
    } else {
        trimmed.chars().take(MAX_ERROR_CHARS).collect()
    }
}
