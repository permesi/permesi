//! Zero token validation helpers.

use anyhow::{Context, Result, anyhow};
use axum::http::{HeaderMap, StatusCode};
use reqwest::Client;
use serde::Serialize;
use tracing::Instrument;

use super::state::{AuthConfig, AuthState};

const ZERO_TOKEN_HEADER: &str = "x-permesi-zero-token";

enum ZeroTokenValidation {
    Valid,
    Invalid,
}

#[derive(Debug)]
pub(super) enum ZeroTokenError {
    Missing,
    Invalid,
    Unavailable(anyhow::Error),
}

async fn validate_zero_token(
    client: &Client,
    config: &AuthConfig,
    token: &str,
) -> Result<ZeroTokenValidation> {
    #[derive(Serialize)]
    struct ValidateRequest<'a> {
        token: &'a str,
    }

    let span = tracing::info_span!(
        "zero_token.validate",
        http.method = "POST",
        url = %config.zero_token_validate_url()
    );
    async {
        let response = client
            .post(config.zero_token_validate_url())
            .json(&ValidateRequest { token })
            .send()
            .await
            .context("failed to send zero token validation request")?;

        if response.status().is_success() {
            return Ok(ZeroTokenValidation::Valid);
        }

        if response.status().is_client_error() {
            return Ok(ZeroTokenValidation::Invalid);
        }

        Err(anyhow!(
            "zero token validation failed with status {}",
            response.status()
        ))
    }
    .instrument(span)
    .await
}

pub(super) async fn require_zero_token(
    headers: &HeaderMap,
    auth_state: &AuthState,
) -> Result<(), ZeroTokenError> {
    let Some(zero_token) = extract_zero_token(headers) else {
        return Err(ZeroTokenError::Missing);
    };

    match validate_zero_token(auth_state.client(), auth_state.config(), &zero_token).await {
        Ok(ZeroTokenValidation::Valid) => Ok(()),
        Ok(ZeroTokenValidation::Invalid) => Err(ZeroTokenError::Invalid),
        Err(err) => Err(ZeroTokenError::Unavailable(err)),
    }
}

pub(super) fn zero_token_error_response(err: &ZeroTokenError) -> (StatusCode, String) {
    match err {
        ZeroTokenError::Missing => (StatusCode::BAD_REQUEST, "Missing zero token".to_string()),
        ZeroTokenError::Invalid => (StatusCode::BAD_REQUEST, "Invalid token".to_string()),
        ZeroTokenError::Unavailable(_) => (
            StatusCode::BAD_GATEWAY,
            "Zero token validation unavailable".to_string(),
        ),
    }
}

fn extract_zero_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(ZERO_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::super::rate_limit::{NoopRateLimiter, RateLimiter};
    use super::super::state::{AuthConfig, AuthState, OpaqueState};
    use super::{
        ZERO_TOKEN_HEADER, ZeroTokenError, extract_zero_token, require_zero_token,
        zero_token_error_response,
    };
    use anyhow::Result;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use std::sync::Arc;
    use std::time::Duration;

    fn auth_state() -> Result<AuthState> {
        let config = AuthConfig::new(
            "http://genesis.test/v1/zero-token/validate".to_string(),
            "https://permesi.dev".to_string(),
        );
        let opaque = OpaqueState::from_seed(
            [1u8; 32],
            "api.permesi.dev".to_string(),
            Duration::from_secs(30),
        );
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
        AuthState::new(config, opaque, limiter)
    }

    #[test]
    fn extract_zero_token_trims_value() {
        let mut headers = HeaderMap::new();
        headers.insert(ZERO_TOKEN_HEADER, HeaderValue::from_static("  token  "));
        assert_eq!(extract_zero_token(&headers), Some("token".to_string()));
    }

    #[test]
    fn zero_token_error_response_maps_status() {
        let (status, message) = zero_token_error_response(&ZeroTokenError::Missing);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, "Missing zero token");
    }

    #[tokio::test]
    async fn require_zero_token_missing_header() -> Result<()> {
        let headers = HeaderMap::new();
        let state = auth_state()?;
        let err = require_zero_token(&headers, &state).await.err();
        assert!(matches!(err, Some(ZeroTokenError::Missing)));
        Ok(())
    }
}
