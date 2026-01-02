//! Zero token validation helpers.

use axum::http::{HeaderMap, StatusCode};

use crate::api::handlers::{AdmissionVerifier, verify_token};

const ZERO_TOKEN_HEADER: &str = "x-permesi-zero-token";

#[derive(Debug)]
pub(super) enum ZeroTokenError {
    Missing,
    Invalid,
}

pub(super) async fn require_zero_token(
    headers: &HeaderMap,
    admission: &AdmissionVerifier,
) -> Result<(), ZeroTokenError> {
    let Some(zero_token) = extract_zero_token(headers) else {
        return Err(ZeroTokenError::Missing);
    };

    if verify_token(admission, &zero_token).await {
        Ok(())
    } else {
        Err(ZeroTokenError::Invalid)
    }
}

pub(super) fn zero_token_error_response(err: &ZeroTokenError) -> (StatusCode, String) {
    match err {
        ZeroTokenError::Missing => (StatusCode::BAD_REQUEST, "Missing zero token".to_string()),
        ZeroTokenError::Invalid => (StatusCode::BAD_REQUEST, "Invalid token".to_string()),
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
    use super::{
        ZERO_TOKEN_HEADER, ZeroTokenError, extract_zero_token, require_zero_token,
        zero_token_error_response,
    };
    use crate::api::handlers::AdmissionVerifier;
    use admission_token::{PaserkKey, PaserkKeySet};
    use anyhow::Result;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    fn admission_verifier() -> Result<AdmissionVerifier> {
        let key = PaserkKey::from_ed25519_public_key_bytes(&[7u8; 32])?;
        let keyset = PaserkKeySet {
            version: "v4".to_string(),
            purpose: "public".to_string(),
            active_kid: key.kid.clone(),
            keys: vec![key],
        };
        Ok(AdmissionVerifier::new(
            keyset,
            "https://genesis.test".to_string(),
            "permesi".to_string(),
        ))
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
        let admission = admission_verifier()?;
        let err = require_zero_token(&headers, &admission).await.err();
        assert!(matches!(err, Some(ZeroTokenError::Missing)));
        Ok(())
    }
}
