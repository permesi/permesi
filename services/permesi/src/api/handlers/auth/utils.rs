//! Small helpers for auth validation and email verification token handling.

use anyhow::{Context, Result};
use base64::Engine;
use rand::{RngCore, rngs::OsRng};
use regex::Regex;
use sha2::{Digest, Sha256};

/// Normalize an email for lookup/uniqueness checks.
pub(super) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Basic email format check on already-normalized input.
pub(super) fn valid_email(email_normalized: &str) -> bool {
    Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").is_ok_and(|regex| regex.is_match(email_normalized))
}

/// Create a new verification token for email links.
///
/// Returned token is only sent to the user; we store a hash in the database.
pub(super) fn generate_verification_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .context("failed to generate verification token")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Create a new session token for the auth cookie.
/// The raw value is only returned to set the cookie; the database stores a hash.
pub(crate) fn generate_session_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .context("failed to generate session token")?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Hash a verification token so we never store the raw token in the database.
pub(super) fn hash_verification_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

/// Hash a session token so raw values never touch the database.
/// The hash is used for lookups when the cookie is presented.
pub(crate) fn hash_session_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

/// Build the frontend verification link included in outbound emails.
pub(super) fn build_verify_url(frontend_base_url: &str, token: &str) -> String {
    let base = frontend_base_url.trim_end_matches('/');
    format!("{base}/verify-email#token={token}")
}

/// Decode a base64 payload (used by OPAQUE handlers).
pub(super) fn decode_base64_field(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Missing opaque payload".to_string());
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|_| "Invalid base64 payload".to_string())
}

pub(super) fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err.code().is_some_and(|code| code.as_ref() == "23505"),
        _ => false,
    }
}

/// Extract a client IP for rate limiting from common proxy headers.
pub(super) fn extract_client_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if forwarded.is_some() {
        return forwarded.map(str::to_string);
    }
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use sqlx::error::{DatabaseError, ErrorKind};
    use std::borrow::Cow;
    use std::error::Error as StdError;
    use std::fmt;

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(normalize_email(" Alice@Example.COM "), "alice@example.com");
    }

    #[test]
    fn valid_email_accepts_basic_format() {
        assert!(valid_email("a@example.com"));
        assert!(valid_email("name.surname@example.co"));
    }

    #[test]
    fn valid_email_rejects_missing_parts() {
        assert!(!valid_email("not-an-email"));
        assert!(!valid_email("missing-at.example.com"));
        assert!(!valid_email("missing-domain@"));
    }

    #[test]
    fn build_verify_url_trims_trailing_slash() {
        let url = build_verify_url("https://permesi.dev/", "token");
        assert_eq!(url, "https://permesi.dev/verify-email#token=token");
    }

    #[test]
    fn decode_base64_field_rejects_empty_or_invalid() {
        assert!(decode_base64_field(" ").is_err());
        assert!(decode_base64_field("not-base64").is_err());
    }

    #[test]
    fn decode_base64_field_accepts_valid() {
        let payload = b"hello";
        let encoded = STANDARD.encode(payload);
        let decoded = decode_base64_field(&encoded);
        assert_eq!(decoded.as_deref(), Ok(payload.as_slice()));
    }

    #[test]
    fn generate_verification_token_round_trip() {
        let decoded_len = generate_verification_token()
            .ok()
            .and_then(|token| URL_SAFE_NO_PAD.decode(token.as_bytes()).ok())
            .map(|bytes| bytes.len());
        assert_eq!(decoded_len, Some(32));
    }

    #[test]
    fn hash_verification_token_stable() {
        let first = hash_verification_token("token");
        let second = hash_verification_token("token");
        let different = hash_verification_token("other");
        assert_eq!(first, second);
        assert_ne!(first, different);
    }

    #[derive(Debug)]
    struct TestDbError {
        code: Option<&'static str>,
    }

    impl fmt::Display for TestDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "test database error")
        }
    }

    impl StdError for TestDbError {}

    impl DatabaseError for TestDbError {
        fn message(&self) -> &'static str {
            "test database error"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.map(Cow::Borrowed)
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::UniqueViolation
        }
    }

    #[test]
    fn is_unique_violation_matches_sqlstate() {
        let err = sqlx::Error::Database(Box::new(TestDbError {
            code: Some("23505"),
        }));
        assert!(is_unique_violation(&err));

        let err = sqlx::Error::Database(Box::new(TestDbError {
            code: Some("99999"),
        }));
        assert!(!is_unique_violation(&err));

        let err = sqlx::Error::RowNotFound;
        assert!(!is_unique_violation(&err));
    }

    #[test]
    fn extract_client_ip_prefers_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );
        headers.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
        assert_eq!(extract_client_ip(&headers), Some("1.2.3.4".to_string()));
    }

    #[test]
    fn extract_client_ip_falls_back_to_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
        assert_eq!(extract_client_ip(&headers), Some("9.9.9.9".to_string()));
    }

    #[test]
    fn extract_client_ip_none_when_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_client_ip(&headers), None);
    }
}
