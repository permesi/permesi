//! Browser binding for a pending signup.
//!
//! A verification link proves control of a mailbox, not knowledge of the password that
//! was registered for it. Anyone can start a signup for somebody else's address, so
//! activating on the link alone would let the first registrant choose the password the
//! mailbox owner turns on by clicking. Signup therefore hands the registering browser a
//! cookie derived from the pending account and its exact registration record
//! ([`OpaqueState::signup_binding`](super::state::OpaqueState)), and verification only
//! activates when the link and that cookie arrive together.
//!
//! Flow Overview:
//! 1) Signup finish stores or replaces the pending record and sets the cookie. An email
//!    that cannot be registered gets a random decoy of the same shape, so the response
//!    does not reveal whether the address already has an account.
//! 2) Verify-email reads the cookie and passes it to the storage check, which compares it
//!    in constant time under the user lock.
//! 3) A successful activation clears the cookie.
//!
//! The cookie is `HttpOnly` and carries no authority by itself: without the mailed link
//! it activates nothing, and it is useless once the record it was derived from is
//! replaced. It lives as long as the link issued with it.

use axum::http::{
    HeaderMap, HeaderValue,
    header::{COOKIE, InvalidHeaderValue},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use super::state::AuthConfig;

const COOKIE_NAME: &str = "permesi_signup";

/// Message for a live link opened without the registering browser's binding.
pub(super) const UNBOUND_BROWSER_MESSAGE: &str =
    "This link only works in the browser where you signed up. Open it there, or sign up again.";

/// Builds the cookie that carries a signup binding (or a decoy) to the browser.
pub(super) fn cookie(
    config: &AuthConfig,
    binding: &[u8; 32],
) -> Result<HeaderValue, InvalidHeaderValue> {
    let value = URL_SAFE_NO_PAD.encode(binding);
    let max_age = config.email_token_ttl_seconds();
    let mut cookie =
        format!("{COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if config.session_cookie_secure() {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie)
}

/// Builds the header that removes the binding after activation.
pub(super) fn clear_cookie(config: &AuthConfig) -> Result<HeaderValue, InvalidHeaderValue> {
    let mut cookie = format!("{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if config.session_cookie_secure() {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie)
}

/// Random value shaped like a binding, for signups that leave no pending record.
pub(super) fn decoy() -> Result<[u8; 32], getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

/// Reads the binding the browser presents; anything that is not 32 decoded bytes is absent.
pub(super) fn presented(headers: &HeaderMap) -> Option<Vec<u8>> {
    let header = headers.get(COOKIE)?.to_str().ok()?;
    let value = header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name.trim() == COOKIE_NAME).then(|| value.trim())
    })?;
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    (decoded.len() == 32).then_some(decoded)
}

#[cfg(test)]
mod tests {
    use super::{clear_cookie, cookie, decoy, presented};
    use crate::api::handlers::auth::state::AuthConfig;
    use anyhow::Result;
    use axum::http::{HeaderMap, HeaderValue, header::COOKIE};

    #[test]
    fn cookie_round_trips_and_is_http_only() -> Result<()> {
        let config = AuthConfig::new("https://permesi.dev".to_string());
        let binding = [7u8; 32];
        let header = cookie(&config, &binding)?;
        let text = header.to_str()?;
        assert!(text.contains("HttpOnly"));
        assert!(text.contains("SameSite=Lax"));
        assert!(text.contains("Secure"));
        let pair = text.split(';').next().unwrap_or_default();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("permesi_session=x; {pair}"))?,
        );
        assert_eq!(presented(&headers).as_deref(), Some(binding.as_slice()));
        assert!(clear_cookie(&config)?.to_str()?.contains("Max-Age=0"));
        Ok(())
    }

    #[test]
    fn presented_rejects_missing_and_malformed_values() -> Result<()> {
        assert!(presented(&HeaderMap::new()).is_none());
        for value in [
            "permesi_signup=",
            "permesi_signup=not base64!",
            "permesi_signup=c2hvcnQ",
            "other=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(COOKIE, HeaderValue::from_str(value)?);
            assert!(presented(&headers).is_none(), "{value}");
        }
        Ok(())
    }

    #[test]
    fn decoys_differ() -> Result<()> {
        assert_ne!(decoy()?, decoy()?);
        Ok(())
    }
}
