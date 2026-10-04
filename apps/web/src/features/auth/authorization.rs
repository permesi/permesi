//! Opaque authorization resume handles, with no browser-owned scopes or redirect URLs.
//!
//! The server stores and validates all authority. This module retains only a UUID
//! locator across the existing login/MFA routes; the API also requires its `HttpOnly`
//! browser-binding cookie. Browser tampering can select an invalid handle, never
//! change client, tenant, redirect, scopes, nonce or PKCE challenge.

/// Validates a canonical UUID locator before persisting or building a resume URL.
#[must_use]
pub fn request_handle(value: &str) -> Option<&str> {
    if value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        Some(value)
    } else {
        None
    }
}

/// Identifies only existing login/MFA presentation routes; it grants no server authority.
#[must_use]
pub fn authorization_path(path: &str) -> bool {
    matches!(
        path,
        "/login" | "/console/mfa/challenge" | "/console/mfa/setup"
    )
}

/// Automatically resumes login/challenge; enrollment waits for recovery-code acknowledgement.
#[must_use]
pub fn automatic_resume_path(path: &str) -> bool {
    matches!(path, "/login" | "/console/mfa/challenge")
}

/// Treats the server-provided deadline as a browser cleanup hint, never authorization.
/// PostgreSQL independently enforces expiry even if the browser changes this value.
#[must_use]
pub fn request_deadline(value: &str, now_ms: f64) -> bool {
    value
        .parse::<f64>()
        .is_ok_and(|deadline| deadline.is_finite() && now_ms.is_finite() && deadline > now_ms)
}

#[cfg(target_arch = "wasm32")]
const STORAGE_KEY: &str = "permesi_oauth_request";
#[cfg(target_arch = "wasm32")]
const DEADLINE_KEY: &str = "permesi_oauth_expires";

/// Clears the locator and nonauthoritative deadline together when login is abandoned.
#[cfg(target_arch = "wasm32")]
fn clear_request() {
    if let Some(storage) =
        web_sys::window().and_then(|window| window.session_storage().ok().flatten())
    {
        let _ = storage.remove_item(STORAGE_KEY);
        let _ = storage.remove_item(DEADLINE_KEY);
    }
}

/// Drops pending browser presentation state on navigation outside login/MFA.
#[cfg(target_arch = "wasm32")]
pub fn abandon_if_outside_flow(path: &str) {
    if !authorization_path(path) {
        clear_request();
    }
}

/// Captures only an opaque locator and cleanup deadline on login entry.
/// The server-owned request and HttpOnly cookie remain the only authority.
#[cfg(target_arch = "wasm32")]
pub fn capture_request() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let Ok(path) = window.location().pathname() else {
        return;
    };
    if !authorization_path(&path) {
        clear_request();
        return;
    }
    let Some(storage) = window.session_storage().ok().flatten() else {
        return;
    };
    let Some(params) = window
        .location()
        .search()
        .ok()
        .and_then(|search| web_sys::UrlSearchParams::new_with_str(&search).ok())
    else {
        return;
    };
    if path == "/login" {
        if let Some(value) = params.get("oauth_request") {
            let expiry = params.get("oauth_expires");
            if let (Some(id), Some(expiry)) = (
                request_handle(&value),
                expiry
                    .as_deref()
                    .filter(|expiry| request_deadline(expiry, js_sys::Date::now())),
            ) {
                if storage.set_item(STORAGE_KEY, id).is_ok()
                    && storage.set_item(DEADLINE_KEY, expiry).is_ok()
                {
                    return;
                }
            }
            clear_request();
            return;
        }
    }
    if !storage
        .get_item(DEADLINE_KEY)
        .ok()
        .flatten()
        .is_some_and(|expiry| request_deadline(&expiry, js_sys::Date::now()))
    {
        clear_request();
    }
}

/// Resumes only the pending login/MFA transition after a full session exists.
/// A stale or abandoned locator cannot redirect an ordinary console login.
/// Enrollment callers must wait until the user acknowledges their recovery codes.
/// Returns whether browser navigation was started, allowing an ordinary-login fallback.
#[cfg(target_arch = "wasm32")]
pub fn resume_after_authentication(api_base_url: &str) -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    if !window
        .location()
        .pathname()
        .is_ok_and(|path| authorization_path(&path))
    {
        clear_request();
        return false;
    }
    let Some(storage) = window.session_storage().ok().flatten() else {
        return false;
    };
    let Some(value) = storage.get_item(STORAGE_KEY).ok().flatten() else {
        return false;
    };
    let expiry = storage.get_item(DEADLINE_KEY).ok().flatten();
    let Some(id) = request_handle(&value).filter(|_| {
        expiry
            .as_deref()
            .is_some_and(|expiry| request_deadline(expiry, js_sys::Date::now()))
    }) else {
        clear_request();
        return false;
    };
    let target = format!(
        "{}/authorize/resume?request_id={id}",
        api_base_url.trim_end_matches('/')
    );
    if window.location().set_href(&target).is_ok() {
        clear_request();
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_resume_discards_expired_or_abandoned_login_state() {
        assert!(authorization_path("/login"));
        assert!(authorization_path("/console/mfa/challenge"));
        assert!(authorization_path("/console/mfa/setup"));
        assert!(automatic_resume_path("/login"));
        assert!(automatic_resume_path("/console/mfa/challenge"));
        assert!(!automatic_resume_path("/console/mfa/setup"));
        assert!(!authorization_path("/console/dashboard"));
        assert!(!authorization_path("/login/other"));
        assert!(request_deadline("2000", 1000.0));
        for expiry in ["1000", "999", "NaN", "inf", "", "garbage"] {
            assert!(!request_deadline(expiry, 1000.0));
        }
    }
    #[test]
    fn authorization_resume_accepts_only_opaque_uuid_handles() {
        assert_eq!(
            request_handle("12345678-1234-1234-1234-123456789abc"),
            Some("12345678-1234-1234-1234-123456789abc")
        );
        for value in [
            "https://attacker.test/",
            "//attacker.test",
            "12345678-1234-1234-1234-123456789abc&scope=jobs:write",
            "12345678_1234-1234-1234-123456789abc",
            "",
        ] {
            assert!(request_handle(value).is_none());
        }
    }
}
