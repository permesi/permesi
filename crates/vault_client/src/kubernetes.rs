//! Native Kubernetes authentication for direct Vault connections.
//!
//! Flow Overview: validate the origin and relative auth mount, read the projected
//! service-account JWT afresh, then exchange it for a renewable Vault token.
//! The services keep that token for their process lifetime; renewal failure closes
//! the service and a supervisor restart reads the current JWT and logs in again.
//! This is restart-based reauthentication, not seamless hot token replacement.
//! Neither credentials nor remote error bodies may escape through diagnostics.

use anyhow::{Result, anyhow};
use http::HeaderValue;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::path::PathBuf;
use url::Url;

/// Non-secret Kubernetes login settings; the JWT is never stored in configuration.
#[derive(Debug)]
pub struct KubernetesAuth {
    pub mount: String,
    pub role: String,
    pub token_path: PathBuf,
}

/// Validate a relative auth mount without URL syntax, empty or traversal segments.
///
/// # Errors
/// Rejects API/auth prefixes, leading/trailing slashes and characters outside
/// ASCII letters, digits, `-`, `_`, `.`, and separating slashes.
pub fn validate_auth_mount(mount: &str) -> Result<String, String> {
    if mount.is_empty()
        || mount.starts_with("auth/")
        || mount.starts_with("v1/auth/")
        || mount.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    {
        return Err("Vault Kubernetes auth mount must be a relative mount without API prefixes or traversal".to_string());
    }
    Ok(mount.to_string())
}

/// Construct a Kubernetes login endpoint only from an HTTP(S) Vault origin.
///
/// # Errors
/// Rejects credentials, paths, queries and fragments so JWTs cannot be directed
/// through an ambiguous operator-supplied login URL.
pub fn kubernetes_login_url(origin: &str, mount: &str) -> Result<String> {
    validate_auth_mount(mount).map_err(|e| anyhow!(e))?;
    let mut url = Url::parse(origin).map_err(|_| anyhow!("invalid Vault Kubernetes origin"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(anyhow!(
            "Vault Kubernetes authentication requires an HTTP(S) origin without credentials, path, query or fragment"
        ));
    }
    url.set_path(&format!("/v1/auth/{mount}/login"));
    Ok(url.into())
}

/// Exchange the current JWT file for a usable renewable Vault service token.
///
/// Reads on every invocation (including projected-volume symlink replacement).
/// Redirects are refused to prevent forwarding the JWT outside the configured
/// Vault origin. Errors never include JWTs, issued tokens or remote response text.
/// The caller owns renewal and fail-closed restart, not live token replacement.
///
/// # Errors
/// Fails closed on unreadable/empty JWTs, transport or protocol errors, and tokens
/// without a positive renewable lease or a usable `X-Vault-Token` value.
pub async fn kubernetes_login(
    user_agent: &str,
    origin: &str,
    config: &KubernetesAuth,
) -> Result<(SecretString, u64)> {
    let url = kubernetes_login_url(origin, &config.mount)?;
    if config.role.trim().is_empty() {
        return Err(anyhow!("Vault Kubernetes role must not be empty"));
    }
    let jwt = tokio::fs::read_to_string(&config.token_path)
        .await
        .map(SecretString::from)
        .map_err(|_| anyhow!("could not read Vault Kubernetes JWT file"))?;
    let jwt = jwt.expose_secret().trim();
    if jwt.is_empty() {
        return Err(anyhow!("Vault Kubernetes JWT file is empty"));
    }
    let client = reqwest::Client::builder()
        .user_agent(user_agent)
        .connect_timeout(crate::transport::VAULT_CONNECT_TIMEOUT)
        .timeout(crate::transport::VAULT_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| anyhow!("could not build Vault Kubernetes login client"))?;
    let response = client
        .post(url)
        .json(&json!({ "role": config.role, "jwt": jwt }))
        .send()
        .await
        .map_err(|_| anyhow!("Vault Kubernetes login request failed"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "Vault Kubernetes login rejected (HTTP {})",
            response.status()
        ));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|_| anyhow!("invalid Vault Kubernetes login response"))?;
    let auth = body
        .get("auth")
        .ok_or_else(|| anyhow!("Vault Kubernetes login returned no auth data"))?;
    let token = auth
        .get("client_token")
        .and_then(Value::as_str)
        .filter(|token| {
            !token.is_empty()
                && !token.bytes().any(|b| b.is_ascii_whitespace())
                && HeaderValue::from_str(token).is_ok()
        })
        .ok_or_else(|| anyhow!("Vault Kubernetes login returned an unusable token"))?;
    let lease = auth
        .get("lease_duration")
        .and_then(Value::as_u64)
        .filter(|lease| *lease > 0)
        .ok_or_else(|| anyhow!("Vault Kubernetes login requires a positive token lease"))?;
    if auth.get("renewable").and_then(Value::as_bool) != Some(true) {
        return Err(anyhow!("Vault Kubernetes login requires a renewable token"));
    }
    Ok((SecretString::from(token), lease))
}

#[cfg(test)]
mod tests;
