pub mod database;
pub mod renew;

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde_json::{Value, json};
use std::env;
use tracing::{debug, instrument, warn};
use url::Url;

fn vault_error_message(json_response: &Value) -> &str {
    json_response
        .get("errors")
        .and_then(|v| v.get(0))
        .and_then(Value::as_str)
        .unwrap_or("")
}

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[instrument]
/// # Errors
/// Returns an error if `url` cannot be parsed, has no host, or uses an unsupported scheme.
pub fn endpoint_url(url: &str, path: &str) -> Result<String> {
    let url = Url::parse(url)?;

    let scheme = url.scheme();

    let host = url
        .host()
        .ok_or_else(|| anyhow!("Error parsing URL: no host specified"))?
        .to_owned();

    let port = match url.port() {
        Some(p) => p,
        None => match scheme {
            "http" => 80,
            "https" => 443,
            _ => return Err(anyhow!("Error parsing URL: unsupported scheme {scheme}")),
        },
    };

    let endpoint_url = format!("{scheme}://{host}:{port}{path}");

    debug!("endpoint URL: {}", endpoint_url);

    Ok(endpoint_url)
}

/// Unwrap a wrapped Vault client token
/// Create wrapped token with:
/// vault write -wrap-ttl=300s -f auth/approle/role/genesis/secret-id
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument]
pub async fn unwrap(url: &str, token: &str) -> Result<String> {
    let client = Client::builder().user_agent(APP_USER_AGENT).build()?;

    let unwrap_url = endpoint_url(url, "/v1/sys/wrapping/unwrap")?;

    let response = client
        .post(&unwrap_url)
        .header("X-Vault-Token", token)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            unwrap_url,
            status,
            vault_error_message(&json_response)
        ));
    }

    let json_response: Value = response.json().await?;
    let sid = json_response
        .get("data")
        .and_then(|v| v.get("secret_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no secret_id found"))?;

    Ok(sid.to_string())
}

/// Login to Vault using `AppRole`
/// Create a secret ID with:
/// vault write -f auth/approle/role/genesis/secret-id
/// # Errors
/// Returns an error if the Vault request fails, Vault returns a non-success status, or the response is missing expected fields.
#[instrument]
pub async fn approle_login(url: &str, sid: &str, rid: &str) -> Result<(String, u64)> {
    let client = Client::builder().user_agent(APP_USER_AGENT).build()?;

    // Create a JSON payload for AppRole login
    let login_payload = json!({
        "role_id": rid,
        "secret_id": sid
    });

    debug!("login URL: {}, role ID: {}", url, rid);

    let response = client.post(url).json(&login_payload).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            url,
            status,
            vault_error_message(&json_response)
        ));
    }

    // Parse the JSON response
    let json_response: Value = response.json().await?;
    let token = json_response
        .get("auth")
        .and_then(|v| v.get("client_token"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Error parsing JSON response: no client_token found"))?;
    let lease_duration = json_response
        .get("auth")
        .and_then(|v| v.get("lease_duration"))
        .and_then(Value::as_u64)
        .unwrap_or(1800);

    Ok((token.to_string(), lease_duration))
}
