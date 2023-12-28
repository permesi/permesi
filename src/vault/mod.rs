pub mod database;

use crate::cli::globals::GlobalArgs;
use anyhow::{anyhow, Result};
use rand::Rng;
use reqwest::Client;
use serde_json::{json, Value};
use std::env;
use tokio::time::{interval, Duration};
use tracing::{debug, instrument};
use url::Url;

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[instrument]
pub fn endpoint_url(globals: &GlobalArgs, endpoint: &str) -> Result<String> {
    let url = Url::parse(&globals.vault_url)?;

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
            _ => return Err(anyhow!("Error parsing URL: unsupported scheme {}", scheme)),
        },
    };

    let endpoint_url = format!("{scheme}://{host}:{port}{}", endpoint);

    debug!("endpoint URL: {}", endpoint);

    Ok(endpoint_url)
}

/// Unwrap a wrapped Vault client token
/// Create wrapped token with:
/// vault write -wrap-ttl=300s -f auth/approle/role/permesi/secret-id
#[instrument]
pub async fn unwrap(globals: &GlobalArgs, token: &str) -> Result<String> {
    let client = Client::builder().user_agent(APP_USER_AGENT).build()?;

    let unwrap_url = endpoint_url(globals, "/v1/sys/wrapping/unwrap")?;

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
            json_response["errors"][0].as_str().unwrap_or("")
        ));
    }

    let json_response: Value = response.json().await?;
    let sid = json_response["data"]["secret_id"]
        .as_str()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no secret_id found"))?;

    Ok(sid.to_string())
}

/// Login to Vault using AppRole
/// Create a secret ID with:
/// vault write -f auth/approle/role/permesi/secret-id
#[instrument]
pub async fn approle_login(globals: &GlobalArgs, sid: &str, rid: &str) -> Result<(String, u64)> {
    let client = Client::builder().user_agent(APP_USER_AGENT).build()?;

    // Create a JSON payload for AppRole login
    let login_payload = json!({
        "role_id": rid,
        "secret_id": sid
    });

    debug!("login URL: {}, role ID: {}", globals.vault_url, rid);

    let response = client
        .post(&globals.vault_url)
        .json(&login_payload)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            globals.vault_url,
            status,
            json_response["errors"][0].as_str().unwrap_or("")
        ));
    }

    // Parse the JSON response
    let json_response: Value = response.json().await?;
    let token = json_response["auth"]["client_token"]
        .as_str()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no client_token found"))?;
    let lease_duration = json_response["auth"]["lease_duration"]
        .as_u64()
        .unwrap_or(1800);

    Ok((token.to_string(), lease_duration))
}

/// Renew a Vault token
#[instrument]
pub async fn renew(globals: &GlobalArgs) -> Result<u64> {
    let client = Client::builder().user_agent(APP_USER_AGENT).build()?;

    // Parse the URL
    let renew_url = endpoint_url(globals, "/v1/auth/token/renew-self")?;

    let response = client
        .post(&renew_url)
        .header("X-Vault-Token", &globals.vault_token)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let json_response: Value = response.json().await?;

        return Err(anyhow!(
            "{} - {}, {}",
            renew_url,
            status,
            json_response["errors"][0].as_str().unwrap_or("")
        ));
    }

    let json_response: Value = response.json().await?;

    json_response["auth"]["lease_duration"]
        .as_u64()
        .ok_or_else(|| anyhow!("Error parsing JSON response: no lease_duration found"))
}

/// Refresh a Vault token
pub async fn refresh_token(globals: &GlobalArgs, lease_duration: u64) -> Result<()> {
    let mut rng = rand::thread_rng();
    let jitter_factor = 0.1;
    let jittered_lease_duration =
        (lease_duration as f64 * rng.gen_range(1.0 - jitter_factor..1.0)) as u64;
    let mut renew_token_interval = interval(Duration::from_secs(jittered_lease_duration));

    let loop_globals = globals.clone();
    tokio::spawn(async move {
        loop {
            renew_token_interval.tick().await;

            // todo use lease_duration returned from vault::renew
            let _ = renew(&loop_globals).await;

            debug!("Will renew token in {} seconds", jittered_lease_duration);
        }
    });

    Ok(())
}
